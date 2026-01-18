use crate::detector::{phy_mac_eht, spectrum, auth_security, roaming, interference};
use crate::types::{Dot11Frame, IssueRecord, GlobalStats};
use std::collections::HashMap;

/// Main detector engine that coordinates all issue detectors
pub struct DetectorEngine {
    pub stats: GlobalStats,
    pub issues: Vec<IssueRecord>,

    // Tracking state for various detectors
    pub last_mcs_per_station: HashMap<String, u8>,
    pub last_nss_per_station: HashMap<String, u8>,
    pub last_bandwidth_per_station: HashMap<String, u16>,
    pub roaming_events: HashMap<String, Vec<RoamingEvent>>,
    pub auth_attempts: HashMap<String, Vec<AuthAttempt>>,
    pub probe_events: HashMap<String, Vec<ProbeEvent>>,
    pub frame_count: u64,
}

#[derive(Debug, Clone)]
pub struct RoamingEvent {
    pub timestamp: f64,
    pub from_bssid: Option<String>,
    pub to_bssid: String,
    pub event_type: RoamingEventType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RoamingEventType {
    Association,
    Reassociation,
    Disassociation,
}

#[derive(Debug, Clone)]
pub struct AuthAttempt {
    pub timestamp: f64,
    pub bssid: String,
    pub station: String,
    pub auth_alg: u16,
    pub status: Option<u16>,
}

#[derive(Debug, Clone)]
pub struct ProbeEvent {
    pub timestamp: f64,
    pub station: String,
    pub ssid: Option<String>,
    pub is_response: bool,
    pub bssid: Option<String>,
}

impl DetectorEngine {
    pub fn new() -> Self {
        Self {
            stats: GlobalStats::new(),
            issues: Vec::new(),
            last_mcs_per_station: HashMap::new(),
            last_nss_per_station: HashMap::new(),
            last_bandwidth_per_station: HashMap::new(),
            roaming_events: HashMap::new(),
            auth_attempts: HashMap::new(),
            probe_events: HashMap::new(),
            frame_count: 0,
        }
    }

    /// Process a single frame and detect issues
    pub fn process_frame(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        self.frame_count += 1;

        // Update global stats
        self.update_stats(frame, timestamp);

        // Run all detectors
        self.detect_phy_mac_eht_issues(frame, packet_number, timestamp);
        self.detect_spectrum_issues(frame, packet_number, timestamp);
        self.detect_auth_security_issues(frame, packet_number, timestamp);
        self.detect_roaming_issues(frame, packet_number, timestamp);
        self.detect_interference_issues(frame, packet_number, timestamp);
    }

    /// Update statistics from frame
    fn update_stats(&mut self, frame: &Dot11Frame, timestamp: f64) {
        if self.stats.start_time == 0.0 {
            self.stats.start_time = timestamp;
        }
        self.stats.end_time = timestamp;
        self.stats.total_frames += 1;

        // Update station stats
        if let Some(src) = crate::parser::dot11::get_source_addr(frame) {
            let src_mac = crate::types::frame::format_mac(&src);
            let station = self.stats.get_or_create_station(&src_mac);

            if station.first_seen == 0.0 {
                station.first_seen = timestamp;
            }
            station.last_seen = timestamp;
            station.frame_count += 1;

            if frame.frame_control.retry {
                station.retry_count += 1;
            }

            match frame.frame_control.get_frame_type() {
                crate::types::frame::FrameType::Management => station.mgmt_frames += 1,
                crate::types::frame::FrameType::Control => station.ctrl_frames += 1,
                crate::types::frame::FrameType::Data => {
                    station.data_frames += 1;
                    if frame.is_qos() {
                        station.qos_frames += 1;
                    }
                }
                _ => {}
            }

            // Update PHY stats from radiotap
            if let Some(rt) = &frame.radiotap {
                if let Some(mcs_info) = &rt.mcs {
                    *station.mcs_distribution.entry(mcs_info.mcs).or_insert(0) += 1;
                }

                if let Some(vht) = &rt.vht {
                    let nss = vht.mcs_nss[0] & 0x0F;
                    *station.nss_distribution.entry(nss).or_insert(0) += 1;
                }

                if let Some(he) = &rt.he {
                    let nss = he.nss();
                    *station.nss_distribution.entry(nss).or_insert(0) += 1;

                    let bw = match he.bandwidth() {
                        0 => 20,
                        1 => 40,
                        2 => 80,
                        3 => 160,
                        _ => 0,
                    };
                    *station.bandwidth_distribution.entry(bw).or_insert(0) += 1;
                }

                if let Some(eht) = &rt.eht {
                    station.eht_frames += 1;
                    let bw = eht.bandwidth();
                    *station.bandwidth_distribution.entry(bw).or_insert(0) += 1;

                    let nss = eht.nss();
                    *station.nss_distribution.entry(nss).or_insert(0) += 1;

                    // Check for MU-MIMO and OFDMA
                    if !eht.user_info.is_empty() {
                        if eht.user_info.len() > 1 {
                            station.mu_mimo_frames += 1;
                        }
                    }

                    let ru = eht.ru_allocation();
                    if ru > 0 {
                        station.ofdma_frames += 1;
                        *station.ru_allocations.entry(ru).or_insert(0) += 1;
                    }
                }
            }
        }

        // Update BSS stats for beacons
        if let Some(mgmt_subtype) = frame.management_subtype() {
            if matches!(mgmt_subtype, crate::types::frame::ManagementSubtype::Beacon) {
                if let Some(bssid) = crate::parser::dot11::get_bssid(frame) {
                    let bssid_mac = crate::types::frame::format_mac(&bssid);
                    let bss = self.stats.get_or_create_bss(&bssid_mac);

                    if bss.first_seen == 0.0 {
                        bss.first_seen = timestamp;
                    }
                    bss.last_seen = timestamp;
                    bss.beacon_count += 1;

                    // Parse beacon IEs
                    for ie in &frame.information_elements {
                        match ie.id {
                            crate::parser::ie_parser::IE_SSID => {
                                if let Some(ssid) = crate::parser::ie_parser::get_ssid(ie) {
                                    bss.ssid = Some(ssid);
                                }
                            }
                            crate::parser::ie_parser::IE_RSN => {
                                if let Some(rsn) = crate::parser::ie_parser::parse_rsn(ie) {
                                    bss.wpa3_sae = rsn.has_wpa3_sae();
                                    bss.owe = rsn.has_owe();
                                }
                            }
                            crate::parser::ie_parser::IE_VHT_CAPABILITIES => {
                                if let Some(vht) = crate::parser::ie_parser::parse_vht_capabilities(ie) {
                                    bss.max_bandwidth = Some(vht.max_bandwidth());
                                }
                            }
                            _ => {}
                        }
                    }

                    // Check for EHT/HE capabilities
                    if let Some(rt) = &frame.radiotap {
                        if rt.eht.is_some() {
                            bss.eht_capable = true;
                        }
                        if let Some(he) = &rt.he {
                            bss.bss_color = Some(he.bss_color());
                        }
                    }
                }
            }
        }
    }

    /// PHY/MAC/EHT issue detection (issues 1-14)
    fn detect_phy_mac_eht_issues(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        phy_mac_eht::detect_modulation_fallback(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_nss_mismatch(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_bandwidth_mismatch(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_ru_allocation_issues(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_ofdma_trigger_rates(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_mu_mimo_utilization(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_high_retry_rate(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_channel_utilization(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_ppdu_type_issues(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_eht_capability_issues(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_bandwidth_negotiation(
            self, frame, packet_number, timestamp
        );
        phy_mac_eht::detect_mlo_issues(
            self, frame, packet_number, timestamp
        );
    }

    /// Spectrum sharing issue detection (issues 15-18)
    fn detect_spectrum_issues(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        spectrum::detect_bss_coloring_issues(
            self, frame, packet_number, timestamp
        );
        spectrum::detect_rnr_issues(
            self, frame, packet_number, timestamp
        );
        spectrum::detect_csa_anomalies(
            self, frame, packet_number, timestamp
        );
        spectrum::detect_missing_mandatory_fields(
            self, frame, packet_number, timestamp
        );
    }

    /// Authentication/Security issue detection (issues 19-22)
    fn detect_auth_security_issues(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        auth_security::detect_wpa3_sae_failures(
            self, frame, packet_number, timestamp
        );
        auth_security::detect_owe_failures(
            self, frame, packet_number, timestamp
        );
        auth_security::detect_association_rejections(
            self, frame, packet_number, timestamp
        );
        auth_security::detect_6ghz_security_failures(
            self, frame, packet_number, timestamp
        );
    }

    /// Roaming/Mobility issue detection (issues 23-29)
    fn detect_roaming_issues(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        roaming::detect_high_roaming_latency(
            self, frame, packet_number, timestamp
        );
        roaming::detect_ft_failures(
            self, frame, packet_number, timestamp
        );
        roaming::detect_neighbor_report_issues(
            self, frame, packet_number, timestamp
        );
        roaming::detect_bss_transition_issues(
            self, frame, packet_number, timestamp
        );
        roaming::detect_sticky_clients(
            self, frame, packet_number, timestamp
        );
        roaming::detect_probe_issues(
            self, frame, packet_number, timestamp
        );
        roaming::detect_beacon_scanning_issues(
            self, frame, packet_number, timestamp
        );
    }

    /// Interference issue detection (issues 30-32)
    fn detect_interference_issues(
        &mut self,
        frame: &Dot11Frame,
        packet_number: u64,
        timestamp: f64,
    ) {
        interference::detect_co_channel_interference(
            self, frame, packet_number, timestamp
        );
        interference::detect_adjacent_channel_interference(
            self, frame, packet_number, timestamp
        );
        interference::detect_obss_degradation(
            self, frame, packet_number, timestamp
        );
    }

    /// Finalize analysis and detect issues that require full capture context
    pub fn finalize_analysis(&mut self) {
        // Detect issues that require analyzing the entire capture
        phy_mac_eht::finalize_phy_mac_eht_analysis(self);
        roaming::finalize_roaming_analysis(self);
        interference::finalize_interference_analysis(self);
    }

    /// Get all detected issues
    pub fn get_issues(&self) -> &[IssueRecord] {
        &self.issues
    }

    /// Get statistics
    pub fn get_stats(&self) -> &GlobalStats {
        &self.stats
    }
}

impl Default for DetectorEngine {
    fn default() -> Self {
        Self::new()
    }
}
