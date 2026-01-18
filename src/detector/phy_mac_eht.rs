use crate::detector::DetectorEngine;
use crate::types::{Dot11Frame, IssueRecord, IssueLocation, IssueType};
use crate::parser::dot11::get_source_addr;
use crate::types::frame::format_mac;

// Thresholds for detection
const MCS_DOWNGRADE_THRESHOLD: i8 = 2;  // Detect if MCS drops by 2 or more
const NSS_MISMATCH_THRESHOLD: i8 = 1;   // Detect if NSS drops by 1 or more
const BW_DOWNGRADE_THRESHOLD: i16 = 20; // Detect bandwidth drops
const RETRY_RATE_THRESHOLD: f64 = 0.15; // 15% retry rate threshold
const MU_MIMO_UTILIZATION_THRESHOLD: f64 = 0.10; // Low MU-MIMO if < 10%
const OFDMA_TRIGGER_RATE_THRESHOLD: f64 = 0.20; // Low OFDMA if < 20%

/// Issue 1: Detect modulation fallback (MCS downgrade)
pub fn detect_modulation_fallback(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(src) = get_source_addr(frame) {
        let src_mac = format_mac(&src);

        if let Some(rt) = &frame.radiotap {
            let current_mcs = if let Some(eht) = &rt.eht {
                Some(eht.mcs())
            } else if let Some(he) = &rt.he {
                Some(he.mcs())
            } else if let Some(vht) = &rt.vht {
                Some((vht.mcs_nss[0] >> 4) & 0x0F)
            } else if let Some(mcs) = &rt.mcs {
                Some(mcs.mcs)
            } else {
                None
            };

            if let Some(mcs) = current_mcs {
                if let Some(&last_mcs) = engine.last_mcs_per_station.get(&src_mac) {
                    let mcs_diff = last_mcs as i8 - mcs as i8;

                    if mcs_diff >= MCS_DOWNGRADE_THRESHOLD {
                        let issue = IssueRecord::new(
                            IssueType::ModulationFallback,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 0,
                                field_name: "radiotap.mcs".to_string(),
                                layer: "radiotap".to_string(),
                            },
                            format!(
                                "MCS dropped from {} to {} (delta: {})",
                                last_mcs, mcs, mcs_diff
                            ),
                            vec![src_mac.clone()],
                        );
                        engine.issues.push(issue);
                    }
                }

                engine.last_mcs_per_station.insert(src_mac, mcs);
            }
        }
    }
}

/// Issue 2: Detect insufficient spatial streams (NSS mismatch)
pub fn detect_nss_mismatch(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(src) = get_source_addr(frame) {
        let src_mac = format_mac(&src);

        if let Some(rt) = &frame.radiotap {
            let current_nss = if let Some(eht) = &rt.eht {
                Some(eht.nss())
            } else if let Some(he) = &rt.he {
                Some(he.nss())
            } else if let Some(vht) = &rt.vht {
                Some(vht.mcs_nss[0] & 0x0F)
            } else {
                None
            };

            if let Some(nss) = current_nss {
                if let Some(&last_nss) = engine.last_nss_per_station.get(&src_mac) {
                    let nss_diff = last_nss as i8 - nss as i8;

                    if nss_diff >= NSS_MISMATCH_THRESHOLD && nss > 0 {
                        let issue = IssueRecord::new(
                            IssueType::InsufficientSpatialStreams,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 0,
                                field_name: "radiotap.nss".to_string(),
                                layer: "radiotap".to_string(),
                            },
                            format!(
                                "NSS dropped from {} to {} streams",
                                last_nss, nss
                            ),
                            vec![src_mac.clone()],
                        );
                        engine.issues.push(issue);
                    }
                }

                engine.last_nss_per_station.insert(src_mac, nss);
            }
        }
    }
}

/// Issue 3: Detect channel bandwidth mismatch
pub fn detect_bandwidth_mismatch(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(src) = get_source_addr(frame) {
        let src_mac = format_mac(&src);

        if let Some(rt) = &frame.radiotap {
            let current_bw = if let Some(eht) = &rt.eht {
                Some(eht.bandwidth())
            } else if let Some(he) = &rt.he {
                match he.bandwidth() {
                    0 => Some(20),
                    1 => Some(40),
                    2 => Some(80),
                    3 => Some(160),
                    _ => None,
                }
            } else if let Some(vht) = &rt.vht {
                match vht.bandwidth {
                    0 => Some(20),
                    1 => Some(40),
                    2 => Some(80),
                    3 => Some(160),
                    _ => None,
                }
            } else if let Some(mcs) = &rt.mcs {
                match mcs.bandwidth() {
                    0 => Some(20),
                    1 => Some(40),
                    _ => None,
                }
            } else {
                None
            };

            if let Some(bw) = current_bw {
                if let Some(&last_bw) = engine.last_bandwidth_per_station.get(&src_mac) {
                    let bw_diff = last_bw as i16 - bw as i16;

                    if bw_diff >= BW_DOWNGRADE_THRESHOLD {
                        let issue = IssueRecord::new(
                            IssueType::ChannelBandwidthMismatch,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 0,
                                field_name: "radiotap.bandwidth".to_string(),
                                layer: "radiotap".to_string(),
                            },
                            format!(
                                "Bandwidth dropped from {} MHz to {} MHz",
                                last_bw, bw
                            ),
                            vec![src_mac.clone()],
                        );
                        engine.issues.push(issue);
                    }
                }

                engine.last_bandwidth_per_station.insert(src_mac, bw);
            }
        }
    }
}

/// Issue 4: Detect improper EHT RU allocation
pub fn detect_ru_allocation_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(rt) = &frame.radiotap {
        if let Some(eht) = &rt.eht {
            let ru = eht.ru_allocation();

            // Check for invalid or inefficient RU allocations
            // RU sizes should be: 26, 52, 106, 242, 484, 996, 2x996, etc.
            let valid_ru_sizes = [26, 52, 106, 242, 484, 996, 1992];

            if ru > 0 && !valid_ru_sizes.contains(&ru) {
                if let Some(src) = get_source_addr(frame) {
                    let issue = IssueRecord::new(
                        IssueType::ImproperEhtRuAllocation,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 0,
                            field_name: "radiotap.eht.ru_allocation".to_string(),
                            layer: "radiotap".to_string(),
                        },
                        format!("Invalid RU allocation: {}", ru),
                        vec![format_mac(&src)],
                    );
                    engine.issues.push(issue);
                }
            }
        }
    }
}

/// Issue 5 & 6: Detect low OFDMA trigger rates (both uplink and downlink)
pub fn detect_ofdma_trigger_rates(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_phy_mac_eht_analysis
}

/// Issue 7: Detect low MU-MIMO utilization
pub fn detect_mu_mimo_utilization(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_phy_mac_eht_analysis
}

/// Issue 8: Detect high frame retry rate
pub fn detect_high_retry_rate(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_phy_mac_eht_analysis
}

/// Issue 9 & 10: Detect high channel utilization and CCA busy
pub fn detect_channel_utilization(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_phy_mac_eht_analysis
}

/// Issue 11: Detect abnormal PPDU type selection
pub fn detect_ppdu_type_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(rt) = &frame.radiotap {
        if let Some(eht) = &rt.eht {
            let ppdu_type = eht.ppdu_type();

            // PPDU types: 0=SU, 1=MU, 2=Trigger-based, 3=Extended Range
            // Check for inconsistent usage (e.g., MU-PPDU with single user)
            if ppdu_type == 1 && eht.user_info.len() <= 1 {
                if let Some(src) = get_source_addr(frame) {
                    let issue = IssueRecord::new(
                        IssueType::AbnormalPpduTypeSelection,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 0,
                            field_name: "radiotap.eht.ppdu_type".to_string(),
                            layer: "radiotap".to_string(),
                        },
                        format!(
                            "MU-PPDU type but only {} user(s)",
                            eht.user_info.len()
                        ),
                        vec![format_mac(&src)],
                    );
                    engine.issues.push(issue);
                }
            }
        }
    }
}

/// Issue 12: Detect incomplete EHT capability negotiation
pub fn detect_eht_capability_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    use crate::types::frame::ManagementSubtype;
    use crate::parser::ie_parser::IE_EXTENSION;

    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse
        ) {
            // Check if EHT capabilities IE is present
            let has_eht_cap = frame.information_elements.iter().any(|ie| {
                ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 108 // EXT_IE_EHT_CAPABILITIES
            });

            let has_he_cap = frame.information_elements.iter().any(|ie| {
                ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 35 // EXT_IE_HE_CAPABILITIES
            });

            // If we see HE but no EHT on a Wi-Fi 7 capable network, flag it
            if has_he_cap && !has_eht_cap {
                if let Some(src) = get_source_addr(frame) {
                    let issue = IssueRecord::new(
                        IssueType::IncompleteEhtCapabilityNegotiation,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 24,
                            field_name: "802.11.association_response.ies".to_string(),
                            layer: "802.11".to_string(),
                        },
                        "HE capabilities present but EHT capabilities missing".to_string(),
                        vec![format_mac(&src)],
                    );
                    engine.issues.push(issue);
                }
            }
        }
    }
}

/// Issue 13: Detect client negotiating less than 320 MHz
pub fn detect_bandwidth_negotiation(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    use crate::types::frame::ManagementSubtype;
    use crate::parser::ie_parser::{IE_EXTENSION, IE_VHT_CAPABILITIES};

    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::AssociationRequest | ManagementSubtype::ReassociationRequest
        ) {
            // Check if client is negotiating with a Wi-Fi 7 AP
            let has_eht_cap = frame.information_elements.iter().any(|ie| {
                ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 108
            });

            // Check negotiated bandwidth from VHT capabilities
            for ie in &frame.information_elements {
                if ie.id == IE_VHT_CAPABILITIES {
                    if let Some(vht_cap) = crate::parser::ie_parser::parse_vht_capabilities(ie) {
                        let max_bw = vht_cap.max_bandwidth();

                        if has_eht_cap && max_bw < 320 {
                            if let Some(src) = get_source_addr(frame) {
                                let issue = IssueRecord::new(
                                    IssueType::ClientNegotiatingLessThan320MHz,
                                    timestamp,
                                    packet_number,
                                    engine.frame_count,
                                    IssueLocation {
                                        byte_offset: 24,
                                        field_name: "802.11.vht_capabilities".to_string(),
                                        layer: "802.11".to_string(),
                                    },
                                    format!(
                                        "EHT-capable client negotiating only {} MHz bandwidth",
                                        max_bw
                                    ),
                                    vec![format_mac(&src)],
                                );
                                engine.issues.push(issue);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Issue 14: Detect MLO negotiation failure or not triggered
pub fn detect_mlo_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    use crate::types::frame::ManagementSubtype;
    use crate::parser::ie_parser::IE_EXTENSION;

    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::AssociationRequest
            | ManagementSubtype::AssociationResponse
            | ManagementSubtype::ReassociationRequest
            | ManagementSubtype::ReassociationResponse
        ) {
            let has_eht_cap = frame.information_elements.iter().any(|ie| {
                ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 108
            });

            let has_mlo_ie = frame.information_elements.iter().any(|ie| {
                ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 107 // EXT_IE_MULTI_LINK
            });

            // If EHT capable but no MLO IE in 6 GHz band, flag it
            if has_eht_cap && !has_mlo_ie {
                if let Some(rt) = &frame.radiotap {
                    if let Some(freq) = rt.channel_freq {
                        if crate::parser::radiotap::is_6ghz(freq) {
                            if let Some(src) = get_source_addr(frame) {
                                let issue = IssueRecord::new(
                                    IssueType::MloNegotiationFailure,
                                    timestamp,
                                    packet_number,
                                    engine.frame_count,
                                    IssueLocation {
                                        byte_offset: 24,
                                        field_name: "802.11.ies".to_string(),
                                        layer: "802.11".to_string(),
                                    },
                                    "EHT-capable device on 6 GHz without MLO IE".to_string(),
                                    vec![format_mac(&src)],
                                );
                                engine.issues.push(issue);
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Finalize analysis for PHY/MAC/EHT issues
pub fn finalize_phy_mac_eht_analysis(engine: &mut DetectorEngine) {
    // Analyze per-station statistics for issues that require full capture context

    for (mac, stats) in &engine.stats.stations {
        // Issue 7: Low MU-MIMO utilization
        let mu_mimo_util = stats.mu_mimo_utilization();
        if stats.eht_frames > 100 && mu_mimo_util < MU_MIMO_UTILIZATION_THRESHOLD {
            let issue = IssueRecord::new(
                IssueType::LowMuMimoUtilization,
                stats.last_seen,
                0,
                0,
                IssueLocation {
                    byte_offset: 0,
                    field_name: "analysis.mu_mimo_utilization".to_string(),
                    layer: "analysis".to_string(),
                },
                format!(
                    "MU-MIMO utilization only {:.1}% ({} MU frames / {} total data frames)",
                    mu_mimo_util * 100.0,
                    stats.mu_mimo_frames,
                    stats.data_frames
                ),
                vec![mac.clone()],
            );
            engine.issues.push(issue);
        }

        // Issue 5 & 6: Low OFDMA trigger rates
        let ofdma_util = stats.ofdma_utilization();
        if stats.eht_frames > 100 && ofdma_util < OFDMA_TRIGGER_RATE_THRESHOLD {
            // Detect both uplink and downlink based on pattern
            let issue = IssueRecord::new(
                IssueType::LowDownlinkOfdmaTriggerRate,
                stats.last_seen,
                0,
                0,
                IssueLocation {
                    byte_offset: 0,
                    field_name: "analysis.ofdma_utilization".to_string(),
                    layer: "analysis".to_string(),
                },
                format!(
                    "OFDMA utilization only {:.1}% ({} OFDMA frames / {} total data frames)",
                    ofdma_util * 100.0,
                    stats.ofdma_frames,
                    stats.data_frames
                ),
                vec![mac.clone()],
            );
            engine.issues.push(issue);
        }

        // Issue 8: High retry rate
        let retry_rate = stats.retry_rate();
        if stats.frame_count > 100 && retry_rate > RETRY_RATE_THRESHOLD {
            let issue = IssueRecord::new(
                IssueType::HighFrameRetryRate,
                stats.last_seen,
                0,
                0,
                IssueLocation {
                    byte_offset: 0,
                    field_name: "analysis.retry_rate".to_string(),
                    layer: "analysis".to_string(),
                },
                format!(
                    "Retry rate {:.1}% ({} retries / {} frames)",
                    retry_rate * 100.0,
                    stats.retry_count,
                    stats.frame_count
                ),
                vec![mac.clone()],
            );
            engine.issues.push(issue);
        }
    }

    // Issue 9: High channel utilization
    // Calculate based on frame density per channel
    for (channel, ch_stats) in &engine.stats.channels {
        let duration = engine.stats.end_time - engine.stats.start_time;
        if duration > 1.0 {
            let frames_per_second = ch_stats.frame_count as f64 / duration;

            // High utilization if > 1000 frames/sec (approximate threshold)
            if frames_per_second > 1000.0 {
                let issue = IssueRecord::new(
                    IssueType::HighChannelUtilization,
                    engine.stats.end_time,
                    0,
                    0,
                    IssueLocation {
                        byte_offset: 0,
                        field_name: format!("analysis.channel_{}_utilization", channel),
                        layer: "analysis".to_string(),
                    },
                    format!(
                        "Channel {} has high utilization: {:.0} frames/sec ({} BSSs)",
                        channel, frames_per_second, ch_stats.bss_count
                    ),
                    vec![],
                );
                engine.issues.push(issue);
            }
        }
    }
}
