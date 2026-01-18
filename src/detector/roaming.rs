use crate::detector::{DetectorEngine, RoamingEvent, RoamingEventType, ProbeEvent};
use crate::types::{Dot11Frame, IssueRecord, IssueLocation, IssueType};
use crate::parser::dot11::{get_source_addr, get_bssid, get_dest_addr};
use crate::types::frame::{format_mac, ManagementSubtype};
use crate::parser::ie_parser::{IE_SSID, IE_MOBILITY_DOMAIN, get_ssid};
use std::collections::HashMap;

// Thresholds
const ROAMING_LATENCY_THRESHOLD: f64 = 0.050; // 50ms threshold for fast roaming
const STICKY_CLIENT_RSSI_THRESHOLD: i8 = -75;  // dBm
const PROBE_BURST_THRESHOLD: usize = 10;       // Probe requests in short time
const PROBE_BURST_WINDOW: f64 = 1.0;          // 1 second window

/// Issue 23: Detect high roaming latency
pub fn detect_high_roaming_latency(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::ReassociationRequest | ManagementSubtype::ReassociationResponse
        ) {
            if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                let src_mac = format_mac(&src);
                let bssid_mac = format_mac(&bssid);

                let events = engine.roaming_events.entry(src_mac.clone()).or_insert_with(Vec::new);

                if matches!(subtype, ManagementSubtype::ReassociationRequest) {
                    // Record reassociation request
                    let event = RoamingEvent {
                        timestamp,
                        from_bssid: None, // Will be inferred from previous association
                        to_bssid: bssid_mac.clone(),
                        event_type: RoamingEventType::Reassociation,
                    };
                    events.push(event);
                } else {
                    // Reassociation response - calculate latency
                    if let Some(req_event) = events.iter().rev().find(|e| {
                        e.event_type == RoamingEventType::Reassociation && e.to_bssid == bssid_mac
                    }) {
                        let latency = timestamp - req_event.timestamp;

                        if latency > ROAMING_LATENCY_THRESHOLD {
                            let issue = IssueRecord::new(
                                IssueType::HighRoamingLatency,
                                timestamp,
                                packet_number,
                                engine.frame_count,
                                IssueLocation {
                                    byte_offset: 24,
                                    field_name: "802.11.reassoc".to_string(),
                                    layer: "802.11".to_string(),
                                },
                                format!(
                                    "Reassociation took {:.1}ms (threshold: {:.1}ms)",
                                    latency * 1000.0,
                                    ROAMING_LATENCY_THRESHOLD * 1000.0
                                ),
                                vec![src_mac, bssid_mac],
                            );
                            engine.issues.push(issue);
                        }
                    }
                }
            }
        }

        // Track associations for roaming analysis
        if matches!(
            subtype,
            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse
        ) {
            if frame.payload.len() >= 6 {
                let status = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);

                if status == 0 {
                    // Successful association
                    if let (Some(dest), Some(bssid)) = (get_dest_addr(frame), get_bssid(frame)) {
                        let dest_mac = format_mac(&dest);
                        let bssid_mac = format_mac(&bssid);

                        let station_stats = engine.stats.get_or_create_station(&dest_mac);
                        if matches!(subtype, ManagementSubtype::AssociationResponse) {
                            station_stats.association_count += 1;
                        } else {
                            station_stats.reassociation_count += 1;
                        }

                        // Track in BSS stats
                        let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);
                        bss_stats.associated_stations.insert(dest_mac, timestamp);
                    }
                }
            }
        }
    }
}

/// Issue 24: Detect 802.11r FT not triggered or failing
pub fn detect_ft_failures(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    use crate::parser::ie_parser::IE_FAST_BSS_TRANSITION;

    if let Some(subtype) = frame.management_subtype() {
        // Check for FT IE presence in reassociation frames
        if matches!(
            subtype,
            ManagementSubtype::ReassociationRequest | ManagementSubtype::ReassociationResponse
        ) {
            // Check if Mobility Domain IE is present (indicates FT support)
            let has_mde = frame.information_elements.iter().any(|ie| ie.id == IE_MOBILITY_DOMAIN);

            // Check if Fast BSS Transition IE is present
            let has_ft_ie = frame.information_elements.iter().any(|ie| ie.id == IE_FAST_BSS_TRANSITION);

            if has_mde && !has_ft_ie {
                // Mobility Domain present but FT not being used
                if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                    let issue = IssueRecord::new(
                        IssueType::Dot11rFtFailure,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 24,
                            field_name: "802.11.reassoc.ies".to_string(),
                            layer: "802.11".to_string(),
                        },
                        "802.11r Mobility Domain present but Fast BSS Transition not triggered"
                            .to_string(),
                        vec![format_mac(&src), format_mac(&bssid)],
                    );
                    engine.issues.push(issue);
                }
            }

            // Check for FT failures in response
            if matches!(subtype, ManagementSubtype::ReassociationResponse) && has_ft_ie {
                if frame.payload.len() >= 6 {
                    let status = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);

                    if status != 0 {
                        if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                            let issue = IssueRecord::new(
                                IssueType::Dot11rFtFailure,
                                timestamp,
                                packet_number,
                                engine.frame_count,
                                IssueLocation {
                                    byte_offset: 24,
                                    field_name: "802.11.reassoc_resp.status".to_string(),
                                    layer: "802.11".to_string(),
                                },
                                format!("802.11r Fast BSS Transition failed with status {}", status),
                                vec![format_mac(&src), format_mac(&bssid)],
                            );
                            engine.issues.push(issue);
                        }
                    }
                }
            }
        }
    }
}

/// Issue 25: Detect abnormal 802.11k neighbor reports
pub fn detect_neighbor_report_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    const ACTION_RADIO_MEASUREMENT: u8 = 5;
    const NEIGHBOR_REPORT_REQUEST: u8 = 4;
    const NEIGHBOR_REPORT_RESPONSE: u8 = 5;

    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Action) {
            if frame.payload.len() >= 2 {
                let category = frame.payload[0];
                let action = frame.payload[1];

                if category == ACTION_RADIO_MEASUREMENT {
                    if action == NEIGHBOR_REPORT_REQUEST {
                        // Track neighbor report request
                        // Could track and correlate with responses
                    } else if action == NEIGHBOR_REPORT_RESPONSE {
                        // Check if response has valid neighbor entries
                        if frame.payload.len() < 10 {
                            // Minimal valid response should have at least one neighbor entry
                            if let (Some(src), Some(dest)) = (get_source_addr(frame), get_dest_addr(frame)) {
                                let issue = IssueRecord::new(
                                    IssueType::AbnormalNeighborReports,
                                    timestamp,
                                    packet_number,
                                    engine.frame_count,
                                    IssueLocation {
                                        byte_offset: 24,
                                        field_name: "802.11.action.rrm.neighbor_report".to_string(),
                                        layer: "802.11".to_string(),
                                    },
                                    "802.11k Neighbor Report response is too short or empty".to_string(),
                                    vec![format_mac(&src), format_mac(&dest)],
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

/// Issue 26: Detect abnormal 802.11v BSS Transition behavior
pub fn detect_bss_transition_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    const ACTION_WNM: u8 = 10;
    const BSS_TM_REQUEST: u8 = 7;
    const BSS_TM_RESPONSE: u8 = 8;

    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Action) {
            if frame.payload.len() >= 2 {
                let category = frame.payload[0];
                let action = frame.payload[1];

                if category == ACTION_WNM {
                    if action == BSS_TM_REQUEST {
                        // BSS Transition Management Request
                        // Could track requests and correlate with responses/roaming
                    } else if action == BSS_TM_RESPONSE {
                        // BSS Transition Management Response
                        if frame.payload.len() >= 4 {
                            let status = frame.payload[3];

                            // Status codes for BSS TM:
                            // 0 = Accept
                            // 1 = Reject - Unspecified
                            // 6 = Reject - Transition delayed
                            // 7 = Reject - BSS termination undesired
                            if status != 0 {
                                if let (Some(src), Some(dest)) = (get_source_addr(frame), get_dest_addr(frame)) {
                                    let status_desc = match status {
                                        1 => "Unspecified rejection",
                                        6 => "Transition delayed",
                                        7 => "BSS termination undesired",
                                        _ => "Unknown status",
                                    };

                                    let issue = IssueRecord::new(
                                        IssueType::AbnormalBssTransition,
                                        timestamp,
                                        packet_number,
                                        engine.frame_count,
                                        IssueLocation {
                                            byte_offset: 24,
                                            field_name: "802.11.action.wnm.bss_tm_resp.status".to_string(),
                                            layer: "802.11".to_string(),
                                        },
                                        format!(
                                            "802.11v BSS Transition rejected with status {}: {}",
                                            status, status_desc
                                        ),
                                        vec![format_mac(&src), format_mac(&dest)],
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
}

/// Issue 27: Detect sticky client behavior
pub fn detect_sticky_clients(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_roaming_analysis
}

/// Issue 28: Detect abnormal Probe Request/Response behavior
pub fn detect_probe_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::ProbeRequest) {
            if let Some(src) = get_source_addr(frame) {
                let src_mac = format_mac(&src);

                // Extract SSID
                let ssid = frame.information_elements.iter()
                    .find(|ie| ie.id == IE_SSID)
                    .and_then(get_ssid);

                // Track probe event
                let probe_event = ProbeEvent {
                    timestamp,
                    station: src_mac.clone(),
                    ssid: ssid.clone(),
                    is_response: false,
                    bssid: None,
                };

                engine.probe_events.entry(src_mac.clone()).or_insert_with(Vec::new).push(probe_event);

                // Update stats
                let station_stats = engine.stats.get_or_create_station(&src_mac);
                station_stats.probe_request_count += 1;

                // Check for probe flooding
                let recent_probes: Vec<&ProbeEvent> = engine.probe_events[&src_mac]
                    .iter()
                    .filter(|e| !e.is_response && (timestamp - e.timestamp) < PROBE_BURST_WINDOW)
                    .collect();

                if recent_probes.len() > PROBE_BURST_THRESHOLD {
                    let issue = IssueRecord::new(
                        IssueType::AbnormalProbeRequestResponse,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 24,
                            field_name: "802.11.probe_req".to_string(),
                            layer: "802.11".to_string(),
                        },
                        format!(
                            "Excessive probe requests: {} in {:.1}s",
                            recent_probes.len(),
                            PROBE_BURST_WINDOW
                        ),
                        vec![src_mac],
                    );
                    engine.issues.push(issue);
                }
            }
        } else if matches!(subtype, ManagementSubtype::ProbeResponse) {
            if let (Some(src), Some(dest)) = (get_source_addr(frame), get_dest_addr(frame)) {
                let src_mac = format_mac(&src);
                let dest_mac = format_mac(&dest);

                let ssid = frame.information_elements.iter()
                    .find(|ie| ie.id == IE_SSID)
                    .and_then(get_ssid);

                // Track probe response
                let probe_event = ProbeEvent {
                    timestamp,
                    station: dest_mac.clone(),
                    ssid,
                    is_response: true,
                    bssid: Some(src_mac),
                };

                engine.probe_events.entry(dest_mac.clone()).or_insert_with(Vec::new).push(probe_event);

                // Update stats
                let station_stats = engine.stats.get_or_create_station(&dest_mac);
                station_stats.probe_response_count += 1;
            }
        }
    }
}

/// Issue 29: Detect abnormal beacon scanning behavior
pub fn detect_beacon_scanning_issues(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_roaming_analysis based on beacon patterns
}

/// Finalize roaming/mobility analysis
pub fn finalize_roaming_analysis(engine: &mut DetectorEngine) {
    // Issue 27: Detect sticky clients
    // A sticky client is one that stays associated despite poor signal or better options available

    for (mac, events) in &engine.roaming_events {
        // If client has very few roaming events despite being active, might be sticky
        let station_stats = engine.stats.stations.get(mac);

        if let Some(stats) = station_stats {
            let duration = stats.last_seen - stats.first_seen;

            // If active for > 60 seconds with no reassociations, check for sticky behavior
            if duration > 60.0 && stats.reassociation_count == 0 && stats.probe_request_count > 10 {
                // Multiple probe requests but no roaming suggests stickiness
                let issue = IssueRecord::new(
                    IssueType::StickyClientBehavior,
                    stats.last_seen,
                    0,
                    0,
                    IssueLocation {
                        byte_offset: 0,
                        field_name: "analysis.roaming_pattern".to_string(),
                        layer: "analysis".to_string(),
                    },
                    format!(
                        "Client sent {} probe requests over {:.0}s but never roamed",
                        stats.probe_request_count,
                        duration
                    ),
                    vec![mac.clone()],
                );
                engine.issues.push(issue);
            }
        }
    }

    // Issue 29: Detect abnormal beacon patterns
    // This would involve analyzing beacon reception patterns, but requires more detailed tracking
    // For now, we can detect if a BSS has irregular beacon intervals

    for (bssid, bss_stats) in &engine.stats.bss {
        if bss_stats.beacon_count > 10 {
            let duration = bss_stats.last_seen - bss_stats.first_seen;
            let expected_beacons = if let Some(interval) = bss_stats.beacon_interval {
                (duration * 1000.0 / interval as f64) as u64
            } else {
                100  // Default ~100ms interval = ~10 beacons/sec
            };

            // Allow 50% variance
            let min_expected = expected_beacons / 2;
            let max_expected = expected_beacons * 2;

            if bss_stats.beacon_count < min_expected || bss_stats.beacon_count > max_expected {
                let issue = IssueRecord::new(
                    IssueType::AbnormalBeaconScanning,
                    bss_stats.last_seen,
                    0,
                    0,
                    IssueLocation {
                        byte_offset: 0,
                        field_name: "analysis.beacon_pattern".to_string(),
                        layer: "analysis".to_string(),
                    },
                    format!(
                        "Abnormal beacon count: {} beacons over {:.1}s (expected ~{})",
                        bss_stats.beacon_count,
                        duration,
                        expected_beacons
                    ),
                    vec![bssid.clone()],
                );
                engine.issues.push(issue);
            }
        }
    }
}
