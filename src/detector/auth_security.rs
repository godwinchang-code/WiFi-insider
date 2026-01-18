use crate::detector::{DetectorEngine, AuthAttempt};
use crate::types::{Dot11Frame, IssueRecord, IssueLocation, IssueType};
use crate::parser::dot11::{get_source_addr, get_bssid};
use crate::types::frame::{format_mac, ManagementSubtype};
use crate::parser::ie_parser::{IE_RSN, parse_rsn};

/// Issue 19: Detect WPA3-SAE authentication failure
pub fn detect_wpa3_sae_failures(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Authentication) {
            // Parse authentication frame
            if frame.payload.len() >= 6 {
                let auth_alg = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                let auth_seq = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);
                let status = u16::from_le_bytes([frame.payload[4], frame.payload[5]]);

                // SAE authentication algorithm = 3
                if auth_alg == 3 {
                    if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                        let src_mac = format_mac(&src);
                        let bssid_mac = format_mac(&bssid);

                        // Track authentication attempt
                        let auth_attempt = AuthAttempt {
                            timestamp,
                            bssid: bssid_mac.clone(),
                            station: src_mac.clone(),
                            auth_alg,
                            status: Some(status),
                        };

                        engine.auth_attempts
                            .entry(src_mac.clone())
                            .or_insert_with(Vec::new)
                            .push(auth_attempt);

                        // Status 0 = success, anything else is failure
                        if status != 0 {
                            let issue = IssueRecord::new(
                                IssueType::Wpa3SaeAuthFailure,
                                timestamp,
                                packet_number,
                                engine.frame_count,
                                IssueLocation {
                                    byte_offset: 24,
                                    field_name: "802.11.auth.status".to_string(),
                                    layer: "802.11".to_string(),
                                },
                                format!(
                                    "WPA3-SAE authentication failed with status code {} (seq {})",
                                    status, auth_seq
                                ),
                                vec![src_mac, bssid_mac],
                            );
                            engine.issues.push(issue);

                            // Update stats
                            let station_stats = engine.stats.get_or_create_station(&format_mac(&src));
                            station_stats.auth_failures += 1;
                        }
                    }
                }
            }
        }
    }
}

/// Issue 20: Detect OWE negotiation failure
pub fn detect_owe_failures(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        // OWE failures typically show up in association responses
        if matches!(
            subtype,
            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse
        ) {
            if frame.payload.len() >= 6 {
                let status = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);

                // Check if RSN IE indicates OWE
                let has_owe = frame.information_elements.iter().any(|ie| {
                    if ie.id == IE_RSN {
                        if let Some(rsn) = parse_rsn(ie) {
                            rsn.has_owe()
                        } else {
                            false
                        }
                    } else {
                        false
                    }
                });

                if has_owe && status != 0 {
                    if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                        let issue = IssueRecord::new(
                            IssueType::OweNegotiationFailure,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 24,
                                field_name: "802.11.assoc_resp.status".to_string(),
                                layer: "802.11".to_string(),
                            },
                            format!("OWE association failed with status code {}", status),
                            vec![format_mac(&src), format_mac(&bssid)],
                        );
                        engine.issues.push(issue);
                    }
                }
            }
        }

        // Also check authentication frames for OWE (uses Open System auth)
        if matches!(subtype, ManagementSubtype::Authentication) {
            if frame.payload.len() >= 6 {
                let auth_alg = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);
                let status = u16::from_le_bytes([frame.payload[4], frame.payload[5]]);

                // OWE uses Open System authentication (0)
                // Need to check beacons/probe responses for OWE support
                if auth_alg == 0 && status != 0 {
                    if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                        let bssid_mac = format_mac(&bssid);

                        // Check if this BSS advertises OWE
                        if let Some(bss_stats) = engine.stats.bss.get(&bssid_mac) {
                            if bss_stats.owe {
                                let issue = IssueRecord::new(
                                    IssueType::OweNegotiationFailure,
                                    timestamp,
                                    packet_number,
                                    engine.frame_count,
                                    IssueLocation {
                                        byte_offset: 24,
                                        field_name: "802.11.auth.status".to_string(),
                                        layer: "802.11".to_string(),
                                    },
                                    format!(
                                        "Authentication failed on OWE network with status {}",
                                        status
                                    ),
                                    vec![format_mac(&src), bssid_mac],
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

/// Issue 21: Detect association rejection with reason codes
pub fn detect_association_rejections(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse
        ) {
            if frame.payload.len() >= 6 {
                let status = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);

                // Status code 0 = success, anything else is a rejection
                if status != 0 {
                    if let (Some(src), Some(bssid)) = (get_source_addr(frame), get_bssid(frame)) {
                        let status_desc = match status {
                            1 => "Unspecified failure",
                            10 => "Cannot support all requested capabilities",
                            11 => "Reassociation denied, could not confirm association exists",
                            12 => "Association denied for reasons outside standard",
                            13 => "Authentication algorithm not supported",
                            17 => "Association denied, AP unable to handle additional stations",
                            18 => "Association denied, requesting station does not support all basic rates",
                            22 => "Association denied, requesting station does not support Short Preamble",
                            23 => "Association denied, requesting station does not support PBCC",
                            24 => "Association denied, requesting station does not support Channel Agility",
                            25 => "Association denied, Spectrum Management required",
                            26 => "Association denied, Power Capability unacceptable",
                            27 => "Association denied, Supported Channels unacceptable",
                            28 => "Association denied, requesting station does not support Short Slot Time",
                            33 => "Association denied, requesting station does not support HT",
                            34 => "Association denied, R0KH unreachable",
                            40 => "Association denied, requesting station does not support VHT",
                            _ => "Unknown status code",
                        };

                        let src_mac = format_mac(&src);
                        let issue = IssueRecord::new(
                            IssueType::AssociationRejection,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 24,
                                field_name: "802.11.assoc_resp.status".to_string(),
                                layer: "802.11".to_string(),
                            },
                            format!(
                                "Association rejected with status {}: {}",
                                status, status_desc
                            ),
                            vec![src_mac.clone(), format_mac(&bssid)],
                        );
                        engine.issues.push(issue);

                        // Update stats
                        let station_stats = engine.stats.get_or_create_station(&src_mac);
                        station_stats.assoc_failures += 1;
                    }
                }
            }
        }

        // Also track disassociation/deauthentication
        if matches!(
            subtype,
            ManagementSubtype::Disassociation | ManagementSubtype::Deauthentication
        ) {
            if frame.payload.len() >= 2 {
                let reason = u16::from_le_bytes([frame.payload[0], frame.payload[1]]);

                if let (Some(src), Some(dest)) = (get_source_addr(frame), frame.addr2) {
                    let reason_desc = match reason {
                        1 => "Unspecified reason",
                        2 => "Previous authentication no longer valid",
                        3 => "Deauthenticated because sending station is leaving",
                        4 => "Disassociated due to inactivity",
                        5 => "Disassociated because AP is unable to handle all associated stations",
                        6 => "Class 2 frame received from nonauthenticated station",
                        7 => "Class 3 frame received from nonassociated station",
                        8 => "Disassociated because sending station is leaving BSS",
                        15 => "4-Way Handshake timeout",
                        23 => "IEEE 802.1X authentication failed",
                        _ => "Unknown reason code",
                    };

                    let issue = IssueRecord::new(
                        IssueType::AssociationRejection,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 24,
                            field_name: format!("802.11.{:?}.reason", subtype).to_lowercase(),
                            layer: "802.11".to_string(),
                        },
                        format!(
                            "{:?} with reason {}: {}",
                            subtype, reason, reason_desc
                        ),
                        vec![format_mac(&src), format_mac(&dest)],
                    );
                    engine.issues.push(issue);
                }
            }
        }
    }
}

/// Issue 22: Detect 6 GHz association failure due to security policy
pub fn detect_6ghz_security_failures(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    // 6 GHz requires WPA3 (no WPA2/Open)
    if let Some(subtype) = frame.management_subtype() {
        if matches!(
            subtype,
            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse
        ) {
            // Check if this is a 6 GHz network
            if let Some(rt) = &frame.radiotap {
                if let Some(freq) = rt.channel_freq {
                    if crate::parser::radiotap::is_6ghz(freq) {
                        if frame.payload.len() >= 6 {
                            let status = u16::from_le_bytes([frame.payload[2], frame.payload[3]]);

                            // Check RSN IE for security policy
                            let has_wpa3 = frame.information_elements.iter().any(|ie| {
                                if ie.id == IE_RSN {
                                    if let Some(rsn) = parse_rsn(ie) {
                                        rsn.has_wpa3_sae() || rsn.has_owe()
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            });

                            // Association rejection on 6 GHz without proper WPA3
                            if status != 0 && !has_wpa3 {
                                if let (Some(src), Some(bssid)) =
                                    (get_source_addr(frame), get_bssid(frame))
                                {
                                    let issue = IssueRecord::new(
                                        IssueType::SixGhzSecurityPolicyFailure,
                                        timestamp,
                                        packet_number,
                                        engine.frame_count,
                                        IssueLocation {
                                            byte_offset: 24,
                                            field_name: "802.11.assoc_resp.rsn".to_string(),
                                            layer: "802.11".to_string(),
                                        },
                                        format!(
                                            "6 GHz association failed (status {}) - WPA3 required but not negotiated",
                                            status
                                        ),
                                        vec![format_mac(&src), format_mac(&bssid)],
                                    );
                                    engine.issues.push(issue);
                                }
                            }

                            // Also flag 6 GHz networks not using WPA3 in beacons
                            if matches!(subtype, ManagementSubtype::Beacon) && !has_wpa3 {
                                if let Some(bssid) = get_bssid(frame) {
                                    let bssid_mac = format_mac(&bssid);

                                    // Only report once per BSS
                                    let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);
                                    if !bss_stats.wpa3_sae && bss_stats.beacon_count == 1 {
                                        let issue = IssueRecord::new(
                                            IssueType::SixGhzSecurityPolicyFailure,
                                            timestamp,
                                            packet_number,
                                            engine.frame_count,
                                            IssueLocation {
                                                byte_offset: 24,
                                                field_name: "802.11.beacon.rsn".to_string(),
                                                layer: "802.11".to_string(),
                                            },
                                            "6 GHz BSS not advertising WPA3 (required for 6 GHz)"
                                                .to_string(),
                                            vec![bssid_mac],
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
}
