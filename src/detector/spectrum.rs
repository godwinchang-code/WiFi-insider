use crate::detector::DetectorEngine;
use crate::types::{Dot11Frame, IssueRecord, IssueLocation, IssueType};
use crate::parser::dot11::{get_source_addr, get_bssid};
use crate::types::frame::{format_mac, ManagementSubtype};
use crate::parser::ie_parser::{IE_EXTENSION, IE_SSID, IE_DSSS_PARAMETER};
use std::collections::HashMap;

/// Issue 15: Detect ineffective BSS Coloring behavior
pub fn detect_bss_coloring_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    // BSS Color is in HE/EHT radiotap and beacon IEs
    if let Some(rt) = &frame.radiotap {
        if let Some(he) = &rt.he {
            let bss_color = he.bss_color();

            // BSS Color 0 or 63 are reserved/invalid
            if bss_color == 0 || bss_color == 63 {
                if let Some(bssid) = get_bssid(frame) {
                    let issue = IssueRecord::new(
                        IssueType::IneffectiveBssColoring,
                        timestamp,
                        packet_number,
                        engine.frame_count,
                        IssueLocation {
                            byte_offset: 0,
                            field_name: "radiotap.he.bss_color".to_string(),
                            layer: "radiotap".to_string(),
                        },
                        format!("Invalid BSS Color: {}", bss_color),
                        vec![format_mac(&bssid)],
                    );
                    engine.issues.push(issue);
                }
            }

            // Track BSS color changes for a BSSID
            if let Some(bssid) = get_bssid(frame) {
                let bssid_mac = format_mac(&bssid);
                let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);

                if let Some(prev_color) = bss_stats.bss_color {
                    if prev_color != bss_color {
                        bss_stats.bss_color_changes += 1;

                        let issue = IssueRecord::new(
                            IssueType::IneffectiveBssColoring,
                            timestamp,
                            packet_number,
                            engine.frame_count,
                            IssueLocation {
                                byte_offset: 0,
                                field_name: "radiotap.he.bss_color".to_string(),
                                layer: "radiotap".to_string(),
                            },
                            format!(
                                "BSS Color changed from {} to {} (change #{})",
                                prev_color, bss_color, bss_stats.bss_color_changes
                            ),
                            vec![bssid_mac],
                        );
                        engine.issues.push(issue);
                    }
                } else {
                    bss_stats.bss_color = Some(bss_color);
                }
            }
        }
    }
}

/// Issue 16: Detect incomplete 6 GHz Reduced Neighbor Report (RNR)
pub fn detect_rnr_issues(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    // RNR is required in 6 GHz beacons
    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Beacon) {
            // Check if this is a 6 GHz beacon
            if let Some(rt) = &frame.radiotap {
                if let Some(freq) = rt.channel_freq {
                    if crate::parser::radiotap::is_6ghz(freq) {
                        // Look for RNR IE (Extension IE with ID 201)
                        let has_rnr = frame.information_elements.iter().any(|ie| {
                            ie.id == IE_EXTENSION && ie.data.len() > 0 && ie.data[0] == 201
                        });

                        if !has_rnr {
                            if let Some(bssid) = get_bssid(frame) {
                                let bssid_mac = format_mac(&bssid);

                                // Mark BSS as 6 GHz
                                let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);
                                bss_stats.is_6ghz = true;

                                // Only report once per BSS
                                if bss_stats.rnr_count == 0 {
                                    let issue = IssueRecord::new(
                                        IssueType::Incomplete6GhzRnr,
                                        timestamp,
                                        packet_number,
                                        engine.frame_count,
                                        IssueLocation {
                                            byte_offset: 24,
                                            field_name: "802.11.beacon.ies".to_string(),
                                            layer: "802.11".to_string(),
                                        },
                                        "6 GHz beacon missing Reduced Neighbor Report (RNR)".to_string(),
                                        vec![bssid_mac],
                                    );
                                    engine.issues.push(issue);
                                }
                            }
                        } else {
                            // Count RNR presence
                            if let Some(bssid) = get_bssid(frame) {
                                let bssid_mac = format_mac(&bssid);
                                let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);
                                bss_stats.rnr_count += 1;
                            }
                        }
                    }
                }
            }
        }
    }
}

/// Issue 17: Detect Channel Switch Announcement (CSA) anomalies
pub fn detect_csa_anomalies(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    // CSA is in beacons and action frames (IE ID 37)
    const IE_CHANNEL_SWITCH_ANNOUNCEMENT: u8 = 37;
    const IE_EXTENDED_CSA: u8 = 60;

    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Beacon | ManagementSubtype::Action) {
            // Check for CSA IE
            for ie in &frame.information_elements {
                if ie.id == IE_CHANNEL_SWITCH_ANNOUNCEMENT || ie.id == IE_EXTENDED_CSA {
                    if ie.data.len() < 3 {
                        if let Some(bssid) = get_bssid(frame) {
                            let issue = IssueRecord::new(
                                IssueType::ChannelSwitchAnomalies,
                                timestamp,
                                packet_number,
                                engine.frame_count,
                                IssueLocation {
                                    byte_offset: 24,
                                    field_name: "802.11.ie.csa".to_string(),
                                    layer: "802.11".to_string(),
                                },
                                "Malformed Channel Switch Announcement (CSA) IE".to_string(),
                                vec![format_mac(&bssid)],
                            );
                            engine.issues.push(issue);
                        }
                    } else {
                        let switch_mode = ie.data[0];
                        let new_channel = ie.data[1];
                        let switch_count = ie.data[2];

                        // Validate CSA parameters
                        if new_channel == 0 || new_channel > 233 {
                            if let Some(bssid) = get_bssid(frame) {
                                let issue = IssueRecord::new(
                                    IssueType::ChannelSwitchAnomalies,
                                    timestamp,
                                    packet_number,
                                    engine.frame_count,
                                    IssueLocation {
                                        byte_offset: 24,
                                        field_name: "802.11.ie.csa.new_channel".to_string(),
                                        layer: "802.11".to_string(),
                                    },
                                    format!(
                                        "Invalid CSA target channel: {} (mode={}, count={})",
                                        new_channel, switch_mode, switch_count
                                    ),
                                    vec![format_mac(&bssid)],
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

/// Issue 18: Detect management frames missing mandatory fields
pub fn detect_missing_mandatory_fields(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    if let Some(subtype) = frame.management_subtype() {
        let mut missing_fields = Vec::new();

        match subtype {
            ManagementSubtype::Beacon | ManagementSubtype::ProbeResponse => {
                // Mandatory IEs for beacons/probe responses: SSID, Supported Rates
                let has_ssid = frame.information_elements.iter().any(|ie| ie.id == IE_SSID);
                let has_supported_rates = frame.information_elements.iter().any(|ie| ie.id == 1);

                if !has_ssid {
                    missing_fields.push("SSID");
                }
                if !has_supported_rates {
                    missing_fields.push("Supported Rates");
                }

                // Check for proper beacon structure (12-byte fixed fields before IEs)
                if frame.payload.len() < 12 {
                    missing_fields.push("Beacon Fixed Fields");
                }
            }

            ManagementSubtype::AssociationRequest | ManagementSubtype::ReassociationRequest => {
                // Mandatory: Capability, Listen Interval, SSID, Supported Rates
                let has_ssid = frame.information_elements.iter().any(|ie| ie.id == IE_SSID);
                let has_supported_rates = frame.information_elements.iter().any(|ie| ie.id == 1);

                if !has_ssid {
                    missing_fields.push("SSID");
                }
                if !has_supported_rates {
                    missing_fields.push("Supported Rates");
                }

                // Check for proper request structure (4 bytes fixed fields)
                if frame.payload.len() < 4 {
                    missing_fields.push("Association Request Fixed Fields");
                }
            }

            ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse => {
                // Mandatory: Capability, Status Code, AID, Supported Rates
                let has_supported_rates = frame.information_elements.iter().any(|ie| ie.id == 1);

                if !has_supported_rates {
                    missing_fields.push("Supported Rates");
                }

                // Check for proper response structure (6 bytes fixed fields)
                if frame.payload.len() < 6 {
                    missing_fields.push("Association Response Fixed Fields");
                }
            }

            _ => {}
        }

        if !missing_fields.is_empty() {
            if let Some(src) = get_source_addr(frame) {
                let issue = IssueRecord::new(
                    IssueType::MissingMandatoryFields,
                    timestamp,
                    packet_number,
                    engine.frame_count,
                    IssueLocation {
                        byte_offset: 24,
                        field_name: "802.11.mgmt".to_string(),
                        layer: "802.11".to_string(),
                    },
                    format!(
                        "{:?} frame missing mandatory fields: {}",
                        subtype,
                        missing_fields.join(", ")
                    ),
                    vec![format_mac(&src)],
                );
                engine.issues.push(issue);
            }
        }
    }
}
