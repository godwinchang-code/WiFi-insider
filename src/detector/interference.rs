use crate::detector::DetectorEngine;
use crate::types::{Dot11Frame, IssueRecord, IssueLocation, IssueType};
use crate::parser::dot11::get_bssid;
use crate::types::frame::{format_mac, ManagementSubtype};
use crate::parser::radiotap::{freq_to_channel, is_6ghz};
use std::collections::{HashMap, HashSet};

// Thresholds
const CO_CHANNEL_BSS_THRESHOLD: usize = 10;  // More than 10 BSSs on same channel = excessive
const ADJACENT_CHANNEL_POWER_RATIO: f64 = 0.3; // 30% of power on adjacent channel = interference
const OBSS_FRAME_RATIO_THRESHOLD: f64 = 0.5;   // > 50% frames from OBSS = degradation

/// Issue 30: Detect excessive co-channel interference
pub fn detect_co_channel_interference(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    _packet_number: u64,
    timestamp: f64,
) {
    // Track unique BSSs per channel from beacons
    if let Some(subtype) = frame.management_subtype() {
        if matches!(subtype, ManagementSubtype::Beacon) {
            if let (Some(bssid), Some(rt)) = (get_bssid(frame), &frame.radiotap) {
                if let Some(freq) = rt.channel_freq {
                    if let Some(channel) = freq_to_channel(freq) {
                        let bssid_mac = format_mac(&bssid);

                        // Track BSS on this channel
                        let ch_stats = engine.stats.get_or_create_channel(channel);
                        ch_stats.frame_count += 1;

                        // Track time (approximate based on frame timestamps)
                        if ch_stats.total_time_us == 0 {
                            ch_stats.total_time_us = (timestamp * 1_000_000.0) as u64;
                        } else {
                            let current_time = (timestamp * 1_000_000.0) as u64;
                            if current_time > ch_stats.total_time_us {
                                ch_stats.total_time_us = current_time;
                            }
                        }

                        // Update BSS stats
                        let bss_stats = engine.stats.get_or_create_bss(&bssid_mac);
                        bss_stats.channel = Some(channel);
                    }
                }
            }
        }
    }
}

/// Issue 31: Detect adjacent channel interference
pub fn detect_adjacent_channel_interference(
    engine: &mut DetectorEngine,
    frame: &Dot11Frame,
    packet_number: u64,
    timestamp: f64,
) {
    // Detect frames received on adjacent channels with significant signal strength
    if let Some(rt) = &frame.radiotap {
        if let (Some(freq), Some(signal)) = (rt.channel_freq, rt.signal) {
            if let Some(primary_channel) = freq_to_channel(freq) {
                // Check if signal is strong (> -70 dBm is considered strong interference)
                if signal > -70 {
                    // In a real capture, we'd need to know the configured channel
                    // For detection, we look for frames that are clearly on adjacent channels
                    // but still being received strongly

                    // This is more complex and would require knowing the AP's configured channel
                    // versus the channel tag in beacons. For now, we'll detect based on
                    // channel tags versus radiotap frequency mismatches.

                    if let Some(subtype) = frame.management_subtype() {
                        if matches!(subtype, ManagementSubtype::Beacon) {
                            // Check DSSS Parameter Set IE for channel number
                            const IE_DSSS_PARAMETER: u8 = 3;

                            for ie in &frame.information_elements {
                                if ie.id == IE_DSSS_PARAMETER && ie.data.len() == 1 {
                                    let advertised_channel = ie.data[0];

                                    // If radiotap channel != advertised channel, potential bleed
                                    if advertised_channel != primary_channel {
                                        let channel_diff = (advertised_channel as i16 - primary_channel as i16).abs();

                                        // Adjacent channels are within 1-2 channels
                                        if channel_diff > 0 && channel_diff <= 2 {
                                            if let Some(bssid) = get_bssid(frame) {
                                                let issue = IssueRecord::new(
                                                    IssueType::AdjacentChannelInterference,
                                                    timestamp,
                                                    packet_number,
                                                    engine.frame_count,
                                                    IssueLocation {
                                                        byte_offset: 0,
                                                        field_name: "radiotap.channel".to_string(),
                                                        layer: "radiotap".to_string(),
                                                    },
                                                    format!(
                                                        "Beacon from channel {} detected on channel {} with signal {}dBm",
                                                        advertised_channel, primary_channel, signal
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
            }
        }
    }
}

/// Issue 32: Detect OBSS-induced scheduling degradation
pub fn detect_obss_degradation(
    engine: &mut DetectorEngine,
    _frame: &Dot11Frame,
    _packet_number: u64,
    _timestamp: f64,
) {
    // This is analyzed in finalize_interference_analysis
}

/// Finalize interference analysis
pub fn finalize_interference_analysis(engine: &mut DetectorEngine) {
    // Issue 30: Detect excessive co-channel interference based on BSS density
    let mut channel_bss_count: HashMap<u8, HashSet<String>> = HashMap::new();

    for (bssid, bss_stats) in &engine.stats.bss {
        if let Some(channel) = bss_stats.channel {
            channel_bss_count
                .entry(channel)
                .or_insert_with(HashSet::new)
                .insert(bssid.clone());
        }
    }

    for (channel, bss_set) in &channel_bss_count {
        if bss_set.len() > CO_CHANNEL_BSS_THRESHOLD {
            let bss_list: Vec<String> = bss_set.iter().take(5).cloned().collect();

            let issue = IssueRecord::new(
                IssueType::ExcessiveCoChannelInterference,
                engine.stats.end_time,
                0,
                0,
                IssueLocation {
                    byte_offset: 0,
                    field_name: format!("analysis.channel_{}_density", channel),
                    layer: "analysis".to_string(),
                },
                format!(
                    "Channel {} has {} co-channel BSSs (threshold: {}). Sample: {}...",
                    channel,
                    bss_set.len(),
                    CO_CHANNEL_BSS_THRESHOLD,
                    bss_list.join(", ")
                ),
                vec![],
            );
            engine.issues.push(issue);
        }
    }

    // Issue 32: Detect OBSS-induced scheduling degradation
    // Analyze per-BSS to see if there's high OBSS traffic

    // Build a map of primary BSSs (those with most traffic) per channel
    let mut channel_primary_bss: HashMap<u8, String> = HashMap::new();
    let mut channel_bss_frames: HashMap<u8, Vec<(String, u64)>> = HashMap::new();

    for (bssid, bss_stats) in &engine.stats.bss {
        if let Some(channel) = bss_stats.channel {
            channel_bss_frames
                .entry(channel)
                .or_insert_with(Vec::new)
                .push((bssid.clone(), bss_stats.beacon_count));
        }
    }

    // Find primary BSS (most beacons) per channel
    for (channel, bss_list) in &mut channel_bss_frames {
        bss_list.sort_by(|a, b| b.1.cmp(&a.1));

        if let Some((primary_bssid, primary_count)) = bss_list.first() {
            channel_primary_bss.insert(*channel, primary_bssid.clone());

            // Calculate OBSS ratio
            let total_beacons: u64 = bss_list.iter().map(|(_, count)| count).sum();
            let obss_beacons = total_beacons - primary_count;
            let obss_ratio = obss_beacons as f64 / total_beacons as f64;

            if bss_list.len() > 1 && obss_ratio > OBSS_FRAME_RATIO_THRESHOLD {
                let issue = IssueRecord::new(
                    IssueType::ObssSchedulingDegradation,
                    engine.stats.end_time,
                    0,
                    0,
                    IssueLocation {
                        byte_offset: 0,
                        field_name: format!("analysis.channel_{}_obss", channel),
                        layer: "analysis".to_string(),
                    },
                    format!(
                        "Channel {} has high OBSS traffic: {:.1}% ({} OBSS BSSs, primary: {})",
                        channel,
                        obss_ratio * 100.0,
                        bss_list.len() - 1,
                        primary_bssid
                    ),
                    vec![primary_bssid.clone()],
                );
                engine.issues.push(issue);
            }
        }
    }

    // Additional OBSS detection: Check for HE spatial reuse issues
    // If BSS Color is not being used effectively, OBSS can't be managed well
    let mut color_usage: HashMap<u8, Vec<String>> = HashMap::new();

    for (bssid, bss_stats) in &engine.stats.bss {
        if let Some(color) = bss_stats.bss_color {
            if color > 0 && color < 63 {
                color_usage
                    .entry(color)
                    .or_insert_with(Vec::new)
                    .push(bssid.clone());
            }
        }
    }

    // Detect BSS Color collisions (same color on same/overlapping channels)
    for (color, bss_list) in &color_usage {
        if bss_list.len() > 1 {
            // Check if these BSSs are on the same or overlapping channels
            let mut channels_for_color: HashSet<u8> = HashSet::new();

            for bssid in bss_list {
                if let Some(bss_stats) = engine.stats.bss.get(bssid) {
                    if let Some(ch) = bss_stats.channel {
                        channels_for_color.insert(ch);
                    }
                }
            }

            // If multiple BSSs with same color on same channel, that's a problem
            for channel in channels_for_color {
                let same_channel_bss: Vec<String> = bss_list
                    .iter()
                    .filter(|bssid| {
                        engine.stats.bss
                            .get(*bssid)
                            .and_then(|s| s.channel)
                            .map_or(false, |ch| ch == channel)
                    })
                    .cloned()
                    .collect();

                if same_channel_bss.len() > 1 {
                    let issue = IssueRecord::new(
                        IssueType::ObssSchedulingDegradation,
                        engine.stats.end_time,
                        0,
                        0,
                        IssueLocation {
                            byte_offset: 0,
                            field_name: "analysis.bss_color_collision".to_string(),
                            layer: "analysis".to_string(),
                        },
                        format!(
                            "BSS Color {} collision on channel {}: {} BSSs using same color (reduces OBSS mitigation)",
                            color,
                            channel,
                            same_channel_bss.len()
                        ),
                        same_channel_bss,
                    );
                    engine.issues.push(issue);
                }
            }
        }
    }
}
