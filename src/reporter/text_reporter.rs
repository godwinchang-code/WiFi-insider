use crate::reporter::AnalysisReport;
use crate::types::{IssueCategory, IssueSeverity};
use anyhow::Result;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate text report
pub fn generate_text_report<P: AsRef<Path>>(report: &AnalysisReport, output_path: P) -> Result<()> {
    let text = format_text_report(report);

    let mut file = File::create(output_path)?;
    file.write_all(text.as_bytes())?;

    Ok(())
}

/// Print text report to stdout
pub fn print_text_report(report: &AnalysisReport) {
    println!("{}", format_text_report(report));
}

/// Format a text report
fn format_text_report(report: &AnalysisReport) -> String {
    let mut output = String::new();

    // Header
    output.push_str("═══════════════════════════════════════════════════════════════\n");
    output.push_str("          WiFi Insider - Wi-Fi 7 Packet Analysis Report        \n");
    output.push_str("═══════════════════════════════════════════════════════════════\n\n");

    // Summary
    let summary = report.summary();
    output.push_str(&format_summary(&summary));
    output.push_str("\n");

    // Issues by severity
    output.push_str("───────────────────────────────────────────────────────────────\n");
    output.push_str("                      DETECTED ISSUES                           \n");
    output.push_str("───────────────────────────────────────────────────────────────\n\n");

    let by_severity = report.issues_by_severity();

    // High severity issues first
    if let Some(high_issues) = by_severity.get(&IssueSeverity::High) {
        if !high_issues.is_empty() {
            output.push_str("🔴 HIGH SEVERITY ISSUES\n");
            output.push_str("─────────────────────────────────────────────────────────\n");
            for issue in high_issues {
                output.push_str(&format!("  {}\n", issue));
            }
            output.push_str("\n");
        }
    }

    // Medium severity issues
    if let Some(medium_issues) = by_severity.get(&IssueSeverity::Medium) {
        if !medium_issues.is_empty() {
            output.push_str("🟡 MEDIUM SEVERITY ISSUES\n");
            output.push_str("─────────────────────────────────────────────────────────\n");
            for issue in medium_issues {
                output.push_str(&format!("  {}\n", issue));
            }
            output.push_str("\n");
        }
    }

    // Low severity issues
    if let Some(low_issues) = by_severity.get(&IssueSeverity::Low) {
        if !low_issues.is_empty() {
            output.push_str("🟢 LOW SEVERITY ISSUES\n");
            output.push_str("─────────────────────────────────────────────────────────\n");
            for issue in low_issues {
                output.push_str(&format!("  {}\n", issue));
            }
            output.push_str("\n");
        }
    }

    // Issues by category
    output.push_str("───────────────────────────────────────────────────────────────\n");
    output.push_str("                   ISSUES BY CATEGORY                          \n");
    output.push_str("───────────────────────────────────────────────────────────────\n\n");

    let by_category = report.issues_by_category();
    let issue_counts = report.issue_counts();

    for (category, category_issues) in &by_category {
        let category_name = match category {
            IssueCategory::PhyMacEht => "PHY/MAC/EHT Capability & Scheduling",
            IssueCategory::SpectrumSharing => "Spectrum Sharing / Coordination",
            IssueCategory::AuthenticationSecurity => "Authentication / Association / Security",
            IssueCategory::RoamingMobility => "Roaming & Mobility (802.11k/v/r)",
            IssueCategory::Interference => "Interference / Multi-BSS Behavioral",
        };

        output.push_str(&format!("📊 {} ({} issues)\n", category_name, category_issues.len()));
        output.push_str("─────────────────────────────────────────────────────────\n");

        // Group by issue type within category
        let mut type_counts = std::collections::HashMap::new();
        for issue in category_issues.iter() {
            *type_counts.entry(issue.issue_type).or_insert(0) += 1;
        }

        let mut sorted_types: Vec<_> = type_counts.iter().collect();
        sorted_types.sort_by(|a, b| b.1.cmp(a.1));

        for (issue_type, count) in sorted_types {
            output.push_str(&format!(
                "  • {} ({}): {} occurrence(s)\n",
                issue_type.description(),
                issue_type.severity(),
                count
            ));
        }
        output.push_str("\n");
    }

    // Statistics
    output.push_str("───────────────────────────────────────────────────────────────\n");
    output.push_str("                     CAPTURE STATISTICS                        \n");
    output.push_str("───────────────────────────────────────────────────────────────\n\n");

    output.push_str(&format_statistics(report));

    // Footer
    output.push_str("\n═══════════════════════════════════════════════════════════════\n");
    output.push_str("                      End of Report                             \n");
    output.push_str("═══════════════════════════════════════════════════════════════\n");

    output
}

fn format_summary(summary: &crate::reporter::ReportSummary) -> String {
    let mut output = String::new();

    output.push_str("SUMMARY\n");
    output.push_str("─────────────────────────────────────────────────────────\n");
    output.push_str(&format!("  Total Issues Found:     {}\n", summary.total_issues));
    output.push_str(&format!("    High Severity:        {}\n", summary.high_severity));
    output.push_str(&format!("    Medium Severity:      {}\n", summary.medium_severity));
    output.push_str(&format!("    Low Severity:         {}\n", summary.low_severity));
    output.push_str("\n");
    output.push_str(&format!("  Total Packets:          {}\n", summary.total_packets));
    output.push_str(&format!("  Total Frames:           {}\n", summary.total_frames));
    output.push_str(&format!("  Capture Duration:       {:.2}s\n", summary.duration));
    output.push_str(&format!("  Unique Stations:        {}\n", summary.unique_stations));
    output.push_str(&format!("  Unique BSSs:            {}\n", summary.unique_bss));
    output.push_str(&format!("  Channels Analyzed:      {}\n", summary.channels_analyzed));

    output
}

fn format_statistics(report: &AnalysisReport) -> String {
    let mut output = String::new();

    // Top stations by frame count
    output.push_str("Top 10 Stations by Frame Count:\n");
    let mut stations: Vec<_> = report.stats.stations.iter().collect();
    stations.sort_by(|a, b| b.1.frame_count.cmp(&a.1.frame_count));

    for (i, (mac, stats)) in stations.iter().take(10).enumerate() {
        output.push_str(&format!(
            "  {}. {} - {} frames ({:.1}% retry rate)\n",
            i + 1,
            mac,
            stats.frame_count,
            stats.retry_rate() * 100.0
        ));
    }
    output.push_str("\n");

    // BSSs
    output.push_str("Detected BSSs:\n");
    let mut bss_list: Vec<_> = report.stats.bss.iter().collect();
    bss_list.sort_by(|a, b| b.1.beacon_count.cmp(&a.1.beacon_count));

    for (mac, stats) in bss_list.iter().take(10) {
        let ssid = stats.ssid.as_deref().unwrap_or("<hidden>");
        let channel = stats.channel.map_or("?".to_string(), |c| c.to_string());
        let security = if stats.wpa3_sae {
            "WPA3-SAE"
        } else if stats.owe {
            "OWE"
        } else {
            "Other"
        };

        output.push_str(&format!(
            "  • {} (SSID: {}) - Ch {} - {} - {} beacons\n",
            mac, ssid, channel, security, stats.beacon_count
        ));

        if stats.eht_capable {
            output.push_str(&format!(
                "    EHT capable, Max BW: {} MHz\n",
                stats.max_bandwidth.unwrap_or(0)
            ));
        }
    }
    output.push_str("\n");

    // Channel utilization
    output.push_str("Channel Utilization:\n");
    let mut channels: Vec<_> = report.stats.channels.iter().collect();
    channels.sort_by_key(|(ch, _)| *ch);

    for (channel, stats) in channels {
        output.push_str(&format!(
            "  Channel {}: {} frames, {} BSSs\n",
            channel, stats.frame_count, stats.bss_count
        ));
    }

    output
}
