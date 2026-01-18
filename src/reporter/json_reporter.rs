use crate::reporter::AnalysisReport;
use anyhow::Result;
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Generate JSON report
pub fn generate_json_report<P: AsRef<Path>>(report: &AnalysisReport, output_path: P) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;

    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}

/// Generate JSON output to stdout
pub fn print_json_report(report: &AnalysisReport) -> Result<()> {
    let json = serde_json::to_string_pretty(report)?;
    println!("{}", json);
    Ok(())
}

use serde::Serialize;

#[derive(Serialize)]
struct JsonReport<'a> {
    summary: JsonSummary,
    issues: &'a Vec<crate::types::IssueRecord>,
    statistics: JsonStatistics<'a>,
}

#[derive(Serialize)]
struct JsonSummary {
    total_issues: usize,
    high_severity: usize,
    medium_severity: usize,
    low_severity: usize,
    total_packets: u64,
    total_frames: u64,
    duration_seconds: f64,
    unique_stations: usize,
    unique_bss: usize,
    channels_analyzed: usize,
}

#[derive(Serialize)]
struct JsonStatistics<'a> {
    stations: &'a std::collections::HashMap<String, crate::types::StationStats>,
    bss: &'a std::collections::HashMap<String, crate::types::BssStats>,
    channels: &'a std::collections::HashMap<u8, crate::types::ChannelStats>,
}

/// Generate structured JSON report
pub fn generate_structured_json<P: AsRef<Path>>(
    report: &AnalysisReport,
    output_path: P,
) -> Result<()> {
    let summary = report.summary();

    let json_report = JsonReport {
        summary: JsonSummary {
            total_issues: summary.total_issues,
            high_severity: summary.high_severity,
            medium_severity: summary.medium_severity,
            low_severity: summary.low_severity,
            total_packets: summary.total_packets,
            total_frames: summary.total_frames,
            duration_seconds: summary.duration,
            unique_stations: summary.unique_stations,
            unique_bss: summary.unique_bss,
            channels_analyzed: summary.channels_analyzed,
        },
        issues: &report.issues,
        statistics: JsonStatistics {
            stations: &report.stats.stations,
            bss: &report.stats.bss,
            channels: &report.stats.channels,
        },
    };

    let json = serde_json::to_string_pretty(&json_report)?;

    let mut file = File::create(output_path)?;
    file.write_all(json.as_bytes())?;

    Ok(())
}
