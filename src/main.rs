mod parser;
mod types;
mod detector;
mod reporter;

use anyhow::{Context, Result};
use clap::Parser;
use log::{info, warn, error};
use std::path::PathBuf;

use parser::pcap_reader::WifiPcapReader;
use parser::dot11::parse_dot11_frame;
use detector::DetectorEngine;
use reporter::{AnalysisReport, text_reporter, json_reporter};

#[derive(Parser, Debug)]
#[command(name = "wifi-insider")]
#[command(version = "0.1.0")]
#[command(about = "Wi-Fi 7 packet analyzer - detects PHY/MAC/EHT issues from pcap files", long_about = None)]
struct Args {
    /// Input pcap file to analyze
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    /// Output format: text, json, or both
    #[arg(short, long, value_name = "FORMAT", default_value = "text")]
    format: String,

    /// Output file (if not specified, prints to stdout)
    #[arg(short, long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// JSON output file (when using 'both' format)
    #[arg(long, value_name = "FILE")]
    json_output: Option<PathBuf>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Only show issues of specified severity or higher (low, medium, high)
    #[arg(long, value_name = "SEVERITY")]
    min_severity: Option<String>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logger
    let log_level = if args.verbose {
        "debug"
    } else {
        "info"
    };

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
        .init();

    info!("WiFi Insider - Wi-Fi 7 Packet Analyzer");
    info!("Opening pcap file: {:?}", args.input);

    // Open pcap file
    let mut pcap_reader = WifiPcapReader::open(&args.input)
        .with_context(|| format!("Failed to open pcap file: {:?}", args.input))?;

    let has_radiotap = pcap_reader.has_radiotap();
    info!("Link type: {} (Radiotap: {})",
        if has_radiotap { "IEEE 802.11 + Radiotap" } else { "IEEE 802.11" },
        has_radiotap
    );

    // Create detector engine
    let mut engine = DetectorEngine::new();

    info!("Starting packet analysis...");

    let mut processed_packets = 0;
    let mut parse_errors = 0;

    // Process all packets
    while let Some(packet) = pcap_reader.next_packet()? {
        processed_packets += 1;

        if processed_packets % 1000 == 0 {
            info!("Processed {} packets, {} frames, {} issues detected",
                processed_packets,
                engine.frame_count,
                engine.issues.len()
            );
        }

        // Update stats
        engine.stats.total_packets = processed_packets;

        // Parse 802.11 frame
        match parse_dot11_frame(&packet.data, has_radiotap) {
            Ok(frame) => {
                // Process frame through detector engine
                engine.process_frame(&frame, packet.packet_number, packet.timestamp);
            }
            Err(e) => {
                parse_errors += 1;
                if parse_errors <= 10 {
                    warn!("Failed to parse packet #{}: {}", packet.packet_number, e);
                }
            }
        }
    }

    info!("Packet processing complete");
    info!("Total packets: {}, Frames analyzed: {}, Parse errors: {}",
        processed_packets,
        engine.frame_count,
        parse_errors
    );

    // Finalize analysis
    info!("Finalizing analysis...");
    engine.finalize_analysis();

    info!("Analysis complete. Total issues found: {}", engine.issues.len());

    // Filter issues by severity if requested
    let mut issues = engine.issues.clone();
    if let Some(min_sev) = &args.min_severity {
        let min_severity = match min_sev.to_lowercase().as_str() {
            "low" => types::IssueSeverity::Low,
            "medium" => types::IssueSeverity::Medium,
            "high" => types::IssueSeverity::High,
            _ => {
                error!("Invalid severity level: {}. Use 'low', 'medium', or 'high'", min_sev);
                return Ok(());
            }
        };

        issues.retain(|issue| issue.severity >= min_severity);
        info!("Filtered to {} issues with severity >= {:?}", issues.len(), min_severity);
    }

    // Sort issues by timestamp
    issues.sort_by(|a, b| {
        a.timestamp.partial_cmp(&b.timestamp).unwrap_or(std::cmp::Ordering::Equal)
    });

    // Create report
    let report = AnalysisReport::new(issues, engine.stats.clone());

    // Generate output
    match args.format.to_lowercase().as_str() {
        "text" => {
            if let Some(output_path) = args.output {
                info!("Writing text report to: {:?}", output_path);
                text_reporter::generate_text_report(&report, output_path)?;
            } else {
                text_reporter::print_text_report(&report);
            }
        }
        "json" => {
            if let Some(output_path) = args.output {
                info!("Writing JSON report to: {:?}", output_path);
                json_reporter::generate_structured_json(&report, output_path)?;
            } else {
                json_reporter::print_json_report(&report)?;
            }
        }
        "both" => {
            // Text to stdout or file
            if let Some(output_path) = &args.output {
                info!("Writing text report to: {:?}", output_path);
                text_reporter::generate_text_report(&report, output_path)?;
            } else {
                text_reporter::print_text_report(&report);
            }

            // JSON to separate file
            if let Some(json_path) = args.json_output {
                info!("Writing JSON report to: {:?}", json_path);
                json_reporter::generate_structured_json(&report, json_path)?;
            } else {
                let json_path = args.input.with_extension("json");
                info!("Writing JSON report to: {:?}", json_path);
                json_reporter::generate_structured_json(&report, json_path)?;
            }
        }
        _ => {
            error!("Invalid output format: {}. Use 'text', 'json', or 'both'", args.format);
        }
    }

    info!("Analysis complete!");

    Ok(())
}
