# WiFi Insider - Wi-Fi 7 Packet Analyzer

A comprehensive Wi-Fi 7 (802.11be) packet analyzer built in Rust for OpenWrt platforms. Analyzes over-the-air captured packets (pcap files) to identify and diagnose 32 different Wi-Fi 7 issues across PHY, MAC, security, roaming, and interference domains.

## Features

### Detectable Issues (32 Total)

#### PHY / MAC / EHT Capability & Scheduling (14 issues)
1. Modulation fallback (MCS downgrade)
2. Insufficient spatial streams (NSS mismatch)
3. Channel bandwidth mismatch (20/40/80/160/320 MHz)
4. Improper EHT RU allocation
5. Low downlink OFDMA trigger rate
6. Low uplink OFDMA trigger rate
7. Low MU-MIMO utilization
8. High frame retry rate
9. High channel utilization (busy medium)
10. CCA busy causing scheduling degradation
11. Abnormal PPDU type selection
12. Incomplete EHT capability negotiation
13. Client negotiating less than 320 MHz (e.g., 160 MHz only)
14. MLO negotiation failure or not triggered

#### Spectrum Sharing / Coordination Features (4 issues)
15. Ineffective BSS Coloring behavior
16. Incomplete 6 GHz Reduced Neighbor Report (RNR)
17. Channel Switch Announcement (CSA) anomalies
18. Management frames missing mandatory fields

#### Authentication / Association / Security (4 issues)
19. WPA3-SAE authentication failure (with status codes)
20. OWE negotiation failure
21. Association rejection with reason codes
22. 6 GHz association failure due to security policy

#### Roaming & Mobility (802.11k/v/r) (7 issues)
23. High roaming latency (slow reassociation)
24. 802.11r FT not triggered or failing
25. Abnormal 802.11k neighbor reports
26. Abnormal 802.11v BSS Transition behavior
27. Sticky client behavior visible in scan/association pattern
28. Abnormal Probe Request / Probe Response behavior
29. Abnormal Beacon scanning or selection behavior

#### Interference / Multi-BSS Behavioral (3 issues)
30. Excessive co-channel interference (dense beacon presence)
31. Observable adjacent channel interference
32. OBSS-induced scheduling degradation

## Building

### Prerequisites

- Rust 1.70 or later
- Cargo (comes with Rust)

### For OpenWrt

```bash
# Install Rust for OpenWrt cross-compilation
rustup target add mips-unknown-linux-musl      # For MIPS routers
# Or
rustup target add aarch64-unknown-linux-musl   # For ARM64 routers
# Or
rustup target add arm-unknown-linux-musleabi   # For ARM routers

# Build for OpenWrt
cargo build --release --target mips-unknown-linux-musl
```

### For Native Systems (Linux/macOS)

```bash
# Clone the repository
git clone https://github.com/yourusername/WiFi-insider.git
cd WiFi-insider

# Build in release mode (optimized)
cargo build --release

# The binary will be in target/release/wifi-insider
```

### For Development

```bash
# Build in debug mode
cargo build

# Run tests
cargo test

# Run with verbose logging
cargo run -- --input capture.pcap --verbose
```

## Usage

### Basic Usage

```bash
# Analyze a pcap file and display results as text
wifi-insider --input /path/to/capture.pcap

# Generate JSON output
wifi-insider --input capture.pcap --format json

# Save output to file
wifi-insider --input capture.pcap --output report.txt

# Generate both text and JSON reports
wifi-insider --input capture.pcap --format both --output report.txt --json-output report.json
```

### Advanced Options

```bash
# Show only high-severity issues
wifi-insider --input capture.pcap --min-severity high

# Show medium and high-severity issues
wifi-insider --input capture.pcap --min-severity medium

# Enable verbose logging
wifi-insider --input capture.pcap --verbose

# Full example with all options
wifi-insider \
  --input /var/log/wifi/capture.pcap \
  --format both \
  --output /tmp/wifi-analysis.txt \
  --json-output /tmp/wifi-analysis.json \
  --min-severity medium \
  --verbose
```

### Command-Line Options

```
Options:
  -i, --input <FILE>          Input pcap file to analyze
  -f, --format <FORMAT>       Output format: text, json, or both [default: text]
  -o, --output <FILE>         Output file (if not specified, prints to stdout)
      --json-output <FILE>    JSON output file (when using 'both' format)
  -v, --verbose               Enable verbose logging
      --min-severity <SEVERITY> Only show issues of specified severity or higher (low, medium, high)
  -h, --help                  Print help
  -V, --version               Print version
```

## Capturing Wi-Fi Packets on OpenWrt

To capture Wi-Fi packets for analysis:

### Method 1: Using tcpdump

```bash
# Put interface in monitor mode
iw dev wlan0 interface add mon0 type monitor
ifconfig mon0 up

# Capture packets
tcpdump -i mon0 -w /tmp/wifi-capture.pcap

# Stop capture with Ctrl+C, then analyze
wifi-insider --input /tmp/wifi-capture.pcap
```

### Method 2: Using tshark

```bash
# Install tshark on OpenWrt
opkg update
opkg install tshark

# Capture with radiotap headers
tshark -i wlan0 -w /tmp/capture.pcap -F pcap

# Analyze
wifi-insider --input /tmp/capture.pcap
```

## Understanding the Output

### Text Report Format

The text report includes:

1. **Summary** - Overview of total issues, packets, frames, and capture duration
2. **Detected Issues** - Organized by severity (High, Medium, Low)
3. **Issues by Category** - Grouped by functionality (PHY/MAC, Security, Roaming, etc.)
4. **Capture Statistics** - Top stations, BSSs, channel utilization

Example output:

```
═══════════════════════════════════════════════════════════════
          WiFi Insider - Wi-Fi 7 Packet Analysis Report
═══════════════════════════════════════════════════════════════

SUMMARY
─────────────────────────────────────────────────────────
  Total Issues Found:     42
    High Severity:        8
    Medium Severity:      24
    Low Severity:         10

  Total Packets:          15234
  Total Frames:           15180
  Capture Duration:       60.45s
  Unique Stations:        12
  Unique BSSs:            5
  Channels Analyzed:      3

───────────────────────────────────────────────────────────────
                      DETECTED ISSUES
───────────────────────────────────────────────────────────────

🔴 HIGH SEVERITY ISSUES
─────────────────────────────────────────────────────────
  [HIGH] High frame retry rate @ packet #4532 (frame #4500, offset 0, analysis.retry_rate) - Retry rate 18.2% (820 retries / 4500 frames)
  ...
```

### JSON Report Format

The JSON report provides machine-readable structured data:

```json
{
  "summary": {
    "total_issues": 42,
    "high_severity": 8,
    "medium_severity": 24,
    "low_severity": 10,
    "total_packets": 15234,
    "total_frames": 15180,
    "duration_seconds": 60.45,
    "unique_stations": 12,
    "unique_bss": 5,
    "channels_analyzed": 3
  },
  "issues": [
    {
      "issue_type": "HighFrameRetryRate",
      "severity": "High",
      "timestamp": 1234567890.123,
      "packet_number": 4532,
      "frame_number": 4500,
      "location": {
        "byte_offset": 0,
        "field_name": "analysis.retry_rate",
        "layer": "analysis"
      },
      "details": "Retry rate 18.2% (820 retries / 4500 frames)",
      "related_addrs": ["aa:bb:cc:dd:ee:ff"]
    }
  ],
  "statistics": {
    "stations": { ... },
    "bss": { ... },
    "channels": { ... }
  }
}
```

## Architecture

### Module Structure

```
wifi-insider/
├── src/
│   ├── main.rs              # CLI application entry point
│   ├── parser/              # Packet parsing modules
│   │   ├── pcap_reader.rs   # PCAP file reader
│   │   ├── radiotap.rs      # Radiotap header parser
│   │   ├── dot11.rs         # 802.11 frame parser
│   │   └── ie_parser.rs     # Information Element parser
│   ├── types/               # Data structures
│   │   ├── issue.rs         # Issue types and records
│   │   ├── frame.rs         # Frame structures
│   │   └── stats.rs         # Statistics tracking
│   ├── detector/            # Issue detection engines
│   │   ├── detector_engine.rs  # Main detection coordinator
│   │   ├── phy_mac_eht.rs      # PHY/MAC/EHT detectors
│   │   ├── spectrum.rs         # Spectrum sharing detectors
│   │   ├── auth_security.rs    # Authentication/security detectors
│   │   ├── roaming.rs          # Roaming/mobility detectors
│   │   └── interference.rs     # Interference detectors
│   └── reporter/            # Output generation
│       ├── output.rs        # Report structures
│       ├── text_reporter.rs # Text output formatter
│       └── json_reporter.rs # JSON output formatter
├── Cargo.toml               # Rust dependencies
└── README.md                # This file
```

## Detection Methodology

Each issue detector uses specific thresholds and patterns:

- **MCS Downgrade**: Detects when MCS drops by 2 or more levels
- **High Retry Rate**: Triggers when retry rate exceeds 15%
- **Low MU-MIMO**: Flags when MU-MIMO usage is below 10%
- **BSS Coloring**: Validates color ranges and detects conflicts
- **WPA3 Failures**: Identifies authentication failures with status codes
- **Roaming Latency**: Detects reassociation delays over 50ms
- **Co-channel Interference**: Counts overlapping BSSs (threshold: 10)

## Performance

- **Processing Speed**: ~10,000-50,000 packets/second (depending on CPU)
- **Memory Usage**: Scales with unique stations/BSSs (typically < 100MB for normal captures)
- **Binary Size**: ~3MB (release build with optimization)

## Limitations

- Requires Radiotap headers for full Wi-Fi 7 analysis
- EHT information parsing depends on capture tool support
- Cannot decrypt encrypted frames (analyzes management and control frames)
- Real-time capture analysis not yet supported (file-based only)

## Contributing

Contributions are welcome! Areas for improvement:

1. Additional detectors for emerging Wi-Fi 7 features
2. Real-time capture support
3. Integration with network management systems
4. GUI interface
5. Performance optimizations

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Based on IEEE 802.11be (Wi-Fi 7) specifications
- Uses the Rust pcap and pnet libraries for packet processing
- Designed for OpenWrt embedded environments

## Support

For issues, questions, or feature requests, please open an issue on GitHub.

## Version History

- **0.1.0** (2026-01-18) - Initial release
  - Support for all 32 Wi-Fi 7 issue types
  - Text and JSON reporting
  - Comprehensive statistics tracking
  - CLI interface with filtering options
