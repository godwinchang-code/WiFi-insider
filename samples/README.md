# Sample PCAP Files

This directory contains sample Wi-Fi packet capture files in PCAP format for testing the Wi-Fi 7 packet analyzer.

## Sample Files

### 1. wifi7_complete_sample.pcap
**Size**: ~227 bytes
**Packets**: 3 packets
**Description**: Complete sample with different packet types for comprehensive testing

**Contents**:
- 1x Beacon frame from AP (BSSID: 00:11:22:33:44:55, SSID: "TestWiFi")
- 1x Probe Request from client (MAC: aa:bb:cc:dd:ee:ff)
- 1x Association Request from client to AP

**Use case**: End-to-end testing of the analyzer with multiple frame types

### 2. wifi7_beacon_sample.pcap
**Size**: ~419 bytes
**Packets**: 5 packets
**Description**: Multiple beacon frames from the same AP

**Contents**:
- 5x Beacon frames from AP (BSSID: 00:11:22:33:44:55, SSID: "TestWiFi")
- Channel 6 (2.4 GHz)
- Beacon interval: 100 TUs

**Use case**: Testing beacon processing, timing analysis, and BSS statistics

### 3. wifi7_probe_sample.pcap
**Size**: ~192 bytes
**Packets**: 3 packets
**Description**: Multiple probe request frames from a client

**Contents**:
- 3x Probe Request frames from client (MAC: aa:bb:cc:dd:ee:ff)
- Wildcard SSID (active scanning)

**Use case**: Testing probe request handling and client discovery

## File Format

All sample files use the standard PCAP format:
- **Format**: PCAP (not PCAP-NG)
- **Version**: 2.4
- **Link-layer type**: 127 (IEEE 802.11 Radiotap)
- **Snapshot length**: 65535 bytes

Each packet includes:
- Radiotap header (minimal, 8 bytes)
- 802.11 MAC header
- Frame body with Information Elements where applicable

## Usage

### Analyze a sample file:
```bash
cargo run -- samples/wifi7_complete_sample.pcap --output-format text
```

### Analyze with JSON output:
```bash
cargo run -- samples/wifi7_beacon_sample.pcap --output-format json > analysis.json
```

### Run tests with sample files:
```bash
cargo test pcap_file_test
```

## Technical Details

### Frame Structure

**Beacon Frame**:
- Frame Control: 0x0080 (Management, Subtype 8)
- Addresses: Broadcast (DA), BSSID (SA), BSSID (BSSID)
- Fixed fields: Timestamp, Beacon Interval (100), Capability Info
- IEs: SSID, Supported Rates, DS Parameter Set

**Probe Request**:
- Frame Control: 0x0040 (Management, Subtype 4)
- Addresses: Broadcast (DA), Client MAC (SA), Broadcast (BSSID)
- IEs: SSID (wildcard), Supported Rates

**Association Request**:
- Frame Control: 0x0000 (Management, Subtype 0)
- Addresses: AP MAC (DA), Client MAC (SA), AP MAC (BSSID)
- Fixed fields: Capability Info, Listen Interval
- IEs: SSID, Supported Rates

## Generating Custom Samples

To regenerate these sample files or create new ones:

```bash
cargo run --example generate_samples
```

This will recreate all sample PCAP files in the `samples/` directory.

## Testing Notes

These are **synthetic** PCAP files created for testing purposes. They contain minimal valid 802.11 frames with Radiotap headers but do not include:
- Advanced Wi-Fi 7 (802.11be) features like EHT capabilities
- Real radio information (rates, signal strength, etc.)
- Complex multi-BSS scenarios
- Actual interference or timing issues

For production testing, use real over-the-air captures from Wi-Fi 7 capable equipment.

## Compatibility

These PCAP files can be opened with standard packet analysis tools:
- **Wireshark**: `wireshark samples/wifi7_complete_sample.pcap`
- **tcpdump**: `tcpdump -r samples/wifi7_complete_sample.pcap -vv`
- **tshark**: `tshark -r samples/wifi7_complete_sample.pcap -V`

## License

These sample files are part of the WiFi-insider project and are provided for testing purposes.
