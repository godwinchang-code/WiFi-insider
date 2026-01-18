use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use wifi_insider::parser::pcap_reader::WifiPcapReader;
use wifi_insider::parser::dot11::parse_dot11_frame;
use wifi_insider::detector::DetectorEngine;
use wifi_insider::reporter::output::AnalysisReport;

/// Create a minimal valid PCAP file with 802.11 Radiotap header
fn create_test_pcap() -> Vec<u8> {
    let mut pcap_data = Vec::new();

    // PCAP Global Header (24 bytes)
    pcap_data.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, // Magic number (little-endian)
        0x02, 0x00,             // Major version (2)
        0x04, 0x00,             // Minor version (4)
        0x00, 0x00, 0x00, 0x00, // Timezone offset (0)
        0x00, 0x00, 0x00, 0x00, // Timestamp accuracy (0)
        0xff, 0xff, 0x00, 0x00, // Snapshot length (65535)
        0x7f, 0x00, 0x00, 0x00, // Link-layer type (127 = IEEE 802.11 Radiotap)
    ]);

    // Packet 1: Beacon frame
    let beacon_packet = create_beacon_packet();
    add_pcap_packet(&mut pcap_data, &beacon_packet, 1000, 0);

    // Packet 2: Probe Request
    let probe_req_packet = create_probe_request_packet();
    add_pcap_packet(&mut pcap_data, &probe_req_packet, 1001, 100000);

    // Packet 3: Association Request
    let assoc_req_packet = create_association_request_packet();
    add_pcap_packet(&mut pcap_data, &assoc_req_packet, 1002, 200000);

    pcap_data
}

fn add_pcap_packet(pcap_data: &mut Vec<u8>, packet: &[u8], ts_sec: u32, ts_usec: u32) {
    // Packet header (16 bytes)
    pcap_data.extend_from_slice(&ts_sec.to_le_bytes());
    pcap_data.extend_from_slice(&ts_usec.to_le_bytes());
    pcap_data.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // Captured length
    pcap_data.extend_from_slice(&(packet.len() as u32).to_le_bytes()); // Original length
    pcap_data.extend_from_slice(packet);
}

fn create_beacon_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Radiotap header (minimal, 8 bytes)
    packet.extend_from_slice(&[
        0x00, 0x00,             // version, padding
        0x08, 0x00,             // length (8 bytes)
        0x00, 0x00, 0x00, 0x00, // present flags (none)
    ]);

    // 802.11 Beacon Frame
    // Frame Control: Beacon (Type=0, Subtype=8)
    packet.extend_from_slice(&[
        0x80, 0x00,             // Frame Control (Beacon)
        0x00, 0x00,             // Duration
    ]);

    // Addresses
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Addr1 (Broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Addr2 (Source/BSSID)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Addr3 (BSSID)
    ]);

    // Sequence Control
    packet.extend_from_slice(&[0x00, 0x00]);

    // Beacon Fixed Fields (12 bytes)
    packet.extend_from_slice(&[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Timestamp
        0x64, 0x00,             // Beacon interval (100 TUs)
        0x11, 0x04,             // Capability info
    ]);

    // Information Elements
    // SSID
    packet.extend_from_slice(&[0x00, 0x08]); // SSID IE, length 8
    packet.extend_from_slice(b"TestWiFi");

    // Supported Rates
    packet.extend_from_slice(&[0x01, 0x04]); // Supported Rates IE
    packet.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96]);

    // DS Parameter Set (Channel 6)
    packet.extend_from_slice(&[0x03, 0x01, 0x06]);

    packet
}

fn create_probe_request_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Radiotap header
    packet.extend_from_slice(&[
        0x00, 0x00,
        0x08, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    // 802.11 Probe Request (Type=0, Subtype=4)
    packet.extend_from_slice(&[
        0x40, 0x00,             // Frame Control (Probe Request)
        0x00, 0x00,             // Duration
    ]);

    // Addresses
    packet.extend_from_slice(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Addr1 (Broadcast)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Addr2 (Source/Client)
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Addr3 (Broadcast)
    ]);

    // Sequence Control
    packet.extend_from_slice(&[0x10, 0x00]);

    // SSID (wildcard)
    packet.extend_from_slice(&[0x00, 0x00]); // SSID IE, length 0 (wildcard)

    // Supported Rates
    packet.extend_from_slice(&[0x01, 0x04]);
    packet.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96]);

    packet
}

fn create_association_request_packet() -> Vec<u8> {
    let mut packet = Vec::new();

    // Radiotap header
    packet.extend_from_slice(&[
        0x00, 0x00,
        0x08, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]);

    // 802.11 Association Request (Type=0, Subtype=0)
    packet.extend_from_slice(&[
        0x00, 0x00,             // Frame Control
        0x3a, 0x01,             // Duration
    ]);

    // Addresses
    packet.extend_from_slice(&[
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Addr1 (BSSID/AP)
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Addr2 (Source/Client)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Addr3 (BSSID)
    ]);

    // Sequence Control
    packet.extend_from_slice(&[0x20, 0x00]);

    // Association Request Fixed Fields
    packet.extend_from_slice(&[
        0x11, 0x04,             // Capability info
        0x0a, 0x00,             // Listen interval
    ]);

    // SSID
    packet.extend_from_slice(&[0x00, 0x08]);
    packet.extend_from_slice(b"TestWiFi");

    // Supported Rates
    packet.extend_from_slice(&[0x01, 0x04]);
    packet.extend_from_slice(&[0x82, 0x84, 0x8b, 0x96]);

    packet
}

#[test]
fn test_pcap_file_reading() {
    // Create test PCAP file
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test.pcap");

    let pcap_data = create_test_pcap();
    let mut file = File::create(&file_path).unwrap();
    file.write_all(&pcap_data).unwrap();
    drop(file);

    // Open and read the PCAP file
    let mut reader = WifiPcapReader::open(&file_path).unwrap();
    assert!(reader.has_radiotap());

    let mut packet_count = 0;
    while let Some(packet) = reader.next_packet().unwrap() {
        packet_count += 1;
        assert!(packet.data.len() > 0);
        assert!(packet.timestamp > 0.0);
    }

    assert_eq!(packet_count, 3);
}

#[test]
fn test_end_to_end_analysis() {
    // Create test PCAP file
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("test_analysis.pcap");

    let pcap_data = create_test_pcap();
    let mut file = File::create(&file_path).unwrap();
    file.write_all(&pcap_data).unwrap();
    drop(file);

    // Analyze the PCAP file
    let mut reader = WifiPcapReader::open(&file_path).unwrap();
    let has_radiotap = reader.has_radiotap();

    let mut engine = DetectorEngine::new();
    let mut processed_packets = 0;

    while let Some(packet) = reader.next_packet().unwrap() {
        processed_packets += 1;

        match parse_dot11_frame(&packet.data, has_radiotap) {
            Ok(frame) => {
                engine.process_frame(&frame, packet.packet_number, packet.timestamp);
            }
            Err(_e) => {
                // Some test packets may not parse perfectly, that's OK
            }
        }
    }

    // Set total packets (this is normally done in main.rs)
    engine.stats.total_packets = processed_packets;

    engine.finalize_analysis();

    // Verify processing
    assert_eq!(processed_packets, 3);
    assert!(engine.stats.total_frames > 0);

    // Create report
    let report = AnalysisReport::new(engine.issues.clone(), engine.stats.clone());
    let summary = report.summary();

    assert_eq!(summary.total_packets, 3);
    assert!(summary.duration >= 0.0);
}

#[test]
fn test_beacon_frame_parsing() {
    let beacon = create_beacon_packet();

    let result = parse_dot11_frame(&beacon, true);
    assert!(result.is_ok());

    let frame = result.unwrap();
    assert!(frame.is_management());

    // Check for SSID IE
    let has_ssid = frame.information_elements.iter().any(|ie| ie.id == 0);
    assert!(has_ssid);
}

#[test]
fn test_probe_request_parsing() {
    let probe = create_probe_request_packet();

    let result = parse_dot11_frame(&probe, true);
    assert!(result.is_ok());

    let frame = result.unwrap();
    assert!(frame.is_management());
}

#[test]
fn test_association_request_parsing() {
    let assoc = create_association_request_packet();

    let result = parse_dot11_frame(&assoc, true);
    assert!(result.is_ok());

    let frame = result.unwrap();
    assert!(frame.is_management());
}

#[test]
fn test_multiple_packet_types() {
    let packets = vec![
        create_beacon_packet(),
        create_probe_request_packet(),
        create_association_request_packet(),
    ];

    let mut successful_parses = 0;
    for packet in packets {
        if parse_dot11_frame(&packet, true).is_ok() {
            successful_parses += 1;
        }
    }

    assert_eq!(successful_parses, 3);
}
