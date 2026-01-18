use std::fs::File;
use std::io::Write;

fn main() {
    println!("Generating sample PCAP files...");

    // Create complete sample with all packet types
    let complete_pcap = create_complete_sample();
    let mut file = File::create("samples/wifi7_complete_sample.pcap").unwrap();
    file.write_all(&complete_pcap).unwrap();
    println!("Created: samples/wifi7_complete_sample.pcap");

    // Create beacon-only sample
    let beacon_pcap = create_beacon_sample();
    let mut file = File::create("samples/wifi7_beacon_sample.pcap").unwrap();
    file.write_all(&beacon_pcap).unwrap();
    println!("Created: samples/wifi7_beacon_sample.pcap");

    // Create probe-only sample
    let probe_pcap = create_probe_sample();
    let mut file = File::create("samples/wifi7_probe_sample.pcap").unwrap();
    file.write_all(&probe_pcap).unwrap();
    println!("Created: samples/wifi7_probe_sample.pcap");

    println!("Sample PCAP files generated successfully!");
}

/// Create a complete PCAP file with beacon, probe request, and association request
fn create_complete_sample() -> Vec<u8> {
    let mut pcap_data = Vec::new();
    add_pcap_header(&mut pcap_data);

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

/// Create a PCAP file with only beacon frames
fn create_beacon_sample() -> Vec<u8> {
    let mut pcap_data = Vec::new();
    add_pcap_header(&mut pcap_data);

    // Add 5 beacon frames
    for i in 0..5 {
        let beacon = create_beacon_packet();
        add_pcap_packet(&mut pcap_data, &beacon, 1000 + i, i * 100000);
    }

    pcap_data
}

/// Create a PCAP file with only probe request frames
fn create_probe_sample() -> Vec<u8> {
    let mut pcap_data = Vec::new();
    add_pcap_header(&mut pcap_data);

    // Add 3 probe request frames
    for i in 0..3 {
        let probe = create_probe_request_packet();
        add_pcap_packet(&mut pcap_data, &probe, 1000 + i, i * 50000);
    }

    pcap_data
}

fn add_pcap_header(pcap_data: &mut Vec<u8>) {
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
