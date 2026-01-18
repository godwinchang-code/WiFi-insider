use anyhow::{Context, Result};
use pcap_file::pcap::PcapReader;
use std::fs::File;
use std::path::Path;

/// Packet from PCAP file
#[derive(Debug, Clone)]
pub struct PcapPacket {
    pub packet_number: u64,
    pub timestamp: f64,
    pub data: Vec<u8>,
    pub orig_len: u32,
}

/// PCAP file reader wrapper
pub struct WifiPcapReader {
    reader: PcapReader<File>,
    packet_count: u64,
    link_type: u32,
}

impl WifiPcapReader {
    /// Open a PCAP file
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = File::open(path.as_ref())
            .with_context(|| format!("Failed to open pcap file: {:?}", path.as_ref()))?;

        let mut reader = PcapReader::new(file)
            .with_context(|| "Failed to parse pcap file header")?;

        // Get link type from header
        let datalink = reader.header().datalink;
        // DataLink::IEEE802_11_RADIOTAP has value 127
        // DataLink::IEEE802_11 has value 105
        let link_type = u32::from(datalink);

        // Validate that this is an 802.11 capture
        // Link type 127 = IEEE 802.11 with Radiotap header
        // Link type 105 = IEEE 802.11 (no radiotap)
        if link_type != 127 && link_type != 105 {
            log::warn!(
                "Unexpected link type: {} (expected 127 for Radiotap or 105 for raw 802.11)",
                link_type
            );
        }

        Ok(Self {
            reader,
            packet_count: 0,
            link_type,
        })
    }

    /// Check if this capture uses Radiotap headers
    pub fn has_radiotap(&self) -> bool {
        self.link_type == 127
    }

    /// Get the next packet from the file
    pub fn next_packet(&mut self) -> Result<Option<PcapPacket>> {
        match self.reader.next_packet() {
            Some(Ok(packet)) => {
                self.packet_count += 1;

                // Convert Duration to timestamp
                let duration = packet.timestamp;
                let timestamp = duration.as_secs() as f64
                    + (duration.subsec_micros() as f64 / 1_000_000.0);

                Ok(Some(PcapPacket {
                    packet_number: self.packet_count,
                    timestamp,
                    data: packet.data.to_vec(),
                    orig_len: packet.orig_len,
                }))
            }
            Some(Err(e)) => Err(anyhow::anyhow!("Failed to read packet: {}", e)),
            None => Ok(None),
        }
    }

    /// Iterator over all packets
    pub fn packets(&mut self) -> PcapPacketIterator {
        PcapPacketIterator { reader: self }
    }

    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }
}

/// Iterator for PCAP packets
pub struct PcapPacketIterator<'a> {
    reader: &'a mut WifiPcapReader,
}

impl<'a> Iterator for PcapPacketIterator<'a> {
    type Item = Result<PcapPacket>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.reader.next_packet() {
            Ok(Some(packet)) => Some(Ok(packet)),
            Ok(None) => None,
            Err(e) => Some(Err(e)),
        }
    }
}
