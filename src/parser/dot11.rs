use crate::parser::radiotap::parse_radiotap;
use crate::parser::ie_parser::parse_information_elements;
use crate::types::frame::{Dot11Frame, FrameControl, FrameType};
use anyhow::{anyhow, Result};

/// Parse an 802.11 frame with optional Radiotap header
pub fn parse_dot11_frame(data: &[u8], has_radiotap: bool) -> Result<Dot11Frame> {
    let mut offset = 0;
    let mut radiotap_info = None;

    // Parse Radiotap header if present
    if has_radiotap {
        let (rt_info, rt_len) = parse_radiotap(data)?;
        radiotap_info = Some(rt_info);
        offset = rt_len;
    }

    // Ensure we have enough data for the 802.11 header
    if data.len() < offset + 24 {
        return Err(anyhow!("Frame too short for 802.11 header"));
    }

    let dot11_data = &data[offset..];

    // Parse Frame Control (2 bytes)
    let fc_bytes = [dot11_data[0], dot11_data[1]];
    let frame_control = FrameControl::from_bytes(&fc_bytes);

    // Parse Duration/ID (2 bytes)
    let duration = u16::from_le_bytes([dot11_data[2], dot11_data[3]]);

    // Parse Address 1 (Receiver) - always present
    let mut addr1 = [0u8; 6];
    addr1.copy_from_slice(&dot11_data[4..10]);

    let mut current_offset = 10;

    // Parse remaining addresses based on frame type
    let mut addr2 = None;
    let mut addr3 = None;
    let mut addr4 = None;
    let mut sequence_control = None;

    // For most frames, we have addr2 and addr3
    if matches!(
        frame_control.get_frame_type(),
        FrameType::Management | FrameType::Data
    ) {
        if dot11_data.len() >= current_offset + 12 {
            let mut a2 = [0u8; 6];
            a2.copy_from_slice(&dot11_data[current_offset..current_offset + 6]);
            addr2 = Some(a2);
            current_offset += 6;

            let mut a3 = [0u8; 6];
            a3.copy_from_slice(&dot11_data[current_offset..current_offset + 6]);
            addr3 = Some(a3);
            current_offset += 6;

            // Sequence Control (2 bytes)
            if dot11_data.len() >= current_offset + 2 {
                sequence_control = Some(u16::from_le_bytes([
                    dot11_data[current_offset],
                    dot11_data[current_offset + 1],
                ]));
                current_offset += 2;
            }
        }
    }

    // Check for Address 4 (for WDS frames)
    if frame_control.to_ds && frame_control.from_ds {
        if dot11_data.len() >= current_offset + 6 {
            let mut a4 = [0u8; 6];
            a4.copy_from_slice(&dot11_data[current_offset..current_offset + 6]);
            addr4 = Some(a4);
            current_offset += 6;
        }
    }

    // Parse QoS Control if this is a QoS data frame
    let mut qos_control = None;
    if frame_control.get_frame_type() == FrameType::Data && (frame_control.subtype & 0x08) != 0 {
        if dot11_data.len() >= current_offset + 2 {
            qos_control = Some(u16::from_le_bytes([
                dot11_data[current_offset],
                dot11_data[current_offset + 1],
            ]));
            current_offset += 2;
        }
    }

    // Parse HT Control if Order bit is set
    let mut ht_control = None;
    if frame_control.order {
        if dot11_data.len() >= current_offset + 4 {
            ht_control = Some(u32::from_le_bytes([
                dot11_data[current_offset],
                dot11_data[current_offset + 1],
                dot11_data[current_offset + 2],
                dot11_data[current_offset + 3],
            ]));
            current_offset += 4;
        }
    }

    // Parse payload and Information Elements (for management frames)
    let mut payload = Vec::new();
    let mut information_elements = Vec::new();

    if dot11_data.len() > current_offset {
        payload = dot11_data[current_offset..].to_vec();

        // Parse IEs for management frames
        if frame_control.get_frame_type() == FrameType::Management {
            // Different management frames have fixed fields before IEs
            let ie_offset = match frame_control.subtype {
                0 | 2 => 4,  // Association/Reassociation Request (Capability + Listen Interval)
                1 | 3 => 6,  // Association/Reassociation Response (Capability + Status + AID)
                4 => 0,      // Probe Request (IEs start immediately)
                5 => 12,     // Probe Response (Timestamp + Beacon Interval + Capability)
                8 => 12,     // Beacon (Timestamp + Beacon Interval + Capability)
                11 => 6,     // Authentication (Auth Algorithm + Auth Seq + Status)
                _ => 0,
            };

            if payload.len() > ie_offset {
                information_elements = parse_information_elements(&payload[ie_offset..]);
            }
        }
    }

    Ok(Dot11Frame {
        radiotap: radiotap_info,
        frame_control,
        duration,
        addr1,
        addr2,
        addr3,
        addr4,
        sequence_control,
        qos_control,
        ht_control,
        payload,
        information_elements,
    })
}

/// Extract BSSID from frame based on addresses
pub fn get_bssid(frame: &Dot11Frame) -> Option<[u8; 6]> {
    match frame.frame_control.get_frame_type() {
        FrameType::Management => frame.addr3,
        FrameType::Data => {
            if frame.frame_control.to_ds && !frame.frame_control.from_ds {
                frame.addr1  // To AP
            } else if !frame.frame_control.to_ds && frame.frame_control.from_ds {
                frame.addr2  // From AP
            } else {
                frame.addr3  // IBSS or other
            }
        }
        _ => None,
    }
}

/// Extract source address from frame
pub fn get_source_addr(frame: &Dot11Frame) -> Option<[u8; 6]> {
    match frame.frame_control.get_frame_type() {
        FrameType::Management | FrameType::Control => frame.addr2,
        FrameType::Data => {
            if frame.frame_control.to_ds && frame.frame_control.from_ds {
                frame.addr4  // WDS
            } else if frame.frame_control.to_ds {
                frame.addr2  // To AP
            } else {
                frame.addr2  // From AP or IBSS
            }
        }
        _ => None,
    }
}

/// Extract destination address from frame
pub fn get_dest_addr(frame: &Dot11Frame) -> Option<[u8; 6]> {
    match frame.frame_control.get_frame_type() {
        FrameType::Data => {
            if frame.frame_control.from_ds {
                Some(frame.addr1)  // From AP
            } else {
                frame.addr3  // To AP or IBSS
            }
        }
        _ => Some(frame.addr1),
    }
}
