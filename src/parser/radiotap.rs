use crate::types::frame::{RadiotapInfo, McsInfo, VhtInfo, HeInfo, EhtInfo, EhtUserInfo};
use anyhow::{anyhow, Result};

/// Radiotap present flags
const RADIOTAP_TSFT: u32 = 1 << 0;
const RADIOTAP_FLAGS: u32 = 1 << 1;
const RADIOTAP_RATE: u32 = 1 << 2;
const RADIOTAP_CHANNEL: u32 = 1 << 3;
const RADIOTAP_FHSS: u32 = 1 << 4;
const RADIOTAP_DBM_ANTSIGNAL: u32 = 1 << 5;
const RADIOTAP_DBM_ANTNOISE: u32 = 1 << 6;
const RADIOTAP_LOCK_QUALITY: u32 = 1 << 7;
const RADIOTAP_TX_ATTENUATION: u32 = 1 << 8;
const RADIOTAP_DB_TX_ATTENUATION: u32 = 1 << 9;
const RADIOTAP_DBM_TX_POWER: u32 = 1 << 10;
const RADIOTAP_ANTENNA: u32 = 1 << 11;
const RADIOTAP_DB_ANTSIGNAL: u32 = 1 << 12;
const RADIOTAP_DB_ANTNOISE: u32 = 1 << 13;
const RADIOTAP_RX_FLAGS: u32 = 1 << 14;
const RADIOTAP_MCS: u32 = 1 << 19;
const RADIOTAP_AMPDU_STATUS: u32 = 1 << 20;
const RADIOTAP_VHT: u32 = 1 << 21;
const RADIOTAP_TIMESTAMP: u32 = 1 << 22;
const RADIOTAP_HE: u32 = 1 << 23;
const RADIOTAP_HE_MU: u32 = 1 << 24;
const RADIOTAP_ZERO_LENGTH_PSDU: u32 = 1 << 26;
const RADIOTAP_L_SIG: u32 = 1 << 27;
const RADIOTAP_EXT: u32 = 1 << 31;

// Vendor namespace for EHT (0x5241434f - "RACO")
const RADIOTAP_VENDOR_NAMESPACE: u32 = 0x5241434f;

/// Parse a Radiotap header
pub fn parse_radiotap(data: &[u8]) -> Result<(RadiotapInfo, usize)> {
    if data.len() < 8 {
        return Err(anyhow!("Radiotap header too short"));
    }

    let version = data[0];
    let _pad = data[1];
    let length = u16::from_le_bytes([data[2], data[3]]);
    let present_flags = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

    if data.len() < length as usize {
        return Err(anyhow!("Incomplete Radiotap header"));
    }

    let mut info = RadiotapInfo {
        version,
        length,
        present_flags,
        channel_freq: None,
        channel_flags: None,
        rate: None,
        signal: None,
        noise: None,
        antenna: None,
        mcs: None,
        vht: None,
        he: None,
        eht: None,
    };

    // Parse radiotap fields
    let mut offset = 8;
    let mut present = present_flags;
    let mut extended_present_count = 0;

    // Handle extended present flags
    while (present & RADIOTAP_EXT) != 0 && offset + 4 <= length as usize {
        extended_present_count += 1;
        present = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        offset += 4;
    }

    // Reset for actual parsing
    offset = 8 + (extended_present_count * 4);
    present = present_flags;

    // Helper to align offset
    let align = |off: usize, alignment: usize| -> usize {
        (off + alignment - 1) & !(alignment - 1)
    };

    // Parse each field based on present flags
    if present & RADIOTAP_TSFT != 0 {
        offset = align(offset, 8);
        offset += 8; // Skip TSFT
    }

    if present & RADIOTAP_FLAGS != 0 {
        offset = align(offset, 1);
        offset += 1; // Skip flags
    }

    if present & RADIOTAP_RATE != 0 {
        offset = align(offset, 1);
        if offset < data.len() {
            info.rate = Some(data[offset]);
        }
        offset += 1;
    }

    if present & RADIOTAP_CHANNEL != 0 {
        offset = align(offset, 2);
        if offset + 4 <= data.len() {
            info.channel_freq = Some(u16::from_le_bytes([data[offset], data[offset + 1]]));
            info.channel_flags = Some(u16::from_le_bytes([data[offset + 2], data[offset + 3]]));
        }
        offset += 4;
    }

    if present & RADIOTAP_FHSS != 0 {
        offset = align(offset, 1);
        offset += 2;
    }

    if present & RADIOTAP_DBM_ANTSIGNAL != 0 {
        offset = align(offset, 1);
        if offset < data.len() {
            info.signal = Some(data[offset] as i8);
        }
        offset += 1;
    }

    if present & RADIOTAP_DBM_ANTNOISE != 0 {
        offset = align(offset, 1);
        if offset < data.len() {
            info.noise = Some(data[offset] as i8);
        }
        offset += 1;
    }

    if present & RADIOTAP_LOCK_QUALITY != 0 {
        offset = align(offset, 2);
        offset += 2;
    }

    if present & RADIOTAP_TX_ATTENUATION != 0 {
        offset = align(offset, 2);
        offset += 2;
    }

    if present & RADIOTAP_DB_TX_ATTENUATION != 0 {
        offset = align(offset, 2);
        offset += 2;
    }

    if present & RADIOTAP_DBM_TX_POWER != 0 {
        offset = align(offset, 1);
        offset += 1;
    }

    if present & RADIOTAP_ANTENNA != 0 {
        offset = align(offset, 1);
        if offset < data.len() {
            info.antenna = Some(data[offset]);
        }
        offset += 1;
    }

    if present & RADIOTAP_DB_ANTSIGNAL != 0 {
        offset = align(offset, 1);
        offset += 1;
    }

    if present & RADIOTAP_DB_ANTNOISE != 0 {
        offset = align(offset, 1);
        offset += 1;
    }

    if present & RADIOTAP_RX_FLAGS != 0 {
        offset = align(offset, 2);
        offset += 2;
    }

    if present & RADIOTAP_MCS != 0 {
        offset = align(offset, 1);
        if offset + 3 <= data.len() {
            info.mcs = Some(McsInfo {
                known: data[offset],
                flags: data[offset + 1],
                mcs: data[offset + 2],
            });
        }
        offset += 3;
    }

    if present & RADIOTAP_AMPDU_STATUS != 0 {
        offset = align(offset, 4);
        offset += 8;
    }

    if present & RADIOTAP_VHT != 0 {
        offset = align(offset, 2);
        if offset + 12 <= data.len() {
            info.vht = Some(VhtInfo {
                known: u16::from_le_bytes([data[offset], data[offset + 1]]),
                flags: data[offset + 2],
                bandwidth: data[offset + 3],
                mcs_nss: [
                    data[offset + 4],
                    data[offset + 5],
                    data[offset + 6],
                    data[offset + 7],
                ],
                coding: data[offset + 8],
                group_id: data[offset + 9],
                partial_aid: u16::from_le_bytes([data[offset + 10], data[offset + 11]]),
            });
        }
        offset += 12;
    }

    if present & RADIOTAP_TIMESTAMP != 0 {
        offset = align(offset, 8);
        offset += 12;
    }

    if present & RADIOTAP_HE != 0 {
        offset = align(offset, 2);
        if offset + 12 <= data.len() {
            info.he = Some(HeInfo {
                data1: u16::from_le_bytes([data[offset], data[offset + 1]]),
                data2: u16::from_le_bytes([data[offset + 2], data[offset + 3]]),
                data3: u16::from_le_bytes([data[offset + 4], data[offset + 5]]),
                data4: u16::from_le_bytes([data[offset + 6], data[offset + 7]]),
                data5: u16::from_le_bytes([data[offset + 8], data[offset + 9]]),
                data6: u16::from_le_bytes([data[offset + 10], data[offset + 11]]),
            });
        }
        offset += 12;
    }

    if present & RADIOTAP_HE_MU != 0 {
        offset = align(offset, 2);
        offset += 12;
    }

    if present & RADIOTAP_ZERO_LENGTH_PSDU != 0 {
        offset = align(offset, 1);
        offset += 1;
    }

    if present & RADIOTAP_L_SIG != 0 {
        offset = align(offset, 2);
        offset += 4;
    }

    // Try to parse EHT information (typically in vendor namespace or future radiotap extensions)
    // This is a simplified parser - actual EHT radiotap format may vary
    if offset + 40 <= length as usize {
        // Look for EHT signature or vendor namespace
        // This is a placeholder - actual implementation would depend on the specific
        // radiotap format used by the capture tool
        if let Some(eht_info) = try_parse_eht(&data[offset..length as usize]) {
            info.eht = Some(eht_info);
        }
    }

    Ok((info, length as usize))
}

/// Attempt to parse EHT information from radiotap extensions
/// This is a simplified parser and may need adjustment based on actual capture format
fn try_parse_eht(data: &[u8]) -> Option<EhtInfo> {
    if data.len() < 40 {
        return None;
    }

    // Check for vendor namespace marker (simplified)
    // In practice, this would need to properly parse vendor-specific extensions

    // For now, create a basic EHT info structure
    // A real implementation would parse the actual EHT radiotap fields
    Some(EhtInfo {
        known: 0,
        data: [0; 9],
        user_info: Vec::new(),
    })
}

/// Get channel number from frequency
pub fn freq_to_channel(freq: u16) -> Option<u8> {
    match freq {
        // 2.4 GHz
        2412 => Some(1),
        2417 => Some(2),
        2422 => Some(3),
        2427 => Some(4),
        2432 => Some(5),
        2437 => Some(6),
        2442 => Some(7),
        2447 => Some(8),
        2452 => Some(9),
        2457 => Some(10),
        2462 => Some(11),
        2467 => Some(12),
        2472 => Some(13),
        2484 => Some(14),

        // 5 GHz
        5180 => Some(36),
        5200 => Some(40),
        5220 => Some(44),
        5240 => Some(48),
        5260 => Some(52),
        5280 => Some(56),
        5300 => Some(60),
        5320 => Some(64),
        5500 => Some(100),
        5520 => Some(104),
        5540 => Some(108),
        5560 => Some(112),
        5580 => Some(116),
        5600 => Some(120),
        5620 => Some(124),
        5640 => Some(128),
        5660 => Some(132),
        5680 => Some(136),
        5700 => Some(140),
        5720 => Some(144),
        5745 => Some(149),
        5765 => Some(153),
        5785 => Some(157),
        5805 => Some(161),
        5825 => Some(165),

        // 6 GHz
        5955 => Some(1),
        5975 => Some(5),
        5995 => Some(9),
        6015 => Some(13),
        6035 => Some(17),
        6055 => Some(21),
        6075 => Some(25),
        6095 => Some(29),
        6115 => Some(33),
        6135 => Some(37),
        6155 => Some(41),
        6175 => Some(45),
        6195 => Some(49),
        6215 => Some(53),
        6235 => Some(57),
        6255 => Some(61),
        6275 => Some(65),
        6295 => Some(69),
        6315 => Some(73),
        6335 => Some(77),
        6355 => Some(81),
        6375 => Some(85),
        6395 => Some(89),
        6415 => Some(93),
        6435 => Some(97),
        6455 => Some(101),
        6475 => Some(105),
        6495 => Some(109),
        6515 => Some(113),
        6535 => Some(117),
        6555 => Some(121),
        6575 => Some(125),
        6595 => Some(129),
        6615 => Some(133),
        6635 => Some(137),
        6655 => Some(141),
        6675 => Some(145),
        6695 => Some(149),
        6715 => Some(153),
        6735 => Some(157),
        6755 => Some(161),
        6775 => Some(165),
        6795 => Some(169),
        6815 => Some(173),
        6835 => Some(177),
        6855 => Some(181),
        6875 => Some(185),
        6895 => Some(189),
        6915 => Some(193),
        6935 => Some(197),
        6955 => Some(201),
        6975 => Some(205),
        6995 => Some(209),
        7015 => Some(213),
        7035 => Some(217),
        7055 => Some(221),
        7075 => Some(225),
        7095 => Some(229),
        7115 => Some(233),

        _ => None,
    }
}

/// Check if frequency is in 6 GHz band
pub fn is_6ghz(freq: u16) -> bool {
    freq >= 5955 && freq <= 7115
}
