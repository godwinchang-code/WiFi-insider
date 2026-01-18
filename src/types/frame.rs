use serde::{Deserialize, Serialize};
use std::fmt;

/// 802.11 Frame Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrameType {
    Management,
    Control,
    Data,
    Extension,
}

/// 802.11 Management Frame Subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ManagementSubtype {
    AssociationRequest,
    AssociationResponse,
    ReassociationRequest,
    ReassociationResponse,
    ProbeRequest,
    ProbeResponse,
    TimingAdvertisement,
    Beacon,
    Atim,
    Disassociation,
    Authentication,
    Deauthentication,
    Action,
    ActionNoAck,
    Unknown(u8),
}

/// 802.11 Data Frame Subtypes
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DataSubtype {
    Data,
    DataCfAck,
    DataCfPoll,
    DataCfAckCfPoll,
    Null,
    CfAck,
    CfPoll,
    CfAckCfPoll,
    QosData,
    QosDataCfAck,
    QosDataCfPoll,
    QosDataCfAckCfPoll,
    QosNull,
    QosCfPoll,
    QosCfAckCfPoll,
    Unknown(u8),
}

/// Radiotap information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RadiotapInfo {
    pub version: u8,
    pub length: u16,
    pub present_flags: u32,
    pub channel_freq: Option<u16>,
    pub channel_flags: Option<u16>,
    pub rate: Option<u8>,
    pub signal: Option<i8>,
    pub noise: Option<i8>,
    pub antenna: Option<u8>,
    pub mcs: Option<McsInfo>,
    pub vht: Option<VhtInfo>,
    pub he: Option<HeInfo>,
    pub eht: Option<EhtInfo>,
}

/// MCS (Modulation and Coding Scheme) Information
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct McsInfo {
    pub known: u8,
    pub flags: u8,
    pub mcs: u8,
}

impl McsInfo {
    pub fn bandwidth(&self) -> u8 {
        (self.flags & 0x03)
    }

    pub fn guard_interval(&self) -> bool {
        (self.flags & 0x04) != 0
    }

    pub fn greenfield(&self) -> bool {
        (self.flags & 0x08) != 0
    }
}

/// VHT (Very High Throughput - 802.11ac) Information
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct VhtInfo {
    pub known: u16,
    pub flags: u8,
    pub bandwidth: u8,
    pub mcs_nss: [u8; 4],
    pub coding: u8,
    pub group_id: u8,
    pub partial_aid: u16,
}

/// HE (High Efficiency - 802.11ax) Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeInfo {
    pub data1: u16,
    pub data2: u16,
    pub data3: u16,
    pub data4: u16,
    pub data5: u16,
    pub data6: u16,
}

impl HeInfo {
    pub fn format(&self) -> u8 {
        ((self.data1 >> 0) & 0x03) as u8
    }

    pub fn bss_color(&self) -> u8 {
        ((self.data2 >> 0) & 0x3F) as u8
    }

    pub fn spatial_reuse(&self) -> u8 {
        ((self.data2 >> 6) & 0x0F) as u8
    }

    pub fn bandwidth(&self) -> u8 {
        ((self.data5 >> 0) & 0x0F) as u8
    }

    pub fn gi(&self) -> u8 {
        ((self.data5 >> 4) & 0x03) as u8
    }

    pub fn mcs(&self) -> u8 {
        ((self.data5 >> 8) & 0x0F) as u8
    }

    pub fn nss(&self) -> u8 {
        ((self.data6 >> 0) & 0x0F) as u8
    }
}

/// EHT (Extremely High Throughput - 802.11be / Wi-Fi 7) Information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EhtInfo {
    pub known: u32,
    pub data: [u32; 9],
    pub user_info: Vec<EhtUserInfo>,
}

impl EhtInfo {
    pub fn bandwidth(&self) -> u16 {
        // EHT bandwidth: 20/40/80/160/320 MHz
        let bw_field = (self.data[0] >> 0) & 0x07;
        match bw_field {
            0 => 20,
            1 => 40,
            2 => 80,
            3 => 160,
            4 => 320,
            _ => 0,
        }
    }

    pub fn mcs(&self) -> u8 {
        ((self.data[0] >> 4) & 0x0F) as u8
    }

    pub fn nss(&self) -> u8 {
        ((self.data[0] >> 8) & 0x0F) as u8
    }

    pub fn gi(&self) -> u8 {
        ((self.data[0] >> 12) & 0x03) as u8
    }

    pub fn ru_allocation(&self) -> u16 {
        ((self.data[1] >> 0) & 0x1FF) as u16
    }

    pub fn ppdu_type(&self) -> u8 {
        ((self.data[0] >> 16) & 0x03) as u8
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EhtUserInfo {
    pub sta_id: u16,
    pub mcs: u8,
    pub nss: u8,
    pub coding: u8,
}

/// 802.11 Frame Control field
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FrameControl {
    pub protocol_version: u8,
    pub frame_type: u8,
    pub subtype: u8,
    pub to_ds: bool,
    pub from_ds: bool,
    pub more_fragments: bool,
    pub retry: bool,
    pub power_management: bool,
    pub more_data: bool,
    pub protected: bool,
    pub order: bool,
}

impl FrameControl {
    pub fn from_bytes(bytes: &[u8; 2]) -> Self {
        let fc = u16::from_le_bytes(*bytes);
        Self {
            protocol_version: (fc & 0x03) as u8,
            frame_type: ((fc >> 2) & 0x03) as u8,
            subtype: ((fc >> 4) & 0x0F) as u8,
            to_ds: (fc & 0x0100) != 0,
            from_ds: (fc & 0x0200) != 0,
            more_fragments: (fc & 0x0400) != 0,
            retry: (fc & 0x0800) != 0,
            power_management: (fc & 0x1000) != 0,
            more_data: (fc & 0x2000) != 0,
            protected: (fc & 0x4000) != 0,
            order: (fc & 0x8000) != 0,
        }
    }

    pub fn get_frame_type(&self) -> FrameType {
        match self.frame_type {
            0 => FrameType::Management,
            1 => FrameType::Control,
            2 => FrameType::Data,
            3 => FrameType::Extension,
            _ => FrameType::Management,
        }
    }
}

/// Information Element (IE) from 802.11 management frames
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InformationElement {
    pub id: u8,
    pub length: u8,
    pub data: Vec<u8>,
}

/// Parsed 802.11 Frame
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dot11Frame {
    pub radiotap: Option<RadiotapInfo>,
    pub frame_control: FrameControl,
    pub duration: u16,
    pub addr1: [u8; 6], // Receiver address
    pub addr2: Option<[u8; 6]>, // Transmitter address
    pub addr3: Option<[u8; 6]>, // BSSID or other
    pub addr4: Option<[u8; 6]>, // Optional 4th address
    pub sequence_control: Option<u16>,
    pub qos_control: Option<u16>,
    pub ht_control: Option<u32>,
    pub payload: Vec<u8>,
    pub information_elements: Vec<InformationElement>,
}

impl Dot11Frame {
    pub fn is_management(&self) -> bool {
        matches!(self.frame_control.get_frame_type(), FrameType::Management)
    }

    pub fn is_data(&self) -> bool {
        matches!(self.frame_control.get_frame_type(), FrameType::Data)
    }

    pub fn is_qos(&self) -> bool {
        self.qos_control.is_some()
    }

    pub fn management_subtype(&self) -> Option<ManagementSubtype> {
        if !self.is_management() {
            return None;
        }

        Some(match self.frame_control.subtype {
            0 => ManagementSubtype::AssociationRequest,
            1 => ManagementSubtype::AssociationResponse,
            2 => ManagementSubtype::ReassociationRequest,
            3 => ManagementSubtype::ReassociationResponse,
            4 => ManagementSubtype::ProbeRequest,
            5 => ManagementSubtype::ProbeResponse,
            6 => ManagementSubtype::TimingAdvertisement,
            8 => ManagementSubtype::Beacon,
            9 => ManagementSubtype::Atim,
            10 => ManagementSubtype::Disassociation,
            11 => ManagementSubtype::Authentication,
            12 => ManagementSubtype::Deauthentication,
            13 => ManagementSubtype::Action,
            14 => ManagementSubtype::ActionNoAck,
            other => ManagementSubtype::Unknown(other),
        })
    }

    pub fn get_ie(&self, ie_id: u8) -> Option<&InformationElement> {
        self.information_elements.iter().find(|ie| ie.id == ie_id)
    }

    pub fn get_all_ie(&self, ie_id: u8) -> Vec<&InformationElement> {
        self.information_elements.iter().filter(|ie| ie.id == ie_id).collect()
    }
}

/// MAC address formatting helper
pub fn format_mac(addr: &[u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]
    )
}

/// Association/Reassociation status codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCode {
    Success,
    UnspecifiedFailure,
    TdlsRejectedAlternative,
    RefusedExternalReason,
    // ... (shortened for brevity, add more as needed)
    Unknown(u16),
}

impl From<u16> for StatusCode {
    fn from(code: u16) -> Self {
        match code {
            0 => Self::Success,
            1 => Self::UnspecifiedFailure,
            2 => Self::TdlsRejectedAlternative,
            3 => Self::RefusedExternalReason,
            other => Self::Unknown(other),
        }
    }
}

/// Association/Disassociation reason codes
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReasonCode {
    Unspecified,
    PreviousAuthNoLongerValid,
    DeauthLeaving,
    // ... (add more as needed)
    Unknown(u16),
}

impl From<u16> for ReasonCode {
    fn from(code: u16) -> Self {
        match code {
            1 => Self::Unspecified,
            2 => Self::PreviousAuthNoLongerValid,
            3 => Self::DeauthLeaving,
            other => Self::Unknown(other),
        }
    }
}
