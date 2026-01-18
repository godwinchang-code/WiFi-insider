use crate::types::frame::InformationElement;

/// Parse 802.11 Information Elements
pub fn parse_information_elements(data: &[u8]) -> Vec<InformationElement> {
    let mut elements = Vec::new();
    let mut offset = 0;

    while offset + 2 <= data.len() {
        let id = data[offset];
        let length = data[offset + 1] as usize;

        if offset + 2 + length > data.len() {
            break;
        }

        let ie_data = data[offset + 2..offset + 2 + length].to_vec();

        elements.push(InformationElement {
            id,
            length: length as u8,
            data: ie_data,
        });

        offset += 2 + length;
    }

    elements
}

/// Common IE IDs
pub const IE_SSID: u8 = 0;
pub const IE_SUPPORTED_RATES: u8 = 1;
pub const IE_DSSS_PARAMETER: u8 = 3;
pub const IE_TIM: u8 = 5;
pub const IE_COUNTRY: u8 = 7;
pub const IE_ERP: u8 = 42;
pub const IE_HT_CAPABILITIES: u8 = 45;
pub const IE_RSN: u8 = 48;
pub const IE_EXTENDED_SUPPORTED_RATES: u8 = 50;
pub const IE_HT_OPERATION: u8 = 61;
pub const IE_RM_ENABLED_CAPABILITIES: u8 = 70;
pub const IE_MOBILITY_DOMAIN: u8 = 54;
pub const IE_FAST_BSS_TRANSITION: u8 = 55;
pub const IE_TIMEOUT_INTERVAL: u8 = 56;
pub const IE_BSS_MAX_IDLE_PERIOD: u8 = 90;
pub const IE_EXTENDED_CAPABILITIES: u8 = 127;
pub const IE_VHT_CAPABILITIES: u8 = 191;
pub const IE_VHT_OPERATION: u8 = 192;
pub const IE_VENDOR_SPECIFIC: u8 = 221;
pub const IE_EXTENSION: u8 = 255;

/// Extension IE IDs (when IE ID = 255)
pub const EXT_IE_HE_CAPABILITIES: u8 = 35;
pub const EXT_IE_HE_OPERATION: u8 = 36;
pub const EXT_IE_HE_6GHZ_BAND_CAP: u8 = 59;
pub const EXT_IE_EHT_CAPABILITIES: u8 = 108;
pub const EXT_IE_EHT_OPERATION: u8 = 106;
pub const EXT_IE_MULTI_LINK: u8 = 107;
pub const EXT_IE_REDUCED_NEIGHBOR_REPORT: u8 = 201;

/// Get SSID from IE
pub fn get_ssid(ie: &InformationElement) -> Option<String> {
    if ie.id == IE_SSID {
        String::from_utf8(ie.data.clone()).ok()
    } else {
        None
    }
}

/// Get RSN information
pub fn parse_rsn(ie: &InformationElement) -> Option<RsnInfo> {
    if ie.id != IE_RSN || ie.data.len() < 2 {
        return None;
    }

    let version = u16::from_le_bytes([ie.data[0], ie.data[1]]);
    let mut offset = 2;

    // Group cipher suite
    let group_cipher = if offset + 4 <= ie.data.len() {
        let oui = [ie.data[offset], ie.data[offset + 1], ie.data[offset + 2]];
        let suite_type = ie.data[offset + 3];
        offset += 4;
        Some((oui, suite_type))
    } else {
        None
    };

    // Pairwise cipher suites
    let pairwise_count = if offset + 2 <= ie.data.len() {
        u16::from_le_bytes([ie.data[offset], ie.data[offset + 1]])
    } else {
        0
    };
    offset += 2;

    let mut pairwise_ciphers = Vec::new();
    for _ in 0..pairwise_count {
        if offset + 4 <= ie.data.len() {
            let oui = [ie.data[offset], ie.data[offset + 1], ie.data[offset + 2]];
            let suite_type = ie.data[offset + 3];
            pairwise_ciphers.push((oui, suite_type));
            offset += 4;
        }
    }

    // AKM suites
    let akm_count = if offset + 2 <= ie.data.len() {
        u16::from_le_bytes([ie.data[offset], ie.data[offset + 1]])
    } else {
        0
    };
    offset += 2;

    let mut akm_suites = Vec::new();
    for _ in 0..akm_count {
        if offset + 4 <= ie.data.len() {
            let oui = [ie.data[offset], ie.data[offset + 1], ie.data[offset + 2]];
            let suite_type = ie.data[offset + 3];
            akm_suites.push((oui, suite_type));
            offset += 4;
        }
    }

    // RSN Capabilities
    let capabilities = if offset + 2 <= ie.data.len() {
        Some(u16::from_le_bytes([ie.data[offset], ie.data[offset + 1]]))
    } else {
        None
    };

    Some(RsnInfo {
        version,
        group_cipher,
        pairwise_ciphers,
        akm_suites,
        capabilities,
    })
}

#[derive(Debug, Clone)]
pub struct RsnInfo {
    pub version: u16,
    pub group_cipher: Option<([u8; 3], u8)>,
    pub pairwise_ciphers: Vec<([u8; 3], u8)>,
    pub akm_suites: Vec<([u8; 3], u8)>,
    pub capabilities: Option<u16>,
}

impl RsnInfo {
    pub fn has_wpa3_sae(&self) -> bool {
        // WPA3-SAE: AKM suite type 8
        self.akm_suites.iter().any(|(_, suite_type)| *suite_type == 8)
    }

    pub fn has_owe(&self) -> bool {
        // OWE: AKM suite type 18
        self.akm_suites.iter().any(|(_, suite_type)| *suite_type == 18)
    }
}

/// Parse HT Capabilities
pub fn parse_ht_capabilities(ie: &InformationElement) -> Option<HtCapabilities> {
    if ie.id != IE_HT_CAPABILITIES || ie.data.len() < 26 {
        return None;
    }

    let cap_info = u16::from_le_bytes([ie.data[0], ie.data[1]]);
    let ampdu_params = ie.data[2];
    let mcs_set = ie.data[3..19].to_vec();
    let ext_cap = u16::from_le_bytes([ie.data[19], ie.data[20]]);
    let txbf_cap = u32::from_le_bytes([ie.data[21], ie.data[22], ie.data[23], ie.data[24]]);
    let asel_cap = ie.data[25];

    Some(HtCapabilities {
        cap_info,
        ampdu_params,
        mcs_set,
        ext_cap,
        txbf_cap,
        asel_cap,
    })
}

#[derive(Debug, Clone)]
pub struct HtCapabilities {
    pub cap_info: u16,
    pub ampdu_params: u8,
    pub mcs_set: Vec<u8>,
    pub ext_cap: u16,
    pub txbf_cap: u32,
    pub asel_cap: u8,
}

impl HtCapabilities {
    pub fn channel_width(&self) -> bool {
        (self.cap_info & 0x02) != 0  // 40 MHz support
    }

    pub fn max_spatial_streams(&self) -> u8 {
        // Check MCS set to determine NSS
        let mut max_nss = 0;
        for i in 0..4 {
            if self.mcs_set[i] != 0 {
                max_nss = i as u8 + 1;
            }
        }
        max_nss
    }
}

/// Parse VHT Capabilities
pub fn parse_vht_capabilities(ie: &InformationElement) -> Option<VhtCapabilities> {
    if ie.id != IE_VHT_CAPABILITIES || ie.data.len() < 12 {
        return None;
    }

    let cap_info = u32::from_le_bytes([ie.data[0], ie.data[1], ie.data[2], ie.data[3]]);
    let mcs_nss = u64::from_le_bytes([
        ie.data[4], ie.data[5], ie.data[6], ie.data[7],
        ie.data[8], ie.data[9], ie.data[10], ie.data[11],
    ]);

    Some(VhtCapabilities { cap_info, mcs_nss })
}

#[derive(Debug, Clone)]
pub struct VhtCapabilities {
    pub cap_info: u32,
    pub mcs_nss: u64,
}

impl VhtCapabilities {
    pub fn max_bandwidth(&self) -> u16 {
        let bw = (self.cap_info >> 2) & 0x03;
        match bw {
            0 => 80,
            1 => 160,
            2 => 160,  // 80+80
            _ => 80,
        }
    }

    pub fn max_spatial_streams_tx(&self) -> u8 {
        let mcs_tx = ((self.mcs_nss >> 32) & 0xFFFF) as u16;
        for nss in (1..=8).rev() {
            let mcs = (mcs_tx >> ((nss - 1) * 2)) & 0x03;
            if mcs != 3 {  // 3 means not supported
                return nss;
            }
        }
        1
    }

    pub fn max_spatial_streams_rx(&self) -> u8 {
        let mcs_rx = (self.mcs_nss & 0xFFFF) as u16;
        for nss in (1..=8).rev() {
            let mcs = (mcs_rx >> ((nss - 1) * 2)) & 0x03;
            if mcs != 3 {
                return nss;
            }
        }
        1
    }
}

/// Parse Extended Capabilities
pub fn parse_extended_capabilities(ie: &InformationElement) -> Option<ExtendedCapabilities> {
    if ie.id != IE_EXTENDED_CAPABILITIES || ie.data.is_empty() {
        return None;
    }

    Some(ExtendedCapabilities {
        data: ie.data.clone(),
    })
}

#[derive(Debug, Clone)]
pub struct ExtendedCapabilities {
    pub data: Vec<u8>,
}

impl ExtendedCapabilities {
    pub fn has_bss_transition(&self) -> bool {
        self.data.len() > 2 && (self.data[2] & 0x08) != 0
    }

    pub fn has_interworking(&self) -> bool {
        self.data.len() > 3 && (self.data[3] & 0x80) != 0
    }
}
