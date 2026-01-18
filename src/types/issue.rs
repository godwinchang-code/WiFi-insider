use serde::{Deserialize, Serialize};
use std::fmt;

/// Categories of Wi-Fi 7 issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssueCategory {
    PhyMacEht,
    SpectrumSharing,
    AuthenticationSecurity,
    RoamingMobility,
    Interference,
}

/// Specific Wi-Fi 7 issue types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IssueType {
    // PHY / MAC / EHT Capability & Scheduling (1-14)
    ModulationFallback,           // 1
    InsufficientSpatialStreams,   // 2
    ChannelBandwidthMismatch,     // 3
    ImproperEhtRuAllocation,      // 4
    LowDownlinkOfdmaTriggerRate,  // 5
    LowUplinkOfdmaTriggerRate,    // 6
    LowMuMimoUtilization,         // 7
    HighFrameRetryRate,           // 8
    HighChannelUtilization,       // 9
    CcaBusySchedulingDegradation, // 10
    AbnormalPpduTypeSelection,    // 11
    IncompleteEhtCapabilityNegotiation, // 12
    ClientNegotiatingLessThan320MHz,    // 13
    MloNegotiationFailure,        // 14

    // Spectrum Sharing / Coordination Features (15-18)
    IneffectiveBssColoring,       // 15
    Incomplete6GhzRnr,            // 16
    ChannelSwitchAnomalies,       // 17
    MissingMandatoryFields,       // 18

    // Authentication / Association / Security (19-22)
    Wpa3SaeAuthFailure,           // 19
    OweNegotiationFailure,        // 20
    AssociationRejection,         // 21
    SixGhzSecurityPolicyFailure,  // 22

    // Roaming & Mobility (23-29)
    HighRoamingLatency,           // 23
    Dot11rFtFailure,              // 24
    AbnormalNeighborReports,      // 25
    AbnormalBssTransition,        // 26
    StickyClientBehavior,         // 27
    AbnormalProbeRequestResponse, // 28
    AbnormalBeaconScanning,       // 29

    // Interference / Multi-BSS Behavioral (30-32)
    ExcessiveCoChannelInterference, // 30
    AdjacentChannelInterference,    // 31
    ObssSchedulingDegradation,      // 32
}

impl IssueType {
    pub fn category(&self) -> IssueCategory {
        match self {
            Self::ModulationFallback
            | Self::InsufficientSpatialStreams
            | Self::ChannelBandwidthMismatch
            | Self::ImproperEhtRuAllocation
            | Self::LowDownlinkOfdmaTriggerRate
            | Self::LowUplinkOfdmaTriggerRate
            | Self::LowMuMimoUtilization
            | Self::HighFrameRetryRate
            | Self::HighChannelUtilization
            | Self::CcaBusySchedulingDegradation
            | Self::AbnormalPpduTypeSelection
            | Self::IncompleteEhtCapabilityNegotiation
            | Self::ClientNegotiatingLessThan320MHz
            | Self::MloNegotiationFailure => IssueCategory::PhyMacEht,

            Self::IneffectiveBssColoring
            | Self::Incomplete6GhzRnr
            | Self::ChannelSwitchAnomalies
            | Self::MissingMandatoryFields => IssueCategory::SpectrumSharing,

            Self::Wpa3SaeAuthFailure
            | Self::OweNegotiationFailure
            | Self::AssociationRejection
            | Self::SixGhzSecurityPolicyFailure => IssueCategory::AuthenticationSecurity,

            Self::HighRoamingLatency
            | Self::Dot11rFtFailure
            | Self::AbnormalNeighborReports
            | Self::AbnormalBssTransition
            | Self::StickyClientBehavior
            | Self::AbnormalProbeRequestResponse
            | Self::AbnormalBeaconScanning => IssueCategory::RoamingMobility,

            Self::ExcessiveCoChannelInterference
            | Self::AdjacentChannelInterference
            | Self::ObssSchedulingDegradation => IssueCategory::Interference,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            Self::ModulationFallback => "Modulation fallback (MCS downgrade)",
            Self::InsufficientSpatialStreams => "Insufficient spatial streams (NSS mismatch)",
            Self::ChannelBandwidthMismatch => "Channel bandwidth mismatch (20/40/80/160/320 MHz)",
            Self::ImproperEhtRuAllocation => "Improper EHT RU allocation",
            Self::LowDownlinkOfdmaTriggerRate => "Low downlink OFDMA trigger rate",
            Self::LowUplinkOfdmaTriggerRate => "Low uplink OFDMA trigger rate",
            Self::LowMuMimoUtilization => "Low MU-MIMO utilization",
            Self::HighFrameRetryRate => "High frame retry rate",
            Self::HighChannelUtilization => "High channel utilization (busy medium)",
            Self::CcaBusySchedulingDegradation => "CCA busy causing scheduling degradation",
            Self::AbnormalPpduTypeSelection => "Abnormal PPDU type selection",
            Self::IncompleteEhtCapabilityNegotiation => "Incomplete EHT capability negotiation",
            Self::ClientNegotiatingLessThan320MHz => "Client negotiating less than 320 MHz",
            Self::MloNegotiationFailure => "MLO negotiation failure or not triggered",
            Self::IneffectiveBssColoring => "Ineffective BSS Coloring behavior",
            Self::Incomplete6GhzRnr => "Incomplete 6 GHz Reduced Neighbor Report (RNR)",
            Self::ChannelSwitchAnomalies => "Channel Switch Announcement (CSA) anomalies",
            Self::MissingMandatoryFields => "Management frames missing mandatory fields",
            Self::Wpa3SaeAuthFailure => "WPA3-SAE authentication failure",
            Self::OweNegotiationFailure => "OWE negotiation failure",
            Self::AssociationRejection => "Association rejection with reason codes",
            Self::SixGhzSecurityPolicyFailure => "6 GHz association failure due to security policy",
            Self::HighRoamingLatency => "High roaming latency (slow reassociation)",
            Self::Dot11rFtFailure => "802.11r FT not triggered or failing",
            Self::AbnormalNeighborReports => "Abnormal 802.11k neighbor reports",
            Self::AbnormalBssTransition => "Abnormal 802.11v BSS Transition behavior",
            Self::StickyClientBehavior => "Sticky client behavior visible in scan/association pattern",
            Self::AbnormalProbeRequestResponse => "Abnormal Probe Request / Probe Response behavior",
            Self::AbnormalBeaconScanning => "Abnormal Beacon scanning or selection behavior",
            Self::ExcessiveCoChannelInterference => "Excessive co-channel interference (dense beacon presence)",
            Self::AdjacentChannelInterference => "Observable adjacent channel interference",
            Self::ObssSchedulingDegradation => "OBSS-induced scheduling degradation",
        }
    }

    pub fn severity(&self) -> IssueSeverity {
        match self {
            Self::ModulationFallback
            | Self::ChannelBandwidthMismatch
            | Self::LowMuMimoUtilization
            | Self::ClientNegotiatingLessThan320MHz => IssueSeverity::Low,

            Self::InsufficientSpatialStreams
            | Self::ImproperEhtRuAllocation
            | Self::LowDownlinkOfdmaTriggerRate
            | Self::LowUplinkOfdmaTriggerRate
            | Self::HighChannelUtilization
            | Self::AbnormalPpduTypeSelection
            | Self::IneffectiveBssColoring
            | Self::Incomplete6GhzRnr
            | Self::AbnormalNeighborReports
            | Self::AbnormalBssTransition
            | Self::AbnormalProbeRequestResponse
            | Self::AbnormalBeaconScanning
            | Self::ExcessiveCoChannelInterference
            | Self::AdjacentChannelInterference => IssueSeverity::Medium,

            Self::HighFrameRetryRate
            | Self::CcaBusySchedulingDegradation
            | Self::IncompleteEhtCapabilityNegotiation
            | Self::MloNegotiationFailure
            | Self::ChannelSwitchAnomalies
            | Self::MissingMandatoryFields
            | Self::Wpa3SaeAuthFailure
            | Self::OweNegotiationFailure
            | Self::AssociationRejection
            | Self::SixGhzSecurityPolicyFailure
            | Self::HighRoamingLatency
            | Self::Dot11rFtFailure
            | Self::StickyClientBehavior
            | Self::ObssSchedulingDegradation => IssueSeverity::High,
        }
    }
}

/// Severity level of detected issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum IssueSeverity {
    Low,
    Medium,
    High,
}

impl fmt::Display for IssueSeverity {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
        }
    }
}

/// Detailed information about a detected issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueRecord {
    pub issue_type: IssueType,
    pub severity: IssueSeverity,
    pub timestamp: f64,           // Packet timestamp
    pub packet_number: u64,       // Packet number in pcap file
    pub frame_number: u64,        // Frame number (for radiotap)
    pub location: IssueLocation,  // Where in the frame the issue was detected
    pub details: String,          // Detailed description
    pub related_addrs: Vec<String>, // Related MAC addresses
}

/// Location information for where an issue was detected
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssueLocation {
    pub byte_offset: usize,       // Byte offset in packet
    pub field_name: String,       // Field name where issue detected
    pub layer: String,            // Protocol layer (e.g., "radiotap", "802.11", "IE")
}

impl IssueRecord {
    pub fn new(
        issue_type: IssueType,
        timestamp: f64,
        packet_number: u64,
        frame_number: u64,
        location: IssueLocation,
        details: String,
        related_addrs: Vec<String>,
    ) -> Self {
        Self {
            severity: issue_type.severity(),
            issue_type,
            timestamp,
            packet_number,
            frame_number,
            location,
            details,
            related_addrs,
        }
    }
}

impl fmt::Display for IssueRecord {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] {} @ packet #{} (frame #{}, offset {}, {}) - {}",
            self.severity,
            self.issue_type.description(),
            self.packet_number,
            self.frame_number,
            self.location.byte_offset,
            self.location.field_name,
            self.details
        )
    }
}
