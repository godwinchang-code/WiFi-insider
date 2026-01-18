use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Statistics for a specific station (client or AP)
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StationStats {
    pub mac_address: String,
    pub frame_count: u64,
    pub retry_count: u64,
    pub data_frames: u64,
    pub mgmt_frames: u64,
    pub ctrl_frames: u64,
    pub qos_frames: u64,

    // PHY stats
    pub mcs_distribution: HashMap<u8, u64>,
    pub nss_distribution: HashMap<u8, u64>,
    pub bandwidth_distribution: HashMap<u16, u64>,

    // EHT specific
    pub eht_frames: u64,
    pub mu_mimo_frames: u64,
    pub ofdma_frames: u64,
    pub ru_allocations: HashMap<u16, u64>,

    // Timing
    pub first_seen: f64,
    pub last_seen: f64,

    // Roaming
    pub association_count: u64,
    pub reassociation_count: u64,
    pub probe_request_count: u64,
    pub probe_response_count: u64,

    // Authentication
    pub auth_attempts: u64,
    pub auth_failures: u64,
    pub assoc_attempts: u64,
    pub assoc_failures: u64,
}

impl StationStats {
    pub fn new(mac_address: String) -> Self {
        Self {
            mac_address,
            ..Default::default()
        }
    }

    pub fn retry_rate(&self) -> f64 {
        if self.frame_count == 0 {
            0.0
        } else {
            self.retry_count as f64 / self.frame_count as f64
        }
    }

    pub fn mu_mimo_utilization(&self) -> f64 {
        if self.data_frames == 0 {
            0.0
        } else {
            self.mu_mimo_frames as f64 / self.data_frames as f64
        }
    }

    pub fn ofdma_utilization(&self) -> f64 {
        if self.data_frames == 0 {
            0.0
        } else {
            self.ofdma_frames as f64 / self.data_frames as f64
        }
    }
}

/// BSSID (AP) specific statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BssStats {
    pub bssid: String,
    pub ssid: Option<String>,
    pub channel: Option<u8>,
    pub beacon_count: u64,
    pub beacon_interval: Option<u16>,
    pub capabilities: Option<u16>,

    // BSS Color (HE/EHT)
    pub bss_color: Option<u8>,
    pub bss_color_changes: u64,

    // Security
    pub rsn_info: Option<String>,
    pub wpa3_sae: bool,
    pub owe: bool,

    // 6 GHz specific
    pub is_6ghz: bool,
    pub rnr_count: u64,

    // MLO
    pub mlo_capable: bool,
    pub mlo_links: Vec<String>,

    // EHT capabilities
    pub eht_capable: bool,
    pub max_bandwidth: Option<u16>,
    pub max_mcs: Option<u8>,
    pub max_nss: Option<u8>,

    // Timing
    pub first_seen: f64,
    pub last_seen: f64,

    // Connected stations
    pub associated_stations: HashMap<String, f64>, // MAC -> last seen
}

impl BssStats {
    pub fn new(bssid: String) -> Self {
        Self {
            bssid,
            ..Default::default()
        }
    }
}

/// Channel utilization tracking
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChannelStats {
    pub channel: u8,
    pub total_time_us: u64,
    pub busy_time_us: u64,
    pub tx_time_us: u64,
    pub rx_time_us: u64,
    pub frame_count: u64,
    pub bss_count: usize,
}

impl ChannelStats {
    pub fn utilization(&self) -> f64 {
        if self.total_time_us == 0 {
            0.0
        } else {
            self.busy_time_us as f64 / self.total_time_us as f64
        }
    }
}

/// Global analysis statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalStats {
    pub total_packets: u64,
    pub total_frames: u64,
    pub analysis_duration: f64,
    pub stations: HashMap<String, StationStats>,
    pub bss: HashMap<String, BssStats>,
    pub channels: HashMap<u8, ChannelStats>,
    pub start_time: f64,
    pub end_time: f64,
}

impl GlobalStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create_station(&mut self, mac: &str) -> &mut StationStats {
        self.stations
            .entry(mac.to_string())
            .or_insert_with(|| StationStats::new(mac.to_string()))
    }

    pub fn get_or_create_bss(&mut self, bssid: &str) -> &mut BssStats {
        self.bss
            .entry(bssid.to_string())
            .or_insert_with(|| BssStats::new(bssid.to_string()))
    }

    pub fn get_or_create_channel(&mut self, channel: u8) -> &mut ChannelStats {
        self.channels
            .entry(channel)
            .or_insert_with(|| ChannelStats {
                channel,
                ..Default::default()
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_station_stats_new() {
        let stats = StationStats::new("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(stats.mac_address, "aa:bb:cc:dd:ee:ff");
        assert_eq!(stats.frame_count, 0);
        assert_eq!(stats.retry_count, 0);
    }

    #[test]
    fn test_station_retry_rate() {
        let mut stats = StationStats::new("aa:bb:cc:dd:ee:ff".to_string());
        stats.frame_count = 100;
        stats.retry_count = 15;

        assert_eq!(stats.retry_rate(), 0.15);
    }

    #[test]
    fn test_station_retry_rate_zero_frames() {
        let stats = StationStats::new("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(stats.retry_rate(), 0.0);
    }

    #[test]
    fn test_station_mu_mimo_utilization() {
        let mut stats = StationStats::new("aa:bb:cc:dd:ee:ff".to_string());
        stats.data_frames = 200;
        stats.mu_mimo_frames = 40;

        assert_eq!(stats.mu_mimo_utilization(), 0.2);
    }

    #[test]
    fn test_station_ofdma_utilization() {
        let mut stats = StationStats::new("aa:bb:cc:dd:ee:ff".to_string());
        stats.data_frames = 100;
        stats.ofdma_frames = 50;

        assert_eq!(stats.ofdma_utilization(), 0.5);
    }

    #[test]
    fn test_bss_stats_new() {
        let stats = BssStats::new("aa:bb:cc:dd:ee:ff".to_string());
        assert_eq!(stats.bssid, "aa:bb:cc:dd:ee:ff");
        assert_eq!(stats.beacon_count, 0);
        assert!(!stats.eht_capable);
    }

    #[test]
    fn test_channel_stats_utilization() {
        let mut stats = ChannelStats::default();
        stats.total_time_us = 1_000_000;  // 1 second
        stats.busy_time_us = 500_000;     // 0.5 seconds

        assert_eq!(stats.utilization(), 0.5);
    }

    #[test]
    fn test_channel_stats_utilization_zero() {
        let stats = ChannelStats::default();
        assert_eq!(stats.utilization(), 0.0);
    }

    #[test]
    fn test_global_stats_get_or_create_station() {
        let mut global = GlobalStats::new();

        let station1 = global.get_or_create_station("aa:bb:cc:dd:ee:ff");
        station1.frame_count = 10;

        let station2 = global.get_or_create_station("aa:bb:cc:dd:ee:ff");
        assert_eq!(station2.frame_count, 10);  // Should be same instance

        let station3 = global.get_or_create_station("11:22:33:44:55:66");
        assert_eq!(station3.frame_count, 0);  // New station

        assert_eq!(global.stations.len(), 2);
    }

    #[test]
    fn test_global_stats_get_or_create_bss() {
        let mut global = GlobalStats::new();

        let bss1 = global.get_or_create_bss("aa:bb:cc:dd:ee:ff");
        bss1.beacon_count = 5;

        let bss2 = global.get_or_create_bss("aa:bb:cc:dd:ee:ff");
        assert_eq!(bss2.beacon_count, 5);  // Should be same instance

        assert_eq!(global.bss.len(), 1);
    }

    #[test]
    fn test_global_stats_get_or_create_channel() {
        let mut global = GlobalStats::new();

        let ch1 = global.get_or_create_channel(6);
        ch1.frame_count = 100;

        let ch2 = global.get_or_create_channel(6);
        assert_eq!(ch2.frame_count, 100);  // Should be same instance

        assert_eq!(global.channels.len(), 1);
    }
}
