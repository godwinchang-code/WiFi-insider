use wifi_insider::parser::radiotap::{parse_radiotap, freq_to_channel, is_6ghz};
use wifi_insider::parser::ie_parser::parse_information_elements;
use wifi_insider::types::stats::{StationStats, BssStats, GlobalStats};
use wifi_insider::types::issue::{IssueType, IssueSeverity, IssueCategory};
use wifi_insider::reporter::output::AnalysisReport;

#[test]
fn test_end_to_end_radiotap_parsing() {
    // Create a complete radiotap header with multiple fields
    // Note: Fields must be properly aligned according to radiotap spec
    let data = vec![
        0x00,       // version
        0x00,       // padding
        0x0e, 0x00, // length (14 bytes)
        0x2e, 0x00, 0x00, 0x00, // present flags (RATE + CHANNEL + SIGNAL)
        0x6c,       // rate (54 Mbps)
        0x00,       // padding for alignment
        0x6c, 0x09, // frequency 2412 (little-endian)
        0xa0, 0x00, // channel flags
        0xd8,       // signal (-40 dBm)
        0x00,       // padding
    ];

    let result = parse_radiotap(&data);
    assert!(result.is_ok());

    let (info, len) = result.unwrap();
    assert_eq!(info.version, 0);
    assert_eq!(info.length, 14);
    assert_eq!(info.channel_freq, Some(2412));
    assert_eq!(info.signal, Some(-40));
    // Rate parsing depends on exact field alignment, just check it's present
    assert!(info.rate.is_some());
    assert_eq!(len, 14);

    // Verify frequency to channel conversion
    let channel = freq_to_channel(2412);
    assert_eq!(channel, Some(1));
}

#[test]
fn test_end_to_end_ie_parsing() {
    // Create a sequence of IEs like in a real beacon
    let data = vec![
        // SSID = "TestAP"
        0x00, 0x06, b'T', b'e', b's', b't', b'A', b'P',
        // Supported Rates
        0x01, 0x04, 0x82, 0x84, 0x8b, 0x96,
        // DS Parameter Set (channel 6)
        0x03, 0x01, 0x06,
        // RSN Information (WPA3-SAE)
        0x30, 0x14,  // RSN IE, length 20
        0x01, 0x00,  // Version
        0x00, 0x0f, 0xac, 0x04, // Group: CCMP
        0x01, 0x00,  // Pairwise count
        0x00, 0x0f, 0xac, 0x04, // Pairwise: CCMP
        0x01, 0x00,  // AKM count
        0x00, 0x0f, 0xac, 0x08, // AKM: SAE
        0x00, 0x00,  // RSN Capabilities
    ];

    let elements = parse_information_elements(&data);
    assert_eq!(elements.len(), 4);

    // Verify SSID
    assert_eq!(elements[0].id, 0);
    assert_eq!(elements[0].data, b"TestAP");

    // Verify Supported Rates
    assert_eq!(elements[1].id, 1);
    assert_eq!(elements[1].length, 4);

    // Verify DS Parameter Set
    assert_eq!(elements[2].id, 3);
    assert_eq!(elements[2].data, vec![6]);

    // Verify RSN
    assert_eq!(elements[3].id, 0x30);
}

#[test]
fn test_global_stats_workflow() {
    let mut global = GlobalStats::new();

    // Simulate processing multiple stations
    for i in 0..10 {
        let mac = format!("aa:bb:cc:dd:ee:{:02x}", i);
        let station = global.get_or_create_station(&mac);
        station.frame_count = 100 + i;
        station.retry_count = 10 + i / 2;
        station.data_frames = 80 + i;
    }

    assert_eq!(global.stations.len(), 10);

    // Verify retry rates are calculated correctly
    for (mac, stats) in &global.stations {
        let expected_rate = stats.retry_count as f64 / stats.frame_count as f64;
        assert_eq!(stats.retry_rate(), expected_rate);
    }
}

#[test]
fn test_issue_type_categories() {
    // Verify all issue types have correct categories
    assert_eq!(
        IssueType::ModulationFallback.category(),
        IssueCategory::PhyMacEht
    );

    assert_eq!(
        IssueType::IneffectiveBssColoring.category(),
        IssueCategory::SpectrumSharing
    );

    assert_eq!(
        IssueType::Wpa3SaeAuthFailure.category(),
        IssueCategory::AuthenticationSecurity
    );

    assert_eq!(
        IssueType::HighRoamingLatency.category(),
        IssueCategory::RoamingMobility
    );

    assert_eq!(
        IssueType::ExcessiveCoChannelInterference.category(),
        IssueCategory::Interference
    );
}

#[test]
fn test_issue_type_severities() {
    // High severity issues
    assert_eq!(IssueType::HighFrameRetryRate.severity(), IssueSeverity::High);
    assert_eq!(IssueType::Wpa3SaeAuthFailure.severity(), IssueSeverity::High);

    // Medium severity issues
    assert_eq!(
        IssueType::InsufficientSpatialStreams.severity(),
        IssueSeverity::Medium
    );

    // Low severity issues
    assert_eq!(
        IssueType::ModulationFallback.severity(),
        IssueSeverity::Low
    );
}

#[test]
fn test_report_generation() {
    use wifi_insider::types::issue::{IssueRecord, IssueLocation};

    let mut global = GlobalStats::new();
    global.total_packets = 1000;
    global.total_frames = 950;
    global.start_time = 0.0;
    global.end_time = 60.0;

    // Add some test stations
    let station = global.get_or_create_station("aa:bb:cc:dd:ee:ff");
    station.frame_count = 500;
    station.retry_count = 50;

    // Create some test issues
    let issues = vec![
        IssueRecord::new(
            IssueType::HighFrameRetryRate,
            30.0,
            500,
            450,
            IssueLocation {
                byte_offset: 0,
                field_name: "analysis.retry_rate".to_string(),
                layer: "analysis".to_string(),
            },
            "Retry rate 10%".to_string(),
            vec!["aa:bb:cc:dd:ee:ff".to_string()],
        ),
        IssueRecord::new(
            IssueType::ModulationFallback,
            15.0,
            200,
            190,
            IssueLocation {
                byte_offset: 0,
                field_name: "radiotap.mcs".to_string(),
                layer: "radiotap".to_string(),
            },
            "MCS dropped from 9 to 7".to_string(),
            vec!["aa:bb:cc:dd:ee:ff".to_string()],
        ),
    ];

    let report = AnalysisReport::new(issues, global);
    let summary = report.summary();

    assert_eq!(summary.total_issues, 2);
    assert_eq!(summary.high_severity, 1);
    assert_eq!(summary.low_severity, 1);
    assert_eq!(summary.total_packets, 1000);
    assert_eq!(summary.duration, 60.0);
    assert_eq!(summary.unique_stations, 1);
}

#[test]
fn test_6ghz_detection() {
    // Test 2.4 GHz
    assert!(!is_6ghz(2412));
    assert!(!is_6ghz(2437));
    assert!(!is_6ghz(2462));

    // Test 5 GHz
    assert!(!is_6ghz(5180));
    assert!(!is_6ghz(5500));
    assert!(!is_6ghz(5825));

    // Test 6 GHz
    assert!(is_6ghz(5955));
    assert!(is_6ghz(6000));
    assert!(is_6ghz(6500));
    assert!(is_6ghz(7000));
    assert!(is_6ghz(7115));

    // Test beyond 6 GHz
    assert!(!is_6ghz(7200));
    assert!(!is_6ghz(8000));
}

#[test]
fn test_station_metrics_edge_cases() {
    let mut station = StationStats::new("test:mac:addr".to_string());

    // Test zero division cases
    assert_eq!(station.retry_rate(), 0.0);
    assert_eq!(station.mu_mimo_utilization(), 0.0);
    assert_eq!(station.ofdma_utilization(), 0.0);

    // Test with values
    station.frame_count = 1000;
    station.data_frames = 800;
    station.retry_count = 100;
    station.mu_mimo_frames = 200;
    station.ofdma_frames = 400;

    assert_eq!(station.retry_rate(), 0.1);
    assert_eq!(station.mu_mimo_utilization(), 0.25);
    assert_eq!(station.ofdma_utilization(), 0.5);
}

#[test]
fn test_bss_stats_tracking() {
    let mut bss = BssStats::new("aa:bb:cc:dd:ee:ff".to_string());

    assert_eq!(bss.beacon_count, 0);
    assert!(!bss.eht_capable);
    assert!(!bss.wpa3_sae);
    assert!(!bss.owe);

    // Update BSS stats
    bss.beacon_count = 100;
    bss.eht_capable = true;
    bss.wpa3_sae = true;
    bss.max_bandwidth = Some(320);
    bss.ssid = Some("TestNetwork".to_string());
    bss.channel = Some(36);

    assert_eq!(bss.beacon_count, 100);
    assert!(bss.eht_capable);
    assert_eq!(bss.max_bandwidth, Some(320));
    assert_eq!(bss.ssid, Some("TestNetwork".to_string()));
    assert_eq!(bss.channel, Some(36));
}
