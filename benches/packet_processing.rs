use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use wifi_insider::parser::radiotap::parse_radiotap;
use wifi_insider::parser::ie_parser::parse_information_elements;
use wifi_insider::types::stats::GlobalStats;

fn benchmark_radiotap_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("radiotap_parsing");

    // Minimal radiotap header
    let minimal_radiotap = vec![
        0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    group.bench_function("minimal", |b| {
        b.iter(|| {
            parse_radiotap(black_box(&minimal_radiotap)).unwrap()
        })
    });

    // Radiotap with multiple fields
    let complex_radiotap = vec![
        0x00, 0x00,       // version, padding
        0x1a, 0x00,       // length (26 bytes)
        0x2f, 0x48, 0x00, 0x00,  // present flags
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // TSFT
        0x00,             // flags
        0x6c,             // rate
        0x6c, 0x09,       // channel freq
        0xa0, 0x00,       // channel flags
        0xdb,             // signal
        0x00,             // noise
        0x00, 0x00,       // antenna
    ];

    group.bench_function("complex", |b| {
        b.iter(|| {
            parse_radiotap(black_box(&complex_radiotap)).unwrap()
        })
    });

    group.finish();
}

fn benchmark_ie_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("ie_parsing");

    // Single IE
    let single_ie = vec![
        0x00, 0x04, b't', b'e', b's', b't',  // SSID = "test"
    ];

    group.bench_function("single_ie", |b| {
        b.iter(|| {
            parse_information_elements(black_box(&single_ie))
        })
    });

    // Multiple IEs (typical beacon)
    let multiple_ies = vec![
        // SSID
        0x00, 0x08, b'T', b'e', b's', b't', b'W', b'i', b'F', b'i',
        // Supported Rates
        0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
        // DS Parameter
        0x03, 0x01, 0x06,
        // TIM
        0x05, 0x04, 0x00, 0x01, 0x00, 0x00,
        // HT Capabilities (26 bytes)
        0x2d, 0x1a,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        // RSN
        0x30, 0x14,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x04,
        0x01, 0x00, 0x00, 0x0f, 0xac, 0x02,
        0x00, 0x00,
    ];

    group.bench_function("multiple_ies", |b| {
        b.iter(|| {
            parse_information_elements(black_box(&multiple_ies))
        })
    });

    group.finish();
}

fn benchmark_stats_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("stats_operations");

    group.bench_function("create_station", |b| {
        let mut global = GlobalStats::new();
        let mut counter = 0u32;

        b.iter(|| {
            let mac = format!("aa:bb:cc:dd:ee:{:02x}", counter % 256);
            global.get_or_create_station(&mac);
            counter += 1;
        })
    });

    group.bench_function("lookup_station", |b| {
        let mut global = GlobalStats::new();

        // Pre-create stations
        for i in 0..100 {
            let mac = format!("aa:bb:cc:dd:ee:{:02x}", i);
            global.get_or_create_station(&mac);
        }

        let mut counter = 0;
        b.iter(|| {
            let mac = format!("aa:bb:cc:dd:ee:{:02x}", counter % 100);
            global.get_or_create_station(black_box(&mac));
            counter += 1;
        })
    });

    group.finish();
}

fn benchmark_packet_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("packet_throughput");

    let packet_data = vec![
        // Radiotap header
        0x00, 0x00, 0x0d, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x6c, 0x6c, 0x09, 0xa0, 0x00, 0xdb,
        // 802.11 header (24 bytes - minimal management frame)
        0x80, 0x00,  // Frame control
        0x00, 0x00,  // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // Addr1
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // Addr2
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,  // Addr3
        0x00, 0x00,  // Seq control
    ];

    for size in [10, 100, 1000].iter() {
        group.bench_with_input(
            BenchmarkId::from_parameter(size),
            size,
            |b, &size| {
                b.iter(|| {
                    for _ in 0..size {
                        parse_radiotap(black_box(&packet_data[..14])).unwrap();
                    }
                })
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    benchmark_radiotap_parsing,
    benchmark_ie_parsing,
    benchmark_stats_operations,
    benchmark_packet_throughput
);
criterion_main!(benches);
