use crate::series::step::{Step, snap_to_tick};

#[test]
fn values_round_to_their_unit_step() {
    let cases = [
        ("cpu.busy_pct", "%", Some(Step::Hundredths)),
        ("load.1m", "ratio", Some(Step::Hundredths)),
        ("temp.c", "Celsius", Some(Step::Tenths)),
        ("mem.used_bytes", "bytes", Some(Step::KiB)),
        ("swap.used_bytes", "bytes", Some(Step::KiB)),
        ("disk.used_bytes", "bytes", Some(Step::KiB)),
        ("diskio.read_bps", "B/s", Some(Step::One)),
        ("net.rx_pps", "pkts/s", Some(Step::One)),
        ("diskio.read_iops", "ops/s", Some(Step::One)),
        ("net.errors", "count", Some(Step::One)),
        ("uptime_s", "s", Some(Step::One)),
        ("check.latency_ms", "ms", None),
        ("driver.something", "", None),
    ];
    for (name, unit, want) in cases {
        assert_eq!(Step::for_metric(name, unit), want, "{name} ({unit})");
    }
    assert_eq!(Step::Hundredths.to_int(12.345_6), Some(1235));
    assert_eq!(Step::Hundredths.to_f64(1235), 12.35);
    assert_eq!(Step::Tenths.to_int(-3.26), Some(-33));
    assert_eq!(Step::KiB.to_int(8_192.0), Some(8));
    assert_eq!(Step::KiB.to_f64(8), 8_192.0);
    assert_eq!(Step::One.to_int(1_234.5), Some(1235));
    for v in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, 1e300] {
        assert_eq!(Step::One.to_int(v), None, "{v} has no integer");
    }
}

#[test]
fn tier0_timestamps_snap_to_tick_later_sample_wins() {
    let base = 1_795_069_665_000i64;
    let points = vec![
        (base + 200, 1.0),
        (base + 200 + 14_200, 2.0),
        (base + 200 + 14_200 + 15_400, 3.0),
        // read twice within one tick: the later sample is kept
        (base + 44_600, 4.0),
        (base + 45_300, 5.0),
    ];
    let snapped = snap_to_tick(&points, 15_000);
    assert_eq!(snapped, vec![(base, 1.0), (base + 15_000, 2.0), (base + 30_000, 3.0), (base + 45_000, 5.0)]);
}
