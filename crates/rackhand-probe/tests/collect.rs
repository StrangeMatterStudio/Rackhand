//! `rackhand-probe collect --once --json` (7.7.3).

#![allow(clippy::unwrap_used)]

mod collect {
    #[test]
    fn once_json_prints_one_sample_set() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/proc/debian-vm/a");
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_rackhand-probe"))
            .args(["collect", "--once", "--json", "--interval-ms", "10", "--root"])
            .arg(&root)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let series = json["series"].as_array().unwrap();
        let names: Vec<&str> = series.iter().map(|s| s["metric"].as_str().unwrap()).collect();
        for want in ["cpu.busy_pct", "mem.available_pct", "disk.used_pct", "net.rx_bps", "uptime_s"] {
            assert!(names.contains(&want), "{want} not in {names:?}");
        }
        assert!(series.iter().all(|s| s["unit"].is_string() && s["value"].is_number() && s["labels"].is_object()));
        assert!(json["sampled_at_ms"].as_i64().unwrap() > 0);
        assert!(json["services"].is_array() && json["events"].is_array());
        let bad = std::process::Command::new(env!("CARGO_BIN_EXE_rackhand-probe"))
            .args(["collect", "--bogus"])
            .output()
            .unwrap();
        assert!(!bad.status.success());
    }
}
