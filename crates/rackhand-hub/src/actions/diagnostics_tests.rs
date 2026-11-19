use std::collections::BTreeMap;
use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::{OUTPUT_LIMIT, prepare, untrusted};
use crate::actions::ActionsError;

/// The names in design 7.8.3, in its order.
const DESIGN: [&str; 19] = [
    "journal",
    "failed_units",
    "service_status",
    "docker_ps",
    "compose_ps",
    "docker_logs",
    "df",
    "mounts",
    "du_top",
    "free",
    "uptime",
    "top_processes",
    "ss_listen",
    "ss_established",
    "dmesg_tail",
    "updates_pending",
    "last_logins",
    "ping",
    "http_head",
];

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

/// Two sites: `web` and `db` at home, `far` elsewhere; `web` has an HTTP check.
async fn db(name: &str) -> Arc<Db> {
    let dir = std::env::temp_dir().join(format!("rackhand-diag-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let site =
        |id: &str| RowWrite::insert("sites", Row::from([("id", t(id)), ("name", t(id)), ("timezone", t("UTC"))]));
    let machine = |id: &str, site: &str, kind: &str, address: &str| {
        RowWrite::insert(
            "machines",
            Row::from([
                ("id", t(id)),
                ("site_id", t(site)),
                ("name", t(id)),
                ("kind", t(kind)),
                ("address", t(address)),
            ]),
        )
    };
    db.writer()
        .send(WriteCmd::Batch(vec![
            site("home"),
            site("away"),
            machine("web", "home", "linux", "192.0.2.10"),
            machine("db", "home", "alpine", "192.0.2.11"),
            machine("far", "away", "linux", "198.51.100.7"),
            RowWrite::insert(
                "checks",
                Row::from([
                    ("id", t("c1")),
                    ("kind", t("http")),
                    ("target", t("https://web.home.example/healthz")),
                    ("interval_s", Value::Integer(60)),
                    ("machine_id", t("web")),
                ]),
            ),
        ]))
        .await
        .unwrap();
    db
}

fn args(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

#[test]
fn every_name_in_design_exists() {
    let names: Vec<&str> = rackhand_runbook::diagnostics::builtin().iter().map(|d| d.name.as_str()).collect();
    assert_eq!(names, DESIGN);
    // Each one's root commands are in every command list, under the wrapper.
    let templates = rackhand_runbook::diagnostics::templates();
    for name in ["journal", "docker_ps", "docker_logs", "du_top", "ss_listen", "dmesg_tail"] {
        assert!(templates.iter().any(|t| t.runbook == "diagnostics" && t.step == name), "{name}");
    }
    assert!(!templates.iter().any(|t| t.step == "df"), "df runs as the automation user, not through the wrapper");
    assert_eq!(OUTPUT_LIMIT, 256 * 1024);
}

#[tokio::test(flavor = "multi_thread")]
async fn parameter_limits_enforced() {
    let db = db("limits").await;
    let journal = |lines: &str| args(&[("unit", "nginx.service"), ("since", "1 hour ago"), ("lines", lines)]);
    let ok = prepare(&db, "web", "journal", &journal("2000")).unwrap();
    assert_eq!(
        ok.argv,
        [
            "sudo",
            "/usr/local/lib/rackhand/run",
            "/usr/bin/journalctl",
            "-u",
            "nginx.service",
            "--since",
            "1 hour ago",
            "-n",
            "2000",
            "--no-pager"
        ]
    );
    assert!(
        matches!(prepare(&db, "web", "journal", &journal("2001")), Err(ActionsError::InvalidParam(p, _)) if p == "lines")
    );
    let du = |depth: &str| args(&[("path", "/var/lib"), ("depth", depth)]);
    assert!(prepare(&db, "web", "du_top", &du("3")).is_ok());
    assert!(matches!(prepare(&db, "web", "du_top", &du("4")), Err(ActionsError::InvalidParam(p, _)) if p == "depth"));
    // ping: a machine in the same site, by name or address; not one elsewhere, not any address.
    assert!(prepare(&db, "web", "ping", &args(&[("target", "db")])).is_ok());
    assert!(prepare(&db, "web", "ping", &args(&[("target", "192.0.2.11")])).is_ok());
    for outside in ["far", "198.51.100.7", "203.0.113.9", "example.com"] {
        let refused = prepare(&db, "web", "ping", &args(&[("target", outside)]));
        assert!(matches!(refused, Err(ActionsError::InvalidParam(p, _)) if p == "target"), "{outside}");
    }
    // http_head: only a URL the machine's checks use.
    assert!(prepare(&db, "web", "http_head", &args(&[("url", "https://web.home.example/healthz")])).is_ok());
    let other = prepare(&db, "web", "http_head", &args(&[("url", "https://elsewhere.example/")]));
    assert!(matches!(other, Err(ActionsError::InvalidParam(p, _)) if p == "url"));
    // Missing and extra parameters, an unknown name, and the Alpine variant.
    assert!(matches!(prepare(&db, "web", "journal", &args(&[])), Err(ActionsError::InvalidParam(..))));
    assert!(matches!(prepare(&db, "web", "df", &args(&[("x", "1")])), Err(ActionsError::InvalidParam(..))));
    assert!(matches!(prepare(&db, "web", "rm_rf", &args(&[])), Err(ActionsError::UnknownDiagnostic)));
    assert_eq!(prepare(&db, "db", "failed_units", &args(&[])).unwrap().argv, ["rc-status", "--crashed"]);
}

#[test]
fn sensitive_flag_on_journal_and_docker_logs_only() {
    let sensitive: Vec<&str> =
        rackhand_runbook::diagnostics::builtin().iter().filter(|d| d.sensitive).map(|d| d.name.as_str()).collect();
    assert_eq!(sensitive, ["journal", "docker_logs"]);
    // Every diagnostic's output goes back wrapped as untrusted.
    assert_eq!(untrusted(b"ok\n"), serde_json::json!({ "untrusted_output": "ok\n" }));
}

#[tokio::test(flavor = "multi_thread")]
async fn leading_dash_unit_refused() {
    let db = db("dash").await;
    let journal = prepare(&db, "web", "journal", &args(&[("unit", "-f"), ("since", "today"), ("lines", "10")]));
    assert!(matches!(journal, Err(ActionsError::InvalidParam(p, _)) if p == "unit"));
    let status = prepare(&db, "web", "service_status", &args(&[("name", "--all")]));
    assert!(matches!(status, Err(ActionsError::InvalidParam(p, _)) if p == "name"));
    let du = prepare(&db, "web", "du_top", &args(&[("path", "-x"), ("depth", "1")]));
    assert!(matches!(du, Err(ActionsError::InvalidParam(p, _)) if p == "path"));
}
