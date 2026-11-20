//! `GET /metrics` (7.3.14, 12): the latest value of every series as `rackhand_<metric>{site,machine,<labels>}` and
//! the hub's internals, in the Prometheus text format, behind the bearer token `metrics_token` in the Vault.

use std::collections::BTreeMap;
use std::fmt::Write;

use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};
use sha2::{Digest, Sha256};

use super::Web;

fn escape(v: &str) -> String {
    v.replace('\\', "\\\\").replace('"', "\\\"").replace('\n', "\\n")
}

fn name_of(metric: &str) -> String {
    let clean: String = metric.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
    format!("rackhand_{clean}")
}

fn number(v: f64) -> String {
    if v.is_nan() {
        "NaN".into()
    } else if v.is_infinite() {
        if v > 0.0 { "+Inf".into() } else { "-Inf".into() }
    } else {
        format!("{v}")
    }
}

/// Whether the request carries the bearer token (compared as digests, in constant time for equal lengths).
fn authorized(web: &Web, auth: Option<&str>) -> bool {
    let Some(given) = auth.and_then(|a| a.strip_prefix("Bearer ")) else { return false };
    let Ok(token) = web.0.vault.get("metrics_token") else { return false };
    let a: [u8; 32] = Sha256::digest(given.trim().as_bytes()).into();
    let b: [u8; 32] = Sha256::digest(token.expose()).into();
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

pub(crate) fn render(web: &Web, auth: Option<&str>, now_ms: i64) -> Response<Body> {
    if !authorized(web, auth) {
        let mut resp = Response::new(Body::from("a bearer token is required\n"));
        *resp.status_mut() = StatusCode::UNAUTHORIZED;
        resp.headers_mut().insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        return resp;
    }
    let mut out = String::new();
    // machine id to (site, machine) names
    let names: BTreeMap<String, (String, String)> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT m.id, s.name, m.name FROM machines m JOIN sites s ON s.id = m.site_id")?;
            s.query_map([], |r| Ok((r.get(0)?, (r.get(1)?, r.get(2)?))))?.collect()
        })
        .unwrap_or_default();
    let mut by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    if let Some(ingest) = web.0.ingest.as_ref() {
        for (machine, series, _, value) in ingest.latest_values() {
            let Some((site, name)) = names.get(&machine) else { continue };
            let labels: BTreeMap<String, String> = serde_json::from_str(&series.labels).unwrap_or_default();
            let mut l = format!("site=\"{}\",machine=\"{}\"", escape(site), escape(name));
            for (k, v) in &labels {
                let key: String =
                    k.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' { c } else { '_' }).collect();
                let _ = write!(l, ",{key}=\"{}\"", escape(v));
            }
            let metric = name_of(&series.name);
            by_name.entry(metric.clone()).or_default().push(format!("{metric}{{{l}}} {}", number(value)));
        }
    }
    for (metric, lines) in &by_name {
        let _ = writeln!(out, "# TYPE {metric} gauge");
        for line in lines {
            let _ = writeln!(out, "{line}");
        }
    }
    internals(web, now_ms, &mut out);
    let mut resp = Response::new(Body::from(out));
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"));
    resp
}

/// The hub's own metrics (section 12).
fn internals(web: &Web, now_ms: i64, out: &mut String) {
    let reports = web.0.ingest.as_ref().map_or(0, |i| i.reports_total());
    let read =
        |sql: &str| -> f64 { web.0.db.readers().with(|c| c.query_row(sql, [], |r| r.get::<_, f64>(0))).unwrap_or(0.0) };
    let oldest_staged = read("SELECT coalesce(min(received_at_ms), 0) FROM report_staging");
    let lag = if oldest_staged > 0.0 { ((now_ms as f64 - oldest_staged) / 1000.0).max(0.0) } else { 0.0 };
    let one = |out: &mut String, name: &str, kind: &str, value: f64| {
        let _ = writeln!(out, "# TYPE {name} {kind}\n{name} {}", number(value));
    };
    one(out, "rackhand_hub_ingest_reports_total", "counter", reports as f64);
    one(out, "rackhand_hub_ingest_lag_seconds", "gauge", lag);
    one(out, "rackhand_hub_staging_rows", "gauge", read("SELECT count(*) FROM report_staging"));
    one(out, "rackhand_hub_jobs_running", "gauge", read("SELECT count(*) FROM jobs WHERE state = 'running'"));
    one(
        out,
        "rackhand_hub_db_size_bytes",
        "gauge",
        read("SELECT page_count * page_size FROM pragma_page_count(), pragma_page_size()"),
    );
    one(
        out,
        "rackhand_hub_notifier_failures_total",
        "counter",
        read("SELECT count(*) FROM notifications WHERE state = 'failed'"),
    );
    // a peer or operator is up when it was seen in the last 10 minutes
    let up = |out: &mut String, name: &str, label: &str, sql: &str| {
        let _ = writeln!(out, "# TYPE {name} gauge");
        let rows: Vec<(String, i64)> = web
            .0
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(sql)?;
                s.query_map([], |r| Ok((r.get(0)?, r.get::<_, Option<i64>>(1)?.unwrap_or(0))))?.collect()
            })
            .unwrap_or_default();
        for (who, seen) in rows {
            let _ = writeln!(out, "{name}{{{label}=\"{}\"}} {}", escape(&who), u8::from(now_ms - seen < 600_000));
        }
    };
    up(out, "rackhand_hub_peer_up", "peer", "SELECT site, last_seen_ms FROM peers WHERE revoked_at IS NULL");
    up(
        out,
        "rackhand_hub_operator_up",
        "operator",
        "SELECT name, last_seen_ms FROM operators WHERE revoked_at IS NULL",
    );
}
