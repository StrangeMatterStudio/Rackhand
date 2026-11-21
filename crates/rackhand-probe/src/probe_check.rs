//! `probe_check` steps on the probe (D115): a check the hub sends as `RunCheck`, run from this machine for what only
//! it can reach (a service on localhost). The syntax is the hub's TCP and HTTP check kinds, `tcp:<host>:<port>` and
//! `http:<url>`, run by the same drivers. Only loopback and this machine's own addresses are checked: a name is judged
//! by every address it resolves to, and the check then connects to the address it judged.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use rackhand_drivers::{Driver, DriverTarget, Http, Tcp};
use rackhand_proto::probe::{CheckResult, RunCheck};

/// Whether `ip` is this machine's: loopback, or an address a socket can be bound to here.
pub fn own(ip: IpAddr) -> bool {
    ip.is_loopback() || std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok()
}

/// What a check's result says on failure.
fn failed(detail: impl Into<String>) -> Outcome {
    Outcome { ok: false, detail: detail.into(), latency_ms: 0.0 }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub ok: bool,
    pub detail: String,
    pub latency_ms: f64,
}

/// The host and port of a `tcp:` target or an `http:` URL.
fn host_port(kind: &str, rest: &str) -> Result<(String, u16), String> {
    if kind == "http" {
        let url = url::Url::parse(rest).map_err(|e| format!("the URL: {e}"))?;
        if !matches!(url.scheme(), "http" | "https") {
            return Err("an http:// or https:// URL".into());
        }
        let host = url.host_str().ok_or("the URL has no host")?.trim_start_matches('[').trim_end_matches(']');
        return Ok((host.to_string(), url.port_or_known_default().unwrap_or(80)));
    }
    let (host, port) = rest.rsplit_once(':').ok_or("tcp:<host>:<port>")?;
    let port = port.parse().map_err(|_| "tcp:<host>:<port>".to_string())?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if host.is_empty() {
        return Err("tcp:<host>:<port>".into());
    }
    Ok((host.to_string(), port))
}

/// Runs `check`, resolving names with `resolve` (the system resolver in [`run`]).
pub async fn run_with(check: &str, timeout: Duration, resolve: &(dyn Fn(&str) -> Vec<IpAddr> + Sync)) -> Outcome {
    let Some((kind, rest)) = check.split_once(':') else { return failed("a check is tcp:<host>:<port> or http:<url>") };
    if !matches!(kind, "tcp" | "http") {
        return failed(format!("only tcp and http checks run on the probe, not {kind}"));
    }
    let (host, port) = match host_port(kind, rest) {
        Ok(hp) => hp,
        Err(e) => return failed(e),
    };
    let ips: Vec<IpAddr> = match host.parse() {
        Ok(ip) => vec![ip],
        Err(_) => resolve(&host),
    };
    let Some(first) = ips.first().copied() else { return failed(format!("{host} doesn't resolve")) };
    if let Some(away) = ips.iter().find(|ip| !own(**ip)) {
        return failed(format!("{away} isn't this machine's address: a probe checks only its own machine"));
    }
    let at = SocketAddr::new(first, port).to_string();
    let target = match kind {
        "tcp" => at,
        _ => {
            let mut url = url::Url::parse(rest).expect("parsed above");
            let _ = url.set_ip_host(first);
            url.to_string()
        }
    };
    let target = DriverTarget { target, settings: serde_json::Value::Null, timeout };
    let started = Instant::now();
    let reading = if kind == "tcp" { Tcp::new().poll(&target).await } else { Http::new().poll(&target).await };
    match reading {
        Ok(r) => Outcome {
            ok: r.ok,
            detail: r.detail,
            latency_ms: r.latency_ms.unwrap_or_else(|| started.elapsed().as_secs_f64() * 1000.0),
        },
        Err(e) => failed(e.to_string()),
    }
}

fn system_resolve(host: &str) -> Vec<IpAddr> {
    use std::net::ToSocketAddrs;
    (host, 0).to_socket_addrs().map(|a| a.map(|s| s.ip()).collect()).unwrap_or_default()
}

/// Runs a `RunCheck` from the hub and makes its answer.
pub async fn run(rc: RunCheck) -> CheckResult {
    let timeout = Duration::from_millis(u64::from(rc.timeout_ms.clamp(100, 60_000)));
    let host = rc.check.clone();
    let resolved = tokio::task::spawn_blocking(move || {
        host.split_once(':')
            .and_then(|(kind, rest)| host_port(kind, rest).ok())
            .map(|(h, _)| system_resolve(&h))
            .unwrap_or_default()
    })
    .await
    .unwrap_or_default();
    let o = run_with(&rc.check, timeout, &move |_| resolved.clone()).await;
    CheckResult { id: rc.id, ok: o.ok, detail: o.detail, latency_ms: o.latency_ms }
}

#[cfg(test)]
mod tests;
