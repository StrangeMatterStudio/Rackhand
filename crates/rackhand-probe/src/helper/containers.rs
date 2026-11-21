//! Container states (7.3.3): read-only calls to the Docker or Podman API socket (`GET /containers/json` and
//! `GET /containers/<id>/json`), so the probe never needs to be in the `docker` group (it would be root-equivalent).

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use rackhand_proto::helper::ContainerInfo;

/// The sockets tried, in order.
pub const SOCKETS: &[&str] = &["/var/run/docker.sock", "/run/podman/podman.sock"];

/// The containers of the first engine socket that answers; none when there is no engine.
pub fn list() -> Result<Vec<ContainerInfo>, String> {
    let Some(socket) = SOCKETS.iter().map(Path::new).find(|p| p.exists()) else { return Ok(Vec::new()) };
    list_at(socket)
}

pub fn list_at(socket: &Path) -> Result<Vec<ContainerInfo>, String> {
    let all = get(socket, "/containers/json?all=1")?;
    let Some(items) = all.as_array() else { return Err("not a container list".into()) };
    let mut out = Vec::new();
    for c in items {
        let id = c["Id"].as_str().unwrap_or_default().to_string();
        let detail = get(socket, &format!("/containers/{id}/json")).unwrap_or_default();
        out.push(ContainerInfo {
            name: c["Names"][0].as_str().unwrap_or_default().trim_start_matches('/').to_string(),
            image: c["Image"].as_str().unwrap_or_default().to_string(),
            state: c["State"].as_str().unwrap_or_default().to_string(),
            health: detail["State"]["Health"]["Status"].as_str().map(str::to_string),
            restart_count: detail["RestartCount"].as_u64().unwrap_or(0) as u32,
            started_at_ms: detail["State"]["StartedAt"].as_str().and_then(rfc3339_ms).filter(|t| *t > 0).unwrap_or(0),
            id: id.chars().take(12).collect(),
        });
    }
    Ok(out)
}

/// One `GET` over the socket (HTTP/1.0, so the body ends with the connection).
fn get(socket: &Path, path: &str) -> Result<serde_json::Value, String> {
    let mut s = UnixStream::connect(socket).map_err(|e| format!("{}: {e}", socket.display()))?;
    s.set_read_timeout(Some(Duration::from_secs(5))).map_err(|e| e.to_string())?;
    write!(s, "GET {path} HTTP/1.0\r\nHost: engine\r\n\r\n").map_err(|e| e.to_string())?;
    let mut raw = Vec::new();
    s.take(16 * 1024 * 1024).read_to_end(&mut raw).map_err(|e| e.to_string())?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    if !head.starts_with("HTTP/1.0 200") && !head.starts_with("HTTP/1.1 200") {
        return Err(head.lines().next().unwrap_or_default().to_string());
    }
    serde_json::from_str(body).map_err(|e| e.to_string())
}

/// `2024-05-01T12:00:00.123456789Z` (or with an offset) as milliseconds since the epoch.
pub fn rfc3339_ms(t: &str) -> Option<i64> {
    let (date, time) = t.split_once('T')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let (clock, offset_s) = match time.find(['Z', '+', '-']) {
        Some(i) if &time[i..] == "Z" => (&time[..i], 0),
        Some(i) => {
            let sign = if time.as_bytes()[i] == b'-' { -1 } else { 1 };
            let mut o = time[i + 1..].split(':').map(|p| p.parse::<i64>().ok());
            (&time[..i], sign * (o.next()?? * 3600 + o.next().flatten().unwrap_or(0) * 60))
        }
        None => (time, 0),
    };
    let (hms, frac) = clock.split_once('.').unwrap_or((clock, ""));
    let mut c = hms.split(':').map(|p| p.parse::<i64>().ok());
    let (h, min, s) = (c.next()??, c.next()??, c.next()??);
    let ms = format!("{frac:0<3}").get(..3)?.parse::<i64>().ok()?;
    // days from 1970-01-01 (Howard Hinnant's days_from_civil)
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + min * 60 + s - offset_s) * 1000) + ms)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_times_parse() {
        assert_eq!(rfc3339_ms("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(rfc3339_ms("2024-05-01T12:00:00.123456789Z"), Some(1_714_564_800_123));
        assert_eq!(rfc3339_ms("2024-05-01T14:00:00+02:00"), Some(1_714_564_800_000));
        assert_eq!(rfc3339_ms("0001-01-01T00:00:00Z").map(|v| v < 0), Some(true), "a container never started");
    }
}
