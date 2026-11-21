//! DNS checks: the name resolves (A, or AAAA when `expect` is an IPv6 address) at `server` (the first `nameserver` of
//! `/etc/resolv.conf` when not given), and with `expect`, to that address. One UDP query, no recursion of our own.

use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, millis, settings, text};

#[derive(Debug, Default)]
pub struct Dns;

impl Dns {
    pub fn new() -> Dns {
        Dns
    }
}

fn system_server() -> Option<SocketAddr> {
    let conf = std::fs::read_to_string("/etc/resolv.conf").ok()?;
    let ip: IpAddr = conf.lines().find_map(|l| l.trim().strip_prefix("nameserver")?.trim().parse().ok())?;
    Some(SocketAddr::new(ip, 53))
}

fn query(id: u16, name: &str, qtype: u16) -> Result<Vec<u8>, DriverError> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]); // recursion desired, one question
    for label in name.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DriverError::Invalid(format!("`{name}` isn't a host name")));
        }
        q.push(label.len() as u8);
        q.extend_from_slice(label.as_bytes());
    }
    q.push(0);
    q.extend_from_slice(&qtype.to_be_bytes());
    q.extend_from_slice(&[0, 1]);
    Ok(q)
}

/// A (possibly compressed) name at `at`; returns it and the offset after it.
pub(crate) fn read_name(msg: &[u8], mut at: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut end = None;
    for _ in 0..64 {
        let len = *msg.get(at)? as usize;
        if len == 0 {
            return Some((labels.join("."), end.unwrap_or(at + 1)));
        }
        if len & 0xc0 == 0xc0 {
            let ptr = ((len & 0x3f) << 8) | *msg.get(at + 1)? as usize;
            end.get_or_insert(at + 2);
            at = ptr;
            continue;
        }
        labels.push(String::from_utf8_lossy(msg.get(at + 1..at + 1 + len)?).into_owned());
        at += 1 + len;
    }
    None
}

/// The answer's addresses, or the reason there are none.
fn answers(msg: &[u8], id: u16) -> Result<Vec<IpAddr>, String> {
    if msg.len() < 12 || u16::from_be_bytes([msg[0], msg[1]]) != id {
        return Err("a malformed answer".into());
    }
    match msg[3] & 0x0f {
        0 => {}
        3 => return Err("no such name (NXDOMAIN)".into()),
        code => return Err(format!("the server answered with error {code}")),
    }
    let (qd, an) = (u16::from_be_bytes([msg[4], msg[5]]), u16::from_be_bytes([msg[6], msg[7]]));
    let mut at = 12;
    for _ in 0..qd {
        at = read_name(msg, at).ok_or("a malformed question")?.1 + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an {
        at = read_name(msg, at).ok_or("a malformed answer")?.1;
        let head = msg.get(at..at + 10).ok_or("a short answer")?;
        let (rtype, len) = (u16::from_be_bytes([head[0], head[1]]), u16::from_be_bytes([head[8], head[9]]) as usize);
        let data = msg.get(at + 10..at + 10 + len).ok_or("a short answer")?;
        match (rtype, len) {
            (1, 4) => out.push(IpAddr::from([data[0], data[1], data[2], data[3]])),
            (28, 16) => out.push(IpAddr::from(<[u8; 16]>::try_from(data).map_err(|_| "a short answer")?)),
            _ => {}
        }
        at += 10 + len;
    }
    if out.is_empty() { Err("no address in the answer".into()) } else { Ok(out) }
}

#[async_trait::async_trait]
impl Driver for Dns {
    fn kind(&self) -> DriverKind {
        DriverKind::Dns
    }

    fn known_settings(&self) -> &'static [&'static str] {
        &["server", "expect"]
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let s = settings(&target.settings, self.known_settings())?;
        let server = match text(s, "server")? {
            Some(a) => a
                .parse::<SocketAddr>()
                .or_else(|_| a.parse::<IpAddr>().map(|ip| SocketAddr::new(ip, 53)))
                .map_err(|_| DriverError::Invalid(format!("`server` {a} isn't an address")))?,
            None => system_server().ok_or_else(|| DriverError::Invalid("no `server` and no nameserver".into()))?,
        };
        let expect = match text(s, "expect")? {
            Some(e) => {
                Some(e.parse::<IpAddr>().map_err(|_| DriverError::Invalid(format!("`expect` {e} isn't an address")))?)
            }
            None => None,
        };
        let qtype = if expect.is_some_and(|e| e.is_ipv6()) { 28 } else { 1 };
        let id = (std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().subsec_nanos()
            & 0xffff) as u16;
        let q = query(id, &target.target, qtype)?;
        let started = Instant::now();
        let ask = async {
            let bind: SocketAddr = if server.is_ipv4() { ([0, 0, 0, 0], 0).into() } else { ([0u16; 8], 0).into() };
            let sock = tokio::net::UdpSocket::bind(bind).await.map_err(|e| e.to_string())?;
            sock.send_to(&q, server).await.map_err(|e| format!("{server}: {e}"))?;
            let mut buf = vec![0u8; 1500];
            loop {
                let (n, from) = sock.recv_from(&mut buf).await.map_err(|e| e.to_string())?;
                if from == server && n >= 2 && u16::from_be_bytes([buf[0], buf[1]]) == id {
                    return answers(&buf[..n], id);
                }
            }
        };
        let found = match tokio::time::timeout(target.timeout, ask).await {
            Ok(Ok(a)) => a,
            Ok(Err(e)) => return Ok(DriverReading::down(format!("{}: {e}", target.target), vec![])),
            Err(_) => {
                return Ok(DriverReading::down(format!("{server}: no answer within {:?}", target.timeout), vec![]));
            }
        };
        let list = found.iter().map(|a| a.to_string()).collect::<Vec<_>>().join(", ");
        let reading = DriverReading::up(millis(started), format!("{} is {list}", target.target), vec![]);
        match expect {
            Some(e) if !found.contains(&e) => Ok(reading.failed(format!("{} is {list}, expected {e}", target.target))),
            _ => Ok(reading),
        }
    }
}
