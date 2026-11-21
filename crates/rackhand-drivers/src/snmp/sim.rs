//! An SNMP agent for tests: the invented walk of `tests/fixtures/snmp/walk.txt`, v2c with community `public-lab`, and
//! v3 user `rackhand` (SHA `invented-auth`, AES `invented-priv`). It answers GET and GET-NEXT, logs the kind of every
//! PDU it is sent, and drops what it can't authenticate.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use super::ber::{self, Pdu, Value};
use super::usm;

const COMMUNITY: &[u8] = b"public-lab";
const USER: &str = "rackhand";
const ENGINE: &[u8] = b"\x80\x00\x1f\x88\x04rackhand-lab";
const USM_UNKNOWN_ENGINE: &[u32] = &[1, 3, 6, 1, 6, 3, 15, 1, 1, 4, 0];

#[derive(Debug, Default)]
struct Log {
    kinds: Vec<u8>,
    encrypted: bool,
}

#[derive(Debug, Clone)]
pub struct Sim {
    pub addr: String,
    log: Arc<Mutex<Log>>,
}

fn load() -> BTreeMap<Vec<u32>, Value> {
    let file = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/snmp/walk.txt");
    let mut mib = BTreeMap::new();
    for line in std::fs::read_to_string(file).unwrap_or_default().lines() {
        let Some((oid, rest)) = line.split_once(" = ") else { continue };
        let Some(oid) = ber::from_dotted(oid.trim()) else { continue };
        let Some((kind, v)) = rest.split_once(": ") else { continue };
        let value = match kind {
            "INTEGER" => Value::Int(v.parse().unwrap_or(0)),
            "STRING" => Value::Bytes(v.trim_matches('"').as_bytes().to_vec()),
            "Counter32" => Value::Unsigned(ber::COUNTER32, v.parse().unwrap_or(0)),
            "Gauge32" => Value::Unsigned(ber::GAUGE32, v.parse().unwrap_or(0)),
            "Timeticks" => Value::Unsigned(ber::TIMETICKS, v.parse().unwrap_or(0)),
            _ => continue,
        };
        mib.insert(oid, value);
    }
    mib
}

fn answer(mib: &BTreeMap<Vec<u32>, Value>, req: &Pdu) -> Pdu {
    let varbinds = req
        .varbinds
        .iter()
        .map(|(oid, _)| match req.kind {
            ber::GET => (oid.clone(), mib.get(oid).cloned().unwrap_or(Value::Missing(ber::NO_SUCH_INSTANCE))),
            _ => match mib
                .range::<Vec<u32>, _>((std::ops::Bound::Excluded(oid.clone()), std::ops::Bound::Unbounded))
                .next()
            {
                Some((o, v)) => (o.clone(), v.clone()),
                None => (oid.clone(), Value::Missing(ber::END_OF_MIB_VIEW)),
            },
        })
        .collect();
    Pdu { kind: ber::RESPONSE, request_id: req.request_id, error_status: 0, varbinds }
}

fn handle(msg: &[u8], mib: &BTreeMap<Vec<u32>, Value>, log: &Mutex<Log>, started: Instant) -> Option<Vec<u8>> {
    let mut outer = ber::Reader::new(msg);
    let mut m = ber::Reader::new(outer.expect(ber::SEQUENCE).ok()?);
    match m.int().ok()? {
        1 => {
            let community = m.octets().ok()?;
            let (kind, body) = m.next_tlv().ok()?;
            log.lock().ok()?.kinds.push(kind);
            if community != COMMUNITY || !matches!(kind, ber::GET | ber::GET_NEXT) {
                return None;
            }
            let req = ber::parse_pdu(kind, body).ok()?;
            Some(ber::seq(&[ber::int(1), ber::octets(COMMUNITY), ber::pdu(&answer(mib, &req))]))
        }
        3 => {
            let p = usm::parse(msg).ok()?;
            let time = started.elapsed().as_secs() as u32;
            let ours =
                usm::Params { engine: ENGINE.to_vec(), boots: 1, time, user: USER.into(), auth: vec![], salt: vec![] };
            if p.flags & usm::AUTH == 0 {
                // discovery: a report naming the engine
                let req = usm::parse_scoped(&p.data).ok()?;
                log.lock().ok()?.kinds.push(req.kind);
                let report = Pdu {
                    kind: ber::REPORT,
                    request_id: req.request_id,
                    error_status: 0,
                    varbinds: vec![(USM_UNKNOWN_ENGINE.to_vec(), Value::Unsigned(ber::COUNTER32, 1))],
                };
                let mut params = ours.clone();
                params.user = String::new();
                return Some(usm::message(p.msg_id, 0, &params, &usm::scoped(ENGINE, &report)));
            }
            let auth = usm::localized_key("invented-auth", ENGINE);
            let privacy = usm::localized_key("invented-priv", ENGINE);
            if p.params.user != USER || p.params.engine != ENGINE || !usm::authentic(msg, &p, &auth) {
                return None;
            }
            let salt: [u8; 8] = p.params.salt.as_slice().try_into().ok()?;
            let plain = usm::aes_cfb(&privacy, p.params.boots, p.params.time, &salt, &p.data, true);
            let req = usm::parse_scoped(&plain).ok()?;
            {
                let mut l = log.lock().ok()?;
                l.kinds.push(req.kind);
                l.encrypted |= p.flags & usm::PRIV != 0 && p.data_tag == ber::OCTET_STRING;
            }
            if !matches!(req.kind, ber::GET | ber::GET_NEXT) {
                return None;
            }
            let mut out_salt = [0u8; 8];
            getrandom::fill(&mut out_salt).ok()?;
            let encrypted = usm::aes_cfb(&privacy, 1, time, &out_salt, &usm::scoped(ENGINE, &answer(mib, &req)), false);
            let mut params = ours;
            params.salt = out_salt.to_vec();
            Some(usm::signed(p.msg_id, usm::AUTH | usm::PRIV, &params, &ber::octets(&encrypted), &auth))
        }
        _ => None,
    }
}

impl Sim {
    pub async fn start() -> Sim {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("a port");
        let addr = sock.local_addr().expect("an address").to_string();
        let log: Arc<Mutex<Log>> = Arc::default();
        let shared = log.clone();
        let mib = load();
        let started = Instant::now();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let Ok((n, from)) = sock.recv_from(&mut buf).await else { return };
                if let Some(reply) = handle(&buf[..n], &mib, &shared, started) {
                    let _ = sock.send_to(&reply, from).await;
                }
            }
        });
        Sim { addr, log }
    }

    /// The kind of every PDU the agent was sent.
    pub fn pdu_kinds(&self) -> Vec<u8> {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).kinds.clone()
    }

    /// Whether a v3 request's scoped PDU came encrypted.
    pub fn saw_encrypted(&self) -> bool {
        self.log.lock().unwrap_or_else(|e| e.into_inner()).encrypted
    }
}
