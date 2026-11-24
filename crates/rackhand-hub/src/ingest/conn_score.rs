//! Connection scoring (7.6.5, FR-5, AC13, AC14, AC71): each connection record `(container, exe, dest_ip, dest_port, proto)` a
//! probe reports is judged on the hub, where the lists and the machine's history are.
//!
//! 1. A private, loopback or link-local destination is skipped unless the policy has `watch_internal`.
//! 2. A destination on a threat list is a critical `conn.known_bad`.
//! 3. The destination's ASN and country are looked up.
//! 4. For a machine's first 7 days the tuple `(container, exe, asn, country, port, proto)` goes into its baseline and
//!    nothing is raised.
//! 5. After that a tuple not in the baseline is `conn.new_destination`: info, and warning when the country is new for the
//!    machine, the executable is new on it, the port is on the watch list, or the port is above 49151 from a server process.
//! 6. Over 1 GB to one new destination within an hour is `conn.large_egress` (warning).
//! 7. Rackhand's own processes, and the package manager during a Rackhand patch job, are left out.
//! 8. A record the probe folded (no destination) is counted, not scored.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use crate::intel::{Intel, Threat};

/// A machine's first days: nothing is raised, the baseline is learned.
pub const LEARNING_MS: i64 = 7 * 86_400_000;
/// Ports that are warning on their own for a destination never seen before.
pub const WATCH_PORTS: [u16; 8] = [22, 23, 1080, 3389, 4444, 5555, 6667, 9001];
/// More than this to one new destination within an hour is `conn.large_egress`.
pub const LARGE_EGRESS_BYTES: u64 = 1 << 30;
const HOUR_MS: i64 = 3_600_000;
/// The highest port that is not "high" (7.6.5).
const HIGH_PORT: u16 = 49_151;

/// Executables that are Rackhand's own, or the package managers a patch job runs.
const OWN: &[&str] = &["/usr/local/lib/rackhand/rackhand-probe", "/usr/local/lib/rackhand/run"];
const PACKAGE_MANAGERS: &[&str] = &[
    "/usr/bin/apt",
    "/usr/bin/apt-get",
    "/usr/bin/dpkg",
    "/usr/lib/apt/methods/http",
    "/usr/lib/apt/methods/https",
    "/sbin/apk",
    "/usr/bin/apk",
];

/// One record a probe sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub container: String,
    pub exe: String,
    pub user: String,
    pub pid: u32,
    /// `None` for a record the probe folded.
    pub dest: Option<IpAddr>,
    pub port: u16,
    pub tcp: bool,
    pub count: u32,
    pub bytes: u64,
}

impl Conn {
    pub fn proto(&self) -> &'static str {
        if self.tcp { "tcp" } else { "udp" }
    }

    /// A record a probe sent, or `None` for one with an address that isn't 4 or 16 bytes.
    pub fn from_wire(r: &rackhand_proto::probe::ConnRecord) -> Option<Conn> {
        let dest = match r.dest_ip.len() {
            0 => None,
            4 => Some(IpAddr::from(<[u8; 4]>::try_from(&r.dest_ip[..]).ok()?)),
            16 => Some(IpAddr::from(<[u8; 16]>::try_from(&r.dest_ip[..]).ok()?)),
            _ => return None,
        };
        Some(Conn {
            container: r.container.clone(),
            exe: r.exe.clone(),
            user: r.user.clone(),
            pid: r.pid,
            dest,
            port: u16::try_from(r.dest_port).ok()?,
            tcp: r.proto != rackhand_proto::probe::Proto::Udp as i32,
            count: r.count,
            bytes: r.bytes,
        })
    }
}

/// Private, loopback, link-local and similar: addresses that are not "out there".
pub fn internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_unspecified()
                || a.is_multicast()
                || a.is_broadcast()
                || (o[0] == 100 && (64..128).contains(&o[1]))
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            a.is_loopback()
                || a.is_unspecified()
                || a.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
        }
    }
}

/// What a machine's baseline holds, in memory.
#[derive(Debug, Default)]
pub struct State {
    pub keys: HashSet<(String, String, u32, String, u16, bool)>,
    pub exes: HashSet<String>,
    pub countries: HashSet<String>,
    /// When the machine's first tuple was learned; `None` before any.
    pub first_seen_ms: Option<i64>,
    /// Bytes to a destination in the current hour: (hour start, bytes).
    pub egress: HashMap<IpAddr, (i64, u64)>,
    /// Destinations already told about for large egress, by the hour.
    pub egress_told: HashMap<IpAddr, i64>,
}

#[derive(Debug)]
pub struct Context<'a> {
    pub now_ms: i64,
    pub watch_internal: bool,
    pub intel: &'a Intel,
    /// A Rackhand patch job is running on the machine.
    pub patch_job_running: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

/// An event a record gives rise to.
#[derive(Debug, Clone, PartialEq)]
pub struct Raised {
    pub kind: &'static str,
    pub severity: Severity,
    pub data: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Not scored: a private destination, an excluded process, or a folded record.
    Skipped,
    KnownBad,
    Learning,
    Known,
    New,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub verdict: Verdict,
    pub asn: Option<u32>,
    pub country: Option<String>,
    pub events: Vec<Raised>,
}

fn excluded(c: &Conn, patch_job_running: bool) -> bool {
    OWN.contains(&c.exe.as_str()) || (patch_job_running && PACKAGE_MANAGERS.contains(&c.exe.as_str()))
}

/// A server process: one inside a container, or run by `root` (no controlling terminal is known from a record).
fn server_process(c: &Conn) -> bool {
    !c.container.is_empty() || c.user == "root"
}

fn describe(c: &Conn, dest: IpAddr) -> serde_json::Value {
    serde_json::json!({
        "dest_ip": dest.to_string(), "dest_port": c.port, "proto": c.proto(), "container": c.container,
        "exe": c.exe, "user": c.user, "pid": c.pid, "count": c.count,
    })
}

pub fn score(c: &Conn, st: &mut State, ctx: &Context<'_>) -> Outcome {
    let skipped = Outcome { verdict: Verdict::Skipped, asn: None, country: None, events: Vec::new() };
    let Some(dest) = c.dest else { return skipped }; // folded: counted, not scored
    if excluded(c, ctx.patch_job_running) || (internal(dest) && !ctx.watch_internal) {
        return skipped;
    }
    if let Some(list) = ctx.intel.threat(dest) {
        let mut data = describe(c, dest);
        data["list"] = serde_json::json!(list.name());
        let geo = ctx.intel.geo(dest);
        let raised = Raised { kind: "conn.known_bad", severity: Severity::Critical, data };
        return Outcome { verdict: Verdict::KnownBad, asn: geo.asn, country: geo.country, events: vec![raised] };
    }
    let geo = ctx.intel.geo(dest);
    let (asn, country) = (geo.asn.unwrap_or(0), geo.country.clone().unwrap_or_default());
    let key = (c.container.clone(), c.exe.clone(), asn, country.clone(), c.port, c.tcp);
    let first = *st.first_seen_ms.get_or_insert(ctx.now_ms);
    let learning = ctx.now_ms - first < LEARNING_MS;
    let known = st.keys.contains(&key);
    let (new_country, new_exe) = (!st.countries.contains(&country), !st.exes.contains(&c.exe));
    let mut events = Vec::new();
    // over 1 GB to a destination within an hour, when it is not one the machine already knew
    let hour = ctx.now_ms - ctx.now_ms.rem_euclid(HOUR_MS);
    let slot = st.egress.entry(dest).or_insert((hour, 0));
    if slot.0 != hour {
        *slot = (hour, 0);
    }
    slot.1 = slot.1.saturating_add(c.bytes);
    let sent = slot.1;
    if !learning && !known && sent > LARGE_EGRESS_BYTES && st.egress_told.get(&dest) != Some(&hour) {
        st.egress_told.insert(dest, hour);
        let mut data = describe(c, dest);
        data["bytes_in_the_hour"] = serde_json::json!(sent);
        events.push(Raised { kind: "conn.large_egress", severity: Severity::Warning, data });
    }
    let verdict = if learning {
        Verdict::Learning
    } else if known {
        Verdict::Known
    } else {
        let mut why = Vec::new();
        if new_country {
            why.push("new country");
        }
        if new_exe {
            why.push("new executable");
        }
        if WATCH_PORTS.contains(&c.port) {
            why.push("watch-list port");
        }
        if c.port > HIGH_PORT && server_process(c) {
            why.push("high port from a server process");
        }
        let severity = if why.is_empty() { Severity::Info } else { Severity::Warning };
        let mut data = describe(c, dest);
        data["asn"] = serde_json::json!(geo.asn);
        data["country"] = serde_json::json!(geo.country);
        data["why"] = serde_json::json!(why);
        events.push(Raised { kind: "conn.new_destination", severity, data });
        Verdict::New
    };
    // learned either way: what was seen once is not new the next time
    st.keys.insert(key);
    st.exes.insert(c.exe.clone());
    st.countries.insert(country.clone());
    Outcome { verdict, asn: geo.asn, country: geo.country, events }
}

/// A record's threat-list name, for the event's text.
pub fn list_name(t: Threat) -> &'static str {
    t.name()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::{Intel, sources};

    const NOW: i64 = 1_795_000_000_000;
    const DAY: i64 = 86_400_000;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn conn(dest: &str, port: u16) -> Conn {
        Conn {
            container: "web".into(),
            exe: "/usr/bin/curl".into(),
            user: "alice".into(),
            pid: 7,
            dest: Some(ip(dest)),
            port,
            tcp: true,
            count: 1,
            bytes: 0,
        }
    }

    fn gz(text: &str) -> Vec<u8> {
        use std::io::Write;
        let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        e.write_all(text.as_bytes()).unwrap();
        e.finish().unwrap()
    }

    /// Lists with one bad address, and addresses in two countries and ASNs.
    fn intel() -> Intel {
        let intel = Intel::default();
        let load = |id: &str, bytes: &[u8]| {
            let s = sources(NOW).into_iter().find(|s| s.id == id).unwrap();
            intel.load(&s, bytes, NOW).unwrap();
        };
        load("feodo", b"203.0.113.9\n");
        load("dbip_country", &gz("93.184.216.0,93.184.216.255,US\n185.0.0.0,185.0.0.255,DE\n"));
        load("dbip_asn", &gz("93.184.216.0,93.184.216.255,15133,Edgecast\n185.0.0.0,185.0.0.255,24940,Hetzner\n"));
        intel
    }

    fn ctx(intel: &Intel, now_ms: i64) -> Context<'_> {
        Context { now_ms, watch_internal: false, intel, patch_job_running: false }
    }

    /// A machine that has been learning for a week and knows `curl` to the US on 443.
    fn learned(intel: &Intel) -> State {
        let mut st = State::default();
        let learning = ctx(intel, NOW - 8 * DAY);
        assert_eq!(score(&conn("93.184.216.34", 443), &mut st, &learning).verdict, Verdict::Learning);
        st
    }

    #[test]
    fn private_destinations_skipped_unless_watch_internal() {
        let intel = intel();
        for dest in [
            "10.1.2.3",
            "172.16.5.5",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.0.9",
            "fe80::1",
            "fd00::5",
            "::1",
        ] {
            let mut st = State::default();
            let out = score(&conn(dest, 22), &mut st, &ctx(&intel, NOW));
            assert_eq!((out.verdict, out.events.len()), (Verdict::Skipped, 0), "{dest}");
            assert!(st.keys.is_empty(), "nothing learned from it");
        }
        let mut st = State::default();
        let watched = Context { watch_internal: true, ..ctx(&intel, NOW) };
        assert_eq!(
            score(&conn("10.1.2.3", 22), &mut st, &watched).verdict,
            Verdict::Learning,
            "scored with watch_internal"
        );
        assert!(!internal(ip("8.8.8.8")) && !internal(ip("2606:4700::1111")));
    }

    #[test]
    fn threat_list_hit_is_critical_conn_known_bad() {
        let intel = intel();
        let mut st = State::default();
        // even while learning, and even from a machine that has seen the destination
        let out = score(&conn("203.0.113.9", 8080), &mut st, &ctx(&intel, NOW));
        assert_eq!(out.verdict, Verdict::KnownBad);
        let e = &out.events[0];
        assert_eq!((e.kind, e.severity), ("conn.known_bad", Severity::Critical));
        assert_eq!(e.data["dest_ip"], "203.0.113.9");
        assert_eq!(e.data["container"], "web");
        assert_eq!(e.data["list"], "abuse.ch Feodo Tracker");
        assert!(st.keys.is_empty(), "a bad destination is not learned as normal");
    }

    #[test]
    fn learning_adds_to_baseline_without_events() {
        let intel = intel();
        let mut st = State::default();
        for day in 0..7 {
            let out = score(&conn("93.184.216.34", 443 + day), &mut st, &ctx(&intel, NOW + day as i64 * DAY));
            assert_eq!((out.verdict, out.events.len()), (Verdict::Learning, 0));
        }
        assert_eq!(st.keys.len(), 7);
        // the eighth day: what was learned is known, and what is new is reported
        let known = score(&conn("93.184.216.34", 443), &mut st, &ctx(&intel, NOW + 7 * DAY));
        assert_eq!((known.verdict, known.events.len()), (Verdict::Known, 0));
        let new = score(&conn("93.184.216.34", 8443), &mut st, &ctx(&intel, NOW + 7 * DAY));
        assert_eq!((new.verdict, new.events[0].severity), (Verdict::New, Severity::Info), "same country and exe: info");
        let again = score(&conn("93.184.216.34", 8443), &mut st, &ctx(&intel, NOW + 7 * DAY + 1));
        assert_eq!(again.verdict, Verdict::Known, "once told, it is known");
    }

    #[test]
    fn new_asn_new_country_port_4444_is_warning_naming_container() {
        let intel = intel();
        let mut st = learned(&intel);
        let mut c = conn("185.0.0.5", 4444);
        c.container = "media".into();
        c.exe = "/usr/bin/ffmpeg".into();
        let out = score(&c, &mut st, &ctx(&intel, NOW));
        let e = &out.events[0];
        assert_eq!((e.kind, e.severity), ("conn.new_destination", Severity::Warning));
        assert_eq!(e.data["container"], "media");
        assert_eq!((out.asn, out.country.as_deref()), (Some(24940), Some("DE")));
        let why: Vec<&str> = e.data["why"].as_array().unwrap().iter().map(|w| w.as_str().unwrap()).collect();
        assert_eq!(why, ["new country", "new executable", "watch-list port"]);
    }

    #[test]
    fn server_process_high_port_raises_to_warning() {
        let intel = intel();
        let mut st = learned(&intel);
        let mut server = conn("93.184.216.34", 50_000);
        let out = score(&server, &mut st, &ctx(&intel, NOW));
        assert_eq!(out.events[0].severity, Severity::Warning, "a container's process on a port above 49151");
        server.port = 50_001;
        server.container = String::new();
        server.user = "alice".into();
        let out = score(&server, &mut st, &ctx(&intel, NOW));
        assert_eq!(out.events[0].severity, Severity::Info, "a person's own program on a high port is only new");
        server.port = 50_002;
        server.user = "root".into();
        assert_eq!(score(&server, &mut st, &ctx(&intel, NOW)).events[0].severity, Severity::Warning, "root's too");
    }

    #[test]
    fn large_egress_over_1gb_per_hour() {
        let intel = intel();
        let mut st = learned(&intel);
        let mut c = conn("93.184.216.34", 8443);
        c.bytes = 600 << 20;
        let first = score(&c, &mut st, &ctx(&intel, NOW));
        assert!(first.events.iter().all(|e| e.kind != "conn.large_egress"), "600 MB isn't enough");
        // the tuple is known now, so a different one to the same address within the hour adds up
        let mut c2 = conn("93.184.216.34", 9443);
        c2.bytes = 600 << 20;
        let second = score(&c2, &mut st, &ctx(&intel, NOW + 60_000));
        let big = second.events.iter().find(|e| e.kind == "conn.large_egress").expect("1.2 GB in the hour");
        assert_eq!(big.severity, Severity::Warning);
        assert!(big.data["bytes_in_the_hour"].as_u64().unwrap() > LARGE_EGRESS_BYTES);
        let mut c3 = conn("93.184.216.34", 9553);
        c3.bytes = 100 << 20;
        assert!(
            score(&c3, &mut st, &ctx(&intel, NOW + 120_000)).events.iter().all(|e| e.kind != "conn.large_egress"),
            "told once an hour"
        );
        // the next hour starts again from nothing
        let mut c4 = conn("93.184.216.34", 9663);
        c4.bytes = 100 << 20;
        assert!(
            score(&c4, &mut st, &ctx(&intel, NOW + 2 * HOUR_MS)).events.iter().all(|e| e.kind != "conn.large_egress")
        );
    }

    #[test]
    fn rackhand_and_patch_job_package_manager_excluded() {
        let intel = intel();
        let mut st = learned(&intel);
        let mut own = conn("185.0.0.5", 4444);
        own.exe = "/usr/local/lib/rackhand/rackhand-probe".into();
        assert_eq!(score(&own, &mut st, &ctx(&intel, NOW)).verdict, Verdict::Skipped);
        let mut apt = conn("185.0.0.5", 4444);
        apt.exe = "/usr/bin/apt-get".into();
        assert_eq!(score(&apt, &mut st, &ctx(&intel, NOW)).verdict, Verdict::New, "outside a patch job it is scored");
        let patching = Context { patch_job_running: true, ..ctx(&intel, NOW) };
        let mut apt2 = conn("185.0.0.6", 4445);
        apt2.exe = "/usr/bin/apt-get".into();
        let out = score(&apt2, &mut st, &patching);
        assert_eq!((out.verdict, out.events.len()), (Verdict::Skipped, 0));
        // a threat-listed destination is not excused by being a package manager's own: the exclusion is for what is normal
        let mut bad = conn("203.0.113.9", 80);
        bad.exe = "/usr/bin/apt-get".into();
        assert_eq!(score(&bad, &mut st, &patching).verdict, Verdict::Skipped, "excluded processes are left out whole");
    }

    #[test]
    fn folded_records_counted_not_scored() {
        let intel = intel();
        let mut st = State::default();
        let mut folded = conn("0.0.0.0", 0);
        folded.dest = None;
        folded.count = 100;
        let out = score(&folded, &mut st, &ctx(&intel, NOW));
        assert_eq!((out.verdict, out.events.len()), (Verdict::Skipped, 0));
        assert!(st.keys.is_empty() && st.first_seen_ms.is_none(), "no destination to learn");
        let wire = rackhand_proto::probe::ConnRecord { folded: true, count: 100, ..Default::default() };
        assert_eq!(Conn::from_wire(&wire).unwrap().dest, None);
        let odd = rackhand_proto::probe::ConnRecord { dest_ip: vec![1, 2, 3], ..Default::default() };
        assert!(Conn::from_wire(&odd).is_none());
    }
}
