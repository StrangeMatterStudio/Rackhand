//! The eBPF capture (FR-4, FR-5, 11, D17, D103, D196). The root helper loads `crates/rackhand-probe-ebpf`'s object
//! built into this binary and attaches its connection hooks to the root cgroup and its exec tracepoint ([`Programs`]);
//! the probe gets the maps' descriptors from it over the helper socket and drains them every interval ([`Capture`]),
//! with `CAP_BPF` only. Anything that stops it (no object in this build, no BTF, no helper, a kernel or a capability
//! that refuses it) leaves the probe on sampling (E36), and the reason is logged once.
//!
//! The layouts here mirror the eBPF crate's `ConnKey`, `Exe` and `ExecEvent`.

use std::net::{IpAddr, Ipv6Addr};

use super::conntable::Proto;

pub const PATH_LEN: usize = 256;

/// The eBPF program built into this probe, or nothing in a build without it (`RACKHAND_PROBE_EBPF` at build time).
pub const OBJECT: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/rackhand-probe-ebpf.o"));

/// `ConnKey` in the eBPF program.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnKey {
    pub cgroup: u64,
    pub addr: [u8; 16],
    pub tgid: u32,
    pub uid: u32,
    pub port: u16,
    pub proto: u8,
    pub _pad: [u8; 5],
    pub comm: [u8; 8],
}

/// `ExecEvent` in the eBPF program.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExecEvent {
    pub cgroup: u64,
    pub tgid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub path: [u8; PATH_LEN],
}

/// One destination a process reached since the last drain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conn {
    pub cgroup: u64,
    pub pid: u32,
    pub uid: u32,
    pub dest: IpAddr,
    pub port: u16,
    pub proto: Proto,
    /// The executable's path when the exec hook saw the process start, else empty.
    pub exe: String,
    /// The process name the kernel had at the connect.
    pub comm: String,
    pub count: u64,
}

/// One process start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exec {
    pub cgroup: u64,
    pub pid: u32,
    pub uid: u32,
    pub path: String,
    pub comm: String,
}

/// The destination: an IPv4 address the program keeps as `::ffff:a.b.c.d`, whatever the socket's family, comes back as
/// IPv4.
pub fn dest(addr: [u8; 16]) -> IpAddr {
    let v6 = Ipv6Addr::from(addr);
    match v6.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(v6),
    }
}

/// Text up to the first NUL.
pub fn c_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

impl Conn {
    pub fn from_key(key: &ConnKey, count: u64, exe: String) -> Option<Conn> {
        let proto = match key.proto {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            _ => return None,
        };
        Some(Conn {
            cgroup: key.cgroup,
            pid: key.tgid,
            uid: key.uid,
            dest: dest(key.addr),
            port: key.port,
            proto,
            exe,
            comm: c_text(&key.comm),
            count,
        })
    }
}

impl Exec {
    pub fn from_event(e: &ExecEvent) -> Exec {
        Exec { cgroup: e.cgroup, pid: e.tgid, uid: e.uid, path: c_text(&e.path), comm: c_text(&e.comm) }
    }
}

/// The maps the helper passes, in this order.
pub const MAPS: [&str; 3] = ["CONNS", "EXES", "EXECS"];

/// Why the capture didn't load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadError {
    /// This probe was built without the eBPF program.
    NoProgram,
    /// The kernel has no BTF (`/sys/kernel/btf/vmlinux`), so the capture isn't used (FR-4).
    NoBtf,
    /// The kernel or the capabilities refused it.
    Refused(String),
}

impl LoadError {
    /// The helper's error code for it.
    pub fn code(&self) -> &'static str {
        match self {
            LoadError::NoProgram => "no_program",
            LoadError::NoBtf => "no_btf",
            LoadError::Refused(_) => "refused",
        }
    }

    /// From the helper's error answer.
    pub fn from_answer(code: &str, message: String) -> LoadError {
        match code {
            "no_program" => LoadError::NoProgram,
            "no_btf" => LoadError::NoBtf,
            _ => LoadError::Refused(message),
        }
    }
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::NoProgram => f.write_str("this probe was built without the eBPF program"),
            LoadError::NoBtf => f.write_str("the kernel has no BTF"),
            LoadError::Refused(why) => write!(f, "the kernel refused the eBPF program: {why}"),
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::{Capture, Programs};

#[cfg(target_os = "linux")]
// The maps' key and value types must be `aya::Pod`, an unsafe trait, and a ring buffer entry is read as bytes; the
// unsafe code is these three lines.
#[allow(unsafe_code)]
mod linux {
    use std::os::fd::{AsFd, OwnedFd};
    use std::path::Path;

    use aya::maps::{HashMap, Map, MapData, PerCpuHashMap, RingBuf};
    use aya::programs::{CgroupAttachMode, CgroupSockAddr, TracePoint};

    use super::{Conn, ConnKey, Exec, ExecEvent, LoadError, MAPS, PATH_LEN};

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Exe {
        path: [u8; PATH_LEN],
    }

    // SAFETY: plain `repr(C)` data with no padding the program leaves unset, read and written as bytes.
    unsafe impl aya::Pod for ConnKey {}
    // SAFETY: as above.
    unsafe impl aya::Pod for Exe {}

    fn refused(e: impl std::fmt::Display) -> LoadError {
        LoadError::Refused(e.to_string())
    }

    /// The loaded and attached programs, in the helper; dropping them detaches them.
    pub struct Programs {
        ebpf: aya::Ebpf,
    }

    impl std::fmt::Debug for Programs {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Programs")
        }
    }

    fn map_data(map: &Map) -> Option<&MapData> {
        match map {
            Map::PerCpuLruHashMap(d)
            | Map::LruHashMap(d)
            | Map::RingBuf(d)
            | Map::HashMap(d)
            | Map::PerCpuHashMap(d) => Some(d),
            _ => None,
        }
    }

    impl Programs {
        /// Loads `object` and attaches it. `root` is `/` outside tests: the kernel's BTF and the cgroup tree are under it.
        pub fn load(object: &[u8], root: &Path) -> Result<Programs, LoadError> {
            if object.is_empty() {
                return Err(LoadError::NoProgram);
            }
            if !root.join("sys/kernel/btf/vmlinux").exists() {
                return Err(LoadError::NoBtf);
            }
            // kernels before 5.11 charge maps to the memlock limit, which the helper (root) may raise; later ones ignore it
            let unlimited = rustix::process::Rlimit { current: None, maximum: None };
            let _ = rustix::process::setrlimit(rustix::process::Resource::Memlock, unlimited);
            let mut ebpf = aya::Ebpf::load(object).map_err(refused)?;
            let cgroup = std::fs::File::open(root.join("sys/fs/cgroup")).map_err(refused)?;
            for name in ["connect4", "connect6", "sendmsg4", "sendmsg6"] {
                let program: &mut CgroupSockAddr = ebpf
                    .program_mut(name)
                    .ok_or_else(|| refused(format!("no program {name}")))?
                    .try_into()
                    .map_err(refused)?;
                program.load().map_err(|e| refused(format!("{name}: {e}")))?;
                // a cgroup link always lets other programs run beside it; the mode is the link's flags, which must be 0
                program.attach(&cgroup, CgroupAttachMode::Single).map_err(|e| refused(format!("{name}: {e}")))?;
            }
            let exec: &mut TracePoint =
                ebpf.program_mut("exec").ok_or_else(|| refused("no program exec"))?.try_into().map_err(refused)?;
            exec.load().map_err(|e| refused(format!("exec: {e}")))?;
            exec.attach("sched", "sched_process_exec").map_err(|e| refused(format!("exec: {e}")))?;
            let programs = Programs { ebpf };
            programs.map_fds().map_err(refused)?;
            Ok(programs)
        }

        /// New descriptors for the maps, in [`MAPS`] order.
        pub fn map_fds(&self) -> std::io::Result<Vec<OwnedFd>> {
            MAPS.iter()
                .map(|name| {
                    let data = self.ebpf.map(name).and_then(map_data);
                    data.ok_or_else(|| std::io::Error::other(format!("no map {name}")))?
                        .fd()
                        .as_fd()
                        .try_clone_to_owned()
                })
                .collect()
        }
    }

    /// The maps, in the probe; draining them needs `CAP_BPF` where unprivileged `bpf()` is off.
    pub struct Capture {
        conns: PerCpuHashMap<MapData, ConnKey, u64>,
        exes: HashMap<MapData, u32, Exe>,
        execs: RingBuf<MapData>,
        ids: Vec<u32>,
    }

    impl std::fmt::Debug for Capture {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "Capture {:?}", self.ids)
        }
    }

    fn open(fd: OwnedFd) -> Result<(Map, u32), LoadError> {
        let data = MapData::from_fd(fd).map_err(refused)?;
        let id = data.info().map_err(refused)?.id();
        Ok((Map::from_map_data(data).map_err(refused)?, id))
    }

    impl Capture {
        /// The maps from the descriptors the helper passed, named by `names`.
        pub fn from_fds(fds: Vec<OwnedFd>, names: &[String]) -> Result<Capture, LoadError> {
            if fds.len() != MAPS.len() || names.len() != MAPS.len() || names.iter().zip(MAPS).any(|(n, m)| n != m) {
                return Err(refused(format!("the helper passed {} descriptors for {names:?}", fds.len())));
            }
            let mut fds = fds.into_iter();
            let mut next = || fds.next().map(open).unwrap_or_else(|| Err(refused("a descriptor is missing")));
            let ((conns, a), (exes, b), (execs, c)) = (next()?, next()?, next()?);
            Ok(Capture {
                conns: PerCpuHashMap::try_from(conns).map_err(refused)?,
                exes: HashMap::try_from(exes).map_err(refused)?,
                execs: RingBuf::try_from(execs).map_err(refused)?,
                ids: vec![a, b, c],
            })
        }

        /// Whether both are the same maps: the helper passes the same ones again until it restarts.
        pub fn same_maps(&self, other: &Capture) -> bool {
            self.ids == other.ids
        }

        /// What was counted since the last drain, and the execs since then; the counts start again from zero.
        pub fn drain(&mut self) -> (Vec<Conn>, Vec<Exec>) {
            let mut execs = Vec::new();
            while let Some(item) = self.execs.next() {
                if item.len() >= std::mem::size_of::<ExecEvent>() {
                    // SAFETY: the program writes whole `ExecEvent`s; the read is unaligned-safe.
                    let e = unsafe { std::ptr::read_unaligned(item.as_ptr().cast::<ExecEvent>()) };
                    execs.push(Exec::from_event(&e));
                }
            }
            let keys: Vec<ConnKey> = self.conns.keys().filter_map(Result::ok).collect();
            let mut conns = Vec::new();
            for key in keys {
                let Ok(values) = self.conns.get(&key, 0) else { continue };
                let count: u64 = values.iter().sum();
                let _ = self.conns.remove(&key);
                let exe = self.exes.get(&key.tgid, 0).map(|e| super::c_text(&e.path)).unwrap_or_default();
                if let Some(c) = Conn::from_key(&key, count, exe) {
                    conns.push(c);
                }
            }
            (conns, execs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn layouts_match_the_program() {
        assert_eq!(std::mem::size_of::<ConnKey>(), 48);
        assert_eq!(std::mem::size_of::<ExecEvent>(), 288);
    }

    #[test]
    fn mapped_ipv4_comes_back_as_ipv4() {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12..].copy_from_slice(&[10, 0, 0, 7]);
        assert_eq!(dest(a), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));
        let v6: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert_eq!(dest(v6.octets()), IpAddr::V6(v6));
    }

    #[test]
    fn keys_become_connections() {
        let mut a = [0u8; 16];
        a[10] = 0xff;
        a[11] = 0xff;
        a[12..].copy_from_slice(&[1, 2, 3, 4]);
        let mut comm = [0u8; 8];
        comm[..4].copy_from_slice(b"curl");
        let key = ConnKey { cgroup: 9, addr: a, tgid: 42, uid: 1000, port: 443, proto: 6, _pad: [0; 5], comm };
        let c = Conn::from_key(&key, 3, "/usr/bin/curl".into()).unwrap();
        assert_eq!((c.pid, c.uid, c.port, c.proto, c.count), (42, 1000, 443, Proto::Tcp, 3));
        assert_eq!(
            (c.dest.to_string().as_str(), c.comm.as_str(), c.exe.as_str()),
            ("1.2.3.4", "curl", "/usr/bin/curl")
        );
        assert_eq!(Conn::from_key(&ConnKey { proto: 17, ..key }, 1, String::new()).unwrap().proto, Proto::Udp);
        assert_eq!(Conn::from_key(&ConnKey { proto: 1, ..key }, 1, String::new()), None, "only TCP and UDP");
    }

    #[test]
    fn helper_codes_round_trip() {
        for e in [LoadError::NoProgram, LoadError::NoBtf, LoadError::Refused("EPERM".into())] {
            assert_eq!(LoadError::from_answer(e.code(), "EPERM".into()), e);
        }
        assert_eq!(LoadError::from_answer("bad_request", "x".into()), LoadError::Refused("x".into()));
    }

    #[test]
    fn text_stops_at_nul() {
        assert_eq!(c_text(b"/tmp/x\0junk"), "/tmp/x");
        assert_eq!(c_text(b"full"), "full");
    }
}
