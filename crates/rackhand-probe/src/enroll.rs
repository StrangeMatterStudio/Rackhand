//! `rackhand-probe enroll` (7.3.1, 7.3.12): the machine's join, run as root by the installer. It joins with the
//! token, writes `probe.toml` (root 0644) pinning the hub from the ticket, and for a managed machine installs the
//! signed command list and leaves the accounts' `authorized_keys` lines and sudoers text for the installer in a
//! root-only directory (the installer creates the users and checks sudoers with `visudo -c`).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use prost::Message;
use rackhand_proto::common::{Access, HostFacts, ProbeMode, SshHostKey};
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{JoinError, JoinRequest, JoinResponse, MachineJoin, MachineJoined};

pub use rackhand_net::ticket::Ticket;

#[derive(Debug, Clone)]
pub struct Request {
    pub ticket: Ticket,
    pub token: String,
    pub access: Access,
    pub mode: ProbeMode,
    /// `hub`, `hypervisor`, `relay`, `operator`, or empty.
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub probe_toml: PathBuf,
    /// The probe's state directory: its node key.
    pub data_dir: PathBuf,
    pub commands: PathBuf,
    /// Where a managed join leaves the accounts' keys and sudoers for the installer (root 0700).
    pub managed_dir: PathBuf,
    pub ssh_dir: PathBuf,
}

impl Default for Paths {
    fn default() -> Paths {
        Paths {
            probe_toml: crate::config::PATH.into(),
            data_dir: "/var/lib/rackhand-probe".into(),
            commands: crate::runcmd::COMMANDS.into(),
            managed_dir: "/var/lib/rackhand-run/enroll".into(),
            ssh_dir: "/etc/ssh".into(),
        }
    }
}

/// What the join gave.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Enrolled {
    pub machine_id: String,
    pub managed: bool,
    pub assistant: bool,
}

/// The machine's SSH host keys (`/etc/ssh/ssh_host_*_key.pub`), which the hub pins (7.3.7).
pub fn host_keys(ssh_dir: &Path) -> Vec<SshHostKey> {
    let mut keys = Vec::new();
    let Ok(entries) = std::fs::read_dir(ssh_dir) else { return keys };
    let mut names: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
    names.sort();
    for p in names {
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        if !(name.starts_with("ssh_host_") && name.ends_with("_key.pub")) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let mut parts = text.split_whitespace();
        if let (Some(algorithm), Some(public_key)) = (parts.next(), parts.next()) {
            keys.push(SshHostKey { algorithm: algorithm.into(), public_key: public_key.into() });
        }
    }
    keys
}

fn os_release() -> (String, String) {
    let text = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let field = |k: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{k}=")))
            .map(|v| v.trim_matches('"').to_string())
            .unwrap_or_default()
    };
    (field("ID"), field("VERSION_ID"))
}

fn facts(role: &str) -> HostFacts {
    let (os_name, os_version) = os_release();
    let read = |p: &str| std::fs::read_to_string(p).map(|s| s.trim().to_string()).unwrap_or_default();
    HostFacts {
        hostname: read("/proc/sys/kernel/hostname"),
        os_name,
        os_version,
        kernel: read("/proc/sys/kernel/osrelease"),
        arch: std::env::consts::ARCH.into(),
        machine_role: role.into(),
        interfaces: Vec::new(),
    }
}

/// `authorized_keys` options for the hub's keys: only from the hub's addresses (loopback in remote mode), and no
/// forwarding (7.3.7).
pub fn authorized_keys_line(key: &str, hub_addrs: &[String], remote: bool) -> String {
    let from: Vec<String> = if remote {
        vec!["127.0.0.1".into(), "::1".into()]
    } else {
        hub_addrs
            .iter()
            .map(|a| a.parse::<SocketAddr>().map(|s| s.ip().to_string()).unwrap_or_else(|_| a.clone()))
            .collect()
    };
    format!("from=\"{}\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding {}", from.join(","), key.trim())
}

fn write_root_file(path: &Path, data: &[u8], mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode)).map_err(|e| e.to_string())?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))
}

/// `probe.toml` for the join.
pub fn probe_toml(ticket: &Ticket, joined: &MachineJoined, mode: ProbeMode) -> Result<String, String> {
    let id = ulid::Ulid::from_bytes(joined.machine_id.as_slice().try_into().map_err(|_| "machine id length")?);
    let hub_id: String = ticket.hub_id.iter().map(|b| format!("{b:02x}")).collect();
    let mut addrs: Vec<String> = ticket.addrs.iter().map(|a| a.to_string()).collect();
    for a in &joined.hub_addrs {
        if a.parse::<SocketAddr>().is_ok() && !addrs.contains(a) {
            addrs.push(a.clone());
        }
    }
    let quote = |v: &[String]| v.iter().map(|s| format!("\"{s}\"")).collect::<Vec<_>>().join(", ");
    let access = if joined.access == Access::Monitor as i32 { "monitor" } else { "managed" };
    let mode = if mode == ProbeMode::Remote { "remote" } else { "local" };
    Ok(format!(
        "[hub]\nid = \"{hub_id}\"\naddrs = [{}]\nrelays = [{}]\n\n[machine]\nid = \"{id}\"\naccess = \"{access}\"\nmode = \"{mode}\"\n",
        quote(&addrs),
        quote(&ticket.relays)
    ))
}

/// One join over `rackhand/join/1`.
pub async fn join(endpoint: &iroh::Endpoint, req: &Request, ssh_dir: &Path) -> Result<MachineJoined, String> {
    let hub_id = iroh::EndpointId::from_bytes(&req.ticket.hub_id).map_err(|e| format!("hub id: {e}"))?;
    let mut addr = iroh::EndpointAddr::new(hub_id);
    for a in &req.ticket.addrs {
        addr.addrs.insert(iroh::TransportAddr::Ip(*a));
    }
    for r in &req.ticket.relays {
        addr.addrs.insert(iroh::TransportAddr::Relay(r.parse().map_err(|_| format!("relay {r}"))?));
    }
    let managed = req.access == Access::Managed;
    let join = MachineJoin {
        token: req.token.clone(),
        facts: Some(facts(&req.role)),
        ssh_host_keys: if managed { host_keys(ssh_dir) } else { Vec::new() },
        mode: req.mode as i32,
        access: req.access as i32,
    };
    let request = JoinRequest { kind: Some(Req::Machine(join)) };
    let conn =
        endpoint.connect(addr, rackhand_proto::alpn::JOIN).await.map_err(|e| format!("can't reach the hub: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    let bytes = frame::encode(&request).map_err(|e| e.to_string())?;
    send.write_all(&bytes).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let data = recv.read_to_end(frame::MAX_FRAME + 4).await.map_err(|e| e.to_string())?;
    conn.close(0u32.into(), b"done");
    let body = frame::read_frame(&mut data.as_slice()).map_err(|e| e.to_string())?;
    let response = JoinResponse::decode(body.as_slice()).map_err(|e| e.to_string())?;
    match response.kind {
        Some(Resp::Machine(m)) => Ok(m),
        Some(Resp::Error(f)) => {
            let code = JoinError::try_from(f.code).map(|c| c.as_str_name()).unwrap_or("JOIN_ERROR_UNSPECIFIED");
            Err(format!("the hub refused the join ({code}): {}", f.message))
        }
        _ => Err("the hub answered something other than a machine join".into()),
    }
}

/// The whole enrollment: the join, then the files it leaves.
pub async fn enroll(req: &Request, paths: &Paths) -> Result<Enrolled, String> {
    let key_path = paths.data_dir.join("node.key");
    let key = rackhand_net::key::load_or_create(&key_path).map_err(|e| format!("{}: {e}", key_path.display()))?;
    let relays = rackhand_net::relays::RelayConfig { relays: req.ticket.relays.clone(), ..Default::default() };
    let config = rackhand_net::endpoint::EndpointConfig { relays, alpns: Vec::new(), bind: None };
    let endpoint = rackhand_net::endpoint::bind(key, &config).await.map_err(|e| e.to_string())?;
    let joined = join(&endpoint, req, &paths.ssh_dir).await?;
    endpoint.close().await;
    let toml = probe_toml(&req.ticket, &joined, req.mode)?;
    write_root_file(&paths.probe_toml, toml.as_bytes(), 0o644)?;
    let machine_id =
        ulid::Ulid::from_bytes(joined.machine_id.as_slice().try_into().map_err(|_| "machine id")?).to_string();
    let Some(managed) = &joined.managed else {
        return Ok(Enrolled { machine_id, managed: false, assistant: false });
    };
    // the first command list arrives with the join (7.3.7, D28), checked like any later one
    let commands = managed.commands.as_ref().ok_or("a managed join without a command list")?;
    let pinned = ed25519_dalek::VerifyingKey::from_bytes(&req.ticket.hub_id).map_err(|_| "the hub id isn't a key")?;
    let now =
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0);
    if let Some(dir) = paths.commands.parent() {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    }
    crate::runcmd::install::install(&paths.commands, &commands.encode_to_vec(), &pinned, now)
        .map_err(|e| format!("the command list: {e}"))?;
    let remote = req.mode == ProbeMode::Remote;
    let dir = &paths.managed_dir;
    write_root_file(&dir.join("sudoers"), managed.sudoers.as_bytes(), 0o600)?;
    let line = authorized_keys_line(&managed.automation_pubkey, &joined.hub_addrs, remote);
    write_root_file(&dir.join("rackhand.authorized_keys"), format!("{line}\n").as_bytes(), 0o600)?;
    if let Some(assistant) = &managed.assistant_pubkey {
        let line = authorized_keys_line(assistant, &joined.hub_addrs, remote);
        write_root_file(&dir.join("rackhand-ai.authorized_keys"), format!("{line}\n").as_bytes(), 0o600)?;
    }
    Ok(Enrolled { machine_id, managed: true, assistant: managed.assistant_pubkey.is_some() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_round_trips() {
        let t = Ticket {
            hub_id: [0xab; 32],
            addrs: vec!["192.0.2.10:7443".parse().unwrap(), "[2001:db8::1]:7443".parse().unwrap()],
            relays: vec!["https://relay.example.net".into()],
        };
        assert_eq!(Ticket::parse(&t.to_text()), Ok(t.clone()));
        assert!(Ticket::parse("rackhand1:abc@1.2.3.4:1").is_err(), "a short id");
        assert!(Ticket::parse("rackhand2:x").is_err());
    }

    #[test]
    fn authorized_keys_limited_to_the_hub() {
        let line = authorized_keys_line("ssh-ed25519 AAAA rackhand", &["192.0.2.10:7443".into()], false);
        assert_eq!(
            line,
            "from=\"192.0.2.10\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding ssh-ed25519 AAAA rackhand"
        );
        let remote = authorized_keys_line("ssh-ed25519 AAAA", &["192.0.2.10:7443".into()], true);
        assert!(remote.starts_with("from=\"127.0.0.1,::1\""), "remote mode: through the probe's tunnel (7.3.7)");
    }

    #[test]
    fn probe_toml_from_the_join_parses() {
        let ticket = Ticket { hub_id: [7; 32], addrs: vec!["192.0.2.10:7443".parse().unwrap()], relays: vec![] };
        let joined = MachineJoined {
            machine_id: ulid::Ulid::from_bytes([1; 16]).to_bytes().to_vec(),
            access: Access::Monitor as i32,
            hub_addrs: vec!["192.0.2.11:7443".into()],
            ..MachineJoined::default()
        };
        let text = probe_toml(&ticket, &joined, ProbeMode::Local).unwrap();
        let cfg = crate::config::ProbeToml::parse(&text).unwrap();
        assert_eq!(cfg.hub_key().unwrap(), [7; 32]);
        assert_eq!(cfg.hub.addrs.len(), 2, "the ticket's address and the join's");
        assert_eq!(cfg.machine.as_ref().map(|m| m.access.as_str()), Some("monitor"));
    }

    #[test]
    fn host_keys_read_from_the_ssh_directory() {
        let dir = std::env::temp_dir().join(format!("rackhand-hostkeys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("ssh_host_ed25519_key.pub"), "ssh-ed25519 AAAAC3Nz root@web1\n").unwrap();
        std::fs::write(dir.join("ssh_host_ed25519_key"), "PRIVATE").unwrap();
        let keys = host_keys(&dir);
        assert_eq!(keys, [SshHostKey { algorithm: "ssh-ed25519".into(), public_key: "AAAAC3Nz".into() }]);
    }
}
