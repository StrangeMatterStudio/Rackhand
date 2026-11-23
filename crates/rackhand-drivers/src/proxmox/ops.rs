//! The Proxmox operations the runbooks use (7.5.3, 7.5.6, D104), each waiting for its task where the API starts one:
//! - `snapshot`, `rollback`, `delete_snapshot`: `{kind, vmid, name}`;
//! - `firewall_read`: `{kind, vmid}` gives `{options, rules, devices}` (the guest's firewall options and rules, and its
//!   network devices' lines, which carry their `firewall` flag), without the digests that change on every write;
//! - `firewall_restore`: `{kind, vmid, saved}` puts a `firewall_read` back exactly;
//! - `firewall_isolate`: `{kind, vmid, hub_addrs, hub_port}` is a quarantine (7.5.6, D104): it needs the datacenter firewall
//!   on (else `pve_firewall_off`, and nothing is written, Rackhand never turns it on), saves the guest's whole firewall
//!   configuration, replaces its rules with DHCP, the guest to the hub's port, and the hub to the guest's SSH and ping,
//!   sets both policies to DROP and every network device's `firewall=1`; it gives `{saved, applied}`;
//! - `firewall_release`: `{kind, vmid, saved, applied}` ends it: when the configuration is not what `firewall_isolate`
//!   left (someone changed it) it stops with `quarantine_config_changed`, else it puts `saved` back exactly;
//! - `power`: `{kind, vmid, action}` with `start`, `stop`, `shutdown` or `reboot`;
//! - `clone`: `{vmid, newid, name, storage?}` (a full clone of a VM);
//! - `create_lxc`: `{vmid, hostname, ostemplate, storage, memory?, cores?, disk_gb?, bridge?}` (an unprivileged
//!   container on DHCP);
//! - `config_set`: `{kind, vmid, set}` with the cloud-init and sizing keys of [`SETTABLE`] only;
//! - `config`: `{kind, vmid}`;
//! - `snapshots`: `{kind, vmid}` gives the guest's snapshots, `[{name, snaptime}]`, without Proxmox's `current`;
//! - `snapshot_room`: `{kind, vmid}` gives `{storages: [{storage, type, avail, total, snapshots}]}`, each storage the
//!   guest's disks use (CD drives left out) and whether it can snapshot them: ZFS, LVM-thin, RBD and Btrfs can; a
//!   directory or network file storage only a VM's qcow2 images; anything else can't.
//! - `host`: `{node, nodes, guests: [{vmid, type, name, running}]}`, this host's node, every node of its cluster (its own
//!   alone when it has none), and the guests on its node.
//!
//! `kind` is `lxc` or `qemu`; `node` may be given, else the guest is looked for on the host's nodes. A failed task's
//! exit status is the error.

use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use super::client::{Client, segment};
use crate::driver::{DriverError, DriverOp, DriverOpResult, DriverTarget};

const TASK_POLL: Duration = Duration::from_millis(500);

fn bad(what: &str) -> DriverError {
    DriverError::Invalid(what.to_string())
}

struct Guest {
    node: String,
    kind: &'static str,
    vmid: u64,
}

impl Guest {
    fn path(&self, tail: &str) -> String {
        format!("/nodes/{}/{}/{}{tail}", self.node, self.kind, self.vmid)
    }
}

async fn guest(c: &Client, args: &Value) -> Result<Guest, DriverError> {
    let kind = match args["kind"].as_str() {
        Some("lxc") => "lxc",
        Some("qemu") => "qemu",
        _ => return Err(bad("`kind` is lxc or qemu")),
    };
    let vmid = args["vmid"].as_u64().ok_or_else(|| bad("`vmid` is a number"))?;
    if let Some(node) = args["node"].as_str().map(str::to_string).or_else(|| c.node.clone()) {
        return Ok(Guest { node, kind, vmid });
    }
    for node in super::nodes(c).await? {
        let list = c.call("GET", &format!("/nodes/{node}/{kind}"), &[]).await?;
        if list.as_array().into_iter().flatten().any(|g| g["vmid"].as_u64() == Some(vmid)) {
            return Ok(Guest { node, kind, vmid });
        }
    }
    Err(DriverError::Failed(format!("no {kind} {vmid} on this host")))
}

fn name(args: &Value) -> Result<String, DriverError> {
    let n = args["name"].as_str().ok_or_else(|| bad("`name` of the snapshot"))?;
    let valid = n.len() <= 40
        && n.starts_with(|c: char| c.is_ascii_alphabetic())
        && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if valid {
        Ok(n.to_string())
    } else {
        Err(bad("a snapshot name is a letter, then letters, digits, - and _ (40 at most)"))
    }
}

/// Waits for the task `upid` on `node` to stop; its exit status is `OK` or the error.
async fn wait(c: &Client, node: &str, upid: &Value, limit: Duration) -> Result<Value, DriverError> {
    let upid = upid.as_str().ok_or_else(|| DriverError::Failed(format!("no task in the answer: {upid}")))?;
    let path = format!("/nodes/{node}/tasks/{}/status", segment(upid));
    let deadline = Instant::now() + limit;
    loop {
        let status = c.call("GET", &path, &[]).await?;
        if status["status"] == "stopped" {
            return match status["exitstatus"].as_str() {
                Some("OK") => Ok(json!({ "upid": upid })),
                Some(why) => Err(DriverError::Failed(why.to_string())),
                None => Err(DriverError::Failed("the task ended without an exit status".into())),
            };
        }
        if Instant::now() >= deadline {
            return Err(DriverError::Failed(format!("the task {upid} didn't end within {limit:?}")));
        }
        tokio::time::sleep(TASK_POLL).await;
    }
}

fn form_value(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn without_digest(v: &Value) -> Value {
    match v {
        Value::Object(m) => {
            Value::Object(m.iter().filter(|(k, _)| *k != "digest").map(|(k, v)| (k.clone(), v.clone())).collect())
        }
        other => other.clone(),
    }
}

async fn firewall_read(c: &Client, g: &Guest) -> Result<Value, DriverError> {
    let options = without_digest(&c.call("GET", &g.path("/firewall/options"), &[]).await?);
    let rules: Vec<Value> = c
        .call("GET", &g.path("/firewall/rules"), &[])
        .await?
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| match without_digest(r) {
            Value::Object(mut m) => {
                m.remove("pos");
                Value::Object(m)
            }
            other => other,
        })
        .collect();
    let config = c.call("GET", &g.path("/config"), &[]).await?;
    let devices: Map<String, Value> = config
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| k.starts_with("net") && k[3..].chars().all(|d| d.is_ascii_digit()))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    Ok(json!({ "options": options, "rules": rules, "devices": devices }))
}

async fn firewall_restore(c: &Client, g: &Guest, saved: &Value) -> Result<(), DriverError> {
    let (Some(options), Some(rules), Some(devices)) =
        (saved["options"].as_object(), saved["rules"].as_array(), saved["devices"].as_object())
    else {
        return Err(bad("`saved` is what firewall_read gave"));
    };
    // options: the saved values, and what has been set since removed
    let now = c.call("GET", &g.path("/firewall/options"), &[]).await?;
    let gone: Vec<String> = now
        .as_object()
        .into_iter()
        .flatten()
        .map(|(k, _)| k.clone())
        .filter(|k| k != "digest" && !options.contains_key(k))
        .collect();
    let mut form: Vec<(String, String)> = options.iter().map(|(k, v)| (k.clone(), form_value(v))).collect();
    if !gone.is_empty() {
        form.push(("delete".into(), gone.join(",")));
    }
    if !form.is_empty() {
        c.call("PUT", &g.path("/firewall/options"), &form).await?;
    }
    // rules: every current one removed (from the bottom), then the saved ones in their order
    let forms: Vec<Vec<(String, String)>> = rules
        .iter()
        .map(|rule| rule.as_object().into_iter().flatten().map(|(k, v)| (k.clone(), form_value(v))).collect())
        .collect();
    put_rules(c, g, &forms).await?;
    // the devices' lines, with their firewall flags
    let form: Vec<(String, String)> = devices.iter().map(|(k, v)| (k.clone(), form_value(v))).collect();
    if !form.is_empty() {
        c.call("PUT", &g.path("/config"), &form).await?;
    }
    Ok(())
}

/// Removes every rule of the guest (from the bottom), then adds `rules` in order.
async fn put_rules(c: &Client, g: &Guest, rules: &[Vec<(String, String)>]) -> Result<(), DriverError> {
    let current = c.call("GET", &g.path("/firewall/rules"), &[]).await?;
    let count = current.as_array().map_or(0, Vec::len);
    for pos in (0..count).rev() {
        c.call("DELETE", &g.path(&format!("/firewall/rules/{pos}")), &[]).await?;
    }
    for (pos, rule) in rules.iter().enumerate() {
        let mut form = rule.clone();
        form.push(("pos".into(), pos.to_string()));
        c.call("POST", &g.path("/firewall/rules"), &form).await?;
    }
    Ok(())
}

fn pair(k: &str, v: &str) -> (String, String) {
    (k.to_string(), v.to_string())
}

/// The rules a quarantined guest keeps (7.5.6, D104), and nothing else: DHCP in both directions, the guest to the hub's
/// port, and the hub to the guest's SSH and echo requests. Replies need no rule: the firewall tracks connections.
fn isolation_rules(hub_addrs: &[std::net::IpAddr], hub_port: u16) -> Vec<Vec<(String, String)>> {
    let port = hub_port.to_string();
    let mut rules = vec![
        vec![
            pair("type", "out"),
            pair("action", "ACCEPT"),
            pair("proto", "udp"),
            pair("sport", "68"),
            pair("dport", "67"),
        ],
        vec![
            pair("type", "in"),
            pair("action", "ACCEPT"),
            pair("proto", "udp"),
            pair("sport", "67"),
            pair("dport", "68"),
        ],
    ];
    for addr in hub_addrs {
        let a = addr.to_string();
        let icmp = if addr.is_ipv6() { "ipv6-icmp" } else { "icmp" };
        rules.push(vec![
            pair("type", "out"),
            pair("action", "ACCEPT"),
            pair("proto", "udp"),
            pair("dest", &a),
            pair("dport", &port),
        ]);
        rules.push(vec![
            pair("type", "in"),
            pair("action", "ACCEPT"),
            pair("proto", "tcp"),
            pair("source", &a),
            pair("dport", "22"),
        ]);
        rules.push(vec![
            pair("type", "in"),
            pair("action", "ACCEPT"),
            pair("proto", icmp),
            pair("source", &a),
            pair("icmp-type", "echo-request"),
        ]);
    }
    for rule in &mut rules {
        rule.push(pair("enable", "1"));
    }
    rules
}

/// A network device's line with its firewall flag on.
fn with_firewall_flag(line: &str) -> String {
    let mut parts: Vec<String> = line.split(',').map(str::to_string).collect();
    match parts.iter_mut().find(|p| p.starts_with("firewall=")) {
        Some(p) => *p = "firewall=1".into(),
        None => parts.push("firewall=1".into()),
    }
    parts.join(",")
}

async fn firewall_isolate(c: &Client, g: &Guest, args: &Value) -> Result<Value, DriverError> {
    let addrs: Vec<std::net::IpAddr> =
        args["hub_addrs"].as_array().into_iter().flatten().filter_map(|v| v.as_str()?.parse().ok()).collect();
    let port = args["hub_port"].as_u64().and_then(|p| u16::try_from(p).ok()).filter(|p| *p > 0);
    let (false, Some(port)) = (addrs.is_empty(), port) else {
        return Err(bad("`hub_addrs` are the hub's addresses and `hub_port` its port"));
    };
    // the datacenter firewall is read, never written
    let datacenter = c.call("GET", "/cluster/firewall/options", &[]).await?;
    let on = match &datacenter["enable"] {
        Value::Number(n) => n.as_i64() == Some(1),
        Value::String(s) => s == "1",
        Value::Bool(b) => *b,
        _ => false,
    };
    if !on {
        return Err(DriverError::Failed(
            "pve_firewall_off: the datacenter firewall is off, so a guest's rules do nothing; turn it on under Datacenter, Firewall, Options (Rackhand never does), then try again".into(),
        ));
    }
    let saved = firewall_read(c, g).await?;
    // rules first (they are inert until the policies and the devices' flags are on), then the policies, then the devices;
    // a write that fails puts the saved configuration back, so a retry never takes a half-isolated one for the original
    let written: Result<(), DriverError> = async {
        put_rules(c, g, &isolation_rules(&addrs, port)).await?;
        let form = vec![pair("enable", "1"), pair("policy_in", "DROP"), pair("policy_out", "DROP")];
        c.call("PUT", &g.path("/firewall/options"), &form).await?;
        let devices: Vec<(String, String)> = saved["devices"]
            .as_object()
            .into_iter()
            .flatten()
            .filter_map(|(k, v)| Some((k.clone(), with_firewall_flag(v.as_str()?))))
            .collect();
        if !devices.is_empty() {
            c.call("PUT", &g.path("/config"), &devices).await?;
        }
        Ok(())
    }
    .await;
    if let Err(e) = written {
        let back = match firewall_restore(c, g, &saved).await {
            Ok(()) => "put back as it was",
            Err(_) => "left as it is: putting it back failed too",
        };
        return Err(DriverError::Failed(format!("isolating the guest failed ({e}); its firewall was {back}")));
    }
    let applied = firewall_read(c, g).await?;
    Ok(json!({ "saved": saved, "applied": applied }))
}

async fn firewall_release(c: &Client, g: &Guest, args: &Value) -> Result<Value, DriverError> {
    let (saved, applied) = (&args["saved"], &args["applied"]);
    if !saved.is_object() || !applied.is_object() {
        return Err(bad("`saved` and `applied` are what firewall_isolate gave"));
    }
    if &firewall_read(c, g).await? != applied {
        return Err(DriverError::Failed(
            "quarantine_config_changed: the guest's firewall configuration was changed while it was quarantined; a person decides which version to keep".into(),
        ));
    }
    firewall_restore(c, g, saved).await?;
    Ok(json!({ "restored": true }))
}

/// A MAC address as a configuration writes it: six pairs of hex digits.
fn is_mac(v: &str) -> bool {
    let parts: Vec<&str> = v.split(':').collect();
    parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()))
}

/// The MACs of a guest's network devices (`netN`): `virtio=<mac>,...` for a VM, `...,hwaddr=<mac>,...` for a container.
fn config_macs(config: &Value) -> Vec<String> {
    config
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(k, _)| k.len() > 3 && k.starts_with("net") && k[3..].chars().all(|d| d.is_ascii_digit()))
        .filter_map(|(_, v)| v.as_str())
        .filter_map(|line| line.split(',').filter_map(|kv| kv.split_once('=')).map(|(_, v)| v).find(|v| is_mac(v)))
        .map(str::to_string)
        .collect()
}

/// Every guest of every node with the MACs its configuration gives (7.3.12 guest binding). A configuration that
/// doesn't load fails the whole list: a list without that guest could miss a second guest with the same MAC.
async fn guests(c: &Client) -> Result<Value, DriverError> {
    let mut out = Vec::new();
    for node in super::nodes(c).await? {
        for kind in ["lxc", "qemu"] {
            let list = c.call("GET", &format!("/nodes/{node}/{kind}"), &[]).await?;
            for g in list.as_array().into_iter().flatten() {
                let Some(vmid) = g["vmid"].as_u64().or_else(|| g["vmid"].as_str().and_then(|v| v.parse().ok())) else {
                    continue;
                };
                let config = c.call("GET", &format!("/nodes/{node}/{kind}/{vmid}/config"), &[]).await?;
                out.push(json!({ "node": node, "vmid": vmid, "type": kind, "macs": config_macs(&config) }));
            }
        }
    }
    Ok(Value::Array(out))
}

/// This host's node and its cluster's nodes (the host's own alone when it has none).
async fn nodes_of(c: &Client) -> Result<(String, Vec<String>), DriverError> {
    let list = c.call("GET", "/nodes", &[]).await?;
    let mut nodes: Vec<String> =
        list.as_array().into_iter().flatten().filter_map(|n| n["node"].as_str().map(str::to_string)).collect();
    nodes.sort();
    nodes.dedup();
    let node = match (&c.node, nodes.as_slice()) {
        (Some(n), _) => n.clone(),
        (None, [only]) => only.clone(),
        _ => return Err(DriverError::Failed("the cluster has several nodes: set `node` to this host's".into())),
    };
    Ok((node, nodes))
}

async fn node_of(c: &Client) -> Result<String, DriverError> {
    Ok(nodes_of(c).await?.0)
}

/// This host: its node, its cluster's nodes (online or not) and the guests on its node (7.5.3 step 7).
async fn host(c: &Client) -> Result<Value, DriverError> {
    let (node, nodes) = nodes_of(c).await?;
    let mut guests = Vec::new();
    for kind in ["lxc", "qemu"] {
        let list = c.call("GET", &format!("/nodes/{}/{kind}", segment(&node)), &[]).await?;
        for g in list.as_array().into_iter().flatten() {
            let Some(vmid) = g["vmid"].as_u64().or_else(|| g["vmid"].as_str().and_then(|v| v.parse().ok())) else {
                continue;
            };
            let running = g["status"].as_str() == Some("running");
            guests.push(json!({ "vmid": vmid, "type": kind, "name": g["name"].as_str(), "running": running }));
        }
    }
    Ok(json!({ "node": node, "nodes": nodes, "guests": guests }))
}

/// The volumes of a guest's disks, by storage: `(storage, volume)` from each disk line, CD drives and `none` left out.
fn disks(kind: &str, config: &Value) -> Vec<(String, String)> {
    let disk_key = |k: &str| {
        let numbered = |prefix: &str| {
            k.strip_prefix(prefix).is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        };
        if kind == "lxc" {
            k == "rootfs" || numbered("mp")
        } else {
            ["scsi", "virtio", "sata", "ide"].iter().any(|p| numbered(p)) || k == "efidisk0" || k == "tpmstate0"
        }
    };
    let mut out = Vec::new();
    for (k, v) in config.as_object().into_iter().flatten() {
        let Some(line) = v.as_str().filter(|_| disk_key(k)) else { continue };
        if line.split(',').any(|o| o == "media=cdrom") {
            continue;
        }
        let volume = line.split(',').next().unwrap_or_default();
        if let Some((storage, name)) = volume.split_once(':') {
            out.push((storage.to_string(), name.to_string()));
        }
    }
    out
}

fn can_snapshot(storage_type: &str, kind: &str, volumes: &[&str]) -> bool {
    match storage_type {
        "zfspool" | "zfs" | "lvmthin" | "rbd" | "btrfs" => true,
        "dir" | "nfs" | "cifs" | "glusterfs" | "cephfs" => {
            kind == "qemu" && volumes.iter().all(|v| v.ends_with(".qcow2"))
        }
        _ => false,
    }
}

async fn snapshot_room(c: &Client, g: &Guest) -> Result<Value, DriverError> {
    let config = c.call("GET", &g.path("/config"), &[]).await?;
    let used = disks(g.kind, &config);
    let storages = c.call("GET", &format!("/nodes/{}/storage", g.node), &[]).await?;
    let mut out = Vec::new();
    let mut names: Vec<&str> = used.iter().map(|(s, _)| s.as_str()).collect();
    names.sort();
    names.dedup();
    for name in names {
        let volumes: Vec<&str> = used.iter().filter(|(s, _)| s == name).map(|(_, v)| v.as_str()).collect();
        let found = storages.as_array().into_iter().flatten().find(|s| s["storage"] == name);
        let Some(st) = found else {
            return Err(DriverError::Failed(format!("storage {name} isn't on node {}", g.node)));
        };
        let storage_type = st["type"].as_str().unwrap_or_default();
        out.push(json!({
            "storage": name,
            "type": storage_type,
            "avail": st["avail"].as_u64().unwrap_or(0),
            "total": st["total"].as_u64().unwrap_or(0),
            "snapshots": can_snapshot(storage_type, g.kind, &volumes),
        }));
    }
    Ok(json!({ "storages": out }))
}

/// What `config_set` may change: cloud-init and sizing. Nothing that runs code on the host (hook scripts, raw QEMU
/// arguments, LXC's own keys) and nothing that deletes.
pub(super) const SETTABLE: &[&str] = &[
    "cicustom",
    "ciuser",
    "cipassword",
    "sshkeys",
    "ipconfig0",
    "nameserver",
    "searchdomain",
    "ciupgrade",
    "agent",
    "name",
    "hostname",
    "memory",
    "cores",
    "net0",
    "description",
    "onboot",
];

pub(super) async fn run(c: &Client, target: &DriverTarget, op: DriverOp) -> Result<DriverOpResult, DriverError> {
    let a = &op.args;
    let limit = target.timeout.max(Duration::from_secs(10));
    let output = match op.name.as_str() {
        "snapshot" => {
            let (g, n) = (guest(c, a).await?, name(a)?);
            let upid = c.call("POST", &g.path("/snapshot"), &[("snapname".into(), n.clone())]).await?;
            let mut out = wait(c, &g.node, &upid, limit).await?;
            out["snapshot"] = json!(n);
            out
        }
        "rollback" => {
            let (g, n) = (guest(c, a).await?, name(a)?);
            let upid = c.call("POST", &g.path(&format!("/snapshot/{}/rollback", segment(&n))), &[]).await?;
            wait(c, &g.node, &upid, limit).await?
        }
        "delete_snapshot" => {
            let (g, n) = (guest(c, a).await?, name(a)?);
            let upid = c.call("DELETE", &g.path(&format!("/snapshot/{}", segment(&n))), &[]).await?;
            wait(c, &g.node, &upid, limit).await?
        }
        "firewall_read" => firewall_read(c, &guest(c, a).await?).await?,
        "firewall_restore" => {
            let g = guest(c, a).await?;
            firewall_restore(c, &g, &a["saved"]).await?;
            json!({ "restored": true })
        }
        "firewall_isolate" => firewall_isolate(c, &guest(c, a).await?, a).await?,
        "firewall_release" => firewall_release(c, &guest(c, a).await?, a).await?,
        "power" => {
            let g = guest(c, a).await?;
            let action = a["action"].as_str().filter(|x| matches!(*x, "start" | "stop" | "shutdown" | "reboot"));
            let action = action.ok_or_else(|| bad("`action` is start, stop, shutdown or reboot"))?;
            let upid = c.call("POST", &g.path(&format!("/status/{action}")), &[]).await?;
            wait(c, &g.node, &upid, limit).await?
        }
        "clone" => {
            let mut args = a.clone();
            args["kind"] = json!("qemu");
            let g = guest(c, &args).await?;
            let newid = a["newid"].as_u64().ok_or_else(|| bad("`newid` is a number"))?;
            let mut form = vec![("newid".to_string(), newid.to_string()), ("full".into(), "1".into())];
            if let Some(n) = a["name"].as_str() {
                form.push(("name".into(), n.into()));
            }
            if let Some(s) = a["storage"].as_str() {
                form.push(("storage".into(), s.into()));
            }
            let upid = c.call("POST", &g.path("/clone"), &form).await?;
            wait(c, &g.node, &upid, limit).await?
        }
        "create_lxc" => {
            let field = |k: &str| a[k].as_str().filter(|v| !v.is_empty()).ok_or_else(|| bad(&format!("`{k}`")));
            let vmid = a["vmid"].as_u64().ok_or_else(|| bad("`vmid` is a number"))?;
            let (hostname, template, storage) = (field("hostname")?, field("ostemplate")?, field("storage")?);
            let size = |k: &str, default: u64| a[k].as_u64().unwrap_or(default);
            let bridge = a["bridge"].as_str().unwrap_or("vmbr0");
            let form = vec![
                ("vmid".to_string(), vmid.to_string()),
                ("hostname".into(), hostname.into()),
                ("ostemplate".into(), template.into()),
                ("rootfs".into(), format!("{storage}:{}", size("disk_gb", 8))),
                ("memory".into(), size("memory", 512).to_string()),
                ("cores".into(), size("cores", 1).to_string()),
                ("net0".into(), format!("name=eth0,bridge={bridge},ip=dhcp")),
                ("unprivileged".into(), "1".into()),
            ];
            let node = node_of(c).await?;
            let upid = c.call("POST", &format!("/nodes/{}/lxc", segment(&node)), &form).await?;
            wait(c, &node, &upid, limit).await?
        }
        "config_set" => {
            let g = guest(c, a).await?;
            let set = a["set"].as_object().filter(|m| !m.is_empty()).ok_or_else(|| bad("`set` names what to set"))?;
            if let Some(key) = set.keys().find(|k| !SETTABLE.contains(&k.as_str())) {
                return Err(bad(&format!("`{key}` isn't a setting a runbook may change")));
            }
            let form: Vec<(String, String)> = set.iter().map(|(k, v)| (k.clone(), form_value(v))).collect();
            c.call("PUT", &g.path("/config"), &form).await?;
            json!({ "set": set.keys().collect::<Vec<_>>() })
        }
        "config" => c.call("GET", &guest(c, a).await?.path("/config"), &[]).await?,
        "snapshots" => {
            let list = c.call("GET", &guest(c, a).await?.path("/snapshot"), &[]).await?;
            let kept = list.as_array().into_iter().flatten().filter(|s| s["name"] != "current");
            Value::Array(kept.map(|s| json!({ "name": s["name"], "snaptime": s["snaptime"] })).collect())
        }
        "snapshot_room" => snapshot_room(c, &guest(c, a).await?).await?,
        "guests" => guests(c).await?,
        "host" => host(c).await?,
        other => return Err(bad(&format!("no Proxmox operation `{other}`"))),
    };
    Ok(DriverOpResult { output })
}
