//! The Proxmox operations the runbooks use (7.5.3, 7.5.6, D104), each waiting for its task where the API starts one:
//! - `snapshot`, `rollback`, `delete_snapshot`: `{kind, vmid, name}`;
//! - `firewall_read`: `{kind, vmid}` gives `{options, rules, devices}` (the guest's firewall options and rules, and its
//!   network devices' lines, which carry their `firewall` flag), without the digests that change on every write;
//! - `firewall_restore`: `{kind, vmid, saved}` puts a `firewall_read` back exactly;
//! - `power`: `{kind, vmid, action}` with `start`, `stop`, `shutdown` or `reboot`;
//! - `clone`: `{vmid, newid, name, storage?}` (a full clone of a VM);
//! - `config`: `{kind, vmid}`;
//! - `snapshots`: `{kind, vmid}` gives the guest's snapshots, `[{name, snaptime}]`, without Proxmox's `current`;
//! - `snapshot_room`: `{kind, vmid}` gives `{storages: [{storage, type, avail, total, snapshots}]}`, each storage the
//!   guest's disks use (CD drives left out) and whether it can snapshot them: ZFS, LVM-thin, RBD and Btrfs can; a
//!   directory or network file storage only a VM's qcow2 images; anything else can't.
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
    let current = c.call("GET", &g.path("/firewall/rules"), &[]).await?;
    let count = current.as_array().map_or(0, Vec::len);
    for pos in (0..count).rev() {
        c.call("DELETE", &g.path(&format!("/firewall/rules/{pos}")), &[]).await?;
    }
    for (pos, rule) in rules.iter().enumerate() {
        let mut form: Vec<(String, String)> =
            rule.as_object().into_iter().flatten().map(|(k, v)| (k.clone(), form_value(v))).collect();
        form.push(("pos".into(), pos.to_string()));
        c.call("POST", &g.path("/firewall/rules"), &form).await?;
    }
    // the devices' lines, with their firewall flags
    let form: Vec<(String, String)> = devices.iter().map(|(k, v)| (k.clone(), form_value(v))).collect();
    if !form.is_empty() {
        c.call("PUT", &g.path("/config"), &form).await?;
    }
    Ok(())
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
        "config" => c.call("GET", &guest(c, a).await?.path("/config"), &[]).await?,
        "snapshots" => {
            let list = c.call("GET", &guest(c, a).await?.path("/snapshot"), &[]).await?;
            let kept = list.as_array().into_iter().flatten().filter(|s| s["name"] != "current");
            Value::Array(kept.map(|s| json!({ "name": s["name"], "snaptime": s["snaptime"] })).collect())
        }
        "snapshot_room" => snapshot_room(c, &guest(c, a).await?).await?,
        "guests" => guests(c).await?,
        other => return Err(bad(&format!("no Proxmox operation `{other}`"))),
    };
    Ok(DriverOpResult { output })
}
