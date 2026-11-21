//! `cargo xtask lab record-proxmox`: the Proxmox VE API's answers on the lab's `pve8` and `pve9` nodes, for the
//! Proxmox driver's simulator (plan T47). Each GET is read with `pvesh` on the node and kept as the API returns it
//! (`{"data": ...}`); the operations the driver performs run once on the lab guest `ct-test` (LXC 100): a snapshot,
//! its rollback and deletion with their task statuses, and a task that fails. The host's CPU model is redacted.
//! Written to `tests/fixtures/proxmox/<node>/`.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use super::config::{Lab, Machine};
use super::qemu;

const NODES: &[&str] = &["pve8", "pve9"];
const CT: u32 = 100;
const VM: u32 = 200;
const SNAP: &str = "rackhand-fixture";

fn pvesh(m: &Machine, verb: &str, path: &str, args: &str) -> Result<Value> {
    let out = qemu::ssh(m, &format!("sudo pvesh {verb} {path} {args} --output-format json"))?;
    // PVE 9 prints a task's progress ("freeze guest filesystem") before the answer, which is the last line
    let text = out.trim().lines().last().unwrap_or("").trim();
    if text.is_empty() {
        return Ok(Value::Null);
    }
    serde_json::from_str(text).with_context(|| format!("{verb} {path}: {text}"))
}

/// Waits for a task and returns its status.
fn task(m: &Machine, node: &str, upid: &str) -> Result<Value> {
    let path = format!("/nodes/{node}/tasks/{}/status", upid.replace(':', "%3A"));
    for _ in 0..120 {
        let status = pvesh(m, "get", &format!("'/nodes/{node}/tasks/{upid}/status'"), "")?;
        if status["status"] == "stopped" {
            return Ok(status);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    bail!("{path}: the task didn't end")
}

/// The computer the lab runs on isn't the project's business (its CPU's model, flags and clock), nor is the lab's
/// own SSH key.
fn redact(mut v: Value) -> Value {
    for (at, value) in
        [("/cpuinfo/model", "Lab CPU"), ("/cpuinfo/flags", "fpu sse2 avx2 hypervisor"), ("/cpuinfo/mhz", "3000.000")]
    {
        if let Some(field) = v.pointer_mut(at) {
            *field = Value::String(value.into());
        }
    }
    if let Some(keys) = v.get_mut("sshkeys") {
        *keys = Value::String("ssh-ed25519%20AAAAlabkey%20rackhand-lab%0A".into());
    }
    v
}

fn save(dir: &Path, name: &str, data: Value) -> Result<()> {
    let text = serde_json::to_string_pretty(&serde_json::json!({ "data": data }))?;
    std::fs::write(dir.join(format!("{name}.json")), text + "\n")?;
    Ok(())
}

fn record_node(m: &Machine, dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    let node = qemu::ssh(m, "hostname")?.trim().to_string();
    let reads: Vec<(String, String)> = vec![
        ("nodes".into(), "/nodes".into()),
        ("node_status".into(), format!("/nodes/{node}/status")),
        ("storage".into(), format!("/nodes/{node}/storage")),
        ("lxc".into(), format!("/nodes/{node}/lxc")),
        ("qemu".into(), format!("/nodes/{node}/qemu")),
        ("lxc_status".into(), format!("/nodes/{node}/lxc/{CT}/status/current")),
        ("qemu_status".into(), format!("/nodes/{node}/qemu/{VM}/status/current")),
        ("lxc_config".into(), format!("/nodes/{node}/lxc/{CT}/config")),
        ("qemu_config".into(), format!("/nodes/{node}/qemu/{VM}/config")),
        ("lxc_firewall_options".into(), format!("/nodes/{node}/lxc/{CT}/firewall/options")),
        ("lxc_firewall_rules".into(), format!("/nodes/{node}/lxc/{CT}/firewall/rules")),
        ("cluster_firewall_options".into(), "/cluster/firewall/options".into()),
        ("lxc_snapshots".into(), format!("/nodes/{node}/lxc/{CT}/snapshot")),
    ];
    for (name, path) in &reads {
        save(dir, name, redact(pvesh(m, "get", path, "")?))?;
    }
    // the operations, on ct-test: a snapshot, its rollback, its deletion
    let _ = pvesh(m, "delete", &format!("/nodes/{node}/lxc/{CT}/snapshot/{SNAP}"), "");
    let snap = pvesh(m, "create", &format!("/nodes/{node}/lxc/{CT}/snapshot"), &format!("--snapname {SNAP}"))?;
    save(dir, "snapshot_create", snap.clone())?;
    save(dir, "snapshot_create_task", task(m, &node, snap.as_str().context("a snapshot UPID")?)?)?;
    let rollback = pvesh(m, "create", &format!("/nodes/{node}/lxc/{CT}/snapshot/{SNAP}/rollback"), "")?;
    save(dir, "snapshot_rollback", rollback.clone())?;
    save(dir, "snapshot_rollback_task", task(m, &node, rollback.as_str().context("a rollback UPID")?)?)?;
    // a rollback stops a running container on PVE 9 (S4): start it again before the next step
    let _ = qemu::ssh(m, &format!("sudo pct status {CT} | grep -q running || sudo pct start {CT}"));
    let delete = pvesh(m, "delete", &format!("/nodes/{node}/lxc/{CT}/snapshot/{SNAP}"), "")?;
    save(dir, "snapshot_delete", delete.clone())?;
    save(dir, "snapshot_delete_task", task(m, &node, delete.as_str().context("a delete UPID")?)?)?;
    // a task that fails: deleting a snapshot that doesn't exist is accepted, and its task ends in an error
    let failed = pvesh(m, "delete", &format!("/nodes/{node}/lxc/{CT}/snapshot/rackhand-missing"), "")?;
    save(dir, "failed_delete", failed.clone())?;
    save(dir, "failed_delete_task", task(m, &node, failed.as_str().context("a delete UPID")?)?)?;
    let upid = failed.as_str().unwrap_or_default();
    let log = pvesh(m, "get", &format!("'/nodes/{node}/tasks/{upid}/log'"), "")?;
    save(dir, "failed_delete_log", log)?;
    std::fs::write(dir.join("node.txt"), format!("{node}\n"))?;
    Ok(())
}

pub fn record_proxmox(lab: &Lab) -> Result<()> {
    let root = crate::workspace_root().join("tests/fixtures/proxmox");
    for name in NODES {
        let m = lab.machine(name)?;
        if !qemu::is_running(&m.name) {
            bail!("{name} isn't running: `cargo xtask lab up spikes` first");
        }
        record_node(m, &root.join(name)).with_context(|| format!("recording {name}"))?;
        println!("recorded {name} into {}", root.join(name).display());
    }
    Ok(())
}
