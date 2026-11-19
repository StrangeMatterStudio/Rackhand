//! Running lab machines with QEMU/KVM as the normal user: disks, NICs, QMP control and SSH (plan L1).
//!
//! Disk layout per machine under `~/.cache/rackhand-lab/machines/<name>/`:
//! - `base.qcow2`: an overlay on the pinned image, provisioned once (cloud-init, then Proxmox for the nodes);
//! - `disk.qcow2`: an overlay on `base.qcow2` that the machine runs from; `lab reset` replaces it.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::config::{Lab, Machine};
use super::lab_dir;
use crate::vm::run_checked;

pub fn machine_dir(name: &str) -> PathBuf {
    lab_dir().join("machines").join(name)
}

pub fn key_path() -> PathBuf {
    lab_dir().join("id_ed25519")
}

/// Creates the lab SSH key once.
pub fn ensure_key() -> Result<PathBuf> {
    let key = key_path();
    if !key.exists() {
        std::fs::create_dir_all(lab_dir())?;
        run_checked(
            Command::new("ssh-keygen").args(["-q", "-t", "ed25519", "-N", "", "-C", "rackhand-lab", "-f"]).arg(&key),
        )?;
    }
    Ok(key)
}

pub fn public_key() -> Result<String> {
    let key = ensure_key()?;
    Ok(std::fs::read_to_string(key.with_extension("pub"))?.trim().to_string())
}

/// The MAC address of a machine's NIC: index 0 is the user-mode NIC, then one per site NIC.
pub fn mac(lab: &Lab, machine: &Machine, nic: usize) -> String {
    let index = lab.machines.iter().position(|m| m.name == machine.name).unwrap_or(0);
    format!("52:54:00:4c:{index:02x}:{nic:02x}")
}

pub fn is_running(name: &str) -> bool {
    let pid_file = machine_dir(name).join("qemu.pid");
    let Ok(pid) = std::fs::read_to_string(&pid_file) else { return false };
    Path::new(&format!("/proc/{}", pid.trim())).exists()
}

fn qemu_img(args: &[&str]) -> Result<()> {
    run_checked(Command::new("qemu-img").args(args).stdout(Stdio::null()))
}

/// Creates `file` as a qcow2 overlay on `backing`.
pub fn create_overlay(file: &Path, backing: &Path, size_gb: Option<u32>) -> Result<()> {
    let file_s = file.display().to_string();
    let backing_s = backing.display().to_string();
    let mut args = vec!["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", backing_s.as_str(), file_s.as_str()];
    let size = size_gb.map(|s| format!("{s}G"));
    if let Some(size) = &size {
        args.push(size);
    }
    qemu_img(&args)
}

pub fn create_blank(file: &Path, size_gb: u32) -> Result<()> {
    qemu_img(&["create", "-q", "-f", "qcow2", &file.display().to_string(), &format!("{size_gb}G")])
}

/// Starts a machine from `disk` (daemonized). `seed_url` is the NoCloud seed for first boot.
pub fn start(lab: &Lab, machine: &Machine, disk: &Path, seed_url: Option<&str>) -> Result<()> {
    let dir = machine_dir(&machine.name);
    std::fs::create_dir_all(&dir)?;
    let qmp = dir.join("qmp.sock");
    let _ = std::fs::remove_file(&qmp);
    let mut cmd = Command::new("qemu-system-x86_64");
    cmd.args(["-name", &machine.name, "-machine", "q35,accel=kvm", "-cpu", "host", "-display", "none"])
        .args(["-smp", &machine.cpus.to_string(), "-m", &machine.memory_mb.to_string()])
        .arg("-daemonize")
        .arg("-pidfile")
        .arg(dir.join("qemu.pid"))
        .arg("-qmp")
        .arg(format!("unix:{},server=on,wait=off", qmp.display()))
        .arg("-serial")
        .arg(format!("file:{}", dir.join("serial.log").display()))
        .arg("-drive")
        .arg(format!("file={},if=virtio,cache=writeback,discard=unmap", disk.display()));
    if machine.extra_disk_gb.is_some() {
        cmd.arg("-drive").arg(format!("file={},if=virtio,cache=writeback", dir.join("extra.qcow2").display()));
    }
    cmd.arg("-netdev")
        .arg(format!("user,id=u0,hostfwd=tcp:127.0.0.1:{}-:22", machine.ssh_port))
        .arg("-device")
        .arg(format!("virtio-net-pci,netdev=u0,mac={}", mac(lab, machine, 0)));
    for (i, nic) in machine.nics.iter().enumerate() {
        let site = &lab.sites[&nic.site];
        cmd.arg("-netdev")
            .arg(format!("socket,id=s{i},mcast=230.0.0.1:{},localaddr=127.0.0.1", site.mcast_port))
            .arg("-device")
            .arg(format!("virtio-net-pci,netdev=s{i},mac={}", mac(lab, machine, i + 1)));
    }
    if let Some(url) = seed_url {
        // `nocloud-net` rather than `nocloud`: Debian 12's cloud-init (22.4) needs it for an HTTP seed; newer
        // versions accept both.
        cmd.arg("-smbios").arg(format!("type=1,serial=ds=nocloud-net;s={url}"));
    }
    run_checked(&mut cmd)
}

/// Sends one QMP command to a running machine and returns the reply line.
pub fn qmp(name: &str, command: &str, arguments: Option<serde_json::Value>) -> Result<serde_json::Value> {
    let sock = machine_dir(name).join("qmp.sock");
    let stream = UnixStream::connect(&sock).with_context(|| format!("connecting to {}", sock.display()))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    reader.read_line(&mut line)?; // greeting
    writeln!(writer, "{}", serde_json::json!({"execute": "qmp_capabilities"}))?;
    read_return(&mut reader)?;
    let mut msg = serde_json::json!({ "execute": command });
    if let Some(args) = arguments {
        msg["arguments"] = args;
    }
    writeln!(writer, "{msg}")?;
    read_return(&mut reader)
}

fn read_return(reader: &mut impl BufRead) -> Result<serde_json::Value> {
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            bail!("QMP connection closed");
        }
        let value: serde_json::Value = serde_json::from_str(&line)?;
        if value.get("event").is_some() {
            continue;
        }
        if let Some(err) = value.get("error") {
            bail!("QMP error: {err}");
        }
        return Ok(value);
    }
}

/// Runs a command on a machine over SSH as the lab user.
pub fn ssh_output(machine: &Machine, command: &str) -> Result<Output> {
    let key = ensure_key()?;
    Command::new("ssh")
        .arg("-i")
        .arg(key)
        .args(["-p", &machine.ssh_port.to_string()])
        .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
        .args(["-o", "ConnectTimeout=5", "-o", "BatchMode=yes"])
        .arg("lab@127.0.0.1")
        .arg(command)
        .stdin(Stdio::null())
        .output()
        .context("running ssh")
}

pub fn ssh(machine: &Machine, command: &str) -> Result<String> {
    let out = ssh_output(machine, command)?;
    if !out.status.success() {
        bail!(
            "`{command}` on {} failed ({}): {}",
            machine.name,
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// Copies a local file to the machine.
pub fn scp_to(machine: &Machine, local: &Path, remote: &str) -> Result<()> {
    let key = ensure_key()?;
    run_checked(
        Command::new("scp")
            .arg("-q")
            .arg("-i")
            .arg(key)
            .args(["-P", &machine.ssh_port.to_string()])
            .args(["-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR"])
            .arg(local)
            .arg(format!("lab@127.0.0.1:{remote}")),
    )
}

/// Waits until the machine answers SSH, or fails after `timeout`.
pub fn wait_ssh(machine: &Machine, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    loop {
        if let Ok(out) = ssh_output(machine, "true") {
            if out.status.success() {
                return Ok(());
            }
        }
        if start.elapsed() > timeout {
            bail!("{} didn't answer SSH within {}s", machine.name, timeout.as_secs());
        }
        std::thread::sleep(Duration::from_secs(3));
    }
}

/// Waits for SSH to stop answering (after a reboot or power-off was requested).
pub fn wait_ssh_gone(machine: &Machine, timeout: Duration) -> Result<()> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        match ssh_output(machine, "true") {
            Ok(out) if out.status.success() => std::thread::sleep(Duration::from_secs(2)),
            _ => return Ok(()),
        }
    }
    bail!("{} still answers SSH after {}s", machine.name, timeout.as_secs())
}

/// Stops a machine: a clean power-off first, then `quit`.
pub fn stop(machine: &Machine) -> Result<()> {
    if !is_running(&machine.name) {
        return Ok(());
    }
    let _ = qmp(&machine.name, "system_powerdown", None);
    let start = Instant::now();
    while is_running(&machine.name) && start.elapsed() < Duration::from_secs(90) {
        std::thread::sleep(Duration::from_secs(1));
    }
    if is_running(&machine.name) {
        let _ = qmp(&machine.name, "quit", None);
        std::thread::sleep(Duration::from_secs(2));
    }
    if is_running(&machine.name) {
        bail!("{} didn't stop", machine.name);
    }
    Ok(())
}
