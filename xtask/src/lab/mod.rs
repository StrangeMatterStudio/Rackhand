//! `cargo xtask lab`: the local lab of QEMU/KVM machines in WSL (plan L1, D107).
//!
//! The lab belongs to the run: it may create, break, snapshot and reset anything in it. All state lives under
//! `~/.cache/rackhand-lab` (Linux filesystem). See `lab/lab.toml` for the machines and profiles.

pub mod config;
pub mod images;
pub mod qemu;
mod seed;

#[cfg(test)]
mod tests;

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::workspace_root;
use config::{Lab, Machine};

/// Memory kept free for builds while the lab runs (plan L1).
pub const BUILD_RESERVE_MB: u64 = 12 * 1024;

pub fn lab_dir() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join(".cache/rackhand-lab")
}

const USAGE: &str = "usage: cargo xtask lab <command>
  doctor                     check KVM, QEMU, images and memory
  fetch                      download and check every base image
  up <profile>               stop other machines, then start the profile (provisioning on first use)
  down                       stop every machine
  status                     list machines and whether they run
  reset [machine]            discard a machine's changes (all except `operator` when no name is given)
  snapshot <machine> <name>  save a running machine's state; `restore <machine> <name>` loads it
  pause|resume <machine>     freeze or continue a machine
  cut|heal <machine>         take its site link down or up
  run <machine> -- <cmd>     run a command over SSH as `lab` (with sudo available)
  ssh <machine>              print the SSH command for a machine
  destroy                    stop everything and delete all lab state except downloaded images";

pub fn run(args: &[String]) -> Result<()> {
    let lab = Lab::load()?;
    let problems = lab.check();
    if !problems.is_empty() {
        bail!("lab/lab.toml: {}", problems.join("; "));
    }
    let arg = |i: usize| args.get(i).map(String::as_str);
    match arg(0) {
        Some("doctor") => doctor(&lab),
        Some("fetch") => images::fetch_all(),
        Some("up") => up(&lab, arg(1).context("lab up <profile>")?),
        Some("down") => down(&lab),
        Some("status") => status(&lab),
        Some("reset") => match arg(1) {
            Some(name) => reset(&lab, lab.machine(name)?),
            None => {
                for m in lab.machines.iter().filter(|m| m.name != "operator" && qemu::is_running(&m.name)) {
                    reset(&lab, m)?;
                }
                Ok(())
            }
        },
        Some("snapshot") => hmp(arg(1).context("machine")?, &format!("savevm {}", arg(2).context("name")?)),
        Some("restore") => hmp(arg(1).context("machine")?, &format!("loadvm {}", arg(2).context("name")?)),
        Some("pause") => qemu::qmp(arg(1).context("machine")?, "stop", None).map(|_| ()),
        Some("resume") => qemu::qmp(arg(1).context("machine")?, "cont", None).map(|_| ()),
        Some("cut") => set_link(&lab, arg(1).context("machine")?, false),
        Some("heal") => set_link(&lab, arg(1).context("machine")?, true),
        Some("run") => {
            let machine = lab.machine(arg(1).context("machine")?)?;
            let rest: Vec<&str> = args.iter().skip(2).map(String::as_str).skip_while(|a| *a == "--").collect();
            let out = qemu::ssh_output(machine, &rest.join(" "))?;
            print!("{}", String::from_utf8_lossy(&out.stdout));
            eprint!("{}", String::from_utf8_lossy(&out.stderr));
            if !out.status.success() {
                bail!("exit status {}", out.status);
            }
            Ok(())
        }
        Some("console") => {
            let name = arg(1).context("machine")?;
            let rest: Vec<&str> = args.iter().skip(2).map(String::as_str).skip_while(|a| *a == "--").collect();
            print!("{}", qemu::console(name, &rest.join(" "))?);
            Ok(())
        }
        Some("ssh") => {
            let machine = lab.machine(arg(1).context("machine")?)?;
            println!(
                "ssh -i {} -p {} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null lab@127.0.0.1",
                qemu::key_path().display(),
                machine.ssh_port
            );
            Ok(())
        }
        Some("destroy") => destroy(&lab),
        _ => bail!("{USAGE}"),
    }
}

fn hmp(name: &str, command: &str) -> Result<()> {
    let reply = qemu::qmp(name, "human-monitor-command", Some(serde_json::json!({ "command-line": command })))?;
    let text = reply["return"].as_str().unwrap_or_default();
    if !text.trim().is_empty() {
        bail!("{command} on {name}: {}", text.trim());
    }
    Ok(())
}

fn set_link(lab: &Lab, name: &str, up: bool) -> Result<()> {
    let machine = lab.machine(name)?;
    for i in 0..machine.nics.len() {
        qemu::qmp(name, "set_link", Some(serde_json::json!({ "name": format!("s{i}"), "up": up })))?;
    }
    Ok(())
}

fn mem_available_mb() -> Result<u64> {
    let info = std::fs::read_to_string("/proc/meminfo")?;
    let kb: u64 = info
        .lines()
        .find(|l| l.starts_with("MemAvailable:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .context("MemAvailable in /proc/meminfo")?;
    Ok(kb / 1024)
}

fn doctor(lab: &Lab) -> Result<()> {
    let kvm = std::fs::OpenOptions::new().read(true).write(true).open("/dev/kvm").is_ok();
    println!("kvm: {}", if kvm { "usable" } else { "NOT usable" });
    for tool in ["qemu-system-x86_64", "qemu-img", "ssh", "ssh-keygen", "curl"] {
        let ok = Command::new("sh").args(["-c", &format!("command -v {tool}")]).output()?.status.success();
        println!("{tool}: {}", if ok { "found" } else { "MISSING" });
    }
    for image in images::load()? {
        let state = if image.path().with_extension("verified").exists() { "verified" } else { "not fetched" };
        println!("image {}: {state}", image.name);
    }
    let available = mem_available_mb()?;
    let largest = lab.profiles.keys().map(|p| (p.clone(), lab.profile_memory_mb(p).unwrap_or(0))).max_by_key(|p| p.1);
    if let Some((profile, mb)) = largest {
        println!(
            "memory: {available} MB available; largest profile `{profile}` needs {mb} MB plus {BUILD_RESERVE_MB} MB for builds"
        );
    }
    if !kvm {
        bail!("/dev/kvm isn't usable");
    }
    Ok(())
}

/// A hash of what a base image is provisioned from; `base.provisioned` holds it, so changing a provision script or
/// the image provisions that machine's base again.
pub(crate) fn stamp(image: &str, parts: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    for part in std::iter::once(image.as_bytes()).chain(parts.iter().copied()) {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.finalize().iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn is_provisioned(dir: &std::path::Path, stamp: &str) -> bool {
    std::fs::read_to_string(dir.join("base.provisioned")).is_ok_and(|s| s.trim() == stamp)
}

fn provision_stamp(lab: &Lab, m: &Machine) -> Result<String> {
    let user_data = seed::user_data(lab, m)?;
    let mut parts = vec![user_data.into_bytes()];
    if m.proxmox.is_some() {
        parts.push(std::fs::read(workspace_root().join("lab/provision/proxmox.sh"))?);
    }
    // The extra disk became an overlay on a provisioned base: machines provisioned before that start over.
    if m.extra_disk_gb.is_some() {
        parts.push(b"extra-base overlay".to_vec());
    }
    Ok(stamp(&m.image, &parts.iter().map(Vec::as_slice).collect::<Vec<_>>()))
}

fn provisioned(lab: &Lab, m: &Machine) -> bool {
    provision_stamp(lab, m).is_ok_and(|s| is_provisioned(&qemu::machine_dir(&m.name), &s))
}

fn status(lab: &Lab) -> Result<()> {
    for m in &lab.machines {
        let provisioned = provisioned(lab, m);
        println!(
            "{:<10} {:<8} {}",
            m.name,
            if qemu::is_running(&m.name) { "running" } else { "stopped" },
            if provisioned { "provisioned" } else { "" }
        );
    }
    Ok(())
}

fn down(lab: &Lab) -> Result<()> {
    for m in lab.machines.iter().filter(|m| qemu::is_running(&m.name)) {
        println!("stopping {}", m.name);
        qemu::stop(m)?;
    }
    Ok(())
}

fn destroy(lab: &Lab) -> Result<()> {
    down(lab)?;
    let machines = lab_dir().join("machines");
    if machines.exists() {
        std::fs::remove_dir_all(&machines)?;
    }
    println!("lab state deleted (images kept under {})", lab_dir().join("images").display());
    Ok(())
}

/// Brings up a profile: stops machines outside it, provisions machines that have never run, starts the rest.
pub fn up(lab: &Lab, profile: &str) -> Result<()> {
    let machines = lab.profile(profile)?;
    for m in lab.machines.iter().filter(|m| qemu::is_running(&m.name) && !machines.iter().any(|p| p.name == m.name)) {
        println!("stopping {} (not in profile {profile})", m.name);
        qemu::stop(m)?;
    }
    let running: u64 = machines.iter().filter(|m| qemu::is_running(&m.name)).map(|m| m.memory_mb).sum();
    lab.check_budget(profile, mem_available_mb()? + running, BUILD_RESERVE_MB)?;
    qemu::ensure_key()?;

    let to_provision: Vec<&Machine> = machines.iter().copied().filter(|m| !provisioned(lab, m)).collect();
    for m in to_provision.iter().filter(|m| qemu::is_running(&m.name)) {
        println!("stopping {} (its provisioning changed)", m.name);
        qemu::stop(m)?;
    }
    if !to_provision.is_empty() {
        let server = seed::Server::start()?;
        std::thread::scope(|scope| -> Result<()> {
            let handles: Vec<_> = to_provision
                .iter()
                .map(|m| {
                    let server = &server;
                    scope.spawn(move || provision(lab, m, server).with_context(|| format!("provisioning {}", m.name)))
                })
                .collect();
            let mut errors = Vec::new();
            for h in handles {
                if let Err(e) = h.join().map_err(|_| anyhow::anyhow!("provisioning thread panicked"))? {
                    errors.push(format!("{e:#}"));
                }
            }
            if errors.is_empty() { Ok(()) } else { bail!("{}", errors.join("\n")) }
        })?;
    }
    for m in &machines {
        if !qemu::is_running(&m.name) {
            ensure_disk(m)?;
            println!("starting {}", m.name);
            qemu::start(lab, m, qemu::Stage::Run, None)?;
        }
    }
    for m in &machines {
        qemu::wait_ssh(m, Duration::from_secs(300))?;
    }
    println!("profile {profile} up: {}", machines.iter().map(|m| m.name.as_str()).collect::<Vec<_>>().join(", "));
    Ok(())
}

fn ensure_disk(m: &Machine) -> Result<()> {
    let dir = qemu::machine_dir(&m.name);
    let disk = dir.join("disk.qcow2");
    if !disk.exists() {
        qemu::create_overlay(&disk, &dir.join("base.qcow2"), None)?;
    }
    let extra = dir.join("extra.qcow2");
    if m.extra_disk_gb.is_some() && !extra.exists() {
        qemu::create_overlay(&extra, &dir.join("extra-base.qcow2"), None)?;
    }
    Ok(())
}

/// The overlays `lab reset` replaces: every disk the machine runs from.
pub(super) fn reset_files(m: &Machine) -> Vec<&'static str> {
    if m.extra_disk_gb.is_some() { vec!["disk.qcow2", "extra.qcow2"] } else { vec!["disk.qcow2"] }
}

/// Discards the machine's changes since provisioning.
fn reset(lab: &Lab, m: &Machine) -> Result<()> {
    let was_running = qemu::is_running(&m.name);
    if was_running {
        let _ = qemu::qmp(&m.name, "quit", None);
        let start = std::time::Instant::now();
        while qemu::is_running(&m.name) && start.elapsed() < Duration::from_secs(20) {
            std::thread::sleep(Duration::from_millis(300));
        }
    }
    let dir = qemu::machine_dir(&m.name);
    for f in reset_files(m) {
        let file = dir.join(f);
        if file.exists() {
            std::fs::remove_file(&file)?;
        }
    }
    if !dir.join("base.provisioned").exists() {
        bail!("{} has never been provisioned; run `lab up` first", m.name);
    }
    ensure_disk(m)?;
    if was_running {
        qemu::start(lab, m, qemu::Stage::Run, None)?;
        qemu::wait_ssh(m, Duration::from_secs(300))?;
    }
    println!("{} reset", m.name);
    Ok(())
}

/// First boot from the base overlay: cloud-init, then Proxmox for the nodes; then shut down and mark provisioned.
fn provision(lab: &Lab, m: &Machine, server: &seed::Server) -> Result<()> {
    let image = images::find(&m.image)?;
    let image_path = image.fetch()?;
    let dir = qemu::machine_dir(&m.name);
    std::fs::create_dir_all(&dir)?;
    let base = dir.join("base.qcow2");
    // The stamp is of the inputs this run starts from, even if a script is edited while it runs.
    let stamp = provision_stamp(lab, m)?;
    let _ = std::fs::remove_file(dir.join("base.provisioned"));
    for f in ["base.qcow2", "disk.qcow2", "extra-base.qcow2", "extra.qcow2"] {
        let _ = std::fs::remove_file(dir.join(f));
    }
    let size = if m.proxmox.is_some() { 32 } else { 16 };
    qemu::create_overlay(&base, &image_path, Some(size))?;
    if let Some(gb) = m.extra_disk_gb {
        qemu::create_blank(&dir.join("extra-base.qcow2"), gb)?;
    }
    let url = server.publish(lab, m)?;
    println!("provisioning {} (first boot)", m.name);
    qemu::start(lab, m, qemu::Stage::Provision, Some(&url))?;
    qemu::wait_ssh(m, Duration::from_secs(600))?;
    qemu::ssh(m, "sudo cloud-init status --wait >/dev/null 2>&1 || true; test -e /var/lib/rackhand-lab-ready")
        .context("cloud-init didn't finish")?;
    // Disable cloud-init before any reboot: on a later boot it would start over as a new instance (new host keys,
    // the image's default user, regenerated network config).
    qemu::ssh(m, "sudo touch /etc/cloud/cloud-init.disabled; sudo sync")?;
    if let Some(major) = m.proxmox {
        provision_proxmox(lab, m, major)?;
    }
    qemu::stop(m)?;
    std::fs::write(dir.join("base.provisioned"), stamp)?;
    println!("{} provisioned", m.name);
    Ok(())
}

fn provision_proxmox(lab: &Lab, m: &Machine, major: u32) -> Result<()> {
    let nic = m.nics.first().context("Proxmox node without a site NIC")?;
    let site = &lab.sites[&nic.site];
    let last: u32 = nic.address.rsplit('.').next().and_then(|o| o.parse().ok()).context("node address")?;
    let base = nic.address.rsplit_once('.').map(|(b, _)| b).unwrap_or("192.0.2");
    let ct_ip = format!("{base}.{}", last + 100);
    let vm_ip = format!("{base}.{}", last + 110);
    let mac = qemu::mac(lab, m, 1);
    let script = workspace_root().join("lab/provision/proxmox.sh");
    qemu::scp_to(m, &script, "/tmp/proxmox.sh")?;
    qemu::scp_to(m, &images::find("alpine-3.20")?.fetch()?, "/tmp/alpine.qcow2")?;
    qemu::scp_to(m, &qemu::key_path().with_extension("pub"), "/tmp/lab.pub")?;
    qemu::ssh(m, "sudo mv /tmp/alpine.qcow2 /tmp/lab.pub /root/")?;
    let args = format!("{major} {} {} {mac} {ct_ip} {vm_ip}", nic.address, site.prefix_len());
    println!("{}: installing Proxmox VE {major} (phase 1)", m.name);
    run_logged(m, &format!("sudo bash /tmp/proxmox.sh 1 {args}"), "proxmox-1.log")?;
    let _ = qemu::ssh_output(m, "sudo systemctl reboot");
    qemu::wait_ssh_gone(m, Duration::from_secs(120))?;
    qemu::wait_ssh(m, Duration::from_secs(600))?;
    for phase in [2, 3] {
        println!("{}: installing Proxmox VE {major} (phase {phase})", m.name);
        qemu::scp_to(m, &script, "/tmp/proxmox.sh")?;
        run_logged(m, &format!("sudo bash /tmp/proxmox.sh {phase} {args}"), &format!("proxmox-{phase}.log"))?;
        if phase == 2 {
            let _ = qemu::ssh_output(m, "sudo systemctl reboot");
            qemu::wait_ssh_gone(m, Duration::from_secs(120))?;
            qemu::wait_ssh(m, Duration::from_secs(600))
                .context("no SSH after switching to the Proxmox network configuration; see `lab console`")?;
        }
    }
    let version = qemu::ssh(m, "sudo pveversion")?;
    println!("{}: {}", m.name, version.trim());
    Ok(())
}

/// Runs a long command over SSH, keeping its output in the machine's directory.
fn run_logged(m: &Machine, command: &str, log: &str) -> Result<()> {
    let out = qemu::ssh_output(m, command)?;
    let path = qemu::machine_dir(&m.name).join(log);
    std::fs::write(&path, [out.stdout.as_slice(), b"\n--- stderr ---\n", out.stderr.as_slice()].concat())?;
    if !out.status.success() {
        let tail: Vec<String> =
            String::from_utf8_lossy(&out.stderr).lines().rev().take(15).map(str::to_string).collect();
        bail!(
            "`{command}` failed on {} ({}); see {}:\n{}",
            m.name,
            out.status,
            path.display(),
            tail.into_iter().rev().collect::<Vec<_>>().join("\n")
        );
    }
    Ok(())
}
