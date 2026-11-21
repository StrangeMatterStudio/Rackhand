//! Helpers for the integration tier: workspace binaries, and containers removed when dropped.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// Builds a workspace binary (once per test process) and returns its path.
pub fn binary(package: &str, bin: &str) -> PathBuf {
    build(package, bin, None)
}

/// The same, as a static musl binary (for Alpine containers).
pub fn musl_binary(package: &str, bin: &str) -> PathBuf {
    build(package, bin, Some("x86_64-unknown-linux-musl"))
}

fn build(package: &str, bin: &str, target: Option<&str>) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let key = format!("{bin}@{}", target.unwrap_or("host"));
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(&key) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "-q", "-p", package, "--bin", bin, "--message-format=json"]);
    if let Some(t) = target {
        cmd.args(["--target", t]);
    }
    let out = cmd.stderr(Stdio::inherit()).output().unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} failed");
    let path = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    cache.insert(key, path.clone());
    path
}

/// A running container from a `rackhand-it-<image>` image, removed on drop.
pub struct Container {
    pub name: String,
}

impl Container {
    pub fn start(image: &str) -> Container {
        Container::start_with(image, &[])
    }

    /// With systemd as PID 1, as the S11 containers ran.
    pub fn start_systemd(image: &str) -> Container {
        Container::start_systemd_with(image, &[])
    }

    /// The same, with more `docker run` arguments.
    pub fn start_systemd_with(image: &str, extra: &[&str]) -> Container {
        let mut args = vec![
            "--privileged",
            "--cgroupns=host",
            "-v",
            "/sys/fs/cgroup:/sys/fs/cgroup:rw",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
        ];
        args.extend_from_slice(extra);
        let c = Container::start_with(image, &args);
        for _ in 0..50 {
            if c.root("systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'").status.success() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        c
    }

    pub fn start_with(image: &str, extra: &[&str]) -> Container {
        let name = format!("rackhand-it-{image}-{}-{}", std::process::id(), ulid_like());
        let out = Command::new("docker")
            .args(["run", "-d", "--name", &name])
            .args(extra)
            .arg(format!("rackhand-it-{image}"))
            .output();
        let out = out.unwrap_or_else(|e| panic!("docker run: {e}"));
        assert!(
            out.status.success(),
            "docker run {image}: {} (run `cargo xtask it-images`)",
            String::from_utf8_lossy(&out.stderr)
        );
        Container { name }
    }

    pub fn copy_in(&self, from: &std::path::Path, to: &str) {
        let out = Command::new("docker")
            .arg("cp")
            .arg(from)
            .arg(format!("{}:{to}", self.name))
            .output()
            .unwrap_or_else(|e| panic!("docker cp: {e}"));
        assert!(out.status.success(), "docker cp: {}", String::from_utf8_lossy(&out.stderr));
    }

    /// Runs a command as `user` (or root), with optional standard input.
    pub fn exec(&self, user: Option<&str>, args: &[&str], stdin: Option<&[u8]>) -> Output {
        use std::io::Write;
        let mut cmd = Command::new("docker");
        cmd.arg("exec").arg("-i");
        if let Some(u) = user {
            cmd.args(["-u", u]);
        }
        cmd.arg(&self.name).args(args).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        let mut child = cmd.spawn().unwrap_or_else(|e| panic!("docker exec: {e}"));
        if let Some(mut input) = child.stdin.take() {
            if let Some(bytes) = stdin {
                let _ = input.write_all(bytes);
            }
        }
        child.wait_with_output().unwrap_or_else(|e| panic!("docker exec: {e}"))
    }

    /// The container's address and its network's gateway (the address the host connects from).
    pub fn ip_and_gateway(&self) -> (String, String) {
        let out = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.Gateway}}{{end}}",
                &self.name,
            ])
            .output()
            .unwrap_or_else(|e| panic!("docker inspect: {e}"));
        let text = String::from_utf8_lossy(&out.stdout).trim().to_string();
        let (ip, gw) = text.split_once(' ').unwrap_or_else(|| panic!("no address: {text}"));
        (ip.to_string(), gw.to_string())
    }

    /// Starts a command as `user` in the background (`docker exec -d`); it lives until it ends or is killed.
    pub fn spawn_detached(&self, user: &str, script: &str) {
        let out = Command::new("docker")
            .args(["exec", "-d", "-u", user, &self.name, "sh", "-c", script])
            .output()
            .unwrap_or_else(|e| panic!("docker exec -d: {e}"));
        assert!(out.status.success(), "docker exec -d: {}", String::from_utf8_lossy(&out.stderr));
    }

    pub fn root(&self, script: &str) -> Output {
        self.exec(None, &["sh", "-c", script], None)
    }
}

impl Drop for Container {
    fn drop(&mut self) {
        let _ = Command::new("docker").args(["rm", "-f", &self.name]).output();
    }
}

fn ulid_like() -> u128 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0)
}
