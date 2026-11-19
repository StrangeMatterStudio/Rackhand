//! Helpers for the integration tier: workspace binaries, and containers removed when dropped.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// Builds a workspace binary (once per test process) and returns its path.
pub fn binary(package: &str, bin: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(bin) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", bin, "--message-format=json"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} failed");
    let path = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    cache.insert(bin.to_string(), path.clone());
    path
}

/// A running container from a `rackhand-it-<image>` image, removed on drop.
pub struct Container {
    pub name: String,
}

impl Container {
    pub fn start(image: &str) -> Container {
        let name = format!("rackhand-it-{image}-{}-{}", std::process::id(), ulid_like());
        let out = Command::new("docker").args(["run", "-d", "--name", &name, &format!("rackhand-it-{image}")]).output();
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
