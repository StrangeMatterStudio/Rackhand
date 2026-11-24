//! Helpers for the integration tier: workspace binaries, and containers removed when dropped.

use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::OnceLock;

/// Builds a workspace binary (once per test process) and returns its path.
pub fn binary(package: &str, bin: &str) -> PathBuf {
    build(package, bin, None)
}

/// The same without its symbols, as a release ships it, for a container.
pub fn container_binary(package: &str, bin: &str) -> PathBuf {
    stripped(&build(package, bin, None))
}

/// The same, as a static musl binary (for Alpine containers).
pub fn musl_binary(package: &str, bin: &str) -> PathBuf {
    stripped(&build(package, bin, Some("x86_64-unknown-linux-musl")))
}

/// `exe` without its symbols, kept next to it for the other test processes. With them the probe is 270 MB: two dozen
/// containers each writing a copy left the disk minutes behind, and everything that syncs (a container's systemd
/// booting, the hub's database) waited for it.
fn stripped(exe: &std::path::Path) -> PathBuf {
    static STRIPPING: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _one = STRIPPING.lock().unwrap_or_else(|e| e.into_inner());
    let meta = std::fs::metadata(exe).unwrap_or_else(|e| panic!("{}: {e}", exe.display()));
    let built = meta.modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos();
    // Named for the build it came from: another build of the same path never finds it.
    let out = exe.with_extension(format!("{built}-{}.stripped", meta.len()));
    if !out.exists() {
        let part = exe.with_extension(format!("{}.part", std::process::id()));
        let strip = Command::new("strip").arg("-o").arg(&part).arg(exe).status();
        assert!(strip.is_ok_and(|s| s.success()), "strip {}", exe.display());
        std::fs::rename(&part, &out).unwrap();
    }
    out
}

/// A host binary built with `features`, copied out of the target directory (a later build without the features writes
/// the same path).
pub fn binary_with(package: &str, bin: &str, features: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let key = format!("{bin}+{features}");
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(&key) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", bin, "--features", features, "--message-format=json"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} with {features} failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    let copy = std::env::temp_dir().join(format!("{bin}-{}-{}", features.replace([',', '/'], "-"), std::process::id()));
    std::fs::copy(&built, &copy).unwrap_or_else(|e| panic!("copying {bin}: {e}"));
    cache.insert(key, copy.clone());
    copy
}

/// A static musl binary built with `features`, copied out of the target directory (a later build without the
/// features writes the same path).
pub fn musl_binary_with(package: &str, bin: &str, features: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let key = format!("{bin}+{features}");
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(&key) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", bin, "--features", features, "--message-format=json"])
        .args(["--target", "x86_64-unknown-linux-musl"])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} with {features} failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    let copy = std::env::temp_dir().join(format!("{bin}-{}-{}", features.replace([',', '/'], "-"), std::process::id()));
    std::fs::copy(stripped(&built), &copy).unwrap_or_else(|e| panic!("copying {bin}: {e}"));
    cache.insert(key, copy.clone());
    copy
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
        // Booted before the test uses it: under the tier's load a container's systemd can take a while, and a test
        // racing its boot (systemd-run blocks until the boot ends) fails in ways that say nothing about Rackhand.
        let start = std::time::Instant::now();
        while !c.root("systemctl is-system-running 2>/dev/null | grep -qE 'running|degraded'").status.success() {
            if start.elapsed() > std::time::Duration::from_secs(60) {
                let state = c.root("systemctl is-system-running; systemctl list-jobs --no-pager | head -20");
                panic!("{image}: systemd didn't finish booting in 60 s: {}", String::from_utf8_lossy(&state.stdout));
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

/// A static musl binary built with `features` and told it is `version` (`RACKHAND_PROBE_VERSION`, which a `lab-build` of
/// the probe honors), to play a newer release in the update tests.
pub fn musl_binary_versioned(package: &str, bin: &str, features: &str, version: &str) -> PathBuf {
    musl_binary_versioned_by(package, bin, features, "RACKHAND_PROBE_VERSION", version)
}

/// The same, with the version in `var` (`RACKHAND_LAB_VERSION` for `rackhand`).
pub fn musl_binary_versioned_by(package: &str, bin: &str, features: &str, var: &str, version: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let key = format!("{bin}+{features}@{version}");
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(&key) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", bin, "--features", features, "--message-format=json"])
        .args(["--target", "x86_64-unknown-linux-musl"])
        .args(["--config", &format!("env.{var}=\"{version}\"")])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} {version} failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    let copy = std::env::temp_dir().join(format!("{bin}-{version}-{}", std::process::id()));
    std::fs::copy(stripped(&built), &copy).unwrap_or_else(|e| panic!("copying {bin}: {e}"));
    // the next build of the same path, without the version, mustn't be taken for this one
    cache.insert(key, copy.clone());
    copy
}

/// A host binary built with `features` and `var=version` in its build's environment (a lab build that plays a newer release).
pub fn binary_versioned(package: &str, bin: &str, features: &str, var: &str, version: &str) -> PathBuf {
    static BUILT: OnceLock<std::sync::Mutex<std::collections::HashMap<String, PathBuf>>> = OnceLock::new();
    let key = format!("{bin}+{features}@{version}");
    let cache = BUILT.get_or_init(Default::default);
    let mut cache = cache.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(p) = cache.get(&key) {
        return p.clone();
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-q", "-p", package, "--bin", bin, "--features", features, "--message-format=json"])
        .args(["--config", &format!("env.{var}=\"{version}\"")])
        .stderr(Stdio::inherit())
        .output()
        .unwrap_or_else(|e| panic!("cargo build {bin}: {e}"));
    assert!(out.status.success(), "building {bin} {version} failed");
    let built = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["target"]["name"] == bin)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .unwrap_or_else(|| panic!("no executable for {bin}"));
    let copy = std::env::temp_dir().join(format!("{bin}-{features}-{version}-{}", std::process::id()));
    std::fs::copy(&built, &copy).unwrap_or_else(|e| panic!("copying {bin}: {e}"));
    cache.insert(key, copy.clone());
    copy
}
