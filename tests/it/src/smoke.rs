//! Checks that the integration tier's environment works.

use std::process::Command;

#[test]
fn docker_answers() {
    let out = Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .output()
        .expect("docker CLI is installed");
    assert!(out.status.success(), "docker version failed: {}", String::from_utf8_lossy(&out.stderr));
    let version = String::from_utf8_lossy(&out.stdout);
    assert!(!version.trim().is_empty(), "docker reported no server version");
}
