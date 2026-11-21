//! Live tier (design 14, D107): the built product against real machines in the local lab (L1 to L8) or the owner's
//! real lab (L9). Run with `cargo xtask ci live --target local --milestone <name>`, which brings the lab profile up
//! first and sets `RACKHAND_XTASK` so tests can drive the lab.

use std::process::{Command, Output};
use std::time::{Duration, Instant};

#[cfg(test)]
mod hub;
#[cfg(test)]
mod lab;
#[cfg(test)]
mod m1;

/// Runs `cargo xtask <args>` through the xtask binary that started this test run.
pub fn xtask(args: &[&str]) -> Output {
    let exe = std::env::var("RACKHAND_XTASK").expect("live tests run through `cargo xtask ci live`");
    Command::new(exe).args(args).output().expect("xtask runs")
}

/// Runs `cmd` on a lab machine and returns stdout; panics with the machine's stderr on failure.
pub fn on(machine: &str, cmd: &str) -> String {
    let out = xtask(&["lab", "run", machine, "--", cmd]);
    assert!(
        out.status.success(),
        "`{cmd}` on {machine} failed: {}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).to_string()
}

/// Whether `cmd` succeeds on a lab machine.
pub fn ok_on(machine: &str, cmd: &str) -> bool {
    xtask(&["lab", "run", machine, "--", cmd]).status.success()
}

/// Runs a lab control command (`pause`, `cut`, `reset`, ...) and panics if it fails.
pub fn lab(args: &[&str]) {
    let mut full = vec!["lab"];
    full.extend_from_slice(args);
    let out = xtask(&full);
    assert!(out.status.success(), "lab {args:?} failed: {}", String::from_utf8_lossy(&out.stderr));
}

/// Polls `check` every two seconds until it returns true or `timeout` passes.
pub fn eventually(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    loop {
        if check() {
            return true;
        }
        if start.elapsed() > timeout {
            return false;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}
