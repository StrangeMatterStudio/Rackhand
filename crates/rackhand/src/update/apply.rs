//! `rackhand update-apply <hub|relay|operator>` (7.5.7): the updater, run as root by `rackhand-updater.service` when a request
//! appears in the component's spool. It trusts nothing the unprivileged side wrote: it takes only the version from the request,
//! checks the release's signed manifest against its own pinned keys (the version must be the manifest's and the signature's
//! too), copies the release into the inactive slot and checks the copy against the manifest's hash and the file's own
//! signature, refuses a version that isn't newer than the installed one, and starts the guard. It answers in the spool and
//! removes the request either way.

use std::path::{Path, PathBuf};

use rackhand_release::binary::Version;
use rackhand_release::manifest;
use rackhand_release::slots::{Applied, ApplyError, Layout, Link, Request, apply, refuse};
use rackhand_release::{Pinned, PublicKey};

use super::request::{Answer, MAX_REQUEST, version_of};
use super::{ANSWER, Component, MANIFEST, MANIFEST_SIG, REQUEST, UPDATER, layout, prepare, spool, spool_dir};

/// A manifest lists a release's files: a few kilobytes.
const MAX_MANIFEST: u64 = 1 << 20;
const MAX_SIGNATURE: u64 = 4096;

/// Starts the guard as a unit of its own, and says whether one is still running.
pub trait Launcher {
    fn start(&self, unit: &str, guard: &Path, args: &[String]) -> Result<(), String>;
    fn running(&self, unit: &str) -> bool;
}

/// `systemd-run` transient units.
#[derive(Debug, Clone, Copy, Default)]
pub struct Systemd;

impl Launcher for Systemd {
    fn start(&self, unit: &str, guard: &Path, args: &[String]) -> Result<(), String> {
        let status = std::process::Command::new("systemd-run")
            .arg(format!("--unit={unit}"))
            .arg("--collect")
            .arg(guard)
            .arg("update-guard")
            .args(args)
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() { Ok(()) } else { Err(format!("systemd-run failed ({status})")) }
    }

    fn running(&self, unit: &str) -> bool {
        std::process::Command::new("systemctl").args(["is-active", "--quiet", unit]).status().is_ok_and(|s| s.success())
    }
}

/// The checks, the copy and the guard's start.
fn checked(
    root: &Path,
    component: Component,
    installed: Version,
    keys: &[(Pinned, PublicKey)],
    launcher: &dyn Launcher,
) -> Result<(Version, Applied), (Option<Version>, ApplyError)> {
    let layout = layout(root, component);
    if launcher.running(&component.guard_unit()) {
        return Err((None, refuse("update_in_progress", "an update is being switched in")));
    }
    prepare(root).map_err(|e| (None, refuse("layout", format!("the slots: {e}"))))?;
    let version =
        version_of(&layout.read_spool(REQUEST, MAX_REQUEST).map_err(|e| (None, e))?).map_err(|e| (None, e))?;
    let fail = |e: ApplyError| (Some(version), e);
    let bytes = layout.read_spool(MANIFEST, MAX_MANIFEST).map_err(fail)?;
    let sig = String::from_utf8(layout.read_spool(MANIFEST_SIG, MAX_SIGNATURE).map_err(fail)?)
        .map_err(|_| fail(refuse("bad_signature", "the manifest's signature isn't text")))?;
    let (_, manifest) =
        manifest::verify_signed_with(&bytes, &sig, keys).map_err(|e| fail(refuse("bad_signature", e.to_string())))?;
    if Version::parse(&manifest.version) != Some(version) {
        return Err(fail(refuse(
            "version_mismatch",
            format!("the request says {version} and the signed manifest says {}", manifest.version),
        )));
    }
    let entry = manifest
        .artifacts
        .iter()
        .find(|a| a.name == layout.artifact)
        .ok_or_else(|| fail(refuse("bad_request", format!("the release has no {}", layout.artifact))))?;
    let minisig = layout.read_spool(&format!("{}.minisig", layout.spool_file), MAX_SIGNATURE).map_err(fail)?;
    let request = Request {
        version: version.to_string(),
        sha256: entry.sha256.clone(),
        signature: data_encoding::BASE64.encode(&minisig),
    };
    let applied = apply(&layout, &Link, installed, &request, keys).map_err(fail)?;
    Ok((version, applied))
}

/// The guard is a copy of the running, known-good binary in root's own directory, so a broken new version can't stop the way
/// back.
fn start_guard(
    root: &Path,
    component: Component,
    layout: &Layout,
    applied: &Applied,
    launcher: &dyn Launcher,
) -> Result<(), ApplyError> {
    use std::os::unix::fs::PermissionsExt;
    let dir = root.join(UPDATER);
    std::fs::create_dir_all(&dir).map_err(|e| refuse("guard_failed", format!("{}: {e}", dir.display())))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| refuse("guard_failed", e.to_string()))?;
    let guard: PathBuf = dir.join(format!("update-guard-{}", component.name()));
    std::fs::read(layout.slot(applied.old))
        .and_then(|bytes| Layout::replace(&guard, &bytes, 0o700))
        .map_err(|e| refuse("guard_failed", format!("the guard's copy of the running binary: {e}")))?;
    let args = [
        component.name().to_string(),
        layout.slot_name(applied.old).to_string(),
        layout.slot_name(applied.new).to_string(),
        applied.version.to_string(),
    ];
    launcher.start(&component.guard_unit(), &guard, &args).map_err(|e| refuse("guard_failed", e))
}

/// Handles the request in `component`'s spool: the answer is written there and the request removed, whatever happened.
pub fn run(
    root: &Path,
    component: Component,
    installed: Version,
    keys: &[(Pinned, PublicKey)],
    launcher: &dyn Launcher,
    now_ms: i64,
) -> Answer {
    let (answer, started) = match checked(root, component, installed, keys, launcher) {
        Ok((version, applied)) => (
            Answer {
                ok: true,
                version: Some(version.to_string()),
                code: "started".into(),
                message: format!("{} is in its slot; the guard switches to it", applied.version),
                at_ms: now_ms,
            },
            Some(applied),
        ),
        Err((version, e)) => (
            Answer {
                ok: false,
                version: version.map(|v| v.to_string()),
                code: e.code.into(),
                message: e.message,
                at_ms: now_ms,
            },
            None,
        ),
    };
    let spool = spool_dir(component);
    let write = |answer: &Answer| {
        let text = serde_json::to_string(answer).unwrap_or_default();
        if let Err(e) = spool::write_in(root, &spool, ANSWER, text.as_bytes()) {
            tracing::warn!(error = %e, "writing the update's answer");
        }
    };
    // the answer is there before the guard starts: the new version reads it when it comes up
    write(&answer);
    if let Err(e) = spool::remove_in(root, &spool, REQUEST) {
        tracing::warn!(error = %e, "removing the update's request");
    }
    if let Some(applied) = started {
        if let Err(e) = start_guard(root, component, &layout(root, component), &applied, launcher) {
            let failed = Answer { ok: false, code: e.code.into(), message: e.message, ..answer };
            write(&failed);
            return failed;
        }
    }
    answer
}

/// `rackhand update-apply <component>`.
pub fn main(args: &[&str]) -> std::process::ExitCode {
    let Some(component) = args.first().and_then(|c| Component::parse(c)).filter(|_| args.len() == 1) else {
        eprintln!("usage: rackhand update-apply hub|relay|operator");
        return std::process::ExitCode::from(2);
    };
    if !rustix::process::geteuid().is_root() {
        eprintln!("rackhand update-apply: needs root (it runs as the updater unit)");
        return std::process::ExitCode::from(1);
    }
    let installed = Version::parse(crate::VERSION).unwrap_or(Version(0, 0, 0));
    let answer =
        run(Path::new("/"), component, installed, &rackhand_release::pinned(), &Systemd, rackhand_store::ids::now_ms());
    println!("{}", serde_json::to_string(&answer).unwrap_or_default());
    if answer.ok { std::process::ExitCode::SUCCESS } else { std::process::ExitCode::from(1) }
}
