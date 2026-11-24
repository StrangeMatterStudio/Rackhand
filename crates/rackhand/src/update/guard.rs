//! `rackhand update-guard <component> <old-slot> <new-slot> <version>` (7.5.7): run by the updater as a transient unit, from
//! root's copy of the old, known-good binary. It switches the slot, restarts the component's unit and waits up to 2 minutes for
//! it to come up: the hub answering `https://127.0.0.1:<port>/healthz`, a relay or an operator staying active for 15 seconds.
//! If it doesn't, the guard stops it, puts the hub's database from before the update back (migrations are forward-only, and a
//! version that never came up wrote nothing worth keeping), records the rollback for the hub to audit, and switches back.

use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rackhand_release::binary::Version;
use rackhand_release::slots::{Env, Link, Outcome, Plan, guard};

use super::request::RolledBack;
use super::{Component, MANIFEST, MANIFEST_SIG, PRE_UPDATE_DB, ROLLED_BACK, layout, spool, spool_dir};

/// How long a relay or an operator must stay active to count as up.
const STABLE: Duration = Duration::from_secs(15);

/// `<component> <old-slot> <new-slot> <version>`.
pub fn parse_args(root: &Path, args: &[&str]) -> Result<(Component, Plan, Version), String> {
    let [component, old, new, version] = args else {
        return Err("update-guard <hub|relay|operator> <old-slot> <new-slot> <version>".into());
    };
    let component = Component::parse(component).ok_or_else(|| format!("`{component}` isn't a component"))?;
    let layout = layout(root, component);
    let slot = |name: &str| layout.slot_named(name).ok_or_else(|| format!("`{name}` isn't a slot"));
    let (old, new) = (slot(old)?, slot(new)?);
    if old == new {
        return Err("the old and the new slot are the same".into());
    }
    let version = Version::parse(version).ok_or("the version isn't x.y.z")?;
    Ok((component, Plan { layout, old, new }, version))
}

/// The hub's data directory relative to the root, and where it answers `/healthz`.
fn hub_paths(root: &Path) -> (PathBuf, u16) {
    let config = crate::hub_cmd::HubConfig::load(&root.join("etc/rackhand/hub.toml")).ok();
    let data = config.as_ref().map_or_else(|| PathBuf::from("/var/lib/rackhand"), |c| c.data_dir.clone());
    let rel = data.strip_prefix("/").map(Path::to_path_buf).unwrap_or(data);
    (rel, config.map_or(8443, |c| c.web.port()))
}

/// Puts the hub's database from before the update back, with the hub stopped: the copy in the spool (read without following
/// a link) replaces `hub.db`, and the new version's journal files go. Whether there was a copy to put back.
pub fn restore_database(root: &Path, data: &Path) -> std::io::Result<bool> {
    let spool = layout(root, Component::Hub);
    let Ok(mut copy) = spool.open_in_spool(PRE_UPDATE_DB, u64::MAX) else { return Ok(false) };
    for journal in ["hub.db-wal", "hub.db-shm"] {
        spool::remove_in(root, data, journal)?;
    }
    spool::write_from(root, data, "hub.db", &mut copy)?;
    Ok(true)
}

/// The machine's services, clock and the component's own sign of life.
struct Server {
    root: PathBuf,
    component: Component,
    started: Instant,
    started_ms: i64,
    from: Version,
    to: Version,
    first_active: Cell<Option<Instant>>,
}

impl Server {
    fn systemctl(&self, args: &[&str]) -> bool {
        std::process::Command::new("systemctl").args(args).status().is_ok_and(|s| s.success())
    }

    fn healthz(port: u16) -> bool {
        let Ok(rt) = tokio::runtime::Builder::new_current_thread().enable_all().build() else { return false };
        let mut body = Vec::new();
        let url = format!("https://127.0.0.1:{port}/healthz");
        let got = rt.block_on(rackhand_drivers::fetch::download(&url, 1024, Duration::from_secs(5), &mut body));
        got.is_ok() && String::from_utf8_lossy(&body).trim() == "ok"
    }
}

impl Env for Server {
    fn restart(&self) -> Result<(), String> {
        if self.systemctl(&["restart", self.component.unit()]) {
            Ok(())
        } else {
            Err(format!("couldn't restart {}", self.component.unit()))
        }
    }

    fn up(&self) -> bool {
        if self.component == Component::Hub {
            return Server::healthz(hub_paths(&self.root).1);
        }
        if !self.systemctl(&["is-active", "--quiet", self.component.unit()]) {
            self.first_active.set(None);
            return false;
        }
        let since = self.first_active.get().unwrap_or_else(Instant::now);
        self.first_active.set(Some(since));
        since.elapsed() >= STABLE
    }

    fn rolling_back(&self) {
        let mut restored = false;
        if self.component == Component::Hub {
            self.systemctl(&["stop", self.component.unit()]);
            let (data, _) = hub_paths(&self.root);
            match restore_database(&self.root, &data) {
                Ok(r) => restored = r,
                Err(e) => tracing::error!(error = %e, "putting the hub's database from before the update back"),
            }
        }
        let record = RolledBack {
            from: self.from.to_string(),
            to: self.to.to_string(),
            restored_database: restored,
            window_from_ms: self.started_ms,
            window_to_ms: rackhand_store::ids::now_ms(),
        };
        let text = serde_json::to_string(&record).unwrap_or_default();
        if let Err(e) = spool::write_in(&self.root, &spool_dir(self.component), ROLLED_BACK, text.as_bytes()) {
            tracing::error!(error = %e, "recording the rollback");
        }
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }

    fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// After a kept hub update: the release's manifest beside `hub.toml`, so the self-watch checks the binary against it, and no
/// copy of the old database left in the spool.
fn kept(root: &Path, component: Component) {
    if component != Component::Hub {
        return;
    }
    let spool = layout(root, component);
    for (from, to) in [(MANIFEST, "release-manifest.json"), (MANIFEST_SIG, "release-manifest.json.minisig")] {
        match spool.read_spool(from, 1 << 20) {
            Ok(bytes) => {
                let path = root.join("etc/rackhand").join(to);
                if let Err(e) = rackhand_release::slots::Layout::replace(&path, &bytes, 0o644) {
                    tracing::warn!(error = %e, path = %path.display(), "installing the release's manifest");
                }
            }
            Err(e) => tracing::warn!(error = %e, "the release's manifest"),
        }
    }
    let _ = spool::remove_in(root, &spool_dir(component), PRE_UPDATE_DB);
}

/// `rackhand update-guard ...`.
pub fn main(args: &[&str]) -> std::process::ExitCode {
    let root = Path::new("/");
    let (component, plan, to) = match parse_args(root, args) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("rackhand update-guard: {e}");
            return std::process::ExitCode::from(2);
        }
    };
    let from = Version::parse(crate::VERSION).unwrap_or(Version(0, 0, 0));
    let server = Server {
        root: root.to_path_buf(),
        component,
        started: Instant::now(),
        started_ms: rackhand_store::ids::now_ms(),
        from,
        to,
        first_active: Cell::new(None),
    };
    match guard(&plan, &Link, &server) {
        Outcome::Kept => {
            kept(root, component);
            std::process::ExitCode::SUCCESS
        }
        Outcome::RolledBack | Outcome::NotSwitched => std::process::ExitCode::from(1),
    }
}
