//! The hub's probe-update service (13, 7.3.3): once a minute it reads the release the hub holds, asks the rollout (see
//! `probe_rollout`) whom to offer it to, sends the offers to the connected probes, and remembers what the rollout says to
//! remember. The release is the signed manifest and the probe files in the hub's release directory (the one it serves at
//! `/release/<file>`), checked against the pinned release keys; the hub never offers what it couldn't verify itself.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rackhand_proto::probe::{HubToProbe, UpdateAvailable, hub_to_probe};
use rackhand_release::binary::Version;
use rackhand_release::manifest::{self, Manifest};
use rackhand_store::Db;

use super::probe_rollout::{Probe, Release, ReleaseFile, Rollout, RolloutEvent};
use crate::ingest::probe_server::ProbeServer;
use crate::ingest::{Event, Ingest, Severity};
use crate::scheduler::tasks::{ScheduleState, state_cmd};

/// A signature file is a few hundred bytes.
const MAX_SIGNATURE: usize = 1024;

pub trait Releases: Send + Sync + std::fmt::Debug {
    /// The release the hub holds, if there is one it can verify.
    fn current(&self) -> Option<Release>;
}

/// What a release's directory holds that this service offers: `manifest.json` and its signature, and for each architecture
/// the probe and its `.minisig`.
pub fn read_release(dir: &Path) -> Result<Release, String> {
    let manifest_path = dir.join(manifest::NAME);
    let bytes = std::fs::read(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
    let sig_path = dir.join(format!("{}.minisig", manifest::NAME));
    let sig = std::fs::read_to_string(&sig_path).map_err(|e| format!("{}: {e}", sig_path.display()))?;
    let (_, manifest): (_, Manifest) = manifest::verify_signed(&bytes, &sig).map_err(|e| e.to_string())?;
    let version = Version::parse(&manifest.version).ok_or("the manifest's version isn't x.y.z")?;
    let mut artifacts = std::collections::BTreeMap::new();
    for a in &manifest.artifacts {
        let Some(arch) =
            a.name.strip_prefix("rackhand-probe-").and_then(|rest| rest.strip_suffix("-unknown-linux-musl"))
        else {
            continue;
        };
        if Release::probe_file(arch) != a.name {
            continue;
        }
        let (Ok(file), Ok(signature)) =
            (std::fs::read(dir.join(&a.name)), std::fs::read(dir.join(format!("{}.minisig", a.name))))
        else {
            continue;
        };
        // a file that isn't the one the signed manifest lists, or a signature that is too big to be one, isn't offered
        if manifest.check(&a.name, &file).is_err() || signature.is_empty() || signature.len() > MAX_SIGNATURE {
            continue;
        }
        let Some(sha256) = hex_to_array(&a.sha256) else { continue };
        artifacts.insert(a.name.clone(), ReleaseFile { sha256, signature });
    }
    Ok(Release { version, channel: manifest.channel, artifacts })
}

fn hex_to_array(hex: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    if hex.len() != 64 {
        return None;
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(2 * i..2 * i + 2)?, 16).ok()?;
    }
    Some(out)
}

/// What was read the last time: the manifest's size and modified time, and the release found (or none).
type Cached = ((u64, std::time::SystemTime), Option<Release>);

/// The release in a directory, read again when its manifest changes.
#[derive(Debug)]
pub struct FsReleases {
    dir: PathBuf,
    cache: Mutex<Option<Cached>>,
}

impl FsReleases {
    pub fn new(dir: PathBuf) -> FsReleases {
        FsReleases { dir, cache: Mutex::new(None) }
    }
}

impl Releases for FsReleases {
    fn current(&self) -> Option<Release> {
        let meta = std::fs::metadata(self.dir.join(manifest::NAME)).ok()?;
        let stamp = (meta.len(), meta.modified().ok()?);
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((seen, release)) = cache.as_ref() {
            if *seen == stamp {
                return release.clone();
            }
        }
        let release = match read_release(&self.dir) {
            Ok(r) => Some(r),
            Err(e) => {
                tracing::warn!(error = %e, "the release in the hub's directory can't be offered to probes");
                None
            }
        };
        *cache = Some((stamp, release.clone()));
        release
    }
}

/// The hub's side of the fleet: who has a probe and what build it runs, who is connected, whether a machine had an
/// incident, and how to tell a probe, save the rollout's rows and raise its events.
#[async_trait::async_trait]
pub trait Fleet: Send + Sync + std::fmt::Debug {
    fn probes(&self) -> Vec<Probe>;
    fn incident_since(&self, machine: &str, since_ms: i64) -> bool;
    /// Whether the offer reached the probe's stream.
    async fn offer(&self, machine: &str, update: UpdateAvailable) -> bool;
    async fn save(&self, rows: Vec<ScheduleState>);
    async fn say(&self, event: &RolloutEvent);
}

pub struct RolloutService {
    rollout: Mutex<Rollout>,
    fleet: Arc<dyn Fleet>,
    releases: Arc<dyn Releases>,
    /// The hub's release channel now (a hub setting the admin can change).
    channel: Arc<dyn Fn() -> manifest::Channel + Send + Sync>,
    /// `https://<an address of this hub>:<port>`, where the hub serves `/release/<file>`; none until it knows one.
    base: Arc<dyn Fn() -> Option<String> + Send + Sync>,
}

impl std::fmt::Debug for RolloutService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RolloutService")
    }
}

impl RolloutService {
    pub fn new(
        channel: Arc<dyn Fn() -> manifest::Channel + Send + Sync>,
        saved: &[ScheduleState],
        fleet: Arc<dyn Fleet>,
        releases: Arc<dyn Releases>,
        base: Arc<dyn Fn() -> Option<String> + Send + Sync>,
    ) -> RolloutService {
        let mut rollout = Rollout::new(channel());
        rollout.restore(saved);
        RolloutService { rollout: Mutex::new(rollout), channel, fleet, releases, base }
    }

    /// One pass: returns how many offers were sent.
    pub async fn tick(&self, now_ms: i64) -> usize {
        let Some(release) = self.releases.current() else { return 0 };
        let Some(base) = (self.base)() else { return 0 };
        let probes = self.fleet.probes();
        let plan = {
            let mut rollout = self.rollout.lock().unwrap_or_else(|e| e.into_inner());
            rollout.set_channel((self.channel)());
            let fleet = &self.fleet;
            rollout.tick(now_ms, &release, &probes, &|machine, since| fleet.incident_since(machine, since), &|file| {
                format!("{base}/release/{file}")
            })
        };
        if !plan.saved.is_empty() {
            self.fleet.save(plan.saved).await;
        }
        for event in &plan.events {
            self.fleet.say(event).await;
        }
        let mut sent = 0;
        for offer in plan.offers {
            if self.fleet.offer(&offer.machine, offer.update).await {
                sent += 1;
            }
        }
        sent
    }
}

/// The real fleet: the database for machines and incidents, Ingest for what the probes' Hellos said, and the probe server's
/// streams.
pub struct HubFleet {
    pub db: Arc<Db>,
    pub ingest: Ingest,
    pub probes: ProbeServer,
}

impl std::fmt::Debug for HubFleet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HubFleet")
    }
}

/// The machines that update themselves: enrolled, with a probe, on Linux or Alpine (a Windows probe doesn't update itself
/// yet, and an appliance or a hypervisor has no probe of ours): machine id and site.
pub fn updatable_machines(db: &Db) -> Vec<(String, String)> {
    db.readers()
        .with(|c| {
            let mut stmt = c.prepare(
                "SELECT id, site_id FROM machines
                 WHERE state = 'enrolled' AND probe_endpoint_id IS NOT NULL AND kind IN ('linux', 'alpine')",
            )?;
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap_or_default()
}

/// Whether an incident, of any severity, opened on the machine after `since_ms`.
pub fn incident_opened_since(db: &Db, machine: &str, since_ms: i64) -> bool {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM incidents WHERE machine_id = ?1 AND opened_at > ?2)",
                rusqlite::params![machine, since_ms],
                |r| r.get::<_, bool>(0),
            )
        })
        .unwrap_or(false)
}

#[async_trait::async_trait]
impl Fleet for HubFleet {
    fn probes(&self) -> Vec<Probe> {
        let connected = self.probes.connected();
        updatable_machines(&self.db)
            .into_iter()
            .filter_map(|(machine, site)| {
                let (version, arch) = self.ingest.probe_build(&machine)?;
                let version = Version::parse(&version)?;
                Some(Probe { connected: connected.contains(&machine), machine, site, version, arch })
            })
            .collect()
    }

    fn incident_since(&self, machine: &str, since_ms: i64) -> bool {
        incident_opened_since(&self.db, machine, since_ms)
    }

    async fn offer(&self, machine: &str, update: UpdateAvailable) -> bool {
        self.probes.send_to(machine, HubToProbe { msg: Some(hub_to_probe::Msg::UpdateAvailable(update)) }).await
    }

    async fn save(&self, rows: Vec<ScheduleState>) {
        for row in rows {
            if let Err(e) = self.db.writer().send(state_cmd(&row)).await {
                tracing::warn!(error = %e, "keeping the probe rollout's state");
            }
        }
    }

    async fn say(&self, event: &RolloutEvent) {
        let data = serde_json::json!({
            "site": event.site,
            "machine_id": event.machine,
            "version": event.version.to_string(),
            "detail": event.detail,
        });
        let _ = self.ingest.raise_event(Event::machine(&event.machine, event.kind, Severity::Warning, data)).await;
    }
}

#[cfg(test)]
mod tests;
