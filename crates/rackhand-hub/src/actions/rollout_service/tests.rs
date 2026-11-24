use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use ed25519_dalek::SigningKey;
use rackhand_release::manifest::{Channel, Manifest};
use rackhand_release::signing::sign;

use super::*;

/// The test keys the hub's tests pin: the current one is seed 0x11, id 1.
fn sign_as(signer: u8, key_id: [u8; 8], data: &[u8], comment: &str) -> String {
    sign(&SigningKey::from_bytes(&[signer; 32]), key_id, data, comment)
}

struct Dir(PathBuf);

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A release directory as `cargo xtask release build` and the maintainer's signing leave it.
fn release_dir(name: &str, version: &str, channel: Channel, manifest_signer: (u8, [u8; 8])) -> Dir {
    let dir = std::env::temp_dir().join(format!("rackhand-releases-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let files: [(&str, &[u8]); 4] = [
        ("install.sh", b"#!/bin/sh\n"),
        ("rackhand-x86_64-unknown-linux-musl", b"the hub"),
        ("rackhand-probe-x86_64-unknown-linux-musl", b"the probe for x86_64"),
        ("rackhand-probe-aarch64-unknown-linux-musl", b"the probe for aarch64"),
    ];
    for (file, bytes) in files {
        std::fs::write(dir.join(file), bytes).unwrap();
        let sig = sign_as(0x11, [1; 8], bytes, &format!("file:{file} version:{version}"));
        std::fs::write(dir.join(format!("{file}.minisig")), sig).unwrap();
    }
    let manifest = Manifest::of_dir(version, &dir).unwrap().with_channel(channel).to_json();
    std::fs::write(dir.join("manifest.json"), &manifest).unwrap();
    let sig = sign_as(
        manifest_signer.0,
        manifest_signer.1,
        manifest.as_bytes(),
        &format!("file:manifest.json version:{version}"),
    );
    std::fs::write(dir.join("manifest.json.minisig"), sig).unwrap();
    Dir(dir)
}

#[test]
fn the_probe_files_of_a_signed_release_are_read_with_their_signatures() {
    let dir = release_dir("read", "0.1.4", Channel::Beta, (0x11, [1; 8]));
    let release = read_release(&dir.0).unwrap();
    assert_eq!(release.version.to_string(), "0.1.4");
    assert_eq!(release.channel, Channel::Beta);
    let names: Vec<&str> = release.artifacts.keys().map(String::as_str).collect();
    assert_eq!(names, ["rackhand-probe-aarch64-unknown-linux-musl", "rackhand-probe-x86_64-unknown-linux-musl"]);
    let x86 = &release.artifacts["rackhand-probe-x86_64-unknown-linux-musl"];
    use sha2::{Digest, Sha256};
    assert_eq!(x86.sha256.to_vec(), Sha256::digest(b"the probe for x86_64").to_vec());
    assert_eq!(x86.signature, std::fs::read(dir.0.join("rackhand-probe-x86_64-unknown-linux-musl.minisig")).unwrap());
}

#[test]
fn a_manifest_that_isnt_signed_by_a_pinned_key_offers_nothing() {
    let dir = release_dir("badkey", "0.1.4", Channel::Stable, (0x33, [3; 8]));
    assert!(read_release(&dir.0).unwrap_err().contains("pinned"));
    let dir = release_dir("nosig", "0.1.4", Channel::Stable, (0x11, [1; 8]));
    std::fs::remove_file(dir.0.join("manifest.json.minisig")).unwrap();
    assert!(read_release(&dir.0).is_err());
    let dir = release_dir("changed", "0.1.4", Channel::Stable, (0x11, [1; 8]));
    // changed after it was signed
    let text = std::fs::read_to_string(dir.0.join("manifest.json")).unwrap().replace("0.1.4", "9.9.9");
    std::fs::write(dir.0.join("manifest.json"), text).unwrap();
    assert!(read_release(&dir.0).is_err());
    assert!(read_release(&PathBuf::from("/nonexistent/release")).is_err());
}

#[test]
fn a_probe_file_that_isnt_the_one_the_manifest_lists_is_left_out() {
    let dir = release_dir("tampered", "0.1.4", Channel::Stable, (0x11, [1; 8]));
    std::fs::write(dir.0.join("rackhand-probe-x86_64-unknown-linux-musl"), b"something else").unwrap();
    std::fs::remove_file(dir.0.join("rackhand-probe-aarch64-unknown-linux-musl.minisig")).unwrap();
    let release = read_release(&dir.0).unwrap();
    assert!(release.artifacts.is_empty(), "{:?}", release.artifacts.keys().collect::<Vec<_>>());
    // a signature too big to be one
    let dir = release_dir("bigsig", "0.1.4", Channel::Stable, (0x11, [1; 8]));
    std::fs::write(dir.0.join("rackhand-probe-x86_64-unknown-linux-musl.minisig"), vec![b'a'; 4096]).unwrap();
    assert_eq!(read_release(&dir.0).unwrap().artifacts.len(), 1);
}

#[test]
fn the_release_in_a_directory_is_read_again_when_its_manifest_changes() {
    let dir = release_dir("cache", "0.1.4", Channel::Stable, (0x11, [1; 8]));
    let releases = FsReleases::new(dir.0.clone());
    assert_eq!(releases.current().unwrap().version.to_string(), "0.1.4");
    assert_eq!(releases.current().unwrap().version.to_string(), "0.1.4");
    let newer = release_dir("cache2", "0.1.10", Channel::Stable, (0x11, [1; 8]));
    for f in std::fs::read_dir(&newer.0).unwrap() {
        let f = f.unwrap();
        std::fs::copy(f.path(), dir.0.join(f.file_name())).unwrap();
    }
    assert_eq!(releases.current().unwrap().version.to_string(), "0.1.10");
    std::fs::remove_file(dir.0.join("manifest.json")).unwrap();
    assert!(releases.current().is_none(), "no manifest, no release");
}

#[derive(Debug, Default)]
struct Log {
    offers: Vec<(String, String)>,
    saved: Vec<ScheduleState>,
    events: Vec<(String, String)>,
}

#[derive(Debug)]
struct FakeFleet {
    probes: Mutex<Vec<Probe>>,
    log: Mutex<Log>,
    incident: Mutex<bool>,
}

#[async_trait::async_trait]
impl Fleet for FakeFleet {
    fn probes(&self) -> Vec<Probe> {
        self.probes.lock().unwrap().clone()
    }

    fn incident_since(&self, _machine: &str, _since_ms: i64) -> bool {
        *self.incident.lock().unwrap()
    }

    async fn offer(&self, machine: &str, update: UpdateAvailable) -> bool {
        self.log.lock().unwrap().offers.push((machine.to_string(), update.url));
        machine != "gone"
    }

    async fn save(&self, rows: Vec<ScheduleState>) {
        self.log.lock().unwrap().saved.extend(rows);
    }

    async fn say(&self, event: &RolloutEvent) {
        self.log.lock().unwrap().events.push((event.kind.to_string(), event.machine.clone()));
    }
}

#[derive(Debug)]
struct Fixed(Option<Release>);

impl Releases for Fixed {
    fn current(&self) -> Option<Release> {
        self.0.clone()
    }
}

fn probe(machine: &str, version: &str) -> Probe {
    Probe {
        machine: machine.into(),
        site: "S".into(),
        version: Version::parse(version).unwrap(),
        arch: "x86_64".into(),
        connected: true,
    }
}

fn release() -> Release {
    let mut artifacts = std::collections::BTreeMap::new();
    artifacts.insert(
        "rackhand-probe-x86_64-unknown-linux-musl".to_string(),
        ReleaseFile { sha256: [1; 32], signature: b"sig".to_vec() },
    );
    Release { version: Version::parse("0.1.1").unwrap(), channel: Channel::Stable, artifacts }
}

const HOUR: i64 = 3_600_000;

fn service(fleet: &Arc<FakeFleet>, release: Option<Release>, saved: &[ScheduleState]) -> RolloutService {
    RolloutService::new(
        Version::parse("0.1.1").unwrap(),
        Arc::new(|| Channel::Stable),
        saved,
        fleet.clone(),
        Arc::new(Fixed(release)),
        Arc::new(|| Some("https://192.0.2.10:8443".to_string())),
    )
}

#[tokio::test]
async fn the_service_sends_the_offers_saves_the_rows_and_says_what_happened() {
    let fleet = Arc::new(FakeFleet {
        probes: Mutex::new(vec![probe("a", "0.1.0"), probe("b", "0.1.0")]),
        log: Mutex::default(),
        incident: Mutex::new(false),
    });
    let service = service(&fleet, Some(release()), &[]);
    assert_eq!(service.tick(1_000 * HOUR).await, 1, "the canary");
    {
        let log = fleet.log.lock().unwrap();
        assert_eq!(
            log.offers,
            [("a".to_string(), "https://192.0.2.10:8443/release/rackhand-probe-x86_64-unknown-linux-musl".to_string())]
        );
        let kept: Vec<&str> = log.saved.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kept, ["probe_rollout", "probe_update_offered"], "the canary, and what it was offered");
    }
    assert_eq!(service.tick(1_000 * HOUR + 60_000).await, 0, "once");
    // a updated, and had an incident since: the rest are held, and it is said
    *fleet.probes.lock().unwrap() = vec![probe("a", "0.1.1"), probe("b", "0.1.0")];
    *fleet.incident.lock().unwrap() = true;
    assert_eq!(service.tick(1_000 * HOUR + 61 * 60_000).await, 0);
    let log = fleet.log.lock().unwrap();
    assert_eq!(log.events, [("rollout.held".to_string(), "a".to_string())]);
    assert_eq!(log.saved.last().map(|r| r.kind.as_str()), Some("probe_rollout_held"), "the hold is kept too");
}

#[tokio::test]
async fn an_offer_that_didnt_reach_its_probe_isnt_counted() {
    let fleet = Arc::new(FakeFleet {
        probes: Mutex::new(vec![probe("gone", "0.1.0")]),
        log: Mutex::default(),
        incident: Mutex::new(false),
    });
    assert_eq!(service(&fleet, Some(release()), &[]).tick(1_000 * HOUR).await, 0);
    assert_eq!(fleet.log.lock().unwrap().offers.len(), 1, "it was tried");
}

#[tokio::test]
async fn nothing_is_offered_without_a_release_or_an_address() {
    let fleet = Arc::new(FakeFleet {
        probes: Mutex::new(vec![probe("a", "0.1.0")]),
        log: Mutex::default(),
        incident: Mutex::new(false),
    });
    assert_eq!(service(&fleet, None, &[]).tick(1_000 * HOUR).await, 0);
    let no_address = RolloutService::new(
        Version::parse("0.1.1").unwrap(),
        Arc::new(|| Channel::Stable),
        &[],
        fleet.clone(),
        Arc::new(Fixed(Some(release()))),
        Arc::new(|| None),
    );
    assert_eq!(no_address.tick(1_000 * HOUR).await, 0);
    assert!(fleet.log.lock().unwrap().offers.is_empty());
}

#[tokio::test]
async fn a_service_started_after_a_restart_goes_on_with_the_saved_rows() {
    let fleet = Arc::new(FakeFleet {
        probes: Mutex::new(vec![probe("a", "0.1.0"), probe("b", "0.1.0"), probe("c", "0.1.0")]),
        log: Mutex::default(),
        incident: Mutex::new(false),
    });
    let t0 = 1_000 * HOUR;
    service(&fleet, Some(release()), &[]).tick(t0).await;
    let saved = fleet.log.lock().unwrap().saved.clone();
    *fleet.probes.lock().unwrap() = vec![probe("a", "0.1.1"), probe("b", "0.1.0"), probe("c", "0.1.0")];
    let after = service(&fleet, Some(release()), &saved);
    assert_eq!(after.tick(t0 + 30 * 60_000).await, 0, "not yet");
    assert_eq!(after.tick(t0 + 61 * 60_000).await, 2, "b and c, an hour after a was offered it");
}

#[test]
fn only_enrolled_linux_machines_with_a_probe_are_updated_and_incidents_are_found_by_machine_and_time() {
    let dir = std::env::temp_dir().join(format!("rackhand-rollout-fleet-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    let db = Db::open(&path).unwrap();
    {
        let c = rusqlite::Connection::open(&path).unwrap();
        c.execute("INSERT INTO sites (id, name, timezone, is_local) VALUES ('s', 'home', 'UTC', 1)", []).unwrap();
        for (id, kind, state, endpoint) in [
            ("m-linux", "linux", "enrolled", Some("e1")),
            ("m-alpine", "alpine", "enrolled", Some("e2")),
            ("m-windows", "windows", "enrolled", Some("e3")),
            ("m-pending", "linux", "pending", Some("e4")),
            ("m-noprobe", "linux", "enrolled", None),
            ("m-appliance", "appliance", "enrolled", Some("e5")),
        ] {
            c.execute(
                "INSERT INTO machines (id, site_id, name, kind, state, probe_endpoint_id) VALUES (?1, 's', ?1, ?2, ?3, ?4)",
                rusqlite::params![id, kind, state, endpoint],
            )
            .unwrap();
        }
        c.execute(
            "INSERT INTO incidents (id, machine_id, dedupe_key, kind, severity, state, title, opened_at)
             VALUES ('i1', 'm-linux', 'k', 'x', 'info', 'open', 't', 5000)",
            [],
        )
        .unwrap();
    }
    let mut machines: Vec<String> = updatable_machines(&db).into_iter().map(|(m, _)| m).collect();
    machines.sort();
    assert_eq!(machines, ["m-alpine", "m-linux"]);
    assert!(incident_opened_since(&db, "m-linux", 4999));
    assert!(!incident_opened_since(&db, "m-linux", 5000), "after, not at");
    assert!(!incident_opened_since(&db, "m-alpine", 0), "another machine's");
}

/// FR-22, 7.5.7: a probe is offered only the hub's own version, so a release put in the hub's directory before the hub itself
/// updates waits for it.
#[tokio::test]
async fn probes_are_offered_only_the_hubs_own_version() {
    let fleet = Arc::new(FakeFleet {
        probes: Mutex::new(vec![probe("a", "0.1.0")]),
        log: Mutex::default(),
        incident: Mutex::new(false),
    });
    let older_hub = RolloutService::new(
        Version::parse("0.1.0").unwrap(),
        Arc::new(|| Channel::Stable),
        &[],
        fleet.clone(),
        Arc::new(Fixed(Some(release()))),
        Arc::new(|| Some("https://192.0.2.10:8443".to_string())),
    );
    assert_eq!(older_hub.tick(1_000 * HOUR).await, 0, "the hub runs 0.1.0 and the release is 0.1.1");
    assert!(fleet.log.lock().unwrap().offers.is_empty());
    assert_eq!(service(&fleet, Some(release()), &[]).tick(1_000 * HOUR).await, 1, "a hub on 0.1.1 offers it");
}
