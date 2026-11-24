//! One endpoint id, one machine (E6, 7.3.2): a VM cloned with the probe installed has the same node key as the original, so the
//! hub sees one endpoint id from two machines. They are told apart by the boot id each Hello carries. Two sessions of one endpoint id
//! with different boot ids, both reporting, is an `identity_conflict`: both are closed and refused until one re-enrolls, since the
//! hub can't tell which is the machine it enrolled. A reboot looks different: the old session is silent, so the new boot id takes
//! its place.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};

use iroh::EndpointId;
use tokio::sync::Notify;

/// A session that reported within this long is still the machine's: a different boot id beside it is another machine.
pub const ACTIVE_MS: i64 = 20_000;

#[derive(Debug)]
struct Live {
    session: u64,
    boot_id: String,
    last_ms: Arc<AtomicI64>,
    kill: Arc<Notify>,
}

#[derive(Debug, Default)]
struct State {
    live: HashMap<EndpointId, Vec<Live>>,
    conflicted: HashSet<EndpointId>,
    next: u64,
}

#[derive(Debug, Default)]
pub struct Identities {
    state: Mutex<State>,
}

/// What a Hello gets.
#[derive(Debug)]
pub enum Entry {
    Admitted(Session),
    /// Another machine uses this endpoint id: both are refused.
    Conflict,
}

/// An admitted session. Dropping it leaves.
#[derive(Debug)]
pub struct Session {
    id: u64,
    endpoint: EndpointId,
    activity: Arc<AtomicI64>,
    kill: Arc<Notify>,
    owner: Arc<Identities>,
}

impl Session {
    /// Notes that the session reported just now.
    pub fn touch(&self, now_ms: i64) {
        self.activity.store(now_ms, Ordering::Relaxed);
    }

    /// What `touch` is, for the tasks that read the session's streams.
    pub fn activity(&self) -> Arc<AtomicI64> {
        self.activity.clone()
    }

    /// Completes when the session must end: a conflict, or a newer boot of the machine.
    pub async fn killed(&self) {
        self.kill.notified().await;
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let mut state = self.owner.state();
        if let Some(list) = state.live.get_mut(&self.endpoint) {
            list.retain(|l| l.session != self.id);
            if list.is_empty() {
                state.live.remove(&self.endpoint);
            }
        }
    }
}

impl Identities {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// A Hello from `endpoint` with this boot id. A probe that doesn't say its boot id is never part of a conflict.
    pub fn enter(self: &Arc<Self>, endpoint: EndpointId, boot_id: &str, now_ms: i64) -> Entry {
        let mut state = self.state();
        if state.conflicted.contains(&endpoint) {
            return Entry::Conflict;
        }
        let mut conflict = false;
        let mut stale = Vec::new();
        for other in state.live.get(&endpoint).into_iter().flatten() {
            let different = !boot_id.is_empty() && !other.boot_id.is_empty() && other.boot_id != boot_id;
            if different {
                if now_ms - other.last_ms.load(Ordering::Relaxed) < ACTIVE_MS {
                    conflict = true;
                } else {
                    stale.push(other.session);
                }
            }
        }
        if conflict {
            state.conflicted.insert(endpoint);
            for other in state.live.remove(&endpoint).into_iter().flatten() {
                other.kill.notify_one();
            }
            return Entry::Conflict;
        }
        if let Some(list) = state.live.get_mut(&endpoint) {
            // a machine that booted again: what it said before the reboot has gone
            list.retain(|l| {
                let old = stale.contains(&l.session);
                if old {
                    l.kill.notify_one();
                }
                !old
            });
        }
        state.next += 1;
        let session = state.next;
        let (activity, kill) = (Arc::new(AtomicI64::new(now_ms)), Arc::new(Notify::new()));
        state.live.entry(endpoint).or_default().push(Live {
            session,
            boot_id: boot_id.to_string(),
            last_ms: activity.clone(),
            kill: kill.clone(),
        });
        Entry::Admitted(Session { id: session, endpoint, activity, kill, owner: self.clone() })
    }

    /// An endpoint id that re-enrolled (or was given up): it may connect again.
    pub fn clear(&self, endpoint: &EndpointId) {
        self.state().conflicted.remove(endpoint);
    }

    pub fn conflicted(&self, endpoint: &EndpointId) -> bool {
        self.state().conflicted.contains(endpoint)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    fn endpoint(n: u8) -> EndpointId {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    fn admitted(entry: Entry) -> Session {
        match entry {
            Entry::Admitted(s) => s,
            Entry::Conflict => panic!("expected to be admitted"),
        }
    }

    #[tokio::test]
    async fn same_endpoint_two_boot_ids_both_refused() {
        let ids = Arc::new(Identities::default());
        let e = endpoint(1);
        let original = admitted(ids.enter(e, "boot-a", 1_000));
        original.touch(10_000);
        // the clone says hello 5 s later, from another boot, while the original is reporting
        assert!(matches!(ids.enter(e, "boot-b", 15_000), Entry::Conflict));
        assert!(ids.conflicted(&e));
        // the original is told to go, and neither is let back in
        tokio::time::timeout(Duration::from_secs(1), original.killed()).await.expect("the original is closed too");
        assert!(matches!(ids.enter(e, "boot-a", 16_000), Entry::Conflict), "the original is refused");
        assert!(matches!(ids.enter(e, "boot-b", 16_000), Entry::Conflict), "and the clone");
        // another endpoint id is not affected
        assert!(matches!(ids.enter(endpoint(2), "boot-a", 16_000), Entry::Admitted(_)));
        // until one re-enrolls
        ids.clear(&e);
        assert!(matches!(ids.enter(e, "boot-b", 20_000), Entry::Admitted(_)));
    }

    #[tokio::test]
    async fn a_reboot_is_not_a_clone() {
        let ids = Arc::new(Identities::default());
        let e = endpoint(1);
        let before = admitted(ids.enter(e, "boot-a", 1_000));
        before.touch(5_000);
        // the machine rebooted hard: its old session went quiet, and is replaced by the new boot's
        let after = admitted(ids.enter(e, "boot-b", 5_000 + ACTIVE_MS + 1));
        tokio::time::timeout(Duration::from_secs(1), before.killed()).await.expect("the old session ends");
        assert!(!ids.conflicted(&e));
        // the same boot reconnecting is never a conflict, however busy it was
        after.touch(100_000);
        let again = admitted(ids.enter(e, "boot-b", 100_001));
        drop(after);
        drop(again);
        // a probe that doesn't say its boot id can't be told apart, so it isn't part of one
        let a = admitted(ids.enter(e, "", 200_000));
        a.touch(200_000);
        assert!(matches!(ids.enter(e, "boot-c", 200_001), Entry::Admitted(_)));
    }

    /// E43: a machine is its machine id and its endpoint id; what it is called and where it is don't matter to who it is,
    /// and the SSH host key pinned at its join is still the one that is checked, wherever it now answers.
    #[tokio::test(flavor = "multi_thread")]
    async fn rename_and_new_address_keep_machine_and_host_key_check() {
        use rackhand_store::{Db, RegistryChange, Row, RowUpdate, RowWrite, WriteCmd};
        use rusqlite::types::Value;

        use crate::ssh::hostkeys::{HostKeyError, HostKeys};
        use crate::ssh::keys::generate_ed25519;

        let dir = std::env::temp_dir().join(format!("rackhand-identity-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
        let t = |s: &str| Value::Text(s.into());
        let endpoint_id = endpoint(5).to_string();
        let machine = Row::from([
            ("id", t("01J1MACH1NE0000000000000AA")),
            ("site_id", t("s1")),
            ("name", t("web")),
            ("kind", t("linux")),
            ("address", t("192.0.2.10")),
            ("probe_endpoint_id", t(&endpoint_id)),
            ("state", t("enrolled")),
        ]);
        let site = Row::from([("id", t("s1")), ("name", t("home")), ("timezone", t("UTC"))]);
        db.writer()
            .send(WriteCmd::Batch(vec![RowWrite::insert("sites", site), RowWrite::insert("machines", machine)]))
            .await
            .unwrap();
        let (keys, _alerts) = HostKeys::new(db.clone());
        let (_, pinned) = generate_ed25519("host").unwrap();
        let (_, stranger) = generate_ed25519("host").unwrap();
        let id = "01J1MACH1NE0000000000000AA";
        keys.pin_from_join(id, std::slice::from_ref(&pinned), 1).await.unwrap();
        // renamed, and moved to another address (what the probe's report says)
        let set = Row::from([("name", t("web-2")), ("address", t("198.51.100.77"))]);
        let update = RowUpdate { table: "machines", key: ("id", t(id)), set };
        db.writer()
            .send(WriteCmd::RegistryChange(RegistryChange { updates: vec![update], ..Default::default() }))
            .await
            .unwrap();
        let (name, address, endpoint, found): (String, String, String, String) = db
            .readers()
            .with(|c| {
                c.query_row("SELECT name, address, probe_endpoint_id, id FROM machines", [], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })
            })
            .unwrap();
        assert_eq!(
            (name.as_str(), address.as_str(), endpoint.as_str(), found.as_str()),
            ("web-2", "198.51.100.77", endpoint_id.as_str(), id)
        );
        // the host key check follows the machine, not its name or address
        assert_eq!(keys.check(id, &pinned), Ok(()));
        assert_eq!(
            keys.check(id, &stranger),
            Err(HostKeyError::Changed),
            "another host answering at the new address is refused"
        );
    }
}
