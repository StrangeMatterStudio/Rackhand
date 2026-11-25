//! The hub's SSH test after a managed machine's first report (7.3.12, AC35): it logs in as `rackhand` and runs `true`
//! and, unless the machine has role hub (D62), as `rackhand-ai` and runs `sudo -n true`, with the host key pinned from
//! the join. A failure names the account. A machine is tested when its probe connects after a join, and from then on
//! about once a minute while it reports, until a test passes. A managed machine stays `pending` from its join until a test passes (D84).

use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rackhand_store::Db;

use super::client::{Output, SshError, run};
use super::hostkeys::HostKeys;
use super::keys::{Identity, load_or_create};
use crate::vault::Vault;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The event kinds a test records on the machine.
pub const PASSED: &str = "machine.ssh_test_passed";
pub const FAILED: &str = "machine.ssh_test_failed";

/// How long one login and its command may take.
const LOGIN_TIMEOUT: Duration = Duration::from_secs(30);
const SSH_PORT: u16 = 22;

/// One login as `id` running `command` on the machine at `addr`.
pub trait Login: Send + Sync {
    fn run<'a>(
        &'a self,
        addr: SocketAddr,
        machine_id: &'a str,
        id: Identity,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Output, SshError>>;
}

/// Logins with the hub's keys from the Vault and the host keys pinned at join.
#[derive(Debug)]
pub struct Pinned {
    pub vault: Arc<Vault>,
    pub host_keys: Arc<HostKeys>,
}

impl Login for Pinned {
    fn run<'a>(
        &'a self,
        addr: SocketAddr,
        machine_id: &'a str,
        id: Identity,
        command: &'a str,
    ) -> BoxFuture<'a, Result<Output, SshError>> {
        Box::pin(async move {
            let key = load_or_create(&self.vault, id).await.map_err(|e| SshError::Transport(e.to_string()))?;
            run(addr, machine_id, self.host_keys.clone(), id, &key, command, LOGIN_TIMEOUT).await
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Passed,
    Failed { account: &'static str, reason: String },
}

/// What the test needs from the machine's row.
struct Target {
    managed: bool,
    hub_role: bool,
    address: Option<String>,
}

pub struct EnrollTest {
    db: Arc<Db>,
    login: Arc<dyn Login>,
    /// Machines that joined since their last test.
    joined: Mutex<HashSet<String>>,
    /// Machines being tested now.
    testing: Mutex<HashSet<String>>,
}

/// A machine's test in progress, until its result is recorded; the machine can be tested again once it is dropped.
#[derive(Debug)]
pub struct Testing<'a> {
    set: &'a Mutex<HashSet<String>>,
    machine: &'a str,
}

impl Drop for Testing<'_> {
    fn drop(&mut self) {
        self.set.lock().unwrap_or_else(|e| e.into_inner()).remove(self.machine);
    }
}

impl std::fmt::Debug for EnrollTest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnrollTest").finish_non_exhaustive()
    }
}

/// The logins the test makes, in order.
fn logins(hub_role: bool) -> Vec<(Identity, &'static str)> {
    let mut l = vec![(Identity::Automation, "true")];
    if !hub_role {
        l.push((Identity::Assistant, "sudo -n true"));
    }
    l
}

fn addr(address: &str) -> Option<SocketAddr> {
    address
        .parse::<SocketAddr>()
        .ok()
        .or_else(|| address.parse::<IpAddr>().ok().map(|ip| SocketAddr::new(ip, SSH_PORT)))
}

fn judged(id: Identity, command: &str, result: Result<Output, SshError>) -> Option<Outcome> {
    let reason = match result {
        Ok(out) if out.exit_code == Some(0) => return None,
        Ok(out) => {
            let status = out.exit_code.map_or_else(|| "no exit status".to_string(), |c| format!("exit {c}"));
            let said = String::from_utf8_lossy(&out.stderr).trim().chars().take(200).collect::<String>();
            if said.is_empty() { format!("`{command}`: {status}") } else { format!("`{command}`: {status}: {said}") }
        }
        Err(e) => e.to_string(),
    };
    Some(Outcome::Failed { account: id.user(), reason })
}

impl EnrollTest {
    pub fn new(db: Arc<Db>, login: Arc<dyn Login>) -> EnrollTest {
        EnrollTest { db, login, joined: Mutex::default(), testing: Mutex::default() }
    }

    /// A machine joined (or joined again): its next report is tested.
    pub fn joined(&self, machine_id: &str) {
        if let Ok(mut j) = self.joined.lock() {
            j.insert(machine_id.to_string());
        }
    }

    fn target(&self, machine_id: &str) -> Option<Target> {
        use rusqlite::OptionalExtension;
        self.db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT access = 'managed', EXISTS (SELECT 1 FROM json_each(roles) WHERE value = 'hub'), address
                     FROM machines WHERE id = ?1 AND state IN ('pending', 'enrolled')",
                    [machine_id],
                    |r| Ok(Target { managed: r.get(0)?, hub_role: r.get(1)?, address: r.get(2)? }),
                )
                .optional()
            })
            .ok()
            .flatten()
    }

    fn last_passed(&self, machine_id: &str) -> bool {
        use rusqlite::OptionalExtension;
        let last: Option<String> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT kind FROM events WHERE machine_id = ?1 AND kind IN (?2, ?3) ORDER BY at_ms DESC LIMIT 1",
                    [machine_id, PASSED, FAILED],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten();
        last.as_deref() == Some(PASSED)
    }

    /// Whether the machine's report now should be followed by a test: a managed machine that joined since its last
    /// test, or whose last test didn't pass.
    pub fn due(&self, machine_id: &str) -> bool {
        if !self.target(machine_id).is_some_and(|t| t.managed) {
            return false;
        }
        let just_joined = self.joined.lock().map(|mut j| j.remove(machine_id)).unwrap_or(false);
        just_joined || !self.last_passed(machine_id)
    }

    /// The managed machines whose last test didn't pass (or that were never tested), to try again while they report.
    pub fn waiting(&self) -> Vec<String> {
        let all: Vec<String> = self
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT id FROM machines WHERE access = 'managed' AND state IN ('pending', 'enrolled')
                       AND (driver IS NULL OR probe_endpoint_id IS NOT NULL)",
                )?;
                s.query_map([], |r| r.get(0))?.collect()
            })
            .unwrap_or_default();
        all.into_iter().filter(|m| !self.last_passed(m)).collect()
    }

    /// Whether `outcome` is the failure the machine's last test already recorded.
    pub fn already_recorded(&self, machine_id: &str, outcome: &Outcome) -> bool {
        use rusqlite::OptionalExtension;
        let Outcome::Failed { account, reason } = outcome else { return false };
        let last: Option<(String, Option<String>, Option<String>)> = self
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT kind, json_extract(data, '$.account'), json_extract(data, '$.reason') FROM events
                     WHERE machine_id = ?1 AND kind IN (?2, ?3) ORDER BY at_ms DESC LIMIT 1",
                    [machine_id, PASSED, FAILED],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        last.is_some_and(|(k, a, r)| k == FAILED && a.as_deref() == Some(*account) && r.as_deref() == Some(reason))
    }

    /// The machine passed its test: a pending machine is enrolled (D84).
    pub async fn passed(&self, machine_id: &str) -> Result<(), rackhand_store::StoreError> {
        use rusqlite::OptionalExtension;
        let state: Option<String> = self
            .db
            .readers()
            .with(|c| c.query_row("SELECT state FROM machines WHERE id = ?1", [machine_id], |r| r.get(0)).optional())?;
        if state.as_deref() != Some("pending") {
            return Ok(());
        }
        let update = rackhand_store::RowUpdate {
            table: "machines",
            key: ("id", rusqlite::types::Value::Text(machine_id.into())),
            set: [("state", rusqlite::types::Value::Text("enrolled".into()))].into_iter().collect(),
        };
        let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
        self.db.writer().send(rackhand_store::WriteCmd::RegistryChange(change)).await?;
        Ok(())
    }

    /// Tests the machine; none for a machine that isn't managed, or that is being tested already.
    pub async fn run(&self, machine_id: &str) -> Option<Outcome> {
        let _testing = self.begin(machine_id)?;
        self.test(machine_id).await
    }

    /// Holds the machine for one test and the recording of its result; none while another holds it.
    pub fn begin<'a>(&'a self, machine_id: &'a str) -> Option<Testing<'a>> {
        if !self.testing.lock().unwrap_or_else(|e| e.into_inner()).insert(machine_id.to_string()) {
            return None;
        }
        Some(Testing { set: &self.testing, machine: machine_id })
    }

    /// The test itself, for a machine [`begin`](Self::begin) holds; none for a machine that isn't managed.
    pub async fn test(&self, machine_id: &str) -> Option<Outcome> {
        // this is the test that follows the join
        self.joined.lock().unwrap_or_else(|e| e.into_inner()).remove(machine_id);
        let target = self.target(machine_id).filter(|t| t.managed)?;
        let Some(addr) = target.address.as_deref().and_then(addr) else {
            let reason = "the machine has no address the hub can reach (it joined through a relay)".to_string();
            return Some(Outcome::Failed { account: Identity::Automation.user(), reason });
        };
        for (id, command) in logins(target.hub_role) {
            let result = self.login.run(addr, machine_id, id, command).await;
            if let Some(failed) = judged(id, command, result) {
                return Some(failed);
            }
        }
        Some(Outcome::Passed)
    }
}
