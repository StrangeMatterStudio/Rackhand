//! What a join hands the other systems (7.3.1, 7.3.7): a managed machine's keys, sudoers and first command list, its
//! host keys pinned in SSH, the hub's SSH test after its first report (7.3.12), and the host key and mirror alerts
//! raised as events through Ingest (7.3.8).

use std::sync::{Arc, Mutex};

use prost::Message;
use rackhand_hub::ingest::Ingest;
use rackhand_hub::ingest::{Event, Severity};
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::library::mirror::MirrorAlert;
use rackhand_hub::registry::Registry;
use rackhand_hub::registry::join_server::{HubInfo, JoinServer, Joined, ManagedSetupSource};
use rackhand_hub::registry::tokens::TokenKind;
use rackhand_hub::ssh::enroll_test::{self, EnrollTest, Outcome};
use rackhand_hub::ssh::hostkeys::{HostKeyAlert, HostKeys};
use rackhand_net::router::Handler;
use rackhand_proto::common::ProbeConfig;
use rackhand_proto::common::SignedPayload;
use rackhand_proto::join::ManagedSetup;
use rackhand_store::Db;
use rackhand_store::ids::now_ms;
use tokio::sync::mpsc::{UnboundedReceiver, UnboundedSender};

/// The automation user's one sudo entry: the command wrapper (7.3.7).
pub const SUDOERS: &str = "rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run\n";
/// The assistant's sudo (7.3.7): everything, with every session's input and output logged.
pub const ASSISTANT_SUDOERS: &str =
    "Defaults:rackhand-ai log_output, iolog_dir=/var/log/rackhand/sudo-io\nrackhand-ai ALL=(ALL) NOPASSWD: ALL\n";
/// How long the command list in a join response stays valid: the installer applies it right away.
const JOIN_COMMANDS_TTL_MS: i64 = 3_600_000;

/// The managed setup from the hub's SSH keys and node key, with the command list of the current runbooks.
pub struct HubSetup {
    pub db: Arc<Db>,
    pub automation: String,
    pub assistant: String,
    pub signing: ed25519_dalek::SigningKey,
}

impl std::fmt::Debug for HubSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HubSetup").finish_non_exhaustive()
    }
}

/// The runbooks enabled now: every runbook in the Library that parses.
pub fn enabled_runbooks(db: &Db) -> Vec<rackhand_runbook::runbook::Runbook> {
    Library::all_current(db)
        .unwrap_or_default()
        .into_iter()
        .filter(|(kind, _, _)| *kind == Kind::Runbook)
        .filter_map(|(_, _, text)| rackhand_runbook::runbook::Runbook::parse(&text).ok())
        .collect()
}

/// How long a command list sent by `sudoers-refresh` stays valid: it is installed at once.
const REFRESH_COMMANDS_TTL_MS: i64 = 600_000;

/// What the hub signs for `sudoers-refresh` and `keys-rotate`: the command list of the enabled runbooks and key updates,
/// with the node key.
pub struct CommandSigner {
    pub db: Arc<Db>,
    pub signing: ed25519_dalek::SigningKey,
    /// The endpoint's id and addresses, set when it is bound.
    pub addrs: Arc<std::sync::OnceLock<(String, HubAddrs)>>,
    /// What `unenroll` revokes machines through.
    pub registry: Arc<rackhand_hub::registry::Registry>,
    pub provisioning: Provisioning,
}

/// What `provision-vm` and `provision-lxc` need beyond the registry (T64).
#[derive(Default)]
pub struct Provisioning {
    /// Reads a hypervisor's node, for the binding.
    pub hosts: Option<Arc<dyn rackhand_hub::actions::patching::hypervisor::Hosts>>,
    /// The hypervisors' API, for a quarantined guest's firewall and its forensic snapshot (7.5.6).
    pub hypervisor: Option<Arc<rackhand_hub::checks::steps::Hypervisor>>,
    /// The release the hub holds; a guest takes its installer from the hub then, not from GitHub.
    pub release_dir: Option<std::path::PathBuf>,
    /// The dashboard's port, for the installer's address (8443 when not set).
    pub web_port: u16,
    /// The token of the machine each job made, until the guest has its enrollment.
    pub made: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

impl std::fmt::Debug for Provisioning {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Provisioning").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for CommandSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandSigner").finish_non_exhaustive()
    }
}

impl rackhand_hub::executor::HubSide for CommandSigner {
    fn provision_machine<'a>(
        &'a self,
        job: &'a str,
        host: &'a str,
        name: &'a str,
    ) -> rackhand_hub::actions::runner::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let now = rackhand_store::ids::now_ms();
            let (_, token) =
                rackhand_hub::actions::provision::pending_guest(&self.registry, host, name, &format!("job:{job}"), now)
                    .await
                    .map_err(|e| e.to_string())?;
            self.provisioning.made.lock().unwrap_or_else(|e| e.into_inner()).insert(job.into(), token.as_str().into());
            Ok(())
        })
    }

    /// The installer's line for the guest: this hub's ticket and the machine's token, from the release (or, when the hub
    /// holds one, from the hub itself, whose own certificate the download then trusts).
    fn guest_enrollment(&self, job: &str) -> Option<rackhand_hub::executor::GuestEnrollment> {
        let token = self.provisioning.made.lock().unwrap_or_else(|e| e.into_inner()).get(job)?.clone();
        let (id, addrs) = self.addrs.get()?;
        let addrs = addrs();
        let ticket = format!("rackhand1:{id}@{}", addrs.join(","));
        let mut args = vec!["--ticket".to_string(), ticket, "--token".into(), token];
        let held = self.provisioning.release_dir.as_ref().is_some_and(|d| d.join("install.sh").is_file());
        let ip = addrs.first().and_then(|a| a.parse::<std::net::SocketAddr>().ok()).map(|a| a.ip());
        if let (true, Some(ip)) = (held, ip) {
            let port = if self.provisioning.web_port == 0 { 8443 } else { self.provisioning.web_port };
            let hub = std::net::SocketAddr::new(ip, port);
            args.extend(["--release-url".into(), format!("https://{hub}/release"), "--self-signed".into()]);
            return Some(rackhand_hub::executor::GuestEnrollment {
                script_url: format!("https://{hub}/install.sh"),
                args,
                self_signed: true,
            });
        }
        let url =
            format!("https://github.com/StrangeMatterStudio/Rackhand/releases/download/v{}/install.sh", crate::VERSION);
        Some(rackhand_hub::executor::GuestEnrollment { script_url: url, args, self_signed: false })
    }

    fn signed_guest(&self, now_ms: i64, body: &[u8]) -> Vec<u8> {
        use prost::Message;
        rackhand_proto::signed::sign(
            &self.signing,
            "guest",
            now_ms.max(0) as u64,
            now_ms,
            now_ms + REFRESH_COMMANDS_TTL_MS,
            body,
        )
        .encode_to_vec()
    }

    fn bind_guest<'a>(
        &'a self,
        job: &'a str,
        host: &'a str,
        name: &'a str,
        kind: &'a str,
        vmid: u64,
    ) -> rackhand_hub::actions::runner::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            let hosts = self.provisioning.hosts.as_ref().ok_or("no_hypervisor_api")?;
            let node = hosts.view(host).await?.node;
            let (machine, _) = rackhand_hub::actions::provision::machine_named(&self.db, host, name)
                .ok_or_else(|| "no_such_machine".to_string())?;
            rackhand_hub::actions::provision::bind_guest(
                &self.db,
                host,
                &node,
                &machine,
                kind,
                vmid,
                &format!("job:{job}"),
            )
            .await
            .map_err(|e| e.to_string())
        })
    }

    fn guest_host(&self, machine: &str) -> Option<rackhand_hub::executor::GuestHost> {
        let ip = |a: &str| {
            a.parse::<std::net::SocketAddr>()
                .map(|s| s.ip().to_string())
                .or_else(|_| a.parse::<std::net::IpAddr>().map(|i| i.to_string()))
                .ok()
        };
        let (reference, address): (Option<String>, Option<String>) = self
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT proxmox_ref, address FROM machines WHERE id = ?1", [machine], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
            })
            .ok()?;
        let reference: serde_json::Value = serde_json::from_str(&reference?).ok()?;
        let host_id = reference["cluster"].as_str()?.to_string();
        let (host_address, access): (Option<String>, String) = self
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT address, access FROM machines WHERE id = ?1", [&host_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
            })
            .ok()?;
        Some(rackhand_hub::executor::GuestHost {
            host_id,
            host_address: host_address.as_deref().and_then(ip),
            managed: access == "managed",
            addresses: address.as_deref().and_then(ip).into_iter().collect(),
        })
    }

    fn quarantine_addrs(&self) -> Vec<String> {
        self.addrs.get().map(|(_, addrs)| addrs()).unwrap_or_default()
    }

    fn guest_firewall<'a>(
        &'a self,
        machine: &'a str,
        op: &'a str,
        args: serde_json::Value,
        timeout: std::time::Duration,
    ) -> rackhand_hub::actions::runner::BoxFuture<'a, Result<serde_json::Value, String>> {
        Box::pin(async move {
            let h = self.provisioning.hypervisor.as_ref().ok_or("no_hypervisor_api")?;
            h.guest_firewall(machine, op, args, timeout).await
        })
    }

    fn guest_snapshot<'a>(
        &'a self,
        machine: &'a str,
        name: &'a str,
        timeout: std::time::Duration,
    ) -> rackhand_hub::actions::runner::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            use rackhand_hub::actions::hypervisor_guard::GuestAction;
            let h = self.provisioning.hypervisor.as_ref().ok_or("no_hypervisor_api")?;
            h.guest_call(machine, GuestAction::Snapshot, serde_json::json!({ "name": name }), timeout).await.map(|_| ())
        })
    }

    /// What the machine's quarantine recorded when it isolated it.
    fn quarantine_record(&self, machine: &str) -> Option<serde_json::Value> {
        rackhand_hub::policy::quarantine::record(&self.db, machine)
    }

    fn machine_enrolled(&self, host: &str, name: &str) -> bool {
        rackhand_hub::actions::provision::is_enrolled(&self.db, host, name)
    }

    fn signed_keys(&self, now_ms: i64, body: &[u8]) -> Vec<u8> {
        use prost::Message;
        rackhand_proto::signed::sign(
            &self.signing,
            "keys",
            now_ms.max(0) as u64,
            now_ms,
            now_ms + REFRESH_COMMANDS_TTL_MS,
            body,
        )
        .encode_to_vec()
    }

    fn managed(&self, machine: &str) -> bool {
        self.db
            .readers()
            .with(|c| c.query_row("SELECT access FROM machines WHERE id = ?1", [machine], |r| r.get::<_, String>(0)))
            .is_ok_and(|access| access == "managed")
    }

    fn revoke<'a>(&'a self, machine: &'a str) -> rackhand_hub::actions::runner::BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            match self.registry.revoke_machine(machine).await {
                Ok(true) => Ok(()),
                Ok(false) => Err("no such machine".into()),
                Err(e) => Err(e.to_string()),
            }
        })
    }

    /// As a join gives them: the hub's addresses (the machine's own loopback for a remote-mode probe, D60).
    fn ssh_from(&self, machine: &str) -> Vec<String> {
        let remote = self
            .db
            .readers()
            .with(|c| c.query_row("SELECT mode FROM machines WHERE id = ?1", [machine], |r| r.get::<_, String>(0)))
            .is_ok_and(|mode| mode == "remote");
        if remote {
            return vec!["127.0.0.1".into(), "::1".into()];
        }
        let Some((_, addrs)) = self.addrs.get() else { return Vec::new() };
        let mut ips: Vec<String> = addrs()
            .iter()
            .map(|a| a.parse::<std::net::SocketAddr>().map(|s| s.ip().to_string()).unwrap_or_else(|_| a.clone()))
            .collect();
        ips.sort();
        ips.dedup();
        ips
    }

    fn signed_commands(&self, now_ms: i64) -> Vec<u8> {
        // versioned by the time in milliseconds, as the list in a join is, so the machine finds it newer
        rackhand_hub::executor::commands::signed_command_list(
            &self.signing,
            &enabled_runbooks(&self.db),
            now_ms.max(0) as u64,
            now_ms,
            REFRESH_COMMANDS_TTL_MS,
        )
    }
}

impl ManagedSetupSource for HubSetup {
    fn managed_setup(&self, _machine_id: ulid::Ulid, with_assistant: bool) -> ManagedSetup {
        let runbooks = enabled_runbooks(&self.db);
        let now = now_ms();
        let bytes = rackhand_hub::executor::commands::signed_command_list(
            &self.signing,
            &runbooks,
            now.max(0) as u64,
            now,
            JOIN_COMMANDS_TTL_MS,
        );
        ManagedSetup {
            automation_pubkey: self.automation.clone(),
            assistant_pubkey: with_assistant.then(|| self.assistant.clone()),
            sudoers: if with_assistant { format!("{SUDOERS}{ASSISTANT_SUDOERS}") } else { SUDOERS.into() },
            commands: SignedPayload::decode(bytes.as_slice()).ok(),
        }
    }
}

/// The event for a host key alert: critical, on the machine (E8).
pub fn host_key_event(alert: &HostKeyAlert) -> Event {
    let HostKeyAlert::Changed { machine_id, key_type, offered } = alert;
    let data = serde_json::json!({ "key_type": key_type, "offered": offered });
    Event::machine(machine_id, alert.kind(), Severity::Critical, data)
}

/// The event for a mirror alert; a push that went through raises none, nor does a hub with no mirror.
pub fn mirror_event(alert: &MirrorAlert) -> Option<Event> {
    match alert {
        MirrorAlert::Failed { error, retry_at_ms } => Some(Event::hub(
            alert.kind(),
            Severity::Warning,
            serde_json::json!({ "error": error, "retry_at_ms": retry_at_ms }),
        )),
        MirrorAlert::SecretBlocked { findings } => {
            let files: Vec<&str> = findings.iter().map(|(p, _)| p.as_str()).collect();
            Some(Event::hub(alert.kind(), Severity::Critical, serde_json::json!({ "files": files })))
        }
        MirrorAlert::Pushed { .. } | MirrorAlert::Off => None,
    }
}

/// The event for an SSH test's outcome (7.3.12): info when it passed, a warning naming the account when it didn't.
pub fn ssh_test_event(machine_id: &str, outcome: &Outcome) -> Event {
    match outcome {
        Outcome::Passed => Event::machine(machine_id, enroll_test::PASSED, Severity::Info, serde_json::json!({})),
        Outcome::Failed { account, reason } => Event::machine(
            machine_id,
            enroll_test::FAILED,
            Severity::Warning,
            serde_json::json!({ "account": account, "reason": reason }),
        ),
    }
}

/// How often a machine whose SSH test hasn't passed is tried again while it reports.
pub const SSH_RETRY: std::time::Duration = std::time::Duration::from_secs(60);

/// A machine that reported this recently can be tried again.
const REPORTING: std::time::Duration = std::time::Duration::from_secs(60);

/// Runs until `greeted` closes: a machine due an SSH test is tested when its probe connects, and every `retry` while
/// it reports until a test passes (7.3.12). A failure the last test already recorded isn't recorded again.
pub fn spawn_enroll_tests(
    ingest: Ingest,
    test: Arc<EnrollTest>,
    mut greeted: UnboundedReceiver<String>,
    retry: std::time::Duration,
) {
    let one = move |ingest: Ingest, test: Arc<EnrollTest>, machine: String, retry: bool| async move {
        // held until the result is recorded: a retry in between would test it again and record a second pass
        let Some(_testing) = test.begin(&machine) else { return };
        // a retry chosen before the last result was recorded
        if retry && test.has_passed(&machine) {
            return;
        }
        let Some(outcome) = test.test(&machine).await else { return };
        if !test.already_recorded(&machine, &outcome) {
            if let Err(e) = ingest.raise_event(ssh_test_event(&machine, &outcome)).await {
                tracing::error!(error = %e, %machine, "SSH test event");
            }
        }
        if outcome == Outcome::Passed {
            if let Err(e) = test.passed(&machine).await {
                tracing::error!(error = %e, %machine, "enrolling after the SSH test");
            }
        }
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval_at(tokio::time::Instant::now() + retry, retry);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                machine = greeted.recv() => {
                    let Some(machine) = machine else { return };
                    if test.due(&machine) {
                        tokio::spawn(one(ingest.clone(), test.clone(), machine, false));
                    }
                }
                _ = tick.tick() => {
                    let since = rackhand_store::ids::now_ms() - REPORTING.as_millis() as i64;
                    for machine in test.waiting() {
                        if ingest.last_seen(&machine).is_some_and(|seen| seen >= since) {
                            tokio::spawn(one(ingest.clone(), test.clone(), machine, true));
                        }
                    }
                }
            }
        }
    });
}

/// Runs until the channels close: a managed machine's join pins its host keys and makes its next report tested over
/// SSH; alerts become events.
pub fn spawn_events(
    ingest: Ingest,
    host_keys: Arc<HostKeys>,
    mut joined: UnboundedReceiver<Joined>,
    mut host_alerts: UnboundedReceiver<HostKeyAlert>,
    mut mirror_alerts: UnboundedReceiver<MirrorAlert>,
    test: Arc<EnrollTest>,
) {
    tokio::spawn(async move {
        while let Some(j) = joined.recv().await {
            if j.kind == TokenKind::Machine && !j.ssh_host_keys.is_empty() {
                if let Err(e) = host_keys.pin_join_message(&j.id, &j.ssh_host_keys, now_ms()).await {
                    tracing::error!(error = %e, machine = %j.id, "pinning the joined machine's host keys");
                }
                test.joined(&j.id);
            }
        }
    });
    let i = ingest.clone();
    tokio::spawn(async move {
        while let Some(alert) = host_alerts.recv().await {
            if let Err(e) = i.raise_event(host_key_event(&alert)).await {
                tracing::error!(error = %e, "host key event");
            }
        }
    });
    tokio::spawn(async move {
        while let Some(alert) = mirror_alerts.recv().await {
            if let Some(event) = mirror_event(&alert) {
                if let Err(e) = ingest.raise_event(event).await {
                    tracing::error!(error = %e, "mirror event");
                }
            }
        }
    });
}

/// The probe settings a hub hands out (7.8.1): the `[probe]` section of `config/hub.toml`, or its defaults.
pub fn probe_config(db: &Db) -> ProbeConfig {
    let p = rackhand_hub::library::config::hub_or_default(db).probe;
    ProbeConfig {
        interval_s: p.interval_s,
        max_connection_tuples: p.connection_tuples,
        buffer_max_mb: p.buffer_max_mb,
        series_cap: p.series_cap,
        ..Default::default()
    }
}

/// This hub's own site, once first run has named it.
fn local_site(db: &Db) -> Option<String> {
    db.readers()
        .with(|c| {
            use rusqlite::OptionalExtension;
            c.query_row("SELECT name FROM sites WHERE is_local = 1", [], |r| r.get::<_, String>(0)).optional()
        })
        .ok()
        .flatten()
}

/// The `rackhand/join/1` server, built at the first join after first run has named this hub's site (7.3.1). Before
/// that no token exists, so a join is closed as from an unknown peer.
pub type HubAddrs = Arc<dyn Fn() -> Vec<String> + Send + Sync>;

pub struct LazyJoin {
    db: Arc<Db>,
    registry: Arc<Registry>,
    setup: Arc<dyn ManagedSetupSource>,
    /// The addresses joins hand out, read when the server is built.
    hub_addrs: HubAddrs,
    joined: UnboundedSender<Joined>,
    /// The hub's own relays, which a join hands to the machine so that it can reach the hub through them.
    relays: Vec<String>,
    server: Mutex<Option<Arc<JoinServer>>>,
}

impl std::fmt::Debug for LazyJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyJoin").finish_non_exhaustive()
    }
}

impl LazyJoin {
    pub fn with_relays(
        db: Arc<Db>,
        registry: Arc<Registry>,
        setup: Arc<dyn ManagedSetupSource>,
        hub_addrs: HubAddrs,
        joined: UnboundedSender<Joined>,
        relays: Vec<String>,
    ) -> Arc<LazyJoin> {
        Arc::new(LazyJoin { db, registry, setup, hub_addrs, joined, relays, server: Mutex::new(None) })
    }

    /// The server, built the first time this hub has a site; its joins are passed on to `joined`.
    pub fn server(&self) -> Option<Arc<JoinServer>> {
        let mut slot = self.server.lock().ok()?;
        if let Some(server) = slot.as_ref() {
            return Some(server.clone());
        }
        let info = HubInfo {
            site: local_site(&self.db)?,
            version: crate::VERSION.into(),
            relays: self.relays.clone(),
            hub_addrs: (self.hub_addrs)(),
            probe_config: probe_config(&self.db),
        };
        let (server, mut joins) = JoinServer::new(self.registry.clone(), self.setup.clone(), info);
        let tx = self.joined.clone();
        tokio::spawn(async move {
            while let Some(j) = joins.recv().await {
                if tx.send(j).is_err() {
                    return;
                }
            }
        });
        *slot = Some(server.clone());
        Some(server)
    }

    pub fn handler(self: &Arc<Self>) -> Handler {
        let this = self.clone();
        rackhand_net::router::handler(move |conn| {
            let this = this.clone();
            async move {
                match this.server() {
                    Some(server) => server.serve(conn).await,
                    None => rackhand_net::close(&conn, rackhand_proto::close::CloseCode::UnknownPeer),
                }
            }
        })
    }
}
