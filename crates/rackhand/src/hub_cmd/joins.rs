//! What a join hands the other systems (7.3.1, 7.3.7): a managed machine's keys, sudoers and first command list, its
//! host keys pinned in SSH, and the host key and mirror alerts raised as events through Ingest (7.3.8).

use std::sync::{Arc, Mutex};

use prost::Message;
use rackhand_hub::ingest::Ingest;
use rackhand_hub::ingest::{Event, Severity};
use rackhand_hub::library::items::{Kind, Library};
use rackhand_hub::library::mirror::MirrorAlert;
use rackhand_hub::registry::Registry;
use rackhand_hub::registry::join_server::{HubInfo, JoinServer, Joined, ManagedSetupSource};
use rackhand_hub::registry::tokens::TokenKind;
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

impl ManagedSetupSource for HubSetup {
    fn managed_setup(&self, _machine_id: ulid::Ulid, with_assistant: bool) -> ManagedSetup {
        let runbooks: Vec<_> = Library::all_current(&self.db)
            .unwrap_or_default()
            .into_iter()
            .filter(|(kind, _, _)| *kind == Kind::Runbook)
            .filter_map(|(_, _, text)| rackhand_runbook::runbook::Runbook::parse(&text).ok())
            .collect();
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
            sudoers: SUDOERS.into(),
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

/// The event for a mirror alert; a push that went through raises none.
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
        MirrorAlert::Pushed { .. } => None,
    }
}

/// Runs until the channels close: a managed machine's join pins its host keys; alerts become events.
pub fn spawn_events(
    ingest: Ingest,
    host_keys: Arc<HostKeys>,
    mut joined: UnboundedReceiver<Joined>,
    mut host_alerts: UnboundedReceiver<HostKeyAlert>,
    mut mirror_alerts: UnboundedReceiver<MirrorAlert>,
) {
    tokio::spawn(async move {
        while let Some(j) = joined.recv().await {
            if j.kind == TokenKind::Machine && !j.ssh_host_keys.is_empty() {
                if let Err(e) = host_keys.pin_join_message(&j.id, &j.ssh_host_keys, now_ms()).await {
                    tracing::error!(error = %e, machine = %j.id, "pinning the joined machine's host keys");
                }
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

/// The probe settings a hub hands out until they are edited (7.8.1): 15 s, 500 tuples, a 64 MB buffer.
pub fn probe_defaults() -> ProbeConfig {
    ProbeConfig { interval_s: 15, max_connection_tuples: 500, buffer_max_mb: 64, ..Default::default() }
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
    server: Mutex<Option<Arc<JoinServer>>>,
}

impl std::fmt::Debug for LazyJoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LazyJoin").finish_non_exhaustive()
    }
}

impl LazyJoin {
    pub fn new(
        db: Arc<Db>,
        registry: Arc<Registry>,
        setup: Arc<dyn ManagedSetupSource>,
        hub_addrs: HubAddrs,
        joined: UnboundedSender<Joined>,
    ) -> Arc<LazyJoin> {
        Arc::new(LazyJoin { db, registry, setup, hub_addrs, joined, server: Mutex::new(None) })
    }

    /// The server, built the first time this hub has a site; its joins are passed on to `joined`.
    pub fn server(&self) -> Option<Arc<JoinServer>> {
        let mut slot = self.server.lock().ok()?;
        if let Some(server) = slot.as_ref() {
            return Some(server.clone());
        }
        let info = HubInfo {
            site: local_site(&self.db)?,
            version: env!("CARGO_PKG_VERSION").into(),
            relays: Vec::new(),
            hub_addrs: (self.hub_addrs)(),
            probe_config: probe_defaults(),
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
