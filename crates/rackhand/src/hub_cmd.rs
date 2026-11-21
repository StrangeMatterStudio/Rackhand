//! `rackhand hub init`, `hub run` and `hub detect replay` (7.7.3): the hub's composition root (7.2).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::probe_server::{ProbeDirectory, ProbeServer, ServerSettings};
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_hub::vault::master_key::{MasterKey, recovery_code};
use rackhand_hub::vault::{Secret, Vault};
use rackhand_store::Db;
use rackhand_store::ids::now_ms;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// `/etc/rackhand/hub.toml` (7.8): listen addresses, data directory, key paths, trusted proxies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubConfig {
    pub web: SocketAddr,
    pub quic: SocketAddr,
    pub data_dir: PathBuf,
    pub master_key: PathBuf,
    pub node_key: PathBuf,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    /// Names the dashboard's certificate is issued for.
    #[serde(default)]
    pub names: Vec<String>,
}

impl HubConfig {
    pub fn defaults(config_dir: &Path, data_dir: &Path) -> HubConfig {
        HubConfig {
            web: SocketAddr::from(([0, 0, 0, 0], 8443)),
            quic: SocketAddr::from(([0, 0, 0, 0], 7443)),
            data_dir: data_dir.to_path_buf(),
            master_key: config_dir.join("master.key"),
            node_key: config_dir.join("node.key"),
            trusted_proxies: Vec::new(),
            names: vec!["localhost".into()],
        }
    }

    pub fn load(path: &Path) -> Result<HubConfig, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    pub fn db_path(&self) -> PathBuf {
        self.data_dir.join("hub.db")
    }
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .map_err(|e| format!("{}: {e}", path.display()))
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

/// What `hub init` made, to print once.
#[derive(Debug)]
pub struct Initialized {
    pub setup_code: String,
    pub recovery_code: String,
    pub config: PathBuf,
}

const SETUP_ALPHABET: &[u8] = b"23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

fn setup_code() -> Result<String, String> {
    let mut raw = [0u8; 12];
    getrandom::fill(&mut raw).map_err(|e| e.to_string())?;
    let chars: String = raw.iter().map(|b| SETUP_ALPHABET[(*b as usize) % SETUP_ALPHABET.len()] as char).collect();
    Ok(format!("SETUP-{}-{}-{}", &chars[..4], &chars[4..8], &chars[8..]))
}

/// `rackhand hub init`: the master key (0600), the node key (0600), `hub.toml` (0640), the database with the
/// automation and assistant keys, the dashboard's CSRF key and the hash of a one-time setup code (7.7.4). It refuses
/// to replace an existing master key.
pub async fn init(config_dir: &Path, data_dir: &Path) -> Result<Initialized, String> {
    std::fs::create_dir_all(config_dir).map_err(|e| format!("{}: {e}", config_dir.display()))?;
    std::fs::create_dir_all(data_dir).map_err(|e| format!("{}: {e}", data_dir.display()))?;
    let config = HubConfig::defaults(config_dir, data_dir);
    if config.master_key.exists() {
        return Err(format!("{} already exists; the hub is already initialized", config.master_key.display()));
    }
    let key = MasterKey::generate();
    key.save(&config.master_key).map_err(|e| format!("{}: {e}", config.master_key.display()))?;
    rackhand_net::key::load_or_create(&config.node_key).map_err(|e| format!("{}: {e}", config.node_key.display()))?;
    set_mode(&config.node_key, 0o600)?;
    let toml_path = config_dir.join("hub.toml");
    let text = toml::to_string(&config).map_err(|e| e.to_string())?;
    std::fs::write(&toml_path, text).map_err(|e| format!("{}: {e}", toml_path.display()))?;
    set_mode(&toml_path, 0o640)?;
    let recovery = recovery_code(&key);
    let db = Arc::new(Db::open(&config.db_path()).map_err(|e| e.to_string())?);
    let vault = Vault::new(key, db.clone());
    for id in [rackhand_hub::ssh::keys::Identity::Automation, rackhand_hub::ssh::keys::Identity::Assistant] {
        rackhand_hub::ssh::keys::load_or_create(&vault, id).await.map_err(|e| e.to_string())?;
    }
    let code = setup_code()?;
    let hash: [u8; 32] = Sha256::digest(code.as_bytes()).into();
    vault.put("setup_code_hash", &Secret::new(hash.to_vec())).await.map_err(|e| e.to_string())?;
    let mut csrf = [0u8; 32];
    getrandom::fill(&mut csrf).map_err(|e| e.to_string())?;
    vault.put("csrf_key", &Secret::new(csrf.to_vec())).await.map_err(|e| e.to_string())?;
    let mut metrics = [0u8; 24];
    getrandom::fill(&mut metrics).map_err(|e| e.to_string())?;
    let token: String = metrics.iter().map(|b| format!("{b:02x}")).collect();
    vault.put("metrics_token", &Secret::from(token.as_str())).await.map_err(|e| e.to_string())?;
    Ok(Initialized { setup_code: code, recovery_code: recovery, config: toml_path })
}

/// Free space on the database's filesystem.
#[derive(Debug)]
struct Statvfs(PathBuf);

impl DiskSpace for Statvfs {
    #[cfg(unix)]
    fn free_fraction(&self) -> f64 {
        match rustix::fs::statvfs(&self.0) {
            Ok(s) if s.f_blocks > 0 => s.f_bavail as f64 / s.f_blocks as f64,
            _ => 1.0,
        }
    }

    #[cfg(not(unix))]
    fn free_fraction(&self) -> f64 {
        1.0
    }
}

/// The probe server's directory: the Registry's machines and their probe endpoints (7.3.2).
#[derive(Debug)]
pub struct MachinesDirectory(pub Arc<Db>);

impl ProbeDirectory for MachinesDirectory {
    fn machine_of(&self, endpoint: &iroh::EndpointId) -> Option<[u8; 16]> {
        let id: Option<String> = self
            .0
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT id FROM machines WHERE probe_endpoint_id = ?1 AND state = 'enrolled'",
                    [endpoint.to_string()],
                    |r| r.get(0),
                )
            })
            .ok();
        id.and_then(|s| s.parse::<ulid::Ulid>().ok()).map(|u| u.to_bytes())
    }
}

/// `addr` or `addr/prefix`, as `trusted_proxies` lists them.
fn cidr(text: &str) -> Option<(std::net::IpAddr, u8)> {
    let (addr, prefix) = text.split_once('/').unwrap_or((text, ""));
    let ip: std::net::IpAddr = addr.trim().parse().ok()?;
    let full = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = if prefix.is_empty() { full } else { prefix.trim().parse().ok().filter(|p| *p <= full)? };
    Some((ip, prefix))
}

fn secret(vault: &Vault, name: &str) -> Result<Vec<u8>, String> {
    vault
        .get(name)
        .map(|s| s.expose().to_vec())
        .map_err(|_| format!("the Vault has no {name}; run `rackhand hub init`"))
}

/// `rackhand hub run`: opens everything the config names and serves until stopped.
pub async fn run(config: &HubConfig) -> Result<(), String> {
    let key = MasterKey::load(Some(&config.master_key))
        .map_err(|_| format!("the master key {} can't be read (or isn't 32 bytes)", config.master_key.display()))?;
    let recovery = recovery_code(&key);
    let db = Arc::new(Db::open(&config.db_path()).map_err(|e| format!("{}: {e}", config.db_path().display()))?);
    let vault = Arc::new(Vault::new(key, db.clone()));
    let setup_hash: [u8; 32] =
        secret(&vault, "setup_code_hash")?.try_into().map_err(|_| "setup_code_hash is malformed")?;
    let csrf_key: [u8; 32] = secret(&vault, "csrf_key")?.try_into().map_err(|_| "csrf_key is malformed")?;
    let audit = Audit::new(db.writer());
    let bus = Bus::new();
    let ingest = Ingest::new(db.clone(), bus.clone(), Arc::new(Statvfs(config.data_dir.clone())));
    ingest.start(now_ms()).await.map_err(|e| e.to_string())?;
    let incidents = rackhand_hub::incidents::Incidents::new(db.clone(), ingest.clone(), bus.clone());
    let transports = notifiers(&db, &vault, None).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "notifiers not started");
        Vec::new()
    });
    let notify = rackhand_hub::notify::Notify::new(db.clone(), ingest.clone(), transports);
    let registry = rackhand_hub::registry::Registry::load(db.clone()).map_err(|e| e.to_string())?;
    let (library, changes) = rackhand_hub::library::items::Library::new(db.clone(), audit.clone());
    let (host_keys, host_alerts) = rackhand_hub::ssh::hostkeys::HostKeys::new(db.clone());
    let mirror = rackhand_hub::library::mirror::Mirror {
        db: db.clone(),
        vault: vault.clone(),
        audit: audit.clone(),
        workdir: config.data_dir.join("mirror"),
        target: rackhand_hub::library::mirror::target_from_settings(db.clone()),
        debounce_ms: 30_000,
        clock: Arc::new(now_ms),
    };
    let mirror_alerts = mirror.spawn(changes);
    let executor = rackhand_hub::executor::Executor::new(vault.clone(), host_keys.clone())
        .with_other(Arc::new(steps(&notify, &ingest)));
    let actions = rackhand_hub::actions::Actions::new(db.clone(), audit.clone(), bus.clone(), Arc::new(executor))
        .with_gate(Arc::new(ingest.clone()));
    let web_config = rackhand_hub::web::WebConfig {
        setup_code_hash: setup_hash,
        csrf_key,
        trusted_proxies: config.trusted_proxies.iter().filter_map(|p| cidr(p)).collect(),
    };
    let web = rackhand_hub::web::Web::new(db.clone(), vault.clone(), audit.clone(), recovery, web_config)
        .with_registry(registry.clone())
        .with_library(library.clone())
        .with_host_keys(host_keys.clone())
        .with_ingest(ingest.clone())
        .with_notify(notify.clone())
        .with_bus(bus.clone());
    // the mesh: probes and MCP clients
    let node_key = rackhand_net::key::load_or_create(&config.node_key)
        .map_err(|e| format!("{}: {e}", config.node_key.display()))?;
    let setup = Arc::new(joins::HubSetup {
        db: db.clone(),
        automation: ssh_public(&vault, rackhand_hub::ssh::keys::Identity::Automation).await?,
        assistant: ssh_public(&vault, rackhand_hub::ssh::keys::Identity::Assistant).await?,
        signing: ed25519_dalek::SigningKey::from_bytes(&node_key.to_bytes()),
    });
    let (joined_tx, joined) = tokio::sync::mpsc::unbounded_channel();
    joins::spawn_events(ingest.clone(), host_keys, joined, host_alerts, mirror_alerts);
    let alpns = vec![
        rackhand_proto::alpn::PROBE.to_vec(),
        rackhand_proto::alpn::MCP.to_vec(),
        rackhand_proto::alpn::JOIN.to_vec(),
    ];
    let endpoint_config =
        rackhand_net::endpoint::EndpointConfig { relays: Default::default(), alpns, bind: Some(config.quic) };
    let endpoint = rackhand_net::endpoint::bind(node_key, &endpoint_config).await.map_err(|e| e.to_string())?;
    let (ep, quic) = (endpoint.clone(), config.clone());
    let addrs = Arc::new(move || hub_addrs(&quic, &ep.addr().ip_addrs().copied().collect::<Vec<_>>()));
    let join = joins::LazyJoin::new(db.clone(), registry.clone(), setup, addrs, joined_tx);
    let probe_server =
        ProbeServer::new(ingest.clone(), Arc::new(MachinesDirectory(db.clone())), probe_server_settings(&db));
    let observations = Arc::new(crate::observations::FromIngest(ingest.clone()));
    let mcp = rackhand_hub::mcp::Mcp::new(db.clone(), audit.clone(), observations)
        .with_actions(actions)
        .with_library(library);
    let router = rackhand_net::router::Router::new(endpoint.clone(), registry.clone())
        .route(rackhand_proto::alpn::PROBE, probe_server.handler())
        .route(rackhand_proto::alpn::MCP, mcp.handler())
        .route(rackhand_proto::alpn::JOIN, join.handler());
    tokio::spawn(router.serve());
    let watch = Arc::new(self_watch(config, &db, &ingest, &notify));
    spawn_loops(ingest.clone(), incidents, notify, db.clone(), Nightly { config: config.clone(), watch });
    // the service checks of config/checks.toml, each at its interval (FR-9)
    rackhand_hub::checks::Checks::new(db.clone(), ingest.clone()).spawn();
    // the dashboard over TLS
    let (cert, key_pem) =
        rackhand_hub::web::tls::load_or_create(&vault, &config.names).await.map_err(|e| e.to_string())?;
    let tls = rackhand_hub::web::tls::server_config(&cert, &key_pem).map_err(|e| e.to_string())?;
    let listener = tokio::net::TcpListener::bind(config.web).await.map_err(|e| format!("{}: {e}", config.web))?;
    tracing::info!(web = %config.web, quic = %config.quic, "hub running");
    tokio::select! {
        () = rackhand_hub::web::tls::serve(listener, web.router(), tls) => {}
        _ = tokio::signal::ctrl_c() => {}
    }
    // on shutdown, staged reports go into chunk rows (7.3.2)
    ingest.compact().await.map_err(|e| e.to_string())?;
    endpoint.close().await;
    Ok(())
}

/// What the probe server's Welcome tells probes: the probe settings of `config/hub.toml`, or their defaults (7.8.1).
pub fn probe_server_settings(db: &Db) -> ServerSettings {
    let mut config = joins::probe_defaults();
    match rackhand_hub::library::config::hub(db) {
        Ok(settings) => {
            if let Some(p) = settings.probe {
                config.interval_s = p.interval_s;
                config.max_connection_tuples = p.connection_tuples;
                config.buffer_max_mb = p.buffer_max_mb;
            }
        }
        Err(e) => tracing::warn!(error = %e, "probe settings: using the defaults"),
    }
    ServerSettings { config, ..ServerSettings::default() }
}

/// The systems that run the step kinds other than `ssh` (7.8.7): `notify` by Notify, `wait_report` by Ingest.
pub fn steps(notify: &rackhand_hub::notify::Notify, ingest: &Ingest) -> rackhand_hub::executor::ByKind {
    use rackhand_runbook::runbook::StepKind;
    rackhand_hub::executor::ByKind::default()
        .with(StepKind::Notify, Arc::new(notify.clone()))
        .with(StepKind::WaitReport, Arc::new(ingest.clone()))
}

/// The public half of one of the hub's SSH identities, as an `authorized_keys` key (made the first time).
async fn ssh_public(vault: &Vault, id: rackhand_hub::ssh::keys::Identity) -> Result<String, String> {
    let key = rackhand_hub::ssh::keys::load_or_create(vault, id).await.map_err(|e| e.to_string())?;
    key.public_key().to_openssh().map_err(|e| e.to_string())
}

/// The addresses a joining machine is told to reach the hub at: the QUIC endpoint's direct addresses (its interfaces,
/// or the one address it is bound to) other than loopback and link-local, then each certificate name that is an IP
/// address, on the QUIC port; each once.
pub fn hub_addrs(config: &HubConfig, endpoint: &[SocketAddr]) -> Vec<String> {
    let port = config.quic.port();
    let named =
        config.names.iter().filter_map(|n| n.parse::<std::net::IpAddr>().ok()).map(|ip| SocketAddr::new(ip, port));
    let mut addrs: Vec<String> = Vec::new();
    for a in endpoint.iter().copied().filter(|a| reachable(a.ip())).chain(named) {
        let a = a.to_string();
        if !addrs.contains(&a) {
            addrs.push(a);
        }
    }
    addrs
}

/// Whether another machine could reach this address: not unspecified, loopback or link-local.
fn reachable(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => !(v4.is_unspecified() || v4.is_loopback() || v4.is_link_local()),
        std::net::IpAddr::V6(v6) => !(v6.is_unspecified() || v6.is_loopback() || v6.is_unicast_link_local()),
    }
}

/// The hub's periodic work: evaluation and callouts every 15 s, compaction every 5 minutes, rollups every minute
/// and hour, retention hourly.
/// The nightly work (9, 10): a backup at 02:00 site time and the self-watch at 02:30.
struct Nightly {
    config: HubConfig,
    watch: Arc<rackhand_hub::selfwatch::SelfWatch>,
}

/// The self-watch's checks for this hub: its database, its binary against the release manifest beside `hub.toml`
/// (`release-manifest.json` and its `.minisig`, installed with the release), and its key and config files.
fn self_watch(
    config: &HubConfig,
    db: &Arc<Db>,
    ingest: &Ingest,
    notify: &rackhand_hub::notify::Notify,
) -> rackhand_hub::selfwatch::SelfWatch {
    use rackhand_hub::selfwatch::{Manifest, SelfWatch, quick_check};
    let config_dir = config.master_key.parent().map(Path::to_path_buf).unwrap_or_default();
    let manifest = config_dir.join("release-manifest.json");
    let manifest =
        manifest.exists().then(|| Manifest { signature: manifest.with_extension("json.minisig"), path: manifest });
    SelfWatch {
        ingest: ingest.clone(),
        notify: notify.clone(),
        db: db.clone(),
        integrity: quick_check(config.db_path()),
        exe: std::env::current_exe().unwrap_or_default(),
        exe_name: format!("rackhand-{}-unknown-linux-musl", std::env::consts::ARCH),
        manifest,
        configs: vec![(config.master_key.clone(), 0o600), (config_dir.join("hub.toml"), 0o640)],
    }
}

fn spawn_loops(
    ingest: Ingest,
    incidents: rackhand_hub::incidents::Incidents,
    notify: rackhand_hub::notify::Notify,
    db: Arc<Db>,
    nightly: Nightly,
) {
    let (i, n, g) = (incidents.clone(), notify, ingest.clone());
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(15));
        loop {
            tick.tick().await;
            let now = now_ms();
            let _ = g.check_disk().await;
            if let Err(e) = i.evaluate(now).await {
                tracing::warn!(error = %e, "evaluating rules");
            }
            if let Err(e) = n.tick(now).await {
                tracing::warn!(error = %e, "notifying");
            }
        }
    });
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(60));
        loop {
            tick.tick().await;
            let now = now_ms();
            every_minute(&ingest, &incidents, &db, now, &rackhand_store::retention::TokioSleeper).await;
            let (backup, watch) = backups::site_minute(&db, now).map(backups::nightly).unwrap_or_default();
            if backup && !ingest.integrity_failed() {
                let config = nightly.config.clone();
                match tokio::task::spawn_blocking(move || backups::backup_now(&config, now)).await {
                    Ok(Ok(path)) => tracing::info!(path = %path.display(), "nightly backup"),
                    Ok(Err(e)) => tracing::error!(error = %e, "nightly backup"),
                    Err(e) => tracing::error!(error = %e, "nightly backup"),
                }
            }
            if watch {
                for f in nightly.watch.daily(now).await {
                    tracing::warn!(kind = f.kind, detail = %f.detail, "self-watch");
                }
            }
        }
    });
}

/// The minute's work (7.4.1, 7.3.8): the last completed minute rolled up, reconciliation, compaction every 5 minutes,
/// and in the first minute of an hour the last hour rolled up, the baselines updated and retention run.
pub async fn every_minute(
    ingest: &Ingest,
    incidents: &rackhand_hub::incidents::Incidents,
    db: &Db,
    now: i64,
    sleeper: &dyn rackhand_store::retention::Sleeper,
) {
    let minute = now - now.rem_euclid(60_000) - 60_000;
    if let Err(e) = ingest.rollup_minute(minute).await {
        tracing::warn!(error = %e, "minute rollup");
    }
    let _ = incidents.reconcile(now).await;
    if (now / 60_000) % 5 == 0 {
        let _ = ingest.compact().await;
    }
    if now.rem_euclid(3_600_000) < 60_000 {
        let hour = now - now.rem_euclid(3_600_000) - 3_600_000;
        if let Err(e) = ingest.rollup_hour(hour).await {
            tracing::warn!(error = %e, "hour rollup");
        }
        let _ = incidents.baseline_hourly(hour, now).await;
        let settings = rackhand_store::retention::RetentionSettings::default();
        if let Err(e) = rackhand_store::retention::run(&db.writer(), &settings, now, sleeper).await {
            tracing::warn!(error = %e, "retention");
        }
    }
}

/// The hub as an install command names it (7.3.12): `rackhand1:<endpoint id hex>@<addr>:<quic port>,...`, the
/// endpoint id from the node key. Used by `hub lab-token` until the Add page issues tickets (T49).
#[cfg(any(test, feature = "lab-build"))]
pub fn ticket(config: &HubConfig, addrs: &[std::net::IpAddr]) -> Result<String, String> {
    if addrs.is_empty() {
        return Err("a ticket needs at least one address of the hub".into());
    }
    let key = rackhand_net::key::load_or_create(&config.node_key)
        .map_err(|e| format!("{}: {e}", config.node_key.display()))?;
    let id: String = key.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    let port = config.quic.port();
    let addrs: Vec<String> = addrs.iter().map(|ip| SocketAddr::new(*ip, port).to_string()).collect();
    Ok(format!("rackhand1:{id}@{}", addrs.join(",")))
}

/// `rackhand hub metrics-token`: the bearer token `/metrics` checks, read from the Vault with the master key, so only
/// root can read it. The database is opened read-only, so it is safe while the hub runs.
pub fn metrics_token(config: &HubConfig) -> Result<String, String> {
    use rackhand_hub::vault::master_key::Sealed;
    const NAME: &str = "metrics_token";
    let key = MasterKey::load(Some(&config.master_key))
        .map_err(|_| format!("the master key {} can't be read", config.master_key.display()))?;
    let path = config.db_path();
    let conn = rusqlite::Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let (nonce, ciphertext): (Vec<u8>, Vec<u8>) = conn
        .query_row("SELECT nonce, ciphertext FROM secrets WHERE name = ?1", [NAME], |r| Ok((r.get(0)?, r.get(1)?)))
        .map_err(|_| "no metrics token: run `rackhand hub init` first".to_string())?;
    let nonce: [u8; 24] = nonce.try_into().map_err(|_| "the stored token is damaged".to_string())?;
    let token = key
        .open(NAME, &Sealed { nonce, ciphertext })
        .map_err(|_| "the token doesn't open with this master key".to_string())?;
    Ok(String::from_utf8_lossy(token.expose()).into_owned())
}

/// The notifiers of `config/notifiers.toml`, their secrets from the Vault (none when the file doesn't exist yet).
pub fn notifiers(
    db: &Db,
    vault: &Vault,
    dashboard_url: Option<&str>,
) -> Result<Vec<Arc<dyn rackhand_hub::notify::Transport>>, String> {
    use rackhand_hub::library::items::{Kind, Library};
    use rackhand_hub::notify::config;
    let Some((_, text)) = Library::current_in(db, Kind::Config, "notifiers").map_err(|e| e.to_string())? else {
        return Ok(Vec::new());
    };
    let file = config::parse(&text).map_err(|e| e.to_string())?;
    let secret = |name: &str| vault.get(name).ok().map(|s| String::from_utf8_lossy(s.expose()).into_owned());
    config::build(&file, &secret, dashboard_url).map_err(|e| e.to_string())
}

/// `rackhand hub detect replay`: what the rules would have opened over stored data; writes nothing.
pub fn detect_replay(db_path: &Path, machine: &str, from_ms: i64, to_ms: i64) -> Result<Vec<String>, String> {
    let db = Db::open(db_path).map_err(|e| format!("{}: {e}", db_path.display()))?;
    rackhand_hub::incidents::replay::replay(&db, machine, from_ms, to_ms, 15)
}

pub mod backups;
pub mod joins;

#[cfg(test)]
mod tests;
