//! Hub configuration stored with revisions (7.8: edited in the dashboard, stored with revisions, mirrored to git as
//! `config/<name>.toml`). Kept as library items of kind `config`, beside runbooks and playbooks.

use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use serde::{Deserialize, Serialize};

pub const HUB: &str = "hub";

/// The outside sources (7.8.5), each on or off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sources {
    pub feodo: bool,
    pub spamhaus: bool,
    pub dbip: bool,
    /// Air-gapped mode: the hub makes no outside request at all (D65).
    #[serde(default)]
    pub airgapped: bool,
    /// Off unless enabled: MaxMind GeoLite2 (own license key), online reputation lookups (send destinations out), relay
    /// lists (URLs the admin adds) and n0's public relays and DNS discovery (7.8.5).
    #[serde(default)]
    pub maxmind: bool,
    #[serde(default)]
    pub reputation: bool,
    #[serde(default)]
    pub relay_lists: bool,
    #[serde(default)]
    pub n0_relays: bool,
}

impl Default for Sources {
    fn default() -> Self {
        Sources {
            feodo: true,
            spamhaus: true,
            dbip: true,
            airgapped: false,
            maxmind: false,
            reputation: false,
            relay_lists: false,
            n0_relays: false,
        }
    }
}

/// `config/hub.toml`: the settings edited in the dashboard.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubConfig {
    #[serde(default)]
    pub sources: Sources,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub git_mirror: Option<GitMirror>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<Oidc>,
    #[serde(default, skip_serializing_if = "ProbeSettings::is_default")]
    pub probe: ProbeSettings,
    #[serde(default, skip_serializing_if = "AssistantSettings::is_default")]
    pub assistant: AssistantSettings,
    #[serde(default, skip_serializing_if = "PatchingSettings::is_default")]
    pub patching: PatchingSettings,
    #[serde(default, skip_serializing_if = "PeerSettings::is_default")]
    pub peers: PeerSettings,
    #[serde(default, skip_serializing_if = "IncidentSettings::is_default")]
    pub incidents: IncidentSettings,
    #[serde(default, skip_serializing_if = "ConnectionSettings::is_default")]
    pub connections: ConnectionSettings,
    #[serde(default, skip_serializing_if = "JobSettings::is_default")]
    pub jobs: JobSettings,
    #[serde(default, skip_serializing_if = "ApprovalSettings::is_default")]
    pub approvals: ApprovalSettings,
    #[serde(default, skip_serializing_if = "AuthSettings::is_default")]
    pub auth: AuthSettings,
    #[serde(default, skip_serializing_if = "BaselineSettings::is_default")]
    pub baseline: BaselineSettings,
    #[serde(default, skip_serializing_if = "RetentionTiers::is_default")]
    pub retention: RetentionTiers,
    #[serde(default, skip_serializing_if = "BackupSettings::is_default")]
    pub backups: BackupSettings,
    /// A URL a hub with no peers calls every 5 minutes, for a service outside the site that notices when it goes quiet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadman_url: Option<String>,
    /// Relay lists this hub follows (7.3.10): HTTPS addresses of TOML lists, fetched daily when `sources.relay_lists` is on.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub relay_list_urls: Vec<String>,
    /// The release channel this hub offers its probes updates from (13): `stable`, or `beta` to take beta releases too.
    #[serde(default, skip_serializing_if = "rackhand_release::manifest::Channel::is_stable")]
    pub release_channel: rackhand_release::manifest::Channel,
}

/// The dashboard's port and the hub's QUIC port by default (7.8.1); they are kept in `/etc/rackhand/hub.toml`.
pub const DASHBOARD_PORT: u16 = 8443;
pub const QUIC_PORT: u16 = 7443;

/// One setting of `config/hub.toml` (7.8.1): its key (`section.field`), its default and its range, in the unit its
/// key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub key: &'static str,
    pub default: i64,
    pub min: i64,
    pub max: i64,
}

impl Setting {
    /// The setting's value, or why it is out of range.
    pub fn check(&self, value: i64) -> Result<(), String> {
        if (self.min..=self.max).contains(&value) {
            return Ok(());
        }
        Err(format!("{} is {} to {}, not {value}", self.key, self.min, self.max))
    }
}

/// A section of `config/hub.toml`: its settings, each with a default and a range, and the constants that name them.
/// A key that is absent takes its default.
macro_rules! section {
    ($(#[$doc:meta])* $name:ident [$section:literal] {
        $($(#[$fdoc:meta])* $field:ident = $setting:ident ($default:expr, $min:expr, $max:expr)),* $(,)?
    }) => {
        $(
            $(#[$fdoc])*
            pub const $setting: Setting =
                Setting { key: concat!($section, ".", stringify!($field)), default: $default, min: $min, max: $max };
        )*

        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(deny_unknown_fields, default)]
        pub struct $name {
            $($(#[$fdoc])* pub $field: u32,)*
        }

        impl Default for $name {
            fn default() -> Self {
                $name { $($field: $setting.default as u32,)* }
            }
        }

        impl $name {
            pub fn is_default(&self) -> bool {
                *self == Self::default()
            }

            /// Each setting with its value, which `f` may change.
            fn visit(&mut self, f: &mut dyn FnMut(&'static Setting, &mut i64)) {
                $({
                    let mut v = i64::from(self.$field);
                    f(&$setting, &mut v);
                    self.$field = u32::try_from(v).unwrap_or(0);
                })*
            }
        }
    };
}

section! {
    /// What every probe is told (7.8.1): its interval, the connection tuples per report, its buffer's cap (5) and the
    /// series it reports.
    ProbeSettings ["probe"] {
        /// Probe interval, in seconds.
        interval_s = PROBE_INTERVAL(15, 5, 300),
        /// Connection tuples per report.
        connection_tuples = CONNECTION_TUPLES(500, 100, 5000),
        /// The probe's buffer, in MB (5, D114).
        buffer_max_mb = PROBE_BUFFER(64, 1, 64),
        /// Series cap per machine.
        series_cap = SERIES_CAP(200, 50, 2000),
    }
}

section! {
    /// Patching (7.5.3).
    PatchingSettings ["patching"] {
        /// Max concurrent patch jobs per site.
        max_jobs_per_site = PATCH_JOBS_PER_SITE(3, 1, 20),
    }
}

section! {
    /// Peers (7.5.5).
    PeerSettings ["peers"] {
        /// Peer summary interval, in seconds.
        summary_interval_s = PEER_SUMMARY_INTERVAL(30, 10, 300),
    }
}

section! {
    /// The assistant's settings (7.7.1, 7.8.1).
    AssistantSettings ["assistant"] {
        /// Assistant jobs per day per hub; 0 starts none.
        daily_cap = ASSISTANT_DAILY_CAP(20, 0, 500),
        /// Assistant job deadline, in minutes, when its playbook sets none.
        deadline_min = ASSISTANT_DEADLINE(30, 5, 120),
        /// Assistant max turns.
        max_turns = ASSISTANT_MAX_TURNS(60, 10, 200),
    }
}

section! {
    /// Routing incidents (7.5.2).
    IncidentSettings ["incidents"] {
        /// Automatic runbook starts per incident in any 24 hours.
        runbook_starts_24h = RUNBOOK_STARTS(2, 1, 10),
        /// Assistant jobs per incident in any 24 hours.
        assistant_jobs_24h = ASSISTANT_JOBS_PER_INCIDENT(1, 1, 5),
        /// How long to wait for the condition to clear after a job, in minutes.
        clear_wait_min = CLEAR_WAIT(10, 2, 60),
    }
}

section! {
    /// Connection records (7.4.1).
    ConnectionSettings ["connections"] {
        /// Connection records per machine per day.
        records_per_day = CONNECTION_RECORDS(20_000, 1_000, 200_000),
    }
}

section! {
    /// Jobs (7.4.1).
    JobSettings ["jobs"] {
        /// The job output and transcript budget, in MB (20 GB at most).
        output_budget_mb = OUTPUT_BUDGET(100, 50, 20 * 1024),
    }
}

section! {
    /// Approvals (7.6.8); a patch approval lasts to the end of its window instead.
    ApprovalSettings ["approvals"] {
        /// Approval expiry, in hours (7 days at most).
        expiry_h = APPROVAL_EXPIRY(24, 1, 7 * 24),
    }
}

section! {
    /// Sign-in (7.7.2).
    AuthSettings ["auth"] {
        /// Step-up freshness, in minutes.
        step_up_min = STEP_UP(5, 1, 15),
    }
}

section! {
    /// Baselines (7.6.4, 7.6.5).
    BaselineSettings ["baseline"] {
        /// Baseline learning, in days: the metric baselines and the connection baseline.
        learning_days = BASELINE_LEARNING(7, 1, 30),
    }
}

section! {
    /// Retention of the metric tiers (7.4.1).
    RetentionTiers ["retention"] {
        /// Tier 0, in hours (12 h to 7 d).
        tier0_h = RETENTION_TIER0(48, 12, 7 * 24),
        /// Tier 1, in days.
        tier1_days = RETENTION_TIER1(30, 7, 365),
        /// Tier 2, in days (30 d to 10 y).
        tier2_days = RETENTION_TIER2(365, 30, 3650),
    }
}

section! {
    /// Local backups (9).
    BackupSettings ["backups"] {
        /// Local backups kept.
        kept = BACKUPS_KEPT(2, 1, 14),
    }
}

const MIN_MS: i64 = 60_000;
const HOUR_MS: i64 = 60 * MIN_MS;
const DAY_MS: i64 = 24 * HOUR_MS;

impl PeerSettings {
    pub fn summary_every(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.summary_interval_s.into())
    }

    /// A peer is silent after the larger of 2 minutes and 3 summary intervals (7.8.1).
    pub fn silent_after_ms(&self) -> i64 {
        (2 * MIN_MS).max(3 * i64::from(self.summary_interval_s) * 1000)
    }
}

impl AssistantSettings {
    pub fn deadline_ms(&self) -> i64 {
        i64::from(self.deadline_min) * MIN_MS
    }
}

impl IncidentSettings {
    pub fn clear_wait_ms(&self) -> i64 {
        i64::from(self.clear_wait_min) * MIN_MS
    }
}

impl JobSettings {
    pub fn output_budget_bytes(&self) -> u64 {
        u64::from(self.output_budget_mb) * 1024 * 1024
    }
}

impl ApprovalSettings {
    pub fn expiry_ms(&self) -> i64 {
        i64::from(self.expiry_h) * HOUR_MS
    }
}

impl AuthSettings {
    pub fn step_up_ms(&self) -> i64 {
        i64::from(self.step_up_min) * MIN_MS
    }
}

impl BaselineSettings {
    pub fn learning_ms(&self) -> i64 {
        i64::from(self.learning_days) * DAY_MS
    }
}

impl RetentionTiers {
    /// The store's retention settings with these tiers (events keep their 90 days).
    pub fn store(&self) -> rackhand_store::retention::RetentionSettings {
        rackhand_store::retention::RetentionSettings {
            tier0_ms: i64::from(self.tier0_h) * HOUR_MS,
            tier1_ms: i64::from(self.tier1_days) * DAY_MS,
            tier2_ms: i64::from(self.tier2_days) * DAY_MS,
            ..rackhand_store::retention::RetentionSettings::default()
        }
    }
}

/// OIDC sign-in (7.7.2). The client secret is in the Vault; `client_secret` names it (`secret:<name>`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Oidc {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// The hub's callback as registered with the provider: `https://<hub>/sign-in/oidc/callback`.
    pub redirect_url: String,
}

/// The library's git mirror (7.3.13). The deploy key is in the Vault, never here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GitMirror {
    pub url: String,
    #[serde(default = "main_branch")]
    pub branch: String,
    /// The server's SHA-256 host key, learned on the first push.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_fingerprint: Option<String>,
}

fn main_branch() -> String {
    "main".into()
}

impl HubConfig {
    pub fn to_toml(&self) -> String {
        toml::to_string(self).unwrap_or_default()
    }

    /// Every setting of every section with its value, which `f` may change.
    fn visit(&mut self, f: &mut dyn FnMut(&'static Setting, &mut i64)) {
        self.probe.visit(f);
        self.assistant.visit(f);
        self.patching.visit(f);
        self.peers.visit(f);
        self.incidents.visit(f);
        self.connections.visit(f);
        self.jobs.visit(f);
        self.approvals.visit(f);
        self.auth.visit(f);
        self.baseline.visit(f);
        self.retention.visit(f);
        self.backups.visit(f);
    }

    /// The value of the setting `key` (`section.field`).
    pub fn value(&self, key: &str) -> Option<i64> {
        let mut found = None;
        self.clone().visit(&mut |s, v| {
            if s.key == key {
                found = Some(*v);
            }
        });
        found
    }

    /// The first setting out of its range.
    fn check(&self) -> Result<(), String> {
        let mut first = Ok(());
        self.clone().visit(&mut |s, v| {
            if first.is_ok() {
                first = s.check(*v);
            }
        });
        first
    }

    /// Brings each setting out of its range to the nearer end, naming each.
    fn clamp(&mut self) -> Vec<String> {
        let mut clamped = Vec::new();
        self.visit(&mut |s, v| {
            if let Err(e) = s.check(*v) {
                clamped.push(e);
                *v = (*v).clamp(s.min, s.max);
            }
        });
        clamped
    }
}

/// Every setting `config/hub.toml` has (7.8.1).
pub fn settings() -> Vec<&'static Setting> {
    let mut all = Vec::new();
    HubConfig::default().visit(&mut |s, _| all.push(s));
    all
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
    #[error("config/{0}.toml: {1}")]
    Parse(String, String),
}

/// The rows of a config item's first revision, to include in another command's transaction (first run).
pub fn first_revision_rows(name: &str, content: &str, author: &str, now_ms: i64) -> Vec<RowWrite> {
    let item: Row = [
        ("name", Value::Text(name.into())),
        ("kind", Value::Text("config".into())),
        ("origin", Value::Text("user".into())),
        ("rev", Value::Integer(1)),
    ]
    .into_iter()
    .collect();
    let rev: Row = [
        ("name", Value::Text(name.into())),
        ("kind", Value::Text("config".into())),
        ("rev", Value::Integer(1)),
        ("content", Value::Text(content.into())),
        ("author", Value::Text(author.into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    vec![RowWrite::insert("library_items", item), RowWrite::insert("library_revisions", rev)]
}

/// Stores a new revision; returns its number.
pub async fn put(db: &Arc<Db>, name: &str, content: &str, author: &str, now_ms: i64) -> Result<i64, ConfigError> {
    let row: Row = [
        ("kind", Value::Text("config".into())),
        ("name", Value::Text(name.into())),
        ("content", Value::Text(content.into())),
        ("author", Value::Text(author.into())),
        ("created_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    let ack = db.writer().send(WriteCmd::PutLibraryRevision(row)).await?;
    Ok(ack.rows as i64)
}

/// The current revision's content.
pub fn current(db: &Db, name: &str) -> Result<Option<String>, ConfigError> {
    Ok(db.readers().with(|c| current_on(c, name))?)
}

/// The current revision's content, read on a connection of the caller's (one that isn't the hub's own, as a backup's).
pub fn current_on(c: &rusqlite::Connection, name: &str) -> rusqlite::Result<Option<String>> {
    c.query_row(
        "SELECT r.content FROM library_items i JOIN library_revisions r ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev
         WHERE i.kind = 'config' AND i.name = ?1",
        [name],
        |r| r.get(0),
    )
    .optional()
}

/// The hub settings, defaults if none are stored yet. A stored value out of its range (saved before its range was
/// checked) is read as the nearer end of the range, with a warning, so the rest of the file still applies.
pub fn hub(db: &Db) -> Result<HubConfig, ConfigError> {
    match current(db, HUB)? {
        Some(text) => read_hub(&text),
        None => Ok(HubConfig::default()),
    }
}

/// The hub settings, or their defaults when the stored file can't be read (with a warning): for the consumers of one
/// setting, which go on with its default.
pub fn hub_or_default(db: &Db) -> HubConfig {
    hub(db).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "hub settings: using the defaults");
        HubConfig::default()
    })
}

/// `config/hub.toml` as saved: every value in its range (7.8.1), else refused naming the key and the range.
pub fn parse_hub(text: &str) -> Result<HubConfig, ConfigError> {
    let cfg = from_toml(text)?;
    cfg.check().map_err(|e| ConfigError::Parse(HUB.into(), e))?;
    Ok(cfg)
}

/// `config/hub.toml` as read: a value out of its range is brought to the nearer end.
pub fn read_hub(text: &str) -> Result<HubConfig, ConfigError> {
    let mut cfg = from_toml(text)?;
    // read often (per probe report, per series query), so not a warning each time; saving the file names the value
    for e in cfg.clamp() {
        tracing::debug!(setting = %e, "config/hub.toml: out of range, the nearer end is used");
    }
    Ok(cfg)
}

fn from_toml(text: &str) -> Result<HubConfig, ConfigError> {
    toml::from_str(text).map_err(|e| ConfigError::Parse(HUB.into(), e.to_string()))
}
