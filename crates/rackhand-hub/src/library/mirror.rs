//! The git mirror (7.3.13): the library and configuration as files, committed and pushed over SSH with the deploy key
//! from the Vault, 30 seconds after the first of a run of changes. A push that the scan finds a secret in is never
//! made; a failed push raises `git_mirror_failed` (warning) and is retried hourly. Never a force push.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rackhand_store::Db;
use tokio::sync::mpsc;

use super::items::{Change, Kind, Library, SaveError};
use super::scan::{Finding, scan};
use crate::audit::Audit;
use crate::vault::Vault;

pub const DEBOUNCE_MS: i64 = 30_000;
pub const RETRY_MS: i64 = 3_600_000;
pub const DEPLOY_KEY: &str = "git.deploy_key";

/// The files of the mirror, by path.
pub fn render(db: &Db) -> Result<BTreeMap<String, String>, SaveError> {
    let mut files = BTreeMap::new();
    let mut items: Vec<(Kind, String, String)> = Library::all_current(db)?;
    items.sort();
    let mut readme = String::from(
        "# Rackhand library\n\nThis repository mirrors the hub's runbooks, playbooks and configuration. It is written by \
         the hub on every change; edit them in the dashboard. Secrets never appear here: settings refer to them as \
         `secret:<name>`, and the values stay in the hub's Vault.\n",
    );
    for (title, kind) in [("Runbooks", Kind::Runbook), ("Playbooks", Kind::Playbook), ("Configuration", Kind::Config)] {
        let mine: Vec<&(Kind, String, String)> = items.iter().filter(|(k, _, _)| *k == kind).collect();
        if mine.is_empty() {
            continue;
        }
        readme.push_str(&format!("\n## {title}\n\n"));
        for (k, name, _) in &mine {
            readme.push_str(&format!("- [`{name}`]({})\n", k.path(name)));
        }
    }
    for (kind, name, content) in items {
        files.insert(kind.path(&name), content);
    }
    readme.push_str("\nRestore a hub from this repository with `rackhand hub restore-library <checkout>`.\n");
    // The configuration README entry names the file path, so `config/hub.toml` appears too.
    files.insert("README.md".into(), readme);
    Ok(files)
}

/// Collects changes until 30 seconds after the first, then gives the commit message `<users>: <summaries>`.
#[derive(Debug, Clone)]
pub struct Debounce {
    window_ms: i64,
    first_ms: Option<i64>,
    users: Vec<String>,
    summaries: Vec<String>,
}

impl Debounce {
    pub fn new(window_ms: i64) -> Debounce {
        Debounce { window_ms, first_ms: None, users: Vec::new(), summaries: Vec::new() }
    }

    pub fn push(&mut self, now_ms: i64, user: &str, summary: &str) {
        self.first_ms.get_or_insert(now_ms);
        if !self.users.iter().any(|u| u == user) {
            self.users.push(user.into());
        }
        self.summaries.push(summary.into());
    }

    pub fn due_at(&self) -> Option<i64> {
        self.first_ms.map(|f| f + self.window_ms)
    }

    pub fn take_due(&mut self, now_ms: i64) -> Option<String> {
        if self.due_at().is_none_or(|d| now_ms < d) {
            return None;
        }
        let message = format!("{}: {}", self.users.join(", "), self.summaries.join("; "));
        *self = Debounce::new(self.window_ms);
        Some(message)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// `ssh://user@host[:port]/path`.
    pub url: String,
    pub branch: String,
    /// The server's host key (SHA-256); learned on the first push if not set, then required.
    pub host_fingerprint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MirrorError {
    #[error("the content holds secrets: {0:?}")]
    SecretFound(Vec<(String, Finding)>),
    #[error("git: {0}")]
    Git(String),
    #[error("the mirror's host key changed")]
    HostKeyChanged,
}

impl From<git2::Error> for MirrorError {
    fn from(e: git2::Error) -> Self {
        MirrorError::Git(e.message().to_string())
    }
}

/// The scan over every file.
pub fn scan_files(files: &BTreeMap<String, String>, vault_values: &[Vec<u8>]) -> Vec<(String, Finding)> {
    files.iter().flat_map(|(path, text)| scan(text, vault_values).into_iter().map(move |f| (path.clone(), f))).collect()
}

/// Writes the files into the work tree, commits and pushes. Returns the commit id and the server's host key.
pub fn commit_and_push(
    workdir: &Path,
    files: &BTreeMap<String, String>,
    message: &str,
    deploy_key_pem: &str,
    target: &Target,
) -> Result<(String, Option<String>), MirrorError> {
    let repo = match git2::Repository::open(workdir) {
        Ok(r) => r,
        Err(_) => {
            std::fs::create_dir_all(workdir).map_err(|e| MirrorError::Git(e.to_string()))?;
            git2::Repository::init(workdir)?
        }
    };
    // Exactly these files: anything else in the tree is removed.
    for entry in walk(workdir) {
        let rel = entry.strip_prefix(workdir).unwrap_or(&entry).to_string_lossy().replace('\\', "/");
        if !files.contains_key(&rel) {
            let _ = std::fs::remove_file(&entry);
        }
    }
    for (path, text) in files {
        let full = workdir.join(path);
        if let Some(parent) = full.parent() {
            std::fs::create_dir_all(parent).map_err(|e| MirrorError::Git(e.to_string()))?;
        }
        std::fs::write(&full, text).map_err(|e| MirrorError::Git(e.to_string()))?;
    }
    let mut index = repo.index()?;
    index.add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)?;
    index.update_all(["*"].iter(), None)?;
    index.write()?;
    let tree = repo.find_tree(index.write_tree()?)?;
    let sig = git2::Signature::now("Rackhand", "rackhand@hub.invalid")?;
    let parent = repo.head().ok().and_then(|h| h.peel_to_commit().ok());
    let refname = format!("refs/heads/{}", target.branch);
    let unchanged = parent.as_ref().is_some_and(|p| p.tree_id() == tree.id());
    let commit = if unchanged {
        parent.as_ref().map(|p| p.id()).ok_or_else(|| MirrorError::Git("no commit".into()))?
    } else {
        let parents: Vec<&git2::Commit<'_>> = parent.iter().collect();
        repo.commit(Some(&refname), &sig, &sig, message, &tree, &parents)?
    };
    repo.set_head(&refname)?;
    let seen = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let mut callbacks = git2::RemoteCallbacks::new();
    let key = deploy_key_pem.to_string();
    callbacks.credentials(move |_url, user, _allowed| {
        git2::Cred::ssh_key_from_memory(user.unwrap_or("git"), None, &key, None)
    });
    let expected = target.host_fingerprint.clone();
    let seen_cb = seen.clone();
    callbacks.certificate_check(move |cert, _host| {
        let Some(hostkey) = cert.as_hostkey() else { return Err(git2::Error::from_str("not an SSH host key")) };
        let Some(sha) = hostkey.hash_sha256() else { return Err(git2::Error::from_str("no SHA-256 host key hash")) };
        let fp = sha.iter().map(|b| format!("{b:02x}")).collect::<String>();
        if let Ok(mut s) = seen_cb.lock() {
            *s = Some(fp.clone());
        }
        match &expected {
            Some(e) if *e != fp => Err(git2::Error::from_str("host key changed")),
            _ => Ok(git2::CertificateCheckStatus::CertificateOk),
        }
    });
    let mut options = git2::PushOptions::new();
    options.remote_callbacks(callbacks);
    let mut remote = repo.remote_anonymous(&target.url)?;
    let pushed = remote.push(&[format!("{refname}:{refname}")], Some(&mut options));
    let seen = seen.lock().ok().and_then(|s| s.clone());
    if let Err(e) = pushed {
        if target.host_fingerprint.is_some() && seen.as_ref() != target.host_fingerprint.as_ref() {
            return Err(MirrorError::HostKeyChanged);
        }
        return Err(e.into());
    }
    Ok((commit.to_string(), seen))
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RestoreReport {
    pub restored: usize,
    /// Files that weren't stored, with the reason.
    pub refused: Vec<(String, String)>,
}

/// `rackhand hub restore-library <checkout>`: every runbook, playbook and config file of a mirror checkout becomes a
/// new revision (after the same validation as an edit).
pub async fn restore(lib: &Library, checkout: &Path, now_ms: i64) -> RestoreReport {
    let mut report = RestoreReport::default();
    let mut files = walk(checkout);
    files.sort();
    for path in files {
        let rel = path.strip_prefix(checkout).unwrap_or(&path).to_string_lossy().replace('\\', "/");
        let parsed = [
            ("runbooks/", ".toml", Kind::Runbook),
            ("playbooks/", ".md", Kind::Playbook),
            ("config/", ".toml", Kind::Config),
        ]
        .into_iter()
        .find_map(|(dir, ext, kind)| Some((kind, rel.strip_prefix(dir)?.strip_suffix(ext)?.to_string())));
        let Some((kind, name)) = parsed.filter(|(_, n)| !n.contains('/')) else { continue };
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                report.refused.push((rel, e.to_string()));
                continue;
            }
        };
        match lib.save(kind, &name, &content, "restore", now_ms).await {
            Ok(_) => report.restored += 1,
            Err(e) => report.refused.push((rel, e.to_string())),
        }
    }
    report
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else { return out };
    for e in entries.flatten() {
        let p = e.path();
        if p.file_name().is_some_and(|n| n == ".git") {
            continue;
        }
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MirrorAlert {
    /// `git_mirror_failed` (warning).
    Failed {
        error: String,
        retry_at_ms: i64,
    },
    /// The scan found secrets; nothing was pushed (critical, audited).
    SecretBlocked {
        findings: Vec<(String, Finding)>,
    },
    Pushed {
        commit: String,
    },
}

impl MirrorAlert {
    pub fn kind(&self) -> &'static str {
        match self {
            MirrorAlert::Failed { .. } => "git_mirror_failed",
            MirrorAlert::SecretBlocked { .. } => "git_mirror_secret_blocked",
            MirrorAlert::Pushed { .. } => "git_mirror_pushed",
        }
    }
    pub fn severity(&self) -> &'static str {
        match self {
            MirrorAlert::Failed { .. } => "warning",
            MirrorAlert::SecretBlocked { .. } => "critical",
            MirrorAlert::Pushed { .. } => "info",
        }
    }
}

/// What the mirror worker needs.
pub struct Mirror {
    pub db: Arc<Db>,
    pub vault: Arc<Vault>,
    pub audit: Audit,
    pub workdir: PathBuf,
    /// The current target from the settings; `None` while no mirror is configured.
    pub target: Arc<dyn Fn() -> Option<Target> + Send + Sync>,
    pub debounce_ms: i64,
    pub clock: Arc<dyn Fn() -> i64 + Send + Sync>,
}

impl std::fmt::Debug for Mirror {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Mirror").field("workdir", &self.workdir).finish()
    }
}

impl Mirror {
    /// One attempt: render, scan, push.
    pub async fn sync(&self, message: &str) -> MirrorAlert {
        let now = (self.clock)();
        let Some(target) = (self.target)() else {
            return MirrorAlert::Failed { error: "no mirror configured".into(), retry_at_ms: now + RETRY_MS };
        };
        let files = match render(&self.db) {
            Ok(f) => f,
            Err(e) => return MirrorAlert::Failed { error: e.to_string(), retry_at_ms: now + RETRY_MS },
        };
        let values: Vec<Vec<u8>> = self.vault.all_values().iter().map(|s| s.expose().to_vec()).collect();
        let findings = scan_files(&files, &values);
        if !findings.is_empty() {
            let paths: Vec<&str> = findings.iter().map(|(p, _)| p.as_str()).collect();
            let data = serde_json::json!({ "severity": "critical", "files": paths }).to_string();
            let _ = self.audit.append("rackhand", "git_mirror.secret_blocked", Some(&target.url), &data).await;
            return MirrorAlert::SecretBlocked { findings };
        }
        let Ok(key) = self.vault.get(DEPLOY_KEY) else {
            return MirrorAlert::Failed { error: "no deploy key".into(), retry_at_ms: now + RETRY_MS };
        };
        let pem = String::from_utf8_lossy(key.expose()).into_owned();
        let (workdir, message, t) = (self.workdir.clone(), message.to_string(), target.clone());
        let pushed = tokio::task::spawn_blocking(move || commit_and_push(&workdir, &files, &message, &pem, &t)).await;
        match pushed {
            Ok(Ok((commit, _))) => MirrorAlert::Pushed { commit },
            Ok(Err(e)) => MirrorAlert::Failed { error: e.to_string(), retry_at_ms: now + RETRY_MS },
            Err(e) => MirrorAlert::Failed { error: e.to_string(), retry_at_ms: now + RETRY_MS },
        }
    }

    /// Runs until the change channel closes: debounces changes, then syncs; retries a failure hourly.
    pub fn spawn(self, mut changes: mpsc::UnboundedReceiver<Change>) -> mpsc::UnboundedReceiver<MirrorAlert> {
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut debounce = Debounce::new(self.debounce_ms);
            let mut retry: Option<(i64, String)> = None;
            loop {
                let now = (self.clock)();
                let wake = [debounce.due_at(), retry.as_ref().map(|(t, _)| *t)].into_iter().flatten().min();
                let sleep = wake.map_or(Duration::from_secs(3600), |w| Duration::from_millis((w - now).max(0) as u64));
                tokio::select! {
                    change = changes.recv() => match change {
                        Some(c) => debounce.push((self.clock)(), &c.user, &c.summary),
                        None => return,
                    },
                    _ = tokio::time::sleep(sleep) => {
                        let now = (self.clock)();
                        let message = match debounce.take_due(now) {
                            Some(m) => Some(m),
                            None => retry.take_if(|(t, _)| *t <= now).map(|(_, m)| m),
                        };
                        if let Some(message) = message {
                            let alert = self.sync(&message).await;
                            if let MirrorAlert::Failed { retry_at_ms, .. } = &alert {
                                retry = Some((*retry_at_ms, message));
                            } else {
                                retry = None;
                            }
                            let _ = tx.send(alert);
                        }
                    }
                }
            }
        });
        rx
    }
}

#[cfg(test)]
#[path = "mirror_tests.rs"]
mod tests;
