//! Library items (7.2, Library; FR-24): runbooks, playbooks and configuration, each change a new revision after
//! validation, with drafts proposed by assistants and applied from the dashboard. Every change is audited and
//! announced to the git mirror.

use std::sync::Arc;

use rackhand_runbook::playbook::Playbook;
use rackhand_runbook::runbook::Runbook;
use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;
use tokio::sync::mpsc;

use crate::audit::Audit;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Kind {
    Runbook,
    Playbook,
    Config,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Runbook => "runbook",
            Kind::Playbook => "playbook",
            Kind::Config => "config",
        }
    }

    pub fn parse(s: &str) -> Option<Kind> {
        Some(match s {
            "runbook" => Kind::Runbook,
            "playbook" => Kind::Playbook,
            "config" => Kind::Config,
            _ => return None,
        })
    }

    /// The item's path in the mirror (7.3.13).
    pub fn path(self, name: &str) -> String {
        match self {
            Kind::Runbook => format!("runbooks/{name}.toml"),
            Kind::Playbook => format!("playbooks/{name}.md"),
            Kind::Config => format!("config/{name}.toml"),
        }
    }
}

/// A change for the git mirror's commit message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Change {
    pub user: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryEntry {
    pub rev: i64,
    pub author: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SaveError {
    #[error("{0}")]
    Invalid(String),
    #[error("store: {0}")]
    Store(String),
}

impl From<StoreError> for SaveError {
    fn from(e: StoreError) -> Self {
        SaveError::Store(e.to_string())
    }
}

impl From<rusqlite::Error> for SaveError {
    fn from(e: rusqlite::Error) -> Self {
        SaveError::Store(e.to_string())
    }
}

#[derive(Debug, Clone)]
pub struct Library {
    db: Arc<Db>,
    audit: Audit,
    changes: mpsc::UnboundedSender<Change>,
}

fn valid_name(name: &str) -> bool {
    (1..=64).contains(&name.len()) && name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// The validation errors for content of a kind (runbooks and playbooks as in 7.8.7 and 7.8.8; configuration as TOML).
pub fn validate(kind: Kind, name: &str, content: &str) -> Result<(), String> {
    if !valid_name(name) {
        return Err(format!("name `{name}`: 1 to 64 of a-z, 0-9 and -"));
    }
    let declared = match kind {
        Kind::Runbook => Runbook::parse(content).map_err(|e| e.to_string())?.name,
        Kind::Playbook => Playbook::parse(content).map_err(|e| e.to_string())?.name,
        Kind::Config => {
            toml::from_str::<toml::Table>(content).map_err(|e| e.to_string())?;
            return Ok(());
        }
    };
    if declared != name {
        return Err(format!("the file's name is `{declared}`, not `{name}`"));
    }
    Ok(())
}

impl Library {
    pub fn new(db: Arc<Db>, audit: Audit) -> (Library, mpsc::UnboundedReceiver<Change>) {
        let (changes, rx) = mpsc::unbounded_channel();
        (Library { db, audit, changes }, rx)
    }

    /// Validates and stores a new revision; returns its number.
    pub async fn save(
        &self,
        kind: Kind,
        name: &str,
        content: &str,
        author: &str,
        now_ms: i64,
    ) -> Result<i64, SaveError> {
        validate(kind, name, content).map_err(SaveError::Invalid)?;
        let row: Row = [
            ("kind", Value::Text(kind.as_str().into())),
            ("name", Value::Text(name.into())),
            ("content", Value::Text(content.into())),
            ("author", Value::Text(author.into())),
            ("created_at", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        let rev = self.db.writer().send(WriteCmd::PutLibraryRevision(row)).await?.rows as i64;
        let target = format!("{}/{name}", kind.as_str());
        let _ = self
            .audit
            .append(author, "library.saved", Some(&target), &serde_json::json!({ "rev": rev }).to_string())
            .await;
        let verb = if rev == 1 { "add" } else { "edit" };
        let _ = self.changes.send(Change { user: author.into(), summary: format!("{verb} {target}") });
        Ok(rev)
    }

    pub fn current(&self, kind: Kind, name: &str) -> Result<Option<(i64, String)>, SaveError> {
        Library::current_in(&self.db, kind, name)
    }

    /// The current revision and content, read from the database (for systems that only read the library).
    pub fn current_in(db: &Db, kind: Kind, name: &str) -> Result<Option<(i64, String)>, SaveError> {
        Ok(db.readers().with(|c| {
            c.query_row(
                "SELECT i.rev, r.content FROM library_items i JOIN library_revisions r ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev
                 WHERE i.kind = ?1 AND i.name = ?2",
                [kind.as_str(), name],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()
        })?)
    }

    pub fn revision(&self, kind: Kind, name: &str, rev: i64) -> Result<Option<String>, SaveError> {
        Library::revision_in(&self.db, kind, name, rev)
    }

    pub fn revision_in(db: &Db, kind: Kind, name: &str, rev: i64) -> Result<Option<String>, SaveError> {
        Ok(db.readers().with(|c| {
            c.query_row(
                "SELECT content FROM library_revisions WHERE kind = ?1 AND name = ?2 AND rev = ?3",
                rusqlite::params![kind.as_str(), name, rev],
                |r| r.get(0),
            )
            .optional()
        })?)
    }

    /// Newest first.
    pub fn history(&self, kind: Kind, name: &str) -> Result<Vec<HistoryEntry>, SaveError> {
        Ok(self.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT rev, author, created_at FROM library_revisions WHERE kind = ?1 AND name = ?2 ORDER BY rev DESC",
            )?;
            let rows = s.query_map([kind.as_str(), name], |r| {
                Ok(HistoryEntry { rev: r.get(0)?, author: r.get(1)?, created_at: r.get(2)? })
            })?;
            rows.collect()
        })?)
    }

    /// Every item's current content, for the mirror.
    pub fn all_current(db: &Db) -> Result<Vec<(Kind, String, String)>, SaveError> {
        let rows: Vec<(String, String, String)> = db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT i.kind, i.name, r.content FROM library_items i JOIN library_revisions r ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev",
            )?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })?;
        Ok(rows.into_iter().filter_map(|(k, n, c)| Some((Kind::parse(&k)?, n, c))).collect())
    }

    /// An assistant's proposal (`propose_library_change`); applied only from the dashboard.
    pub async fn propose(
        &self,
        kind: Kind,
        name: &str,
        content: &str,
        by: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<String, SaveError> {
        if !valid_name(name) {
            return Err(SaveError::Invalid(format!("name `{name}`: 1 to 64 of a-z, 0-9 and -")));
        }
        let id = ulid::Ulid::new().to_string();
        let row: Row = [
            ("id", Value::Text(id.clone())),
            ("name", Value::Text(name.into())),
            ("kind", Value::Text(kind.as_str().into())),
            ("content", Value::Text(content.into())),
            ("proposed_by", Value::Text(by.into())),
            ("reason", Value::Text(reason.into())),
            ("created_at", Value::Integer(now_ms)),
        ]
        .into_iter()
        .collect();
        self.db.writer().send(WriteCmd::PutDraft(row)).await?;
        let target = format!("{}/{name}", kind.as_str());
        let _ = self
            .audit
            .append(
                by,
                "library.draft_proposed",
                Some(&target),
                &serde_json::json!({ "draft": id, "reason": reason }).to_string(),
            )
            .await;
        Ok(id)
    }

    /// Applies a pending draft as a new revision.
    pub async fn apply_draft(&self, id: &str, by: &str, now_ms: i64) -> Result<i64, SaveError> {
        let draft: Option<(String, String, String)> = self.db.readers().with(|c| {
            c.query_row(
                "SELECT kind, name, content FROM library_drafts WHERE id = ?1 AND state = 'pending'",
                [id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
        })?;
        let (kind, name, content) = draft.ok_or_else(|| SaveError::Invalid("no pending draft with that id".into()))?;
        let kind = Kind::parse(&kind).ok_or_else(|| SaveError::Invalid("unknown kind".into()))?;
        let rev = self.save(kind, &name, &content, by, now_ms).await?;
        let mark: Row =
            [("id", Value::Text(id.into())), ("state", Value::Text("applied".into()))].into_iter().collect();
        self.db.writer().send(WriteCmd::PutDraft(mark)).await?;
        Ok(rev)
    }
}
