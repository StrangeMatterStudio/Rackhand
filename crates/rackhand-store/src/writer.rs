//! The single writer (7.3.8, 11): every write is a [`WriteCmd`] sent to one task, which runs each command in its own
//! transaction in the order commands were sent.

use std::collections::BTreeMap;
use std::path::Path;

use rusqlite::Connection;
use rusqlite::types::Value;
use tokio::sync::{mpsc, oneshot};

/// Column name to value. Column and table names come from code, never from input.
pub type Row = BTreeMap<&'static str, Value>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteMode {
    Insert,
    Replace,
    /// Insert only if the table has no rows yet; otherwise the whole command fails with `Conflict` (the first admin).
    InsertIfTableEmpty,
}

/// One row written to one table.
#[derive(Debug, Clone)]
pub struct RowWrite {
    pub table: &'static str,
    pub row: Row,
    pub mode: WriteMode,
}

impl RowWrite {
    pub fn insert(table: &'static str, row: Row) -> RowWrite {
        RowWrite { table, row, mode: WriteMode::Insert }
    }

    pub fn replace(table: &'static str, row: Row) -> RowWrite {
        RowWrite { table, row, mode: WriteMode::Replace }
    }
}

/// An update of chosen columns of the one row whose `key` column has the given value; it fails if no row matches.
#[derive(Debug, Clone)]
pub struct RowUpdate {
    pub table: &'static str,
    pub key: (&'static str, Value),
    pub set: Row,
}

/// A join token to use up (7.3.1): it must exist, be unused, unexpired at `now_ms` and of `kind`.
#[derive(Debug, Clone)]
pub struct ConsumeToken {
    pub hash: Vec<u8>,
    pub kind: String,
    pub now_ms: i64,
}

/// Why a join token wasn't used up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRefusal {
    Unknown,
    Used,
    Expired,
    WrongKind,
}

/// The Registry's writes: optionally uses up a join token, then inserts and updates rows, all in one transaction, so
/// a token can't join twice and a refused join changes nothing.
#[derive(Debug, Clone, Default)]
pub struct RegistryChange {
    pub consume: Option<ConsumeToken>,
    pub writes: Vec<RowWrite>,
    pub updates: Vec<RowUpdate>,
}

/// The write operations of design 7.3.8. Each system sends commands only for the tables it owns (7.2). A variant's
/// handler returns [`StoreError::Unimplemented`] until the step that builds its owning system.
#[derive(Debug, Clone)]
pub enum WriteCmd {
    // Ingest
    StageReport(Row),
    CompactStaged,
    PutProbeLabels(Vec<Row>),
    PutEvents(Vec<Row>),
    PutConnRecords(Vec<Row>),
    UpdateBaselines(Vec<Row>),
    PutConnBaseline(Vec<Row>),
    MarkRollupDirty(Row),
    // Checks
    PutCheck(Row),
    PutCheckResults(Vec<Row>),
    // SSH
    PutHostKey(Row),
    // Incidents
    UpsertIncident(Row),
    AppendIncidentEvent(Row),
    PutSilence(Row),
    // Actions
    CreateJob(Row),
    UpdateJobStep(Row),
    FinishJob(Row),
    AppendTranscript(Row),
    // Policy
    PutPolicy(Row),
    CreateApproval(Row),
    DecideApproval(Row),
    UseApproval(String),
    PutQuarantineRule(Row),
    PutWindow(Row),
    // Registry, Peers, Assist, MCP, Web
    RegistryChange(RegistryChange),
    PutPeerSummary(Row),
    PutJobToken(Row),
    PutMcpKey(Row),
    PutUser(Row),
    PutCredential(Row),
    PutSession(Row),
    PutKnownDevice(Row),
    // Library, Vault, Notify, Audit, Scheduler
    CreateLibraryItem(Row),
    PutLibraryRevision(Row),
    PutDraft(Row),
    PutSecret(Row),
    PutNotification(Row),
    AppendAudit(Row),
    AppendAuditCheckpoint(Row),
    PutScheduleState(Row),
    // Store maintenance
    RetentionBatch(String),
    Rollup {
        tier: u8,
        from_ms: i64,
        to_ms: i64,
    },
    /// Rows for several tables in one transaction (the building block owning systems use).
    Batch(Vec<RowWrite>),
}

impl WriteCmd {
    pub fn name(&self) -> &'static str {
        macro_rules! names {
            ($($v:ident),*) => { match self { $(WriteCmd::$v { .. } => stringify!($v),)* } };
        }
        names!(
            StageReport,
            CompactStaged,
            PutProbeLabels,
            PutEvents,
            PutConnRecords,
            UpdateBaselines,
            PutConnBaseline,
            MarkRollupDirty,
            PutCheck,
            PutCheckResults,
            PutHostKey,
            UpsertIncident,
            AppendIncidentEvent,
            PutSilence,
            CreateJob,
            UpdateJobStep,
            FinishJob,
            AppendTranscript,
            PutPolicy,
            CreateApproval,
            DecideApproval,
            UseApproval,
            PutQuarantineRule,
            PutWindow,
            RegistryChange,
            PutPeerSummary,
            PutJobToken,
            PutMcpKey,
            PutUser,
            PutCredential,
            PutSession,
            PutKnownDevice,
            CreateLibraryItem,
            PutLibraryRevision,
            PutDraft,
            PutSecret,
            PutNotification,
            AppendAudit,
            AppendAuditCheckpoint,
            PutScheduleState,
            RetentionBatch,
            Rollup,
            Batch
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAck {
    /// The commit sequence number: commands commit in send order.
    pub seq: u64,
    pub rows: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("write command {0} isn't implemented yet")]
    Unimplemented(&'static str),
    #[error("invalid identifier `{0}`")]
    InvalidIdentifier(String),
    #[error("command is missing column `{0}`")]
    MissingColumn(&'static str),
    #[error("the store writer has stopped")]
    WriterStopped,
    #[error("join token refused: {0:?}")]
    TokenRefused(TokenRefusal),
    #[error("no `{0}` row to update")]
    NoSuchRow(&'static str),
    /// A conditional update found the row no longer in the state it needed (decided, used).
    #[error("conflict: {0}")]
    Conflict(&'static str),
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

type Reply = oneshot::Sender<Result<WriteAck, StoreError>>;

#[derive(Debug, Clone)]
pub struct StoreWriter {
    tx: mpsc::Sender<(WriteCmd, Reply)>,
}

impl StoreWriter {
    pub(crate) fn spawn(path: &Path) -> rusqlite::Result<StoreWriter> {
        let conn = Connection::open(path)?;
        crate::db::configure(&conn)?;
        let (tx, mut rx) = mpsc::channel::<(WriteCmd, Reply)>(4096);
        std::thread::Builder::new()
            .name("store-writer".into())
            .spawn(move || {
                let mut conn = conn;
                let mut seq = 0u64;
                while let Some((cmd, reply)) = rx.blocking_recv() {
                    let result = apply(&mut conn, cmd).map(|rows| {
                        seq += 1;
                        WriteAck { seq, rows }
                    });
                    let _ = reply.send(result);
                }
            })
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(StoreWriter { tx })
    }

    /// Queues a command and returns the receiver for its result; commands commit in the order they were queued.
    pub async fn enqueue(&self, cmd: WriteCmd) -> Result<oneshot::Receiver<Result<WriteAck, StoreError>>, StoreError> {
        let (reply, rx) = oneshot::channel();
        self.tx.send((cmd, reply)).await.map_err(|_| StoreError::WriterStopped)?;
        Ok(rx)
    }

    /// Sends a command and waits until it has committed (or failed).
    pub async fn send(&self, cmd: WriteCmd) -> Result<WriteAck, StoreError> {
        self.enqueue(cmd).await?.await.map_err(|_| StoreError::WriterStopped)?
    }
}

fn check_ident(s: &str) -> Result<(), StoreError> {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_') {
        Ok(())
    } else {
        Err(StoreError::InvalidIdentifier(s.to_string()))
    }
}

fn write_row(tx: &rusqlite::Transaction<'_>, w: &RowWrite) -> Result<usize, StoreError> {
    check_ident(w.table)?;
    let cols: Vec<&str> = w.row.keys().copied().collect();
    for c in &cols {
        check_ident(c)?;
    }
    let verb = match w.mode {
        WriteMode::Insert => "INSERT",
        WriteMode::Replace => "INSERT OR REPLACE",
        WriteMode::InsertIfTableEmpty => {
            let empty: bool =
                tx.query_row(&format!("SELECT NOT EXISTS (SELECT 1 FROM {})", w.table), [], |r| r.get(0))?;
            if !empty {
                return Err(StoreError::Conflict("the table already has rows"));
            }
            "INSERT"
        }
    };
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let quoted: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
    let sql = format!("{verb} INTO {} ({}) VALUES ({})", w.table, quoted.join(", "), placeholders.join(", "));
    let values: Vec<&Value> = w.row.values().collect();
    Ok(tx.execute(&sql, rusqlite::params_from_iter(values))?)
}

fn consume_token(tx: &rusqlite::Transaction<'_>, t: &ConsumeToken) -> Result<usize, StoreError> {
    use rusqlite::OptionalExtension;
    let found: Option<(String, i64, Option<i64>)> = tx
        .query_row("SELECT kind, expires_at, used_at FROM join_tokens WHERE hash = ?1", [&t.hash], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })
        .optional()?;
    let refusal = match found {
        None => Some(TokenRefusal::Unknown),
        Some((kind, _, _)) if kind != t.kind => Some(TokenRefusal::WrongKind),
        Some((_, _, Some(_))) => Some(TokenRefusal::Used),
        Some((_, expires_at, None)) if expires_at <= t.now_ms => Some(TokenRefusal::Expired),
        Some(_) => None,
    };
    if let Some(r) = refusal {
        return Err(StoreError::TokenRefused(r));
    }
    Ok(tx.execute(
        "UPDATE join_tokens SET used_at = ?1 WHERE hash = ?2 AND used_at IS NULL",
        rusqlite::params![t.now_ms, t.hash],
    )?)
}

fn update_row(tx: &rusqlite::Transaction<'_>, u: &RowUpdate) -> Result<usize, StoreError> {
    check_ident(u.table)?;
    check_ident(u.key.0)?;
    let cols: Vec<&str> = u.set.keys().copied().collect();
    for c in &cols {
        check_ident(c)?;
    }
    let sets: Vec<String> = cols.iter().enumerate().map(|(i, c)| format!("\"{c}\" = ?{}", i + 1)).collect();
    let sql = format!("UPDATE {} SET {} WHERE \"{}\" = ?{}", u.table, sets.join(", "), u.key.0, cols.len() + 1);
    let values: Vec<&Value> = u.set.values().chain(std::iter::once(&u.key.1)).collect();
    match tx.execute(&sql, rusqlite::params_from_iter(values))? {
        0 => Err(StoreError::NoSuchRow(u.table)),
        n => Ok(n),
    }
}

/// Inserts the row, or updates the given columns of the existing one (never a delete and re-insert, which would break
/// rows that reference it).
fn upsert_one(conn: &mut Connection, table: &'static str, key: &'static str, row: Row) -> Result<usize, StoreError> {
    check_ident(table)?;
    check_ident(key)?;
    let cols: Vec<&str> = row.keys().copied().collect();
    for c in &cols {
        check_ident(c)?;
    }
    let quoted: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let updates: Vec<String> =
        cols.iter().filter(|c| **c != key).map(|c| format!("\"{c}\" = excluded.\"{c}\"")).collect();
    let sql = format!(
        "INSERT INTO {table} ({}) VALUES ({}) ON CONFLICT(\"{key}\") DO {}",
        quoted.join(", "),
        placeholders.join(", "),
        if updates.is_empty() { "NOTHING".to_string() } else { format!("UPDATE SET {}", updates.join(", ")) }
    );
    let values: Vec<&Value> = row.values().collect();
    Ok(conn.execute(&sql, rusqlite::params_from_iter(values))?)
}

fn replace_one(conn: &mut Connection, table: &'static str, row: Row) -> Result<usize, StoreError> {
    let tx = conn.transaction()?;
    let n = write_row(&tx, &RowWrite::replace(table, row))?;
    tx.commit()?;
    Ok(n)
}

/// Runs one command in one transaction; nothing is committed if any part fails.
fn apply(conn: &mut Connection, cmd: WriteCmd) -> Result<usize, StoreError> {
    match cmd {
        WriteCmd::Batch(rows) => {
            let tx = conn.transaction()?;
            let mut n = 0;
            for w in &rows {
                n += write_row(&tx, w)?;
            }
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::PutSecret(mut row) => {
            // A replaced secret keeps its created_at and records rotated_at.
            let tx = conn.transaction()?;
            let name = text(&row, "name")?.to_string();
            let created: Option<i64> = {
                use rusqlite::OptionalExtension;
                tx.query_row("SELECT created_at FROM secrets WHERE name = ?1", [&name], |r| r.get(0)).optional()?
            };
            if let Some(created) = created {
                let now = int(&row, "created_at")?;
                row.insert("created_at", Value::Integer(created));
                row.insert("rotated_at", Value::Integer(now));
            }
            let n = write_row(&tx, &RowWrite::replace("secrets", row))?;
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::AppendAudit(row) => {
            let tx = conn.transaction()?;
            append_audit(&tx, &row, false)?;
            tx.commit()?;
            Ok(1)
        }
        WriteCmd::AppendAuditCheckpoint(row) => {
            let tx = conn.transaction()?;
            let through = int(&row, "removed_through_seq")?;
            let removed_hash: Vec<u8> =
                tx.query_row("SELECT hash FROM audit_log WHERE seq = ?1", [through], |r| r.get(0))?;
            let data =
                format!("{{\"removed_through_seq\":{through},\"hash\":\"{}\"}}", crate::audit::hex(&removed_hash));
            let mut cp = Row::new();
            cp.insert("at_ms", Value::Integer(int(&row, "at_ms")?));
            cp.insert("actor", Value::Text("hub".into()));
            cp.insert("action", Value::Text("audit.checkpoint".into()));
            cp.insert("data", Value::Text(data));
            append_audit(&tx, &cp, true)?;
            let removed = tx.execute("DELETE FROM audit_log WHERE seq <= ?1", [through])?;
            tx.commit()?;
            Ok(removed + 1)
        }
        WriteCmd::RegistryChange(change) => {
            let tx = conn.transaction()?;
            let mut n = 0;
            if let Some(token) = &change.consume {
                n += consume_token(&tx, token)?;
            }
            for w in &change.writes {
                n += write_row(&tx, w)?;
            }
            for u in &change.updates {
                n += update_row(&tx, u)?;
            }
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::CreateApproval(row) => {
            let tx = conn.transaction()?;
            let n = write_row(&tx, &RowWrite::insert("approvals", row))?;
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::DecideApproval(row) => {
            // Only a pending, unexpired approval can be decided: the first decision wins.
            let n = conn.execute(
                "UPDATE approvals SET state = ?1, decided_by = ?2, decided_at = ?3
                 WHERE id = ?4 AND state = 'pending' AND expires_at > ?3",
                rusqlite::params![
                    text(&row, "state")?,
                    text(&row, "decided_by")?,
                    int(&row, "decided_at")?,
                    text(&row, "id")?
                ],
            )?;
            if n == 0 { Err(StoreError::Conflict("approval already decided")) } else { Ok(n) }
        }
        WriteCmd::UseApproval(id) => {
            let n = conn.execute("UPDATE approvals SET state = 'used' WHERE id = ?1 AND state = 'approved'", [&id])?;
            if n == 0 { Err(StoreError::Conflict("approval already used")) } else { Ok(n) }
        }
        WriteCmd::PutSession(mut row) => {
            // A whole row starts a session; a row of just some columns updates one (touch, step-up, sign-out).
            if row.contains_key("user_id") {
                return upsert_one(conn, "sessions", "id_hash", row);
            }
            let key = row.remove("id_hash").ok_or(StoreError::MissingColumn("id_hash"))?;
            let tx = conn.transaction()?;
            let n = update_row(&tx, &RowUpdate { table: "sessions", key: ("id_hash", key), set: row })?;
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::PutCredential(row) => {
            // A whole row stores a credential; `id` with `last_totp_step` alone records a used TOTP step, only if it
            // is later than any used before, so a code works once even when two sign-ins race.
            if row.contains_key("data") {
                return upsert_one(conn, "credentials", "id", row);
            }
            let n = conn.execute(
                "UPDATE credentials SET last_totp_step = ?1 WHERE id = ?2 AND (last_totp_step IS NULL OR last_totp_step < ?1)",
                rusqlite::params![int(&row, "last_totp_step")?, text(&row, "id")?],
            )?;
            if n == 0 { Err(StoreError::Conflict("TOTP step already used")) } else { Ok(n) }
        }
        WriteCmd::PutKnownDevice(row) => {
            let n = conn.execute(
                "INSERT INTO known_devices (user_id, cookie_hash, first_seen_at, last_seen_at) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (user_id, cookie_hash) DO UPDATE SET last_seen_at = excluded.last_seen_at",
                rusqlite::params![
                    text(&row, "user_id")?,
                    row.get("cookie_hash").ok_or(StoreError::MissingColumn("cookie_hash"))?,
                    int(&row, "first_seen_at")?,
                    int(&row, "last_seen_at")?
                ],
            )?;
            Ok(n)
        }
        WriteCmd::PutLibraryRevision(row) => {
            // The next revision of an item, and the item's current revision, in one transaction.
            let tx = conn.transaction()?;
            let (kind, name) = (text(&row, "kind")?.to_string(), text(&row, "name")?.to_string());
            let current: Option<i64> = {
                use rusqlite::OptionalExtension;
                tx.query_row("SELECT rev FROM library_items WHERE kind = ?1 AND name = ?2", [&kind, &name], |r| {
                    r.get(0)
                })
                .optional()?
            };
            let rev = current.unwrap_or(0) + 1;
            let origin = row.get("origin").cloned().unwrap_or(Value::Text("user".into()));
            tx.execute(
                "INSERT INTO library_items (name, kind, origin, rev) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (kind, name) DO UPDATE SET rev = excluded.rev",
                rusqlite::params![name, kind, origin, rev],
            )?;
            tx.execute(
                "INSERT INTO library_revisions (name, kind, rev, content, author, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![name, kind, rev, text(&row, "content")?, text(&row, "author")?, int(&row, "created_at")?],
            )?;
            tx.commit()?;
            Ok(rev as usize)
        }
        WriteCmd::PutDraft(mut row) => {
            // A whole row proposes a draft; `id` with `state` alone marks it applied or dismissed.
            if row.contains_key("content") {
                let tx = conn.transaction()?;
                let n = write_row(&tx, &RowWrite::insert("library_drafts", row))?;
                tx.commit()?;
                return Ok(n);
            }
            let key = row.remove("id").ok_or(StoreError::MissingColumn("id"))?;
            let tx = conn.transaction()?;
            let n = update_row(&tx, &RowUpdate { table: "library_drafts", key: ("id", key), set: row })?;
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::PutHostKey(row) => {
            // A machine's pinned keys, replaced as a whole: `machine_id` and `keys` (a JSON list).
            let machine = text(&row, "machine_id")?.to_string();
            let keys: Vec<serde_json::Value> =
                serde_json::from_str(text(&row, "keys")?).map_err(|_| StoreError::MissingColumn("keys"))?;
            let tx = conn.transaction()?;
            tx.execute("DELETE FROM ssh_host_keys WHERE machine_id = ?1", [&machine])?;
            for k in &keys {
                let s = |f: &str| k[f].as_str().map(str::to_string).ok_or(StoreError::MissingColumn("keys"));
                tx.execute(
                    "INSERT INTO ssh_host_keys (machine_id, key_type, fingerprint, accepted_at, accepted_by) VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![machine, s("key_type")?, s("fingerprint")?, k["accepted_at"].as_i64().unwrap_or(0), s("accepted_by")?],
                )?;
            }
            tx.commit()?;
            Ok(keys.len())
        }
        WriteCmd::CreateJob(row) => {
            let tx = conn.transaction()?;
            let n = write_row(&tx, &RowWrite::insert("jobs", row))?;
            tx.commit()?;
            Ok(n)
        }
        WriteCmd::UpdateJobStep(row) => {
            // Keyed on (job_id, step_id): the first write records the step before it runs, later ones fill in the
            // columns they name and leave the rest.
            let cols: Vec<&str> = row.keys().copied().collect();
            for c in &cols {
                check_ident(c)?;
            }
            let quoted: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
            let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
            let updates: Vec<String> = cols
                .iter()
                .filter(|c| !matches!(**c, "job_id" | "step_id"))
                .map(|c| format!("\"{c}\" = excluded.\"{c}\""))
                .collect();
            if updates.is_empty() {
                return Err(StoreError::MissingColumn("state"));
            }
            let sql = format!(
                "INSERT INTO job_steps ({}) VALUES ({}) ON CONFLICT(job_id, step_id) DO UPDATE SET {}",
                quoted.join(", "),
                placeholders.join(", "),
                updates.join(", ")
            );
            let values: Vec<&Value> = row.values().collect();
            Ok(conn.execute(&sql, rusqlite::params_from_iter(values))?)
        }
        WriteCmd::FinishJob(row) => {
            // Only a job that hasn't finished: the first finish wins.
            let n = conn.execute(
                "UPDATE jobs SET state = ?2, ended_at = ?3, outcome = ?4
                 WHERE id = ?1 AND state IN ('queued', 'waiting_approval', 'running')",
                rusqlite::params![
                    text(&row, "id")?,
                    text(&row, "state")?,
                    int(&row, "ended_at")?,
                    opt_text(&row, "outcome")
                ],
            )?;
            if n == 0 { Err(StoreError::Conflict("job already finished")) } else { Ok(n) }
        }
        WriteCmd::PutPolicy(row) => upsert_one(conn, "policies", "id", row),
        WriteCmd::PutQuarantineRule(row) => upsert_one(conn, "quarantine_rules", "id", row),
        WriteCmd::PutScheduleState(row) => replace_one(conn, "schedule_state", row),
        WriteCmd::PutWindow(row) => replace_one(conn, "windows", row),
        other => Err(StoreError::Unimplemented(other.name())),
    }
}

fn int(row: &Row, col: &'static str) -> Result<i64, StoreError> {
    match row.get(col) {
        Some(Value::Integer(i)) => Ok(*i),
        _ => Err(StoreError::MissingColumn(col)),
    }
}

fn opt_text<'a>(row: &'a Row, col: &str) -> Option<&'a str> {
    match row.get(col) {
        Some(Value::Text(s)) => Some(s),
        _ => None,
    }
}

fn text<'a>(row: &'a Row, col: &'static str) -> Result<&'a str, StoreError> {
    match row.get(col) {
        Some(Value::Text(s)) => Ok(s),
        _ => Err(StoreError::MissingColumn(col)),
    }
}

/// Appends one audit row after the current head, inside the caller's transaction (the single writer keeps one chain).
fn append_audit(tx: &rusqlite::Transaction<'_>, row: &Row, checkpoint: bool) -> Result<(), StoreError> {
    use rusqlite::OptionalExtension;
    let head: Option<(i64, Vec<u8>)> = tx
        .query_row("SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1", [], |r| Ok((r.get(0)?, r.get(1)?)))
        .optional()?;
    let (prev_seq, prev_hash) = head.unwrap_or((0, crate::audit::GENESIS.to_vec()));
    let target = match row.get("target") {
        Some(Value::Text(s)) => Some(s.as_str()),
        _ => None,
    };
    let fields = crate::audit::AuditFields {
        seq: prev_seq + 1,
        at_ms: int(row, "at_ms")?,
        actor: text(row, "actor")?,
        action: text(row, "action")?,
        target,
        data: text(row, "data")?,
        checkpoint,
    };
    let hash = crate::audit::row_hash(&prev_hash, &fields);
    tx.execute(
        "INSERT INTO audit_log (seq, at_ms, actor, action, target, data, prev_hash, hash, checkpoint) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            fields.seq,
            fields.at_ms,
            fields.actor,
            fields.action,
            fields.target,
            fields.data,
            prev_hash,
            hash.to_vec(),
            checkpoint
        ],
    )?;
    Ok(())
}
