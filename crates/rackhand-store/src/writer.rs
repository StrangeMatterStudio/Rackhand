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
    RegistryChange(Row),
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
    #[error("the store writer has stopped")]
    WriterStopped,
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
    };
    let placeholders: Vec<String> = (1..=cols.len()).map(|i| format!("?{i}")).collect();
    let quoted: Vec<String> = cols.iter().map(|c| format!("\"{c}\"")).collect();
    let sql = format!("{verb} INTO {} ({}) VALUES ({})", w.table, quoted.join(", "), placeholders.join(", "));
    let values: Vec<&Value> = w.row.values().collect();
    Ok(tx.execute(&sql, rusqlite::params_from_iter(values))?)
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
        other => Err(StoreError::Unimplemented(other.name())),
    }
}
