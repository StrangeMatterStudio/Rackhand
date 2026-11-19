//! Actions' rows: `jobs` and `job_steps` (7.2: Actions is their only writer).

use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::types::Value;

use crate::bus::JobOutcome;
use crate::ssh::client::TRUNCATED;

/// The most output a step row keeps per stream (the schema's limit), marker included.
pub const STEP_OUTPUT_LIMIT: usize = 1 << 20;

pub(crate) fn state_name(outcome: JobOutcome) -> &'static str {
    match outcome {
        JobOutcome::Succeeded => "succeeded",
        JobOutcome::Failed => "failed",
        JobOutcome::Cancelled => "cancelled",
        JobOutcome::TimedOut => "timed_out",
        JobOutcome::Interrupted => "interrupted",
    }
}

/// Output cut to the row limit, ending with the truncation marker when anything was cut.
pub fn fit_output(mut bytes: Vec<u8>) -> Vec<u8> {
    if bytes.len() <= STEP_OUTPUT_LIMIT {
        return bytes;
    }
    // A marker already at the end (from the SSH client's own cap) is replaced, not repeated.
    if bytes.ends_with(TRUNCATED.as_bytes()) {
        bytes.truncate(bytes.len() - TRUNCATED.len());
    }
    bytes.truncate(STEP_OUTPUT_LIMIT - TRUNCATED.len());
    bytes.extend_from_slice(TRUNCATED.as_bytes());
    bytes
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

fn opt_text(s: Option<&str>) -> Value {
    s.map_or(Value::Null, text)
}

pub(crate) struct NewJob<'a> {
    pub id: &'a str,
    pub kind: &'a str,
    pub name: &'a str,
    pub rev: Option<i64>,
    pub target: Option<&'a str>,
    pub params: &'a str,
    pub requested_by: &'a str,
    pub incident_id: Option<&'a str>,
    pub approval_id: Option<&'a str>,
    /// `running`, or `queued` for a job that never got its machine.
    pub state: &'a str,
    pub now_ms: i64,
}

pub(crate) async fn create(db: &Db, job: &NewJob<'_>) -> Result<(), StoreError> {
    let row: Row = [
        ("id", text(job.id)),
        ("kind", text(job.kind)),
        ("name", text(job.name)),
        ("rev", job.rev.map_or(Value::Null, Value::Integer)),
        ("target", opt_text(job.target)),
        ("params", text(job.params)),
        ("requested_by", text(job.requested_by)),
        ("incident_id", opt_text(job.incident_id)),
        ("approval_id", opt_text(job.approval_id)),
        ("state", text(job.state)),
        ("started_at", Value::Integer(job.now_ms)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::CreateJob(row)).await.map(|_| ())
}

/// Records a step before anything is sent for it.
pub(crate) async fn step_started(
    db: &Db,
    job: &str,
    step: &str,
    command: Option<&str>,
    now_ms: i64,
) -> Result<(), StoreError> {
    let row: Row = [
        ("job_id", text(job)),
        ("step_id", text(step)),
        ("state", text("running")),
        ("command", opt_text(command)),
        ("started_at", Value::Integer(now_ms)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::UpdateJobStep(row)).await.map(|_| ())
}

pub(crate) struct StepEnd<'a> {
    pub state: &'a str,
    pub exit_code: Option<i64>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub now_ms: i64,
}

pub(crate) async fn step_finished(db: &Db, job: &str, step: &str, end: StepEnd<'_>) -> Result<(), StoreError> {
    let row: Row = [
        ("job_id", text(job)),
        ("step_id", text(step)),
        ("state", text(end.state)),
        ("exit_code", end.exit_code.map_or(Value::Null, Value::Integer)),
        ("stdout", Value::Blob(fit_output(end.stdout))),
        ("stderr", Value::Blob(fit_output(end.stderr))),
        ("ended_at", Value::Integer(end.now_ms)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::UpdateJobStep(row)).await.map(|_| ())
}

pub(crate) async fn finish(
    db: &Db,
    job: &str,
    outcome: JobOutcome,
    reason: Option<&str>,
    now_ms: i64,
) -> Result<(), StoreError> {
    let row: Row = [
        ("id", text(job)),
        ("state", text(state_name(outcome))),
        ("ended_at", Value::Integer(now_ms)),
        ("outcome", opt_text(reason)),
    ]
    .into_iter()
    .collect();
    db.writer().send(WriteCmd::FinishJob(row)).await.map(|_| ())
}
