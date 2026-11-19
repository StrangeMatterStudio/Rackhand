//! Job events and the end of a job (7.3.5): events are stored through Actions up to 5 MB per job, later ones counted;
//! `JobDone` ends the job. A deadline reached with an approval still open ends it `needs_human` (E21).

use rackhand_proto::operator::{JobDone, JobEvent, JobEventKind, Outcome};
use rackhand_store::Db;

use super::{Assist, ulid_text};

/// The most transcript text kept per job.
pub const TRANSCRIPT_CAP: usize = 5 * 1024 * 1024;

/// The next sequence number and the bytes already stored, for a job picked up again.
pub(super) fn stored_so_far(db: &Db, job: &str) -> (i64, usize) {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT coalesce(max(seq), 0) + 1, coalesce(sum(length(text)), 0) FROM assistant_transcripts WHERE job_id = ?1",
                [job],
                |r| Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1)? as usize)),
            )
        })
        .unwrap_or((1, 0))
}

fn kind_name(kind: i32) -> &'static str {
    match JobEventKind::try_from(kind) {
        Ok(JobEventKind::ToolCall) => "tool_call",
        Ok(JobEventKind::ToolResult) => "tool_result",
        Ok(JobEventKind::Error) => "error",
        _ => "message",
    }
}

/// Whether the job's assistant asked for something a person approved or still may approve.
pub(super) fn approval_open(db: &Db, job: &str, now_ms: i64) -> bool {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT EXISTS (SELECT 1 FROM approvals WHERE requested_by = ?1 AND state IN ('pending', 'approved') AND expires_at > ?2)",
                rusqlite::params![format!("job:{job}"), now_ms],
                |r| r.get(0),
            )
        })
        .unwrap_or(false)
}

impl Assist {
    /// An event from the operator running the job; another operator's events for it are ignored.
    pub(super) async fn event(&self, operator_id: &str, e: JobEvent) {
        let Some(job) = ulid_text(&e.job_id) else { return };
        let store = self.inner.jobs.lock().ok().and_then(|mut jobs| {
            let t = jobs.get_mut(&job).filter(|t| t.operator_id == operator_id)?;
            if t.stored + e.text.len() > TRANSCRIPT_CAP {
                t.dropped += 1;
                return None;
            }
            t.stored += e.text.len();
            t.seq += 1;
            Some(t.seq - 1)
        });
        if let Some(seq) = store
            && let Err(err) = self.inner.actions.append_transcript(&job, seq, e.at_ms, kind_name(e.kind), &e.text).await
        {
            tracing::warn!(error = %err, "transcript");
        }
    }

    pub(super) async fn done(&self, operator_id: &str, d: JobDone) {
        let Some(job) = ulid_text(&d.job_id) else { return };
        let track = self.inner.jobs.lock().ok().and_then(|mut jobs| {
            if jobs.get(&job).is_some_and(|t| t.operator_id == operator_id) { jobs.remove(&job) } else { None }
        });
        let Some(track) = track else { return };
        if let Some(link) = self.inner.links.lock().ok().and_then(|l| l.get(operator_id).cloned())
            && let Ok(mut r) = link.running.lock()
        {
            r.remove(&job);
        }
        let now = rackhand_store::ids::now_ms();
        if track.dropped > 0 {
            let s = if track.dropped == 1 { "" } else { "s" };
            let text = format!("{} event{s} not stored (over 5 MB)", track.dropped);
            let _ = self.inner.actions.append_transcript(&job, track.seq, now, "dropped", &text).await;
        }
        let outcome = match Outcome::try_from(d.outcome) {
            Ok(Outcome::Resolved) => "resolved",
            Ok(Outcome::NeedsHuman) => "needs_human",
            Ok(Outcome::TimedOut) if approval_open(&self.inner.db, &job, now) => "needs_human",
            Ok(Outcome::TimedOut) => "timed_out",
            _ => "failed",
        };
        if let Err(e) = self.inner.actions.finish_assistant(&job, outcome, &d.summary).await {
            tracing::warn!(error = %e, job, "job done");
        }
    }
}
