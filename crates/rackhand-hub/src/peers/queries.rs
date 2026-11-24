//! What a peer may ask (7.3.4): `Vitals`, `Machine` and `Incident` by default, `JobLog` only when the admin turns it on (job
//! output can hold credentials, and the output of a sensitive diagnostic, `journal` and `docker_logs`, is never sent), and at
//! most 10 queries a second per peer. A query a peer isn't allowed is answered `Denied`.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use iroh::endpoint::SendStream;
use rackhand_proto::peer::{JobLogChunk, PeerAnswer, PeerQuery, Point, Series, VitalsQuery, peer_answer, peer_query};
use serde_json::json;

use super::{PeerRow, Peers, QUERIES_PER_SECOND, wire};
use crate::policy::risk::SENSITIVE_DIAGNOSTICS;

/// A job log goes out in chunks of this size.
const CHUNK: usize = 64 * 1024;
/// The most of a job's log one answer carries.
const MAX_LOG: usize = 4 * 1024 * 1024;

fn denied(why: &str) -> PeerAnswer {
    PeerAnswer { kind: Some(peer_answer::Kind::Denied(why.to_string())) }
}

fn ulid_text(bytes: &[u8]) -> Option<String> {
    let b: [u8; 16] = bytes.try_into().ok()?;
    Some(ulid::Ulid::from_bytes(b).to_string())
}

/// Whether a step is a sensitive diagnostic's (`diag-journal-...`, `diag-docker-logs-...`): its output never leaves the hub.
fn sensitive_step(step_id: &str) -> bool {
    SENSITIVE_DIAGNOSTICS.iter().any(|name| step_id.starts_with(&format!("diag-{}-", name.replace('_', "-"))))
}

impl Peers {
    /// Whether this peer may ask another query now (10 in any second).
    pub(super) fn allow_query(&self, peer_id: &str, now: Instant) -> bool {
        let Ok(mut all) = self.inner.queries.lock() else { return false };
        let times = all.entry(peer_id.to_string()).or_default();
        while times.front().is_some_and(|t| now.duration_since(*t) >= Duration::from_secs(1)) {
            times.pop_front();
        }
        if times.len() >= QUERIES_PER_SECOND {
            return false;
        }
        times.push_back(now);
        true
    }

    /// The answers to a query: one, except a job log, which is a run of chunks.
    pub fn answer_query(&self, peer: &PeerRow, query: &PeerQuery, now: Instant) -> Vec<PeerAnswer> {
        if !self.allow_query(&peer.id, now) {
            return vec![denied("rate limited")];
        }
        let (name, what) = match &query.kind {
            Some(peer_query::Kind::Vitals(_)) => ("vitals", "vitals"),
            Some(peer_query::Kind::Machine(_)) => ("machine", "machine"),
            Some(peer_query::Kind::Incident(_)) => ("incident", "incident"),
            Some(peer_query::Kind::JobLog(_)) => ("job_log", "job log"),
            None => return vec![denied("not a query")],
        };
        if !peer.allowed.iter().any(|a| a == name) {
            let _ = what;
            return vec![denied("not allowed")];
        }
        match &query.kind {
            Some(peer_query::Kind::Vitals(v)) => vec![self.vitals(v)],
            Some(peer_query::Kind::Machine(id)) => vec![self.machine(id)],
            Some(peer_query::Kind::Incident(id)) => vec![self.incident(id)],
            Some(peer_query::Kind::JobLog(id)) => self.job_log(id),
            None => vec![denied("not a query")],
        }
    }

    fn vitals(&self, q: &VitalsQuery) -> PeerAnswer {
        let Some(machine) = ulid_text(&q.machine) else { return denied("no such machine") };
        let labels: BTreeMap<String, String> = q
            .labels
            .as_ref()
            .map(|l| l.labels.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
            .unwrap_or_default();
        let points = crate::query::vitals::vitals(&self.inner.ingest, &machine, &q.metric, &labels, q.from_ms, q.to_ms);
        let points = points.into_iter().map(|(at_ms, value)| Point { at_ms, value, min: None, max: None }).collect();
        PeerAnswer { kind: Some(peer_answer::Kind::Vitals(Series { points })) }
    }

    fn machine(&self, id: &[u8]) -> PeerAnswer {
        let Some(id) = ulid_text(id) else { return denied("no such machine") };
        type M = (String, String, Option<String>, String, String, String, String, String);
        let found: Option<M> = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT name, kind, os, access, state, quarantine, roles, tags FROM machines WHERE id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?, r.get(7)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((name, kind, os, access, state, quarantine, roles, tags)) = found else {
            return denied("no such machine");
        };
        let facts = self.inner.ingest.latest(&id);
        let detail = json!({
            "id": id, "name": name, "kind": kind, "os": os, "access": access, "state": state, "quarantine": quarantine,
            "roles": serde_json::from_str::<serde_json::Value>(&roles).unwrap_or_default(),
            "tags": serde_json::from_str::<serde_json::Value>(&tags).unwrap_or_default(),
            "services": facts.as_ref().map(|f| f.services_json()).unwrap_or_default(),
            "containers": facts.as_ref().map(|f| f.containers_json()).unwrap_or_default(),
        });
        PeerAnswer { kind: Some(peer_answer::Kind::Machine(detail.to_string().into_bytes())) }
    }

    fn incident(&self, id: &[u8]) -> PeerAnswer {
        let Some(id) = ulid_text(id) else { return denied("no such incident") };
        type I = (String, String, String, String, Option<String>, i64);
        let found: Option<I> = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row(
                    "SELECT kind, severity, state, title, machine_id, opened_at FROM incidents WHERE id = ?1",
                    [&id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((kind, severity, state, title, machine, opened)) = found else { return denied("no such incident") };
        let events: Vec<serde_json::Value> = self
            .inner
            .db
            .readers()
            .with(|c| {
                let mut s =
                    c.prepare("SELECT at_ms, kind, data FROM incident_events WHERE incident_id = ?1 ORDER BY at_ms, rowid LIMIT 200")?;
                s.query_map([&id], |r| {
                    let data: String = r.get(2)?;
                    Ok(json!({ "at_ms": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?,
                               "data": serde_json::from_str::<serde_json::Value>(&data).unwrap_or_default() }))
                })?
                .collect()
            })
            .unwrap_or_default();
        let detail = json!({ "id": id, "kind": kind, "severity": severity, "state": state, "title": title,
                              "machine": machine, "opened_at_ms": opened, "events": events });
        PeerAnswer { kind: Some(peer_answer::Kind::Incident(detail.to_string().into_bytes())) }
    }

    fn job_log(&self, id: &[u8]) -> Vec<PeerAnswer> {
        let Some(job) = ulid_text(id) else { return vec![denied("no such job")] };
        type Step = (String, Option<Vec<u8>>, Option<Vec<u8>>);
        let steps: Vec<Step> = self
            .inner
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT step_id, stdout, stderr FROM job_steps WHERE job_id = ?1 ORDER BY started_at, step_id",
                )?;
                s.query_map([&job], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?.collect()
            })
            .unwrap_or_default();
        let mut log = Vec::new();
        for (step, out, err) in steps {
            if sensitive_step(&step) {
                log.extend_from_slice(format!("== {step}: output withheld (sensitive)\n").as_bytes());
                continue;
            }
            log.extend_from_slice(format!("== {step}\n").as_bytes());
            log.extend_from_slice(out.as_deref().unwrap_or_default());
            log.extend_from_slice(err.as_deref().unwrap_or_default());
        }
        log.truncate(MAX_LOG);
        if log.is_empty() {
            return vec![PeerAnswer {
                kind: Some(peer_answer::Kind::JobLogChunk(JobLogChunk { data: Vec::new(), last: true })),
            }];
        }
        let chunks: Vec<&[u8]> = log.chunks(CHUNK).collect();
        let n = chunks.len();
        chunks
            .into_iter()
            .enumerate()
            .map(|(i, data)| PeerAnswer {
                kind: Some(peer_answer::Kind::JobLogChunk(JobLogChunk { data: data.to_vec(), last: i + 1 == n })),
            })
            .collect()
    }

    pub(super) async fn answer(&self, peer: &PeerRow, query: PeerQuery, send: &mut SendStream) {
        for answer in self.answer_query(peer, &query, Instant::now()) {
            if !wire::write(send, &answer).await {
                return;
            }
        }
    }
}
