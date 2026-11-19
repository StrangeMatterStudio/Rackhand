//! Offering a job (7.3.5): to connected operators with room, in their configured order, each with a token bound to it.
//! A decline moves to the next; no operator, or 3 declines, ends the job and the incident goes to a person.

use std::time::Duration;

use rackhand_proto::operator::{HubToOperator, JobOffer, hub_to_operator};
use rackhand_runbook::playbook::Playbook;
use rackhand_store::ids::now_ms;
use tokio::sync::oneshot;

use super::{Assist, DEFAULT_DEADLINE_MS, DEFAULT_MAX_TURNS, Link, MAX_DEADLINE_MS, MAX_DECLINES, Track, cap};
use crate::library::items::{Kind, Library};
use crate::mcp::keys;

/// How long an operator has to answer an offer.
const REPLY_WAIT: Duration = Duration::from_secs(10);

/// Incidents asks for an assistant job (7.5.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssistRequest {
    pub incident_id: String,
    pub playbook: String,
    pub brief: String,
    /// Machine ids the job may act on.
    pub hosts: Vec<String>,
    /// At most 2 hours from now; 30 minutes when `None`.
    pub deadline_ms: Option<i64>,
    pub max_turns: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AssistResult {
    Accepted {
        job_id: String,
        operator_id: String,
    },
    /// The incident goes to a person: `no_operator`, `declined`, `daily_cap` or `no_playbook`.
    ToPerson {
        job_id: Option<String>,
        reason: &'static str,
    },
}

fn id_bytes(id: &str) -> Vec<u8> {
    ulid::Ulid::from_string(id).map(|u| u.to_bytes().to_vec()).unwrap_or_else(|_| id.as_bytes().to_vec())
}

impl Assist {
    /// Operators with room for one more job, in their configured order.
    fn candidates(&self) -> Vec<std::sync::Arc<Link>> {
        let order: Vec<String> = self
            .inner
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT id FROM operators WHERE revoked_at IS NULL ORDER BY \"order\", name")?;
                let rows = s.query_map([], |r| r.get(0))?;
                rows.collect()
            })
            .unwrap_or_default();
        let links = self.connected();
        order
            .iter()
            .filter_map(|id| links.iter().find(|l| &l.operator_id == id).cloned())
            .filter(|l| l.running.lock().map(|r| (r.len() as u32) < l.max_jobs).unwrap_or(false))
            .collect()
    }

    async fn offer_to(&self, link: &Link, offer: JobOffer) -> bool {
        let _one_at_a_time = link.offering.lock().await;
        let (tx, rx) = oneshot::channel();
        if let Ok(mut r) = link.reply.lock() {
            *r = Some(tx);
        }
        if link.tx.send(HubToOperator { msg: Some(hub_to_operator::Msg::Offer(offer)) }).is_err() {
            return false;
        }
        matches!(tokio::time::timeout(REPLY_WAIT, rx).await, Ok(Ok(true)))
    }

    async fn to_person(
        &self,
        job: Option<&str>,
        incident: &str,
        reason: &'static str,
        note: Option<String>,
    ) -> AssistResult {
        if let Some(job) = job
            && let Err(e) = self.inner.actions.finish_assistant(job, reason, "no operator took the job").await
        {
            tracing::warn!(error = %e, "assist");
        }
        if let Some(text) = note
            && let Err(e) = crate::incidents::notes::add_note(&self.inner.db, incident, &text, "assist", now_ms()).await
        {
            tracing::warn!(error = %e, "assist note");
        }
        AssistResult::ToPerson { job_id: job.map(str::to_string), reason }
    }

    /// Starts an assistant job for an incident and offers it.
    pub async fn start(&self, req: AssistRequest) -> AssistResult {
        let now = now_ms();
        let cap = self.inner.daily_cap;
        if cap::started_today(&self.inner.db, now) >= cap {
            let note = format!("The daily assistant cap ({cap}) is reached; this incident goes to a person.");
            return self.to_person(None, &req.incident_id, "daily_cap", Some(note)).await;
        }
        let book = Library::current_in(&self.inner.db, Kind::Playbook, &req.playbook)
            .ok()
            .flatten()
            .and_then(|(rev, text)| Playbook::parse(&text).ok().map(|p| (rev, p)));
        let Some((rev, playbook)) = book else {
            return self.to_person(None, &req.incident_id, "no_playbook", None).await;
        };
        let deadline = req.deadline_ms.unwrap_or(now + DEFAULT_DEADLINE_MS).min(now + MAX_DEADLINE_MS);
        let job = match self.inner.actions.open_assistant_job(&req.playbook, "incidents", Some(&req.incident_id)).await
        {
            Ok(j) => j,
            Err(e) => {
                tracing::error!(error = %e, "assist");
                return AssistResult::ToPerson { job_id: None, reason: "no_operator" };
            }
        };
        let hosts: Vec<&str> = req.hosts.iter().map(String::as_str).collect();
        let tools: Vec<&str> = playbook.tools.iter().map(String::as_str).collect();
        let mut declines = 0;
        let mut first = true;
        for link in self.candidates() {
            if declines >= MAX_DECLINES {
                break;
            }
            let token = if first {
                keys::issue_job_token(&self.inner.db, &job, &link.operator_id, &hosts, &tools, deadline).await
            } else {
                keys::rebind_job_token(&self.inner.db, &job, &link.operator_id).await
            };
            first = false;
            let Ok(token) = token else { continue };
            let offer = JobOffer {
                job_id: id_bytes(&job),
                incident_id: id_bytes(&req.incident_id),
                playbook: req.playbook.clone(),
                playbook_rev: rev as u64,
                brief_markdown: req.brief.clone(),
                allowed_tools: playbook.tools.clone(),
                autonomy: u32::from(playbook.autonomy),
                hosts: req.hosts.iter().map(|h| id_bytes(h)).collect(),
                deadline_ms: deadline,
                max_turns: req.max_turns.unwrap_or(DEFAULT_MAX_TURNS),
                job_token: token,
            };
            if self.offer_to(&link, offer).await {
                if let Ok(mut r) = link.running.lock() {
                    r.insert(job.clone());
                }
                if let Ok(mut jobs) = self.inner.jobs.lock() {
                    jobs.insert(
                        job.clone(),
                        Track { operator_id: link.operator_id.clone(), seq: 1, ..Track::default() },
                    );
                }
                let data = serde_json::json!({ "operator": link.operator_id, "incident": req.incident_id });
                let _ = self.inner.audit.append("assist", "job.offered", Some(&job), &data.to_string()).await;
                return AssistResult::Accepted { job_id: job, operator_id: link.operator_id.clone() };
            }
            declines += 1;
        }
        let reason = if declines == 0 { "no_operator" } else { "declined" };
        self.to_person(Some(&job), &req.incident_id, reason, None).await
    }
}
