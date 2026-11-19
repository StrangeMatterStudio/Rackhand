//! Resume job (7.5.4, E21): a job that reached its deadline with an approval open ends `needs_human`; Resume runs the
//! approved call first (with the old job as its requester, as approved) and then offers a new job that is told what
//! ran.

use std::collections::BTreeMap;

use rackhand_store::ids::now_ms;
use rusqlite::OptionalExtension;

use super::offers::{AssistRequest, AssistResult};
use super::{Assist, transcripts};
use crate::actions::{JobKind, StartJob};

struct Old {
    playbook: String,
    incident: Option<String>,
    hosts: Vec<String>,
}

impl Assist {
    /// Whether the job ended `needs_human` with an approval still to use.
    pub fn resumable(&self, job_id: &str) -> bool {
        let ended: Option<i64> = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT 1 FROM jobs WHERE id = ?1 AND kind = 'assistant' AND outcome = 'needs_human' AND state != 'running'",
                    [job_id],
                    |r| r.get(0),
                )
                .optional()
            })
            .ok()
            .flatten();
        ended.is_some() && transcripts::approval_open(&self.inner.db, job_id, now_ms())
    }

    pub async fn resume(&self, job_id: &str) -> Result<AssistResult, String> {
        if !self.resumable(job_id) {
            return Err("the job didn't end with an approval to use".into());
        }
        let old: Old = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT j.name, j.incident_id, t.hosts FROM jobs j LEFT JOIN job_tokens t ON t.job_id = j.id WHERE j.id = ?1",
                    [job_id],
                    |r| {
                        let hosts: Option<String> = r.get(2)?;
                        Ok(Old {
                            playbook: r.get(0)?,
                            incident: r.get(1)?,
                            hosts: hosts.and_then(|h| serde_json::from_str(&h).ok()).unwrap_or_default(),
                        })
                    },
                )
            })
            .map_err(|e| e.to_string())?;
        let approved: Option<(String, Option<String>, String)> = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT id, target, args FROM approvals WHERE requested_by = ?1 AND tool = 'run_runbook' AND state = 'approved'
                     AND expires_at > ?2 ORDER BY expires_at LIMIT 1",
                    rusqlite::params![format!("job:{job_id}"), now_ms()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
            })
            .map_err(|e| e.to_string())?;
        let ran = match approved {
            Some((approval, Some(target), args)) => {
                let args: serde_json::Value = serde_json::from_str(&args).unwrap_or_default();
                let name = args["name"].as_str().unwrap_or_default().to_string();
                let params: BTreeMap<String, String> = args["params"]
                    .as_object()
                    .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                    .unwrap_or_default();
                let start = StartJob {
                    kind: JobKind::Runbook,
                    name: name.clone(),
                    rev: None,
                    machine_id: target.clone(),
                    params,
                    requested_by: format!("job:{job_id}"),
                    incident_id: old.incident.clone(),
                    approval_id: Some(approval),
                };
                match self.inner.actions.run(start).await {
                    Ok(r) => format!("The approved call ran first: run_runbook {name} on {target}, {:?}.", r.outcome),
                    Err(e) => format!("The approved call (run_runbook {name} on {target}) didn't run: {e}."),
                }
            }
            _ => "The approved call couldn't be run again here; check it before acting.".to_string(),
        };
        let incident = old.incident.unwrap_or_default();
        let brief = format!("Resumed after job {job_id} reached its deadline with an approval open. {ran}");
        Ok(self
            .start(AssistRequest {
                incident_id: incident,
                playbook: old.playbook,
                brief,
                hosts: old.hosts,
                deadline_ms: None,
                max_turns: None,
            })
            .await)
    }
}
