//! Routing to a playbook (7.5.2, 7.5.4, D76, D96). A runbook is tried first; a playbook only when no runbook matches or the
//! runbook failed (or its condition persisted), and when a failed step names `on_failure = { playbook = ... }` that playbook is
//! used and `incident_kinds` matching is skipped. An incident gets at most one assistant job (a setting) in any 24 hours, however often
//! it reopens. The assistant's end is judged here too: an event incident (security and system events) is resolved by an
//! assistant only at level 2 or 3 and only for a warning, and every other end goes to a person.

use rackhand_runbook::playbook::{Hosts, Playbook};

use super::*;
use crate::incidents::brief;

// Assistant jobs for one incident in any 24 hours (D96) and the deadline of a playbook that sets no `max_runtime` are
// settings of `config/hub.toml` (7.8.1).
const ASSISTANT_STARTED: &str = "assistant.started";
const ASSISTANT_RESOLVED: &str = "assistant.resolved";

/// What routing asks of Assist (through the composition: Incidents never depends on it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlaybookRequest {
    pub incident_id: String,
    pub playbook: String,
    pub brief: String,
    pub hosts: Vec<String>,
    pub deadline_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlaybookStart {
    Accepted {
        job_id: String,
    },
    /// Nobody took it: `no_operator`, `declined`, `daily_cap` or `no_playbook`.
    ToPerson {
        reason: String,
    },
}

pub trait AssistStarter: Send + Sync + std::fmt::Debug {
    fn start(&self, req: PlaybookRequest) -> BoxFuture<PlaybookStart>;
}

/// The playbook for an incident of `kind`: the one a failed step names, else one whose `incident_kinds` has it, ties to the
/// name that sorts first. (A playbook has no targets of its own, so there is no more specific match than the kind.)
pub fn choose_playbook<'a>(books: &'a [Playbook], kind: &str, on_failure: Option<&str>) -> Option<&'a Playbook> {
    if let Some(name) = on_failure {
        return books.iter().find(|b| b.name == name);
    }
    books.iter().filter(|b| b.incident_kinds.iter().any(|k| k == kind)).min_by(|a, b| a.name.cmp(&b.name))
}

/// Whether the assistant's `resolved` closes an incident by itself: an event incident only at level 2 or 3 and for a warning,
/// a condition incident waits for its condition to clear instead.
pub fn assistant_may_resolve_event(level: u8, severity: Severity) -> bool {
    level >= 2 && severity == Severity::Warning
}

impl Routing {
    /// The assistant for the incident, with `why` as the reason a person is told if there is no assistant to give it to.
    pub(super) async fn to_playbook(
        &self,
        inc: &IncidentRow,
        machine_id: &str,
        on_failure: Option<&str>,
        why: &str,
        now_ms: i64,
    ) -> Result<(), IncidentsError> {
        let Some(assist) = &self.assist else { return self.nobody(inc, why, now_ms).await };
        let books: Vec<Playbook> = Library::all_current(self.db())
            .unwrap_or_default()
            .into_iter()
            .filter(|(kind, _, _)| *kind == Kind::Playbook)
            .filter_map(|(_, _, text)| Playbook::parse(&text).ok())
            .collect();
        let Some(book) = choose_playbook(&books, &inc.kind, on_failure) else {
            return self.nobody(inc, why, now_ms).await;
        };
        if book.autonomy == 0 {
            let note = format!("level 0: playbook `{}` would run for this incident; nothing was run", book.name);
            return self.to_person(&inc.id, &note, now_ms).await;
        }
        let settings = self.settings();
        if self.assistant_starts(&inc.id, now_ms)? >= i64::from(settings.incidents.assistant_jobs_24h) {
            let note = format!(
                "attempt limit reached: an assistant job started for this incident in the last 24 hours (playbook `{}`)",
                book.name
            );
            return self.to_person(&inc.id, &note, now_ms).await;
        }
        let hosts = self.hosts_for(book, machine_id)?;
        let runtime_ms = book.max_runtime_s().map_or(settings.assistant.deadline_ms(), |s| s as i64 * 1000);
        let deadline_ms = now_ms + runtime_ms;
        let input =
            brief::gather(self.db(), &self.incidents.inner.ingest, inc, book, hosts.clone(), deadline_ms, now_ms);
        let request = PlaybookRequest {
            incident_id: inc.id.clone(),
            playbook: book.name.clone(),
            brief: brief::render(&input),
            hosts: hosts.into_iter().map(|(id, _)| id).collect(),
            deadline_ms,
        };
        let mut open = inc.clone();
        match assist.start(request).await {
            PlaybookStart::Accepted { job_id } => {
                open.state = State::Assistant;
                let data = serde_json::json!({ "playbook": book.name, "job": job_id });
                self.mark(&open, ASSISTANT_STARTED, data, now_ms).await?;
                self.note(&inc.id, &format!("assistant job started with playbook `{}`", book.name), now_ms).await;
                Ok(())
            }
            PlaybookStart::ToPerson { reason } => {
                let text = match reason.as_str() {
                    "no_operator" => "no operator is connected, so no assistant could take this incident".to_string(),
                    "declined" => {
                        "every operator declined the job, so no assistant could take this incident".to_string()
                    }
                    "daily_cap" => "the daily assistant cap is reached".to_string(),
                    other => format!("the assistant couldn't be started ({other})"),
                };
                self.needs_a_person(inc, &text, now_ms).await
            }
        }
    }

    /// Nothing for an assistant to do: a person has it, told why when there is a reason to tell.
    async fn nobody(&self, inc: &IncidentRow, why: &str, now_ms: i64) -> Result<(), IncidentsError> {
        if why.is_empty() {
            return self.incidents.set_state(&inc.id, State::Human, now_ms).await;
        }
        self.to_person(&inc.id, why, now_ms).await
    }

    /// A person takes it, and a callout says why (E15).
    async fn needs_a_person(&self, inc: &IncidentRow, text: &str, now_ms: i64) -> Result<(), IncidentsError> {
        self.to_person(&inc.id, text, now_ms).await?;
        let mut human = inc.clone();
        human.state = State::Human;
        self.mark(&human, "human", serde_json::json!({ "why": text, "callout": true }), now_ms).await
    }

    fn assistant_starts(&self, incident_id: &str, now_ms: i64) -> Result<i64, IncidentsError> {
        Ok(self.db().readers().with(|c| {
            c.query_row(
                "SELECT count(*) FROM incident_events WHERE incident_id = ?1 AND kind = ?2 AND at_ms > ?3",
                rusqlite::params![incident_id, ASSISTANT_STARTED, now_ms - ATTEMPT_WINDOW_MS],
                |r| r.get(0),
            )
        })?)
    }

    /// The machines a job may act on: the incident's, or all of its site's (`hosts = "site"`).
    fn hosts_for(&self, book: &Playbook, machine_id: &str) -> Result<Vec<(String, String)>, IncidentsError> {
        let sql = match book.hosts {
            Hosts::Incident => "SELECT id, name FROM machines WHERE id = ?1",
            Hosts::Site => {
                "SELECT id, name FROM machines WHERE state = 'enrolled' AND site_id = (SELECT site_id FROM machines WHERE id = ?1)"
            }
        };
        Ok(self.db().readers().with(|c| {
            let mut s = c.prepare(sql)?;
            s.query_map([machine_id], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })?)
    }

    /// The playbook a failed job's failed step names, if it names one.
    pub(super) fn on_failure_of(&self, job_id: &str) -> Option<String> {
        let (name, rev, step): (String, Option<i64>, Option<String>) = self
            .db()
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT j.name, j.rev, (SELECT step_id FROM job_steps s WHERE s.job_id = j.id AND s.state IN ('failed', 'timed_out')
                                            ORDER BY s.started_at LIMIT 1) FROM jobs j WHERE j.id = ?1",
                    [job_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
            })
            .ok()?;
        let step = step?;
        let source = match rev {
            Some(rev) => Library::revision_in(self.db(), Kind::Runbook, &name, rev).ok().flatten(),
            None => Library::current_in(self.db(), Kind::Runbook, &name).ok().flatten().map(|(_, s)| s),
        }?;
        let runbook = Runbook::parse(&source).ok()?;
        runbook.steps.iter().find(|s| s.id == step)?.on_failure.as_ref().map(|f| f.playbook.clone())
    }

    /// An assistant job ended (its `JobFinished`). `Some` when this was one: the incident goes on from here.
    pub(super) async fn assistant_finished(
        &self,
        job_id: &str,
        outcome: JobOutcome,
        now_ms: i64,
    ) -> Result<bool, IncidentsError> {
        type JobRow = (String, Option<String>, Option<String>);
        let row: Option<JobRow> = self.db().readers().with(|c| {
            c.query_row(
                "SELECT name, incident_id, outcome FROM jobs WHERE id = ?1 AND kind = 'assistant'",
                [job_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()
        })?;
        let Some((playbook, Some(incident_id), reason)) = row else { return Ok(row.is_some()) };
        let inc = by_id(self.db(), &incident_id)?;
        if matches!(inc.state, State::Resolved | State::Human) {
            return Ok(true);
        }
        let level = Library::current_in(self.db(), Kind::Playbook, &playbook)
            .ok()
            .flatten()
            .and_then(|(_, t)| Playbook::parse(&t).ok())
            .map_or(1, |p| p.autonomy);
        let event_incident = is_event_kind(&inc.kind);
        if outcome == JobOutcome::Succeeded {
            if event_incident {
                if assistant_may_resolve_event(level, inc.severity) {
                    self.incidents.resolve_by(&incident_id, &format!("assistant:{playbook}"), now_ms).await?;
                } else {
                    let why = format!(
                        "the assistant reported resolved; an event incident is closed by a person unless the assistant is at level 2 or 3 and it is a warning (level {level}, {})",
                        crate::incidents::lifecycle::severity_str(inc.severity)
                    );
                    self.needs_a_person(&inc, &why, now_ms).await?;
                }
            } else {
                // a condition incident waits to see the condition clear
                self.mark(&inc, ASSISTANT_RESOLVED, serde_json::json!({ "playbook": playbook, "job": job_id }), now_ms)
                    .await?;
            }
            return Ok(true);
        }
        let ended = match reason.as_deref() {
            Some("needs_human") | Some("handed_over") => "handed the incident to a person".to_string(),
            Some("timed_out") => "ran out of time".to_string(),
            Some("no_operator") | Some("declined") | Some("daily_cap") | Some("no_playbook") => {
                format!("couldn't be started ({})", reason.unwrap_or_default())
            }
            Some(other) => format!("ended {other}"),
            None => "failed".to_string(),
        };
        self.needs_a_person(&inc, &format!("assistant playbook `{playbook}` {ended} (job {job_id})"), now_ms).await?;
        Ok(true)
    }

    /// Incidents whose assistant said resolved but whose condition hasn't cleared in the wait (10 minutes by default,
    /// 7.8.1) go to a person.
    pub(super) async fn assistant_waits(&self, now_ms: i64) -> Result<(), IncidentsError> {
        let wait = self.settings().incidents;
        let waiting: Vec<String> = self.db().readers().with(|c| {
            let mut s = c.prepare(
                "SELECT i.id FROM incidents i JOIN incident_events e ON e.incident_id = i.id
                 WHERE i.state = 'assistant' AND e.kind = ?1 AND e.at_ms <= ?2
                   AND NOT EXISTS (SELECT 1 FROM incident_events s WHERE s.incident_id = i.id AND s.kind = ?3 AND s.at_ms > e.at_ms)",
            )?;
            s.query_map(rusqlite::params![ASSISTANT_RESOLVED, now_ms - wait.clear_wait_ms(), ASSISTANT_STARTED], |r| {
                r.get(0)
            })?
            .collect()
        })?;
        for id in waiting {
            let inc = by_id(self.db(), &id)?;
            let why =
                format!("the condition persists {} minutes after the assistant said resolved", wait.clear_wait_min);
            self.needs_a_person(&inc, &why, now_ms).await?;
        }
        Ok(())
    }
}

/// Event incidents have no condition to clear: security findings and the hub's own system events.
fn is_event_kind(kind: &str) -> bool {
    crate::policy::quarantine::SECURITY_PREFIXES.iter().any(|p| kind.starts_with(p))
        || ["probe.", "ssh.", "machine.ssh", "job."].iter().any(|p| kind.starts_with(p))
}

#[cfg(test)]
mod tests {
    use rackhand_detect::rules::Severity;

    use super::*;

    fn book(name: &str, kinds: &[&str]) -> Playbook {
        let kinds: Vec<String> = kinds.iter().map(|k| format!("\"{k}\"")).collect();
        let text = format!(
            "+++\nname = \"{name}\"\nincident_kinds = [{}]\nautonomy = 1\nrisk = \"normal\"\ntools = [\"get_incident\", \"finish_job\"]\nhosts = \"incident\"\n+++\n## When\n.\n## Read first\n.\n## Do\n.\n## Done when\n.\n## Stop and ask if\n.\n",
            kinds.join(", ")
        );
        Playbook::parse(&text).unwrap()
    }

    #[test]
    fn precedence_and_on_failure_override() {
        let books = [
            book("zeta", &["service.not_active"]),
            book("alpha", &["service.not_active", "disk.used"]),
            book("named", &[]),
        ];
        // the kind's playbook, ties to the name that sorts first
        assert_eq!(choose_playbook(&books, "service.not_active", None).unwrap().name, "alpha");
        assert_eq!(choose_playbook(&books, "disk.used", None).unwrap().name, "alpha");
        assert!(choose_playbook(&books, "cpu.busy", None).is_none());
        // a failed step's `on_failure` names the playbook, and the kinds aren't looked at
        assert_eq!(choose_playbook(&books, "service.not_active", Some("named")).unwrap().name, "named");
        assert_eq!(choose_playbook(&books, "cpu.busy", Some("zeta")).unwrap().name, "zeta");
        assert!(
            choose_playbook(&books, "service.not_active", Some("missing")).is_none(),
            "a name that doesn't exist matches nothing"
        );
    }

    #[test]
    fn assistant_resolves_event_incident_only_level_2_3_warning() {
        for (level, severity, expected) in [
            (1, Severity::Warning, false),
            (2, Severity::Warning, true),
            (3, Severity::Warning, true),
            (2, Severity::Critical, false),
            (3, Severity::Critical, false),
            (0, Severity::Warning, false),
        ] {
            assert_eq!(assistant_may_resolve_event(level, severity), expected, "level {level}, {severity:?}");
        }
        assert!(is_event_kind("conn.known_bad") && is_event_kind("file.changed") && is_event_kind("probe.data_gap"));
        assert!(!is_event_kind("service.not_active") && !is_event_kind("disk.used") && !is_event_kind("patch_failed"));
    }
}
