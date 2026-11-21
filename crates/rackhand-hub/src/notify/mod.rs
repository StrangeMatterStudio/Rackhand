//! Discord webhook and SMTP callouts (7.3.9, 7.6.7): criticals at once, warnings grouped per site for 5 minutes,
//! re-sent when severity rises or every 6 hours while unacknowledged, a resolution for every incident called out, and
//! retries at 1, 5 and 15 minutes after which a failing notifier raises `notifier_failed`. Callouts are built from the
//! incident only: no secrets, no command output and no links that act without signing in.

pub mod config;
pub mod discord;
mod grouping;
mod retry;
pub mod smtp;

use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use rackhand_store::ids::new_id;
use rackhand_store::{Db, Row, StoreError, WriteCmd};
use rusqlite::OptionalExtension;
use rusqlite::types::Value;

use crate::ingest::{Event, Ingest, Severity};

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Re-send an open, unacknowledged incident this often (7.6.7).
pub const RESEND_MS: i64 = 6 * 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    /// One incident, opened or risen (or re-sent).
    Callout,
    /// The warnings of one site gathered over 5 minutes.
    Group,
    Resolution,
    NotifierFailed,
    /// A runbook `notify` step's message.
    Text,
}

/// What a message says about one incident: nothing but its own fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CalloutIncident {
    pub id: String,
    pub site: String,
    pub machine: String,
    pub severity: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: MessageKind,
    pub severity: String,
    pub incidents: Vec<CalloutIncident>,
    pub at_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The service asked to wait (Discord's 429 `retry_after`).
    RetryAfter(Duration),
    Failed(String),
}

/// A notifier: Discord webhook or SMTP.
pub trait Transport: Send + Sync + std::fmt::Debug {
    fn name(&self) -> &str;
    fn send<'a>(&'a self, msg: &'a Message) -> BoxFuture<'a, Result<(), SendError>>;
}

#[derive(Debug, thiserror::Error)]
pub enum NotifyError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("no notifier took the message")]
    NotSent,
    #[error(transparent)]
    Sqlite(#[from] rusqlite::Error),
}

/// After a restart: the unresolved incidents a callout went out for, when it last did, or `None` once acknowledged
/// (7.6.7: their re-sends and resolutions still go out).
fn called_out(db: &Db) -> HashMap<String, Option<i64>> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT n.incident_id, max(n.at_ms), i.acked_at IS NOT NULL FROM notifications n
                 JOIN incidents i ON i.id = n.incident_id
                 WHERE n.state = 'sent' AND i.state != 'resolved' GROUP BY n.incident_id",
            )?;
            s.query_map([], |r| {
                let acked: bool = r.get(2)?;
                Ok((r.get::<_, String>(0)?, if acked { None } else { Some(r.get::<_, i64>(1)?) }))
            })?
            .collect()
        })
        .unwrap_or_default()
}

#[derive(Debug, Clone)]
pub struct Notify {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    db: Arc<Db>,
    ingest: Ingest,
    transports: Vec<Arc<dyn Transport>>,
    dashboard_url: Option<String>,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    last_event: i64,
    groups: grouping::Groups,
    /// Incidents called out: when they were last sent, or `None` once acknowledged (no more re-sends).
    called_out: HashMap<String, Option<i64>>,
    pending: Vec<retry::Pending>,
}

impl Notify {
    pub fn new(db: Arc<Db>, ingest: Ingest, transports: Vec<Arc<dyn Transport>>) -> Notify {
        let last_event = db
            .readers()
            .with(|c| c.query_row("SELECT coalesce(max(rowid), 0) FROM incident_events", [], |r| r.get(0)))
            .unwrap_or(0);
        let state = State { last_event, called_out: called_out(&db), ..State::default() };
        Notify { inner: Arc::new(Inner { db, ingest, transports, dashboard_url: None, state: Mutex::new(state) }) }
    }

    /// The public dashboard URL, for links to incidents.
    pub fn with_dashboard_url(self, url: &str) -> Notify {
        let inner = Arc::try_unwrap(self.inner).expect("set before the notifier is shared");
        Notify { inner: Arc::new(Inner { dashboard_url: Some(url.trim_end_matches('/').to_string()), ..inner }) }
    }

    /// The notifiers' names, for the settings page.
    pub fn names(&self) -> Vec<String> {
        self.inner.transports.iter().map(|t| t.name().to_string()).collect()
    }

    pub fn dashboard_url(&self) -> Option<&str> {
        self.inner.dashboard_url.as_deref()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.inner.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// One pass: new incident events, groups that are due, re-sends and retries.
    pub async fn tick(&self, now_ms: i64) -> Result<(), NotifyError> {
        let last = self.state().last_event;
        let events: Vec<(i64, String, String, String)> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT rowid, incident_id, kind, data FROM incident_events WHERE rowid > ?1 ORDER BY rowid",
            )?;
            s.query_map([last], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
        })?;
        for (rowid, incident, kind, data) in events {
            self.state().last_event = rowid;
            let data: serde_json::Value = serde_json::from_str(&data).unwrap_or_default();
            let callout = data["callout"].as_bool().unwrap_or(false);
            match kind.as_str() {
                "opened" | "reopened" | "severity" if callout => self.call_out(&incident, now_ms).await?,
                "resolved" => self.resolved(&incident, now_ms).await?,
                _ => {}
            }
        }
        // taken out first: the state lock must not be held across the sends below
        let due_groups = self.state().groups.take_due(now_ms);
        for (_, ids) in due_groups {
            let incidents: Vec<CalloutIncident> =
                ids.iter().filter_map(|id| self.summary(id).ok().flatten().map(|s| s.0)).collect();
            if incidents.is_empty() {
                continue;
            }
            for i in &incidents {
                self.state().called_out.insert(i.id.clone(), Some(now_ms));
            }
            self.send(
                Message { kind: MessageKind::Group, severity: "warning".into(), incidents, at_ms: now_ms },
                now_ms,
            )
            .await?;
        }
        let due: Vec<String> = self
            .state()
            .called_out
            .iter()
            .filter(|(_, at)| at.is_some_and(|at| now_ms - at >= RESEND_MS))
            .map(|(id, _)| id.clone())
            .collect();
        for id in due {
            match self.summary(&id)? {
                Some((inc, true, false)) => {
                    self.state().called_out.insert(id.clone(), Some(now_ms));
                    let severity = inc.severity.clone();
                    self.send(
                        Message { kind: MessageKind::Callout, severity, incidents: vec![inc], at_ms: now_ms },
                        now_ms,
                    )
                    .await?;
                }
                // acknowledged: no more re-sends, but its resolution still goes out
                Some((_, true, true)) => {
                    self.state().called_out.insert(id, None);
                }
                _ => {}
            }
        }
        self.retry_due(now_ms).await
    }

    /// An incident opened or rose: criticals go now, warnings join their site's group, info stays on the dashboard.
    async fn call_out(&self, id: &str, now_ms: i64) -> Result<(), NotifyError> {
        let Some((inc, open, _)) = self.summary(id)? else { return Ok(()) };
        if !open {
            return Ok(());
        }
        match inc.severity.as_str() {
            "critical" => {
                self.state().called_out.insert(id.to_string(), Some(now_ms));
                let severity = inc.severity.clone();
                self.send(
                    Message { kind: MessageKind::Callout, severity, incidents: vec![inc], at_ms: now_ms },
                    now_ms,
                )
                .await?;
                Ok(())
            }
            "warning" => {
                self.state().groups.add(&inc.site, id, now_ms);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    async fn resolved(&self, id: &str, now_ms: i64) -> Result<(), NotifyError> {
        self.state().groups.remove(id);
        if self.state().called_out.remove(id).is_none() {
            return Ok(());
        }
        let Some((inc, _, _)) = self.summary(id)? else { return Ok(()) };
        let severity = inc.severity.clone();
        self.send(Message { kind: MessageKind::Resolution, severity, incidents: vec![inc], at_ms: now_ms }, now_ms)
            .await?;
        Ok(())
    }

    /// The incident as a message shows it, whether it is unresolved, and whether it was acknowledged.
    fn summary(&self, id: &str) -> Result<Option<(CalloutIncident, bool, bool)>, NotifyError> {
        Ok(self.inner.db.readers().with(|c| {
            c.query_row(
                "SELECT i.id, coalesce(s.name, ''), coalesce(m.name, 'hub'), i.severity, i.title, i.state, i.opened_at,
                        i.acked_at IS NOT NULL
                 FROM incidents i LEFT JOIN machines m ON m.id = i.machine_id LEFT JOIN sites s ON s.id = m.site_id
                 WHERE i.id = ?1",
                [id],
                |r| {
                    let state: String = r.get(5)?;
                    let opened: i64 = r.get(6)?;
                    let title: String = r.get(4)?;
                    let opened_at =
                        jiff::Timestamp::from_millisecond(opened).map(|t| t.to_string()).unwrap_or_default();
                    let description = format!("{title}. Opened {opened_at}; now {state}.");
                    Ok((
                        CalloutIncident {
                            id: r.get(0)?,
                            site: r.get(1)?,
                            machine: r.get(2)?,
                            severity: r.get(3)?,
                            title,
                            description,
                        },
                        state != "resolved",
                        r.get(7)?,
                    ))
                },
            )
            .optional()
        })?)
    }

    /// Sends a runbook `notify` step's message through every notifier.
    pub async fn send_text(&self, text: &str, now_ms: i64) -> Result<(), NotifyError> {
        let inc = CalloutIncident {
            id: String::new(),
            site: String::new(),
            machine: String::new(),
            severity: "info".into(),
            title: text.to_string(),
            description: text.to_string(),
        };
        let msg = Message { kind: MessageKind::Text, severity: "info".into(), incidents: vec![inc], at_ms: now_ms };
        if self.send(msg, now_ms).await? == 0 { Err(NotifyError::NotSent) } else { Ok(()) }
    }

    /// Tries every notifier once (failures are retried by [`Notify::tick`]); returns how many took it.
    async fn send(&self, msg: Message, now_ms: i64) -> Result<usize, NotifyError> {
        let mut sent = 0;
        for i in 0..self.inner.transports.len() {
            let p = retry::Pending {
                transport: i,
                message: msg.clone(),
                attempt: 0,
                due_ms: now_ms,
                id: new_id().to_string(),
            };
            if self.attempt(p, now_ms).await? {
                sent += 1;
            }
        }
        Ok(sent)
    }

    /// One try through one notifier; returns whether it was sent.
    async fn attempt(&self, mut p: retry::Pending, now_ms: i64) -> Result<bool, NotifyError> {
        let transport = self.inner.transports[p.transport].clone();
        let result = transport.send(&p.message).await;
        let incident = p.message.incidents.first().map(|i| i.id.clone()).filter(|id| !id.is_empty());
        let (state, error) = match &result {
            Ok(()) => ("sent", None),
            Err(SendError::RetryAfter(d)) => {
                p.due_ms = now_ms + d.as_millis() as i64;
                ("retrying", Some(format!("retry after {} ms", d.as_millis())))
            }
            Err(SendError::Failed(e)) => match retry::next_delay(p.attempt) {
                Some(d) => {
                    p.attempt += 1;
                    p.due_ms = now_ms + d;
                    ("retrying", Some(e.clone()))
                }
                None => ("failed", Some(e.clone())),
            },
        };
        let row = Row::from([
            ("id", Value::Text(p.id.clone())),
            ("notifier", Value::Text(transport.name().to_string())),
            ("incident_id", incident.map(Value::Text).unwrap_or(Value::Null)),
            ("at_ms", Value::Integer(now_ms)),
            ("state", Value::Text(state.into())),
            ("attempts", Value::Integer(p.attempt as i64 + 1)),
            ("last_error", error.clone().map(Value::Text).unwrap_or(Value::Null)),
        ]);
        self.inner.db.writer().send(WriteCmd::PutNotification(row)).await?;
        match state {
            "retrying" => self.state().pending.push(p),
            "failed" if p.message.kind != MessageKind::NotifierFailed => {
                self.failed(p.transport, transport.name(), error.unwrap_or_default(), now_ms).await?
            }
            _ => {}
        }
        Ok(state == "sent")
    }

    /// A notifier gave up: `notifier_failed` on the dashboard and through every other notifier.
    async fn failed(&self, index: usize, name: &str, error: String, now_ms: i64) -> Result<(), NotifyError> {
        let data = serde_json::json!({ "notifier": name, "error": error });
        let event = Event {
            subject: Some(name.to_string()),
            at_ms: now_ms,
            ..Event::hub("notifier_failed", Severity::Warning, data)
        };
        if let Err(e) = self.inner.ingest.raise_event(event).await {
            tracing::warn!(error = %e, "raising notifier_failed");
        }
        let inc = CalloutIncident {
            id: String::new(),
            site: String::new(),
            machine: String::new(),
            severity: "warning".into(),
            title: format!("Notifier {name} failed"),
            description: format!("Callouts through {name} failed after retries at 1, 5 and 15 minutes."),
        };
        let msg = Message {
            kind: MessageKind::NotifierFailed,
            severity: "warning".into(),
            incidents: vec![inc],
            at_ms: now_ms,
        };
        for (i, _) in self.inner.transports.iter().enumerate().filter(|(i, _)| *i != index) {
            let p = retry::Pending {
                transport: i,
                message: msg.clone(),
                attempt: 0,
                due_ms: now_ms,
                id: new_id().to_string(),
            };
            Box::pin(self.attempt(p, now_ms)).await?;
        }
        Ok(())
    }

    async fn retry_due(&self, now_ms: i64) -> Result<(), NotifyError> {
        let due: Vec<retry::Pending> = {
            let mut s = self.state();
            let (due, later) = std::mem::take(&mut s.pending).into_iter().partition(|p| p.due_ms <= now_ms);
            s.pending = later;
            due
        };
        for p in due {
            self.attempt(p, now_ms).await?;
        }
        Ok(())
    }
}

/// The Executor's `notify` step (7.8.7): its message through every notifier.
impl crate::actions::runner::StepRunner for Notify {
    fn run<'a>(
        &'a self,
        _ctx: &'a crate::actions::runner::StepCtx,
        step: &'a rackhand_runbook::runbook::Step,
        _argv: Option<&'a [String]>,
    ) -> crate::actions::runner::BoxFuture<'a, crate::actions::runner::StepResult> {
        use crate::actions::runner::StepResult;
        Box::pin(async move {
            if step.kind != rackhand_runbook::runbook::StepKind::Notify {
                return StepResult::failed("notify_only");
            }
            let text = step.message.clone().unwrap_or_default();
            let now = rackhand_store::ids::now_ms();
            match self.send_text(&text, now).await {
                Ok(()) => {
                    StepResult { outcome: crate::actions::runner::StepOutcome::Succeeded, ..StepResult::failed("") }
                }
                Err(e) => StepResult::failed(e.to_string()),
            }
        })
    }
}

/// A mail server for tests (the hub's own and the integration tier's).
#[cfg(any(test, feature = "testing"))]
pub mod smtp_sink;
#[cfg(test)]
mod tests;
