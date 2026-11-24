//! Events a probe reports in its reports (D91, 7.3.2, 7.6.6): only the kinds the hub knows, with the severity the hub gives
//! them, their fields in `data`. A kind it doesn't know is counted and dropped, so a probe can't write what it likes into
//! the events table. The exemptions apply here (E48), and logins make the events that need a history. `conn.overflow` is kept
//! to once an hour per machine (7.3.2).

use std::sync::Arc;

use rackhand_proto::probe::ProbeEvent;
use rackhand_store::Db;
use rusqlite::OptionalExtension;

use super::events::{Event, Severity};
use super::exemptions::{self, Facts, Verdict};
use super::security_events::{self, Logins};

/// How often `conn.overflow` is kept per machine.
pub const OVERFLOW_EVERY_MS: i64 = 3_600_000;

/// What the exemptions turn on, from the hub's own records. The package check (`dpkg -S`) isn't one the hub can make, so a
/// file under the system's binary directories counts as a package's while a patch job runs, and a command list the hub sent
/// is told by the job that sends it.
pub struct DbFacts(pub Arc<Db>);

impl Facts for DbFacts {
    fn running_job(&self, machine: &str, names: &[&str]) -> Option<String> {
        self.0
            .readers()
            .with(|c| {
                let mut s = c.prepare("SELECT id, name FROM jobs WHERE target = ?1 AND state = 'running'")?;
                let rows: Vec<(String, String)> =
                    s.query_map([machine], |r| Ok((r.get(0)?, r.get(1)?)))?.collect::<Result<_, _>>()?;
                Ok(rows
                    .into_iter()
                    .find(|(_, name)| {
                        names.iter().any(|n| n.strip_suffix('*').map_or(*n == name, |p| name.starts_with(p)))
                    })
                    .map(|(id, _)| id))
            })
            .ok()
            .flatten()
    }

    fn enrolling(&self, machine: &str) -> bool {
        let recent = rackhand_store::ids::now_ms() - 10 * 60_000;
        self.0
            .readers()
            .with(|c| {
                let pending: Option<i64> = c
                    .query_row("SELECT 1 FROM machines WHERE id = ?1 AND state = 'pending'", [machine], |r| r.get(0))
                    .optional()?;
                let joined: Option<i64> = c
                    .query_row(
                        "SELECT 1 FROM join_tokens WHERE used_at > ?1 AND json_extract(bound, '$.machine_id') = ?2 LIMIT 1",
                        rusqlite::params![recent, machine],
                        |r| r.get(0),
                    )
                    .optional()?;
                Ok(pending.is_some() || joined.is_some())
            })
            .unwrap_or(false)
    }

    fn sent_commands(&self, machine: &str, _sha256: &str) -> bool {
        self.running_job(machine, &["sudoers-refresh"]).is_some() || self.enrolling(machine)
    }

    fn update_offered(&self, machine: &str, sha256: &str) -> bool {
        let since = rackhand_store::ids::now_ms() - 60 * 60_000;
        // a hash a probe reports is hex or it matches nothing (it goes into a LIKE)
        if !sha256.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return false;
        }
        // an offer is a row keyed `<machine>/<sha256>`; no hash asks for any of the machine's
        let like = format!("{}/{}%", machine.replace(['%', '_', '\\'], ""), sha256);
        self.0
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT EXISTS (SELECT 1 FROM schedule_state WHERE kind = ?1 AND key LIKE ?2 AND last_run_ms > ?3)",
                    rusqlite::params![super::exemptions::UPDATE_OFFERED_KIND, like, since],
                    |r| r.get::<_, bool>(0),
                )
            })
            .unwrap_or(false)
    }

    fn upgraded_by(&self, _machine: &str, _job: &str, path: &str) -> bool {
        ["/usr/bin/", "/usr/sbin/", "/usr/lib/", "/bin/", "/sbin/"].iter().any(|p| path.starts_with(p))
    }
}

/// What a machine's events are turned into with.
pub struct Context<'a> {
    pub facts: &'a dyn Facts,
    pub logins: &'a mut Logins,
    pub last_overflow_ms: &'a mut i64,
    /// Sources of earlier logins, read when the machine's logins are first needed.
    pub known_logins: &'a dyn Fn() -> Vec<(String, String)>,
}

/// What a report's events become. `offset_ms` places the probe's clock on the hub's.
pub fn to_events(machine: &str, events: &[ProbeEvent], offset_ms: i64, ctx: &mut Context<'_>) -> (Vec<Event>, u32) {
    let (mut out, mut unknown) = (Vec::new(), 0);
    for e in events {
        let fields = &e.fields;
        let Some(mut severity) = security_events::severity(&e.kind, fields) else {
            unknown += 1;
            continue;
        };
        let at_ms = e.at_ms + offset_ms;
        if e.kind == "conn.overflow" {
            if at_ms.saturating_sub(*ctx.last_overflow_ms) < OVERFLOW_EVERY_MS {
                continue;
            }
            *ctx.last_overflow_ms = at_ms;
        }
        let mut job_id = None;
        match exemptions::judge(machine, &e.kind, &e.fields.clone().into_iter().collect(), ctx.facts) {
            Verdict::Exempt => continue,
            Verdict::Info { job } => {
                severity = Severity::Info;
                job_id = Some(job);
            }
            Verdict::Raise => {}
        }
        let mut data: serde_json::Map<String, serde_json::Value> =
            fields.iter().map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone()))).collect();
        if let Some(j) = &job_id {
            data.insert("job_id".into(), serde_json::Value::String(j.clone()));
        }
        let subject = fields
            .get("port")
            .or_else(|| fields.get("path"))
            .or_else(|| fields.get("exe"))
            .or_else(|| fields.get("user"))
            .cloned();
        let make = |kind: &str, severity: Severity, data: serde_json::Value, subject: Option<String>| Event {
            at_ms,
            subject,
            job_id: job_id.clone(),
            ..Event::machine(machine, kind, severity, data)
        };
        out.push(make(&e.kind, severity, serde_json::Value::Object(data.clone()), subject));
        // the events that need the machine's history
        let plain: std::collections::BTreeMap<String, String> = fields.clone().into_iter().collect();
        match e.kind.as_str() {
            "auth.login" => {
                if !ctx.logins.loaded {
                    for (user, source) in (ctx.known_logins)() {
                        ctx.logins.learn(&user, &source);
                    }
                    ctx.logins.loaded = true;
                }
                for d in ctx.logins.login(&plain) {
                    out.push(make(
                        d.kind,
                        d.severity,
                        serde_json::Value::Object(data.clone()),
                        plain.get("user").cloned(),
                    ));
                }
            }
            "auth.failed" => {
                if let Some(d) = ctx.logins.failure(at_ms) {
                    out.push(make(
                        d.kind,
                        d.severity,
                        serde_json::Value::Object(data.clone()),
                        plain.get("user").cloned(),
                    ));
                }
            }
            _ => {}
        }
    }
    (out, unknown)
}
