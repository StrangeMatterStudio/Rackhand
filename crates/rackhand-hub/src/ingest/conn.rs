//! Connection records in reports (7.3.2, 7.6.5): scored, their events raised, and their rows stored before compaction deletes
//! the report's frame. The scoring is `conn_score`, the rows `conn_store`.

use rackhand_proto::probe::ConnRecord;
use rackhand_store::WriteCmd;
use rusqlite::OptionalExtension;

use super::conn_score::{self, Conn, Context, Severity, State};
use super::conn_store::{self, Mode, Today};
use super::events::{Event, Severity as EventSeverity};
use super::{Ingest, IngestError};

/// What a machine's connections need between reports.
#[derive(Debug, Default)]
pub struct ConnState {
    pub score: State,
    pub today: Today,
    loaded: bool,
}

struct Settings {
    mode: Mode,
    watch_internal: bool,
}

fn event_severity(s: Severity) -> EventSeverity {
    match s {
        Severity::Info => EventSeverity::Info,
        Severity::Warning => EventSeverity::Warning,
        Severity::Critical => EventSeverity::Critical,
    }
}

impl Ingest {
    /// The machine's policy for connections: `full` unless its policy says otherwise (`summary` by default for a machine with
    /// the role `desktop`, 7.4.1).
    fn conn_settings(&self, machine: &str) -> Settings {
        let row: Option<(Option<String>, Option<i64>, String)> = self
            .inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT p.connections, p.watch_internal, m.roles FROM machines m
                     LEFT JOIN policies p ON p.id = m.policy_id WHERE m.id = ?1",
                    [machine],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()
            })
            .ok()
            .flatten();
        let Some((mode, watch, roles)) = row else { return Settings { mode: Mode::Full, watch_internal: false } };
        let desktop = serde_json::from_str::<Vec<String>>(&roles).unwrap_or_default().iter().any(|r| r == "desktop");
        let mode = match mode {
            Some(m) => Mode::parse(&m),
            None if desktop => Mode::Summary,
            None => Mode::Full,
        };
        Settings { mode, watch_internal: watch.unwrap_or(0) != 0 }
    }

    /// Whether a Rackhand patch job is running on the machine.
    fn patching(&self, machine: &str) -> bool {
        self.inner
            .db
            .readers()
            .with(|c| {
                c.query_row(
                    "SELECT 1 FROM jobs WHERE target = ?1 AND state = 'running' AND name LIKE 'patch-%' LIMIT 1",
                    [machine],
                    |r| r.get::<_, i64>(0),
                )
                .optional()
            })
            .ok()
            .flatten()
            .is_some()
    }

    /// The machine's baseline, read once.
    fn load_conn_state(&self, machine: &str) {
        let rows: Vec<(String, String, i64, String, i64, String, i64)> = self
            .inner
            .db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT container, exe, dest_asn, dest_country, dest_port, proto, first_seen_ms
                     FROM conn_baseline WHERE machine_id = ?1",
                )?;
                s.query_map([machine], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
                })?
                .collect()
            })
            .unwrap_or_default();
        let mut s = self.state();
        let st = &mut s.machines.entry(machine.to_string()).or_default().conn;
        for (container, exe, asn, country, port, proto, first) in rows {
            st.score.exes.insert(exe.clone());
            st.score.countries.insert(country.clone());
            st.score.first_seen_ms = Some(st.score.first_seen_ms.map_or(first, |f| f.min(first)));
            st.score.keys.insert((container, exe, asn as u32, country, port as u16, proto == "tcp"));
        }
        st.loaded = true;
    }

    /// Scores and stores one report's connection records, placed at `at_ms`.
    pub(super) async fn process_connections(
        &self,
        machine: &str,
        at_ms: i64,
        records: &[ConnRecord],
    ) -> Result<(), IngestError> {
        let Some(intel) = self.inner.intel.clone() else { return Ok(()) };
        if records.is_empty() {
            return Ok(());
        }
        if !self.state().machines.get(machine).is_some_and(|m| m.conn.loaded) {
            self.load_conn_state(machine);
        }
        let settings = self.conn_settings(machine);
        let patching = self.patching(machine);
        let today_rows: Option<usize> = {
            let needs = self.state().machines.get(machine).is_none_or(|m| m.conn.today.needs_load(at_ms));
            needs.then(|| {
                let day_start = at_ms - at_ms.rem_euclid(86_400_000);
                self.inner
                    .db
                    .readers()
                    .with(|c| {
                        c.query_row(
                            "SELECT count(*) FROM conn_records WHERE machine_id = ?1 AND bucket_ms >= ?2",
                            rusqlite::params![machine, day_start],
                            |r| r.get::<_, i64>(0),
                        )
                    })
                    .unwrap_or(0) as usize
            })
        };
        // the baseline learning and the daily cap of `config/hub.toml` (7.8.1), read before the state is locked
        let hub = crate::library::config::hub_or_default(&self.inner.db);
        let daily_rows = hub.connections.records_per_day as usize;
        let ctx = Context {
            now_ms: at_ms,
            watch_internal: settings.watch_internal,
            intel: &intel,
            patch_job_running: patching,
            learning_ms: hub.baseline.learning_ms(),
        };
        let (mut events, mut scored, mut baseline) = (Vec::new(), Vec::new(), Vec::new());
        let rows = {
            let mut s = self.state();
            let st = &mut s.machines.entry(machine.to_string()).or_default().conn;
            if let Some(n) = today_rows {
                st.today.load(at_ms, n);
            }
            for r in records {
                let Some(c) = Conn::from_wire(r) else { continue };
                // the threat-list check runs in every mode; learning and the rest only where connections are kept in full
                let outcome = if settings.mode == Mode::Full {
                    let before = st.score.keys.len();
                    let o = conn_score::score(&c, &mut st.score, &ctx);
                    if st.score.keys.len() > before {
                        baseline.push(conn_store::baseline_row(machine, &c, o.asn, o.country.as_deref(), at_ms));
                    }
                    o
                } else {
                    let mut scratch = State::default();
                    let o = conn_score::score(&c, &mut scratch, &ctx);
                    conn_score::Outcome {
                        events: o.events.into_iter().filter(|e| e.kind == "conn.known_bad").collect(),
                        ..o
                    }
                };
                for e in &outcome.events {
                    let mut data = e.data.clone();
                    data["count"] = serde_json::json!(c.count);
                    let subject = data["dest_ip"].as_str().map(str::to_string);
                    events.push(Event {
                        at_ms,
                        subject,
                        ..Event::machine(machine, e.kind, event_severity(e.severity), data)
                    });
                }
                scored.push((c, outcome));
            }
            conn_store::plan(machine, at_ms, &scored, settings.mode, daily_rows, &mut st.today)
        };
        self.raise_events(events).await?;
        if !rows.records.is_empty() {
            self.inner.writer.send(WriteCmd::PutConnRecords(rows.records)).await?;
        }
        if !baseline.is_empty() && settings.mode == Mode::Full {
            self.inner.writer.send(WriteCmd::PutConnBaseline(baseline)).await?;
        }
        Ok(())
    }
}
