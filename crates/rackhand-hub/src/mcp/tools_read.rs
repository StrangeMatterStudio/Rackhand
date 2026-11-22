//! The read tools (7.3.6). Machines are named by id or `site/name`; machine output (job logs) comes back wrapped as
//! untrusted, and so is text a machine reported: its OS, service, container and package names, event subjects and data,
//! connection executables, and the incident titles and timelines built from them (owner review, 2026-11-21).

use std::collections::BTreeMap;

use rackhand_store::Db;
use rusqlite::OptionalExtension;
use serde_json::{Value, json};

use super::{Observations, SeriesQuery, ToolError};
use crate::actions::diagnostics::untrusted;

/// The most points `get_vitals` returns.
pub const MAX_POINTS: usize = 2000;
/// Event kinds that are security events (7.6.6).
const SECURITY_PREFIXES: [&str; 6] = ["conn.", "proc.", "user.", "auth.", "file.", "port."];

/// A tool's description and argument schema for `tools/list`.
pub(super) fn describe(tool: &str) -> Value {
    let s = |props: Value, required: &[&str]| json!({ "type": "object", "properties": props, "required": required });
    let string = json!({ "type": "string" });
    let int = json!({ "type": "integer" });
    let (description, schema) = match tool {
        "list_machines" => ("Machines and their health", s(json!({ "site": string, "health": string }), &[])),
        "get_machine" => (
            "A machine: OS, policy, services, containers, updates, open incidents",
            s(json!({ "machine": string }), &["machine"]),
        ),
        "get_vitals" => (
            "A metric's series, at most 2000 points",
            s(
                json!({ "machine": string, "metric": string, "labels": { "type": "object" }, "from": int, "to": int, "step": int }),
                &["machine", "metric", "from", "to"],
            ),
        ),
        "list_incidents" => ("Incidents", s(json!({ "state": string, "severity": string, "machine": string }), &[])),
        "get_incident" => ("An incident: timeline, events, job logs, notes", s(json!({ "id": string }), &["id"])),
        "list_security_events" => {
            ("Security events", s(json!({ "machine": string, "since": int, "kind": string }), &[]))
        }
        "get_connections" => (
            "Connection records with their verdicts",
            s(json!({ "machine": string, "since": int }), &["machine", "since"]),
        ),
        "list_runbooks" => ("Runbooks", s(json!({ "name": string }), &[])),
        "get_runbook" => ("A runbook's definition", s(json!({ "name": string }), &["name"])),
        "list_playbooks" => ("Playbooks", s(json!({ "name": string }), &[])),
        "get_playbook" => ("A playbook", s(json!({ "name": string }), &["name"])),
        "get_approval" => ("An approval's state", s(json!({ "id": string }), &["id"])),
        "run_diagnostic" => (
            "Run a diagnostic from the allow-list on a machine",
            s(json!({ "machine": string, "name": string, "args": { "type": "object" } }), &["machine", "name"]),
        ),
        "exec" => (
            "Run a command on a job host as the assistant identity",
            s(
                json!({ "machine": string, "command": string, "reason": string, "approval_id": string }),
                &["machine", "command", "reason"],
            ),
        ),
        "run_runbook" => (
            "Run a runbook on a machine",
            s(
                json!({ "name": string, "target": string, "params": { "type": "object" }, "reason": string, "approval_id": string }),
                &["name", "target", "reason"],
            ),
        ),
        "propose_library_change" => (
            "Propose a runbook or playbook change; applied only from the dashboard",
            s(
                json!({ "kind": string, "name": string, "content": string, "reason": string }),
                &["kind", "name", "content", "reason"],
            ),
        ),
        "add_incident_note" => {
            ("Add a note to an incident", s(json!({ "incident": string, "text": string }), &["incident", "text"]))
        }
        "finish_job" => {
            ("Finish this job", s(json!({ "outcome": string, "summary": string }), &["outcome", "summary"]))
        }
        _ => ("", s(json!({}), &[])),
    };
    json!({ "name": tool, "description": description, "inputSchema": schema })
}

fn store(e: rusqlite::Error) -> ToolError {
    tracing::error!(error = %e, "mcp read");
    ToolError::new("internal", "the hub couldn't read that")
}

fn arg<'a>(args: &'a Value, name: &str) -> Option<&'a str> {
    args.get(name).and_then(Value::as_str).filter(|s| !s.is_empty())
}

fn need<'a>(args: &'a Value, name: &str) -> Result<&'a str, ToolError> {
    arg(args, name).ok_or_else(|| ToolError::invalid(format!("`{name}` is required")))
}

fn int(args: &Value, name: &str) -> Option<i64> {
    args.get(name).and_then(Value::as_i64)
}

/// A machine named by id or `site/name`.
pub(crate) fn resolve_machine(db: &Db, name: &str) -> Result<String, ToolError> {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT m.id FROM machines m JOIN sites s ON s.id = m.site_id WHERE m.id = ?1 OR s.name || '/' || m.name = ?1",
                [name],
                |r| r.get(0),
            )
            .optional()
        })
        .map_err(store)?
        .ok_or_else(|| ToolError::invalid(format!("no machine `{name}`")))
}

fn rows(
    db: &Db,
    sql: &str,
    params: &[&dyn rusqlite::ToSql],
    f: fn(&rusqlite::Row) -> rusqlite::Result<Value>,
) -> Result<Vec<Value>, ToolError> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare(sql)?;
            let rows = s.query_map(params, f)?;
            rows.collect()
        })
        .map_err(store)
}

/// A value the machine reported, or built from what it reported, wrapped as untrusted like command output (owner
/// review, 2026-11-21); none stays none.
fn reported(v: Value) -> Value {
    if v.is_null() { v } else { json!({ "untrusted_output": v }) }
}

fn json_text(text: Option<String>) -> Value {
    text.and_then(|t| serde_json::from_str(&t).ok()).unwrap_or(Value::Null)
}

/// Fewer points by averaging neighbours, so a long range still fits [`MAX_POINTS`].
fn downsample(points: Vec<(i64, f64)>) -> Vec<(i64, f64)> {
    if points.len() <= MAX_POINTS {
        return points;
    }
    let per = points.len().div_ceil(MAX_POINTS);
    points.chunks(per).map(|c| (c[0].0, c.iter().map(|p| p.1).sum::<f64>() / c.len() as f64)).collect()
}

fn health(state: &str, quarantine: &str, worst: Option<&str>) -> &'static str {
    match (state, quarantine, worst) {
        ("revoked", _, _) => "revoked",
        ("pending", _, _) => "pending",
        (_, q, _) if q != "none" => "quarantined",
        (_, _, Some("critical")) => "critical",
        (_, _, Some("warning")) => "warning",
        _ => "ok",
    }
}

fn library(db: &Db, kind: &str, name: Option<&str>) -> Result<Vec<Value>, ToolError> {
    let sql = "SELECT name, rev, origin FROM library_items WHERE kind = ?1 AND (?2 IS NULL OR name = ?2) ORDER BY name";
    rows(db, sql, &[&kind, &name], |r| {
        Ok(json!({ "name": r.get::<_, String>(0)?, "rev": r.get::<_, i64>(1)?, "origin": r.get::<_, String>(2)? }))
    })
}

fn library_item(db: &Db, kind: &str, name: &str) -> Result<Value, ToolError> {
    db.readers()
        .with(|c| {
            c.query_row(
                "SELECT i.rev, r.content FROM library_items i JOIN library_revisions r
                 ON r.kind = i.kind AND r.name = i.name AND r.rev = i.rev WHERE i.kind = ?1 AND i.name = ?2",
                [kind, name],
                |r| Ok(json!({ "name": name, "rev": r.get::<_, i64>(0)?, "content": r.get::<_, String>(1)? })),
            )
            .optional()
        })
        .map_err(store)?
        .ok_or_else(|| ToolError::invalid(format!("no {kind} `{name}`")))
}

fn machines(db: &Db, site: Option<&str>, want: Option<&str>) -> Result<Value, ToolError> {
    let sql = "SELECT m.id, m.name, s.name, m.kind, m.os, m.access, m.state, m.quarantine,
                      (SELECT max(CASE severity WHEN 'critical' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)
                       FROM incidents i WHERE i.machine_id = m.id AND i.state != 'resolved')
               FROM machines m JOIN sites s ON s.id = m.site_id WHERE (?1 IS NULL OR s.name = ?1) ORDER BY s.name, m.name";
    let all = rows(db, sql, &[&site], |r| {
        let worst: Option<i64> = r.get(8)?;
        let worst = match worst {
            Some(2) => Some("critical"),
            Some(1) => Some("warning"),
            _ => None,
        };
        let (state, quarantine): (String, String) = (r.get(6)?, r.get(7)?);
        Ok(json!({
            "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "site": r.get::<_, String>(2)?,
            "kind": r.get::<_, String>(3)?, "os": reported(json!(r.get::<_, Option<String>>(4)?)),
            "access": r.get::<_, String>(5)?, "health": health(&state, &quarantine, worst),
        }))
    })?;
    let kept: Vec<Value> = all.into_iter().filter(|m| want.is_none_or(|h| m["health"] == h)).collect();
    Ok(json!({ "machines": kept }))
}

fn machine(db: &Db, obs: &dyn Observations, id: &str) -> Result<Value, ToolError> {
    let base = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT m.id, m.name, s.name, m.kind, m.os, m.access, m.state, m.quarantine, m.roles, m.tags, p.name
                 FROM machines m JOIN sites s ON s.id = m.site_id LEFT JOIN policies p ON p.id = m.policy_id
                 WHERE m.id = ?1",
                [id],
                |r| {
                    Ok(json!({
                        "id": r.get::<_, String>(0)?, "name": r.get::<_, String>(1)?, "site": r.get::<_, String>(2)?,
                        "kind": r.get::<_, String>(3)?, "os": reported(json!(r.get::<_, Option<String>>(4)?)),
                        "access": r.get::<_, String>(5)?, "state": r.get::<_, String>(6)?,
                        "quarantine": r.get::<_, String>(7)?, "roles": json_text(r.get(8)?), "tags": json_text(r.get(9)?),
                        "policy": r.get::<_, Option<String>>(10)?,
                    }))
                },
            )
        })
        .map_err(store)?;
    let open = rows(
        db,
        "SELECT id, kind, severity, state, title, opened_at FROM incidents WHERE machine_id = ?1 AND state != 'resolved'
         ORDER BY opened_at DESC",
        &[&id],
        |r| {
            Ok(json!({ "id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "severity": r.get::<_, String>(2)?,
                       "state": r.get::<_, String>(3)?, "title": reported(json!(r.get::<_, String>(4)?)),
                       "opened_at": r.get::<_, i64>(5)? }))
        },
    )?;
    let facts = obs.facts(id);
    let mut out = base;
    out["services"] = reported(Value::Array(facts.services));
    out["containers"] = reported(Value::Array(facts.containers));
    out["updates"] = reported(Value::Array(facts.updates));
    out["open_incidents"] = Value::Array(open);
    Ok(out)
}

fn incident(db: &Db, id: &str) -> Result<Value, ToolError> {
    let base: Option<(Value, Option<String>, i64, Option<i64>)> = db
        .readers()
        .with(|c| {
            c.query_row(
                "SELECT id, machine_id, kind, severity, state, title, opened_at, acked_at, acked_by, resolved_at
                 FROM incidents WHERE id = ?1",
                [id],
                |r| {
                    let machine: Option<String> = r.get(1)?;
                    let (opened, resolved): (i64, Option<i64>) = (r.get(6)?, r.get(9)?);
                    let v = json!({
                        "id": r.get::<_, String>(0)?, "machine": machine, "kind": r.get::<_, String>(2)?,
                        "severity": r.get::<_, String>(3)?, "state": r.get::<_, String>(4)?,
                        "title": reported(json!(r.get::<_, String>(5)?)),
                        "opened_at": opened, "acked_at": r.get::<_, Option<i64>>(7)?, "acked_by": r.get::<_, Option<String>>(8)?,
                        "resolved_at": resolved,
                    });
                    Ok((v, machine, opened, resolved))
                },
            )
            .optional()
        })
        .map_err(store)?;
    let (mut out, machine, opened, resolved) = base.ok_or_else(|| ToolError::invalid(format!("no incident `{id}`")))?;
    let entries =
        rows(db, "SELECT at_ms, kind, data FROM incident_events WHERE incident_id = ?1 ORDER BY at_ms", &[&id], |r| {
            Ok(json!({ "at_ms": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "data": json_text(r.get(2)?) }))
        })?;
    let (notes, timeline): (Vec<Value>, Vec<Value>) = entries.into_iter().partition(|e| e["kind"] == "note");
    // Notes are people's and the assistant's own words; the rest of the timeline can carry what the machine said.
    let timeline: Vec<Value> = timeline
        .into_iter()
        .map(|mut e| {
            e["data"] = reported(e["data"].take());
            e
        })
        .collect();
    let notes: Vec<Value> = notes
        .into_iter()
        .map(|n| json!({ "at_ms": n["at_ms"], "text": n["data"]["text"], "by": n["data"]["by"] }))
        .collect();
    // The machine's events from a quarter of an hour before the incident to its end.
    let until = resolved.unwrap_or(i64::MAX);
    let events = match &machine {
        Some(m) => rows(
            db,
            "SELECT at_ms, kind, severity, subject FROM events WHERE machine_id = ?1 AND at_ms >= ?2 AND at_ms <= ?3 ORDER BY at_ms",
            &[m, &(opened - 900_000), &until],
            |r| {
                Ok(
                    json!({ "at_ms": r.get::<_, i64>(0)?, "kind": r.get::<_, String>(1)?, "severity": r.get::<_, String>(2)?,
                           "subject": reported(json!(r.get::<_, Option<String>>(3)?)) }),
                )
            },
        )?,
        None => Vec::new(),
    };
    let jobs = rows(
        db,
        "SELECT id, kind, name, state, outcome FROM jobs WHERE incident_id = ?1 ORDER BY started_at",
        &[&id],
        |r| {
            Ok(json!({ "id": r.get::<_, String>(0)?, "kind": r.get::<_, String>(1)?, "name": r.get::<_, String>(2)?,
                   "state": r.get::<_, String>(3)?, "outcome": r.get::<_, Option<String>>(4)? }))
        },
    )?;
    let mut job_logs = Vec::new();
    for mut job in jobs {
        let job_id = job["id"].as_str().unwrap_or_default().to_string();
        let steps = rows(
            db,
            "SELECT step_id, state, command, exit_code, stdout, stderr FROM job_steps WHERE job_id = ?1 ORDER BY started_at",
            &[&job_id],
            |r| {
                let mut out: Vec<u8> = r.get::<_, Option<Vec<u8>>>(4)?.unwrap_or_default();
                out.extend(r.get::<_, Option<Vec<u8>>>(5)?.unwrap_or_default());
                Ok(json!({ "step": r.get::<_, String>(0)?, "state": r.get::<_, String>(1)?,
                           "command": r.get::<_, Option<String>>(2)?, "exit_code": r.get::<_, Option<i64>>(3)?,
                           "output": untrusted(&out) }))
            },
        )?;
        job["steps"] = Value::Array(steps);
        job_logs.push(job);
    }
    out["timeline"] = Value::Array(timeline);
    out["events"] = Value::Array(events);
    out["job_logs"] = Value::Array(job_logs);
    out["notes"] = Value::Array(notes);
    Ok(out)
}

pub(super) fn call(db: &Db, obs: &dyn Observations, tool: &str, args: &Value, now: i64) -> Result<Value, ToolError> {
    match tool {
        "list_machines" => machines(db, arg(args, "site"), arg(args, "health")),
        "get_machine" => machine(db, obs, &resolve_machine(db, need(args, "machine")?)?),
        "get_vitals" => {
            let machine_id = resolve_machine(db, need(args, "machine")?)?;
            let (Some(from_ms), Some(to_ms)) = (int(args, "from"), int(args, "to")) else {
                return Err(ToolError::invalid("`from` and `to` (Unix milliseconds) are required"));
            };
            if to_ms < from_ms {
                return Err(ToolError::invalid("`to` is before `from`"));
            }
            let labels: BTreeMap<String, String> = args
                .get("labels")
                .and_then(Value::as_object)
                .map(|o| o.iter().filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_string()))).collect())
                .unwrap_or_default();
            let q = SeriesQuery {
                machine_id: machine_id.clone(),
                metric: need(args, "metric")?.to_string(),
                labels,
                from_ms,
                to_ms,
                step_ms: int(args, "step"),
            };
            let points: Vec<Value> = downsample(obs.series(&q)).into_iter().map(|(t, v)| json!([t, v])).collect();
            Ok(json!({ "machine": machine_id, "metric": q.metric, "labels": q.labels, "points": points }))
        }
        "list_incidents" => {
            let machine = arg(args, "machine").map(|m| resolve_machine(db, m)).transpose()?;
            let (state, severity) = (arg(args, "state"), arg(args, "severity"));
            let list = rows(
                db,
                "SELECT id, machine_id, kind, severity, state, title, opened_at FROM incidents
                 WHERE (?1 IS NULL OR state = ?1) AND (?2 IS NULL OR severity = ?2) AND (?3 IS NULL OR machine_id = ?3)
                 ORDER BY opened_at DESC LIMIT 500",
                &[&state, &severity, &machine],
                |r| {
                    Ok(json!({ "id": r.get::<_, String>(0)?, "machine": r.get::<_, Option<String>>(1)?,
                               "kind": r.get::<_, String>(2)?, "severity": r.get::<_, String>(3)?,
                               "state": r.get::<_, String>(4)?, "title": reported(json!(r.get::<_, String>(5)?)),
                               "opened_at": r.get::<_, i64>(6)? }))
                },
            )?;
            Ok(json!({ "incidents": list }))
        }
        "get_incident" => incident(db, need(args, "id")?),
        "list_security_events" => {
            let machine = arg(args, "machine").map(|m| resolve_machine(db, m)).transpose()?;
            let since = int(args, "since").unwrap_or(now - 7 * 86_400_000);
            let kind = arg(args, "kind");
            let all = rows(
                db,
                "SELECT id, machine_id, at_ms, kind, severity, subject, data FROM events
                 WHERE (?1 IS NULL OR machine_id = ?1) AND at_ms >= ?2 AND (?3 IS NULL OR kind = ?3)
                 ORDER BY at_ms DESC LIMIT 1000",
                &[&machine, &since, &kind],
                |r| {
                    Ok(json!({ "id": r.get::<_, String>(0)?, "machine": r.get::<_, Option<String>>(1)?,
                               "at_ms": r.get::<_, i64>(2)?, "kind": r.get::<_, String>(3)?, "severity": r.get::<_, String>(4)?,
                               "subject": reported(json!(r.get::<_, Option<String>>(5)?)),
                               "data": reported(json_text(r.get(6)?)) }))
                },
            )?;
            let events: Vec<Value> = all
                .into_iter()
                .filter(|e| e["kind"].as_str().is_some_and(|k| SECURITY_PREFIXES.iter().any(|p| k.starts_with(p))))
                .collect();
            Ok(json!({ "events": events }))
        }
        "get_connections" => {
            let machine = resolve_machine(db, need(args, "machine")?)?;
            let since =
                int(args, "since").ok_or_else(|| ToolError::invalid("`since` (Unix milliseconds) is required"))?;
            let list = rows(
                db,
                "SELECT bucket_ms, container, exe, dest_ip, dest_port, proto, dest_asn, dest_country, verdict, bytes_out, count
                 FROM conn_records WHERE machine_id = ?1 AND bucket_ms >= ?2 ORDER BY bucket_ms DESC LIMIT 2000",
                &[&machine, &since],
                |r| {
                    Ok(json!({ "bucket_ms": r.get::<_, i64>(0)?, "container": reported(json!(r.get::<_, String>(1)?)),
                               "exe": reported(json!(r.get::<_, String>(2)?)),
                               "dest_ip": r.get::<_, String>(3)?, "dest_port": r.get::<_, i64>(4)?, "proto": r.get::<_, String>(5)?,
                               "dest_asn": r.get::<_, Option<i64>>(6)?, "dest_country": r.get::<_, Option<String>>(7)?,
                               "verdict": r.get::<_, Option<String>>(8)?, "bytes_out": r.get::<_, i64>(9)?, "count": r.get::<_, i64>(10)? }))
                },
            )?;
            Ok(json!({ "machine": machine, "connections": list }))
        }
        "list_runbooks" => Ok(json!({ "runbooks": library(db, "runbook", arg(args, "name"))? })),
        "get_runbook" => library_item(db, "runbook", need(args, "name")?),
        "list_playbooks" => Ok(json!({ "playbooks": library(db, "playbook", arg(args, "name"))? })),
        "get_playbook" => library_item(db, "playbook", need(args, "name")?),
        "get_approval" => {
            let id = need(args, "id")?;
            db.readers()
                .with(|c| {
                    c.query_row(
                        "SELECT id, tool, target, state, risk, expires_at, decided_by, decided_at FROM approvals WHERE id = ?1",
                        [id],
                        |r| {
                            Ok(json!({ "id": r.get::<_, String>(0)?, "tool": r.get::<_, String>(1)?,
                                       "target": r.get::<_, Option<String>>(2)?, "state": r.get::<_, String>(3)?,
                                       "risk": r.get::<_, String>(4)?, "expires_at": r.get::<_, i64>(5)?,
                                       "decided_by": r.get::<_, Option<String>>(6)?, "decided_at": r.get::<_, Option<i64>>(7)? }))
                        },
                    )
                    .optional()
                })
                .map_err(store)?
                .ok_or_else(|| ToolError::invalid(format!("no approval `{id}`")))
        }
        _ => Err(ToolError::new("tool_not_allowed", format!("no tool `{tool}`"))),
    }
}
