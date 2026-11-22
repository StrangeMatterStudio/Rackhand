//! Jobs (7.7.1, AC12): runs, and for each its steps with the command, exit code and output as stored (cut at 1 MiB
//! with its marker). Output is machine text, shown escaped.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rusqlite::OptionalExtension;

use super::{html, status};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

struct Run {
    id: String,
    kind: String,
    name: String,
    target: String,
    state: String,
    outcome: String,
    requested_by: String,
}

struct StepView {
    id: String,
    state: String,
    command: String,
    exit_code: Option<i64>,
    stdout: String,
    stderr: String,
}

#[derive(Template)]
#[template(path = "jobs.html")]
struct List {
    shell: Shell,
    q: String,
    runs: Vec<Run>,
}

#[derive(Template)]
#[template(path = "job.html")]
struct Detail {
    shell: Shell,
    run: Run,
    steps: Vec<StepView>,
}

fn run(r: &rusqlite::Row) -> rusqlite::Result<Run> {
    Ok(Run {
        id: r.get(0)?,
        kind: r.get(1)?,
        name: r.get(2)?,
        target: r.get::<_, Option<String>>(3)?.unwrap_or_default(),
        state: r.get(4)?,
        outcome: r.get::<_, Option<String>>(5)?.unwrap_or_default(),
        requested_by: r.get(6)?,
    })
}

const COLUMNS: &str = "id, kind, name, target, state, outcome, requested_by";

pub(super) fn list(web: &Web, ctx: &Ctx) -> Response<Body> {
    let runs: rusqlite::Result<Vec<Run>> = web.0.db.readers().with(|c| {
        let mut s = c.prepare(&format!("SELECT {COLUMNS} FROM jobs ORDER BY started_at DESC LIMIT 200"))?;
        let rows = s.query_map([], run)?;
        rows.collect()
    });
    match runs {
        Ok(runs) => {
            let q = ui::query(ctx);
            let fits = |r: &Run| ui::found(&q, &[&r.name, &r.kind, &r.target, &r.state, &r.outcome, &r.requested_by]);
            let runs = runs.into_iter().filter(fits).collect();
            html(StatusCode::OK, List { shell: Shell::new(web, ctx, "Jobs"), q: q.clone(), runs }.render())
        }
        Err(e) => {
            tracing::error!(error = %e, "jobs");
            status(StatusCode::INTERNAL_SERVER_ERROR, "Jobs unreadable")
        }
    }
}

pub(super) fn detail(web: &Web, ctx: &Ctx) -> Response<Body> {
    let id = ctx.path.strip_prefix("/jobs/").unwrap_or("");
    let found: rusqlite::Result<Option<(Run, Vec<StepView>)>> = web.0.db.readers().with(|c| {
        let Some(job) = c.query_row(&format!("SELECT {COLUMNS} FROM jobs WHERE id = ?1"), [id], run).optional()? else {
            return Ok(None);
        };
        let mut s = c.prepare(
            "SELECT step_id, state, command, exit_code, stdout, stderr FROM job_steps WHERE job_id = ?1 ORDER BY started_at",
        )?;
        let text = |b: Option<Vec<u8>>| String::from_utf8_lossy(&b.unwrap_or_default()).into_owned();
        let steps = s
            .query_map([id], |r| {
                Ok(StepView {
                    id: r.get(0)?,
                    state: r.get(1)?,
                    command: r.get::<_, Option<String>>(2)?.unwrap_or_default(),
                    exit_code: r.get(3)?,
                    stdout: text(r.get(4)?),
                    stderr: text(r.get(5)?),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(Some((job, steps)))
    });
    match found {
        Ok(Some((run, steps))) => {
            html(StatusCode::OK, Detail { shell: Shell::new(web, ctx, &run.name), run, steps }.render())
        }
        Ok(None) => status(StatusCode::NOT_FOUND, "No such job"),
        Err(e) => {
            tracing::error!(error = %e, "job");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The job is unreadable")
        }
    }
}
