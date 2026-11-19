//! Library (7.7.1): runbooks and playbooks with their revisions, a line diff between revisions, validation errors when
//! a change doesn't parse, and drafts proposed by assistants or keys, applied only here.

use askama::Template;
use axum::body::Body;
use axum::http::{HeaderValue, Response, StatusCode, header};

use super::{html, redirect, status};
use crate::library::items::{HistoryEntry, Kind, Library, SaveError};
use crate::web::perms::{Permission, allowed};
use crate::web::{Ctx, Web};

/// The longest file a diff is computed for, in lines.
const MAX_DIFF_LINES: usize = 3000;

struct Item {
    kind: String,
    name: String,
    rev: i64,
}

struct Draft {
    id: String,
    kind: String,
    name: String,
    proposed_by: String,
    reason: String,
}

#[derive(Template)]
#[template(path = "library.html")]
struct List<'a> {
    csrf: &'a str,
    items: Vec<Item>,
    drafts: Vec<Draft>,
    can_edit: bool,
}

#[derive(PartialEq, Eq)]
enum Op {
    Same,
    Del,
    Add,
}

struct Line {
    op: Op,
    text: String,
}

impl Line {
    fn class(&self) -> &'static str {
        match self.op {
            Op::Same => "same",
            Op::Del => "del",
            Op::Add => "add",
        }
    }
}

#[derive(Template)]
#[template(path = "library_item.html")]
struct ItemPage<'a> {
    csrf: &'a str,
    kind: &'a str,
    name: &'a str,
    content: &'a str,
    history: Vec<HistoryEntry>,
    diff: Option<(i64, i64, Vec<Line>)>,
    error: Option<&'a str>,
    can_edit: bool,
}

fn library(web: &Web) -> Library {
    web.0.library.clone().unwrap_or_else(|| Library::new(web.0.db.clone(), web.0.audit.clone()).0)
}

fn can_edit(ctx: &Ctx) -> bool {
    ctx.user.as_ref().is_some_and(|u| allowed(u.role, Permission::EditLibrary))
}

/// A line diff (longest common subsequence) from `a` to `b`.
fn diff(a: &str, b: &str) -> Vec<Line> {
    let (x, y): (Vec<&str>, Vec<&str>) = (a.lines().collect(), b.lines().collect());
    let (n, m) = (x.len(), y.len());
    let mut lcs = vec![vec![0u32; m + 1]; n + 1];
    for i in (0..n).rev() {
        for j in (0..m).rev() {
            lcs[i][j] = if x[i] == y[j] { lcs[i + 1][j + 1] + 1 } else { lcs[i + 1][j].max(lcs[i][j + 1]) };
        }
    }
    let (mut i, mut j, mut out) = (0, 0, Vec::new());
    while i < n || j < m {
        if i < n && j < m && x[i] == y[j] {
            out.push(Line { op: Op::Same, text: x[i].into() });
            (i, j) = (i + 1, j + 1);
        } else if j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j]) {
            out.push(Line { op: Op::Add, text: y[j].into() });
            j += 1;
        } else {
            out.push(Line { op: Op::Del, text: x[i].into() });
            i += 1;
        }
    }
    out
}

fn kind_of(s: &str) -> Option<Kind> {
    match s {
        "runbook" => Some(Kind::Runbook),
        "playbook" => Some(Kind::Playbook),
        _ => None,
    }
}

/// `/library/<kind>/<name>` → the kind and name.
fn item_path(path: &str) -> Option<(Kind, &str, &str)> {
    let rest = path.strip_prefix("/library/")?;
    let (kind, name) = rest.split_once('/')?;
    Some((kind_of(kind)?, kind, name))
}

pub(super) fn list(web: &Web, ctx: &Ctx) -> Response<Body> {
    let found = web.0.db.readers().with(|c| {
        let mut s = c.prepare("SELECT kind, name, rev FROM library_items WHERE kind != 'config' ORDER BY kind DESC, name")?;
        let items =
            s.query_map([], |r| Ok(Item { kind: r.get(0)?, name: r.get(1)?, rev: r.get(2)? }))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let mut s = c.prepare(
            "SELECT id, kind, name, proposed_by, reason FROM library_drafts WHERE state = 'pending' ORDER BY created_at",
        )?;
        let drafts = s
            .query_map([], |r| {
                Ok(Draft { id: r.get(0)?, kind: r.get(1)?, name: r.get(2)?, proposed_by: r.get(3)?, reason: r.get(4)? })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok::<_, rusqlite::Error>((items, drafts))
    });
    match found {
        Ok((items, drafts)) => {
            html(StatusCode::OK, List { csrf: &ctx.csrf, items, drafts, can_edit: can_edit(ctx) }.render())
        }
        Err(e) => {
            tracing::error!(error = %e, "library");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The library is unreadable")
        }
    }
}

fn item_page(web: &Web, ctx: &Ctx, code: StatusCode, typed: Option<&str>, error: Option<&str>) -> Response<Body> {
    let Some((kind, kind_name, name)) = item_path(&ctx.path) else {
        return status(StatusCode::NOT_FOUND, "No such item");
    };
    let lib = library(web);
    let current = lib.current(kind, name).ok().flatten();
    if current.is_none() && typed.is_none() && !can_edit(ctx) {
        return status(StatusCode::NOT_FOUND, "No such item");
    }
    let history = lib.history(kind, name).unwrap_or_default();
    // `?diff=<n>`: revision n against the one after it.
    let diff = ctx.query.get("diff").and_then(|d| d.parse::<i64>().ok()).and_then(|from| {
        let a = lib.revision(kind, name, from).ok().flatten()?;
        let b = lib.revision(kind, name, from + 1).ok().flatten()?;
        (a.lines().count() <= MAX_DIFF_LINES && b.lines().count() <= MAX_DIFF_LINES)
            .then(|| (from, from + 1, diff(&a, &b)))
    });
    let content = typed.map(str::to_string).or(current.map(|(_, c)| c)).unwrap_or_default();
    let page = ItemPage {
        csrf: &ctx.csrf,
        kind: kind_name,
        name,
        content: &content,
        history,
        diff,
        error,
        can_edit: can_edit(ctx),
    };
    html(code, page.render())
}

pub(super) fn item(web: &Web, ctx: &Ctx) -> Response<Body> {
    item_page(web, ctx, StatusCode::OK, None, None)
}

fn see_other(to: &str) -> Response<Body> {
    let mut resp = Response::new(Body::empty());
    *resp.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(v) = HeaderValue::from_str(to) {
        resp.headers_mut().insert(header::LOCATION, v);
    }
    resp
}

/// Saves a new revision, or shows why it doesn't validate with the text kept.
pub(super) async fn save(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some((kind, _, name)) = item_path(&ctx.path) else { return status(StatusCode::NOT_FOUND, "No such item") };
    let content = ctx.form.get("content").map(String::as_str).unwrap_or("");
    match library(web).save(kind, name, content, &user.name, ctx.now_ms).await {
        Ok(_) => see_other(&ctx.path),
        Err(SaveError::Invalid(why)) => item_page(web, ctx, StatusCode::BAD_REQUEST, Some(content), Some(&why)),
        Err(e) => {
            tracing::error!(error = %e, "library save");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The change couldn't be saved")
        }
    }
}

pub(super) async fn apply_draft(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let id = ctx.path.strip_prefix("/library/drafts/").and_then(|r| r.strip_suffix("/apply")).unwrap_or("");
    match library(web).apply_draft(id, &user.name, ctx.now_ms).await {
        Ok(_) => redirect("/library"),
        Err(SaveError::Invalid(why)) => status(StatusCode::BAD_REQUEST, &why),
        Err(e) => {
            tracing::error!(error = %e, "apply draft");
            status(StatusCode::NOT_FOUND, "No such draft waiting")
        }
    }
}
