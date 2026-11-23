//! The dashboard's shell (docs/designs/0002-dashboard-ui): the frame every page has, from one table of places filtered by
//! role, which the navigation, the header's search and the keyboard shortcuts all read; the theme; and the pieces
//! templates share (icons, badges, dialogs).

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::perms::{Permission, allowed, role_name};
use super::{Ctx, Web, icons};

pub(crate) const THEME_COOKIE: &str = "rh_theme";
/// Where signing in or stepping up returns to.
pub(crate) const NEXT_COOKIE: &str = "rh_next";

pub(crate) const VERSION: &str = env!("CARGO_PKG_VERSION");
pub(crate) const APP_CSS: &[u8] = include_bytes!("../../static/app.css");
pub(crate) const APP_JS: &[u8] = include_bytes!("../../static/app.js");
pub(crate) const FORMS_JS: &[u8] = include_bytes!("../../static/forms.js");

/// What a page was drawn by: it changes when the version or the hub's own files do.
pub(crate) fn build() -> &'static str {
    static BUILD: OnceLock<String> = OnceLock::new();
    BUILD.get_or_init(|| {
        let mut h = Sha256::new();
        for part in [VERSION.as_bytes(), APP_CSS, APP_JS, FORMS_JS] {
            h.update(part);
        }
        h.finalize().iter().take(4).map(|b| format!("{b:02x}")).collect()
    })
}

/// A place in the dashboard: its name is its page's heading.
pub(crate) struct Place {
    pub path: &'static str,
    pub name: &'static str,
    pub icon: &'static str,
    /// `g` and this letter go there.
    pub key: char,
    pub needs: Permission,
    pub area: Area,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Area {
    /// The sidebar's first group.
    Watch,
    Operate,
    /// The account menu.
    Account,
}

const fn place(
    path: &'static str,
    name: &'static str,
    icon: &'static str,
    key: char,
    needs: Permission,
    area: Area,
) -> Place {
    Place { path, name, icon, key, needs, area }
}

pub(crate) const PLACES: &[Place] = &[
    place("/", "Overview", "home", 'h', Permission::SeeEverything, Area::Watch),
    place("/incidents", "Incidents", "warning", 'i', Permission::SeeEverything, Area::Watch),
    place("/approvals", "Approvals", "fact_check", 'a', Permission::SeeEverything, Area::Watch),
    place("/jobs", "Jobs", "play_circle", 'j', Permission::SeeEverything, Area::Watch),
    place("/library", "Library", "menu_book", 'l', Permission::SeeEverything, Area::Operate),
    place("/patching", "Patching", "system_update_alt", 'p', Permission::SeeEverything, Area::Operate),
    place("/add", "Add", "add_circle", 'n', Permission::Administer, Area::Operate),
    place("/audit", "Audit", "history", 'd', Permission::SeeEverything, Area::Operate),
    place("/account", "Account", "person", 'm', Permission::SeeEverything, Area::Account),
    place("/users", "Users", "group", 'u', Permission::Administer, Area::Account),
    place("/settings", "System settings", "settings", 's', Permission::Administer, Area::Account),
];

/// The shortcuts that aren't places: the keys, as the help shows them, and what they do.
pub(crate) const KEYS: &[(&str, &str)] = &[
    ("<kbd data-ctrl>Ctrl</kbd> <kbd>K</kbd>", "Find anything"),
    ("<kbd>/</kbd>", "Find anything"),
    ("<kbd>c</kbd>", "Add a machine"),
    ("<kbd>?</kbd>", "These shortcuts"),
    ("<kbd>Esc</kbd>", "Close what is on top"),
    ("<kbd data-ctrl>Ctrl</kbd> <kbd>Enter</kbd>", "Send the form being written in"),
];

/// The frame of a signed-in page.
pub(crate) struct Shell {
    pub title: String,
    pub csrf: String,
    pub user: String,
    pub role: &'static str,
    pub theme: &'static str,
    pub path: String,
    pub places: Vec<&'static Place>,
    pub sites: Vec<String>,
    pub incidents: i64,
    pub approvals: i64,
    /// Whether the person may add machines (`c`).
    pub adds: bool,
}

/// The theme the browser's cookie asks for: only the two there are, and nothing else of it reaches a page.
pub(crate) fn theme(ctx: &Ctx) -> &'static str {
    match ctx.cookies.get(THEME_COOKIE).map(String::as_str) {
        Some("light") => "light",
        Some("dark") => "dark",
        _ => "",
    }
}

impl Shell {
    pub fn new(web: &Web, ctx: &Ctx, title: &str) -> Shell {
        Shell::at(web, ctx, title, &ctx.path)
    }

    /// A page drawn for another address than the request's (a refused form shows its page).
    pub fn at(web: &Web, ctx: &Ctx, title: &str, path: &str) -> Shell {
        let (incidents, approvals, sites) = web
            .0
            .db
            .readers()
            .with(|c| {
                let incidents =
                    c.query_row("SELECT count(*) FROM incidents WHERE state != 'resolved'", [], |r| r.get(0))?;
                let approvals = c.query_row(
                    "SELECT count(*) FROM approvals WHERE state = 'pending' AND expires_at > ?1",
                    [ctx.now_ms],
                    |r| r.get(0),
                )?;
                let mut s = c.prepare("SELECT name FROM sites ORDER BY is_local DESC, name")?;
                let sites = s.query_map([], |r| r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?;
                Ok::<_, rusqlite::Error>((incidents, approvals, sites))
            })
            .unwrap_or_default();
        let role = ctx.user.as_ref().map(|u| u.role);
        let may = |p: Permission| role.is_some_and(|r| allowed(r, p));
        Shell {
            title: title.to_string(),
            csrf: ctx.csrf.clone(),
            user: ctx.user.as_ref().map(|u| u.name.clone()).unwrap_or_default(),
            role: match role.map(role_name) {
                Some("admin") => "Admin",
                Some("responder") => "Responder",
                _ => "Viewer",
            },
            theme: theme(ctx),
            path: path.to_string(),
            places: PLACES.iter().filter(|p| may(p.needs)).collect(),
            sites,
            incidents,
            approvals,
            adds: may(Permission::Administer),
        }
    }

    // What templates call.

    pub fn in_area(&self, area: &str) -> Vec<&'static Place> {
        let area = match area {
            "watch" => Area::Watch,
            "operate" => Area::Operate,
            _ => Area::Account,
        };
        self.places.iter().copied().filter(|p| p.area == area).collect()
    }

    /// Whether the page is this place, or inside it.
    pub fn here(&self, path: &str) -> bool {
        self.path == path || (path != "/" && path != "/settings" && self.path.starts_with(&format!("{path}/")))
    }

    /// What waits at a place: the number, and how a screen reader says it.
    pub fn waiting(&self, path: &str) -> Option<(i64, String)> {
        match path {
            "/incidents" if self.incidents > 0 => Some((self.incidents, format!("{} open", self.incidents))),
            "/approvals" if self.approvals > 0 => Some((self.approvals, format!("{} waiting", self.approvals))),
            _ => None,
        }
    }

    /// The menu button's name on a phone, where it carries the counts: "Menu: 1 open incident and 2 approvals waiting".
    pub fn menu_name(&self) -> String {
        let say = |n: i64, one: &str, many: &str| match n {
            0 => None,
            1 => Some(format!("1 {one}")),
            n => Some(format!("{n} {many}")),
        };
        let what: Vec<String> = [
            say(self.incidents, "open incident", "open incidents"),
            say(self.approvals, "approval waiting", "approvals waiting"),
        ]
        .into_iter()
        .flatten()
        .collect();
        if what.is_empty() { "Menu".into() } else { format!("Menu: {}", what.join(" and ")) }
    }

    pub fn initial(&self) -> String {
        self.user.chars().next().map(|c| c.to_uppercase().collect()).unwrap_or_default()
    }

    pub fn version(&self) -> &'static str {
        VERSION
    }

    pub fn build(&self) -> &'static str {
        build()
    }
}

/// An icon beside text.
pub(crate) fn icon(name: &str) -> String {
    let path = icons::path(name).unwrap_or_default();
    format!("<svg class=\"i\" viewBox=\"0 -960 960 960\" aria-hidden=\"true\"><path d=\"{path}\"/></svg>")
}

/// The mark: a rack drawer pulled out by its handle. The favicon (`static/icon.svg`) is the same drawing.
pub(crate) const MARK: &str = include_str!("../../static/icon.svg");

/// A state as a badge: its color, an icon and a word, never the color alone.
pub(crate) fn badge(state: &str) -> String {
    let (class, name, word) = match state {
        "ok" => (" ok", "check_circle", "Healthy"),
        "critical" => (" err", "error", "Critical"),
        "warning" => (" warn", "warning", "Warning"),
        "info" => ("", "info", "Info"),
        "silent" => (" err", "cloud_off", "Silent"),
        "quarantined" => (" err", "block", "Quarantined"),
        "pending" => (" warn", "hourglass_top", "Pending"),
        "revoked" => ("", "block", "Revoked"),
        "enrolled" => (" ok", "check", "Enrolled"),
        "running" | "active" | "up" => (" ok", "check_circle", "Running"),
        "failed" => (" err", "error", "Failed"),
        "timed_out" => (" err", "error", "Timed out"),
        "interrupted" => (" warn", "warning", "Interrupted"),
        "cancelled" => ("", "block", "Cancelled"),
        "queued" => ("", "hourglass_top", "Queued"),
        "waiting_approval" => (" warn", "hourglass_top", "Waiting for approval"),
        "succeeded" | "success" | "done" => (" ok", "check_circle", "Succeeded"),
        "open" => (" warn", "error", "Open"),
        "resolved" => (" ok", "check_circle", "Resolved"),
        "high" => (" err", "warning", "High risk"),
        "normal" => (" warn", "info", "Normal risk"),
        "low" => ("", "info", "Low risk"),
        other => return format!("<span class=\"badge\">{}</span>", escape(&word(other))),
    };
    format!("<span class=\"badge{class}\">{}{word}</span>", icon(name))
}

/// A stored word as it is read: `approve-only` is `Approve only`.
/// An incident's state (7.5.2), as someone new reads it.
pub(crate) fn incident_state(stored: &str) -> String {
    match stored {
        "automation" => "A runbook is on it".into(),
        "assistant" => "The assistant is on it".into(),
        "human" => "Needs a person".into(),
        other => word(other),
    }
}

pub(crate) fn word(stored: &str) -> String {
    let spaced = stored.replace(['_', '-'], " ");
    let mut chars = spaced.chars();
    chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default()
}

/// What stands behind the state a badge would hide, for the attribute a script or a person can read.
pub(crate) fn escape(text: &str) -> String {
    text.replace('&', "&#38;").replace('<', "&#60;").replace('>', "&#62;").replace('"', "&#34;").replace('\'', "&#39;")
}

/// Text that wraps between words only: each is one piece (what an approval runs can't be misread on a small screen).
pub(crate) fn words(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while !rest.is_empty() {
        let space = rest.chars().next().is_some_and(char::is_whitespace);
        let end = rest.find(|c: char| c.is_whitespace() != space).unwrap_or(rest.len());
        let (piece, after) = rest.split_at(end);
        if space {
            out.push_str(piece);
        } else {
            out.push_str(&format!("<span>{}</span>", escape(piece)));
        }
        rest = after;
    }
    out
}

/// A moment, with its weekday, for people; the exact time is in the element.
pub(crate) fn time(ms: i64) -> String {
    let Ok(t) = jiff::Timestamp::from_millisecond(ms) else { return String::new() };
    format!("<time datetime=\"{t}\">{}</time>", t.strftime("%A, %B %-d, %H:%M UTC"))
}

/// Whether every word searched for is in the text, in any order and case.
pub(crate) fn found(q: &str, text: &[&str]) -> bool {
    let text = text.join(" ").to_lowercase();
    q.to_lowercase().split_whitespace().all(|w| text.contains(w))
}

/// What a page's search looks for.
pub(crate) fn query(ctx: &Ctx) -> String {
    ctx.query.get("q").map(|q| q.trim().chars().take(200).collect()).unwrap_or_default()
}

/// A search box over a list. The hub answers it; with the script a list sent whole filters as you type.
pub(crate) fn search(path: &str, q: &str, what: &str) -> String {
    let what = escape(what);
    let id: String = what.chars().filter(char::is_ascii_alphanumeric).collect::<String>().to_lowercase();
    format!(
        "<form class=\"find\" role=\"search\" method=\"get\" action=\"{}\">{}<input type=\"search\" id=\"find-{id}\" name=\"q\" \
         value=\"{}\" placeholder=\"Search {what}\" aria-label=\"Search {what}\" autocomplete=\"off\" data-filter>\
         <button type=\"submit\">Search</button></form>",
        escape(path),
        icon("search"),
        escape(q)
    )
}

/// A list with nothing in it: nothing matched, or nothing there yet.
pub(crate) fn none(q: &str, what: &str, next: &str) -> String {
    if q.is_empty() {
        return format!("<p class=\"empty\">{next}</p>");
    }
    format!("<p class=\"empty\">No {what} match \u{201c}{}\u{201d}.</p>", escape(q))
}

/// The id of a dialog's heading: its own, so a question over an editor is announced by its own name.
fn heading_id(title: &str) -> String {
    let word = |c: char| if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '-' };
    format!("dialog-{}", title.chars().map(word).collect::<String>().trim_matches('-'))
}

/// A dialog's opening, drawn open: a card in the page, which the script makes modal. Its way out is a link.
pub(crate) fn dialog(title: impl AsRef<str>, back: impl AsRef<str>) -> String {
    let id = heading_id(title.as_ref());
    let (title, back) = (escape(title.as_ref()), escape(back.as_ref()));
    format!(
        "<dialog open data-modal data-back=\"{back}\" aria-labelledby=\"{id}\"><div class=\"d-h\">\
         <h2 id=\"{id}\">{title}</h2><a class=\"btn ghost\" href=\"{back}\" data-close aria-label=\"Close\">{}</a></div>",
        icon("close")
    )
}

/// A question before a removal: the safe choice first and focused, then what it does.
pub(crate) struct Confirm {
    pub title: String,
    pub body: String,
    pub action: String,
    pub keep: &'static str,
    pub does: String,
    pub back: &'static str,
}

impl Confirm {
    pub fn html(&self, csrf: &str) -> String {
        format!(
            "<dialog open data-modal data-back=\"{back}\" class=\"small\" role=\"alertdialog\" aria-labelledby=\"{id}\" \
             aria-describedby=\"{id}-body\"><div class=\"d-h\"><h2 id=\"{id}\">{title}</h2></div>\
             <div class=\"d-b\"><p id=\"{id}-body\">{body}</p></div><form class=\"d-f\" method=\"post\" action=\"{action}\">\
             <input type=\"hidden\" name=\"csrf\" value=\"{csrf}\"><a class=\"btn\" href=\"{back}\" data-close autofocus>{keep}</a>\
             <button type=\"submit\" class=\"danger\">{does}</button></form></dialog>",
            id = heading_id(&self.title),
            back = escape(self.back),
            title = escape(&self.title),
            body = escape(&self.body),
            action = escape(&self.action),
            csrf = escape(csrf),
            keep = self.keep,
            does = escape(&self.does),
        )
    }
}

/// The dialog a page's address asks for: `?add=user`, `?edit=<id>`, `?confirm=disable:<id>`.
pub(crate) fn asked<'a>(ctx: &'a Ctx, what: &str) -> Option<&'a str> {
    ctx.query.get(what).map(String::as_str).filter(|v| !v.is_empty())
}

/// A path of this hub, for returning to; anything else is the overview.
pub(crate) fn local(path: &str) -> &str {
    let fits = path.starts_with('/')
        && !path.starts_with("//")
        && path.len() <= 512
        && path.bytes().all(|b| b.is_ascii_graphic() && b != b'\\' && b != b';' && b != b'"' && b != b',');
    if fits { path } else { "/" }
}
