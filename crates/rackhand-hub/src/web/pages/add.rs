//! Add (7.7.1, 7.3.12): the one-time install command for a Linux, Alpine or Windows machine (local or remote, managed
//! or monitor; for Linux and Alpine also the offline variant, which fetches the hub's own `install.sh` and checks it
//! against its SHA-256), invites for devices, operators and peers (the hub's ticket plus a one-time secret, 24 hours),
//! the site bootstrap command (7.7.4), and the machines added in the last day with how their enrollment went. Admin
//! only.

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_proto::common::{Access, ProbeMode};
use sha2::{Digest, Sha256};

use super::{html, redirect, status};
use crate::registry::machines::AddMachine;
use crate::web::forms::{self, Choices, Form, Spec};
use crate::web::ui::{self, Shell};
use crate::web::{Ctx, Web};

fn release_url() -> String {
    format!("https://github.com/StrangeMatterStudio/Rackhand/releases/download/v{}", env!("CARGO_PKG_VERSION"))
}

#[derive(Template)]
#[template(path = "add.html")]
struct AddPage<'a> {
    shell: Shell,
    /// The dialog that is open, by its form.
    open: String,
    csrf: &'a str,
    machine: Form,
    /// The appliance forms: driver, title, form.
    appliances: Vec<(&'static str, &'static str, Form)>,
    device: Form,
    bootstrap: String,
    lxc: String,
    /// Machines enrolled in the last day, newest first: name, access, how it went.
    recent: Vec<(String, String, String)>,
}

/// What an appliance of a driver is, on the Add page.
pub(super) fn about(driver: &str) -> &'static str {
    match driver {
        "proxmox" => "Virtualization hosts and clusters",
        "truenas" => "Storage servers",
        "redfish" => "A server's management board (BMC)",
        "snmp" => "Switches, routers, printers and UPSes",
        _ => "Through its API",
    }
}

/// What a machine or an appliance is called.
pub(super) const NAME_HINT: &str = "1 to 64 letters, digits, dots, dashes and underscores; not used here yet.";
pub(super) const NAME_PATTERN: &str = r"[A-Za-z0-9._\-]{1,64}";
pub(super) const NAME_RULE: &str = "Use 1 to 64 letters, digits, dots, dashes and underscores, with no spaces";
pub(super) const PLAIN: &str = "autocomplete=\"off\" autocapitalize=\"none\" spellcheck=\"false\"";

const SYSTEMS: Choices = &[("linux", "Linux"), ("alpine", "Alpine"), ("windows", "Windows")];
const ACCESS: Choices = &[("managed", "Managed"), ("monitor", "Monitor only")];
const ACCESS_HINT: &str = "Managed: the hub can also patch it and run runbooks on it. Monitor only: it is watched, and the hub can run nothing on it.";
const MODES: Choices = &[("local", "Local"), ("remote", "Remote")];
const MODES_HINT: &str = "Local when it is on this hub's network. Remote for a machine at a place with no hub of its own: its probe reports over the internet, and the hub reaches it through the probe.";

/// The roles of section 10 a machine can have; none for an ordinary server.
const ROLES: Choices = &[
    ("hub", "Hub host"),
    ("hypervisor", "Hypervisor"),
    ("operator", "Operator host"),
    ("relay", "Relay host"),
    ("storage", "Storage"),
    ("network", "Network"),
    ("desktop", "Desktop"),
];
const ROLES_HINT: &str = "Leave it empty for an ordinary server. A hub host gets no assistant account; the assistant's commands on hypervisor, operator and relay hosts are high risk, and those are never quarantined; a desktop's connections are kept as a summary.";

const MACHINE: &[Spec] = &[
    Spec::text("name", "Name").hint(NAME_HINT).pattern(NAME_PATTERN, NAME_RULE).attrs(PLAIN),
    Spec::select("os", "System", SYSTEMS),
    Spec::select("access", "Access", ACCESS).hint(ACCESS_HINT),
    Spec::select("mode", "Probe", MODES).hint(MODES_HINT),
    Spec::select("role", "Role", ROLES).hint(ROLES_HINT).optional(),
];

const DEVICE: &[Spec] = &[Spec::select("user", "Device of", &[])
    .hint("The person whose laptop or phone it is. The device acts as them, with their role.")];

/// The people a device can belong to.
fn user_options(web: &Web) -> forms::Groups {
    let users = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id, name FROM users WHERE disabled_at IS NULL ORDER BY name")?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap_or_default();
    vec![(String::new(), users)]
}

/// Whether a machine of that name is already at the site.
pub(super) fn name_taken(web: &Web, site: &str, name: &str) -> bool {
    web.0
        .db
        .readers()
        .with(|c| {
            c.query_row("SELECT count(*) > 0 FROM machines WHERE site_id = ?1 AND name = ?2", [site, name], |r| {
                r.get(0)
            })
        })
        .unwrap_or(false)
}

pub(super) fn local_site(web: &Web) -> Option<String> {
    web.0.db.readers().with(|c| c.query_row("SELECT id FROM sites WHERE is_local = 1", [], |r| r.get(0))).ok()
}

/// How long a machine stays in the Add page's list.
const RECENT_MS: i64 = 86_400_000;

#[derive(Template)]
#[template(path = "add_done.html")]
pub(super) struct AddDone {
    pub shell: Shell,
    pub lines: Vec<(String, String)>,
    pub note: String,
    /// Where the page leads back to, and what it calls it.
    pub back: (String, String),
}

pub(super) fn page(web: &Web, ctx: &Ctx) -> Response<Body> {
    show(web, ctx, StatusCode::OK, None)
}

/// The page, with the form that was refused as it was sent.
pub(super) fn show(web: &Web, ctx: &Ctx, code: StatusCode, mut sent: Option<Form>) -> Response<Body> {
    let url = release_url();
    let open = match sent.as_ref().map(|f| f.id()) {
        Some("add-machine") => "machine".to_string(),
        Some("invite-device") => "device".to_string(),
        Some(id) => id.trim_start_matches("add-").to_string(),
        None => ui::asked(ctx, "add").unwrap_or("").to_string(),
    };
    let page = AddPage {
        shell: Shell::at(web, ctx, "Add", "/add"),
        open,
        csrf: &ctx.csrf,
        machine: Form::blank("add-machine", MACHINE).or_sent(&mut sent),
        appliances: super::appliance::forms(web, &mut sent),
        device: Form::blank("invite-device", DEVICE).options("user", user_options(web)).or_sent(&mut sent),
        bootstrap: format!("curl -fsSL {url}/install.sh | sudo sh -s -- --hub"),
        lxc: format!("curl -fsSL {url}/rackhand-lxc.sh | sudo sh"),
        recent: recent(web),
    };
    html(code, page.render())
}

/// The machines enrolled in the last day (7.3.12): a managed one is enrolled and healthy once the hub's SSH test
/// passed, and shows the latest failure with its account until then; a monitor one once it reports.
fn recent(web: &Web) -> Vec<(String, String, String)> {
    type Row = (String, String, String, String, Option<String>, Option<String>, Option<String>);
    let since = rackhand_store::ids::now_ms() - RECENT_MS;
    let rows: Vec<Row> = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT m.id, m.name, m.access, m.state, e.kind, json_extract(e.data, '$.account'), json_extract(e.data, '$.reason')
                 FROM machines m
                 LEFT JOIN events e ON e.id = (
                   SELECT id FROM events WHERE machine_id = m.id
                     AND kind IN ('machine.ssh_test_passed', 'machine.ssh_test_failed')
                   ORDER BY at_ms DESC LIMIT 1)
                 WHERE m.state IN ('pending', 'enrolled') AND m.enrolled_at >= ?1 AND m.driver IS NULL
                 ORDER BY m.enrolled_at DESC LIMIT 50",
            )?;
            s.query_map([since], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?))
            })?
                .collect()
        })
        .unwrap_or_default();
    let reporting = |id: &str| web.0.ingest.as_ref().and_then(|i| i.last_seen(id)).is_some();
    rows.into_iter()
        .map(|(id, name, access, machine_state, test, account, reason)| {
            // D84: a managed machine is pending until its SSH test passes.
            let pending = if machine_state == "pending" { "Pending: " } else { "" };
            let state = match (access.as_str(), test.as_deref()) {
                ("managed", Some(crate::ssh::enroll_test::PASSED)) if machine_state != "pending" => {
                    "Enrolled and healthy".to_string()
                }
                ("managed", Some(crate::ssh::enroll_test::FAILED)) => format!(
                    "{pending}SSH test failed as {}: {}",
                    account.unwrap_or_else(|| "rackhand".into()),
                    reason.unwrap_or_default()
                ),
                ("managed", _) if machine_state == "pending" => "Pending: waiting for the hub's SSH test".to_string(),
                ("managed", _) => "Waiting for the hub's SSH test".to_string(),
                _ if reporting(&id) => "Enrolled and healthy".to_string(),
                _ => "Waiting for its first report".to_string(),
            };
            (name, access, state)
        })
        .collect()
}

/// A release file the hub holds, by its plain name (no path, nothing hidden), for the offline install.
pub(super) fn release_file(web: &Web, name: &str) -> Response<Body> {
    let plain = (1..=128).contains(&name.len())
        && !name.starts_with('.')
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-');
    let found = web.release_dir().filter(|_| plain).and_then(|dir| std::fs::read(dir.join(name)).ok());
    let Some(bytes) = found else { return status(StatusCode::NOT_FOUND, "Not found") };
    let kind = if name.ends_with(".sh") { "text/x-shellscript" } else { "application/octet-stream" };
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, kind)
        .body(Body::from(bytes))
        .unwrap_or_else(|_| status(StatusCode::INTERNAL_SERVER_ERROR, "Not served"))
}

/// The hub's own `install.sh` and its SHA-256, when the hub holds the release files.
fn held_script(web: &Web) -> Option<String> {
    let bytes = std::fs::read(web.release_dir()?.join("install.sh")).ok()?;
    Some(Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect())
}

pub(super) async fn machine(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("add-machine", MACHINE, ctx, &web.0.held);
    let (Some(registry), Some(ticket)) = (web.0.registry.as_ref(), web.ticket()) else {
        form.notice("The hub isn't ready to add machines yet; try again in a minute.");
        return show(web, ctx, StatusCode::SERVICE_UNAVAILABLE, Some(form));
    };
    let Some(site) = local_site(web) else { return status(StatusCode::CONFLICT, "Complete first run first") };
    form.check();
    let mut code = StatusCode::BAD_REQUEST;
    if !form.has_error("name") && name_taken(web, &site, form.value("name")) {
        if form.ok() {
            code = StatusCode::CONFLICT;
        }
        form.refuse("name", "A machine of that name is already here");
    }
    if !form.ok() {
        return show(web, ctx, code, Some(form));
    }
    let name = form.value("name").to_string();
    let kind = match form.value("os") {
        "alpine" => "alpine",
        "windows" => "windows",
        _ => "linux",
    };
    let access = if form.value("access") == "monitor" { Access::Monitor } else { Access::Managed };
    let mode = if form.value("mode") == "remote" { ProbeMode::Remote } else { ProbeMode::Local };
    let roles = match form.value("role") {
        "" => vec![],
        role => vec![role.to_string()],
    };
    let add = AddMachine { site_id: site, name: name.clone(), kind: kind.into(), access, mode, roles };
    let (id, token) = match registry.add_machine(&add, &user.name, ctx.now_ms).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "add machine");
            form.notice("The machine couldn't be added; try again.");
            return show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form));
        }
    };
    let (id, token) = (id.to_string(), token.as_str().to_string());
    let monitor = access == Access::Monitor;
    let remote = mode == ProbeMode::Remote;
    let lines = install_commands(web, ctx, kind, &ticket, &token, monitor, remote);
    let data = serde_json::json!({ "machine": id, "name": name, "os": kind, "access": if monitor { "monitor" } else { "managed" } });
    if let Err(e) = web.0.audit.append(&user.name, "machine.added", Some(&id), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
    let page = AddDone {
        shell: Shell::at(web, ctx, &format!("Install the probe on {name}"), "/add"),
        lines,
        note: "The command works once, for 60 minutes. Run it on the machine. It shows on the Overview once its probe connects."
            .into(),
        back: ("/add".into(), "Back to Add".into()),
    };
    html(StatusCode::OK, page.render())
}

/// The one-time install commands for a machine of `kind`: the release's and, for Linux and Alpine, the offline one from
/// this hub. `monitor` and `remote` add the flags; the same commands change an enrolled machine's level (7.3.12).
pub(super) fn install_commands(
    web: &Web,
    ctx: &Ctx,
    kind: &str,
    ticket: &str,
    token: &str,
    monitor: bool,
    remote: bool,
) -> Vec<(String, String)> {
    let flags = format!("{}{}", if monitor { " --monitor" } else { "" }, if remote { " --remote" } else { "" });
    let args = format!("--ticket {ticket} --token {token}{flags}");
    let url = release_url();
    let mut lines = Vec::new();
    match kind {
        "windows" => {
            let ps = format!(
                "iwr -useb {url}/install.ps1 -OutFile $env:TEMP\\rackhand-install.ps1; & $env:TEMP\\rackhand-install.ps1 -Ticket {ticket} -Token {token}{}{}",
                if monitor { " -Monitor" } else { "" },
                if remote { " -Remote" } else { "" }
            );
            lines.push(("In PowerShell as Administrator".to_string(), ps));
        }
        "alpine" => lines.push(("As root".to_string(), format!("wget -qO- {url}/install.sh | sh -s -- {args}"))),
        _ => lines
            .push(("As a user with sudo".to_string(), format!("curl -fsSL {url}/install.sh | sudo sh -s -- {args}"))),
    }
    if kind != "windows" {
        // the address the admin reached the dashboard at, else the ticket's first on the default dashboard port
        let fallback = ticket.split_once('@').and_then(|(_, a)| a.split([',', '!']).next()).and_then(|a| {
            a.parse::<std::net::SocketAddr>().ok().map(|s| std::net::SocketAddr::new(s.ip(), 8443).to_string())
        });
        if let (Some(sha), Some(host)) = (held_script(web), ctx.host.clone().or(fallback)) {
            let hub = format!("https://{host}");
            // Alpine: as root, with BusyBox's wget (a stock Alpine machine has neither sudo nor curl)
            let (fetch, run) = if kind == "alpine" {
                (format!("wget -q --no-check-certificate -O /tmp/rackhand-install.sh {hub}/install.sh"), "sh")
            } else {
                (format!("curl -fsSLk {hub}/install.sh -o /tmp/rackhand-install.sh"), "sudo sh")
            };
            lines.push((
                "Offline, from this hub".to_string(),
                format!(
                    "{fetch} && echo '{sha}  /tmp/rackhand-install.sh' | sha256sum -c - && {run} /tmp/rackhand-install.sh {args} --release-url {hub}/release --self-signed"
                ),
            ));
        }
    }
    lines
}

pub(super) async fn invite(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let mut form = Form::sent("invite-device", DEVICE, ctx, &web.0.held).options("user", user_options(web));
    let (Some(registry), Some(ticket)) = (web.0.registry.as_ref(), web.ticket()) else {
        form.notice("The hub isn't ready to invite yet; try again in a minute.");
        return show(web, ctx, StatusCode::SERVICE_UNAVAILABLE, Some(form));
    };
    let kind = ctx.form.get("kind").map(String::as_str).unwrap_or("");
    let issued = match kind {
        "operator" => registry.invite_operator(&user.name, ctx.now_ms).await,
        "peer" => registry.invite_peer(&user.name, ctx.now_ms).await,
        "device" => {
            form.check();
            if !form.ok() {
                return show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
            }
            registry.invite_device(form.value("user"), &user.name, ctx.now_ms).await
        }
        _ => return status(StatusCode::BAD_REQUEST, "The invite is for a device, an operator or a peer"),
    };
    let token = match issued {
        Ok(t) => t,
        Err(e) => {
            tracing::error!(error = %e, "invite");
            form.notice("The invite couldn't be made; try again.");
            return show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form));
        }
    };
    let invite = format!("{ticket}#{}", token.as_str());
    let line = match kind {
        "operator" => ("On the operator host".to_string(), format!("rackhand operator join '{invite}'")),
        "peer" => ("On the other hub, Peers, Join with this invite".to_string(), invite.clone()),
        _ => ("On the device".to_string(), format!("rackhand-cli login '{invite}'")),
    };
    if let Err(e) =
        web.0.audit.append(&user.name, "invite.created", None, &serde_json::json!({ "kind": kind }).to_string()).await
    {
        tracing::error!(error = %e, "audit");
    }
    let page = AddDone {
        shell: Shell::at(web, ctx, &format!("Invite a {kind}"), "/add"),
        lines: vec![line],
        note: "The invite works once, for 24 hours.".into(),
        back: ("/add".into(), "Back to Add".into()),
    };
    html(StatusCode::OK, page.render())
}
