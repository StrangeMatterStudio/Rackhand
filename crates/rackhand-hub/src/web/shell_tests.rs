//! The dashboard's shell and its page rules (docs/designs/0002-dashboard-ui): one frame on every page, lists that inform
//! and dialogs that change, the same on a phone as on a desktop. What the hub decides is checked here, what a browser
//! decides (sizes, overflow) by the script in `docs/designs/0002-dashboard-ui/measure.js`.

use super::first_run::{control, error_of, no_inline, selected};
use super::*;

/// A page's text, as someone reads it: tags out, a term and its value as `Term: value`.
pub(super) fn plain(html: &str) -> String {
    let html = html.replace("</dt>", ": ").replace("</td>", " | ");
    let mut out = String::new();
    let mut tag = false;
    for c in html.chars() {
        match c {
            '<' => tag = true,
            '>' => tag = false,
            _ if !tag => out.push(c),
            _ => {}
        }
    }
    let out = out.replace("&#39;", "'").replace("&#x27;", "'").replace("&#124;", "|").replace("&#38;", "&");
    out.split_whitespace().collect::<Vec<_>>().join(" ").replace(" : ", ": ")
}

/// The text of each cell of a table row.
pub(super) fn cells(row: &str) -> Vec<String> {
    row.split("<td")
        .skip(1)
        .filter_map(|c| {
            let body = &c[c.find('>')? + 1..];
            Some(plain(&body[..body.find("</td>").unwrap_or(body.len())]))
        })
        .collect()
}

fn block<'a>(html: &'a str, open: &str, close: &str) -> &'a str {
    let at = html.find(open).unwrap_or_else(|| panic!("no {open}: {html}"));
    &html[at..at + html[at..].find(close).unwrap_or(html.len() - at)]
}

async fn ready(name: &str) -> (App, String) {
    let app = app_with(name, |web| {
        let registry = crate::registry::Registry::load(web.db().clone()).unwrap();
        let ingest = crate::ingest::Ingest::new(web.db().clone(), crate::bus::Bus::new(), Arc::new(pages::Roomy));
        let ticket = "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";
        web.with_registry(registry).with_ingest(ingest).with_ticket(Arc::new(move || Some(ticket.to_string())))
    })
    .await;
    complete_first_run(&app, SETUP_CODE).await;
    let admin = session_for(&app.db, Role::Admin).await;
    (app, admin)
}

async fn see(app: &App, path: &str, cookie: &str) -> String {
    let resp = send(&app.router, get(path, cookie)).await;
    assert!(resp.status().is_success(), "{path}: {}", resp.status());
    text(resp).await
}

async fn submit(app: &App, cookie: &str, path: &str, fields: &[(&str, &str)]) -> (StatusCode, String) {
    let csrf = csrf_of(app, cookie).await;
    let mut all = vec![("csrf", csrf.as_str())];
    all.extend_from_slice(fields);
    let resp = send(&app.router, post(path, cookie, &all)).await;
    let code = resp.status();
    if code == StatusCode::SEE_OTHER {
        return (code, location(&resp).unwrap_or_default());
    }
    (code, text(resp).await)
}

async fn insert(app: &App, table: &'static str, row: Row) {
    app.db.writer().send(WriteCmd::Batch(vec![RowWrite::insert(table, row)])).await.unwrap();
}

async fn machine(app: &App, id: &str, name: &str) {
    let site: String = app.db.readers().with(|c| c.query_row("SELECT id FROM sites", [], |r| r.get(0))).unwrap();
    let row = Row::from([
        ("id", Value::Text(id.into())),
        ("site_id", Value::Text(site)),
        ("name", Value::Text(name.into())),
        ("kind", Value::Text("linux".into())),
        ("state", Value::Text("enrolled".into())),
    ]);
    insert(app, "machines", row).await;
}

/// How many of `PAGES`, from the first, are in the side navigation.
const NAV: usize = 9;

/// Every page a signed-in admin opens by its address, and the heading it has.
const PAGES: [(&str, &str); 17] = [
    ("/", "Overview"),
    ("/incidents", "Incidents"),
    ("/approvals", "Approvals"),
    ("/jobs", "Jobs"),
    ("/security", "Security"),
    ("/library", "Library"),
    ("/patching", "Patching"),
    ("/add", "Add"),
    ("/audit", "Audit"),
    ("/account", "Account"),
    ("/account/keys", "MCP keys"),
    ("/settings/assistant", "Assistant"),
    ("/users", "Users"),
    ("/settings", "System settings"),
    ("/settings/notifiers", "Notifiers"),
    ("/shortcuts", "Keyboard shortcuts"),
    ("/about", "About"),
];

#[tokio::test(flavor = "multi_thread")]
async fn every_page_has_the_shell() {
    let (app, admin) = ready("shell-pages").await;
    machine(&app, "01JD0000000000000000000001", "web1").await;
    let mut pages: Vec<(&str, &str)> = PAGES.to_vec();
    pages.extend([
        ("/machines/01JD0000000000000000000001", "web1"),
        ("/sites/home", "home"),
        ("/library/config/checks", "config checks"),
        ("/step-up", "Confirm with your authenticator"),
        ("/find?q=web1", "Find"),
    ]);
    for (path, heading) in pages {
        let html = see(&app, path, &admin).await;
        no_inline(&html);
        assert_eq!(html.matches("<h1").count(), 1, "{path}: one heading");
        assert_eq!(plain(block(&html, "<h1", "</h1>")), heading, "{path}");
        assert!(block(&html, "<title>", "</title>").contains(&format!("{heading}: Rackhand")), "{path}: its title");
        // the frame: skip link, mark, search, account, navigation, main
        for part in ["href=\"#main\"", "<header", "<nav", "id=\"main\"", "href=\"/find\"", "action=\"/sign-out\""] {
            assert!(html.contains(part), "{path}: {part}");
        }
        let nav = block(&html, "<nav", "</nav>");
        for (to, name) in &PAGES[..NAV] {
            assert!(nav.contains(&format!("href=\"{to}\"")) && nav.contains(name), "{path}: {name} in the navigation");
        }
        assert!(nav.matches("aria-current=\"page\"").count() <= 1, "{path}");
        if PAGES[..NAV].iter().any(|(p, _)| *p == path) {
            let at = nav.find("aria-current=\"page\"").unwrap_or_else(|| panic!("{path} is marked in the navigation"));
            let link = &nav[nav[..at].rfind("<a").unwrap()..];
            assert!(link[..link.find('>').unwrap()].contains(&format!("href=\"{path}\"")), "{path}: {link}");
        }
        // scripts come from the hub, and the frame's own are there
        assert!(html.contains("src=\"/static/app.js\""), "{path}");
        // what stands alone has a name
        for (i, _) in html.match_indices("<button") {
            let button = &html[i..i + html[i..].find("</button>").unwrap()];
            let open = &button[..button.find('>').unwrap()];
            assert!(
                open.contains("aria-label") || !plain(&format!("{button}</button>")).is_empty(),
                "{path}: {button}"
            );
        }
        // (what the phone's header shows as icons only)
        for class in ["menu-btn", "brand", "search", "pill"] {
            let header = block(&html, "<header", "</header>");
            let at = header.find(&format!("{class}\"")).unwrap_or_else(|| panic!("{path}: {class}"));
            let open = &header[header[..at].rfind('<').unwrap()..];
            assert!(open[..open.find('>').unwrap()].contains("aria-label"), "{path}: {class} has a name");
        }
        for (i, _) in html.match_indices("<svg") {
            let open = &html[i..i + html[i..].find('>').unwrap()];
            assert!(open.contains("aria-hidden=\"true\"") || open.contains("aria-label"), "{path}: {open}");
        }
        for (i, _) in html.match_indices("<th") {
            let th = &html[i..i + html[i..].find('>').unwrap()];
            assert!(th.starts_with("<thead") || th.contains("scope="), "{path}: {th}");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_shell_offers_only_what_the_role_can_open() {
    let (app, admin) = ready("shell-roles").await;
    for (role, sees) in [(Role::Viewer, false), (Role::Responder, false), (Role::Admin, true)] {
        let cookie = session_for(&app.db, role).await;
        let html = see(&app, "/audit", &cookie).await;
        for only in ["href=\"/add\"", "href=\"/users\"", "href=\"/settings\""] {
            assert_eq!(html.contains(only), sees, "{role:?}: {only}");
        }
        assert!(html.contains("href=\"/account\"") && html.contains("href=\"/about\""), "{role:?}");
    }
    // what waits is counted in the navigation, for everyone
    let row = Row::from([
        ("id", Value::Text("01JD00000000000000000000I1".into())),
        ("rule_id", Value::Text("hub.x".into())),
        ("dedupe_key", Value::Text("hub.x".into())),
        ("kind", Value::Text("hub.x".into())),
        ("severity", Value::Text("warning".into())),
        ("state", Value::Text("open".into())),
        ("title", Value::Text("Something".into())),
        ("opened_at", Value::Integer(now_ms())),
    ]);
    insert(&app, "incidents", row).await;
    let nav = see(&app, "/audit", &admin).await;
    let nav = block(&nav, "<nav", "</nav>");
    let link = block(nav, "href=\"/incidents\"", "</a>");
    assert!(link.contains("1 open"), "{link}");
}

#[tokio::test(flavor = "multi_thread")]
async fn errors_are_shown_in_the_shell() {
    let (app, admin) = ready("shell-errors").await;
    let resp = send(&app.router, get("/jobs/nothing", &admin)).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let html = text(resp).await;
    assert!(html.contains("<nav") && html.contains("No such job") && html.contains("href=\"/\""), "{html}");
    // without a session there is no navigation to offer
    let bare = text(send(&app.router, get("/nowhere", "")).await).await;
    assert!(!bare.contains("<nav") && bare.contains("Not found"), "{bare}");
}

#[tokio::test(flavor = "multi_thread")]
async fn the_theme_is_chosen_per_browser() {
    let (app, admin) = ready("shell-theme").await;
    let html = see(&app, "/", &admin).await;
    assert!(!block(&html, "<html", ">").contains("data-theme"), "the system's until someone chooses");
    for label in ["System theme", "Light theme", "Dark theme"] {
        assert!(html.contains(&format!("aria-label=\"{label}\"")), "{label}");
    }
    let csrf = csrf_of(&app, &admin).await;
    let resp =
        send(&app.router, post("/theme", &admin, &[("csrf", csrf.as_str()), ("theme", "dark"), ("back", "/audit")]))
            .await;
    assert_eq!((resp.status(), location(&resp).as_deref()), (StatusCode::SEE_OTHER, Some("/audit")));
    let cookie = set_cookie(&resp, "rh_theme").expect("kept in a cookie");
    assert!(
        cookie.starts_with("rh_theme=dark;") && cookie.contains("HttpOnly") && cookie.contains("Secure"),
        "{cookie}"
    );
    let html = see(&app, "/", &format!("{admin}; rh_theme=dark")).await;
    assert!(block(&html, "<html", ">").contains("data-theme=\"dark\""));
    // before anyone has signed in too, and nothing else from the cookie reaches the page
    let html = see(&app, "/sign-in", "rh_theme=light").await;
    assert!(block(&html, "<html", ">").contains("data-theme=\"light\""));
    let html = see(&app, "/sign-in", "rh_theme=\"onload").await;
    assert!(!block(&html, "<html", ">").contains("theme"), "{html}");
    // back only to a page of the hub
    for elsewhere in ["https://example.test/", "//example.test/", "/\\example.test", "javascript:x", ""] {
        let fields = [("csrf", csrf.as_str()), ("theme", "light"), ("back", elsewhere)];
        let resp = send(&app.router, post("/theme", &admin, &fields)).await;
        assert_eq!(location(&resp).as_deref(), Some("/"), "{elsewhere}");
    }
    let resp = send(&app.router, post("/theme", &admin, &[("theme", "dark")])).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "not without the page's token");
}

/// Both themes are defined once, and every pair of colors used together can be read (WCAG AA, 4.5:1).
#[test]
fn every_color_pair_can_be_read_in_both_themes() {
    let css = include_str!("../../static/app.css");
    let token = |name: &str, dark: bool| -> [f64; 3] {
        let at = css.find(&format!("--{name}: light-dark(")).unwrap_or_else(|| panic!("--{name}"));
        let pair = &css[at + name.len() + 15..];
        let (light, rest) = pair.split_once(',').unwrap();
        let hex = if dark { rest[..rest.find(')').unwrap()].trim() } else { light.trim() };
        let part = |i: usize| f64::from(u8::from_str_radix(&hex[i..i + 2], 16).unwrap()) / 255.0;
        [part(1), part(3), part(5)]
    };
    let luminance = |c: [f64; 3]| {
        let l = c.map(|v| if v <= 0.03928 { v / 12.92 } else { ((v + 0.055) / 1.055).powf(2.4) });
        0.2126 * l[0] + 0.7152 * l[1] + 0.0722 * l[2]
    };
    let pairs = [
        ("fg", "bg"),
        ("fg", "surface"),
        ("fg", "soft"),
        ("fg", "accent-soft"),
        ("muted", "bg"),
        ("muted", "surface"),
        ("muted", "soft"),
        ("accent", "bg"),
        ("accent", "surface"),
        ("accent", "soft"),
        ("accent", "accent-soft"),
        ("accent-fg", "accent"),
        ("ok", "surface"),
        ("ok", "ok-bg"),
        ("warn", "warn-bg"),
        ("err", "surface"),
        ("err", "bg"),
        ("err", "err-bg"),
        ("focus", "bg"),
        ("focus", "surface"),
    ];
    for dark in [false, true] {
        for (a, b) in pairs {
            let (x, y) = (luminance(token(a, dark)), luminance(token(b, dark)));
            let ratio = (x.max(y) + 0.05) / (x.min(y) + 0.05);
            assert!(ratio >= 4.5, "{a} on {b}, dark {dark}: {ratio:.2}");
        }
    }
    // colors are tokens and nothing else, the focus ring is there, and motion can be turned off
    let rules = &css[css.find("}").unwrap()..];
    for (i, _) in rules.match_indices('#') {
        let word: String = rules[i + 1..].chars().take_while(char::is_ascii_hexdigit).collect();
        assert!(!matches!(word.len(), 3 | 6) || rules[..i].ends_with("url("), "a color outside the tokens: #{word}");
    }
    for must in [":focus-visible", "prefers-reduced-motion: reduce", "[data-instant]", "[hidden]"] {
        assert!(css.contains(must), "{must}");
    }
    assert!(!css.contains("http"), "nothing from elsewhere");
}

/// A list informs: no form in a row, one button at most, every cell labeled for a phone.
#[tokio::test(flavor = "multi_thread")]
async fn lists_inform_and_dialogs_change() {
    let (app, admin) = ready("shell-lists").await;
    machine(&app, "01JD0000000000000000000001", "web1").await;
    submit(
        &app,
        &admin,
        "/settings/users",
        &[
            ("name", "kit"),
            ("role", "viewer"),
            ("auth", "local"),
            ("password", "a long enough secret"),
            ("password_again", "a long enough secret"),
        ],
    )
    .await;
    submit(
        &app,
        &admin,
        "/policies",
        &[
            ("name", "web-servers"),
            ("patch", "auto"),
            ("snapshot", "required"),
            ("quarantine", "approval"),
            ("peer_requests", "approval"),
        ],
    )
    .await;
    for path in ["/", "/incidents", "/jobs", "/library", "/patching", "/add", "/audit", "/users", "/settings/notifiers"]
    {
        let html = see(&app, path, &admin).await;
        for (i, _) in html.match_indices("<tr") {
            let row = &html[i..i + html[i..].find("</tr>").unwrap()];
            for control in ["<form", "<select", "<input", "<textarea"] {
                assert!(!row.contains(control), "{path}: {control} in a row: {row}");
            }
            let buttons = row.matches("class=\"btn").count() + row.matches("<button").count();
            assert!(buttons <= 1, "{path}: {buttons} buttons in a row: {row}");
            for (n, cell) in row.split("<td").skip(1).enumerate() {
                let open = &cell[..cell.find('>').unwrap()];
                let labeled = ["data-label=", "class=\"t", "class=\"state", "class=\"act", "colspan="];
                assert!(labeled.iter().any(|l| open.contains(l)), "{path}: cell {n} isn't labeled: {row}");
            }
        }
        // nothing that changes something stands open on a list
        let main = block(&html, "id=\"main\"", "</main>");
        assert!(!main.contains("method=\"post\"") || path == "/add" || path == "/settings/notifiers", "{path}");
        if !matches!(path, "/add" | "/settings/notifiers") {
            assert!(main.contains("role=\"search\""), "{path}: a search");
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dialogs_have_addresses_and_come_drawn_open() {
    let (app, admin) = ready("shell-dialogs").await;
    let id: String =
        app.db.readers().with(|c| c.query_row("SELECT id FROM users WHERE name = 'admin'", [], |r| r.get(0))).unwrap();
    for (path, title, back) in [
        ("/users?add=user".to_string(), "Add a user", "/users"),
        (format!("/users?edit={id}"), "Edit admin", "/users"),
        (format!("/users?confirm=disable:{id}"), "Disable admin?", "/users"),
        ("/patching?add=policy".into(), "Add a policy", "/patching"),
        ("/patching?add=window".into(), "Add a maintenance window", "/patching"),
        ("/settings/notifiers?add=discord".into(), "Discord notifier", "/settings/notifiers"),
        ("/settings/notifiers?add=smtp".into(), "Email notifier", "/settings/notifiers"),
        ("/add?add=machine".into(), "Add a machine", "/add"),
        ("/add?add=truenas".into(), "Add TrueNAS", "/add"),
        ("/add?add=device".into(), "Invite a device", "/add"),
    ] {
        let html = see(&app, &path, &admin).await;
        let dialog = block(&html, "<dialog", "</dialog>");
        let open = &dialog[..dialog.find('>').unwrap()];
        assert!(open.contains(" open") && open.contains("data-modal"), "{path}: {open}");
        assert_eq!(plain(block(dialog, "<h2", "</h2>")), title, "{path}");
        // its way out is a link, for a browser without the script
        assert!(dialog.contains(&format!("href=\"{back}\"")), "{path}: {dialog}");
        // and the list is behind it
        assert_eq!(html.matches("<h1").count(), 1, "{path}");
        // the list offers it
        let list = see(&app, back, &admin).await;
        assert!(!list.contains("<dialog open"), "{back} alone has no dialog open");
        if !path.contains("confirm") && !path.contains("edit") {
            assert!(list.contains(&format!("href=\"{path}\"")), "{back} links to {path}");
        }
    }
    let list = see(&app, "/users", &admin).await;
    assert!(list.contains(&format!("href=\"/users?edit={id}\"")));
    // a refused form comes back in its dialog
    let (code, html) = submit(&app, &admin, "/settings/users", &[("name", "al ice")]).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    let dialog = block(&html, "<dialog", "</dialog>");
    assert!(dialog.contains("Add a user") && !error_of(dialog, "user", "name").is_empty(), "{dialog}");
    // someone who can't change anything isn't shown how
    let viewer = session_for(&app.db, Role::Viewer).await;
    let html = see(&app, "/patching?add=policy", &viewer).await;
    assert!(!html.contains("<dialog open") && !html.contains("?add="), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn every_removal_asks_with_the_safe_choice_first() {
    let (app, admin) = ready("shell-confirm").await;
    let id: String =
        app.db.readers().with(|c| c.query_row("SELECT id FROM users WHERE name = 'admin'", [], |r| r.get(0))).unwrap();
    insert(
        &app,
        "devices",
        Row::from([
            ("id", Value::Text("d1".into())),
            ("user_id", Value::Text(id.clone())),
            ("name", Value::Text("laptop".into())),
            ("endpoint_id", Value::Text("e".repeat(64))),
            ("created_at", Value::Integer(1)),
        ]),
    )
    .await;
    for (path, action, keep) in [
        (format!("/users?confirm=disable:{id}"), format!("/settings/users/{id}/disable"), "Keep it"),
        ("/users?confirm=revoke:d1".into(), "/settings/devices/d1/revoke".into(), "Keep it"),
    ] {
        let html = see(&app, &path, &admin).await;
        let dialog = block(&html, "<dialog", "</dialog>");
        assert!(dialog.contains(&format!("action=\"{action}\"")), "{path}: {dialog}");
        let safe = dialog.find(keep).unwrap_or_else(|| panic!("{path}: {keep}"));
        let danger = dialog.find("danger").unwrap_or_else(|| panic!("{path}: a danger button"));
        assert!(safe < danger, "{path}: the safe choice is first");
        let link = &dialog[dialog[..safe].rfind("<a").unwrap()..safe];
        assert!(link.contains("autofocus"), "{path}: and focused: {link}");
    }
    // nothing on the list acts at once
    let list = see(&app, "/users", &admin).await;
    let main = block(&list, "id=\"main\"", "</main>");
    assert!(!main.contains("/disable\"") && !main.contains("/revoke\""), "{main}");
    assert!(main.contains("href=\"/users?confirm=revoke:d1\""));
    // you can't disable yourself by a slip, and a device that isn't there has no dialog
    let html = see(&app, "/users?confirm=revoke:nothing", &admin).await;
    assert!(!html.contains("<dialog open"), "{html}");
}

#[tokio::test(flavor = "multi_thread")]
async fn lists_are_searched_by_the_hub_too() {
    let (app, admin) = ready("shell-search").await;
    for (i, name) in ["web-east", "web-west", "nas-east"].into_iter().enumerate() {
        machine(&app, &format!("01JD000000000000000000000{i}"), name).await;
    }
    for path in ["/", "/sites/home", "/patching"] {
        let html = see(&app, &format!("{path}?q=EAST+web"), &admin).await;
        let main = block(&html, "id=\"main\"", "</main>");
        assert!(main.contains("web-east") && !main.contains("web-west") && !main.contains("nas-east"), "{path}");
        assert!(main.contains("value=\"EAST web\""), "{path}: what was searched for is kept");
        let html = see(&app, &format!("{path}?q=%3Cscript%3E"), &admin).await;
        assert!(html.contains("match") && !html.contains("value=\"<script>"), "{path}: none, and said so");
    }
    let html = see(&app, "/users?q=admin", &admin).await;
    assert!(block(&html, "id=\"main\"", "</main>").contains("Admin"));
    let html = see(&app, "/audit?q=first_run", &admin).await;
    assert!(block(&html, "id=\"main\"", "</main>").contains("first_run.completed"));
    let html = see(&app, "/audit?q=nothing-like-it", &admin).await;
    assert!(!block(&html, "id=\"main\"", "</main>").contains("first_run.completed"));
    // the header's search finds machines and pages
    let html = see(&app, "/find?q=nas", &admin).await;
    let main = block(&html, "id=\"main\"", "</main>");
    assert!(main.contains("nas-east") && !main.contains("web-east"), "{main}");
    let html = see(&app, "/find?q=patch", &admin).await;
    assert!(block(&html, "id=\"main\"", "</main>").contains("href=\"/patching\""));
}

#[tokio::test(flavor = "multi_thread")]
async fn shortcuts_come_from_one_table() {
    let (app, admin) = ready("shell-keys").await;
    let html = see(&app, "/shortcuts", &admin).await;
    let main = block(&html, "id=\"main\"", "</main>");
    let shell = see(&app, "/", &admin).await;
    let mut seen = std::collections::HashSet::new();
    for (i, _) in shell.match_indices("data-key=\"") {
        let key = &shell[i + 10..i + 11];
        assert!(seen.insert(key.to_string()), "`g {key}` goes to two places");
        assert!(main.contains(&format!("<kbd>g</kbd> <kbd>{key}</kbd>")), "`g {key}` is in the help");
    }
    assert!(seen.len() >= 9, "{seen:?}");
    for key in ["<kbd>?</kbd>", "<kbd>/</kbd>", "<kbd>c</kbd>", "<kbd>Esc</kbd>", "<kbd>K</kbd>"] {
        assert!(main.contains(key), "{key}");
    }
    // a viewer has fewer places to go, and the help says so
    let viewer = session_for(&app.db, Role::Viewer).await;
    let html = see(&app, "/shortcuts", &viewer).await;
    assert!(!block(&html, "id=\"main\"", "</main>").contains("System settings"));
}

#[tokio::test(flavor = "multi_thread")]
async fn the_version_is_shown_and_an_update_can_be_noticed() {
    let (app, admin) = ready("shell-about").await;
    let version = env!("CARGO_PKG_VERSION");
    let html = see(&app, "/about", &admin).await;
    let main = block(&html, "id=\"main\"", "</main>");
    assert!(main.contains(version) && main.contains("Made by Strange Matter Studios LLC"), "{main}");
    assert!(!main.contains("github"), "the interface doesn't point at its repository");
    let html = see(&app, "/", &admin).await;
    assert!(block(&html, "<nav", "</nav>").contains(&format!("Rackhand {version}")), "in the sidebar");
    let build = {
        let meta = block(&html, "name=\"app-build\"", ">");
        let at = meta.find("content=\"").unwrap() + 9;
        meta[at..at + meta[at..].find('"').unwrap()].to_string()
    };
    let resp = send(&app.router, get("/version", "")).await;
    assert_eq!(resp.status(), StatusCode::OK, "asked before signing in too");
    let body: serde_json::Value = serde_json::from_str(&text(resp).await).unwrap();
    assert_eq!((body["version"].as_str(), body["build"].as_str()), (Some(version), Some(build.as_str())));
    // the old page's styles don't outlive an update for long
    let css = send(&app.router, get("/static/app.css", "")).await;
    assert_eq!(css.headers().get(header::CACHE_CONTROL).unwrap(), "public, max-age=300");
}

#[tokio::test(flavor = "multi_thread")]
async fn stepping_up_returns_to_what_asked_for_it() {
    let (app, _) = ready("shell-next").await;
    let resp = send(&app.router, get("/sign-in", "")).await;
    let anon = set_cookie(&resp, "rh_anon").unwrap().split(';').next().unwrap().to_string();
    // a page asked for without a session is where signing in leads
    let resp = send(&app.router, get("/audit?q=x", &anon)).await;
    assert_eq!(location(&resp).as_deref(), Some("/sign-in"));
    let next = set_cookie(&resp, "rh_next").expect("the page is remembered");
    assert!(next.contains("HttpOnly") && next.contains("SameSite=Strict"), "{next}");
    // but not a fragment a page left open keeps asking for, nor anything the page's script asks for
    let resp = send(&app.router, get("/machines/01JD0000000000000000000001/vitals", &anon)).await;
    assert_eq!(location(&resp).as_deref(), Some("/sign-in"));
    assert_eq!(set_cookie(&resp, "rh_next"), None, "a fragment isn't a page to return to");
    for (header_name, value) in [("hx-request", "true"), ("sec-fetch-dest", "empty")] {
        let mut asked = get("/audit", &anon);
        asked.headers_mut().insert(header_name, value.parse().unwrap());
        let resp = send(&app.router, asked).await;
        assert_eq!(set_cookie(&resp, "rh_next"), None, "{header_name}");
    }
    let (id, name): (String, String) = app
        .db
        .readers()
        .with(|c| c.query_row("SELECT id, name FROM users WHERE name = 'admin'", [], |r| Ok((r.get(0)?, r.get(1)?))))
        .unwrap();
    assert_eq!(name, "admin");
    let token = session::create(&app.db, &id, now_ms()).await.unwrap();
    let cookie = format!("{}={token}", session::COOKIE);
    // something that needs a step-up remembers the page it was asked from
    let csrf = csrf_of(&app, &cookie).await;
    machine(&app, "01JD0000000000000000000001", "web1").await;
    let path = "/machines/01JD0000000000000000000001/binding/confirm";
    let resp = send(&app.router, post(path, &cookie, &[("csrf", csrf.as_str()), ("guest", "x")])).await;
    assert_eq!(location(&resp).as_deref(), Some("/step-up"));
    let next = set_cookie(&resp, "rh_next").unwrap().split(';').next().unwrap().to_string();
    let key = {
        let vault = Vault::new(MasterKey::from_bytes([3u8; 32]), app.db.clone());
        vault.get(&format!("totp:{id}")).unwrap().expose().to_vec()
    };
    // (the first run used this 30 seconds' code)
    let code = totp::code_at_step(&key, totp::step(now_ms() / 1000) + 1);
    let cookies = format!("{cookie}; {next}");
    let resp = send(&app.router, post("/step-up", &cookies, &[("csrf", csrf.as_str()), ("code", code.as_str())])).await;
    assert_eq!(location(&resp).as_deref(), Some("/machines/01JD0000000000000000000001"));
    assert!(set_cookie(&resp, "rh_next").unwrap().contains("Max-Age=0"), "used once");
    // a cookie of someone else's making leads nowhere else
    for bad in ["//example.test", "https://example.test", "/\\x"] {
        let cookies = format!("{cookie}; rh_next={bad}");
        let code = totp::code_at_step(&key, totp::step(now_ms() / 1000) + 1);
        let resp =
            send(&app.router, post("/step-up", &cookies, &[("csrf", csrf.as_str()), ("code", code.as_str())])).await;
        assert!(location(&resp).is_none_or(|l| l == "/"), "{bad}: {:?}", location(&resp));
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn new_passwords_are_typed_twice() {
    let (app, admin) = ready("shell-twice").await;
    let fields = [("name", "kit"), ("role", "viewer"), ("auth", "local"), ("password", "a long enough secret")];
    let mut differ = fields.to_vec();
    differ.push(("password_again", "a long enough secreT"));
    let (code, html) = submit(&app, &admin, "/settings/users", &differ).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert!(error_of(&html, "user", "password_again").contains("same"), "{html}");
    let (code, html) = submit(&app, &admin, "/settings/users", &fields).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    assert_ne!(error_of(&html, "user", "password_again"), "");
    let label = block(&html, "for=\"user-password_again\"", "</label>");
    assert!(!label.contains("optional"), "it isn't: {label}");
    differ[4].1 = "a long enough secret";
    assert_eq!(submit(&app, &admin, "/settings/users", &differ).await.0, StatusCode::OK);
    // first run as well
    let app = app_with("shell-twice-first", |w| w).await;
    let opened = open_first_run(&app).await;
    let fields = [
        ("csrf", opened.1.as_str()),
        ("setup_code", SETUP_CODE),
        ("admin_name", "admin"),
        ("password", "correct horse battery staple"),
        ("password_again", "correct horse battery stable"),
        ("site_name", "home"),
        ("timezone", "UTC"),
    ];
    let html = text(send(&app.router, post("/first-run", &opened.0, &fields)).await).await;
    assert!(error_of(&html, "first-run", "password_again").contains("same"), "{html}");
}

/// A window is picked, not typed; the rule it makes is the one there has always been.
#[tokio::test(flavor = "multi_thread")]
async fn a_window_is_picked_from_day_time_and_length() {
    let (app, admin) = ready("shell-window").await;
    let html = see(&app, "/patching?add=window", &admin).await;
    for name in ["repeat", "lasts", "timezone", "machine", "for"] {
        assert!(control(&html, "window", name).starts_with("<select"), "{name}");
    }
    assert!(control(&html, "window", "start").contains("type=\"time\""));
    let window = [
        ("for", "tag"),
        ("tag", "lab"),
        ("machine", ""),
        ("repeat", "sun"),
        ("start", "03:00"),
        ("lasts", "120"),
        ("timezone", "Europe/Berlin"),
    ];
    assert_eq!(submit(&app, &admin, "/windows", &window).await.0, StatusCode::SEE_OTHER);
    let daily =
        [("for", "tag"), ("tag", "web"), ("repeat", "daily"), ("start", "23:30"), ("lasts", "60"), ("timezone", "UTC")];
    assert_eq!(submit(&app, &admin, "/windows", &daily).await.0, StatusCode::SEE_OTHER);
    let rules: Vec<String> = app
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT rrule FROM windows ORDER BY rrule")?;
            let rows = s.query_map([], |r| r.get(0))?;
            rows.collect()
        })
        .unwrap();
    assert_eq!(rules, ["daily 23:30 60m", "weekly sun 03:00 120m"]);
    machine(&app, "01JD0000000000000000000009", "nas9").await;
    let one = [
        ("for", "machine"),
        ("machine", "01JD0000000000000000000009"),
        ("repeat", "fri"),
        ("start", "22:00"),
        ("lasts", "240"),
        ("timezone", "UTC"),
    ];
    assert_eq!(submit(&app, &admin, "/windows", &one).await.0, StatusCode::SEE_OTHER);
    let html = see(&app, "/patching", &admin).await;
    assert!(html.contains("Sundays, 03:00 to 05:00"), "said as a person would: {html}");
    let row = html.split("<tr").find(|r| r.contains("Fridays, 22:00 to 02:00 the next day")).expect("the third window");
    assert_eq!(cells(row)[0], "nas9", "a machine by its name");
    let bad =
        [("for", "tag"), ("tag", ""), ("repeat", "sometimes"), ("start", "25:00"), ("lasts", "7"), ("timezone", "")];
    let (code, html) = submit(&app, &admin, "/windows", &bad).await;
    assert_eq!(code, StatusCode::BAD_REQUEST);
    for name in ["tag", "repeat", "start", "lasts", "timezone"] {
        assert_ne!(error_of(&html, "window", name), "", "{name}");
    }
    assert_eq!(selected(&html, "window", "for").as_deref(), Some("tag"));
}

/// Fields that only one choice needs are marked with it, for the script to show and hide; without it all are there.
#[tokio::test(flavor = "multi_thread")]
async fn fields_that_depend_on_a_choice_say_so() {
    let (app, admin) = ready("shell-when").await;
    let html = see(&app, "/users?add=user", &admin).await;
    for (name, when) in [("password", "auth=local"), ("password_again", "auth=local"), ("subject", "auth=oidc")] {
        let at = html.find(&format!("id=\"user-{name}\"")).unwrap();
        let wrapper = &html[html[..at].rfind("<div class=\"field").unwrap()..at];
        assert!(wrapper.contains(&format!("data-when=\"{when}\"")), "{name}: {wrapper}");
    }
    let html = see(&app, "/patching?add=window", &admin).await;
    for (name, when) in [("machine", "for=machine"), ("tag", "for=tag")] {
        let at = html.find(&format!("id=\"window-{name}\"")).unwrap();
        let wrapper = &html[html[..at].rfind("<div class=\"field").unwrap()..at];
        assert!(wrapper.contains(&format!("data-when=\"{when}\"")), "{name}: {wrapper}");
    }
}

/// What is approved is shown in full, and wraps between words only.
#[tokio::test(flavor = "multi_thread")]
async fn what_an_approval_runs_is_never_broken_inside_a_word() {
    let (app, admin) = ready("shell-approval").await;
    let request = crate::policy::approvals::ApprovalRequest {
        requester: "job:01JASSISTANTJOBAAAAAAAAAAA".into(),
        tool: "exec".into(),
        target: Some("m1".into()),
        args: serde_json::json!({ "command": "systemctl is-active --quiet nginx.service" }),
        runbook_rev: None,
        risk: rackhand_runbook::runbook::Risk::Normal,
        step_up: false,
        reason: "it keeps failing".into(),
    };
    let approvals = crate::policy::approvals::Approvals::new(app.db.clone());
    let id = approvals.create(&request, now_ms(), 3_600_000).await.unwrap();
    let html = see(&app, "/approvals", &admin).await;
    assert!(html.contains("<span>--quiet</span>"), "each word is one piece: {html}");
    assert!(plain(&html).contains("systemctl is-active --quiet nginx.service"), "and reads as it runs");
    // rejecting asks first
    let main = block(&html, "id=\"main\"", "</main>");
    assert!(main.contains(&format!("href=\"/approvals?confirm=reject:{id}\"")), "{main}");
    let html = see(&app, &format!("/approvals?confirm=reject:{id}"), &admin).await;
    let dialog = block(&html, "<dialog", "</dialog>");
    assert!(dialog.contains(&format!("action=\"/approvals/{id}/reject\"")) && dialog.contains("Keep it waiting"));
}

/// Writes every page and dialog as files, with data that looks real, for the script that measures them in a browser
/// (`docs/designs/0002-dashboard-ui/measure.js`): `RACKHAND_PAGES=<dir> cargo nextest run ... pages_for_measuring`.
#[tokio::test(flavor = "multi_thread")]
async fn pages_for_measuring() {
    let (app, admin) = ready("shell-measure").await;
    let long = "a-database-server-with-quite-a-long-name.storage.example";
    for (i, name) in ["web1", "web2", long, "nas1", "pve1", "dns1", "desk1", "switch1"].into_iter().enumerate() {
        machine(&app, &format!("01JD000000000000000000000{i}"), name).await;
    }
    for (i, (severity, state, title)) in [
        ("critical", "open", "Disk /var/lib/containers fills in about 9 hours"),
        ("warning", "open", "nginx.service keeps restarting"),
        ("warning", "resolved", "No report from the machine"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut row = Row::from([
            ("id", Value::Text(format!("01JD00000000000000000000I{i}"))),
            ("machine_id", Value::Text(format!("01JD000000000000000000000{i}"))),
            ("rule_id", Value::Text("x".into())),
            ("dedupe_key", Value::Text(format!("x{i}"))),
            ("kind", Value::Text("x".into())),
            ("severity", Value::Text(severity.into())),
            ("state", Value::Text(state.into())),
            ("title", Value::Text(title.into())),
            ("opened_at", Value::Integer(now_ms() - 7_200_000)),
        ]);
        if state == "resolved" {
            row.insert("resolved_at", Value::Integer(now_ms()));
        }
        insert(&app, "incidents", row).await;
    }
    let request = crate::policy::approvals::ApprovalRequest {
        requester: "job:01JASSISTANTJOBAAAAAAAAAAA".into(),
        tool: "exec".into(),
        target: Some(long.into()),
        args: serde_json::json!({ "command": "systemctl restart nginx.service && systemctl is-active --quiet nginx.service" }),
        runbook_rev: Some(3),
        risk: rackhand_runbook::runbook::Risk::Normal,
        step_up: false,
        reason: "nginx keeps failing its health check, and a restart cleared it twice this week".into(),
    };
    let approval =
        crate::policy::approvals::Approvals::new(app.db.clone()).create(&request, now_ms(), 3_600_000).await.unwrap();
    for (n, state) in [("patch-debian", "running"), ("restart-web", "failed"), ("reboot", "succeeded")] {
        insert(
            &app,
            "jobs",
            Row::from([
                ("id", Value::Text(format!("01JJOB{n}").replace('-', ""))),
                ("kind", Value::Text("runbook".into())),
                ("name", Value::Text(n.into())),
                ("target", Value::Text(long.into())),
                ("state", Value::Text(state.into())),
                ("requested_by", Value::Text("admin".into())),
                ("started_at", Value::Integer(now_ms())),
            ]),
        )
        .await;
    }
    let user: String =
        app.db.readers().with(|c| c.query_row("SELECT id FROM users WHERE name = 'admin'", [], |r| r.get(0))).unwrap();
    insert(
        &app,
        "devices",
        Row::from([
            ("id", Value::Text("d1".into())),
            ("user_id", Value::Text(user.clone())),
            ("name", Value::Text("a laptop with a long name of its own".into())),
            ("endpoint_id", Value::Text("e".repeat(64))),
            ("created_at", Value::Integer(1)),
        ]),
    )
    .await;
    for (path, fields) in [
        (
            "/policies",
            vec![
                ("name", "web-servers"),
                ("patch", "auto"),
                ("auto_reboot", "on"),
                ("snapshot", "required"),
                ("quarantine", "approval"),
                ("peer_requests", "approval"),
            ],
        ),
        (
            "/windows",
            vec![
                ("for", "tag"),
                ("tag", "web"),
                ("repeat", "sun"),
                ("start", "03:00"),
                ("lasts", "120"),
                ("timezone", "Europe/Berlin"),
            ],
        ),
        (
            "/settings/notifiers",
            vec![("kind", "discord"), ("name", "ops"), ("webhook", "https://discord.example.test/api/webhooks/1/x")],
        ),
        ("/settings/git-mirror", vec![("url", "ssh://git@git.example.test/homelab/rackhand.git")]),
        (
            "/library/config/checks",
            vec![("content", "[[check]]\nname = \"web\"\nkind = \"tcp\"\ntarget = \"192.0.2.20:22\"\n")],
        ),
    ] {
        assert_eq!(submit(&app, &admin, path, &fields).await.0, StatusCode::SEE_OTHER, "{path}");
    }
    let mut pages: Vec<(String, String, String)> = Vec::new();
    let at = |name: &str, path: &str| (name.to_string(), path.to_string(), admin.clone());
    for (path, heading) in PAGES {
        pages.push(at(&heading.to_lowercase().replace(' ', "-"), path));
    }
    for (name, path) in [
        ("machine", "/machines/01JD0000000000000000000002".to_string()),
        ("site", "/sites/home".into()),
        ("incident", "/incidents/01JD00000000000000000000I0".into()),
        ("job", "/jobs/01JJOBrestartweb".into()),
        ("library-item", "/library/config/checks".into()),
        ("library-edit", "/library/config/checks?write=1".into()),
        ("step-up", "/step-up".into()),
        ("find", "/find?q=web".into()),
        ("not-found", "/nowhere".into()),
        ("dialog-user", "/users?add=user".into()),
        ("dialog-edit-user", format!("/users?edit={user}")),
        ("dialog-disable", format!("/users?confirm=disable:{user}")),
        ("dialog-policy", "/patching?add=policy".into()),
        ("dialog-window", "/patching?add=window".into()),
        ("dialog-discord", "/settings/notifiers?add=discord".into()),
        ("dialog-smtp", "/settings/notifiers?add=smtp".into()),
        ("dialog-machine", "/add?add=machine".into()),
        ("dialog-proxmox", "/add?add=proxmox".into()),
        ("dialog-device", "/add?add=device".into()),
        ("dialog-reject", format!("/approvals?confirm=reject:{approval}")),
        ("dialog-rule", "/security?add=rule".into()),
        ("none-found", "/?q=nothing+like+it".into()),
    ] {
        pages.push((name.into(), path, admin.clone()));
    }
    pages.push(("sign-in".into(), "/sign-in".into(), String::new()));
    let mut out: Vec<(String, String)> = Vec::new();
    for (name, path, cookie) in pages {
        let html = text(send(&app.router, get(&path, &cookie)).await).await;
        assert!(html.contains("</html>"), "{path}");
        out.push((name, html));
    }
    // refused forms, with every message on
    let bad = [("name", "al ice"), ("role", "owner"), ("auth", "local"), ("password", "short")];
    out.push(("refused-user".into(), submit(&app, &admin, "/settings/users", &bad).await.1));
    let bad = [("for", "tag"), ("repeat", "x"), ("start", "25:00"), ("lasts", "7")];
    out.push(("refused-window".into(), submit(&app, &admin, "/windows", &bad).await.1));
    let good = [
        ("name", "kit"),
        ("role", "viewer"),
        ("auth", "local"),
        ("password", "a long enough secret"),
        ("password_again", "a long enough secret"),
    ];
    out.push(("user-created".into(), submit(&app, &admin, "/settings/users", &good).await.1));
    let machine = [("name", "web9"), ("os", "linux"), ("access", "managed"), ("mode", "local")];
    out.push(("install-command".into(), submit(&app, &admin, "/add/machine", &machine).await.1));
    // first run
    let fresh = app_with("shell-measure-first", |w| w).await;
    let opened = open_first_run(&fresh).await;
    out.push(("first-run".into(), see(&fresh, "/first-run", &opened.0).await));
    let refused = post(
        "/first-run",
        &opened.0,
        &[("csrf", opened.1.as_str()), ("setup_code", "SETUP-NOPE"), ("admin_name", "Alex Smith")],
    );
    out.push(("first-run-refused".into(), text(send(&fresh.router, refused).await).await));
    submit_details(&fresh, &opened, SETUP_CODE).await;
    out.push(("first-run-factor".into(), see(&fresh, "/first-run/second-factor", &opened.0).await));
    let key = second_factor_key(&fresh, &opened).await;
    out.push(("first-run-done".into(), text(submit_second_factor(&fresh, &opened, &key, now_ms()).await).await));
    let Some(dir) = std::env::var_os("RACKHAND_PAGES").map(std::path::PathBuf::from) else { return };
    std::fs::create_dir_all(dir.join("static/vendor")).unwrap();
    let assets = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("static");
    for file in ["app.css", "app.js", "forms.js", "passkey.js", "icon.svg", "vendor/htmx-2.0.11.min.js"] {
        std::fs::copy(assets.join(file), dir.join("static").join(file)).unwrap();
    }
    for (name, html) in &out {
        std::fs::write(dir.join(format!("{name}.html")), html).unwrap();
    }
    let names: Vec<&String> = out.iter().map(|(n, _)| n).collect();
    std::fs::write(dir.join("pages.json"), serde_json::to_string(&names).unwrap()).unwrap();
}

/// The integration and live tiers read a command from the page between `<code>` and `</code>`; they aren't run with
/// these tests, so what they read is checked here.
#[tokio::test(flavor = "multi_thread")]
async fn a_command_is_read_by_the_other_tiers() {
    let (app, admin) = ready("shell-command").await;
    let fields = [("name", "web9"), ("os", "linux"), ("access", "managed"), ("mode", "local")];
    let (code, html) = submit(&app, &admin, "/add/machine", &fields).await;
    assert_eq!(code, StatusCode::OK);
    let at = html.find("<h2>As a user with sudo</h2>").expect("the heading they look for");
    let command = &html[at..];
    let start = command.find("<code>").expect("a bare <code>") + 6;
    let command = &command[start..start + command[start..].find("</code>").unwrap()];
    assert!(command.contains("install.sh") && command.contains("--token "), "{command}");
}

/// A question over an editor is announced by its own name.
#[tokio::test(flavor = "multi_thread")]
async fn each_dialog_is_named_by_its_own_heading() {
    let (app, admin) = ready("shell-names").await;
    let id: String =
        app.db.readers().with(|c| c.query_row("SELECT id FROM users WHERE name = 'admin'", [], |r| r.get(0))).unwrap();
    let mut names = Vec::new();
    for path in [format!("/users?edit={id}"), format!("/users?confirm=disable:{id}"), "/users?add=user".into()] {
        let html = see(&app, &path, &admin).await;
        let open = block(&html, "<dialog", ">");
        let at = open.find("aria-labelledby=\"").expect("named") + 17;
        let name = open[at..at + open[at..].find('"').unwrap()].to_string();
        assert!(block(&html, "<dialog", "</dialog>").contains(&format!("<h2 id=\"{name}\"")), "{path}: {name}");
        names.push(name);
    }
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 3, "{names:?}");
}

/// What waits is counted in words a screen reader says right, and an empty list offers what its page's button does.
#[tokio::test(flavor = "multi_thread")]
async fn counts_and_offers_are_worded_right() {
    let (app, admin) = ready("shell-words").await;
    let html = see(&app, "/", &admin).await;
    assert!(html.contains("aria-label=\"Menu\""), "nothing waits: {}", block(&html, "<header", "</header>"));
    assert!(html.contains("No machines yet. <a href=\"/add\">Add a machine</a>"), "{html}");
    insert(
        &app,
        "incidents",
        Row::from([
            ("id", Value::Text("01JD00000000000000000000W1".into())),
            ("machine_id", Value::Text("01JD00000000000000000000W1".into())),
            ("rule_id", Value::Text("x".into())),
            ("dedupe_key", Value::Text("w1".into())),
            ("kind", Value::Text("x".into())),
            ("severity", Value::Text("warning".into())),
            ("state", Value::Text("open".into())),
            ("title", Value::Text("One".into())),
            ("opened_at", Value::Integer(now_ms())),
        ]),
    )
    .await;
    let html = see(&app, "/", &admin).await;
    assert!(html.contains("aria-label=\"Menu: 1 open incident\""), "{}", block(&html, "<header", "</header>"));
    let html = see(&app, "/sites/home", &admin).await;
    assert!(html.contains("<a href=\"/add\">Add a machine</a>"), "{html}");
}

/// Someone new can tell what each choice is for, and what a page's words mean, without leaving the page.
#[tokio::test(flavor = "multi_thread")]
async fn a_newcomer_is_told_what_each_thing_is() {
    let (app, admin) = ready("shell-help").await;
    machine(&app, "01JD00000000000000000000H1", "web1").await;
    insert(
        &app,
        "incidents",
        Row::from([
            ("id", Value::Text("01JD00000000000000000000H1".into())),
            ("machine_id", Value::Text("01JD00000000000000000000H1".into())),
            ("rule_id", Value::Text("x".into())),
            ("dedupe_key", Value::Text("h1".into())),
            ("kind", Value::Text("x".into())),
            ("severity", Value::Text("warning".into())),
            ("state", Value::Text("human".into())),
            ("title", Value::Text("Waits for someone".into())),
            ("opened_at", Value::Integer(now_ms())),
        ]),
    )
    .await;
    let says = |path: &'static str, html: String, all: &[&str]| {
        let text = plain(&html);
        for what in all {
            assert!(text.contains(what), "{path} says {what:?}: {text}");
        }
    };
    let pages: &[(&str, &[&str])] = &[
        (
            "/add",
            &[
                "Add what Rackhand should watch; invite what should work with this hub.",
                "It gets the probe, a small program that reports its health.",
                "For what you can't install software on",
                "Virtualization hosts and clusters",
                "A server's management board",
                "Switches, routers, printers and UPSes",
                "An invite connects something that works with this hub",
                "it works once, for 24 hours",
                "to use the rackhand command line with this hub",
                "an AI that works incidents through Rackhand's tools",
                "To watch its health too, add it as a machine as well.",
                "Linked hubs share summaries, watch each other",
                "A place with its own network gets its own hub.",
            ],
        ),
        (
            "/add?add=machine",
            &[
                "Monitor only: it is watched, and the hub can run nothing on it.",
                "Remote for a machine at a place with no hub of its own",
            ],
        ),
        ("/incidents", &["An incident is a problem the hub tracks until its cause clears.", "Needs a person"]),
        ("/incidents/01JD00000000000000000000H1", &["State: Needs a person"]),
        ("/approvals", &["Actions that wait for a person to say yes", "Each approval covers exactly what it shows"]),
        ("/jobs", &["Work the hub ran: runbooks, patches and the assistant's jobs."]),
        (
            "/library",
            &["Runbooks are steps the hub runs by itself.", "Playbooks guide the assistant.", "Nothing changes until"],
        ),
        (
            "/patching",
            &[
                "security updates daily at 04:00 and the rest on Sundays at 03:00",
                "A maintenance window pauses patching and silence alerts",
                "No windows yet. Add one for times you work on machines yourself.",
            ],
        ),
        (
            "/patching?add=policy",
            &["each patch waits on the Approvals page", "cut a machine off its network", "another site's hub"],
        ),
        ("/patching?add=window", &["a machine going quiet raises no alert"]),
        ("/audit", &["a changed or removed entry breaks the chain"]),
        ("/users", &["A device acts as its person"]),
        ("/users?add=user", &["Responder: also handles incidents and approvals that aren't high risk."]),
        (
            "/settings",
            &["known-bad addresses", "nothing about your machines is sent", "a copy and a history outside the hub"],
        ),
        ("/settings/notifiers", &["warning and critical incidents are sent to every notifier"]),
        ("/sites/home", &["A site is a place with its own network and its own hub."]),
    ];
    for (path, all) in pages {
        says(path, see(&app, path, &admin).await, all);
    }
    let incidents = see(&app, "/incidents", &admin).await;
    assert!(!plain(&incidents).contains("| Human |"), "a stored state isn't shown as it is stored");
    let patching = plain(&see(&app, "/patching", &admin).await);
    assert!(
        !patching.contains("Nothing is patched by itself without one"),
        "patches don't wait for a maintenance window"
    );
    let fields = [("name", "web9"), ("os", "linux"), ("access", "managed"), ("mode", "local")];
    let (_, html) = submit(&app, &admin, "/add/machine", &fields).await;
    says("/add/machine", html, &["It shows on the Overview once its probe connects."]);
    // a choice says what it is in a few words, so it isn't cut off on a phone; its field's hint says the rest
    let users: Vec<String> = app
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT id FROM users")?;
            s.query_map([], |r| r.get(0))?.collect()
        })
        .unwrap();
    for (i, user) in users.into_iter().enumerate() {
        insert(
            &app,
            "devices",
            Row::from([
                ("id", Value::Text(format!("help-device-{i}"))),
                ("user_id", Value::Text(user)),
                ("name", Value::Text(format!("laptop-{i}"))),
                ("endpoint_id", Value::Text(format!("{i}").repeat(64))),
                ("created_at", Value::Integer(1)),
            ]),
        )
        .await;
    }
    let keys = see(&app, "/account/keys", &admin).await;
    assert!(keys.contains("name=\"scope\""), "the key form is there to look at: {keys}");
    for path in ["/add?add=machine", "/users?add=user", "/patching?add=policy", "/security?add=rule", "/account/keys"] {
        let html = see(&app, path, &admin).await;
        for option in html.split("<option").skip(1) {
            let label = plain(&option[option.find('>').unwrap() + 1..option.find("</option>").unwrap()]);
            assert!(label.chars().count() <= 32, "{path}: {label}");
        }
    }
}
