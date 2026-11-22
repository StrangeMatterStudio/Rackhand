//! M2 live pass (plan L3): agentless machines, service checks and the Proxmox driver against the lab's real machines
//! and real Proxmox VE 8 and 9 APIs.

use std::time::{Duration, Instant};

use crate::hub::{self, Dash, RELEASE_URL, field, lab_dir, machine_id, metrics, metrics_token, open_incidents};
use crate::{eventually, lab, ok_on, on};

/// `snmpd` on `agentless` answers v2c with this community (lab/provision/agentless.sh).
const COMMUNITY: &str = "rackhand-lab";
/// The 7.8.6 Rackhand role.
const PRIVILEGES: &str = "VM.Audit,VM.Snapshot,VM.Snapshot.Rollback,VM.PowerMgmt,VM.Config.Network,VM.Allocate,\
VM.Clone,Datastore.Audit,Datastore.AllocateSpace,Sys.Audit,SDN.Use";
const TARGET: &str = "x86_64-unknown-linux-musl";

/// HTML text as typed.
fn unescape(html: &str) -> String {
    let mut out = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(at) = rest.find('&') {
        out.push_str(&rest[..at]);
        let tail = &rest[at..];
        let decoded = tail.find(';').filter(|e| *e <= 10).and_then(|e| {
            let c = match &tail[1..e] {
                "amp" => Some('&'),
                "lt" => Some('<'),
                "gt" => Some('>'),
                "quot" => Some('"'),
                name => match name.strip_prefix("#x") {
                    Some(hex) => u32::from_str_radix(hex, 16).ok().and_then(char::from_u32),
                    None => name.strip_prefix('#').and_then(|d| d.parse().ok()).and_then(char::from_u32),
                },
            };
            c.map(|c| (c, e + 1))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &tail[len..];
            }
            None => {
                out.push('&');
                rest = &tail[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

/// Adds an appliance through the Add page: its address, then, shown its certificate, the credentials. Returns the
/// form's token (now used) and the accept page's answer.
fn add_appliance(
    dash: &Dash,
    driver: &str,
    name: &str,
    address: &str,
    certificate: Option<&str>,
    credentials: &[(&str, &str)],
) -> (String, u16, String) {
    let (code, shown) =
        dash.post("/add", "/add/appliance", &[("driver", driver), ("name", name), ("address", address)]);
    let shown = unescape(&shown);
    assert_eq!(code, 200, "{driver}: {shown}");
    let token = field(&shown, "token").expect("the accept form");
    let shown_fp = field(&shown, "fingerprint");
    if let Some(expected) = certificate {
        assert_eq!(shown_fp.as_deref(), Some(expected), "the page shows the appliance's own certificate");
    }
    let mut fields = vec![("token", token.as_str())];
    if let Some(fp) = shown_fp.as_deref() {
        fields.push(("fingerprint", fp));
    }
    fields.extend_from_slice(credentials);
    let (code, done) = dash.post("/add", "/add/appliance/accept", &fields);
    (token, code, unescape(&done))
}

/// The value of `rackhand_<metric>` for the machine whose labels include all of `labels`.
fn value(scrape: &str, metric: &str, machine: &str, labels: &[(&str, &str)]) -> Option<f64> {
    let name = format!("rackhand_{}{{", metric.replace('.', "_"));
    scrape
        .lines()
        .filter(|l| l.starts_with(&name) && l.contains(&format!("machine=\"{machine}\"")))
        .find(|l| labels.iter().all(|(k, v)| l.contains(&format!("{k}=\"{v}\""))))
        .and_then(|l| l.rsplit(' ').next())
        .and_then(|v| v.parse().ok())
}

/// A Proxmox node's API: a token for the Rackhand role, made on the node.
fn proxmox_token(node: &str) -> String {
    let script = format!(
        "set -e; pveum role add Rackhand -privs {PRIVILEGES} 2>/dev/null || pveum role modify Rackhand -privs {PRIVILEGES}; \
         pveum user add rackhand@pve 2>/dev/null || true; pveum acl modify / -user rackhand@pve -role Rackhand; \
         pveum user token remove rackhand@pve live 2>/dev/null || true; \
         pveum user token add rackhand@pve live --privsep 0 --output-format json"
    );
    let out = on(node, &format!("sudo bash -c '{script}'"));
    let at = out.find("\"value\":\"").expect("the token's secret") + 9;
    format!("rackhand@pve!live={}", &out[at..at + out[at..].find('"').unwrap()])
}

/// The SHA-256 of the node's API certificate, as the Add page shows it.
fn proxmox_fingerprint(node: &str) -> String {
    let out = on(node, "sudo openssl x509 -in /etc/pve/local/pve-ssl.pem -noout -fingerprint -sha256");
    out.trim().rsplit('=').next().unwrap().to_uppercase()
}

/// The node added through the Add page's Proxmox form, once.
fn ensure_proxmox(dash: &Dash, node: &str, address: &str) {
    if machine_id(dash, node).is_some() {
        return;
    }
    let token = proxmox_token(node);
    let fp = proxmox_fingerprint(node);
    let (_, code, done) =
        add_appliance(dash, "proxmox", node, &format!("https://{address}:8006"), Some(&fp), &[("token_value", &token)]);
    assert_eq!(code, 200, "{node}: {done}");
}

fn node_and_guests(node: &str, address: &str) {
    let dash = Dash::shared().signed_in();
    ensure_proxmox(&dash, node, address);
    let token = metrics_token();
    let reports = || {
        let scrape = metrics(&token).1;
        value(&scrape, "pve.node.cpu_pct", node, &[("node", node)]).is_some()
            && ["100", "200"].iter().all(|vmid| value(&scrape, "pve.guest.up", node, &[("vmid", vmid)]).is_some())
    };
    assert!(
        eventually(Duration::from_secs(150), reports),
        "{node}: the node and its two guests on /metrics: {}",
        metrics(&token).1.lines().filter(|l| l.contains("pve_")).collect::<Vec<_>>().join("\n")
    );
    let scrape = metrics(&token).1;
    assert_eq!(value(&scrape, "pve.guest.up", node, &[("vmid", "100")]), Some(1.0), "ct-test runs");
}

/// The command a dashboard shows, from its `<pre><code>` under `heading`.
fn command(page: &str, heading: &str) -> String {
    let at = page.find(heading).unwrap_or_else(|| panic!("`{heading}` on the page: {page}"));
    let code = &page[at..];
    let start = code.find("<code>").unwrap() + 6;
    code[start..code.find("</code>").unwrap()].to_string()
}

/// The shared session's cookies, for a request that names the hub's site address as `Host` (curl only sends the
/// jar's cookies to the name they came from).
fn cookie_header() -> String {
    let jar = std::fs::read_to_string(lab_dir().join("live-cookies")).unwrap_or_default();
    let pairs: Vec<String> = jar
        .lines()
        .filter(|l| !l.is_empty() && (!l.starts_with('#') || l.starts_with("#HttpOnly_")))
        .filter_map(|l| {
            let f: Vec<&str> = l.split('\t').collect();
            (f.len() == 7).then(|| format!("{}={}", f[5], f[6]))
        })
        .collect();
    format!("Cookie: {}", pairs.join("; "))
}

/// Stops pausing `node` however the test ends.
struct Resume(&'static str);

impl Drop for Resume {
    fn drop(&mut self) {
        let _ = crate::xtask(&["lab", "resume", self.0]);
    }
}

#[test]
fn snmp_appliance_added_by_form_reports() {
    let dash = Dash::shared().signed_in();
    assert!(!ok_on("agentless", "test -e /usr/local/lib/rackhand"), "no probe on agentless");
    if machine_id(&dash, "agentless").is_none() {
        let creds = [("version", "2c"), ("community", COMMUNITY)];
        let (token, code, done) = add_appliance(&dash, "snmp", "agentless", "192.0.2.30:161", None, &creds);
        assert_eq!(code, 200, "{done}");
        // the form's invite works once
        let (code, again) = dash.post(
            "/add",
            "/add/appliance/accept",
            &[("token", &token), ("version", "2c"), ("community", COMMUNITY)],
        );
        assert_eq!(code, 409, "{again}");
        assert!(unescape(&again).contains("already been used"), "{again}");
    }
    let token = metrics_token();
    let reports = || {
        let scrape = metrics(&token).1;
        value(&scrape, "snmp.if_in_octets", "agentless", &[]).is_some()
            && value(&scrape, "snmp.if_oper_up", "agentless", &[]).is_some()
    };
    assert!(
        eventually(Duration::from_secs(150), reports),
        "agentless's interface metrics: {}",
        metrics(&token).1.lines().filter(|l| l.contains("agentless")).collect::<Vec<_>>().join("\n")
    );
}

#[test]
fn alpine_installs_and_reports() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    if machine_id(&dash, "alpine").is_none() {
        if ok_on("alpine", "test -e /usr/local/lib/rackhand/rackhand-probe") {
            lab(&["reset", "alpine"]);
            assert!(eventually(Duration::from_secs(300), || ok_on("alpine", "true")), "alpine after reset");
        }
        let fields = [("os", "alpine"), ("name", "alpine"), ("access", "managed"), ("mode", "local")];
        let (code, page) = dash.post("/add", "/add/machine", &fields);
        let page = unescape(&page);
        assert_eq!(code, 200, "{page}");
        // the Add page's Alpine command, from the lab release server instead of GitHub's
        let line = command(&page, "As root");
        let github = line.split("wget -qO- ").nth(1).and_then(|r| r.split("/install.sh").next()).unwrap().to_string();
        let line = format!("{} --release-url {RELEASE_URL}", line.replace(&github, RELEASE_URL));
        assert!(line.starts_with("wget -qO- ") && line.contains(" --token "), "{line}");
        on("alpine", &format!("sudo sh -c '{line}'"));
    }
    assert!(eventually(Duration::from_secs(60), || hub::live(&token, "alpine", 45.0)), "alpine reports");
    assert!(ok_on("alpine", "sudo rc-service rackhand-probe status"), "the probe runs under OpenRC");
    let healthy = || {
        let page = unescape(&dash.get("/add").1);
        page.find("<b>alpine</b>")
            .map(|at| &page[at..at + page[at..].find("</tr>").unwrap_or(0)])
            .is_some_and(|row| row.contains("Enrolled and healthy"))
    };
    assert!(eventually(Duration::from_secs(120), healthy), "the hub's SSH test passed: {}", dash.get("/add").1);
}

#[test]
fn service_checks_and_certificate_warning() {
    let dash = Dash::shared().signed_in();
    hub::ensure_target(&dash, &metrics_token());
    // a web service on target: HTTP on 8080, HTTPS on 8443 with a certificate that expires in 10 days
    on(
        "target",
        "sudo mkdir -p /srv/live && cd /srv/live && echo live-ok | sudo tee index.html >/dev/null && \
         sudo openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 10 -subj /CN=target \
         >/dev/null 2>&1 && sudo tee https.py >/dev/null <<'PY'
import http.server, ssl
s = http.server.HTTPServer(('', 8443), http.server.SimpleHTTPRequestHandler)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
c.load_cert_chain('cert.pem', 'key.pem')
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
PY",
    );
    on(
        "target",
        "sudo systemctl stop live-http live-https 2>/dev/null; sudo systemctl reset-failed live-http live-https \
         2>/dev/null; sudo systemd-run --unit=live-http -p WorkingDirectory=/srv/live python3 -m http.server 8080 && \
         sudo systemd-run --unit=live-https -p WorkingDirectory=/srv/live python3 https.py",
    );
    let checks = "[[check]]\nname = \"live-http\"\nkind = \"http\"\ntarget = \"http://192.0.2.20:8080/\"\ninterval_s = 15\n\
machine = \"target\"\n[check.settings]\nbody_contains = \"live-ok\"\n\n\
[[check]]\nname = \"live-tcp\"\nkind = \"tcp\"\ntarget = \"192.0.2.20:22\"\ninterval_s = 15\nmachine = \"target\"\n\n\
[[check]]\nname = \"live-cert\"\nkind = \"tls\"\ntarget = \"192.0.2.20:8443\"\ninterval_s = 15\nmachine = \"target\"\n";
    let (code, saved) = dash.post("/library/config/checks", "/library/config/checks", &[("content", checks)]);
    assert!(code == 200 || code == 303, "checks saved: {code} {saved}");
    let token = metrics_token();
    let up = || {
        let scrape = metrics(&token).1;
        ["live-http", "live-tcp", "live-cert"]
            .iter()
            .all(|c| value(&scrape, "check.up", "target", &[("check", c)]) == Some(1.0))
    };
    assert!(
        eventually(Duration::from_secs(90), up),
        "the three checks pass: {}",
        metrics(&token).1.lines().filter(|l| l.contains("check_")).collect::<Vec<_>>().join("\n")
    );
    let days = value(&metrics(&token).1, "check.cert_days", "target", &[("check", "live-cert")]);
    assert!(days.is_some_and(|d| (9.0..=10.0).contains(&d)), "10 days left: {days:?}");
    let warned = || {
        open_incidents(&dash)
            .iter()
            .any(|i| i.title.starts_with("Certificate of live-cert expires in") && i.severity == "warning")
    };
    assert!(eventually(Duration::from_secs(90), warned), "the certificate warning: {:?}", open_incidents(&dash));
}

#[test]
fn proxmox8_driver_reports_node_and_guests() {
    node_and_guests("pve8", "192.0.2.51");
}

#[test]
fn proxmox9_driver_reports_node_and_guests() {
    node_and_guests("pve9", "192.0.2.52");
}

#[test]
fn silent_proxmox_node_after_two_polls() {
    let dash = Dash::shared().signed_in();
    ensure_proxmox(&dash, "pve8", "192.0.2.51");
    let silent = |dash: &Dash| {
        open_incidents(dash)
            .into_iter()
            .find(|i| i.machine == "pve8" && unescape(&i.title) == "No answer from the machine's API")
    };
    assert!(eventually(Duration::from_secs(150), || silent(&dash).is_none()), "pve8 answers before the pause");
    lab(&["pause", "pve8"]);
    let resume = Resume("pve8");
    let paused = Instant::now();
    assert!(
        eventually(Duration::from_secs(300), || silent(&dash).is_some()),
        "pve8 silent: {:?}",
        open_incidents(&dash)
    );
    let after = paused.elapsed().as_secs();
    println!("pve8 silent {after} s after the pause");
    assert!(after >= 60, "after 2 failed polls (60 s apart), not at the first: {after} s");
    assert_eq!(silent(&dash).unwrap().severity, "warning");
    drop(resume);
    assert!(
        eventually(Duration::from_secs(240), || silent(&dash).is_none()),
        "resolved once pve8 answers again: {:?}",
        open_incidents(&dash)
    );
}

#[test]
fn probe_in_lxc_is_bound_to_its_guest() {
    let dash = Dash::shared().signed_in();
    ensure_proxmox(&dash, "pve9", "192.0.2.52");
    if machine_id(&dash, "ct-test").is_none() {
        // the hub holds the release files, so a machine that only reaches the hub installs from it (7.3.12)
        let mut names = vec!["install.sh".to_string(), format!("rackhand-verify-{TARGET}")];
        for f in [
            format!("rackhand-{TARGET}"),
            format!("rackhand-probe-{TARGET}"),
            "rackhand-hub.service".into(),
            "rackhand-probe.service".into(),
            "rackhand-probe-helper.service".into(),
            "rackhand-probe.openrc".into(),
            "rackhand-probe-helper.openrc".into(),
        ] {
            names.push(format!("{f}.minisig"));
            names.push(f);
        }
        let fetch: Vec<String> = names.iter().map(|n| format!("curl -fsSO {RELEASE_URL}/{n}")).collect();
        let fetch = format!(
            "mkdir -p /var/lib/rackhand/release && cd /var/lib/rackhand/release && {} && \
             chown -R rackhand-hub:rackhand-hub /var/lib/rackhand/release",
            fetch.join(" && ")
        );
        on("hub", &format!("sudo sh -c '{fetch}'"));
        // the Add page's offline command, as the admin copies it from the dashboard at the hub's site address
        let (_, add) = dash.get("/add");
        let csrf = field(&add, "csrf").unwrap();
        let fields = [
            format!("csrf={csrf}"),
            "os=alpine".into(),
            "name=ct-test".into(),
            "access=monitor".into(),
            "mode=local".into(),
        ];
        let mut args: Vec<String> = vec!["-H".into(), "Host: 192.0.2.10:8443".into(), "-H".into(), cookie_header()];
        for f in &fields {
            args.push("--data-urlencode".into());
            args.push(f.clone());
        }
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let (code, page) = dash.curl(&refs, "/add/machine");
        let page = unescape(&page);
        assert_eq!(code, 200, "{page}");
        let line = command(&page, "Offline, from this hub");
        assert!(
            line.starts_with("wget -q --no-check-certificate") && line.contains("https://192.0.2.10:8443"),
            "{line}"
        );
        let script = base64(line.as_bytes());
        on(
            "pve9",
            &format!(
                "echo {script} | base64 -d > /tmp/ct-install.sh && sudo pct push 100 /tmp/ct-install.sh /tmp/ct-install.sh \
                 && sudo pct exec 100 -- sh /tmp/ct-install.sh"
            ),
        );
    }
    let token = metrics_token();
    // ct-test isn't a lab machine: its own uptime comes through pve9
    let lag = || {
        let seen = hub::series(&metrics(&token).1, "uptime_s", "ct-test")?;
        let own: f64 = on("pve9", "sudo pct exec 100 -- cut -d' ' -f1 /proc/uptime").trim().parse().ok()?;
        Some(own - seen)
    };
    assert!(eventually(Duration::from_secs(60), || lag().is_some_and(|l| l <= 45.0)), "ct-test reports: {:?}", lag());
    let id = machine_id(&dash, "ct-test").unwrap();
    let binding = |dash: &Dash| {
        let page = unescape(&dash.get(&format!("/machines/{id}")).1);
        let state = page.split("Guest binding: ").nth(1).and_then(|r| r.split('.').next()).map(str::to_string);
        (state, page)
    };
    assert!(
        eventually(Duration::from_secs(150), || {
            matches!(binding(&dash).0.as_deref(), Some("proposed") | Some("confirmed"))
        }),
        "ct-test proposed as its guest: {}",
        binding(&dash).1
    );
    // the guest's reference is JSON in an attribute: read it escaped, then unescape it
    let raw = dash.get(&format!("/machines/{id}")).1;
    let guest = unescape(&field(&raw, "guest").expect("the proposed guest"));
    assert!(guest.contains("pve9") && guest.contains("100"), "LXC 100 on pve9: {guest}");
    if binding(&dash).0.as_deref() == Some("confirmed") {
        return; // confirmed by an earlier run on this hub
    }
    // confirming a binding asks for a fresh step-up
    dash.step_up();
    let (code, said) =
        dash.post(&format!("/machines/{id}"), &format!("/machines/{id}/binding/confirm"), &[("guest", &guest)]);
    assert_eq!(code, 303, "confirmed: {said}");
    assert_eq!(binding(&dash).0.as_deref(), Some("confirmed"), "{}", binding(&dash).1);
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
