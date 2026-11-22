//! The appliance forms (7.3.12): an agentless machine, or a Proxmox host's API, added per driver. First its address:
//! for the HTTPS drivers the hub reads the certificate the appliance presents (the handshake only, so no credential
//! goes to a certificate nobody has accepted) and shows its fingerprint. Then the accepted certificate and the
//! credentials: the hub polls once, pinned to that certificate, and only a poll that succeeds completes the form.
//! The credentials go into the Vault; the machine's row keeps `secret:` references. Admin only.

use std::time::Duration;

use askama::Template;
use axum::body::Body;
use axum::http::{Response, StatusCode};
use rackhand_drivers::DriverTarget;
use rackhand_store::{StoreError, TokenRefusal};

use super::add::{self, NAME_HINT, NAME_PATTERN, NAME_RULE, PLAIN, local_site, name_taken};
use super::{html, redirect, status};
use crate::registry::RegistryError;
use crate::registry::agentless::{AddAppliance, referenced, vault_name};
use crate::registry::tokens::Token;
use crate::vault::Secret;
use crate::web::ui::Shell;
use crate::web::forms::{Choices, Form, Groups, Spec};
use crate::web::{Ctx, Web};

/// A driver's form: its title, whether it is HTTPS (a certificate to accept), and its default port.
struct DriverForm {
    driver: &'static str,
    id: &'static str,
    title: &'static str,
    tls: bool,
    port: u16,
    specs: &'static [Spec],
    credentials: &'static [Spec],
}

const DRIVERS: &[DriverForm] = &[
    DriverForm {
        driver: "proxmox",
        id: "add-proxmox",
        title: "Proxmox VE",
        tls: true,
        port: 8006,
        specs: PROXMOX,
        credentials: PROXMOX_CREDENTIALS,
    },
    DriverForm {
        driver: "truenas",
        id: "add-truenas",
        title: "TrueNAS",
        tls: true,
        port: 443,
        specs: &[NAME, address("Such as https://nas.lab.test; its port, if it isn't 443.")],
        credentials: &[Spec::secret("api_key", "API key").hint("Made in TrueNAS for this hub.").attrs(SECRET)],
    },
    DriverForm {
        driver: "redfish",
        id: "add-redfish",
        title: "Redfish BMC",
        tls: true,
        port: 443,
        specs: &[NAME, address("Such as https://bmc.lab.test; its port, if it isn't 443.")],
        credentials: &[
            Spec::text("username", "BMC account").hint("One that can read is enough.").attrs(PLAIN),
            Spec::secret("password", "Password").attrs(SECRET),
        ],
    },
    DriverForm {
        driver: "snmp",
        id: "add-snmp",
        title: "SNMP device",
        tls: false,
        port: 161,
        specs: &[NAME, address("Such as switch.lab.test:161, or 192.0.2.30:161.")],
        credentials: SNMP_CREDENTIALS,
    },
];

const SECRET: &str = "autocomplete=\"new-password\"";
const NAME: Spec = Spec::text("name", "Name").hint(NAME_HINT).pattern(NAME_PATTERN, NAME_RULE).attrs(PLAIN);

const fn address(hint: &'static str) -> Spec {
    Spec::text("address", "Address").hint(hint).length(1, 512).attrs(PLAIN)
}

const PROXMOX: &[Spec] = &[
    NAME.optional(),
    Spec::select("machine", "Or the machine it is", &[])
        .optional()
        .hint("When the host already runs a probe, its API is added to that machine and needs no name."),
    address("Such as https://pve.lab.test:8006."),
];

const PROXMOX_CREDENTIALS: &[Spec] = &[
    Spec::secret("token_value", "API token")
        .hint("As Proxmox shows it: user@realm!id=secret.")
        .pattern(r"[^\s!]+![^\s=]+=\S+", "A token is user@realm!id=secret, all of it")
        .attrs(SECRET),
    Spec::text("node", "Node").optional().hint("Only for one node of a cluster.").attrs(PLAIN),
];

const VERSIONS: Choices = &[("2c", "2c: a community"), ("3", "3: a user, authenticated (SHA) and encrypted (AES)")];

const SNMP_CREDENTIALS: &[Spec] = &[
    Spec::select("version", "Version", VERSIONS),
    Spec::secret("community", "Community").optional().when("version=2c").attrs(SECRET),
    Spec::text("user", "User").optional().when("version=3").attrs(PLAIN),
    Spec::secret("auth_password", "Authentication password")
        .optional()
        .hint("At least 8 characters.")
        .length(8, 1024)
        .when("version=3")
        .attrs(SECRET),
    Spec::secret("priv_password", "Privacy password")
        .optional()
        .hint("At least 8 characters.")
        .length(8, 1024)
        .when("version=3")
        .attrs(SECRET),
];

fn driver_form(driver: &str) -> Option<&'static DriverForm> {
    DRIVERS.iter().find(|d| d.driver == driver)
}

/// Enrolled machines a Proxmox API can belong to.
fn host_options(web: &Web) -> Groups {
    let machines = web
        .0
        .db
        .readers()
        .with(|c| {
            let mut s = c.prepare(
                "SELECT id, name FROM machines WHERE state = 'enrolled' AND probe_endpoint_id IS NOT NULL ORDER BY name",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?.collect()
        })
        .unwrap_or_default();
    vec![(String::new(), vec![(String::new(), "A new machine".to_string())]), ("Machines".into(), machines)]
}

/// The Add page's appliance forms: driver, title and form, one of them perhaps as it was sent.
pub(super) fn forms(web: &Web, sent: &mut Option<Form>) -> Vec<(&'static str, &'static str, Form)> {
    let hosts = host_options(web);
    DRIVERS
        .iter()
        .map(|d| {
            let form = Form::blank(d.id, d.specs).options("machine", hosts.clone()).or_sent(sent);
            (d.driver, d.title, form)
        })
        .collect()
}

/// The settings that are credentials: the Vault holds them, the row a reference.
const SECRETS: &[&str] = &["token", "api_key", "password", "community", "auth_password", "priv_password"];

fn setting_of(field: &str) -> &str {
    if field == "token_value" { "token" } else { field }
}

#[derive(Template)]
#[template(path = "appliance_accept.html")]
struct Accept<'a> {
    shell: Shell,
    csrf: &'a str,
    title: &'static str,
    address: String,
    token: String,
    fingerprint: String,
    form: Form,
}

#[derive(Template)]
#[template(path = "add_done.html")]
struct Done {
    shell: Shell,
    lines: Vec<(String, String)>,
    note: String,
}

/// `https://host[:port][/...]` (or without the scheme) as the URL the drivers take, with its host and port.
fn https_address(address: &str, default_port: u16) -> Option<(String, String, u16)> {
    let rest = address.strip_prefix("https://").unwrap_or(address);
    if rest.contains("://") {
        return None;
    }
    let authority = rest.split('/').next().unwrap_or("");
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None if after.is_empty() => default_port,
            None => return None,
        };
        (format!("[{h}]"), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    Some((format!("https://{host}:{port}"), host, port))
}

fn refusal(e: &RegistryError) -> Option<Response<Body>> {
    let RegistryError::Store(StoreError::TokenRefused(r)) = e else { return None };
    Some(match r {
        TokenRefusal::Used => status(StatusCode::CONFLICT, "This form has already been used. Start again from Add."),
        TokenRefusal::Expired => status(StatusCode::GONE, "This form has expired. Start again from Add."),
        TokenRefusal::WrongKind => status(StatusCode::BAD_REQUEST, "That token is for another kind of join"),
        TokenRefusal::Unknown => status(StatusCode::BAD_REQUEST, "That form isn't one this hub made"),
    })
}

fn machine_name(web: &Web, id: &str) -> Option<String> {
    web.0.db.readers().with(|c| c.query_row("SELECT name FROM machines WHERE id = ?1", [id], |r| r.get(0))).ok()
}

/// The address half: the pending machine (or the machine it attaches to), the certificate shown, the form's token.
pub(super) async fn start(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let given = ctx.form.get("driver").map(|d| d.trim()).unwrap_or("");
    let Some(d) = driver_form(given) else {
        return status(StatusCode::BAD_REQUEST, "The appliance is Proxmox VE, TrueNAS, Redfish or SNMP");
    };
    let mut form = Form::sent(d.id, d.specs, ctx, &web.0.held).options("machine", host_options(web));
    let Some(registry) = web.0.registry.as_ref().filter(|_| web.0.drivers.contains_key(d.driver)) else {
        form.notice("The hub isn't ready to add appliances yet; try again in a minute.");
        return add::show(web, ctx, StatusCode::SERVICE_UNAVAILABLE, Some(form));
    };
    let Some(site) = local_site(web) else { return status(StatusCode::CONFLICT, "Complete first run first") };
    let attach = Some(form.value("machine").to_string()).filter(|m| !m.is_empty());
    if attach.is_none() && form.value("name").is_empty() {
        form.refuse("name", "This is needed");
    }
    form.check();
    let url = if d.tls { https_address(form.value("address"), d.port) } else { None };
    form.require("address", !d.tls || url.is_some(), "The address is https://host, or https://host:port");
    let mut code = StatusCode::BAD_REQUEST;
    if attach.is_none() && !form.has_error("name") && name_taken(web, &site, form.value("name")) {
        if form.ok() {
            code = StatusCode::CONFLICT;
        }
        form.refuse("name", "A machine of that name is already here");
    }
    if !form.ok() {
        return add::show(web, ctx, code, Some(form));
    }
    let (address, fingerprint) = match url {
        Some((url, host, port)) => {
            match rackhand_drivers::pinned::presented(&host, port, Duration::from_secs(10)).await {
                Ok(fp) => (url, Some(fp)),
                Err(e) => {
                    form.refuse("address", format!("Couldn't reach {url}: {e}"));
                    return add::show(web, ctx, StatusCode::BAD_GATEWAY, Some(form));
                }
            }
        }
        None => (form.value("address").to_string(), None),
    };
    let name = form.value("name").to_string();
    let add = AddAppliance {
        site_id: site,
        name: name.clone(),
        driver: d.driver.into(),
        address: address.clone(),
        fingerprint: fingerprint.clone(),
        attach,
    };
    let (id, token) = match registry.add_appliance(&add, &user.name, ctx.now_ms).await {
        Ok(r) => r,
        Err(RegistryError::Invalid(why)) => {
            form.notice(why);
            return add::show(web, ctx, StatusCode::BAD_REQUEST, Some(form));
        }
        Err(e) => {
            tracing::error!(error = %e, "add appliance");
            form.notice("The appliance couldn't be added; try again.");
            return add::show(web, ctx, StatusCode::INTERNAL_SERVER_ERROR, Some(form));
        }
    };
    let name = machine_name(web, &id).unwrap_or(name);
    let page = Accept {
        shell: Shell::at(web, ctx, &format!("Add {name}"), "/add"),
        csrf: &ctx.csrf,
        title: d.title,
        address,
        token: token.as_str().to_string(),
        fingerprint: fingerprint.unwrap_or_default(),
        form: Form::blank("accept", d.credentials),
    };
    html(StatusCode::OK, page.render())
}

/// The credentials half: the certificate accepted, one poll pinned to it, then the form completed at once.
pub(super) async fn accept(web: &Web, ctx: &Ctx) -> Response<Body> {
    let Some(user) = &ctx.user else { return redirect("/sign-in") };
    let Some(registry) = web.0.registry.as_ref() else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub isn't ready to add appliances yet");
    };
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let token = Token::parse(&f("token"));
    let form = match registry.appliance_form(&token, ctx.now_ms) {
        Ok(form) => form,
        Err(e) => {
            return refusal(&e).unwrap_or_else(|| status(StatusCode::BAD_REQUEST, "That form can't be completed"));
        }
    };
    let Some(d) = driver_form(&form.driver) else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub has no driver for it");
    };
    let mut sent = Form::sent("accept", d.credentials, ctx, &web.0.held);
    // what SNMP needs depends on its version; the other one's fields aren't looked at
    let (needs, unused): (&[&'static str], &[&'static str]) = match (d.driver, sent.value("version")) {
        ("snmp", "3") => (&["user", "auth_password", "priv_password"], &["community"]),
        ("snmp", "2c") => (&["community"], &["user", "auth_password", "priv_password"]),
        _ => (&[], &[]),
    };
    for name in unused {
        sent.set(name, "");
    }
    for name in needs {
        if sent.value(name).is_empty() {
            sent.refuse(name, "This is needed for the version chosen");
        }
    }
    sent.check();
    // the same page again: what was typed kept, the secrets held
    let again = |mut sent: Form, code: StatusCode, why: Option<String>| {
        if let Some(why) = why {
            sent.notice(why);
        }
        sent.hold(&web.0.held, ctx);
        let name = machine_name(web, &form.machine_id).unwrap_or_default();
        let page = Accept {
            shell: Shell::at(web, ctx, &format!("Add {name}"), "/add"),
            csrf: &ctx.csrf,
            title: d.title,
            address: form.address.clone(),
            token: token.as_str().to_string(),
            fingerprint: form.fingerprint.clone().unwrap_or_default(),
            form: sent,
        };
        html(code, page.render())
    };
    if !sent.ok() {
        return again(sent, StatusCode::BAD_REQUEST, None);
    }
    let mut settings = serde_json::Map::new();
    if let Some(shown) = &form.fingerprint {
        if !f("fingerprint").eq_ignore_ascii_case(shown) {
            let why = "That isn't the certificate the appliance presented".to_string();
            return again(sent, StatusCode::UNPROCESSABLE_ENTITY, Some(why));
        }
        settings.insert("fingerprint".into(), shown.clone().into());
    }
    for spec in d.credentials {
        let v = sent.value(spec.name).trim();
        if !v.is_empty() {
            settings.insert(setting_of(spec.name).into(), v.into());
        }
    }
    let settings = serde_json::Value::Object(settings);
    let Some(driver) = web.0.drivers.get(form.driver.as_str()) else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub has no driver for it");
    };
    let target =
        DriverTarget { target: form.address.clone(), settings: settings.clone(), timeout: Duration::from_secs(10) };
    match driver.poll(&target).await {
        Ok(r) if r.ok => {}
        Ok(r) => {
            let why = format!("The first poll failed: {}", r.detail);
            return again(sent, StatusCode::UNPROCESSABLE_ENTITY, Some(why));
        }
        Err(e) => return again(sent, StatusCode::UNPROCESSABLE_ENTITY, Some(format!("The settings: {e}"))),
    }
    let name = vault_name(&form.machine_id);
    let secret = match web.0.vault.sealed(&name, &Secret::new(settings.to_string().into_bytes()), ctx.now_ms) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "sealing appliance credentials");
            let why = "The credentials couldn't be stored; try again.".to_string();
            return again(sent, StatusCode::INTERNAL_SERVER_ERROR, Some(why));
        }
    };
    let shown = referenced(&settings, SECRETS, &name);
    let attached = machine_name(web, &form.machine_id).is_some_and(|_| {
        web.0
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT state FROM machines WHERE id = ?1", [&form.machine_id], |r| r.get::<_, String>(0))
            })
            .is_ok_and(|s| s == "enrolled")
    });
    if let Err(e) = registry.complete_appliance(&token, &form, &shown, secret, ctx.now_ms).await {
        return refusal(&e).unwrap_or_else(|| {
            tracing::error!(error = %e, "complete appliance");
            status(StatusCode::INTERNAL_SERVER_ERROR, "The appliance couldn't be added")
        });
    }
    let machine = machine_name(web, &form.machine_id).unwrap_or_default();
    let (action, title) = if attached {
        ("machine.driver_added", format!("{machine} now has its {} API", form.driver))
    } else {
        ("machine.added", format!("Added {machine}"))
    };
    let data = serde_json::json!({ "machine": form.machine_id, "name": machine, "driver": form.driver, "address": form.address });
    if let Err(e) = web.0.audit.append(&user.name, action, Some(&form.machine_id), &data.to_string()).await {
        tracing::error!(error = %e, "audit");
    }
    let page = Done { shell: Shell::at(web, ctx, &title, "/add"), lines: vec![], note: "Rackhand checks it through its API from now on.".into() };
    html(StatusCode::OK, page.render())
}
