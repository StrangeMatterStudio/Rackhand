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

use super::add::valid_name;
use super::{html, redirect, status};
use crate::registry::RegistryError;
use crate::registry::agentless::{AddAppliance, referenced, vault_name};
use crate::registry::tokens::Token;
use crate::vault::Secret;
use crate::web::{Ctx, Web};

/// The drivers with a form: name, title, address example, HTTPS (a certificate to accept), default port.
pub(super) const DRIVERS: &[(&str, &str, &str, bool, u16)] = &[
    ("proxmox", "Proxmox VE", "https://pve.lab.test:8006", true, 8006),
    ("truenas", "TrueNAS", "https://nas.lab.test", true, 443),
    ("redfish", "Redfish BMC", "https://bmc.lab.test", true, 443),
    ("snmp", "SNMP device", "switch.lab.test:161", false, 161),
];

/// The settings that are credentials: the Vault holds them, the row a reference.
const SECRETS: &[&str] = &["token", "api_key", "password", "community", "auth_password", "priv_password"];

/// A driver's credential fields: the form field, its label, whether it is hidden as typed, and the setting it sets.
fn fields(driver: &str) -> Vec<(&'static str, &'static str, bool)> {
    match driver {
        "proxmox" => {
            vec![("token_value", "API token (user@realm!id=secret)", true), ("node", "Node (optional)", false)]
        }
        "truenas" => vec![("api_key", "API key", true)],
        "redfish" => vec![("username", "BMC account", false), ("password", "Password", true)],
        _ => vec![
            ("version", "Version (2c or 3)", false),
            ("community", "Community (v2c)", true),
            ("user", "User (v3)", false),
            ("auth", "Authentication (v3: SHA or SHA-256)", false),
            ("auth_password", "Authentication password (v3)", true),
            ("priv", "Privacy (v3: AES)", false),
            ("priv_password", "Privacy password (v3)", true),
        ],
    }
}

fn setting_of(field: &str) -> &str {
    if field == "token_value" { "token" } else { field }
}

#[derive(Template)]
#[template(path = "appliance_accept.html")]
struct Accept<'a> {
    csrf: &'a str,
    name: String,
    title: &'static str,
    address: String,
    token: String,
    fingerprint: String,
    fields: Vec<(&'static str, &'static str, bool)>,
}

#[derive(Template)]
#[template(path = "add_done.html")]
struct Done {
    title: String,
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
    let f = |k: &str| ctx.form.get(k).map(|v| v.trim().to_string()).unwrap_or_default();
    let (driver, name, address, attach) = (f("driver"), f("name"), f("address"), f("machine"));
    let Some(&(driver, title, _, tls, port)) = DRIVERS.iter().find(|d| d.0 == driver) else {
        return status(StatusCode::BAD_REQUEST, "The appliance is Proxmox VE, TrueNAS, Redfish or SNMP");
    };
    let Some(registry) = web.0.registry.as_ref().filter(|_| web.0.drivers.contains_key(driver)) else {
        return status(StatusCode::SERVICE_UNAVAILABLE, "The hub isn't ready to add appliances yet");
    };
    let attach = (driver == "proxmox" && !attach.is_empty()).then_some(attach);
    if attach.is_none() && !valid_name(&name) {
        return status(StatusCode::BAD_REQUEST, "The name is 1 to 64 letters, digits, ., _ and -");
    }
    if address.is_empty() || address.len() > 512 {
        return status(StatusCode::BAD_REQUEST, "Give the appliance's address");
    }
    let site: Option<String> =
        web.0.db.readers().with(|c| c.query_row("SELECT id FROM sites WHERE is_local = 1", [], |r| r.get(0))).ok();
    let Some(site) = site else { return status(StatusCode::CONFLICT, "Complete first run first") };
    if attach.is_none() {
        let taken: bool = web
            .0
            .db
            .readers()
            .with(|c| {
                c.query_row("SELECT count(*) > 0 FROM machines WHERE site_id = ?1 AND name = ?2", [&site, &name], |r| {
                    r.get(0)
                })
            })
            .unwrap_or(false);
        if taken {
            return status(StatusCode::CONFLICT, "A machine of that name is already here");
        }
    }
    let (address, fingerprint) = if tls {
        let Some((url, host, port)) = https_address(&address, port) else {
            return status(StatusCode::BAD_REQUEST, "The address is https://host[:port]");
        };
        match rackhand_drivers::pinned::presented(&host, port, Duration::from_secs(10)).await {
            Ok(fp) => (url, Some(fp)),
            Err(e) => return status(StatusCode::BAD_GATEWAY, &format!("Couldn't reach {url}: {e}")),
        }
    } else {
        (address, None)
    };
    let add = AddAppliance {
        site_id: site,
        name: name.clone(),
        driver: driver.into(),
        address: address.clone(),
        fingerprint: fingerprint.clone(),
        attach,
    };
    let (id, token) = match registry.add_appliance(&add, &user.name, ctx.now_ms).await {
        Ok(r) => r,
        Err(RegistryError::Invalid(why)) => return status(StatusCode::BAD_REQUEST, &why),
        Err(e) => {
            tracing::error!(error = %e, "add appliance");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The appliance couldn't be added");
        }
    };
    let page = Accept {
        csrf: &ctx.csrf,
        name: machine_name(web, &id).unwrap_or(name),
        title,
        address,
        token: token.as_str().to_string(),
        fingerprint: fingerprint.unwrap_or_default(),
        fields: fields(driver),
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
    let mut settings = serde_json::Map::new();
    if let Some(shown) = &form.fingerprint {
        if !f("fingerprint").eq_ignore_ascii_case(shown) {
            return status(StatusCode::UNPROCESSABLE_ENTITY, "That isn't the certificate the appliance presented");
        }
        settings.insert("fingerprint".into(), shown.clone().into());
    }
    for (field, _, _) in fields(&form.driver) {
        let v = f(field);
        if !v.is_empty() {
            settings.insert(setting_of(field).into(), v.into());
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
        Ok(r) => return status(StatusCode::UNPROCESSABLE_ENTITY, &format!("The first poll failed: {}", r.detail)),
        Err(e) => return status(StatusCode::UNPROCESSABLE_ENTITY, &format!("The settings: {e}")),
    }
    let name = vault_name(&form.machine_id);
    let secret = match web.0.vault.sealed(&name, &Secret::new(settings.to_string().into_bytes()), ctx.now_ms) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "sealing appliance credentials");
            return status(StatusCode::INTERNAL_SERVER_ERROR, "The credentials couldn't be stored");
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
    let page = Done { title, lines: vec![], note: "Rackhand checks it through its API from now on.".into() };
    html(StatusCode::OK, page.render())
}
