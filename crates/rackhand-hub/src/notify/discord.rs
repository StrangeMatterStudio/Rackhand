//! Discord webhooks (7.3.9): `{username: "Rackhand", embeds: [{title, description, color, url, fields, timestamp}]}`,
//! at most 2000 characters of description, and HTTP 429's `retry_after` respected.

use std::time::Duration;

use axum::http::Method;
use serde_json::{Value, json};

use super::{BoxFuture, Message, MessageKind, SendError, Transport};

pub const RED: u32 = 0xD3_2F2F;
pub const AMBER: u32 = 0xF9_A825;
pub const GREEN: u32 = 0x38_8E3C;
pub const GREY: u32 = 0x75_7575;
const MAX_DESCRIPTION: usize = 2000;
const TIMEOUT: Duration = Duration::from_secs(15);

fn truncate(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let mut out: String = text.chars().take(max - 1).collect();
    out.push('…');
    out
}

/// The title a message has in Discord and the email subject (without the `[Rackhand]` prefix).
pub fn headline(msg: &Message) -> String {
    let one = msg.incidents.first();
    let place = one.map(|i| format!("{}/{}", i.site, i.machine)).unwrap_or_default();
    let title = one.map(|i| i.title.as_str()).unwrap_or_default();
    match msg.kind {
        MessageKind::Callout => format!("{} {place}: {title}", msg.severity.to_uppercase()),
        MessageKind::Resolution => format!("RESOLVED {place}: {title}"),
        MessageKind::Group => {
            let site = one.map(|i| i.site.as_str()).unwrap_or_default();
            format!("WARNING {site}: {} warnings", msg.incidents.len())
        }
        MessageKind::NotifierFailed | MessageKind::Text => title.to_string(),
    }
}

pub fn payload(msg: &Message, dashboard_url: Option<&str>) -> Value {
    let color = match (msg.kind, msg.severity.as_str()) {
        (MessageKind::Resolution, _) => GREEN,
        (_, "critical") => RED,
        (_, "warning") => AMBER,
        _ => GREY,
    };
    let description = match msg.kind {
        MessageKind::Group => {
            msg.incidents.iter().map(|i| format!("- {}: {}", i.machine, i.title)).collect::<Vec<_>>().join("\n")
        }
        _ => msg.incidents.first().map(|i| i.description.clone()).unwrap_or_default(),
    };
    let timestamp = jiff::Timestamp::from_millisecond(msg.at_ms).map(|t| t.to_string()).unwrap_or_default();
    let mut embed = json!({
        "title": truncate(&headline(msg), 256),
        "description": truncate(&description, MAX_DESCRIPTION),
        "color": color,
        "timestamp": timestamp,
    });
    if let [one] = msg.incidents.as_slice() {
        if !one.id.is_empty() {
            embed["fields"] = json!([
                { "name": "Site", "value": one.site, "inline": true },
                { "name": "Machine", "value": one.machine, "inline": true },
                { "name": "Severity", "value": one.severity, "inline": true },
            ]);
            if let Some(base) = dashboard_url {
                embed["url"] = json!(format!("{}/incidents/{}", base.trim_end_matches('/'), one.id));
            }
        }
    }
    json!({ "username": "Rackhand", "embeds": [embed] })
}

#[derive(Debug)]
pub struct Discord {
    name: String,
    webhook: String,
    dashboard_url: Option<String>,
}

impl Discord {
    pub fn new(name: &str, webhook: &str) -> Discord {
        Discord { name: name.to_string(), webhook: webhook.to_string(), dashboard_url: None }
    }

    pub fn with_dashboard_url(mut self, url: Option<&str>) -> Discord {
        self.dashboard_url = url.map(str::to_string);
        self
    }
}

impl Transport for Discord {
    fn name(&self) -> &str {
        &self.name
    }

    fn send<'a>(&'a self, msg: &'a Message) -> BoxFuture<'a, Result<(), SendError>> {
        Box::pin(async move {
            let body = payload(msg, self.dashboard_url.as_deref()).to_string().into_bytes();
            let resp = crate::http::request(
                Method::POST,
                &self.webhook,
                &[("content-type", "application/json")],
                body,
                TIMEOUT,
            )
            .await
            .map_err(SendError::Failed)?;
            match resp.status {
                200..=299 => Ok(()),
                429 => {
                    let secs = serde_json::from_slice::<Value>(&resp.body)
                        .ok()
                        .and_then(|v| v["retry_after"].as_f64())
                        .or_else(|| resp.header("retry-after").and_then(|h| h.parse().ok()))
                        .unwrap_or(1.0);
                    Err(SendError::RetryAfter(Duration::from_secs_f64(secs.clamp(0.0, 3_600.0))))
                }
                code => Err(SendError::Failed(format!("Discord answered {code}"))),
            }
        })
    }
}
