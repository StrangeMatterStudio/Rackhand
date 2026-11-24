//! Logon events (7.3.3): the Security log's 4624 (an account logged on) and 4625 (a logon failed), as the helper reads them,
//! and of those only the logon types a person makes: 2 (interactive), 3 (network) and 10 (remote interactive, which is
//! Remote Desktop). Services, scheduled tasks, unlocks and cached logons are the machine's own and not reported, nor are
//! machine accounts and anonymous logons.
//!
//! The helper's PowerShell line writes one object per event: `Id`, `TimeMs` (Unix milliseconds), `LogonType`, `User`, `Domain`
//! and `Ip`, taken from the event's data.

use rackhand_proto::helper::{AuthEvent, AuthKind};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Row {
    id: u32,
    time_ms: i64,
    #[serde(default)]
    logon_type: u32,
    #[serde(default)]
    user: String,
    #[serde(default)]
    ip: Option<String>,
}

const LOGON: u32 = 4624;
const FAILED: u32 = 4625;

fn method(logon_type: u32) -> Option<&'static str> {
    match logon_type {
        2 => Some("interactive"),
        3 => Some("network"),
        10 => Some("remote_interactive"),
        _ => None,
    }
}

/// A person's account: not a machine account (`HOST$`) and not one of the anonymous or built-in ones.
fn person(user: &str) -> bool {
    let upper = user.to_ascii_uppercase();
    !user.is_empty()
        && !user.ends_with('$')
        && !matches!(upper.as_str(), "ANONYMOUS LOGON" | "SYSTEM" | "LOCAL SERVICE" | "NETWORK SERVICE" | "-")
}

pub fn parse(json: &str) -> Result<Vec<AuthEvent>, String> {
    let value: serde_json::Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    let items = match value {
        serde_json::Value::Array(items) => items,
        one @ serde_json::Value::Object(_) => vec![one],
        _ => return Err("the logon events aren't a list".into()),
    };
    let mut out = Vec::new();
    for item in items {
        let row: Row = serde_json::from_value(item).map_err(|e| e.to_string())?;
        let kind = match row.id {
            LOGON => AuthKind::Logon,
            FAILED => AuthKind::SshFailed,
            _ => continue,
        };
        let (Some(method), true) = (method(row.logon_type), person(&row.user)) else { continue };
        let ip = row.ip.filter(|ip| !ip.is_empty() && ip != "-" && ip != "::1" && ip != "127.0.0.1");
        out.push(AuthEvent {
            at_ms: row.time_ms,
            kind,
            user: row.user,
            source_ip: ip,
            method: Some(method.into()),
            detail: None,
        });
    }
    Ok(out)
}
