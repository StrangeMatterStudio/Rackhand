//! The agentless machines' polls (FR-10, 7.3.12): which machines are polled, and one poll with the Vault's settings.

use std::time::Duration;

use rackhand_drivers::{DriverReading, DriverTarget};
use rackhand_store::{Row, WriteCmd};
use rusqlite::types::Value;

use super::{Checks, ChecksError, MAX_TIMEOUT, Scheduled, config::CheckSpec, text};
use crate::registry::agentless::vault_name;

/// The check id of an agentless machine's poll is this and the machine's id.
pub const PREFIX: &str = "driver:";
/// How often an agentless machine is polled.
pub const INTERVAL_S: u32 = 60;

pub fn check_id(machine_id: &str) -> String {
    format!("{PREFIX}{machine_id}")
}

impl Checks {
    /// Makes the polls those of the enrolled machines with a driver: new and changed ones are due now, unchanged ones
    /// keep their schedule, and those of machines no longer polled stop (their rows kept, with `interval_s` 0).
    pub async fn sync_agentless(&self) -> Result<usize, ChecksError> {
        type Polled = (String, String, String, Option<String>);
        let polled: Vec<Polled> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare(
                "SELECT id, driver, coalesce(address, ''), driver_settings FROM machines
                 WHERE state = 'enrolled' AND driver IS NOT NULL ORDER BY id",
            )?;
            s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?.collect()
        })?;
        let mut next = std::collections::BTreeMap::new();
        for (machine, driver, address, settings) in polled {
            let spec = CheckSpec {
                name: check_id(&machine),
                kind: driver,
                target: address,
                interval_s: INTERVAL_S,
                machine: None,
                settings: toml::Table::new(),
            };
            let kept = self.state().agentless.get(&spec.name).filter(|s| s.spec == spec).map(|s| s.next_ms);
            let row = Row::from([
                ("id", text(&spec.name)),
                ("kind", text(&spec.kind)),
                ("target", text(&spec.target)),
                ("interval_s", Value::Integer(INTERVAL_S.into())),
                ("machine_id", text(&machine)),
                // the settings as the machine's row shows them: credentials as `secret:` references
                ("settings", text(settings.as_deref().unwrap_or("{}"))),
            ]);
            self.inner.db.writer().send(WriteCmd::PutCheck(row)).await?;
            let s = Scheduled { spec, machine_id: Some(machine), next_ms: kept.unwrap_or(i64::MIN), agentless: true };
            next.insert(s.spec.name.clone(), s);
        }
        let stopped: Vec<Scheduled> =
            self.state().agentless.values().filter(|s| !next.contains_key(&s.spec.name)).cloned().collect();
        for s in stopped {
            let row = Row::from([
                ("id", text(&s.spec.name)),
                ("kind", text(&s.spec.kind)),
                ("target", text(&s.spec.target)),
                ("interval_s", Value::Integer(0)),
                ("machine_id", s.machine_id.as_deref().map_or(Value::Null, text)),
                ("settings", text("{}")),
            ]);
            self.inner.db.writer().send(WriteCmd::PutCheck(row)).await?;
        }
        let n = next.len();
        self.state().agentless = next;
        Ok(n)
    }

    /// One poll of an agentless machine, with the settings its Vault entry holds now.
    pub(super) async fn poll_agentless(&self, s: &Scheduled) -> DriverReading {
        let Some((vault, drivers)) = &self.inner.api else {
            return DriverReading::down("agentless machines aren't polled here", vec![]);
        };
        let Some(driver) = drivers.get(s.spec.kind.as_str()) else {
            return DriverReading::down(format!("no driver for {}", s.spec.kind), vec![]);
        };
        let machine = s.machine_id.as_deref().unwrap_or_default();
        let settings = match vault.get(&vault_name(machine)) {
            Ok(v) => match serde_json::from_slice(v.expose()) {
                Ok(settings) => settings,
                Err(_) => return DriverReading::down("its settings in the Vault aren't readable", vec![]),
            },
            Err(_) => return DriverReading::down("it has no credentials in the Vault", vec![]),
        };
        let timeout = Duration::from_secs(INTERVAL_S.into()).min(MAX_TIMEOUT);
        let target = DriverTarget { target: s.spec.target.clone(), settings, timeout };
        match driver.poll(&target).await {
            Ok(r) => r,
            Err(e) => DriverReading::down(e.to_string(), vec![]),
        }
    }
}
