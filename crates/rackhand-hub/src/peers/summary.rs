//! The site summary (7.3.4, FR-18): what a hub tells its peers every 30 seconds, and what it keeps of theirs (the latest from
//! each peer, one row).

use rackhand_proto::common::SemVer;
use rackhand_proto::peer::{Health, HubHealth, IncidentSummary, MachineSummary, PeerSeen, SiteSummary};
use rackhand_store::ids::now_ms;
use rackhand_store::{Row, RowUpdate, WriteCmd};
use rusqlite::types::Value;

use super::{PeerRow, Peers};

/// What a hub says of itself beyond what its tables show.
pub trait HubHealthSource: Send + Sync {
    fn operators_online(&self) -> u32;
    fn notifiers_ok(&self) -> bool;
    fn self_check_ok(&self) -> bool;
    fn disk_free_pct(&self) -> f64;
}

fn ulid_bytes(id: &str) -> Vec<u8> {
    ulid::Ulid::from_string(id).map(|u| u.to_bytes().to_vec()).unwrap_or_else(|_| id.as_bytes().to_vec())
}

impl Peers {
    /// The summary of this hub's site now.
    pub fn summary(&self, now: i64) -> SiteSummary {
        let db = &self.inner.db;
        type M = (String, String, String, String, String);
        let machines: Vec<M> = db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT id, name, kind, quarantine, state FROM machines WHERE state = 'enrolled' ORDER BY name, id",
                )?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)))?.collect()
            })
            .unwrap_or_default();
        type I = (String, String, String, Option<String>, String, i64);
        let incidents: Vec<I> = db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT id, severity, title, machine_id, kind, opened_at FROM incidents WHERE state != 'resolved'
                     ORDER BY opened_at DESC LIMIT 200",
                )?;
                s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?)))?.collect()
            })
            .unwrap_or_default();
        let machine_health = |id: &str, quarantine: &str| {
            if quarantine != "none" && quarantine != "pending" {
                return Health::Quarantined;
            }
            let own: Vec<&I> = incidents.iter().filter(|i| i.3.as_deref() == Some(id)).collect();
            if own.iter().any(|i| i.4 == "machine.silent") {
                Health::Silent
            } else if own.iter().any(|i| i.1 == "critical") {
                Health::Critical
            } else if own.iter().any(|i| i.1 == "warning") {
                Health::Warning
            } else {
                Health::Ok
            }
        };
        let machines = machines
            .iter()
            .map(|(id, name, kind, quarantine, _)| MachineSummary {
                id: ulid_bytes(id),
                name: name.clone(),
                kind: kind.clone(),
                health: machine_health(id, quarantine) as i32,
                last_seen_ms: self.inner.ingest.latest(id).map_or(0, |l| l.reported_at_ms),
            })
            .collect();
        let open_incidents = incidents
            .iter()
            .map(|(id, severity, title, machine, _, opened)| IncidentSummary {
                id: ulid_bytes(id),
                severity: severity.clone(),
                title: title.clone(),
                machine_id: machine.as_deref().map(ulid_bytes).unwrap_or_default(),
                opened_at_ms: *opened,
            })
            .collect();
        let peers_seen = db
            .readers()
            .with(|c| {
                let mut s = c.prepare(
                    "SELECT site, last_seen_ms FROM peers WHERE revoked_at IS NULL AND last_seen_ms IS NOT NULL ORDER BY site",
                )?;
                s.query_map([], |r| Ok(PeerSeen { site: r.get(0)?, last_heard_ms: r.get(1)? }))?.collect()
            })
            .unwrap_or_default();
        let audit_head: Vec<u8> =
            self.one("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1", []).unwrap_or_default();
        let source = self.inner.health.lock().ok().and_then(|h| h.clone());
        let hub_health = HubHealth {
            version: Some(SemVer { version: self.inner.version.clone() }),
            db_ok: true,
            disk_free_pct: source.as_ref().map_or(100.0, |s| s.disk_free_pct()),
            operators_online: source.as_ref().map_or(0, |s| s.operators_online()),
            notifiers_ok: source.as_ref().is_none_or(|s| s.notifiers_ok()),
            self_check_ok: source.as_ref().is_none_or(|s| s.self_check_ok()),
        };
        SiteSummary {
            site: self.inner.site.clone(),
            generated_at_ms: now,
            machines,
            open_incidents,
            hub_health: Some(hub_health),
            peers_seen,
            audit_head,
        }
    }

    /// Keeps the latest summary a peer sent (one row), and when it was heard from.
    pub(super) async fn store_summary(&self, peer: &PeerRow, summary: &SiteSummary) {
        use prost::Message;
        let now = now_ms();
        let row: Row = [
            ("peer_id", Value::Text(peer.id.clone())),
            ("received_at_ms", Value::Integer(now)),
            ("summary", Value::Blob(summary.encode_to_vec())),
        ]
        .into_iter()
        .collect();
        let db = &self.inner.db;
        if let Err(e) = db.writer().send(WriteCmd::PutPeerSummary(row)).await {
            tracing::warn!(error = %e, peer = %peer.site, "storing a peer's summary");
            return;
        }
        let update = RowUpdate {
            table: "peers",
            key: ("id", Value::Text(peer.id.clone())),
            set: Row::from([("last_seen_ms", Value::Integer(now))]),
        };
        let change = rackhand_store::RegistryChange { updates: vec![update], ..Default::default() };
        let _ = db.writer().send(WriteCmd::RegistryChange(change)).await;
    }

    /// The latest summary a peer sent, and when.
    pub fn latest_summary(&self, peer_id: &str) -> Option<(i64, SiteSummary)> {
        use prost::Message;
        let (at, blob): (i64, Vec<u8>) = self
            .inner
            .db
            .readers()
            .with(|c| {
                use rusqlite::OptionalExtension;
                c.query_row("SELECT received_at_ms, summary FROM peer_summaries WHERE peer_id = ?1", [peer_id], |r| {
                    Ok((r.get(0)?, r.get(1)?))
                })
                .optional()
            })
            .ok()
            .flatten()?;
        Some((at, SiteSummary::decode(blob.as_slice()).ok()?))
    }
}
