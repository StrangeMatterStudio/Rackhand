//! Incidents about a peer hub (7.6.3, 7.5.5): silent after 2 minutes without a summary (a warning) and down after 10 (critical),
//! one per peer and kind, resolved when the peer is heard from again.

use rackhand_detect::rules::Severity;

use super::lifecycle::Opening;
use super::{Incidents, IncidentsError};

fn key(site: &str, kind: &str) -> String {
    format!("peer:{site}:{kind}")
}

impl Incidents {
    /// A peer is silent (`peer.silent`, a warning) or down (`peer.down`, critical).
    pub async fn peer_unwell(&self, site: &str, down: bool, since_ms: i64, now_ms: i64) -> Result<(), IncidentsError> {
        let (kind, severity, word) =
            if down { ("peer.down", Severity::Critical, "down") } else { ("peer.silent", Severity::Warning, "silent") };
        let minutes = (now_ms - since_ms) / 60_000;
        let o = Opening {
            machine_id: None,
            rule_id: None,
            dedupe_key: key(site, kind),
            kind: kind.into(),
            severity,
            title: format!("Peer hub {site} is {word}: nothing from it for {minutes} minutes"),
        };
        self.open(o, now_ms).await.map(|_| ())
    }

    /// The peer is heard from: its open incidents are resolved.
    pub async fn peer_well(&self, site: &str, now_ms: i64) -> Result<(), IncidentsError> {
        let open: Vec<String> = self.inner.db.readers().with(|c| {
            let mut s = c.prepare("SELECT id FROM incidents WHERE dedupe_key IN (?1, ?2) AND state != 'resolved'")?;
            s.query_map([key(site, "peer.silent"), key(site, "peer.down")], |r| r.get(0))?.collect()
        })?;
        for id in open {
            self.resolve_by(&id, "peer watch", now_ms).await?;
        }
        Ok(())
    }
}
