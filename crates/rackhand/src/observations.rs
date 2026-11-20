//! What MCP and the dashboard read from Ingest (7.3.6): the latest report's facts and series by range.

use rackhand_hub::ingest::Ingest;
use rackhand_hub::mcp::{Facts, Observations, SeriesQuery};

#[derive(Debug)]
pub struct FromIngest(pub Ingest);

impl Observations for FromIngest {
    fn series(&self, q: &SeriesQuery) -> Vec<(i64, f64)> {
        rackhand_hub::query::vitals::vitals(&self.0, &q.machine_id, &q.metric, &q.labels, q.from_ms, q.to_ms)
    }

    fn facts(&self, machine_id: &str) -> Facts {
        self.0
            .latest(machine_id)
            .map(|l| Facts { services: l.services_json(), containers: l.containers_json(), updates: l.updates_json() })
            .unwrap_or_default()
    }
}
