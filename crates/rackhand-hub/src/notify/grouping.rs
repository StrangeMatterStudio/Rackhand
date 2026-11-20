//! Warning groups (7.6.7): per site, the first warning starts a 5-minute group, then one message lists them all.

use std::collections::BTreeMap;

pub const GROUP_MS: i64 = 5 * 60_000;

#[derive(Debug, Default)]
pub struct Groups {
    /// Site to (when the group started, its incidents in order).
    by_site: BTreeMap<String, (i64, Vec<String>)>,
}

impl Groups {
    pub fn add(&mut self, site: &str, incident: &str, now_ms: i64) {
        let (_, ids) = self.by_site.entry(site.to_string()).or_insert((now_ms, Vec::new()));
        if !ids.iter().any(|i| i == incident) {
            ids.push(incident.to_string());
        }
    }

    /// An incident resolved before its group went out leaves the group.
    pub fn remove(&mut self, incident: &str) {
        for (_, ids) in self.by_site.values_mut() {
            ids.retain(|i| i != incident);
        }
        self.by_site.retain(|_, (_, ids)| !ids.is_empty());
    }

    /// The groups whose 5 minutes are up, taken out.
    pub fn take_due(&mut self, now_ms: i64) -> Vec<(String, Vec<String>)> {
        let due: Vec<String> =
            self.by_site.iter().filter(|(_, (at, _))| now_ms - at >= GROUP_MS).map(|(s, _)| s.clone()).collect();
        due.into_iter().filter_map(|s| self.by_site.remove(&s).map(|(_, ids)| (s, ids))).collect()
    }
}
