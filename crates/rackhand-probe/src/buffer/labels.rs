//! The probe's label table for the current epoch (7.3.2, D94): ids are never reused within an epoch, the table lives
//! on disk next to the buffer, and the probe starts a new epoch before the table passes 4096 entries.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

pub type LabelSet = BTreeMap<String, String>;

pub const MAX_ENTRIES: u32 = 4096;
/// Roll to a new epoch this close to the limit, once the buffer is empty.
const ROLL_MARGIN: u32 = 64;

#[derive(Debug)]
pub struct LabelTable {
    path: PathBuf,
    by_set: BTreeMap<LabelSet, u32>,
    entries: BTreeMap<u32, LabelSet>,
    next_id: u32,
}

impl LabelTable {
    pub fn open(dir: &Path, epoch: u64) -> std::io::Result<LabelTable> {
        let path = dir.join(format!("labels-{epoch:016x}.jsonl"));
        let mut t = LabelTable { path: path.clone(), by_set: BTreeMap::new(), entries: BTreeMap::new(), next_id: 0 };
        if let Ok(text) = std::fs::read_to_string(&path) {
            for line in text.lines() {
                let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else { continue };
                let id = v["id"].as_u64().unwrap_or(0) as u32;
                let labels: LabelSet = serde_json::from_value(v["labels"].clone()).unwrap_or_default();
                t.next_id = t.next_id.max(id + 1);
                if v["removed"].as_bool().unwrap_or(false) {
                    t.entries.remove(&id);
                    t.by_set.remove(&labels);
                } else {
                    t.by_set.insert(labels.clone(), id);
                    t.entries.insert(id, labels);
                }
            }
        }
        Ok(t)
    }

    fn log(&self, id: u32, labels: &LabelSet, removed: bool) {
        let line = serde_json::json!({"id": id, "labels": labels, "removed": removed});
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.path) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// The id for a label set, adding it to the table if it is new.
    pub fn id_for(&mut self, labels: &LabelSet) -> u32 {
        if let Some(id) = self.by_set.get(labels) {
            return *id;
        }
        let id = self.next_id;
        self.next_id += 1;
        self.by_set.insert(labels.clone(), id);
        self.entries.insert(id, labels.clone());
        self.log(id, labels, false);
        id
    }

    /// Forgets a label set (its series went away); the id is never handed out again in this epoch.
    pub fn forget(&mut self, labels: &LabelSet) {
        if let Some(id) = self.by_set.remove(labels) {
            self.entries.remove(&id);
            self.log(id, labels, true);
        }
    }

    pub fn entries(&self) -> &BTreeMap<u32, LabelSet> {
        &self.entries
    }

    /// Whether to start a new epoch now: close to the id limit and nothing left in the buffer that uses old ids.
    pub fn needs_new_epoch(&self, buffer_empty: bool) -> bool {
        buffer_empty && self.next_id >= MAX_ENTRIES - ROLL_MARGIN
    }
}
