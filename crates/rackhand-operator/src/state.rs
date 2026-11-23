//! What an operator host keeps on disk: its node key (its endpoint id on every hub), the hubs it joined, a configuration
//! directory for the runner of its own, and the sockets of the jobs it runs.

use std::path::PathBuf;

use rackhand_net::ticket::Ticket;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct Dirs(pub PathBuf);

impl Dirs {
    pub fn node_key(&self) -> PathBuf {
        self.0.join("node.key")
    }

    pub fn hubs_file(&self) -> PathBuf {
        self.0.join("hubs.toml")
    }

    /// The runner's configuration directory: only the AI provider's credential is in it.
    pub fn runner_config(&self) -> PathBuf {
        self.0.join("runner")
    }

    /// The runner's working directories, one per job.
    pub fn work(&self) -> PathBuf {
        self.0.join("work")
    }

    /// The sockets the bridges connect to, one per job.
    pub fn sockets(&self) -> PathBuf {
        self.0.join("run")
    }
}

/// A hub this host joined.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hub {
    /// Its endpoint id, hex.
    pub id: String,
    pub site: String,
    pub addrs: Vec<String>,
    pub relays: Vec<String>,
}

impl Hub {
    pub fn ticket(&self) -> Result<Ticket, String> {
        Ticket::parse(&format!("rackhand1:{}@{}!{}", self.id, self.addrs.join(","), self.relays.join(",")))
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct File {
    #[serde(default)]
    hub: Vec<Hub>,
}

pub fn load(dirs: &Dirs) -> Vec<Hub> {
    std::fs::read_to_string(dirs.hubs_file())
        .ok()
        .and_then(|t| toml::from_str::<File>(&t).ok())
        .map(|f| f.hub)
        .unwrap_or_default()
}

/// Remembers a hub, replacing one with the same id.
pub fn save(dirs: &Dirs, hub: Hub) -> Result<(), String> {
    let mut hubs = load(dirs);
    hubs.retain(|h| h.id != hub.id);
    hubs.push(hub);
    std::fs::create_dir_all(&dirs.0).map_err(|e| format!("{}: {e}", dirs.0.display()))?;
    let text = toml::to_string(&File { hub: hubs }).map_err(|e| e.to_string())?;
    std::fs::write(dirs.hubs_file(), text).map_err(|e| format!("{}: {e}", dirs.hubs_file().display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hubs_are_kept_and_replaced_by_id() {
        let dir = std::env::temp_dir().join(format!("rackhand-operator-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let dirs = Dirs(dir);
        assert!(load(&dirs).is_empty());
        let hub = |site: &str| Hub {
            id: "ab".repeat(32),
            site: site.into(),
            addrs: vec!["192.0.2.10:7443".into()],
            relays: vec![],
        };
        save(&dirs, hub("home")).unwrap();
        save(&dirs, Hub { id: "cd".repeat(32), ..hub("lab") }).unwrap();
        save(&dirs, hub("home2")).unwrap();
        let all = load(&dirs);
        assert_eq!(all.len(), 2);
        assert!(all.iter().any(|h| h.site == "home2") && !all.iter().any(|h| h.site == "home"));
        let ticket = all.iter().find(|h| h.site == "home2").unwrap().ticket().unwrap();
        assert_eq!(ticket.addrs.len(), 1);
    }
}
