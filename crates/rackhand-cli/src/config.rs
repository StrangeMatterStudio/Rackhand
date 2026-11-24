//! The CLI's files (7.7.3, D59): the hubs this computer is enrolled to, and a device key for each of them. A device is enrolled
//! to one hub for one user, so two hubs give two keys and the one a hub knows is of no use to another.

use std::path::PathBuf;

use iroh::{Endpoint, SecretKey};
use rackhand_net::ticket::Ticket;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dirs(pub PathBuf);

impl Dirs {
    /// `RACKHAND_CLI_DIR`, or the platform's configuration directory.
    pub fn default_dir() -> Dirs {
        if let Some(dir) = std::env::var_os("RACKHAND_CLI_DIR") {
            return Dirs(dir.into());
        }
        let env = |name: &str| std::env::var_os(name).map(PathBuf::from);
        let base = if cfg!(windows) {
            env("APPDATA")
        } else if cfg!(target_os = "macos") {
            env("HOME").map(|h| h.join("Library/Application Support"))
        } else {
            env("XDG_CONFIG_HOME").or_else(|| env("HOME").map(|h| h.join(".config")))
        };
        Dirs(base.unwrap_or_else(|| PathBuf::from(".")).join("rackhand-cli"))
    }

    fn hubs_file(&self) -> PathBuf {
        self.0.join("hubs.toml")
    }

    /// The device key for the hub with this endpoint id (hex).
    pub fn key_file(&self, hub_id: &str) -> PathBuf {
        self.0.join("keys").join(format!("{hub_id}.key"))
    }
}

/// A hub this computer is enrolled to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hub {
    /// Its endpoint id, hex.
    pub id: String,
    pub site: String,
    /// The user on that hub this device belongs to.
    pub user: String,
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
        .and_then(|text| toml::from_str::<File>(&text).ok())
        .map(|f| f.hub)
        .unwrap_or_default()
}

/// Remembers a hub, replacing an earlier entry for the same hub.
pub fn save(dirs: &Dirs, hub: Hub) -> Result<(), String> {
    let mut hubs = load(dirs);
    hubs.retain(|h| h.id != hub.id);
    hubs.push(hub);
    std::fs::create_dir_all(&dirs.0).map_err(|e| format!("{}: {e}", dirs.0.display()))?;
    let text = toml::to_string(&File { hub: hubs }).map_err(|e| e.to_string())?;
    std::fs::write(dirs.hubs_file(), text).map_err(|e| format!("{}: {e}", dirs.hubs_file().display()))
}

/// The hub of this site, or what the sites are.
pub fn find(dirs: &Dirs, site: &str) -> Result<Hub, String> {
    let hubs = load(dirs);
    hubs.iter().find(|h| h.site == site).cloned().ok_or_else(|| {
        if hubs.is_empty() {
            format!("no hub is known for `{site}`: enroll this device with `rackhand-cli login <invite>`")
        } else {
            let known: Vec<&str> = hubs.iter().map(|h| h.site.as_str()).collect();
            format!("no hub is known for `{site}`; this device is enrolled to {}", known.join(", "))
        }
    })
}

/// This device's key for a hub, made the first time.
pub fn device_key(dirs: &Dirs, hub_id: &str) -> Result<SecretKey, String> {
    let path = dirs.key_file(hub_id);
    rackhand_net::key::load_or_create(&path).map_err(|e| format!("{}: {e}", path.display()))
}

/// An endpoint with this device's key for the hub, accepting nothing.
pub async fn endpoint(dirs: &Dirs, hub_id: &str, relays: Vec<String>) -> Result<Endpoint, String> {
    let key = device_key(dirs, hub_id)?;
    let relays = rackhand_net::relays::RelayConfig { relays, ..Default::default() };
    let config = rackhand_net::endpoint::EndpointConfig { relays, alpns: Vec::new(), bind: None };
    rackhand_net::endpoint::bind(key, &config).await.map_err(|e| e.to_string())
}

/// `<site>/<machine>` as the two names.
pub fn machine(target: &str) -> Result<(&str, &str), String> {
    match target.split_once('/') {
        Some((site, machine)) if !site.is_empty() && !machine.is_empty() && !machine.contains('/') => {
            Ok((site, machine))
        }
        _ => Err(format!("`{target}` isn't `<site>/<machine>`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dirs(name: &str) -> Dirs {
        let dir = std::env::temp_dir().join(format!("rackhand-cli-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        Dirs(dir)
    }

    #[test]
    fn device_keys_per_hub_mode_0600() {
        let d = dirs("keys");
        let (a, b) = ("aa".repeat(32), "bb".repeat(32));
        let (ka, kb) = (device_key(&d, &a).unwrap(), device_key(&d, &b).unwrap());
        assert_ne!(ka.public(), kb.public(), "two hubs give two keys");
        assert_eq!(device_key(&d, &a).unwrap().public(), ka.public(), "the same hub gets the same key again");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for id in [&a, &b] {
                let mode = std::fs::metadata(d.key_file(id)).unwrap().permissions().mode() & 0o777;
                assert_eq!(mode, 0o600, "{id}");
            }
            // a key that others can read is refused, not used
            std::fs::set_permissions(d.key_file(&a), std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(device_key(&d, &a).unwrap_err().contains("0600"));
        }
    }

    #[test]
    fn hubs_are_remembered_and_found_by_site() {
        let d = dirs("hubs");
        assert!(find(&d, "home").unwrap_err().contains("rackhand-cli login"));
        let hub = |id: &str, site: &str| Hub {
            id: id.repeat(32),
            site: site.into(),
            user: "riley".into(),
            addrs: vec!["192.0.2.1:7443".into()],
            relays: vec![],
        };
        save(&d, hub("aa", "home")).unwrap();
        save(&d, hub("bb", "offsite")).unwrap();
        save(&d, Hub { user: "sam".into(), ..hub("aa", "home") }).unwrap();
        assert_eq!(load(&d).len(), 2, "a hub enrolled again replaces its entry");
        assert_eq!(find(&d, "home").unwrap().user, "sam");
        assert!(
            find(&d, "elsewhere").unwrap_err().contains("home, offsite")
                || find(&d, "elsewhere").unwrap_err().contains("offsite, home")
        );
        assert_eq!(find(&d, "offsite").unwrap().ticket().unwrap().addrs.len(), 1);
    }

    #[test]
    fn a_machine_is_a_site_and_a_name() {
        assert_eq!(machine("siteb/vm1"), Ok(("siteb", "vm1")));
        for bad in ["vm1", "/vm1", "siteb/", "a/b/c", ""] {
            assert!(machine(bad).is_err(), "{bad:?}");
        }
    }
}
