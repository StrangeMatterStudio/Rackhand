//! `rackhand-probe set-hub <ticket>` (7.7.3, E35, D91): points this machine's probe at a hub by a new ticket. `probe.toml`
//! pins the hub and only root writes it, so this is for root; it is what fixes a probe at a LAN-only site whose hub changed
//! address, where no relay lets the hub tell the probe itself. The machine's own section is kept.

use std::path::Path;

use rackhand_net::ticket::Ticket;

use crate::config::ProbeToml;

/// Rewrites the `[hub]` section of `path` from `ticket_text`; `is_root` is whether the caller is root.
pub fn rewrite(path: &Path, ticket_text: &str, is_root: bool) -> Result<String, String> {
    if !is_root {
        return Err("set-hub changes the hub this machine trusts, so it needs root".into());
    }
    let ticket = Ticket::parse(ticket_text)?;
    let current = ProbeToml::load(path).map_err(|e| e.to_string())?;
    let id: String = ticket.hub_id.iter().map(|b| format!("{b:02x}")).collect();
    let quote = |items: &[String]| items.iter().map(|i| format!("{i:?}")).collect::<Vec<_>>().join(", ");
    let addrs: Vec<String> = ticket.addrs.iter().map(|a| a.to_string()).collect();
    let mut text = format!("[hub]\nid = {id:?}\naddrs = [{}]\nrelays = [{}]\n", quote(&addrs), quote(&ticket.relays));
    if let Some(machine) = &current.machine {
        text.push_str(&format!(
            "\n[machine]\nid = {:?}\naccess = {:?}\nmode = {:?}\n",
            machine.id, machine.access, machine.mode
        ));
    }
    // what is written must read back as a probe.toml, or nothing is replaced
    ProbeToml::parse(&text).map_err(|e| e.to_string())?;
    let tmp = path.with_extension("toml.new");
    std::fs::write(&tmp, &text).map_err(|e| format!("{}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(format!(
        "this probe now trusts hub {} at {}",
        &id[..12],
        if addrs.is_empty() { "its relays".to_string() } else { addrs.join(", ") }
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const OLD_ID: &str = "11111111111111111111111111111111111111111111111111111111111111aa";

    fn probe_toml(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("rackhand-set-hub-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("probe.toml");
        std::fs::write(
            &path,
            format!("[hub]\nid = \"{OLD_ID}\"\naddrs = [\"192.0.2.10:7443\"]\n\n[machine]\nid = \"01J1MACH1NE0000000000000AA\"\naccess = \"managed\"\nmode = \"remote\"\n"),
        )
        .unwrap();
        path
    }

    #[test]
    fn set_hub_requires_root_and_rewrites_probe_toml() {
        let path = probe_toml("rewrite");
        let new_id = "22".repeat(32);
        let ticket = format!("rackhand1:{new_id}@198.51.100.5:7443,198.51.100.6:7443!https://relay.example.net");
        // not root: nothing changes
        let before = std::fs::read_to_string(&path).unwrap();
        assert!(rewrite(&path, &ticket, false).unwrap_err().contains("needs root"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
        // root: the hub, its addresses and relays are the ticket's, and the machine's own section is as it was
        let said = rewrite(&path, &ticket, true).unwrap();
        assert!(said.contains("198.51.100.5:7443"), "{said}");
        let now = ProbeToml::load(&path).unwrap();
        assert_eq!(now.hub.id, new_id);
        assert_eq!(now.hub.addrs.len(), 2);
        assert_eq!(now.hub.relays, ["https://relay.example.net"]);
        let machine = now.machine.unwrap();
        assert_eq!(
            (machine.id.as_str(), machine.access.as_str(), machine.mode.as_str()),
            ("01J1MACH1NE0000000000000AA", "managed", "remote")
        );
        // a ticket that isn't one, and a probe.toml that can't be read, change nothing
        let again = std::fs::read_to_string(&path).unwrap();
        assert!(rewrite(&path, "not a ticket", true).is_err());
        assert!(rewrite(&path.with_file_name("missing.toml"), &ticket, true).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), again);
        assert!(!path.with_extension("toml.new").exists(), "no half-written file is left");
    }
}
