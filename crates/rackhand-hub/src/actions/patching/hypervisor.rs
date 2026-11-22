//! Rebooting a hypervisor (7.5.3 step 7): never automatic (E13). A patched one that needs it gets a high-risk approval
//! that lists every guest that goes down with it, and names the hub when it is one of them (E62); two of one cluster
//! are never rebooted in the same window.

use crate::actions::runner::BoxFuture;

/// The runbook a hypervisor's approved reboot runs.
pub const REBOOT: &str = "reboot-host";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostGuest {
    pub vmid: u64,
    /// `lxc` or `qemu`.
    pub kind: String,
    pub name: String,
    pub running: bool,
}

impl HostGuest {
    fn label(&self) -> String {
        let kind = if self.kind == "lxc" { "CT" } else { "VM" };
        let stopped = if self.running { "" } else { ", stopped" };
        let name = if self.name.is_empty() { "unnamed" } else { &self.name };
        format!("{name} ({kind} {}{stopped})", self.vmid)
    }
}

/// A hypervisor as its API gives it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostView {
    pub node: String,
    /// Every node of its cluster; its own alone when it has none.
    pub nodes: Vec<String>,
    /// The guests on its node.
    pub guests: Vec<HostGuest>,
}

/// Reads hypervisors' APIs.
pub trait Hosts: Send + Sync {
    fn view<'a>(&'a self, host: &'a str) -> BoxFuture<'a, Result<HostView, String>>;
}

/// Whether two hypervisors are of one cluster: each is among the other's nodes, and neither stands alone.
pub fn same_cluster(a: &HostView, b: &HostView) -> bool {
    a.nodes.len() > 1 && b.nodes.len() > 1 && a.nodes.contains(&b.node) && b.nodes.contains(&a.node)
}

/// What the reboot's approval tells the person deciding; `hub` is the hub's own guest on this host, if it is one.
pub fn reason(view: &HostView, hub: Option<&HostGuest>) -> String {
    let mut guests: Vec<&HostGuest> = view.guests.iter().collect();
    guests.sort_by_key(|g| (!g.running, g.vmid));
    let list = match guests.as_slice() {
        [] => "It has no guests.".to_string(),
        some => {
            let names: Vec<String> = some.iter().map(|g| g.label()).collect();
            format!("These guests go down with it: {}.", names.join(", "))
        }
    };
    let hub = hub.map(|g| format!(" This hub is one of them: {}.", g.label())).unwrap_or_default();
    format!("updates were installed on the hypervisor and it needs a reboot. {list}{hub}")
}
