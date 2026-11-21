//! The Proxmox VE driver (FR-10, 7.4.2): polls each node's CPU and memory, its datastores' use and its guests' status,
//! CPU and memory, and performs what the runbooks need (snapshot, rollback, the guest firewall, power, clone, config).
//! Target `https://<host>:8006` (or `<host>[:port]`); settings `token`, `fingerprint` and, optionally, `node`.

mod client;
mod ops;
#[cfg(any(test, feature = "sim"))]
pub mod sim;

use serde_json::Value;

use crate::driver::{Driver, DriverError, DriverKind, DriverOp, DriverOpResult, DriverReading, DriverTarget, Point};
use client::Client;

#[derive(Debug, Default)]
pub struct Proxmox;

impl Proxmox {
    pub fn new() -> Proxmox {
        Proxmox
    }
}

fn num(v: &Value) -> Option<f64> {
    v.as_f64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

fn pct(used: f64, total: f64) -> f64 {
    if total > 0.0 { (used / total * 10_000.0).round() / 100.0 } else { 0.0 }
}

/// The nodes to read: the `node` setting, or every online node the token sees.
pub(crate) async fn nodes(c: &Client) -> Result<Vec<String>, DriverError> {
    if let Some(n) = &c.node {
        return Ok(vec![n.clone()]);
    }
    let list = c.call("GET", "/nodes", &[]).await?;
    Ok(list
        .as_array()
        .map(|a| {
            a.iter()
                .filter(|n| n["status"].as_str().is_none_or(|s| s == "online"))
                .filter_map(|n| n["node"].as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default())
}

async fn read_node(c: &Client, node: &str, points: &mut Vec<Point>) -> Result<usize, DriverError> {
    let n = [("node", node)];
    let status = c.call("GET", &format!("/nodes/{node}/status"), &[]).await?;
    if let Some(cpu) = num(&status["cpu"]) {
        points.push(Point::new("pve.node.cpu_pct", &n, (cpu * 10_000.0).round() / 100.0));
    }
    if let (Some(used), Some(total)) = (num(&status["memory"]["used"]), num(&status["memory"]["total"])) {
        points.push(Point::new("pve.node.mem_used_bytes", &n, used));
        points.push(Point::new("pve.node.mem_used_pct", &n, pct(used, total)));
    }
    let storage = c.call("GET", &format!("/nodes/{node}/storage"), &[]).await?;
    for s in storage.as_array().into_iter().flatten() {
        let Some(name) = s["storage"].as_str() else { continue };
        if s["active"].as_i64() == Some(0) {
            continue;
        }
        let labels = [("node", node), ("storage", name)];
        let (used, total) = (num(&s["used"]).unwrap_or(0.0), num(&s["total"]).unwrap_or(0.0));
        points.push(Point::new("pve.storage.used_bytes", &labels, used));
        points.push(Point::new("pve.storage.total_bytes", &labels, total));
        points.push(Point::new("pve.storage.used_pct", &labels, pct(used, total)));
    }
    let mut guests = 0;
    for kind in ["lxc", "qemu"] {
        let list = c.call("GET", &format!("/nodes/{node}/{kind}"), &[]).await?;
        for g in list.as_array().into_iter().flatten() {
            let Some(vmid) = num(&g["vmid"]).map(|v| (v as u64).to_string()) else { continue };
            let labels = [("node", node), ("vmid", vmid.as_str())];
            let up = if g["status"].as_str() == Some("running") { 1.0 } else { 0.0 };
            points.push(Point::new("pve.guest.up", &labels, up));
            points.push(Point::new("pve.guest.cpu_pct", &labels, num(&g["cpu"]).unwrap_or(0.0) * 100.0));
            points.push(Point::new("pve.guest.mem_used_bytes", &labels, num(&g["mem"]).unwrap_or(0.0)));
            guests += 1;
        }
    }
    Ok(guests)
}

#[async_trait::async_trait]
impl Driver for Proxmox {
    fn kind(&self) -> DriverKind {
        DriverKind::Proxmox
    }

    fn known_settings(&self) -> &'static [&'static str] {
        Client::SETTINGS
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        let c = Client::new(target)?;
        let started = std::time::Instant::now();
        let read = async {
            let mut points = Vec::new();
            let list = nodes(&c).await?;
            let mut guests = 0;
            for node in &list {
                guests += read_node(&c, node, &mut points).await?;
            }
            Ok::<_, DriverError>((points, list.len(), guests))
        };
        match read.await {
            Ok((points, n, guests)) => {
                let mut r =
                    DriverReading::up(crate::driver::millis(started), format!("{n} nodes, {guests} guests"), vec![]);
                r.points = points;
                Ok(r)
            }
            Err(e) => Ok(DriverReading::down(e.to_string(), vec![])),
        }
    }

    async fn call(&self, target: &DriverTarget, op: DriverOp) -> Result<DriverOpResult, DriverError> {
        let c = Client::new(target)?;
        ops::run(&c, target, op).await
    }
}

#[cfg(test)]
mod tests;
