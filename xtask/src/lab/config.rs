//! `lab/lab.toml`: the lab's sites, machines and profiles (plan L1).

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use anyhow::{Context, Result, bail};
use serde::Deserialize;

use crate::workspace_root;

#[derive(Debug, Clone, Deserialize)]
pub struct Site {
    pub network: String,
    pub mcast_port: u16,
}

impl Site {
    /// Whether `address` is inside this site's network (`a.b.c.d/nn`).
    pub fn contains(&self, address: &str) -> bool {
        let Some((net, bits)) = self.network.split_once('/') else { return false };
        let (Ok(net), Ok(bits), Ok(addr)) = (net.parse::<Ipv4Addr>(), bits.parse::<u32>(), address.parse::<Ipv4Addr>())
        else {
            return false;
        };
        let mask = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
        u32::from(net) & mask == u32::from(addr) & mask
    }

    pub fn prefix_len(&self) -> &str {
        self.network.split_once('/').map(|(_, b)| b).unwrap_or("24")
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Nic {
    pub site: String,
    pub address: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Machine {
    pub name: String,
    pub image: String,
    pub cpus: u32,
    pub memory_mb: u64,
    pub ssh_port: u16,
    #[serde(default)]
    pub extra_disk_gb: Option<u32>,
    /// Proxmox VE major version to install on top of the image.
    #[serde(default)]
    pub proxmox: Option<u32>,
    pub nics: Vec<Nic>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Lab {
    pub sites: BTreeMap<String, Site>,
    #[serde(rename = "machine")]
    pub machines: Vec<Machine>,
    pub profiles: BTreeMap<String, Vec<String>>,
}

impl Lab {
    pub fn load() -> Result<Lab> {
        let path = workspace_root().join("lab/lab.toml");
        let text = std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&text).context("parsing lab/lab.toml")
    }

    pub fn machine(&self, name: &str) -> Result<&Machine> {
        self.machines.iter().find(|m| m.name == name).with_context(|| format!("no lab machine `{name}`"))
    }

    pub fn profile(&self, name: &str) -> Result<Vec<&Machine>> {
        let names = self.profiles.get(name).with_context(|| {
            format!(
                "no lab profile `{name}`; profiles: {}",
                self.profiles.keys().cloned().collect::<Vec<_>>().join(", ")
            )
        })?;
        names.iter().map(|n| self.machine(n)).collect()
    }

    /// Problems with the configuration: unknown machines in profiles, unknown sites, duplicate ports or addresses.
    pub fn check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        for (profile, names) in &self.profiles {
            for name in names {
                if !self.machines.iter().any(|m| &m.name == name) {
                    problems.push(format!("profile `{profile}` names unknown machine `{name}`"));
                }
            }
        }
        let mut ports = BTreeMap::new();
        let mut addresses = BTreeMap::new();
        for m in &self.machines {
            if let Some(other) = ports.insert(m.ssh_port, &m.name) {
                problems.push(format!("`{}` and `{other}` share SSH port {}", m.name, m.ssh_port));
            }
            for nic in &m.nics {
                match self.sites.get(&nic.site) {
                    None => problems.push(format!("`{}` uses unknown site `{}`", m.name, nic.site)),
                    Some(site) if !site.contains(&nic.address) => {
                        problems.push(format!("`{}` address {} is outside site `{}`", m.name, nic.address, nic.site))
                    }
                    Some(_) => {}
                }
                if let Some(other) = addresses.insert(nic.address.clone(), &m.name) {
                    problems.push(format!("`{}` and `{other}` share address {}", m.name, nic.address));
                }
            }
        }
        problems
    }

    pub fn profile_memory_mb(&self, profile: &str) -> Result<u64> {
        Ok(self.profile(profile)?.iter().map(|m| m.memory_mb).sum())
    }

    /// Fails unless the profile's machines fit in `available_mb` minus `reserve_mb` kept for builds.
    pub fn check_budget(&self, profile: &str, available_mb: u64, reserve_mb: u64) -> Result<()> {
        let needed = self.profile_memory_mb(profile)?;
        let room = available_mb.saturating_sub(reserve_mb);
        if needed > room {
            bail!(
                "profile `{profile}` needs {needed} MB but only {room} MB is free after keeping {reserve_mb} MB for builds \
                 ({available_mb} MB available); stop other machines or free memory"
            );
        }
        Ok(())
    }
}
