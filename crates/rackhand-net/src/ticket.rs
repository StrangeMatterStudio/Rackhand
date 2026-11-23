//! The ticket an install or join command names a hub by (7.3.1): `rackhand1:<endpoint id hex>@<addr>,<addr>[!<relay>,<relay>]`.

use std::net::SocketAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ticket {
    pub hub_id: [u8; 32],
    pub addrs: Vec<SocketAddr>,
    pub relays: Vec<String>,
}

impl Ticket {
    pub fn parse(text: &str) -> Result<Ticket, String> {
        let rest = text.trim().strip_prefix("rackhand1:").ok_or("not a rackhand1 ticket")?;
        let (id, rest) = rest.split_once('@').unwrap_or((rest, ""));
        let (addrs, relays) = rest.split_once('!').unwrap_or((rest, ""));
        if id.len() != 64 {
            return Err("the ticket's hub id isn't 64 hex characters".into());
        }
        let mut hub_id = [0u8; 32];
        for (i, b) in hub_id.iter_mut().enumerate() {
            *b = u8::from_str_radix(&id[2 * i..2 * i + 2], 16).map_err(|_| "the ticket's hub id isn't hex")?;
        }
        let addrs = addrs
            .split(',')
            .filter(|a| !a.is_empty())
            .map(|a| a.parse().map_err(|_| format!("ticket address {a}")))
            .collect::<Result<_, _>>()?;
        let relays = relays.split(',').filter(|r| !r.is_empty()).map(str::to_string).collect();
        Ok(Ticket { hub_id, addrs, relays })
    }

    pub fn to_text(&self) -> String {
        let id: String = self.hub_id.iter().map(|b| format!("{b:02x}")).collect();
        let addrs: Vec<String> = self.addrs.iter().map(|a| a.to_string()).collect();
        let mut t = format!("rackhand1:{id}@{}", addrs.join(","));
        if !self.relays.is_empty() {
            t.push('!');
            t.push_str(&self.relays.join(","));
        }
        t
    }

    /// Where to dial the hub: its endpoint id with the ticket's direct addresses and relays.
    pub fn endpoint_addr(&self) -> Result<iroh::EndpointAddr, String> {
        let id = iroh::EndpointId::from_bytes(&self.hub_id).map_err(|e| format!("hub id: {e}"))?;
        let mut addr = iroh::EndpointAddr::new(id);
        for a in &self.addrs {
            addr.addrs.insert(iroh::TransportAddr::Ip(*a));
        }
        for r in &self.relays {
            addr.addrs.insert(iroh::TransportAddr::Relay(r.parse().map_err(|_| format!("relay {r}"))?));
        }
        Ok(addr)
    }
}
