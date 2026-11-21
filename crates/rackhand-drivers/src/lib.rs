//! Agentless checks and API calls behind the `Driver` trait (design 7.2, Drivers): ICMP, TCP, HTTP(S), DNS and TLS
//! expiry for service checks (FR-9, FR-10); Proxmox, TrueNAS, Redfish and SNMP come in their own steps.

mod dns;
mod driver;
mod http;
mod icmp;
mod tcp;
mod tls;

pub use dns::Dns;
pub use driver::{Driver, DriverError, DriverKind, DriverOp, DriverOpResult, DriverReading, DriverTarget};
pub use http::Http;
pub use icmp::Icmp;
pub use tcp::Tcp;
pub use tls::Tls;

/// The driver for a service check of `kind`, or none for the API drivers.
pub fn check_driver(kind: DriverKind) -> Option<Box<dyn Driver>> {
    match kind {
        DriverKind::Icmp => Some(Box::new(Icmp::new())),
        DriverKind::Tcp => Some(Box::new(Tcp::new())),
        DriverKind::Http => Some(Box::new(Http::new())),
        DriverKind::Dns => Some(Box::new(Dns::new())),
        DriverKind::Tls => Some(Box::new(Tls::new())),
        _ => None,
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod drivers;
