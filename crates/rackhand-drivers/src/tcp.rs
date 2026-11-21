//! TCP checks: the port accepts a connection within the timeout. Target `host:port`.

use std::time::Instant;

use crate::driver::{Driver, DriverError, DriverKind, DriverReading, DriverTarget, millis, resolve, settings};

#[derive(Debug, Default)]
pub struct Tcp;

impl Tcp {
    pub fn new() -> Tcp {
        Tcp
    }
}

#[async_trait::async_trait]
impl Driver for Tcp {
    fn kind(&self) -> DriverKind {
        DriverKind::Tcp
    }

    async fn poll(&self, target: &DriverTarget) -> Result<DriverReading, DriverError> {
        settings(&target.settings, &[])?;
        let started = Instant::now();
        let addr = match resolve(&target.target).await {
            Ok(a) => a,
            Err(e) => return Ok(DriverReading::down(e, vec![])),
        };
        match tokio::time::timeout(target.timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok(DriverReading::up(millis(started), format!("{addr} accepts connections"), vec![])),
            Ok(Err(e)) => Ok(DriverReading::down(format!("{addr}: {e}"), vec![])),
            Err(_) => Ok(DriverReading::down(format!("{addr}: no answer within {:?}", target.timeout), vec![])),
        }
    }
}
