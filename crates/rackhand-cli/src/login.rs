//! `rackhand-cli login <invite>` (7.3.1, D59): enrolls this computer as a device of a user on one hub. The invite from the
//! dashboard is `<ticket>#<secret>`; the device's key for that hub is made here and never leaves.

use prost::Message;
use rackhand_net::ticket::Ticket;
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{DeviceJoin, JoinError, JoinRequest, JoinResponse};

use crate::config::{self, Dirs, Hub};

/// The ticket and the secret of an invite.
pub fn parse_invite(invite: &str) -> Result<(Ticket, String), String> {
    let (ticket, secret) =
        invite.trim().split_once('#').ok_or("an invite is `<ticket>#<secret>`, as the dashboard shows it")?;
    if secret.is_empty() {
        return Err("the invite has no secret after the `#`".into());
    }
    Ok((Ticket::parse(ticket)?, secret.to_string()))
}

/// What this computer is called on the hub: `--name`, or its host name.
pub fn default_name() -> String {
    ["HOSTNAME", "COMPUTERNAME", "HOST"]
        .iter()
        .find_map(|v| std::env::var(v).ok().filter(|n| !n.is_empty()))
        .unwrap_or_else(|| "device".into())
}

pub async fn login(dirs: &Dirs, invite: &str, name: &str) -> Result<Hub, String> {
    let (ticket, secret) = parse_invite(invite)?;
    let hub_id: String = ticket.hub_id.iter().map(|b| format!("{b:02x}")).collect();
    let endpoint = config::endpoint(dirs, &hub_id, ticket.relays.clone()).await?;
    let request =
        JoinRequest { kind: Some(Req::Device(DeviceJoin { invite_secret: secret, device_name: name.to_string() })) };
    let conn = endpoint
        .connect(ticket.endpoint_addr()?, rackhand_proto::alpn::JOIN)
        .await
        .map_err(|e| format!("can't reach the hub: {e}"))?;
    let (mut send, mut recv) = conn.open_bi().await.map_err(|e| e.to_string())?;
    send.write_all(&frame::encode(&request).map_err(|e| e.to_string())?).await.map_err(|e| e.to_string())?;
    send.finish().map_err(|e| e.to_string())?;
    let data = recv.read_to_end(frame::MAX_FRAME + 4).await.map_err(|e| e.to_string())?;
    conn.close(0u32.into(), b"done");
    endpoint.close().await;
    let body = frame::read_frame(&mut data.as_slice()).map_err(|e| e.to_string())?;
    match JoinResponse::decode(body.as_slice()).map_err(|e| e.to_string())?.kind {
        Some(Resp::Device(joined)) => {
            let hub = Hub {
                id: hub_id,
                site: joined.hub_site,
                user: joined.user,
                addrs: ticket.addrs.iter().map(|a| a.to_string()).collect(),
                relays: ticket.relays.clone(),
            };
            config::save(dirs, hub.clone())?;
            Ok(hub)
        }
        Some(Resp::Error(f)) => {
            let code = JoinError::try_from(f.code).map(|c| c.as_str_name()).unwrap_or("JOIN_ERROR_UNSPECIFIED");
            Err(format!("the hub refused the login ({code}): {}", f.message))
        }
        _ => Err("the hub answered something other than a device login".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_invite_is_a_ticket_and_a_secret() {
        let id = "ab".repeat(32);
        let (ticket, secret) = parse_invite(&format!("rackhand1:{id}@192.0.2.1:7443#SECRET123")).unwrap();
        assert_eq!((ticket.addrs.len(), secret.as_str()), (1, "SECRET123"));
        for bad in [
            "",
            "SECRET",
            &format!("rackhand1:{id}@192.0.2.1:7443"),
            &format!("rackhand1:{id}@192.0.2.1:7443#"),
            "nope#x",
        ] {
            assert!(parse_invite(bad).is_err(), "{bad:?}");
        }
    }
}
