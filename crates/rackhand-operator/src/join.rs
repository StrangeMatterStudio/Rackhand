//! `rackhand operator join` (7.3.5, 7.3.12): the operator host's join to a hub with an invite. The hub registers the host's
//! endpoint id as an operator, and this host remembers the hub. The node key is the same for every hub it joins.

use prost::Message;
use rackhand_net::ticket::Ticket;
use rackhand_proto::common::RunnerInfo;
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{JoinError, JoinRequest, JoinResponse, OperatorJoin};

use crate::runner::Info;
use crate::state::{Dirs, Hub, save};

/// The endpoint of this host: its node key, no ALPN of its own to serve.
pub async fn endpoint(dirs: &Dirs, relays: Vec<String>) -> Result<iroh::Endpoint, String> {
    let key = rackhand_net::key::load_or_create(&dirs.node_key())
        .map_err(|e| format!("{}: {e}", dirs.node_key().display()))?;
    let relays = rackhand_net::relays::RelayConfig { relays, ..Default::default() };
    let config = rackhand_net::endpoint::EndpointConfig { relays, alpns: Vec::new(), bind: None };
    rackhand_net::endpoint::bind(key, &config).await.map_err(|e| e.to_string())
}

pub async fn join(dirs: &Dirs, ticket: &Ticket, invite: &str, name: &str, runners: &[Info]) -> Result<Hub, String> {
    let endpoint = endpoint(dirs, ticket.relays.clone()).await?;
    let request = JoinRequest {
        kind: Some(Req::Operator(OperatorJoin {
            invite_secret: invite.to_string(),
            operator_name: name.to_string(),
            runners: runners.iter().map(|r| RunnerInfo { name: r.name.clone(), version: r.version.clone() }).collect(),
        })),
    };
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
        Some(Resp::Operator(joined)) => {
            let hub = Hub {
                id: ticket.hub_id.iter().map(|b| format!("{b:02x}")).collect(),
                site: joined.hub_site,
                addrs: ticket.addrs.iter().map(|a| a.to_string()).collect(),
                relays: ticket.relays.clone(),
            };
            save(dirs, hub.clone())?;
            Ok(hub)
        }
        Some(Resp::Error(f)) => {
            let code = JoinError::try_from(f.code).map(|c| c.as_str_name()).unwrap_or("JOIN_ERROR_UNSPECIFIED");
            Err(format!("the hub refused the join ({code}): {}", f.message))
        }
        _ => Err("the hub answered something other than an operator join".into()),
    }
}
