//! The `rackhand/join/1` contract (7.3.1, 7.3.12) between real endpoints, with the hub's Registry and join server.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use iroh::Endpoint;
use iroh::endpoint::Connection;
use prost::Message;
use rackhand_hub::registry::Registry;
use rackhand_hub::registry::join_server::{HubInfo, JoinServer, Joined, ManagedSetupSource};
use rackhand_hub::registry::machines::AddMachine;
use rackhand_hub::registry::tokens::{Token, TokenKind};
use rackhand_net::registry::{Admission, Registry as _};
use rackhand_net::router::{Router, handler};
use rackhand_net::testing::{endpoint, local_relay};
use rackhand_proto::common::{Access, HostFacts, ProbeConfig, ProbeMode, RelayUrl, RunnerInfo, SemVer, SshHostKey};
use rackhand_proto::frame;
use rackhand_proto::join::join_request::Kind as Req;
use rackhand_proto::join::join_response::Kind as Resp;
use rackhand_proto::join::{
    DeviceJoin, JoinError, JoinRequest, JoinResponse, MachineJoin, MachineJoined, ManagedSetup, OperatorJoin, PeerJoin,
};
use rackhand_proto::{alpn, signed};
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, RegistryChange, RowUpdate, RowWrite, WriteCmd};
use rusqlite::types::Value;
use tokio::sync::mpsc::UnboundedReceiver;

const SITE_ID: &str = "01JSITE0000000000000000000";
const USER_ID: &str = "01JUSER0000000000000000000";
const MIN: i64 = 60_000;

/// The keys, sudoers and command list come from the SSH system and the command lists (T51, T53); here, fixed values
/// with a command list really signed by the hub key.
struct FixedSetup {
    key: SigningKey,
}

impl ManagedSetupSource for FixedSetup {
    fn managed_setup(&self, _machine_id: ulid::Ulid, with_assistant: bool) -> ManagedSetup {
        ManagedSetup {
            automation_pubkey: "ssh-ed25519 AAAAautomation rackhand".into(),
            assistant_pubkey: with_assistant.then(|| "ssh-ed25519 AAAAassistant rackhand-ai".into()),
            sudoers: "rackhand ALL=(root) NOPASSWD: /usr/local/libexec/rackhand-run\n".into(),
            commands: Some(signed::sign(&self.key, "commands", 1, now_ms(), now_ms() + 60 * MIN, b"{\"commands\":[]}")),
        }
    }
}

struct Hub {
    db: Arc<Db>,
    registry: Arc<Registry>,
    server: Arc<JoinServer>,
    joined: UnboundedReceiver<Joined>,
    endpoint: Endpoint,
    relay_url: iroh::RelayUrl,
    key: SigningKey,
    _relay: iroh_relay::server::Server,
}

fn row(cols: &[(&'static str, Value)]) -> rackhand_store::Row {
    cols.iter().cloned().collect()
}

async fn hub(name: &str) -> Hub {
    let dir = std::env::temp_dir().join(format!("rackhand-join-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    db.writer()
        .send(WriteCmd::Batch(vec![
            RowWrite::insert(
                "sites",
                row(&[
                    ("id", Value::Text(SITE_ID.into())),
                    ("name", Value::Text("home".into())),
                    ("timezone", Value::Text("Europe/Berlin".into())),
                    ("is_local", Value::Integer(1)),
                ]),
            ),
            RowWrite::insert(
                "users",
                row(&[
                    ("id", Value::Text(USER_ID.into())),
                    ("name", Value::Text("admin".into())),
                    ("role", Value::Text("admin".into())),
                    ("created_at", Value::Integer(0)),
                ]),
            ),
        ]))
        .await
        .unwrap();
    let registry = Registry::load(db.clone()).unwrap();
    let key = SigningKey::from_bytes(&[7u8; 32]);
    let info = HubInfo {
        site: "home".into(),
        version: "0.1.0".into(),
        relays: vec!["https://relay.example.net".into()],
        hub_addrs: vec!["192.0.2.10:7843".into()],
        probe_config: ProbeConfig { interval_s: 15, buffer_max_mb: 64, ..ProbeConfig::default() },
    };
    let (server, joined) = JoinServer::new(registry.clone(), Arc::new(FixedSetup { key: key.clone() }), info);
    let (relay, relay_url) = local_relay().await;
    let ep = endpoint(&relay_url, &[alpn::JOIN, alpn::PROBE, alpn::TUNNEL]).await;
    let s = server.clone();
    let router = Router::new(ep.clone(), registry.clone())
        .route(alpn::JOIN, handler(move |conn| s.clone().serve(conn)))
        .route(alpn::PROBE, handler(echo))
        .route(alpn::TUNNEL, handler(echo));
    tokio::spawn(router.serve());
    Hub { db, registry, server, joined, endpoint: ep, relay_url, key, _relay: relay }
}

async fn echo(conn: Connection) {
    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
        if let Ok(data) = recv.read_to_end(1 << 16).await {
            let _ = send.write_all(&data).await;
            let _ = send.finish();
        }
    }
}

impl Hub {
    fn addr(&self) -> iroh::EndpointAddr {
        let mut addr = self.endpoint.addr();
        addr.addrs.insert(iroh::TransportAddr::Relay(self.relay_url.clone()));
        addr
    }

    async fn client(&self) -> Endpoint {
        endpoint(&self.relay_url, &[]).await
    }

    /// One join over QUIC from `client`.
    async fn join(&self, client: &Endpoint, req: Req) -> Resp {
        let conn = client.connect(self.addr(), alpn::JOIN).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&frame::encode(&JoinRequest { kind: Some(req) }).unwrap()).await.unwrap();
        send.finish().unwrap();
        let data = tokio::time::timeout(Duration::from_secs(20), recv.read_to_end(1 << 20)).await.unwrap().unwrap();
        conn.close(0u32.into(), b"done");
        let body = frame::read_frame(&mut data.as_slice()).unwrap();
        JoinResponse::decode(body.as_slice()).unwrap().kind.unwrap()
    }

    async fn add_machine(&self, name: &str, access: Access, roles: &[&str]) -> (ulid::Ulid, Token) {
        let add = AddMachine {
            site_id: SITE_ID.into(),
            name: name.into(),
            kind: "linux".into(),
            access,
            mode: ProbeMode::Local,
            roles: roles.iter().map(|r| r.to_string()).collect(),
        };
        self.registry.add_machine(&add, "admin", now_ms()).await.unwrap()
    }

    fn query(&self, sql: &str) -> Vec<String> {
        self.db
            .readers()
            .with(|c| {
                let mut stmt = c.prepare(sql)?;
                let rows = stmt.query_map([], |r| r.get::<_, Option<String>>(0))?;
                rows.map(|r| r.map(|v| v.unwrap_or_default())).collect()
            })
            .unwrap()
    }
}

fn facts(role: &str) -> HostFacts {
    HostFacts {
        hostname: "web1".into(),
        os_name: "debian".into(),
        os_version: "12".into(),
        kernel: "6.1.0".into(),
        arch: "x86_64".into(),
        machine_role: role.into(),
        interfaces: vec![],
    }
}

fn host_keys() -> Vec<SshHostKey> {
    vec![SshHostKey { algorithm: "ssh-ed25519".into(), public_key: "AAAAhostkey".into() }]
}

fn machine_req(token: &Token, access: Access) -> Req {
    Req::Machine(MachineJoin {
        token: token.as_str().into(),
        facts: Some(facts("")),
        ssh_host_keys: host_keys(),
        mode: ProbeMode::Local as i32,
        access: access as i32,
    })
}

fn joined(resp: Resp) -> MachineJoined {
    match resp {
        Resp::Machine(m) => m,
        other => panic!("expected a machine join, got {other:?}"),
    }
}

fn error(resp: Resp) -> JoinError {
    match resp {
        Resp::Error(e) => JoinError::try_from(e.code).unwrap(),
        other => panic!("expected an error, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_managed_join_returns_managed_setup() {
    let mut hub = hub("managed").await;
    let (id, token) = hub.add_machine("web1", Access::Managed, &[]).await;
    let client = hub.client().await;
    let m = joined(hub.join(&client, machine_req(&token, Access::Managed)).await);
    assert_eq!(m.machine_id, id.to_bytes().to_vec());
    assert_eq!(m.access, Access::Managed as i32);
    assert_eq!(m.config.unwrap().interval_s, 15);
    assert_eq!(m.hub_addrs, ["192.0.2.10:7843"]);
    let setup = m.managed.expect("managed setup");
    assert!(setup.automation_pubkey.starts_with("ssh-ed25519 "));
    assert!(setup.assistant_pubkey.is_some());
    assert!(setup.sudoers.contains("rackhand"));
    let commands = setup.commands.unwrap();
    signed::verify(&commands, &hub.key.verifying_key(), "commands", 0, now_ms()).expect("hub-signed command list");
    let event = hub.joined.recv().await.unwrap();
    assert_eq!((event.kind, event.endpoint_id), (TokenKind::Machine, client.id()));
    assert_eq!(event.ssh_host_keys, host_keys(), "host keys go to the SSH system");
    assert_eq!(
        hub.query(&format!("SELECT state || ' ' || probe_endpoint_id FROM machines WHERE id = '{id}'")),
        [format!("enrolled {}", client.id())]
    );
    assert_eq!(hub.registry.admission(alpn::PROBE, &client.id()), Admission::Allowed);
}

#[tokio::test(flavor = "multi_thread")]
async fn machine_monitor_join_has_no_managed_setup_or_host_keys() {
    let mut hub = hub("monitor").await;
    let (_, token) = hub.add_machine("cam", Access::Monitor, &[]).await;
    let m = joined(hub.join(&hub.client().await, machine_req(&token, Access::Monitor)).await);
    assert_eq!(m.access, Access::Monitor as i32);
    assert!(m.managed.is_none(), "monitor gets no accounts");
    assert!(hub.joined.recv().await.unwrap().ssh_host_keys.is_empty(), "the hub keeps no host keys for monitor");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_hub_gets_no_assistant_key() {
    let hub = hub("role-hub").await;
    let (_, token) = hub.add_machine("hub", Access::Managed, &["hub"]).await;
    let m = joined(hub.join(&hub.client().await, machine_req(&token, Access::Managed)).await);
    assert!(m.managed.unwrap().assistant_pubkey.is_none());
    // The role comes from the token, not from what the machine says about itself.
    let (_, token) = hub.add_machine("other", Access::Managed, &[]).await;
    let mut req = machine_req(&token, Access::Managed);
    if let Req::Machine(m) = &mut req {
        m.facts = Some(facts("hub"));
    }
    assert!(joined(hub.join(&hub.client().await, req).await).managed.unwrap().assistant_pubkey.is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn access_mismatch_fails_invalid() {
    let hub = hub("mismatch").await;
    let (_, token) = hub.add_machine("web1", Access::Managed, &[]).await;
    let client = hub.client().await;
    assert_eq!(error(hub.join(&client, machine_req(&token, Access::Monitor)).await), JoinError::Invalid);
    assert_eq!(hub.registry.admission(alpn::PROBE, &client.id()), Admission::Unknown);
    // The token wasn't used up.
    joined(hub.join(&client, machine_req(&token, Access::Managed)).await);
}

#[tokio::test(flavor = "multi_thread")]
async fn used_expired_and_wrong_kind_tokens_refused() {
    let hub = hub("refused").await;
    let client = hub.client().await;
    let (_, token) = hub.add_machine("web1", Access::Managed, &[]).await;
    joined(hub.join(&client, machine_req(&token, Access::Managed)).await);
    assert_eq!(error(hub.join(&client, machine_req(&token, Access::Managed)).await), JoinError::Used);

    let add = AddMachine {
        site_id: SITE_ID.into(),
        name: "old".into(),
        kind: "linux".into(),
        access: Access::Managed,
        mode: ProbeMode::Local,
        roles: vec![],
    };
    let (_, old) = hub.registry.add_machine(&add, "admin", now_ms() - 61 * MIN).await.unwrap();
    assert_eq!(error(hub.join(&client, machine_req(&old, Access::Managed)).await), JoinError::Expired);

    let invite = hub.registry.invite_device(USER_ID, "admin", now_ms()).await.unwrap();
    assert_eq!(error(hub.join(&client, machine_req(&invite, Access::Managed)).await), JoinError::WrongKind);
    let unknown = Token::parse("0000000000000000000000000");
    assert_eq!(error(hub.join(&client, machine_req(&unknown, Access::Managed)).await), JoinError::Invalid);

    // Two joins racing with one token: exactly one succeeds.
    let (_, token) = hub.add_machine("race", Access::Managed, &[]).await;
    let (a, b) = (hub.client().await, hub.client().await);
    let (ra, rb) = tokio::join!(
        hub.server.handle(
            JoinRequest { kind: Some(machine_req(&token, Access::Managed)) },
            a.id(),
            "ip:203.0.113.1",
            now_ms()
        ),
        hub.server.handle(
            JoinRequest { kind: Some(machine_req(&token, Access::Managed)) },
            b.id(),
            "ip:203.0.113.2",
            now_ms()
        ),
    );
    let mut kinds: Vec<String> = [ra, rb]
        .into_iter()
        .map(|r| match r.kind.unwrap() {
            Resp::Machine(_) => "joined".to_string(),
            Resp::Error(e) => format!("{:?}", JoinError::try_from(e.code).unwrap()),
            other => format!("{other:?}"),
        })
        .collect();
    kinds.sort();
    assert_eq!(kinds, ["Used", "joined"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn device_operator_and_peer_invites_join() {
    let hub = hub("invites").await;
    let device = hub.client().await;
    let invite = hub.registry.invite_device(USER_ID, "admin", now_ms()).await.unwrap();
    let resp = hub
        .join(&device, Req::Device(DeviceJoin { invite_secret: invite.as_str().into(), device_name: "laptop".into() }))
        .await;
    let Resp::Device(d) = resp else { panic!("{resp:?}") };
    assert_eq!((d.user.as_str(), d.hub_site.as_str()), ("admin", "home"));
    for a in [alpn::TUNNEL, alpn::XFER] {
        assert_eq!(hub.registry.admission(a, &device.id()), Admission::Allowed);
    }
    assert_eq!(hub.registry.admission(alpn::PROBE, &device.id()), Admission::Unknown);
    // Registered for real: the router serves the device on its ALPN.
    let conn = device.connect(hub.addr(), alpn::TUNNEL).await.unwrap();
    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello").await.unwrap();
    send.finish().unwrap();
    assert_eq!(recv.read_to_end(64).await.unwrap(), b"hello");

    let operator = hub.client().await;
    let invite = hub.registry.invite_operator("admin", now_ms()).await.unwrap();
    let resp = hub
        .join(
            &operator,
            Req::Operator(OperatorJoin {
                invite_secret: invite.as_str().into(),
                operator_name: "op1".into(),
                runners: vec![RunnerInfo { name: "claude".into(), version: "2.0".into() }],
            }),
        )
        .await;
    let Resp::Operator(o) = resp else { panic!("{resp:?}") };
    assert_eq!(o.hub_site, "home");
    for a in [alpn::OPERATOR, alpn::MCP] {
        assert_eq!(hub.registry.admission(a, &operator.id()), Admission::Allowed);
    }

    let peer = hub.client().await;
    let invite = hub.registry.invite_peer("admin", now_ms()).await.unwrap();
    let resp = hub.join(&peer, peer_req(&invite, "lab-b")).await;
    let Resp::Peer(p) = resp else { panic!("{resp:?}") };
    assert_eq!((p.site.as_str(), p.hub_version.unwrap().version.as_str()), ("home", "0.1.0"));
    assert_eq!(p.relays, [RelayUrl { url: "https://relay.example.net".into() }]);
    for a in [alpn::PEER, alpn::XFER] {
        assert_eq!(hub.registry.admission(a, &peer.id()), Admission::Allowed);
    }
    assert_eq!(hub.query("SELECT site FROM peers"), ["lab-b"]);
}

fn peer_req(invite: &Token, site: &str) -> Req {
    Req::Peer(PeerJoin {
        invite_secret: invite.as_str().into(),
        site: site.into(),
        hub_version: Some(SemVer { version: "0.1.0".into() }),
        relays: vec![],
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_with_known_site_name_fails() {
    let hub = hub("peer-name").await;
    let invite = hub.registry.invite_peer("admin", now_ms()).await.unwrap();
    assert_eq!(
        error(hub.join(&hub.client().await, peer_req(&invite, "home")).await),
        JoinError::SiteNameTaken,
        "the local site"
    );
    let Resp::Peer(_) = hub.join(&hub.client().await, peer_req(&invite, "lab-b")).await else { panic!() };
    let again = hub.registry.invite_peer("admin", now_ms()).await.unwrap();
    assert_eq!(
        error(hub.join(&hub.client().await, peer_req(&again, "lab-b")).await),
        JoinError::SiteNameTaken,
        "a known peer"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn eleven_failures_per_minute_rate_limited() {
    let hub = hub("rate").await;
    let caller = hub.client().await.id();
    let bad = || JoinRequest { kind: Some(machine_req(&Token::parse("1111111111111111111111111"), Access::Managed)) };
    let code = |r: JoinResponse| match r.kind.unwrap() {
        Resp::Error(e) => JoinError::try_from(e.code).unwrap(),
        other => panic!("{other:?}"),
    };
    let t0 = now_ms();
    for i in 0..10 {
        assert_eq!(
            code(hub.server.handle(bad(), caller, "ip:203.0.113.9", t0 + i).await),
            JoinError::Invalid,
            "failure {i}"
        );
    }
    assert_eq!(code(hub.server.handle(bad(), caller, "ip:203.0.113.9", t0 + 10).await), JoinError::RateLimited);
    // Even a good token waits while the address is limited.
    let (_, token) = hub.add_machine("web1", Access::Managed, &[]).await;
    let good = JoinRequest { kind: Some(machine_req(&token, Access::Managed)) };
    assert_eq!(code(hub.server.handle(good.clone(), caller, "ip:203.0.113.9", t0 + 20).await), JoinError::RateLimited);
    assert_eq!(
        code(hub.server.handle(bad(), caller, "ip:198.51.100.7", t0 + 20).await),
        JoinError::Invalid,
        "another address"
    );
    // A minute after the first failure, one slot is free again.
    let later = hub.server.handle(good, caller, "ip:203.0.113.9", t0 + MIN).await;
    assert!(matches!(later.kind, Some(Resp::Machine(_))), "{later:?}");
}

#[tokio::test(flavor = "multi_thread")]
async fn level_change_token_keeps_machine_id() {
    let hub = hub("level").await;
    let (id, token) = hub.add_machine("nas", Access::Monitor, &[]).await;
    let client = hub.client().await;
    joined(hub.join(&client, machine_req(&token, Access::Monitor)).await);
    // History and settings that must survive: a maintenance window and tags.
    hub.db
        .writer()
        .send(WriteCmd::Batch(vec![RowWrite::insert(
            "windows",
            row(&[
                ("id", Value::Text("w1".into())),
                ("machine_id", Value::Text(id.to_string())),
                ("rrule", Value::Text("daily 02:00 60m".into())),
                ("timezone", Value::Text("UTC".into())),
            ]),
        )]))
        .await
        .unwrap();
    let tags = RowUpdate {
        table: "machines",
        key: ("id", Value::Text(id.to_string())),
        set: row(&[("tags", Value::Text("[\"db\"]".into()))]),
    };
    hub.db
        .writer()
        .send(WriteCmd::RegistryChange(RegistryChange { updates: vec![tags], ..Default::default() }))
        .await
        .unwrap();

    let change = hub.registry.level_change_token(id, Access::Managed, "admin", now_ms()).await.unwrap();
    assert_eq!(
        error(hub.join(&client, machine_req(&change, Access::Monitor)).await),
        JoinError::Invalid,
        "bound to the new level"
    );
    let m = joined(hub.join(&client, machine_req(&change, Access::Managed)).await);
    assert_eq!(m.machine_id, id.to_bytes().to_vec(), "same machine id");
    assert!(m.managed.is_some());
    assert_eq!(
        hub.query(&format!("SELECT access || ' ' || tags || ' ' || state FROM machines WHERE id = '{id}'")),
        ["managed [\"db\"] enrolled"]
    );
    assert_eq!(hub.query("SELECT id FROM windows"), ["w1"]);
    assert_eq!(hub.query("SELECT CAST(count(*) AS TEXT) FROM machines"), ["1"]);
}
