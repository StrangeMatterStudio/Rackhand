//! Making a link between two hubs (7.3.4, 7.3.1): the invite, the join the second hub makes, and the summaries each side then
//! pushes, over real endpoints and a relay in this process.

#![allow(clippy::unwrap_used)]

use std::sync::Arc;

use iroh::Endpoint;
use rackhand_hub::actions::Actions;
use rackhand_hub::actions::runner::{BoxFuture, StepCtx, StepOutcome, StepResult, StepRunner};
use rackhand_hub::audit::Audit;
use rackhand_hub::bus::Bus;
use rackhand_hub::ingest::{DiskSpace, Ingest};
use rackhand_hub::peers::tunnel::Network;
use rackhand_hub::peers::{PeerState, Peers};
use rackhand_hub::registry::Registry;
use rackhand_hub::registry::join_server::{HubInfo, JoinServer, ManagedSetupSource};
use rackhand_net::registry::{Admission, Registry as _};
use rackhand_net::router::{Router, handler};
use rackhand_net::ticket::Ticket;
use rackhand_proto::alpn;
use rackhand_proto::common::ProbeConfig;
use rackhand_proto::join::ManagedSetup;
use rackhand_runbook::runbook::Step;
use rackhand_store::ids::now_ms;
use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

fn t(s: &str) -> Value {
    Value::Text(s.into())
}

#[derive(Debug)]
struct Works;

impl StepRunner for Works {
    fn run<'a>(&'a self, _c: &'a StepCtx, _s: &'a Step, _a: Option<&'a [String]>) -> BoxFuture<'a, StepResult> {
        Box::pin(async {
            StepResult {
                outcome: StepOutcome::Succeeded,
                command: None,
                exit_code: Some(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            }
        })
    }
}

#[derive(Debug)]
struct Roomy;

impl DiskSpace for Roomy {
    fn free_fraction(&self) -> f64 {
        0.5
    }
}

struct NoSetup;

impl ManagedSetupSource for NoSetup {
    fn managed_setup(&self, _machine_id: ulid::Ulid, _with_assistant: bool) -> ManagedSetup {
        ManagedSetup::default()
    }
}

/// One hub: its database, registry, peers and the endpoint that serves the peer and join protocols.
struct Hub {
    db: Arc<Db>,
    registry: Arc<Registry>,
    peers: Peers,
    endpoint: Endpoint,
    relay: iroh::RelayUrl,
}

async fn hub(name: &str, site: &str, relay: &iroh::RelayUrl) -> Hub {
    let dir = std::env::temp_dir().join(format!("rackhand-link-{name}-{site}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    serve(db, site, relay).await
}

/// A hub on a database that already exists (a restart).
async fn serve(db: Arc<Db>, site: &str, relay: &iroh::RelayUrl) -> Hub {
    let known: i64 =
        db.readers().with(|c| c.query_row("SELECT count(*) FROM sites WHERE name = ?1", [site], |r| r.get(0))).unwrap();
    if known == 0 {
        db.writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::insert(
                    "sites",
                    Row::from([
                        ("id", t(&format!("01J{site}SITE00000000000000"))),
                        ("name", t(site)),
                        ("timezone", t("UTC")),
                        ("is_local", Value::Integer(1)),
                    ]),
                ),
                RowWrite::insert(
                    "users",
                    Row::from([
                        ("id", t("01JUSER0000000000000000000")),
                        ("name", t("admin")),
                        ("role", t("admin")),
                        ("created_at", Value::Integer(0)),
                    ]),
                ),
            ]))
            .await
            .unwrap();
    }
    let audit = Audit::new(db.writer());
    let _ = audit.append("admin", "test", None, "{}").await;
    let bus = Bus::new();
    let actions = Actions::new(db.clone(), audit.clone(), bus.clone(), Arc::new(Works));
    let ingest = Ingest::new(db.clone(), bus.clone(), Arc::new(Roomy));
    let registry = Registry::load(db.clone()).unwrap();
    let endpoint = rackhand_net::testing::endpoint(relay, &[alpn::PEER, alpn::JOIN]).await;
    let network = Arc::new(Network::new(endpoint.clone(), vec![relay.clone()]));
    let peers = Peers::new(db.clone(), audit, actions, ingest, site, "0.1.0")
        .with_registry(registry.clone())
        .with_network(network);
    peers.clone().spawn(bus.subscribe("peers"));
    let info = HubInfo {
        site: site.into(),
        version: "0.1.0".into(),
        relays: vec![relay.to_string()],
        hub_addrs: Vec::new(),
        probe_config: ProbeConfig::default(),
    };
    let (join, _joined) = JoinServer::new(registry.clone(), Arc::new(NoSetup), info);
    let router = Router::new(endpoint.clone(), registry.clone())
        .route(alpn::PEER, peers.handler())
        .route(alpn::JOIN, handler(move |conn| join.clone().serve(conn)));
    tokio::spawn(router.serve());
    Hub { db, registry, peers, endpoint, relay: relay.clone() }
}

impl Hub {
    /// What the other hub's Peers page tells its admin to paste: this hub's ticket and a fresh invite secret.
    async fn invite(&self) -> String {
        let token = self.registry.invite_peer("admin", now_ms()).await.unwrap();
        let ticket =
            Ticket { hub_id: *self.endpoint.id().as_bytes(), addrs: Vec::new(), relays: vec![self.relay.to_string()] };
        format!("{}#{}", ticket.to_text(), token.as_str())
    }

    fn admits(&self, other: &Hub) -> Admission {
        self.registry.admission(alpn::PEER, &other.endpoint.id())
    }
}

async fn two(name: &str) -> (Hub, Hub, iroh_relay::server::Server) {
    let (relay, url) = rackhand_net::testing::local_relay().await;
    let alpha = hub(name, "alpha", &url).await;
    let beta = hub(name, "beta", &url).await;
    (alpha, beta, relay)
}

async fn eventually<F: Fn() -> bool>(what: &str, check: F) {
    for _ in 0..100 {
        if check() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("{what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn joining_with_an_invite_links_both_hubs_and_survives_a_restart() {
    let (alpha, beta, _relay) = two("join").await;
    let linked = beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    assert_eq!(linked.site, "alpha");
    assert_eq!(linked.endpoint_id, alpha.endpoint.id().to_string());
    assert_eq!(linked.relays, [alpha.relay.to_string()], "the inviter's relays are kept for dialing it again");
    // each hub lists the other, and each admits the other for the peer protocol
    assert_eq!(beta.peers.peers().iter().map(|p| p.site.as_str()).collect::<Vec<_>>(), ["alpha"]);
    assert_eq!(alpha.peers.peers().iter().map(|p| p.site.as_str()).collect::<Vec<_>>(), ["beta"]);
    assert_eq!(alpha.peers.peers()[0].relays, [beta.relay.to_string()], "the joiner's relays reach the inviter's row");
    assert_eq!(beta.admits(&alpha), Admission::Allowed);
    assert_eq!(alpha.admits(&beta), Admission::Allowed);
    // a restart reads the same from the database
    let again = Registry::load(beta.db.clone()).unwrap();
    assert_eq!(again.admission(alpn::PEER, &alpha.endpoint.id()), Admission::Allowed);
}

#[tokio::test(flavor = "multi_thread")]
async fn summaries_flow_both_ways_after_the_link() {
    let (alpha, beta, _relay) = two("flow").await;
    beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    let (a_row, b_row) = (alpha.peers.peers().remove(0), beta.peers.peers().remove(0));
    // the joiner pushed at once, and the inviter reaches the joiner without its address
    eventually("alpha heard from beta", || alpha.peers.latest_summary(&a_row.id).is_some()).await;
    let pushed = alpha.peers.push().await;
    assert_eq!(pushed.len(), 1);
    assert!(pushed[0].1.is_ok(), "{:?}", pushed[0]);
    eventually("beta heard from alpha", || beta.peers.latest_summary(&b_row.id).is_some()).await;
    let (_, summary) = beta.peers.latest_summary(&b_row.id).unwrap();
    assert_eq!(summary.site, "alpha");
    let now = now_ms();
    assert_eq!(alpha.peers.states(now)[0].1, PeerState::Ok);
    assert_eq!(beta.peers.states(now)[0].1, PeerState::Ok);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_used_invite_a_known_site_and_a_stranger_link_nothing() {
    let (alpha, beta, _relay) = two("refused").await;
    let invite = alpha.invite().await;
    beta.peers.join(&invite, "admin").await.unwrap();
    // the same invite again: the inviter refuses it, and the second hub has still only the one peer
    let gamma = hub("refused", "gamma", &alpha.relay).await;
    let err = gamma.peers.join(&invite, "admin").await.unwrap_err();
    assert!(err.contains("refused"), "{err}");
    assert!(gamma.peers.peers().is_empty());
    // a site name that is already known on the joining hub
    let delta = hub("refused", "beta", &alpha.relay).await;
    let err = delta.peers.join(&alpha.invite().await, "admin").await.unwrap_err();
    assert!(err.contains("site_name_taken") || err.contains("already known"), "{err}");
    assert!(delta.peers.peers().is_empty());
    // not an invite at all
    assert!(gamma.peers.join("nonsense", "admin").await.is_err());
    assert!(gamma.peers.join("rackhand1:00#x", "admin").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_peer_that_cannot_be_reached_is_reported_and_the_others_still_get_theirs() {
    let (alpha, beta, _relay) = two("down").await;
    beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    let gamma = hub("down", "gamma", &alpha.relay).await;
    gamma.peers.join(&alpha.invite().await, "admin").await.unwrap();
    // gamma goes away; beta stays
    gamma.endpoint.close().await;
    let pushed = tokio::time::timeout(std::time::Duration::from_secs(60), alpha.peers.push()).await.unwrap();
    assert_eq!(pushed.len(), 2);
    let by_site = |s: &str| pushed.iter().find(|p| p.0 == s).unwrap().1.clone();
    assert!(by_site("beta").is_ok());
    assert!(by_site("gamma").is_err());
    eventually("beta heard from alpha", || beta.peers.latest_summary(&beta.peers.peers()[0].id).is_some()).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_hub_with_a_name_this_hub_already_knows_is_not_linked() {
    let (alpha, beta, _relay) = two("twin").await;
    beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    // another hub that calls itself `alpha`: the inviter accepts the join, but beta already has an `alpha`
    let twin = hub("twin-b", "alpha", &alpha.relay).await;
    let err = beta.peers.join(&twin.invite().await, "admin").await.unwrap_err();
    assert!(err.contains("already known"), "{err}");
    let peers = beta.peers.peers();
    assert_eq!(peers.len(), 1);
    assert_eq!(peers[0].endpoint_id, alpha.endpoint.id().to_string(), "the first alpha is still the one");
}

#[tokio::test(flavor = "multi_thread")]
async fn unlinking_tells_the_peer_and_both_hubs_forget() {
    use rackhand_hub::peers::PeerReach;
    let (alpha, beta, _relay) = two("unlink").await;
    beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    let row = alpha.peers.peers().remove(0);
    eventually("alpha heard from beta", || alpha.peers.latest_summary(&row.id).is_some()).await;
    PeerReach::unlink(&alpha.peers, &row.id, "admin").await.unwrap();
    assert!(alpha.peers.peers().is_empty());
    eventually("beta forgot alpha", || beta.peers.peers().is_empty()).await;
    assert_eq!(alpha.admits(&beta), Admission::Revoked);
    assert_eq!(beta.admits(&alpha), Admission::Revoked);
    assert!(PeerReach::unlink(&alpha.peers, "nobody", "admin").await.is_err());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_request_for_a_peers_machine_gets_the_owners_answer_and_the_path_is_known() {
    use rackhand_hub::peers::PeerReach;
    use rackhand_proto::peer::{ActionRequest, action_request_status};
    let (alpha, beta, _relay) = two("ask").await;
    beta.peers.join(&alpha.invite().await, "admin").await.unwrap();
    let row = alpha.peers.peers().remove(0);
    eventually("alpha heard from beta", || alpha.peers.latest_summary(&row.id).is_some()).await;
    // beta has no such runbook, and says so on the request's own stream
    let request = ActionRequest {
        request_id: ulid::Ulid::new().to_bytes().to_vec(),
        requested_by: "admin@alpha".into(),
        runbook: "nope".into(),
        target: ulid::Ulid::new().to_bytes().to_vec(),
        params: Default::default(),
        reason: "test".into(),
    };
    let first = PeerReach::request(&alpha.peers, &row.id, &request).await.unwrap();
    assert!(matches!(first.status, Some(action_request_status::Status::Rejected(_))), "{first:?}");
    assert!(PeerReach::request(&alpha.peers, "nobody", &request).await.is_err());
    // the path to a peer that is connected is direct or through the relay, never unreachable
    let path = PeerReach::path(&alpha.peers, &row.id);
    assert!(["direct", "via relay"].contains(&path.label), "{}", path.label);
    assert_eq!(PeerReach::path(&alpha.peers, "nobody").label, "unreachable: no path");
}
