//! One deterministic sample of every message type, for the round-trip and golden tests.

use std::collections::BTreeMap;

use prost::Message;

use crate::common::*;
use crate::{join, operator as op, peer, probe, tunnel};

pub type Decode = Box<dyn Fn(&[u8]) -> bool>;

fn entry<M: Message + Default + PartialEq + 'static>(name: &'static str, msg: M) -> (&'static str, Vec<u8>, Decode) {
    let bytes = msg.encode_to_vec();
    (name, bytes, Box::new(move |b: &[u8]| M::decode(b).map(|d| d == msg).unwrap_or(false)))
}

fn id(n: u8) -> Vec<u8> {
    vec![n; 16]
}

fn ver(v: &str) -> Option<SemVer> {
    Some(SemVer { version: v.into() })
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
}

fn config() -> Option<ProbeConfig> {
    Some(ProbeConfig {
        interval_s: 15,
        max_connection_tuples: 500,
        per_core_cpu: false,
        extra_mount_excludes: vec!["/srv/scratch".into()],
        extra_iface_excludes: vec![],
        watched_services: vec!["nginx.service".into()],
        ebpf_enabled: true,
        hub_addrs: vec![],
        hub_relays: vec![],
        buffer_max_mb: 64,
        // 0: the default 200, so the golden encodings stay as they were (an additive field)
        series_cap: 0,
    })
}

fn facts() -> Option<HostFacts> {
    Some(HostFacts {
        hostname: "web-1".into(),
        os_name: "Debian GNU/Linux".into(),
        os_version: "12".into(),
        kernel: "6.1.0-28-amd64".into(),
        arch: "x86_64".into(),
        machine_role: String::new(),
        interfaces: vec![IfaceInfo {
            name: "eth0".into(),
            mac: "52:54:00:12:34:56".into(),
            addrs: vec!["192.0.2.20/24".into()],
        }],
    })
}

fn signed() -> Option<SignedPayload> {
    Some(SignedPayload { payload: vec![1, 2, 3], hub_signature: vec![9; 64] })
}

fn report() -> probe::Report {
    probe::Report {
        epoch: 7,
        seq: 42,
        sampled_at_ms: 1_800_000_000_000,
        vitals: vec![probe::Sample { metric: 1, labels_id: 0, value: 12.5 }],
        label_sets: vec![LabelEntry { id: 3, labels: labels(&[("mount", "/")]) }],
        services: vec![probe::ServiceState {
            name: "nginx.service".into(),
            status: probe::ServiceStatus::Active as i32,
            enabled: true,
            since_ms: 1,
        }],
        containers: vec![probe::ContainerState {
            id: "abc".into(),
            name: "db".into(),
            image: "postgres:16".into(),
            state: "running".into(),
            health: "healthy".into(),
            restart_count: 0,
            started_at_ms: 2,
            project: String::new(),
        }],
        updates: Some(probe::UpdateSummary {
            pending: 3,
            security: 1,
            reboot_required: false,
            packages: vec!["openssl".into()],
        }),
        events: vec![probe::ProbeEvent {
            kind: "exec_from_tmp".into(),
            at_ms: 3,
            fields: labels(&[("exe", "/tmp/x")]),
        }],
        connections: vec![probe::ConnRecord {
            container: String::new(),
            exe: "/usr/bin/curl".into(),
            dest_ip: vec![198, 51, 100, 7],
            dest_port: 443,
            proto: probe::Proto::Tcp as i32,
            count: 1,
            bytes: 1200,
            pid: 123,
            user: "root".into(),
            folded: false,
        }],
    }
}

pub fn all() -> Vec<(&'static str, Vec<u8>, Decode)> {
    use join::{join_request as jq, join_response as jr};
    use op::{hub_to_operator as ho, job_reply, operator_to_hub as oh};
    use probe::{hub_to_probe as hp, probe_to_hub as ph};
    vec![
        entry(
            "join_request_machine",
            join::JoinRequest {
                kind: Some(jq::Kind::Machine(join::MachineJoin {
                    token: "t0k3n".into(),
                    facts: facts(),
                    ssh_host_keys: vec![SshHostKey { algorithm: "ssh-ed25519".into(), public_key: "AAAA".into() }],
                    mode: ProbeMode::Local as i32,
                    access: Access::Managed as i32,
                })),
            },
        ),
        entry(
            "join_request_device",
            join::JoinRequest {
                kind: Some(jq::Kind::Device(join::DeviceJoin {
                    invite_secret: "s".into(),
                    device_name: "laptop".into(),
                })),
            },
        ),
        entry(
            "join_request_operator",
            join::JoinRequest {
                kind: Some(jq::Kind::Operator(join::OperatorJoin {
                    invite_secret: "s".into(),
                    operator_name: "op-1".into(),
                    runners: vec![RunnerInfo { name: "claude-code".into(), version: "2.1".into() }],
                })),
            },
        ),
        entry(
            "join_request_peer",
            join::JoinRequest {
                kind: Some(jq::Kind::Peer(join::PeerJoin {
                    invite_secret: "s".into(),
                    site: "b".into(),
                    hub_version: ver("0.1.0"),
                    relays: vec![RelayUrl { url: "https://relay.example.net".into() }],
                })),
            },
        ),
        entry(
            "join_response_machine",
            join::JoinResponse {
                kind: Some(jr::Kind::Machine(join::MachineJoined {
                    machine_id: id(1),
                    config: config(),
                    access: Access::Managed as i32,
                    managed: Some(join::ManagedSetup {
                        automation_pubkey: "ssh-ed25519 AAAA".into(),
                        assistant_pubkey: Some("ssh-ed25519 BBBB".into()),
                        sudoers: "rackhand ALL=(root) NOPASSWD: /usr/local/lib/rackhand/run".into(),
                        commands: signed(),
                    }),
                    hub_addrs: vec!["192.0.2.10:7843".into()],
                })),
            },
        ),
        entry(
            "join_response_device",
            join::JoinResponse {
                kind: Some(jr::Kind::Device(join::DeviceJoined { user: "owner".into(), hub_site: "a".into() })),
            },
        ),
        entry(
            "join_response_operator",
            join::JoinResponse { kind: Some(jr::Kind::Operator(join::OperatorJoined { hub_site: "a".into() })) },
        ),
        entry(
            "join_response_peer",
            join::JoinResponse {
                kind: Some(jr::Kind::Peer(join::PeerJoined {
                    site: "a".into(),
                    hub_version: ver("0.1.0"),
                    relays: vec![],
                })),
            },
        ),
        entry(
            "join_response_error",
            join::JoinResponse {
                kind: Some(jr::Kind::Error(join::JoinFailed {
                    code: join::JoinError::Expired as i32,
                    message: "token expired".into(),
                })),
            },
        ),
        entry(
            "probe_hello",
            probe::ProbeToHub {
                msg: Some(ph::Msg::Hello(probe::Hello {
                    probe_version: ver("0.1.0"),
                    machine_id: id(1),
                    epoch: 7,
                    os: Some(OsInfo {
                        name: "Debian".into(),
                        version: "12".into(),
                        kernel: "6.1".into(),
                        arch: "x86_64".into(),
                        systemd: true,
                    }),
                    boot_id: "b00t".into(),
                    capabilities: vec![probe::Capability::Ebpf as i32],
                    interfaces: vec![],
                    label_table: vec![LabelEntry { id: 0, labels: BTreeMap::new() }],
                })),
            },
        ),
        entry(
            "probe_data_dropped",
            probe::ProbeToHub {
                msg: Some(ph::Msg::DataDropped(probe::DataDropped { epoch: 7, from_seq: 10, to_seq: 20 })),
            },
        ),
        entry(
            "probe_welcome",
            probe::HubToProbe {
                msg: Some(hp::Msg::Welcome(probe::Welcome {
                    hub_version: ver("0.1.0"),
                    config: config(),
                    config_rev: 3,
                    received: Some(probe::EpochRanges { epoch: 7, ranges: vec![probe::SeqRange { from: 1, to: 41 }] }),
                    server_time_ms: 1_800_000_000_000,
                })),
            },
        ),
        entry(
            "probe_ack",
            probe::HubToProbe {
                msg: Some(hp::Msg::Ack(probe::Ack { epoch: 7, ranges: vec![probe::SeqRange { from: 1, to: 42 }] })),
            },
        ),
        entry(
            "probe_config_update",
            probe::HubToProbe {
                msg: Some(hp::Msg::ConfigUpdate(probe::ConfigUpdate { config: config(), config_rev: 4 })),
            },
        ),
        entry(
            "probe_update_available",
            probe::HubToProbe {
                msg: Some(hp::Msg::UpdateAvailable(probe::UpdateAvailable {
                    version: ver("0.1.1"),
                    url: "https://github.com/StrangeMatterStudio/Rackhand/releases/download/v0.1.1/rackhand-probe"
                        .into(),
                    sha256: vec![5; 32],
                    signature: vec![6; 74],
                })),
            },
        ),
        entry(
            "probe_keys_update",
            probe::HubToProbe { msg: Some(hp::Msg::KeysUpdate(probe::KeysUpdate { keys: signed() })) },
        ),
        entry("probe_report", report()),
        entry("probe_replay_batch", probe::ReplayBatch { reports: vec![report(), report()] }),
        entry("peer_hello", peer::PeerHello { site: "b".into(), hub_version: ver("0.1.0"), relays: vec![] }),
        entry(
            "peer_site_summary",
            peer::SiteSummary {
                site: "b".into(),
                generated_at_ms: 5,
                machines: vec![peer::MachineSummary {
                    id: id(2),
                    name: "nas".into(),
                    kind: "machine".into(),
                    health: peer::Health::Ok as i32,
                    last_seen_ms: 4,
                }],
                open_incidents: vec![peer::IncidentSummary {
                    id: id(3),
                    severity: "warning".into(),
                    title: "disk filling".into(),
                    machine_id: id(2),
                    opened_at_ms: 3,
                }],
                hub_health: Some(peer::HubHealth {
                    version: ver("0.1.0"),
                    db_ok: true,
                    disk_free_pct: 40.0,
                    operators_online: 1,
                    notifiers_ok: true,
                    self_check_ok: true,
                }),
                peers_seen: vec![peer::PeerSeen { site: "c".into(), last_heard_ms: 2 }],
                audit_head: vec![7; 32],
            },
        ),
        entry(
            "peer_query",
            peer::PeerQuery {
                kind: Some(peer::peer_query::Kind::Vitals(peer::VitalsQuery {
                    machine: id(2),
                    metric: "cpu.busy_pct".into(),
                    labels: Some(Labels { labels: BTreeMap::new() }),
                    from_ms: 0,
                    to_ms: 60_000,
                    step_s: 60,
                })),
            },
        ),
        entry(
            "peer_answer",
            peer::PeerAnswer {
                kind: Some(peer::peer_answer::Kind::Vitals(peer::Series {
                    points: vec![peer::Point { at_ms: 0, value: 1.5, min: Some(1.0), max: Some(2.0) }],
                })),
            },
        ),
        entry(
            "peer_action_request",
            peer::ActionRequest {
                request_id: id(4),
                requested_by: "owner@a".into(),
                runbook: "restart-service".into(),
                target: id(2),
                params: labels(&[("service", "nginx")]),
                reason: "down".into(),
            },
        ),
        entry(
            "peer_action_status",
            peer::ActionRequestStatus { status: Some(peer::action_request_status::Status::NeedsApproval(true)) },
        ),
        entry("peer_unlink", peer::PeerUnlink { reason: "removed".into() }),
        entry(
            "operator_hello",
            op::OperatorToHub {
                msg: Some(oh::Msg::Hello(op::OperatorHello {
                    operator_version: ver("0.1.0"),
                    runners: vec![RunnerInfo { name: "claude-code".into(), version: "2.1".into() }],
                    max_jobs: 2,
                    running: vec![],
                })),
            },
        ),
        entry(
            "operator_reply",
            op::OperatorToHub {
                msg: Some(oh::Msg::Reply(op::JobReply { reply: Some(job_reply::Reply::Accepted(true)) })),
            },
        ),
        entry(
            "operator_event",
            op::OperatorToHub {
                msg: Some(oh::Msg::Event(op::JobEvent {
                    job_id: id(5),
                    at_ms: 1,
                    kind: op::JobEventKind::ToolCall as i32,
                    text: "run_diagnostic".into(),
                })),
            },
        ),
        entry(
            "operator_done",
            op::OperatorToHub {
                msg: Some(oh::Msg::Done(op::JobDone {
                    job_id: id(5),
                    outcome: op::Outcome::Resolved as i32,
                    summary: "restarted".into(),
                })),
            },
        ),
        entry(
            "operator_offer",
            op::HubToOperator {
                msg: Some(ho::Msg::Offer(op::JobOffer {
                    job_id: id(5),
                    incident_id: id(3),
                    playbook: "service-down".into(),
                    playbook_rev: 1,
                    brief_markdown: "# Brief".into(),
                    allowed_tools: vec!["run_diagnostic".into()],
                    autonomy: 1,
                    hosts: vec![id(2)],
                    deadline_ms: 1_800_000_000_000,
                    max_turns: 60,
                    job_token: "jt".into(),
                })),
            },
        ),
        entry(
            "operator_cancel",
            op::HubToOperator {
                msg: Some(ho::Msg::Cancel(op::JobCancel { job_id: id(5), reason: "incident resolved".into() })),
            },
        ),
        entry("tunnel_open", tunnel::TunnelOpen { target: id(2), port: 22, purpose: "ssh".into() }),
        entry(
            "tunnel_reply",
            tunnel::TunnelReply {
                reply: Some(tunnel::tunnel_reply::Reply::Error(tunnel::TunnelError::PortNotAllowed as i32)),
            },
        ),
        entry(
            "xfer_offer",
            tunnel::XferOffer {
                transfer_id: id(6),
                kind: tunnel::XferKind::File as i32,
                blake3: vec![8; 32],
                size: 5 << 30,
                chunk_size: 1 << 20,
                target: id(2),
                dest: "/var/lib/rackhand-run/incoming/backup.tar".into(),
            },
        ),
        entry("xfer_resume", tunnel::XferResume { next_chunk: 17 }),
        entry("xfer_chunk", tunnel::XferChunk { index: 17, blake3: vec![8; 32], data: vec![0xab; 64] }),
        entry("xfer_done", tunnel::XferDone { ok: true, error: String::new() }),
        entry("signed_payload", SignedPayload { payload: vec![1, 2, 3], hub_signature: vec![9; 64] }),
    ]
}
