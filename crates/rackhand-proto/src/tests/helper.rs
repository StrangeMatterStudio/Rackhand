use crate::helper::{HelperRequest, HelperResponse, parse_request};

#[test]
fn request_lines_parse_and_reject_unknown_fields() {
    let requests = [
        HelperRequest::Ping,
        HelperRequest::HashFiles,
        HelperRequest::AuthEventsSince { cursor: Some("s=abc".into()) },
        HelperRequest::Containers,
        HelperRequest::SocketOwners { inodes: vec![1, 2] },
        HelperRequest::ContainerOf { cgroup_ids: vec![99] },
        HelperRequest::ProcessScan,
        HelperRequest::UpdatesStatus,
        HelperRequest::ApplyUpdate { version: "0.1.1".into(), sha256: "00".repeat(32), signature: "c2ln".into() },
        HelperRequest::ApplyKeys { payload: "cA==".into(), hub_signature: "c2ln".into() },
    ];
    for req in requests {
        let line = serde_json::to_string(&req).unwrap();
        assert!(!line.contains('\n'), "one line");
        assert_eq!(parse_request(&line).unwrap(), req, "{line}");
    }
    assert!(parse_request(r#"{"op":"socket_owners","inodes":[1],"path":"/etc/shadow"}"#).is_err(), "unknown field");
    assert!(parse_request(r#"{"op":"read_file","path":"/etc/shadow"}"#).is_err(), "unknown request");
    let pong = serde_json::to_string(&HelperResponse::Pong { version: "0.1.0".into() }).unwrap();
    assert_eq!(pong, r#"{"kind":"pong","version":"0.1.0"}"#);
}
