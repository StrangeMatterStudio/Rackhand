//! Checks that the network tier's VM can do what the network tests need.

use std::process::Command;

fn ip(args: &str) {
    let status = Command::new("ip").args(args.split_whitespace()).status().expect("ip is installed");
    assert!(status.success(), "ip {args} failed");
}

#[test]
fn can_create_netns() {
    crate::require_vm();
    ip("netns add smoke-a");
    ip("netns add smoke-b");
    ip("link add veth-a netns smoke-a type veth peer name veth-b netns smoke-b");
    ip("-n smoke-a addr add 192.0.2.1/24 dev veth-a");
    ip("-n smoke-b addr add 192.0.2.2/24 dev veth-b");
    ip("-n smoke-a link set veth-a up");
    ip("-n smoke-b link set veth-b up");
    let ping = Command::new("ip")
        .args(["netns", "exec", "smoke-a", "ping", "-c", "1", "-W", "2", "192.0.2.2"])
        .status()
        .expect("ping runs");
    ip("netns del smoke-a");
    ip("netns del smoke-b");
    assert!(ping.success(), "no ping across the veth pair");
}
