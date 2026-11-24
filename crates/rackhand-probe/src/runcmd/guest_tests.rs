use std::cell::RefCell;
use std::path::PathBuf;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rackhand_proto::common::SignedPayload;
use serde_json::json;

use super::*;

const NOW: i64 = 1_795_000_000_000;
const URL: &str = "https://github.com/StrangeMatterStudio/Rackhand/releases/download/v0.1.0/install.sh";
const TICKET: &str = "rackhand1:0000000000000000000000000000000000000000000000000000000000000001@192.0.2.10:7443";

/// A hypervisor host that records what it was asked to do.
#[derive(Default)]
struct Fake {
    snippets: RefCell<Vec<(String, String)>>,
    /// `pct status` answers, one per call; the last one repeats.
    running: RefCell<Vec<bool>>,
    asked: RefCell<Vec<(u64, String)>>,
    exec_code: i32,
    slept: RefCell<Duration>,
}

impl Host for Fake {
    fn write_snippet(&self, name: &str, data: &str) -> std::io::Result<()> {
        self.snippets.borrow_mut().push((name.into(), data.into()));
        Ok(())
    }

    fn lxc_running(&self, _vmid: u64) -> bool {
        let mut r = self.running.borrow_mut();
        if r.len() > 1 { r.remove(0) } else { r.first().copied().unwrap_or(true) }
    }

    fn lxc_exec(&self, vmid: u64, line: &str) -> std::io::Result<(i32, String)> {
        self.asked.borrow_mut().push((vmid, line.into()));
        Ok((self.exec_code, "enrolled as machine 01JD\n".into()))
    }

    fn sleep(&self, d: Duration) {
        *self.slept.borrow_mut() += d;
    }
}

struct Machine {
    files: GuestFiles,
    hub: SigningKey,
}

impl Machine {
    fn new(name: &str, access: &str) -> Machine {
        let dir: PathBuf = std::env::temp_dir().join(format!("rackhand-guest-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let hub = SigningKey::from_bytes(&[7; 32]);
        let id: String = hub.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let text =
            format!("[hub]\nid = \"{id}\"\n\n[machine]\nid = \"01JD0000000000000000000001\"\naccess = \"{access}\"\n");
        std::fs::write(dir.join("probe.toml"), text).unwrap();
        Machine { files: GuestFiles { probe_toml: dir.join("probe.toml"), version: dir.join("guest.version") }, hub }
    }

    fn sign(&self, version: u64, ttl: i64, body: &serde_json::Value) -> SignedPayload {
        rackhand_proto::signed::sign(
            &self.hub,
            KIND,
            version,
            NOW,
            NOW + ttl,
            serde_json::to_vec(body).unwrap().as_slice(),
        )
    }
}

fn body(kind: &str, vmid: u64) -> serde_json::Value {
    json!({ "kind": kind, "vmid": vmid, "script_url": URL, "args": ["--ticket", TICKET, "--token", "01JDTOKEN0123456789ABCDEF"],
            "self_signed": false })
}

#[test]
fn a_vm_gets_the_user_data_that_runs_the_installer_and_nothing_else_is_written() {
    let m = Machine::new("vm", "managed");
    let host = Fake::default();
    let out = apply(&m.files, &host, &m.sign(1, 600_000, &body("qemu", 300)), NOW).unwrap();
    assert_eq!(out, "user=local:snippets/rackhand-300.yml", "what the hub puts in `cicustom`");
    let snippets = host.snippets.borrow();
    assert_eq!(snippets.len(), 1);
    let (name, data) = &snippets[0];
    assert_eq!(name, "rackhand-300.yml");
    assert!(data.starts_with("#cloud-config\nruncmd:\n"), "{data}");
    assert!(
        data.contains(URL)
            && data.contains("--ticket rackhand1:")
            && data.contains("--token 01JDTOKEN0123456789ABCDEF"),
        "{data}"
    );
    assert!(data.contains("curl -fsSL") && data.contains("wget -qO-"), "{data}");
    assert!(!data.contains("-k ") && !data.contains("no-check-certificate"), "the release's TLS is checked: {data}");
    assert!(host.asked.borrow().is_empty(), "no container was touched");
    // the same payload again is a replay
    assert_eq!(apply(&m.files, &host, &m.sign(1, 600_000, &body("qemu", 300)), NOW), Err(GuestError::NotNewer));
    assert_eq!(host.snippets.borrow().len(), 1);
}

#[test]
fn an_offline_install_trusts_the_hubs_own_certificate_for_the_download_only() {
    let m = Machine::new("offline", "managed");
    let host = Fake::default();
    let mut b = body("qemu", 301);
    b["script_url"] = json!("https://192.0.2.10:8443/release/install.sh");
    b["self_signed"] = json!(true);
    b["args"] = json!([
        "--ticket",
        TICKET,
        "--token",
        "01JDTOKEN0123456789ABCDEF",
        "--release-url",
        "https://192.0.2.10:8443/release",
        "--self-signed"
    ]);
    apply(&m.files, &host, &m.sign(1, 600_000, &b), NOW).unwrap();
    let data = host.snippets.borrow()[0].1.clone();
    assert!(data.contains("curl -fsSLk") && data.contains("--no-check-certificate"), "{data}");
}

#[test]
fn a_container_is_waited_for_and_the_installer_runs_inside_it() {
    let m = Machine::new("lxc", "managed");
    let host = Fake { running: RefCell::new(vec![false, false, true]), ..Fake::default() };
    let out = apply(&m.files, &host, &m.sign(1, 600_000, &body("lxc", 400)), NOW).unwrap();
    assert!(out.contains("enrolled as machine"), "what the installer printed comes back: {out}");
    let asked = host.asked.borrow();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, 400);
    assert!(asked[0].1.contains(URL) && asked[0].1.contains("--token 01JDTOKEN0123456789ABCDEF"), "{}", asked[0].1);
    assert!(*host.slept.borrow() >= Duration::from_secs(2), "it waited for the container to run");
    assert!(host.snippets.borrow().is_empty(), "no user data for a container");
    // a container that never runs is an error, and nothing ran in it
    let m = Machine::new("lxc-down", "managed");
    let down = Fake { running: RefCell::new(vec![false]), ..Fake::default() };
    let refused = apply(&m.files, &down, &m.sign(1, 600_000, &body("lxc", 401)), NOW);
    assert!(matches!(refused, Err(GuestError::Guest(_))), "{refused:?}");
    assert!(down.asked.borrow().is_empty());
    // the installer's failure is the answer's
    let m = Machine::new("lxc-fails", "managed");
    let fails = Fake { exec_code: 1, ..Fake::default() };
    assert!(matches!(apply(&m.files, &fails, &m.sign(1, 600_000, &body("lxc", 402)), NOW), Err(GuestError::Guest(_))));
}

#[test]
fn only_a_payload_the_pinned_hub_signed_is_acted_on() {
    let m = Machine::new("sig", "managed");
    let host = Fake::default();
    let forged = rackhand_proto::signed::sign(
        &SigningKey::from_bytes(&[9; 32]),
        KIND,
        1,
        NOW,
        NOW + 600_000,
        serde_json::to_vec(&body("qemu", 300)).unwrap().as_slice(),
    );
    assert_eq!(apply(&m.files, &host, &forged, NOW), Err(GuestError::Signature));
    let other_kind = rackhand_proto::signed::sign(
        &m.hub,
        "keys",
        1,
        NOW,
        NOW + 600_000,
        serde_json::to_vec(&body("qemu", 300)).unwrap().as_slice(),
    );
    assert_eq!(apply(&m.files, &host, &other_kind, NOW), Err(GuestError::Signature), "a key update isn't a guest");
    assert_eq!(
        apply(&m.files, &host, &m.sign(1, 600_000, &body("qemu", 300)), NOW + 700_000),
        Err(GuestError::Expired)
    );
    assert_eq!(
        apply(&m.files, &host, &m.sign(1, 7_200_000, &body("qemu", 300)), NOW),
        Err(GuestError::Expired),
        "valid for too long"
    );
    assert!(host.snippets.borrow().is_empty() && host.asked.borrow().is_empty());
    // a machine without the hub's accounts has no wrapper to ask
    let monitor = Machine::new("sig-monitor", "monitor");
    assert_eq!(
        apply(&monitor.files, &host, &monitor.sign(1, 600_000, &body("qemu", 300)), NOW),
        Err(GuestError::MonitorOnly)
    );
}

#[test]
fn what_the_installer_line_is_made_of_cannot_be_widened() {
    let m = Machine::new("body", "managed");
    let host = Fake::default();
    let mut version = 0;
    let mut refuse = |what: &str, b: serde_json::Value| {
        version += 1;
        let r = apply(&m.files, &host, &m.sign(version, 600_000, &b), NOW);
        assert!(matches!(r, Err(GuestError::Body(_))), "{what}: {r:?}");
    };
    let with = |key: &str, value: serde_json::Value| {
        let mut b = body("qemu", 300);
        b[key] = value;
        b
    };
    refuse("another kind", with("kind", json!("kvm")));
    refuse("a vmid below the first guest", with("vmid", json!(99)));
    refuse("a vmid that isn't a number", with("vmid", json!("300; id")));
    refuse("a script from plain http", with("script_url", json!("http://example.net/install.sh")));
    refuse("a script from a file", with("script_url", json!("file:///etc/passwd")));
    refuse("a quote in the address", with("script_url", json!("https://example.net/a'b")));
    refuse("a space in the address", with("script_url", json!("https://example.net/a b")));
    for bad in ["x; reboot", "$(id)", "`id`", "a|b", "a b", "a'b", "a\"b", "a\nb", "a\\b", "a&b", ""] {
        refuse(bad, with("args", json!(["--ticket", bad])));
    }
    refuse("no arguments", with("args", json!([])));
    refuse("too many arguments", with("args", json!(vec!["--x"; 40])));
    refuse("an unknown field", with("shell", json!("id")));
    assert!(host.snippets.borrow().is_empty() && host.asked.borrow().is_empty());
}
