use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

use ed25519_dalek::SigningKey;
use serde_json::json;

use super::*;

const NOW: i64 = 1_795_000_000_000;
const HOUR: i64 = 3_600_000;

/// A valid `ssh-ed25519` key whose 32 bytes are all `n`.
fn key(n: u8) -> String {
    let mut blob = b"\0\0\0\x0bssh-ed25519\0\0\0\x20".to_vec();
    blob.extend([n; 32]);
    format!("ssh-ed25519 {}", BASE64.encode(&blob))
}

struct Machine {
    dir: PathBuf,
    files: Files,
    hub: SigningKey,
}

impl Machine {
    /// A managed machine with both hub users (owned by the user running the test), each with one old key.
    fn new(name: &str) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-keys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let hub = SigningKey::from_bytes(&[7; 32]);
        let m = Machine {
            files: Files {
                probe_toml: dir.join("probe.toml"),
                passwd: dir.join("passwd"),
                version: dir.join("keys.version"),
            },
            dir,
            hub,
        };
        std::fs::create_dir_all(&m.dir).unwrap();
        m.access("managed");
        let me = std::fs::metadata(&m.dir).unwrap();
        let mut passwd = String::from("root:x:0:0::/root:/bin/sh\n");
        for user in ["rackhand", "rackhand-ai", "owner"] {
            let home = m.home(user);
            std::fs::create_dir_all(home.join(".ssh")).unwrap();
            passwd.push_str(&format!("{user}:x:{}:{}::{}:/bin/sh\n", me.uid(), me.gid(), home.display()));
            m.write(user, &format!("# kept\n{}\n", m.line(1, "192.0.2.10")));
        }
        std::fs::write(&m.files.passwd, passwd).unwrap();
        m
    }

    fn access(&self, access: &str) {
        let id: String = self.hub.verifying_key().to_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let text =
            format!("[hub]\nid = \"{id}\"\n\n[machine]\nid = \"01JD0000000000000000000001\"\naccess = \"{access}\"\n");
        std::fs::write(&self.files.probe_toml, text).unwrap();
    }

    fn home(&self, user: &str) -> PathBuf {
        self.dir.join("home").join(user)
    }

    fn file(&self, user: &str) -> PathBuf {
        self.home(user).join(".ssh/authorized_keys")
    }

    fn write(&self, user: &str, text: &str) {
        std::fs::write(self.file(user), text).unwrap();
    }

    fn read(&self, user: &str) -> String {
        std::fs::read_to_string(self.file(user)).unwrap()
    }

    fn line(&self, n: u8, from: &str) -> String {
        format!("from=\"{from}\",no-agent-forwarding,no-X11-forwarding,no-port-forwarding {}", key(n))
    }

    fn all(&self) -> Vec<String> {
        ["rackhand", "rackhand-ai", "owner"].map(|u| self.read(u)).to_vec()
    }

    fn signed(
        &self,
        by: &SigningKey,
        kind: &str,
        version: u64,
        valid_ms: i64,
        body: &serde_json::Value,
    ) -> (String, String) {
        let p = signed::sign(by, kind, version, NOW, NOW + valid_ms, body.to_string().as_bytes());
        (BASE64.encode(&p.payload), BASE64.encode(&p.hub_signature))
    }

    fn apply(&self, version: u64, body: serde_json::Value) -> Result<u64, KeysError> {
        let (p, s) = self.signed(&self.hub, KIND, version, HOUR, &body);
        apply(&self.files, &p, &s, NOW + 1000)
    }
}

fn both(n: u8) -> serde_json::Value {
    json!({ "from": ["192.0.2.11", "2001:db8::1"], "keys": { "rackhand": [key(n)], "rackhand-ai": [key(n + 1)] } })
}

/// 7.3.3: the key lines and their `from=` are replaced, with the join's restrictions; comments stay, and the file is the
/// user's own and private.
#[test]
fn new_keys_replace_the_old_ones() {
    let m = Machine::new("replace");
    assert_eq!(m.apply(5, both(2)), Ok(5));
    assert_eq!(m.read("rackhand"), format!("# kept\n{}\n", m.line(2, "192.0.2.11,2001:db8::1")));
    assert_eq!(m.read("rackhand-ai"), format!("# kept\n{}\n", m.line(3, "192.0.2.11,2001:db8::1")));
    assert_eq!(m.read("owner"), format!("# kept\n{}\n", m.line(1, "192.0.2.10")), "nobody else's");
    let meta = std::fs::metadata(m.file("rackhand")).unwrap();
    assert_eq!((meta.permissions().mode() & 0o777, meta.uid()), (0o600, std::fs::metadata(&m.dir).unwrap().uid()));
    // one user only, with its old and new key during a rotation
    let rotate = json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [key(2), key(9)] } });
    assert_eq!(m.apply(6, rotate), Ok(6));
    assert_eq!(m.read("rackhand").lines().count(), 3);
    assert!(m.read("rackhand-ai").contains(&key(3)), "untouched");
    let names: Vec<String> = std::fs::read_dir(m.home("rackhand").join(".ssh"))
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["authorized_keys"], "nothing left behind");
}

#[test]
fn older_equal_or_expired_payload_refused() {
    let m = Machine::new("replay");
    let first = m.signed(&m.hub, KIND, 5, HOUR, &both(2));
    assert_eq!(apply(&m.files, &first.0, &first.1, NOW + 1000), Ok(5));
    assert_eq!(m.apply(6, both(4)), Ok(6));
    let rotated = m.all();
    assert_eq!(apply(&m.files, &first.0, &first.1, NOW + 2000), Err(KeysError::NotNewer), "an older one replayed");
    assert_eq!(m.apply(6, both(8)), Err(KeysError::NotNewer), "an equal one");
    let (p, s) = m.signed(&m.hub, KIND, 7, HOUR, &both(8));
    assert_eq!(apply(&m.files, &p, &s, NOW + HOUR + 1), Err(KeysError::Expired));
    let (p, s) = m.signed(&m.hub, KIND, 7, HOUR + 1, &both(8));
    assert_eq!(apply(&m.files, &p, &s, NOW + 1), Err(KeysError::Expired), "valid for more than an hour");
    assert_eq!(m.all(), rotated, "nothing changed");
    // a version that can't be read accepts nothing
    std::fs::write(&m.files.version, "?").unwrap();
    assert!(matches!(m.apply(99, both(8)), Err(KeysError::Write(_))));
    assert_eq!(m.all(), rotated);
}

#[test]
fn only_the_pinned_hubs_key_payloads() {
    let m = Machine::new("signer");
    let before = m.all();
    let other = SigningKey::from_bytes(&[8; 32]);
    let (p, s) = m.signed(&other, KIND, 5, HOUR, &both(2));
    assert_eq!(apply(&m.files, &p, &s, NOW + 1), Err(KeysError::Signature));
    let (p, s) = m.signed(&m.hub, "commands", 5, HOUR, &both(2));
    assert_eq!(apply(&m.files, &p, &s, NOW + 1), Err(KeysError::Signature), "a command list isn't a key update");
    let (_, s) = m.signed(&m.hub, KIND, 5, HOUR, &both(2));
    let (p, _) = m.signed(&m.hub, KIND, 5, HOUR, &both(4));
    assert_eq!(apply(&m.files, &p, &s, NOW + 1), Err(KeysError::Signature), "another payload's signature");
    assert_eq!(apply(&m.files, "not base64!", &s, NOW + 1), Err(KeysError::Malformed));
    assert_eq!(m.all(), before);
}

#[test]
fn payload_can_only_touch_hub_users_key_lines_and_from() {
    let m = Machine::new("bounds");
    let before = m.all();
    let k = || key(2);
    let evil = [
        json!({ "from": ["192.0.2.11"], "keys": { "owner": [k()] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "root": [k()] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "../root": [k()] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [k()], "owner": [k()] } }),
        json!({ "from": ["*"], "keys": { "rackhand": [k()] } }),
        json!({ "from": ["0.0.0.0/0"], "keys": { "rackhand": [k()] } }),
        json!({ "from": ["192.0.2.11\",command=\"x"], "keys": { "rackhand": [k()] } }),
        json!({ "from": [], "keys": { "rackhand": [k()] } }),
        json!({ "from": ["192.0.2.11"], "keys": {} }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [k(), k(), k(), k(), k()] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [format!("{}\n{}", k(), k())] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [format!("command=\"sh\" {}", k())] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [format!("{} a b", k())] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": ["ssh-rsa AAAAB3NzaC1yc2E="] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": ["ssh-ed25519 AAAA"] } }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [k()] }, "sudoers": "ALL" }),
        json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [k()] }, "path": "/etc/shadow" }),
        json!([]),
    ];
    for (i, body) in evil.into_iter().enumerate() {
        let r = m.apply(10 + i as u64, body.clone());
        assert!(matches!(r, Err(KeysError::Body(_))), "{body}: {r:?}");
    }
    assert_eq!(m.all(), before);
    assert!(!m.files.version.exists(), "a refused payload doesn't use its version up");
    assert_eq!(
        m.apply(10, json!({ "from": ["192.0.2.11"], "keys": { "rackhand": [format!("{} rackhand@hub-1", k())] } })),
        Ok(10)
    );
}

/// The users own their `.ssh`: links there lead nowhere.
#[test]
fn links_are_not_followed() {
    let m = Machine::new("links");
    let secret = m.dir.join("secret");
    std::fs::write(&secret, "# not to be read\nuntouched\n").unwrap();
    let authorized = m.file("rackhand");
    std::fs::remove_file(&authorized).unwrap();
    symlink(&secret, &authorized).unwrap();
    symlink(&secret, m.home("rackhand").join(".ssh/.authorized_keys.rackhand")).unwrap();
    assert_eq!(m.apply(5, both(2)), Ok(5));
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "# not to be read\nuntouched\n");
    assert!(!std::fs::symlink_metadata(&authorized).unwrap().file_type().is_symlink(), "replaced by a file");
    assert_eq!(
        m.read("rackhand"),
        format!("{}\n", m.line(2, "192.0.2.11,2001:db8::1")),
        "nothing of the link's target"
    );
    // a hard link isn't read either: its comments aren't the user's
    std::fs::remove_file(m.file("rackhand")).unwrap();
    std::fs::hard_link(&secret, m.file("rackhand")).unwrap();
    assert_eq!(m.apply(6, both(4)), Ok(6));
    assert!(!m.read("rackhand").contains("not to be read"), "{}", m.read("rackhand"));
    assert_eq!(std::fs::read_to_string(&secret).unwrap(), "# not to be read\nuntouched\n");
    // `.ssh` itself a link: refused
    let elsewhere = m.dir.join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    std::fs::remove_dir_all(m.home("rackhand").join(".ssh")).unwrap();
    symlink(&elsewhere, m.home("rackhand").join(".ssh")).unwrap();
    assert!(matches!(m.apply(7, both(4)), Err(KeysError::Write(_))));
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

/// A user that isn't there refuses the whole payload before anything is written.
#[test]
fn missing_user_changes_nothing() {
    let m = Machine::new("missing");
    let before = m.all();
    let passwd = std::fs::read_to_string(&m.files.passwd).unwrap();
    let without: String = passwd.lines().filter(|l| !l.starts_with("rackhand-ai:")).map(|l| format!("{l}\n")).collect();
    std::fs::write(&m.files.passwd, without).unwrap();
    assert!(matches!(m.apply(5, both(2)), Err(KeysError::Write(_))));
    assert_eq!(m.all(), before);
}

#[test]
fn monitor_machine_refuses_apply_keys() {
    let m = Machine::new("monitor");
    m.access("monitor");
    let before = m.all();
    assert_eq!(m.apply(5, both(2)), Err(KeysError::MonitorOnly));
    assert_eq!(m.all(), before);
    // through the helper's socket interface
    let (payload, hub_signature) = m.signed(&m.hub, KIND, 6, HOUR, &both(2));
    let request =
        serde_json::to_string(&rackhand_proto::helper::HelperRequest::ApplyKeys { payload, hub_signature }).unwrap();
    let helper = crate::helper::server::Helper::with_keys("0.1.0", m.files.clone());
    match helper.answer(&request) {
        rackhand_proto::helper::HelperResponse::Error { code, .. } => assert_eq!(code, "monitor_only"),
        other => panic!("{other:?}"),
    }
}

/// The helper's answer to a payload that applies.
#[test]
fn helper_answers_keys_applied() {
    let m = Machine::new("helper");
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
    let p = signed::sign(&m.hub, KIND, 5, now, now + HOUR, both(2).to_string().as_bytes());
    let request = rackhand_proto::helper::HelperRequest::ApplyKeys {
        payload: BASE64.encode(&p.payload),
        hub_signature: BASE64.encode(&p.hub_signature),
    };
    let helper = crate::helper::server::Helper::with_keys("0.1.0", m.files.clone());
    let answer = helper.answer(&serde_json::to_string(&request).unwrap());
    assert_eq!(answer, rackhand_proto::helper::HelperResponse::KeysApplied);
    assert!(m.read("rackhand").contains(&key(2)));
}

/// Two updates at once: whichever comes first, the newer one is what stays.
#[test]
fn concurrent_updates_leave_the_newest() {
    for round in 0..20 {
        let m = Machine::new(&format!("race-{round}"));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let helper = crate::helper::server::Helper::with_keys("0.1.0", m.files.clone());
        let threads: Vec<_> = (1..=8u8)
            .map(|n| {
                let p = signed::sign(&m.hub, KIND, u64::from(n), now, now + HOUR, both(n * 2).to_string().as_bytes());
                let request = rackhand_proto::helper::HelperRequest::ApplyKeys {
                    payload: BASE64.encode(&p.payload),
                    hub_signature: BASE64.encode(&p.hub_signature),
                };
                let (helper, line) = (helper.clone(), serde_json::to_string(&request).unwrap());
                std::thread::spawn(move || helper.answer(&line))
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(std::fs::read_to_string(&m.files.version).unwrap().trim(), "8", "round {round}");
        assert!(m.read("rackhand").contains(&key(16)), "round {round}: {}", m.read("rackhand"));
    }
}
