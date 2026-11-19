use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use prost::Message;
use rackhand_proto::signed;
use serde_json::json;

use super::install::{InstallError, install};
use super::matcher::{CommandList, Refusal, matching};
use super::spawn_capture;

fn list(commands: serde_json::Value) -> CommandList {
    serde_json::from_value(json!({ "version": 1, "commands": commands })).unwrap()
}

fn args(a: &[&str]) -> Vec<String> {
    a.iter().map(|s| s.to_string()).collect()
}

#[test]
fn exact_template_match_executes_without_shell() {
    let l = list(json!([{
        "runbook": "test", "step": "echo",
        "args": [{"literal": "/usr/bin/printf"}, {"literal": "%s\\n"}, {"param": "a", "regex": "^(?:.*)$", "allow_leading_dash": false},
                 {"param": "b", "regex": "^(?:.*)$", "allow_leading_dash": false}]
    }]));
    let req = args(&["/usr/bin/printf", "%s\\n", "two words; $(id) `id`", "it's \"quoted\" | *"]);
    let argv = matching(&l, &req).unwrap();
    let out = spawn_capture(&argv).unwrap();
    // Each argument arrives as one argument, with no shell expansion of any kind.
    assert_eq!(out, "two words; $(id) `id`\nit's \"quoted\" | *\n");
}

#[test]
fn one_argument_different_from_every_template_refused() {
    let canary = std::env::temp_dir().join(format!("rackhand-canary-{}", std::process::id()));
    let _ = std::fs::remove_file(&canary);
    let allowed = std::env::temp_dir().join(format!("rackhand-allowed-{}", std::process::id()));
    let l = list(json!([{
        "runbook": "test", "step": "touch",
        "args": [{"literal": "/usr/bin/touch"}, {"literal": allowed.to_string_lossy()}]
    }]));
    let req = args(&["/usr/bin/touch", &canary.to_string_lossy()]);
    assert_eq!(matching(&l, &req), Err(Refusal::NoTemplate));
    assert!(!canary.exists(), "nothing ran");
    assert_eq!(matching(&l, &args(&["/usr/bin/touch"])), Err(Refusal::NoTemplate), "fewer arguments");
    assert_eq!(
        matching(&l, &args(&["/usr/bin/touch", &allowed.to_string_lossy(), "x"])),
        Err(Refusal::NoTemplate),
        "more"
    );
    assert!(matching(&l, &args(&["/usr/bin/touch", &allowed.to_string_lossy()])).is_ok());
    // A parameter's regex is matched as given; a pattern can't match only part of the value.
    let p = list(json!([{
        "runbook": "test", "step": "p",
        "args": [{"literal": "/usr/bin/true"}, {"param": "project", "regex": "^(?:[a-z]+)$", "allow_leading_dash": false}]
    }]));
    assert_eq!(matching(&p, &args(&["/usr/bin/true", "web;rm"])), Err(Refusal::NoTemplate));
    assert!(matching(&p, &args(&["/usr/bin/true", "web"])).is_ok());
}

#[test]
fn leading_dash_value_refused() {
    let l = list(json!([{
        "runbook": "test", "step": "p",
        "args": [{"literal": "/usr/bin/docker"}, {"literal": "logs"}, {"param": "c", "regex": "^(?:.*)$", "allow_leading_dash": false}]
    }]));
    assert_eq!(matching(&l, &args(&["/usr/bin/docker", "logs", "-f"])), Err(Refusal::LeadingDash));
    assert_eq!(matching(&l, &args(&["/usr/bin/docker", "logs", "--since=1h"])), Err(Refusal::LeadingDash));
    let allowed = list(json!([{
        "runbook": "test", "step": "p",
        "args": [{"literal": "/usr/bin/docker"}, {"literal": "logs"}, {"param": "c", "regex": "^(?:.*)$", "allow_leading_dash": true}]
    }]));
    assert!(matching(&allowed, &args(&["/usr/bin/docker", "logs", "-f"])).is_ok());
}

fn dir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("rackhand-install-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn payload(key: &SigningKey, version: u64, now: i64, expires: i64) -> Vec<u8> {
    let body = json!({"commands": [{"runbook": "r", "step": "s", "args": [{"literal": "/usr/bin/true"}]}]}).to_string();
    signed::sign(key, "commands", version, now, expires, body.as_bytes()).encode_to_vec()
}

#[test]
fn unsigned_expired_or_not_newer_list_refused() {
    let d = dir("refused");
    let key = SigningKey::from_bytes(&[1u8; 32]);
    let pinned = key.verifying_key();
    let now = 1_795_000_000_000;
    let target = d.join("commands.json");
    install(&target, &payload(&key, 5, now, now + 60_000), &pinned, now).unwrap();
    let before = std::fs::read(&target).unwrap();
    let installed: serde_json::Value = serde_json::from_slice(&before).unwrap();
    assert_eq!(installed["version"], 5);
    assert_eq!(installed["commands"][0]["args"][0]["literal"], "/usr/bin/true");

    let mut tampered =
        rackhand_proto::common::SignedPayload::decode(payload(&key, 6, now, now + 60_000).as_slice()).unwrap();
    tampered.payload.push(0);
    let cases: Vec<(&str, Vec<u8>, InstallError)> = vec![
        ("unsigned", tampered.encode_to_vec(), InstallError::Signature),
        ("garbage", b"not a payload".to_vec(), InstallError::Malformed),
        ("expired", payload(&key, 6, now - 120_000, now - 60_000), InstallError::Expired),
        ("not newer", payload(&key, 5, now, now + 60_000), InstallError::NotNewer),
        ("older", payload(&key, 4, now, now + 60_000), InstallError::NotNewer),
    ];
    for (what, bytes, want) in cases {
        assert_eq!(install(&target, &bytes, &pinned, now), Err(want), "{what}");
        assert_eq!(std::fs::read(&target).unwrap(), before, "{what}: commands.json changed");
    }
    install(&target, &payload(&key, 6, now, now + 60_000), &pinned, now).unwrap();
    assert_ne!(std::fs::read(&target).unwrap(), before, "a newer signed list is installed");
}

#[test]
fn list_signed_by_other_key_refused() {
    let d = dir("other-key");
    let hub = SigningKey::from_bytes(&[1u8; 32]);
    let other = SigningKey::from_bytes(&[2u8; 32]);
    let now = 1_795_000_000_000;
    let target = d.join("commands.json");
    install(&target, &payload(&hub, 1, now, now + 60_000), &hub.verifying_key(), now).unwrap();
    let before = std::fs::read(&target).unwrap();
    assert_eq!(
        install(&target, &payload(&other, 2, now, now + 60_000), &hub.verifying_key(), now),
        Err(InstallError::Signature)
    );
    assert_eq!(std::fs::read(&target).unwrap(), before);
    // The pinned key comes from probe.toml.
    let toml = d.join("probe.toml");
    let hex: String = hub.verifying_key().as_bytes().iter().map(|b| format!("{b:02x}")).collect();
    std::fs::write(&toml, format!("[hub]\nid = \"{hex}\"\n")).unwrap();
    assert_eq!(super::install::pinned_hub_key(&toml).unwrap(), hub.verifying_key());
    std::fs::write(&toml, "[hub]\nid = \"nothex\"\n").unwrap();
    assert!(super::install::pinned_hub_key(&toml).is_err());
}
