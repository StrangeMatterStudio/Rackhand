//! Golden encodings. Update deliberately with `cargo xtask golden --update` and review the diff.
use std::path::PathBuf;

use prost::Message;

use crate::samples;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/golden")
}

#[test]
fn encoded_bytes_match_fixtures() {
    let update = std::env::var("RACKHAND_GOLDEN_UPDATE").is_ok();
    for (name, bytes, _) in samples::all() {
        let path = dir().join(format!("{name}.bin"));
        if update {
            std::fs::create_dir_all(dir()).unwrap();
            std::fs::write(&path, &bytes).unwrap();
        }
        let golden = std::fs::read(&path).unwrap_or_else(|_| panic!("missing golden file {}", path.display()));
        assert_eq!(bytes, golden, "{name}: encoding changed; update deliberately");
    }
}

/// The `Hello` of an older probe that predates `interfaces` and `label_table`.
#[derive(Clone, PartialEq, Message)]
struct HelloV0 {
    #[prost(message, optional, tag = "1")]
    probe_version: Option<crate::common::SemVer>,
    #[prost(bytes = "vec", tag = "2")]
    machine_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    epoch: u64,
}

#[test]
fn older_message_without_new_optional_field_decodes() {
    let path = dir().join("hello_v0.bin");
    let old = HelloV0 {
        probe_version: Some(crate::common::SemVer { version: "0.0.9".into() }),
        machine_id: vec![1; 16],
        epoch: 42,
    }
    .encode_to_vec();
    if std::env::var("RACKHAND_GOLDEN_UPDATE").is_ok() {
        std::fs::create_dir_all(dir()).unwrap();
        std::fs::write(&path, &old).unwrap();
    }
    let fixture = std::fs::read(&path).expect("hello_v0.bin");
    let hello = crate::probe::Hello::decode(fixture.as_slice()).unwrap();
    assert_eq!(hello.epoch, 42);
    assert!(hello.interfaces.is_empty() && hello.label_table.is_empty(), "new fields take their defaults");
}
