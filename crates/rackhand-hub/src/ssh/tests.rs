use std::sync::Arc;

use rackhand_store::{Db, Row, RowWrite, WriteCmd};
use rusqlite::types::Value;

use super::hostkeys::{HostKeyAlert, HostKeyError, HostKeys};
use super::keys::generate_ed25519;
use super::quote::{join, quote};

/// A small deterministic generator, so a failure can be replayed.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

const HOSTILE: &[&str] = &[
    "'",
    "\"",
    "$(id)",
    "`id`",
    "$HOME",
    "\n",
    "*",
    "?",
    " ",
    "\t",
    ";",
    "|",
    "&",
    "\\",
    "!",
    "#",
    "~",
    "{a,b}",
    "-",
    "--",
    "é",
    "\u{1f511}",
    "%s",
    "a",
];

mod quote {
    use super::*;

    #[test]
    fn posix_quoting_round_trips_hostile_strings() {
        let mut rng = Rng(0x5eed_1234_abcd_ef01);
        for case in 0..300 {
            let n = 1 + (rng.next() % 5) as usize;
            let args: Vec<String> = (0..n)
                .map(|_| (0..(rng.next() % 6)).map(|_| HOSTILE[(rng.next() % HOSTILE.len() as u64) as usize]).collect())
                .collect();
            let command = format!("printf '%s\\0' {}", join(&args));
            let out = std::process::Command::new("sh").args(["-c", &command]).output().unwrap();
            assert!(out.status.success(), "case {case}: {command:?}");
            let got: Vec<String> = String::from_utf8(out.stdout).unwrap().split('\0').map(str::to_string).collect();
            assert_eq!(&got[..got.len() - 1], args.as_slice(), "case {case}: {command:?}");
        }
        assert_eq!(quote("it's"), "'it'\\''s'");
        assert_eq!(quote(""), "''");
    }
}

mod hostkeys {
    use super::*;

    fn db(name: &str) -> Arc<Db> {
        let dir = std::env::temp_dir().join(format!("rackhand-hostkeys-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Arc::new(Db::open(&dir.join("hub.db")).unwrap())
    }

    async fn machine(db: &Db) {
        db.writer()
            .send(WriteCmd::Batch(vec![
                RowWrite::insert(
                    "sites",
                    Row::from([
                        ("id", Value::Text("s".into())),
                        ("name", Value::Text("home".into())),
                        ("timezone", Value::Text("UTC".into())),
                    ]),
                ),
                RowWrite::insert(
                    "machines",
                    Row::from([
                        ("id", Value::Text("m1".into())),
                        ("site_id", Value::Text("s".into())),
                        ("name", Value::Text("web".into())),
                        ("kind", Value::Text("linux".into())),
                    ]),
                ),
            ]))
            .await
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn changed_key_blocks_and_raises_critical() {
        let db = db("changed");
        machine(&db).await;
        let (keys, mut alerts) = HostKeys::new(db.clone());
        let (_, pinned) = generate_ed25519("host").unwrap();
        let (_, other) = generate_ed25519("host").unwrap();
        assert_eq!(keys.check("m1", &pinned), Err(HostKeyError::NotPinned), "only keys from the join are trusted");
        keys.pin_from_join("m1", std::slice::from_ref(&pinned), 1_000).await.unwrap();
        assert_eq!(keys.check("m1", &pinned), Ok(()));
        assert_eq!(keys.check("m1", &other), Err(HostKeyError::Changed), "a different key is refused");
        let alert = alerts.try_recv().unwrap();
        assert_eq!(alert.kind(), "ssh.host_key_changed");
        assert_eq!(alert.severity(), "critical");
        let HostKeyAlert::Changed { machine_id, offered, .. } = &alert;
        assert_eq!(machine_id, "m1");
        assert_eq!(offered, &super::super::hostkeys::fingerprint(&other).unwrap());
        // Still refused until an admin accepts the offered key; then the old one is the stranger.
        assert_eq!(keys.check("m1", &other), Err(HostKeyError::Changed));
        keys.accept_offered("m1", "admin", 2_000).await.unwrap();
        assert_eq!(keys.check("m1", &other), Ok(()));
        assert_eq!(keys.check("m1", &pinned), Err(HostKeyError::Changed));
        let (reloaded, _) = HostKeys::new(db.clone());
        assert_eq!(reloaded.check("m1", &other), Ok(()), "pins are stored");
    }
}
