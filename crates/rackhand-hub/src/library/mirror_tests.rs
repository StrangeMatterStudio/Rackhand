use super::super::items::Kind;
use super::super::tests::{PLAYBOOK, RUNBOOK, library};
use super::{Debounce, render};

#[tokio::test(flavor = "multi_thread")]
async fn layout_matches_design() {
    let (db, lib) = library("layout");
    lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", 1).await.unwrap();
    lib.save(Kind::Playbook, "patch-failure", PLAYBOOK, "admin", 1).await.unwrap();
    lib.save(Kind::Config, "hub", "[sources]\nfeodo = true\nspamhaus = true\ndbip = true\n", "admin", 1).await.unwrap();
    lib.save(Kind::Config, "policies", "[policy.default]\npatch = \"approve-only\"\n", "admin", 1).await.unwrap();
    let files = render(&db).unwrap();
    let names: Vec<&str> = files.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        [
            "README.md",
            "config/hub.toml",
            "config/policies.toml",
            "playbooks/patch-failure.md",
            "runbooks/compose-restart.toml"
        ]
    );
    assert_eq!(files["runbooks/compose-restart.toml"], RUNBOOK);
    let readme = &files["README.md"];
    for item in ["compose-restart", "patch-failure", "config/hub.toml"] {
        assert!(readme.contains(item), "{readme}");
    }
    assert!(readme.contains("secret:"), "the README explains secret references: {readme}");
}

#[test]
fn debounced_30s_commit_message_user_summary() {
    let mut d = Debounce::new(30_000);
    assert!(d.take_due(0).is_none());
    d.push(1_000, "admin", "edit compose-restart");
    d.push(11_000, "alice", "add patch-failure");
    assert!(d.take_due(30_999).is_none(), "30 s after the first change");
    let message = d.take_due(31_000).unwrap();
    assert_eq!(message, "admin, alice: edit compose-restart; add patch-failure");
    assert!(d.take_due(100_000).is_none(), "one commit for both");
    d.push(200_000, "admin", "again");
    assert_eq!(d.take_due(230_000).unwrap(), "admin: again");
}

#[tokio::test(flavor = "multi_thread")]
async fn restore_reads_the_layout_back() {
    let (db, lib) = library("restore-from");
    lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", 1).await.unwrap();
    lib.save(Kind::Playbook, "patch-failure", PLAYBOOK, "admin", 1).await.unwrap();
    lib.save(Kind::Config, "hub", "[sources]\nfeodo = true\nspamhaus = false\ndbip = true\n", "admin", 1)
        .await
        .unwrap();
    let dir = std::env::temp_dir().join(format!("rackhand-restore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    for (path, text) in render(&db).unwrap() {
        let full = dir.join(path);
        std::fs::create_dir_all(full.parent().unwrap()).unwrap();
        std::fs::write(full, text).unwrap();
    }
    let (fresh_db, fresh) = library("restore-to");
    let report = super::restore(&fresh, &dir, 5).await;
    assert_eq!(report.restored, 3, "{report:?}");
    assert!(report.refused.is_empty(), "{report:?}");
    assert_eq!(render(&fresh_db).unwrap(), render(&db).unwrap(), "the same files come out");
    // An invalid file is reported, not stored.
    std::fs::write(dir.join("runbooks/broken.toml"), "name = ").unwrap();
    let report = super::restore(&fresh, &dir, 6).await;
    assert_eq!(report.refused.len(), 1, "{report:?}");
}
