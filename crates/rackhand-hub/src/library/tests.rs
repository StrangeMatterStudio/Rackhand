use std::sync::Arc;

use rackhand_store::Db;

use super::items::{Kind, Library, SaveError};
use crate::audit::Audit;

pub(crate) const RUNBOOK: &str = r#"name = "compose-restart"
description = "Restart one Docker Compose project"
targets = { kinds = ["linux"] }
identity = "automation"
risk = "low"
autonomy = 1
[params.project]
type = "string"
pattern = "[a-z0-9_-]{1,64}"
[[step]]
id = "restart"
kind = "ssh"
cmd = ["sudo", "/usr/local/lib/rackhand/run", "/usr/bin/docker", "compose", "-p", "{{project}}", "restart"]
"#;

pub(crate) const PLAYBOOK: &str = "+++\nname = \"patch-failure\"\nincident_kinds = [\"patch_failed\"]\nautonomy = 1\nrisk = \"normal\"\ntools = [\"get_incident\"]\nhosts = \"incident\"\n+++\n## When\nA patch failed.\n## Read first\nThe log.\n## Do\nLook.\n## Done when\nFixed.\n## Stop and ask if\nUnsure.\n";

pub(crate) fn library(name: &str) -> (Arc<Db>, Library) {
    let dir = std::env::temp_dir().join(format!("rackhand-library-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let db = Arc::new(Db::open(&dir.join("hub.db")).unwrap());
    let (lib, _changes) = Library::new(db.clone(), Audit::new(db.writer()));
    (db, lib)
}

#[tokio::test(flavor = "multi_thread")]
async fn edit_creates_revision_and_keeps_history() {
    let (_, lib) = library("history");
    assert_eq!(lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", 1_000).await.unwrap(), 1);
    let edited = RUNBOOK.replace("Restart one Docker Compose project", "Restart a Compose project");
    assert_eq!(lib.save(Kind::Runbook, "compose-restart", &edited, "alice", 2_000).await.unwrap(), 2);
    assert_eq!(lib.current(Kind::Runbook, "compose-restart").unwrap().unwrap(), (2, edited.clone()));
    assert_eq!(lib.revision(Kind::Runbook, "compose-restart", 1).unwrap().unwrap(), RUNBOOK, "old content readable");
    let history = lib.history(Kind::Runbook, "compose-restart").unwrap();
    assert_eq!(history.iter().map(|h| (h.rev, h.author.as_str())).collect::<Vec<_>>(), [(2, "alice"), (1, "admin")]);
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_runbook_refused_on_save_with_errors() {
    let (_, lib) = library("invalid");
    let bad = RUNBOOK.replace("kind = \"ssh\"", "kind = \"teleport\"");
    match lib.save(Kind::Runbook, "compose-restart", &bad, "admin", 1).await {
        Err(SaveError::Invalid(e)) => assert!(e.contains("line") && e.contains("teleport"), "{e}"),
        other => panic!("{other:?}"),
    }
    let mismatched = RUNBOOK.replace("name = \"compose-restart\"", "name = \"other\"");
    assert!(
        matches!(lib.save(Kind::Runbook, "compose-restart", &mismatched, "admin", 1).await, Err(SaveError::Invalid(_))),
        "the name must match"
    );
    assert!(matches!(
        lib.save(Kind::Playbook, "patch-failure", "no front matter", "admin", 1).await,
        Err(SaveError::Invalid(_))
    ));
    assert!(lib.save(Kind::Playbook, "patch-failure", PLAYBOOK, "admin", 1).await.is_ok());
    assert!(lib.current(Kind::Runbook, "compose-restart").unwrap().is_none(), "nothing stored");
}

#[tokio::test(flavor = "multi_thread")]
async fn changes_are_audited() {
    let (db, lib) = library("audited");
    lib.save(Kind::Runbook, "compose-restart", RUNBOOK, "admin", 1).await.unwrap();
    let draft = lib
        .propose(Kind::Playbook, "patch-failure", PLAYBOOK, "job:01J", "the assistant suggests it", 2)
        .await
        .unwrap();
    lib.apply_draft(&draft, "admin", 3).await.unwrap();
    let rows: Vec<(String, String, String)> = db
        .readers()
        .with(|c| {
            let mut s = c.prepare("SELECT actor, action, COALESCE(target, '') FROM audit_log ORDER BY seq")?;
            let rows = s.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
            rows.collect()
        })
        .unwrap();
    let actions: Vec<(&str, &str, &str)> = rows.iter().map(|(a, b, c)| (a.as_str(), b.as_str(), c.as_str())).collect();
    assert_eq!(
        actions,
        [
            ("admin", "library.saved", "runbook/compose-restart"),
            ("job:01J", "library.draft_proposed", "playbook/patch-failure"),
            ("admin", "library.saved", "playbook/patch-failure"),
        ]
    );
    assert_eq!(lib.current(Kind::Playbook, "patch-failure").unwrap().unwrap().0, 1, "applied as a revision");
}
