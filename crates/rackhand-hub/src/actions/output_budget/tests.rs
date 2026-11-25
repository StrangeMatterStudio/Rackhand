use super::{DEFAULT_BUDGET, MB, enforce};

fn temp_db(name: &str) -> (rackhand_store::Db, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("rackhand-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("hub.db");
    (rackhand_store::Db::open(&path).unwrap(), path)
}

const PART: usize = 1_000_000;

fn ids(db: &rackhand_store::Db, sql: &str) -> Vec<String> {
    db.readers()
        .with(|c| {
            let mut s = c.prepare(sql)?;
            s.query_map([], |r| r.get::<_, String>(0))?.collect::<Result<Vec<_>, _>>()
        })
        .unwrap()
}

#[tokio::test(flavor = "multi_thread")]
async fn oldest_trimmed_first_metadata_kept() {
    assert_eq!(DEFAULT_BUDGET, 100 * MB, "100 MB (7.4.1, 7.8.1)");
    let (db, path) = temp_db("output-budget");
    {
        let conn = rusqlite::Connection::open(&path).unwrap();
        for (job, ended) in [("a", 1_000), ("b", 2_000), ("c", 3_000)] {
            conn.execute(
                "INSERT INTO jobs (id, kind, name, requested_by, state) VALUES (?1, 'runbook', 'r', 'u', 'succeeded')",
                [job],
            )
            .unwrap();
            conn.execute(
                "INSERT INTO job_steps (job_id, step_id, state, stdout, ended_at) VALUES (?1, 's', 'succeeded', ?2, ?3)",
                rusqlite::params![job, vec![b'x'; PART], ended],
            )
            .unwrap();
        }
        // a transcript between b's step and c's
        conn.execute(
            "INSERT INTO assistant_transcripts (job_id, seq, at_ms, kind, text) VALUES ('b', 1, 2_500, 'turn', ?1)",
            ["y".repeat(PART / 2)],
        )
        .unwrap();
    }
    // 3.5 MB over a 2 MB budget: the oldest go until it fits
    let trimmed = enforce(&db, 2 * PART as u64).await.unwrap();
    assert_eq!(trimmed, 2, "a's and b's output");
    let steps = ids(
        &db,
        "SELECT job_id || ':' || CASE WHEN stdout IS NULL THEN 'trimmed' ELSE 'kept' END FROM job_steps ORDER BY job_id",
    );
    assert_eq!(steps, ["a:trimmed", "b:trimmed", "c:kept"], "oldest first; every step row stays");
    assert_eq!(
        ids(&db, "SELECT CASE WHEN text IS NULL THEN 'trimmed' ELSE 'kept' END FROM assistant_transcripts"),
        ["kept"]
    );
    assert_eq!(ids(&db, "SELECT id FROM jobs ORDER BY id"), ["a", "b", "c"], "the jobs stay");
    assert_eq!(enforce(&db, 2 * PART as u64).await.unwrap(), 0, "within its budget, nothing more");
}
