use crate::db::Db;

use super::db::temp;

#[test]
fn pool_has_four_read_only_connections() {
    let db = Db::open(&temp("reader")).unwrap();
    let pool = db.readers();
    assert_eq!(pool.size(), 4);
    let n: i64 = pool.with(|c| c.query_row("SELECT count(*) FROM sites", [], |r| r.get(0))).unwrap();
    assert_eq!(n, 0);
    let write =
        pool.with(|c| c.execute("INSERT INTO sites (id, name, timezone, is_local) VALUES ('x', 'a', 'UTC', 1)", []));
    assert!(write.is_err(), "a write through a reader fails");
}
