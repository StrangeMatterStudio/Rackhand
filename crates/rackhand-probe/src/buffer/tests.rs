use std::collections::BTreeMap;

use super::epoch::{EpochState, Received};
use super::labels::LabelTable;
use super::segments::{Buffer, Dropped, Limits};

fn dir(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("rackhand-buffer-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const NOW: i64 = 1_800_000_000_000;

fn small() -> Limits {
    Limits { segment_bytes: 4096, max_bytes: 16 * 1024, max_age_ms: 24 * 3600 * 1000 }
}

mod buffer {
    use super::*;

    #[test]
    fn cap_from_hub_drops_oldest_with_ranges() {
        let d = dir("cap");
        let mut b = Buffer::open(&d, Limits::default(), NOW).unwrap();
        let payload = vec![7u8; 10_000];
        for seq in 1..=200 {
            b.append(3, seq, NOW + seq as i64, &payload, NOW).unwrap();
        }
        assert!(b.take_dropped().is_empty(), "2 MB fits under the default 64 MB");
        b.set_max_bytes(1024 * 1024).unwrap();
        assert!(b.total_bytes() <= 1024 * 1024, "{} bytes kept", b.total_bytes());
        let dropped = b.take_dropped();
        assert_eq!(dropped.first().map(|d| (d.epoch, d.from_seq)), Some((3, 1)), "the oldest go first: {dropped:?}");
        let kept_from = b.pending().next().unwrap().seq;
        assert_eq!(dropped.last().unwrap().to_seq + 1, kept_from, "every dropped report is in a range");
        for seq in 201..=400 {
            b.append(3, seq, NOW + seq as i64, &payload, NOW).unwrap();
        }
        assert!(b.total_bytes() <= 1024 * 1024, "the cap holds for new reports");
    }

    #[test]
    fn reports_survive_restart_in_order() {
        let d = dir("restart");
        {
            let mut b = Buffer::open(&d, Limits::default(), NOW).unwrap();
            for seq in 1..=10 {
                b.append(7, seq, NOW + seq as i64, format!("report {seq}").as_bytes(), NOW).unwrap();
            }
        }
        let b = Buffer::open(&d, Limits::default(), NOW).unwrap();
        let seqs: Vec<u64> = b.pending().map(|r| r.seq).collect();
        assert_eq!(seqs, (1..=10).collect::<Vec<u64>>());
        assert_eq!(b.read(7, 4).unwrap(), b"report 4");
        assert_eq!(Limits::default().max_bytes, 64 * 1024 * 1024, "design default");
        assert_eq!(Limits::default().segment_bytes, 4 * 1024 * 1024, "design default");
    }

    #[test]
    fn full_buffer_drops_oldest_and_records_range() {
        let d = dir("full");
        let mut b = Buffer::open(&d, small(), NOW).unwrap();
        let payload = vec![0xabu8; 1000];
        for seq in 1..=40 {
            b.append(7, seq, NOW, &payload, NOW).unwrap();
        }
        assert!(b.total_bytes() <= small().max_bytes, "{} bytes", b.total_bytes());
        let dropped = b.take_dropped();
        assert!(!dropped.is_empty());
        assert_eq!(dropped[0], Dropped { epoch: 7, from_seq: 1, to_seq: dropped[0].to_seq });
        let first_kept = b.pending().next().unwrap().seq;
        assert_eq!(dropped.last().unwrap().to_seq + 1, first_kept, "dropped ranges end where the kept reports begin");
    }

    #[test]
    fn reports_older_than_24h_are_dropped() {
        let d = dir("age");
        let mut b = Buffer::open(&d, small(), NOW).unwrap();
        b.append(7, 1, NOW, b"old", NOW).unwrap();
        let later = NOW + 24 * 3600 * 1000 + 1;
        b.append(7, 2, later, b"new", later).unwrap();
        b.expire(later).unwrap();
        let seqs: Vec<u64> = b.pending().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![2]);
        assert_eq!(b.take_dropped(), vec![Dropped { epoch: 7, from_seq: 1, to_seq: 1 }]);
    }

    #[test]
    fn ack_ranges_delete_only_inside_ranges() {
        let d = dir("ack");
        let mut b = Buffer::open(&d, Limits::default(), NOW).unwrap();
        for seq in 1..=10 {
            b.append(7, seq, NOW, b"r", NOW).unwrap();
        }
        b.ack(7, &[(1, 5), (8, 9)]).unwrap();
        let seqs: Vec<u64> = b.pending().map(|r| r.seq).collect();
        assert_eq!(seqs, vec![6, 7, 10]);
        b.ack(8, &[(6, 7)]).unwrap();
        assert_eq!(b.pending().count(), 3, "an ack for another epoch deletes nothing");
    }
}

mod epoch {
    use super::*;

    #[test]
    fn empty_buffer_starts_new_random_epoch() {
        let a = EpochState::start(None);
        let b = EpochState::start(None);
        assert_ne!(a.epoch(), b.epoch(), "random epochs");
        assert_eq!(a.peek_seq(), 1);
        let resumed = EpochState::start(Some((a.epoch(), 41)));
        assert_eq!((resumed.epoch(), resumed.peek_seq()), (a.epoch(), 42), "a backlog keeps its epoch");
    }

    #[test]
    fn hub_ahead_starts_new_epoch_even_with_backlog() {
        let mut s = EpochState::start(Some((99, 10)));
        assert_eq!(s.peek_seq(), 11);
        let changed = s.on_welcome(&Received { epoch: 99, ranges: vec![(1, 12)] });
        assert!(changed, "the hub already holds seq 11 of this epoch (a rolled-back guest)");
        assert_ne!(s.epoch(), 99);
        assert_eq!(s.peek_seq(), 1);
        let mut t = EpochState::start(Some((99, 10)));
        assert!(!t.on_welcome(&Received { epoch: 99, ranges: vec![(1, 8)] }), "the hub is behind: keep the epoch");
    }
}

mod labels {
    use super::*;

    fn set(k: &str, v: &str) -> BTreeMap<String, String> {
        BTreeMap::from([(k.to_string(), v.to_string())])
    }

    #[test]
    fn ids_never_reused_within_epoch() {
        let d = dir("labels");
        let mut t = LabelTable::open(&d, 7).unwrap();
        let a = t.id_for(&set("mount", "/"));
        let b = t.id_for(&set("mount", "/data"));
        assert_ne!(a, b);
        assert_eq!(t.id_for(&set("mount", "/")), a, "the same set keeps its id");
        t.forget(&set("mount", "/data"));
        let again = t.id_for(&set("mount", "/data"));
        assert!(again != b && again != a, "a removed set added again gets a new id");
        let reopened = LabelTable::open(&d, 7).unwrap();
        assert_eq!(reopened.entries().len(), t.entries().len(), "the table persists next to the buffer");
    }

    #[test]
    fn table_near_4096_rolls_epoch_when_buffer_empty() {
        let d = dir("labels-full");
        let mut t = LabelTable::open(&d, 7).unwrap();
        for i in 0..4090 {
            t.id_for(&set("iface", &format!("if{i}")));
        }
        assert!(!t.needs_new_epoch(false), "wait for the buffer to drain");
        assert!(t.needs_new_epoch(true));
    }
}
