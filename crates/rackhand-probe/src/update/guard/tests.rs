use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::time::Duration;

use super::*;
use crate::update::apply::{Paths, Slot};

fn v(text: &str) -> Version {
    Version::parse(text).unwrap()
}

struct Machine {
    dir: PathBuf,
    paths: Paths,
}

impl Drop for Machine {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

impl Machine {
    /// Slot A runs (and the wrapper is its copy); slot B holds the new release.
    fn new(name: &str) -> Machine {
        let dir = std::env::temp_dir().join(format!("rackhand-guard-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let paths = Paths::new(&dir);
        std::fs::create_dir_all(paths.lib()).unwrap();
        std::fs::write(paths.slot(Slot::A), b"old probe").unwrap();
        std::fs::write(paths.slot(Slot::B), b"new probe").unwrap();
        std::fs::write(paths.wrapper(), b"old probe").unwrap();
        std::os::unix::fs::symlink("probe-a", paths.link()).unwrap();
        Machine { dir, paths }
    }

    fn plan(&self) -> Plan {
        Plan { paths: self.paths.clone(), old: Slot::A, new: Slot::B, version: v("0.1.1") }
    }

    fn running(&self) -> String {
        std::fs::read_link(self.paths.link()).unwrap().to_string_lossy().into_owned()
    }
}

/// A clock that only moves when the guard sleeps, and a state file that says what the test says from a given time on.
struct Fake {
    now: Cell<Duration>,
    restarts: Cell<u32>,
    /// From this long after the start: the state file's text.
    says: Vec<(Duration, String)>,
    /// What the link pointed at when each restart happened.
    at_restart: RefCell<Vec<String>>,
    link: PathBuf,
}

impl Fake {
    fn new(m: &Machine, says: Vec<(Duration, String)>) -> Fake {
        Fake {
            now: Cell::new(Duration::ZERO),
            restarts: Cell::new(0),
            says,
            at_restart: RefCell::new(Vec::new()),
            link: m.paths.link(),
        }
    }
}

impl Env for Fake {
    fn restart(&self) -> Result<(), String> {
        self.restarts.set(self.restarts.get() + 1);
        let at = std::fs::read_link(&self.link).unwrap().to_string_lossy().into_owned();
        self.at_restart.borrow_mut().push(at);
        Ok(())
    }

    fn state(&self) -> Option<String> {
        let now = self.now.get();
        self.says.iter().rev().find(|(from, _)| *from <= now).map(|(_, text)| text.clone())
    }

    fn sleep(&self, d: Duration) {
        self.now.set(self.now.get() + d);
    }

    fn elapsed(&self) -> Duration {
        self.now.get()
    }
}

fn state(state: &str, version: &str) -> String {
    format!(r#"{{"state":"{state}","version":"{version}","at_ms":1}}"#)
}

#[test]
fn a_probe_that_connects_with_the_new_version_is_kept() {
    let m = Machine::new("kept");
    let env = Fake::new(
        &m,
        vec![(Duration::ZERO, state("connecting", "0.1.0")), (Duration::from_secs(14), state("connected", "0.1.1"))],
    );
    assert_eq!(run(&m.plan(), &env), Outcome::Kept);
    assert_eq!(m.running(), "probe-b");
    assert_eq!(std::fs::read(m.paths.wrapper()).unwrap(), b"new probe", "the command wrapper is the new version too");
    assert_eq!(env.restarts.get(), 1);
    assert_eq!(*env.at_restart.borrow(), ["probe-b"], "the services were restarted after the switch");
    assert!(env.elapsed() < Duration::from_secs(20), "it stops waiting when the probe is connected");
}

#[test]
fn broken_release_restored_within_two_minutes() {
    let m = Machine::new("broken");
    // the new probe never says anything; the old one's last words are still in the file
    let env = Fake::new(&m, vec![(Duration::ZERO, state("connected", "0.1.0"))]);
    assert_eq!(run(&m.plan(), &env), Outcome::RolledBack);
    assert_eq!(m.running(), "probe-a");
    assert_eq!(std::fs::read(m.paths.wrapper()).unwrap(), b"old probe");
    assert_eq!(*env.at_restart.borrow(), ["probe-b", "probe-a"], "restarted onto the new, then back onto the old");
    assert!(env.elapsed() >= TIMEOUT && env.elapsed() < TIMEOUT + Duration::from_secs(10), "{:?}", env.elapsed());
    assert_eq!(std::fs::read(m.paths.slot(Slot::B)).unwrap(), b"new probe", "the failed slot is left for inspection");
}

#[test]
fn only_connected_with_the_new_version_counts() {
    for (name, says) in [
        ("old version connected", state("connected", "0.1.0")),
        ("new version connecting", state("connecting", "0.1.1")),
        ("new version waiting to retry", state("disconnected", "0.1.1")),
        ("a state that isn't json", "connected 0.1.1".to_string()),
        ("a newer version than the one installed", state("connected", "0.1.2")),
        ("connected without a version", r#"{"state":"connected"}"#.to_string()),
    ] {
        let m = Machine::new("counts");
        let env = Fake::new(&m, vec![(Duration::ZERO, says)]);
        assert_eq!(run(&m.plan(), &env), Outcome::RolledBack, "{name}");
        assert_eq!(m.running(), "probe-a", "{name}");
    }
}

#[test]
fn a_switch_that_cannot_be_made_changes_nothing_and_restarts_nothing() {
    let m = Machine::new("noswitch");
    std::fs::remove_file(m.paths.slot(Slot::B)).unwrap();
    let env = Fake::new(&m, vec![(Duration::ZERO, state("connected", "0.1.1"))]);
    assert_eq!(run(&m.plan(), &env), Outcome::NotSwitched);
    assert_eq!(m.running(), "probe-a");
    assert_eq!(env.restarts.get(), 0);
}

#[test]
fn the_slots_are_named_by_the_helper_and_nothing_else_is_accepted() {
    assert_eq!(parse_args(&["probe-a".into(), "probe-b".into(), "0.1.1".into()]).unwrap().new, Slot::B);
    for bad in [
        vec!["probe-a", "probe-a", "0.1.1"],
        vec!["/etc/passwd", "probe-b", "0.1.1"],
        vec!["probe-a", "../probe-b", "0.1.1"],
        vec!["probe-a", "probe-b", "latest"],
        vec!["probe-a", "probe-b"],
        vec!["probe-a", "probe-b", "0.1.1", "extra"],
    ] {
        let args: Vec<String> = bad.iter().map(|s| s.to_string()).collect();
        assert!(parse_args(&args).is_err(), "{bad:?}");
    }
}
