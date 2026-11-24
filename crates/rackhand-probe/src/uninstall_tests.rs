use std::cell::RefCell;
use std::path::{Path, PathBuf};

use super::*;

/// A machine that records what is done to it.
struct Fake {
    euid: u32,
    systemd: bool,
    present: Vec<&'static str>,
    log: RefCell<Vec<String>>,
}

impl Fake {
    fn new(euid: u32, systemd: bool) -> Fake {
        Fake { euid, systemd, present: PATHS.to_vec(), log: RefCell::new(Vec::new()) }
    }

    fn log(&self) -> Vec<String> {
        self.log.borrow().clone()
    }

    fn at(&self, what: &str) -> usize {
        let log = self.log();
        log.iter().position(|l| l.contains(what)).unwrap_or_else(|| panic!("{what} not in {log:?}"))
    }
}

impl Host for Fake {
    fn euid(&self) -> u32 {
        self.euid
    }

    fn exists(&self, path: &Path) -> bool {
        let rel = path.strip_prefix("/m").unwrap();
        rel == Path::new("run/systemd/system") && self.systemd
            || self.present.iter().any(|p| rel == Path::new(p) || rel.starts_with(p))
    }

    fn run(&self, argv: &[&str]) -> bool {
        self.log.borrow_mut().push(format!("run {}", argv.join(" ")));
        true
    }

    fn remove(&self, path: &Path) {
        self.log.borrow_mut().push(format!("remove {}", path.display()));
    }

    fn spawn_detached(&self, argv: &[String]) -> std::io::Result<()> {
        self.log.borrow_mut().push(format!("spawn {}", argv.join(" ")));
        Ok(())
    }

    fn sleep(&self, seconds: u64) {
        self.log.borrow_mut().push(format!("sleep {seconds}"));
    }
}

fn options(after: Option<u64>) -> Options {
    Options { root: PathBuf::from("/m"), after, delayed: false }
}

/// 7.3.12: only root removes it, and only what the table of paths names.
#[test]
fn probe_uninstall_needs_root_and_touches_only_its_own() {
    let user = Fake::new(998, true);
    assert_eq!(uninstall(&options(None), &user), Err(UninstallError::NotRoot));
    assert!(user.log().is_empty(), "nothing is done by anyone else: {:?}", user.log());
    let root = Fake::new(0, true);
    uninstall(&options(None), &root).unwrap();
    let removed: Vec<String> =
        root.log().iter().filter_map(|l| l.strip_prefix("remove /m/")).map(str::to_string).collect();
    let mut expected: Vec<&str> = PATHS.to_vec();
    expected.sort_unstable();
    let mut got: Vec<&str> = removed.iter().map(String::as_str).collect();
    got.sort_unstable();
    assert_eq!(got, expected, "exactly the table's paths");
    assert!(removed.iter().all(|p| !p.contains("..") && !p.starts_with('/')), "{removed:?}");
    for must in ["etc/sudoers.d/rackhand", "etc/rackhand", "etc/rackhand-probe", "usr/local/lib/rackhand"] {
        assert!(PATHS.contains(&must), "{must}");
    }
}

/// Services first (the probe stops reporting), then the way in (sudoers, the list, the keys with the users), and the
/// directory the binary and wrapper are in last.
#[test]
fn probe_uninstall_cuts_access_before_removing_files() {
    let m = Fake::new(0, true);
    uninstall(&options(None), &m).unwrap();
    let log = m.log();
    let stop = m.at("systemctl disable --now rackhand-probe.service rackhand-probe-helper.service");
    assert!(stop == 0, "services first: {log:?}");
    assert!(m.at("remove /m/etc/sudoers.d/rackhand") < m.at("userdel"), "no sudo, then no users: {log:?}");
    for user in ["rackhand", "rackhand-ai", "rackhand-probe"] {
        m.at(&format!("userdel --force --remove {user}"));
    }
    assert!(m.at("remove /m/etc/rackhand") < m.at("userdel"));
    assert_eq!(m.at("remove /m/usr/local/lib/rackhand"), log.len() - 1, "the binary last: {log:?}");
    m.at("systemctl daemon-reload");
    assert!(!log.iter().any(|l| l.contains("sh -c") || l.contains(" rm ")), "no shell: {log:?}");
}

#[test]
fn probe_uninstall_on_openrc_uses_its_tools() {
    let m = Fake::new(0, false);
    uninstall(&options(None), &m).unwrap();
    let log = m.log();
    m.at("rc-service rackhand-probe stop");
    m.at("rc-service rackhand-probe-helper stop");
    m.at("rc-update del rackhand-probe default");
    m.at("deluser --remove-home rackhand");
    assert!(!log.iter().any(|l| l.contains("systemctl") || l.contains("userdel")), "{log:?}");
}

/// Run again with nothing left, and for the machine that has no hub users (monitor), it still ends well.
#[test]
fn probe_uninstall_is_safe_to_repeat() {
    let mut m = Fake::new(0, true);
    m.present = vec!["etc/rackhand-probe", "usr/local/lib/rackhand"];
    uninstall(&options(None), &m).unwrap();
    let removed: Vec<String> = m.log().into_iter().filter(|l| l.starts_with("remove ")).collect();
    assert_eq!(removed.len(), 2, "only what is there: {removed:?}");
    let empty = Fake { present: vec![], ..Fake::new(0, true) };
    uninstall(&options(None), &empty).unwrap();
}

/// `--after N` answers at once: it starts a copy of itself that waits N seconds, and does nothing else.
#[test]
fn probe_uninstall_after_schedules_a_copy_and_returns() {
    let m = Fake::new(0, true);
    uninstall(&options(Some(5)), &m).unwrap();
    assert_eq!(m.log(), ["spawn /usr/local/lib/rackhand/rackhand-probe uninstall --delay 5"]);
    let delayed = Fake::new(0, true);
    uninstall(&Options { delayed: true, after: Some(5), ..options(None) }, &delayed).unwrap();
    assert_eq!(delayed.at("sleep 5"), 0, "the copy waits, then removes");
    delayed.at("systemctl disable");
    let not_root = Fake::new(998, true);
    assert_eq!(uninstall(&options(Some(5)), &not_root), Err(UninstallError::NotRoot));
    assert!(not_root.log().is_empty(), "not even scheduled");
}
