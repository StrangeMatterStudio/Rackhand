//! M1 on the lab (plan L2): the build `cargo xtask lab deploy` put on `hub` enrolls `target` with the 7.3.12 install
//! command, watches it, calls out and recovers. The hub runs as its shipped unit (7.1, 5.2 security, AC67); in a Docker
//! container systemd 252 can't give a service's user its `LoadCredential` directory, so the integration tier can't run
//! these (T41, D52).

use std::time::{Duration, Instant};

use crate::hub::{
    self, Dash, HOOK_NAME, UNIT, chart_xs, ensure_notifier, ensure_target, ensure_unit, gap_ratio, hook_posts, lag,
    live, machine_id, metrics, metrics_token, open_incidents, resolved_titles, series,
};
use crate::{eventually, lab, ok_on, on};

#[test]
fn hub_service_runs_unprivileged_and_healthz_ok() {
    assert_eq!(on("hub", "curl -sk https://127.0.0.1:8443/healthz").trim(), "ok");
    let uid =
        on("hub", "pid=$(systemctl show -p MainPID --value rackhand-hub); awk '/^Uid:/ {print $2}' /proc/$pid/status");
    let uid = uid.trim();
    assert!(!uid.is_empty() && uid != "0", "the hub runs as uid {uid}");
    // the page before first run, a redirect to the overview once the deploy has completed it
    let first_run =
        on("hub", "curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' https://127.0.0.1:8443/first-run");
    let first_run = first_run.trim();
    assert!(first_run == "200" || first_run.starts_with("303 "), "first run answers: {first_run}");
}

#[test]
fn hub_user_cannot_open_master_key_by_path() {
    assert!(!ok_on("hub", "sudo -u rackhand-hub cat /etc/rackhand/master.key"), "refused by path");
    assert_eq!(on("hub", "sudo stat -c '%a %U' /etc/rackhand/master.key").trim(), "600 root");
}

#[test]
fn hub_serves_dashboard_and_metrics() {
    assert!(hub::healthy(), "the hub isn't reachable");
    // the password alone signs nobody in (AC40)
    let browser = Dash::fresh("second-factor");
    browser.password_step();
    assert_ne!(browser.get("/").0, 200, "signed in without the second factor");
    assert!(browser.get("/sign-in/code").1.contains("name=\"code\""), "the code is asked for");
    browser.sign_in();
    assert_eq!(browser.get("/").0, 200);
    // /metrics: 401 without the token; with it, the hub's internals and the target's series (AC49)
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    ensure_target(&dash, &token);
    assert_eq!(metrics("not-the-token").0, 401);
    assert_eq!(Dash::fresh("no-token").get("/metrics").0, 401);
    let (code, scrape) = metrics(&token);
    assert_eq!(code, 200);
    assert!(scrape.contains("rackhand_hub_ingest_reports_total"), "{scrape}");
    for m in hub::VITALS {
        assert!(series(&scrape, m, "target").is_some(), "no {m} for target: {scrape}");
    }
}

#[test]
fn target_installs_and_reports_within_30s() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    let id = ensure_target(&dash, &token);
    let install = hub::read_install().expect("the fixture records the install");
    assert_eq!(install.machine, id, "measured on this hub's enrollment of target");
    assert_eq!(install.access, "managed");
    assert!(install.vitals_s <= 30.0, "vitals after {} s", install.vitals_s);
    assert!(install.services_s <= 30.0, "services after {} s", install.services_s);
    assert!(install.updates_s <= 30.0, "pending updates after {} s", install.updates_s);
    // managed: the hub's accounts and sudoers are in place, checked by visudo
    assert!(ok_on("target", "id rackhand && id rackhand-ai && sudo visudo -c -f /etc/sudoers.d/rackhand"));
}

#[test]
fn tampered_probe_stops_the_install() {
    // a copy of the release whose probe changed after it was signed, served on another port
    let good = hub::lab_dir().join("release");
    let bad = hub::lab_dir().join("release-tampered");
    let _ = std::fs::remove_dir_all(&bad);
    std::fs::create_dir_all(&bad).unwrap();
    for entry in std::fs::read_dir(&good).expect("a deployed release") {
        let p = entry.unwrap().path();
        std::fs::copy(&p, bad.join(p.file_name().unwrap())).unwrap();
    }
    let probe = bad.join("rackhand-probe-x86_64-unknown-linux-musl");
    let mut data = std::fs::read(&probe).unwrap();
    let n = data.len() / 2;
    data[n] ^= 0xff;
    std::fs::write(&probe, data).unwrap();
    let mut server = std::process::Command::new("python3")
        .args(["-m", "http.server", "8791", "--bind", "0.0.0.0", "--directory"])
        .arg(&bad)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let listening = || std::net::TcpStream::connect(("127.0.0.1", 8791)).is_ok();
    assert!(eventually(Duration::from_secs(15), listening), "the tampered release server listens");
    // the hub machine has no probe; the install there must stop before installing anything
    assert!(ok_on("hub", "test ! -e /usr/local/lib/rackhand/rackhand-probe"), "the hub machine already has a probe");
    let ticket = format!("rackhand1:{}@{}:7443", "0".repeat(64), hub::HUB_ADDR);
    let cmd = hub::install_command("http://10.0.2.2:8791", &ticket, "not-a-token");
    let out = crate::xtask(&["lab", "run", "hub", "--", &format!("{cmd} 2>&1")]);
    let _ = server.kill();
    let _ = server.wait();
    let said = String::from_utf8_lossy(&out.stdout).to_string() + &String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "the install went through: {said}");
    assert!(said.contains("isn't signed by a pinned release key"), "{said}");
    assert!(
        ok_on(
            "hub",
            "test ! -e /usr/local/lib/rackhand/rackhand-probe && ! id rackhand-probe && \
             test ! -e /etc/systemd/system/rackhand-probe.service && test ! -e /etc/rackhand-probe"
        ),
        "something was installed"
    );
}

/// Seconds since `start`.
fn since(start: Instant) -> u64 {
    start.elapsed().as_secs()
}

#[test]
fn stopped_service_calls_out_and_resolves() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    ensure_target(&dash, &token);
    ensure_notifier(&dash);
    ensure_unit();
    let before = hook_posts().len();
    let start = Instant::now();
    hub::fail_unit();
    let critical = |p: &String| p.contains("CRITICAL") && p.contains(UNIT);
    assert!(
        eventually(Duration::from_secs(180), || hook_posts()[before..].iter().any(critical)),
        "no critical callout for {UNIT} within 180 s of it failing; posts: {:?}",
        &hook_posts()[before..]
    );
    println!("critical callout {} s after the unit failed", since(start));
    let open = open_incidents(&dash);
    assert!(
        open.iter().any(|i| i.title.contains(UNIT) && i.machine == "target" && i.severity == "critical"),
        "{open:?}"
    );
    let after = hook_posts().len();
    let start = Instant::now();
    hub::recover_unit();
    let resolved = |p: &String| p.contains("RESOLVED") && p.contains(UNIT);
    assert!(
        eventually(Duration::from_secs(120), || hook_posts()[after..].iter().any(resolved)),
        "no resolution within 120 s of the unit running again"
    );
    println!("resolution {} s after the unit recovered", since(start));
    assert!(!open_incidents(&dash).iter().any(|i| i.title.contains(UNIT)), "the incident is still open");
    println!("notifier {HOOK_NAME} got {} posts in this test", hook_posts().len() - before);
}

fn silent(dash: &Dash) -> Option<hub::Open> {
    open_incidents(dash).into_iter().find(|i| i.machine == "target" && i.title == "No report from the machine")
}

/// How far a machine's clock is behind WSL's after it was frozen.
fn clock_lag(machine: &str) -> i64 {
    let theirs: i64 = on(machine, "date +%s").trim().parse().unwrap();
    let ours = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
    ours - theirs
}

#[test]
fn paused_target_raises_silence_warning() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    ensure_target(&dash, &token);
    assert!(silent(&dash).is_none(), "target is already silent");
    // no silence in the hub's first 3 minutes (E44): after the reboot test the hub may have only just started
    let up = hub::hub_uptime_s();
    if up < 190 {
        std::thread::sleep(Duration::from_secs(190 - up));
    }
    lab(&["pause", "target"]);
    let start = Instant::now();
    let mut seen = None;
    let opened = eventually(Duration::from_secs(150), || {
        seen = silent(&dash);
        seen.is_some()
    });
    let took = since(start);
    lab(&["resume", "target"]);
    // a frozen VM's clock stays behind when it resumes, which a real machine's doesn't; set it from WSL's at once, so
    // at most one report carries the old time and the hub sees no clock skew
    let behind = clock_lag("target");
    hub::set_clock("target");
    assert!(opened, "no silence warning within 150 s of the pause");
    println!("silence warning {took} s after the pause");
    assert!(took >= 40, "the silence warning came after {took} s, before the 60 s the rule waits");
    assert_eq!(seen.map(|i| i.severity).as_deref(), Some("warning"));
    let start = Instant::now();
    assert!(eventually(Duration::from_secs(90), || silent(&dash).is_none()), "the warning didn't clear after resume");
    println!("cleared {} s after resume; target's clock was {behind} s behind and was set", since(start));
    assert!(clock_lag("target").abs() <= 2, "target's clock is set");
    std::thread::sleep(Duration::from_secs(30));
    let open = open_incidents(&dash);
    let left =
        |i: &hub::Open| i.machine == "target" && (i.title == "No report from the machine" || i.title.contains("clock"));
    assert!(!open.iter().any(left), "the pause left no silence or clock skew open: {open:?}");
}

#[test]
fn cut_link_backfills_without_stale_incidents() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    let id = ensure_target(&dash, &token);
    // what was open for target before the cut (another milestone's check, say) isn't the cut's doing
    let before: Vec<String> =
        open_incidents(&dash).into_iter().filter(|i| i.machine == "target").map(|i| i.title).collect();
    lab(&["cut", "target"]);
    let cut = Instant::now();
    std::thread::sleep(Duration::from_secs(600));
    lab(&["heal", "target"]);
    let healed = Instant::now();
    // the probe's reconnect backoff tops out at 60 s; once it's back, live data stays under 30 s old while the
    // buffered 10 minutes replay (AC2)
    assert!(
        eventually(Duration::from_secs(90), || live(&token, "target", 30.0)),
        "target's live data wasn't back within 90 s of the heal"
    );
    println!("live again {} s after the heal", since(healed));
    let mut worst = 0.0f64;
    let filled = eventually(Duration::from_secs(900), || {
        worst = worst.max(lag(&token, "target").unwrap_or(f64::INFINITY));
        // the cut leaves a hole of 40 intervals until it fills; a pause in an earlier test leaves one of at most 10
        gap_ratio(&chart_xs(&dash, &id, "cpu.busy_pct")) < 20.0
    });
    let xs = chart_xs(&dash, &id, "cpu.busy_pct");
    assert!(filled, "the cut's 10 minutes never filled in: gap ratio {}", gap_ratio(&xs));
    println!(
        "the gap filled {} s after the heal ({} points); live lag at most {worst:.0} s during the replay",
        since(healed),
        xs.len()
    );
    assert!(worst <= 35.0, "live data fell {worst:.0} s behind during the replay");
    assert!(cut.elapsed() < Duration::from_secs(3600), "the chart's hour still covers the cut");
    // no incident left open for target once it's back: the silence warning resolved, nothing opened from old samples
    assert!(
        eventually(Duration::from_secs(120), || {
            !open_incidents(&dash).iter().any(|i| i.machine == "target" && !before.contains(&i.title))
        }),
        "stale incidents for target: {:?}",
        open_incidents(&dash)
    );
}

#[test]
fn hub_reboot_keeps_history_and_rules() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    let id = ensure_target(&dash, &token);
    ensure_notifier(&dash);
    ensure_unit();
    hub::fail_unit();
    let critical = |d: &Dash| open_incidents(d).into_iter().any(|i| i.title.contains(UNIT) && i.severity == "critical");
    assert!(eventually(Duration::from_secs(180), || critical(&dash)), "no open incident before the reboot");
    let points = chart_xs(&dash, &id, "cpu.busy_pct").len();
    let resolved = resolved_titles(&dash);
    hub::reboot("hub");
    hub::wait_healthy(Duration::from_secs(120));
    let dash = Dash::shared().signed_in();
    assert!(critical(&dash), "the open incident survived the reboot");
    assert!(chart_xs(&dash, &id, "cpu.busy_pct").len() + 8 >= points, "history kept: {points} points before");
    let now = resolved_titles(&dash);
    assert!(resolved.iter().all(|t| now.contains(t)), "resolved incidents kept: {resolved:?} then {now:?}");
    let (_, page) = dash.get("/settings/notifiers");
    assert!(page.contains(HOOK_NAME) && page.contains("running"), "the notifier is kept and runs: {page}");
    let token = metrics_token();
    assert!(eventually(Duration::from_secs(120), || live(&token, "target", 30.0)), "target didn't reconnect");
    hub::ensure_hook();
    let before = hook_posts().len();
    hub::recover_unit();
    let resolution = |p: &String| p.contains("RESOLVED") && p.contains(UNIT);
    assert!(
        eventually(Duration::from_secs(120), || hook_posts()[before..].iter().any(resolution)),
        "the incident opened before the reboot resolves after it"
    );
}

#[test]
fn backup_restores_on_a_fresh_hub() {
    let dash = Dash::shared().signed_in();
    let token = metrics_token();
    let id = ensure_target(&dash, &token);
    let probe_toml = on("target", "sudo sha256sum /etc/rackhand-probe/probe.toml");
    let file = on("hub", "sudo /usr/local/bin/rackhand hub backup").trim().to_string();
    // a backup the owner takes as root leaves the directory to the hub, whose 02:00 backup writes and prunes there
    let dir = "/var/lib/rackhand/backups";
    assert!(
        ok_on("hub", &format!("sudo -u rackhand-hub test -w {dir} && sudo -u rackhand-hub test -r {file}")),
        "after `sudo rackhand hub backup`: {}",
        on("hub", &format!("sudo ls -la {dir}"))
    );
    // the backup and the master key leave the machine, as an owner would keep them
    let backup = hub::lab_dir().join("live-backup.rhbk");
    let key = hub::lab_dir().join("live-master.key");
    std::fs::write(&backup, hub::fetch("hub", &file)).unwrap();
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(&key).unwrap();
        std::io::Write::write_all(&mut f, &hub::fetch("hub", "/etc/rackhand/master.key")).unwrap();
    }
    let points = chart_xs(&dash, &id, "cpu.busy_pct").len();
    let resolved = resolved_titles(&dash);
    lab(&["reset", "hub"]);
    assert!(eventually(Duration::from_secs(300), || ok_on("hub", "true")), "hub after reset");
    assert!(ok_on("hub", "test ! -e /etc/rackhand/master.key"), "the reset left a hub behind");
    let restored = Instant::now();
    hub::deploy(&["--restore", backup.to_str().unwrap(), "--master-key", key.to_str().unwrap()]);
    let dash = Dash::shared().signed_in();
    assert_eq!(machine_id(&dash, "target").as_deref(), Some(id.as_str()), "the same machine, not a new one");
    let now = chart_xs(&dash, &id, "cpu.busy_pct").len();
    let aged = (restored.elapsed().as_secs() / 15) as usize + 8;
    assert!(now + aged >= points, "history is back: {points} points before, {now} after");
    let titles = resolved_titles(&dash);
    assert!(resolved.iter().all(|t| titles.contains(t)), "incidents are back: {resolved:?} then {titles:?}");
    let token = metrics_token();
    assert!(
        eventually(Duration::from_secs(180), || live(&token, "target", 30.0)),
        "target didn't reconnect to the restored hub"
    );
    println!("target reported to the restored hub {} s after the restore began", since(restored));
    assert_eq!(on("target", "sudo sha256sum /etc/rackhand-probe/probe.toml"), probe_toml, "not re-enrolled");
    let _ = std::fs::remove_file(&key);
}
