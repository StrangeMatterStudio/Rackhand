//! Composition root for the probe and its root helper (design 7.2).

use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rackhand_probe::collect::{self, Config, RootHost, SelfUse, Stamp};

const USAGE: &str = "usage: rackhand-probe --version
       rackhand-probe collect --once --json [--root <dir>] [--interval-ms <n>]
       rackhand-probe run [--config <probe.toml>] [--data-dir <dir>] [--state-file <path>] [--root <dir>]
       rackhand-probe helper [--socket <path>]";

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Installed as /usr/local/lib/rackhand/run, the binary is the command wrapper (7.3.7).
    if std::path::Path::new(&argv0).file_name().is_some_and(|n| n == "run") {
        return rackhand_probe::runcmd::main(&args);
    }
    match args.first().map(String::as_str) {
        Some("run-cmd") => rackhand_probe::runcmd::main(&args[1..]),
        Some("--version") => {
            println!("rackhand-probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("collect") => collect_once(&args[1..]),
        Some("run") => run(&args[1..]),
        #[cfg(target_os = "linux")]
        Some("helper") => helper(&args[1..]),
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

/// `collect --once --json`: two snapshots an interval apart (1 s by default), printed as one sample set (7.7.3).
fn collect_once(args: &[String]) -> ExitCode {
    let (mut once, mut json, mut root, mut interval_ms) = (false, false, None, 1000u64);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--once" => once = true,
            "--json" => json = true,
            "--root" => root = it.next().cloned(),
            "--interval-ms" => match it.next().and_then(|v| v.parse().ok()) {
                Some(v) => interval_ms = v,
                None => return usage(),
            },
            _ => return usage(),
        }
    }
    if !(once && json) {
        return usage();
    }
    let host = root.map_or_else(RootHost::system, RootHost::new);
    let cfg = Config::default();
    let start = std::time::Instant::now();
    let first = collect::collect_at(&host, None, Stamp { wall_ms: now_ms(), mono_ms: 0 }, &cfg, SelfUse::default());
    std::thread::sleep(Duration::from_millis(interval_ms));
    let now = now_ms();
    let self_use = SelfUse { rss_bytes: collect::own_rss_bytes(), ..SelfUse::default() };
    let at = Stamp { wall_ms: now, mono_ms: start.elapsed().as_millis() as i64 };
    let second = collect::collect_at(&host, Some(&first.snapshot), at, &cfg, self_use);
    println!("{}", collect::to_json(&second, now));
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// `run`: the probe daemon (7.3.2). Exits 3 when the hub revokes this machine.
fn run(args: &[String]) -> ExitCode {
    let mut paths = rackhand_probe::run::Paths::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(v) = it.next() else { return usage() };
        match a.as_str() {
            "--config" => paths.config = v.into(),
            "--data-dir" => paths.data_dir = v.into(),
            "--state-file" => paths.state_file = v.into(),
            "--root" => paths.root = Some(v.into()),
            _ => return usage(),
        }
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rackhand-probe: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(rackhand_probe::run::main(paths)) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(1)),
        Err(e) => {
            eprintln!("rackhand-probe: {e}");
            ExitCode::from(1)
        }
    }
}

/// `helper`: the root helper (7.3.3).
#[cfg(target_os = "linux")]
fn helper(args: &[String]) -> ExitCode {
    let mut paths = rackhand_probe::helper::daemon::Paths::default();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match (a.as_str(), it.next()) {
            ("--socket", Some(v)) => paths.socket = v.into(),
            _ => return usage(),
        }
    }
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rackhand-probe helper: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(rackhand_probe::helper::daemon::main(paths, env!("CARGO_PKG_VERSION"))) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("rackhand-probe helper: {e}");
            ExitCode::from(1)
        }
    }
}
