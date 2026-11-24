//! Composition root for the probe and its root helper (design 7.2).

use std::process::ExitCode;
#[cfg(not(windows))]
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(not(windows))]
use rackhand_probe::collect::RootHost;
use rackhand_probe::collect::{self, Config, SelfUse, Stamp};

const USAGE: &str = "usage: rackhand-probe --version
       rackhand-probe collect --once --json [--root <dir>] [--interval-ms <n>]
       rackhand-probe security [--seconds <n>] [--every-ms <n>] [--socket <path>]
       rackhand-probe run [--config <probe.toml>] [--data-dir <dir>] [--state-file <path>] [--root <dir>]
       rackhand-probe helper [--socket <path>]
       rackhand-probe enroll --ticket <ticket> --token <token> [--monitor] [--remote] [--role <role>]
       rackhand-probe uninstall [--after <seconds>]";

fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn main() -> ExitCode {
    let argv0 = std::env::args().next().unwrap_or_default();
    let args: Vec<String> = std::env::args().skip(1).collect();
    // Installed as /usr/local/lib/rackhand/run, the binary is the command wrapper (7.3.7).
    #[cfg(unix)]
    if std::path::Path::new(&argv0).file_name().is_some_and(|n| n == "run") {
        return rackhand_probe::runcmd::main(&args);
    }
    #[cfg(not(unix))]
    let _ = &argv0;
    match args.first().map(String::as_str) {
        #[cfg(unix)]
        Some("run-cmd") => rackhand_probe::runcmd::main(&args[1..]),
        Some("--version") => {
            println!("rackhand-probe {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("collect") => collect_once(&args[1..]),
        Some("run") => run(&args[1..]),
        #[cfg(unix)]
        Some("security") => security(&args[1..]),
        #[cfg(unix)]
        Some("enroll") => enroll(&args[1..]),
        #[cfg(unix)]
        Some("uninstall") => uninstall(&args[1..]),
        #[cfg(unix)]
        Some("set-hub") => set_hub(&args[1..]),
        #[cfg(target_os = "linux")]
        Some("helper") => helper(&args[1..]),
        #[cfg(windows)]
        Some("helper") => windows_cmd::helper(&args[1..]),
        #[cfg(windows)]
        Some("service") => windows_cmd::service(&args[1..]),
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
    let cfg = Config::default();
    // Windows has no /proc to read: the collection is CIM's, and the rates come from it already (FR-2)
    #[cfg(windows)]
    {
        let _ = (&root, interval_ms);
        let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("rackhand-probe: {e}");
                return ExitCode::from(1);
            }
        };
        let now = now_ms();
        let at = Stamp { wall_ms: now, mono_ms: 0 };
        let collection = runtime.block_on(rackhand_probe::windows::collect::collect(at, &cfg, SelfUse::default()));
        println!("{}", collect::to_json(&collection, now));
        ExitCode::SUCCESS
    }
    #[cfg(not(windows))]
    {
        let host = root.map_or_else(RootHost::system, RootHost::new);
        two_snapshots(&host, &cfg, interval_ms)
    }
}

/// Two snapshots an interval apart, printed as one sample set.
#[cfg(not(windows))]
fn two_snapshots(host: &RootHost, cfg: &Config, interval_ms: u64) -> ExitCode {
    let start = std::time::Instant::now();
    let first = collect::collect_at(host, None, Stamp { wall_ms: now_ms(), mono_ms: 0 }, cfg, SelfUse::default());
    std::thread::sleep(Duration::from_millis(interval_ms));
    let now = now_ms();
    let self_use = SelfUse { rss_bytes: collect::own_rss_bytes(), ..SelfUse::default() };
    let at = Stamp { wall_ms: now, mono_ms: start.elapsed().as_millis() as i64 };
    let second = collect::collect_at(host, Some(&first.snapshot), at, cfg, self_use);
    println!("{}", collect::to_json(&second, now));
    ExitCode::SUCCESS
}

/// `security`: the sampling capture for a few seconds, printed as one JSON object: the connection records and the events it
/// would report (7.7.3). It asks the helper at `--socket` for who owns each socket.
#[cfg(unix)]
fn security(args: &[String]) -> ExitCode {
    let (mut seconds, mut every_ms) = (10u64, 5000u64);
    let mut socket = rackhand_probe::helper::SOCKET.to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        let Some(v) = it.next() else { return usage() };
        match (a.as_str(), v.parse::<u64>()) {
            ("--seconds", Ok(n)) => seconds = n,
            ("--every-ms", Ok(n)) => every_ms = n.max(100),
            ("--socket", _) => socket = v.clone(),
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
    let helper = rackhand_probe::helper::client::HelperClient::new(socket, env!("CARGO_PKG_VERSION"));
    let out = runtime.block_on(async move {
        let host = RootHost::system();
        let mut sampler = rackhand_probe::security::Sampler::default();
        let mut pending = rackhand_probe::security::Pending::default();
        let end = std::time::Instant::now() + Duration::from_secs(seconds);
        let (mut records, mut events) = (Vec::new(), Vec::new());
        loop {
            let (seen, found) = sampler.tick(&host, Some(&helper), now_ms()).await;
            pending.add(seen, found);
            let (r, e) = pending.take(now_ms());
            records.extend(r);
            events.extend(e);
            if std::time::Instant::now() >= end {
                break;
            }
            tokio::time::sleep(Duration::from_millis(every_ms)).await;
        }
        let records: Vec<serde_json::Value> = records
            .iter()
            .map(|c| {
                let ip = match c.dest_ip.len() {
                    4 => std::net::IpAddr::from(<[u8; 4]>::try_from(&c.dest_ip[..]).unwrap_or_default()).to_string(),
                    16 => std::net::IpAddr::from(<[u8; 16]>::try_from(&c.dest_ip[..]).unwrap_or_default()).to_string(),
                    _ => String::new(),
                };
                serde_json::json!({
                    "container": c.container, "exe": c.exe, "dest_ip": ip, "dest_port": c.dest_port,
                    "count": c.count, "user": c.user, "folded": c.folded,
                })
            })
            .collect();
        let events: Vec<serde_json::Value> =
            events.iter().map(|e| serde_json::json!({ "kind": e.kind, "fields": e.fields })).collect();
        serde_json::json!({ "connections": records, "events": events })
    });
    println!("{out}");
    ExitCode::SUCCESS
}

fn usage() -> ExitCode {
    eprintln!("{USAGE}");
    ExitCode::from(2)
}

/// `run`: the probe daemon (7.3.2). Exits 3 when the hub revokes this machine.
fn run(args: &[String]) -> ExitCode {
    rackhand_probe::logging::init();
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
    rackhand_probe::logging::init();
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

/// `enroll`: the join, as root (the installer runs it). Prints `machine_id=`, `managed=` and `assistant=` lines.
#[cfg(unix)]
fn enroll(args: &[String]) -> ExitCode {
    rackhand_probe::logging::init();
    use rackhand_proto::common::{Access, ProbeMode};
    let (mut ticket, mut token, mut role) = (None, None, String::new());
    let (mut access, mut mode) = (Access::Managed, ProbeMode::Local);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--ticket" => ticket = it.next().cloned(),
            "--token" => token = it.next().cloned(),
            "--monitor" => access = Access::Monitor,
            "--remote" => mode = ProbeMode::Remote,
            "--role" => role = it.next().cloned().unwrap_or_default(),
            _ => return usage(),
        }
    }
    let (Some(ticket), Some(token)) = (ticket, token) else { return usage() };
    let ticket = match rackhand_probe::enroll::Ticket::parse(&ticket) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("rackhand-probe enroll: {e}");
            return ExitCode::from(2);
        }
    };
    let req = rackhand_probe::enroll::Request { ticket, token, access, mode, role };
    let runtime = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("rackhand-probe enroll: {e}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(rackhand_probe::enroll::enroll(&req, &rackhand_probe::enroll::Paths::default())) {
        Ok(e) => {
            println!("machine_id={}\nmanaged={}\nassistant={}", e.machine_id, e.managed, e.assistant);
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-probe enroll: {e}");
            ExitCode::from(1)
        }
    }
}

/// `set-hub <ticket>` (7.7.3, E35): the hub this probe trusts and where it is, from a new ticket; root only.
#[cfg(unix)]
fn set_hub(args: &[String]) -> ExitCode {
    let [ticket] = args else { return usage() };
    let root = rustix::process::geteuid().is_root();
    match rackhand_probe::set_hub::rewrite(std::path::Path::new(rackhand_probe::config::PATH), ticket, root) {
        Ok(said) => {
            println!("{said}; restart the probe (systemctl restart rackhand-probe) to use it");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-probe set-hub: {e}");
            ExitCode::from(1)
        }
    }
}

/// `uninstall [--after <seconds>]` (7.3.12); `--delay` is the copy that `--after` starts.
#[cfg(unix)]
fn uninstall(args: &[String]) -> ExitCode {
    let (mut after, mut delayed) = (None, false);
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--after" | "--delay" => {
                let Some(n) = it.next().and_then(|v| v.parse::<u64>().ok()).filter(|n| *n <= 3600) else {
                    eprintln!("{USAGE}");
                    return ExitCode::from(2);
                };
                (after, delayed) = (Some(n), a == "--delay");
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let options = rackhand_probe::uninstall::Options { root: "/".into(), after, delayed };
    match rackhand_probe::uninstall::uninstall(&options, &rackhand_probe::uninstall::System) {
        Ok(()) if after.is_some() && !delayed => {
            println!("rackhand-probe: uninstall in {} seconds", after.unwrap_or(0));
            ExitCode::SUCCESS
        }
        Ok(()) => {
            println!("rackhand-probe: uninstalled");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("rackhand-probe: {e}");
            ExitCode::from(1)
        }
    }
}

/// The commands only Windows has (7.3.3): the helper and the services.
#[cfg(windows)]
mod windows_cmd {
    use std::process::ExitCode;
    use std::sync::Arc;

    use rackhand_probe::windows::service;
    use tokio::sync::Notify;

    fn usage() -> ExitCode {
        eprintln!("usage: rackhand-probe helper [--pipe <name>]\n       rackhand-probe service probe|helper");
        ExitCode::from(2)
    }

    async fn helper_body(path: String) -> Result<(), String> {
        let helper = rackhand_probe::helper::server::Helper::new(env!("CARGO_PKG_VERSION"));
        rackhand_probe::windows::pipe::serve(&path, helper).await.map_err(|e| format!("{path}: {e}"))
    }

    /// `helper`: the helper in this console, for trying it by hand.
    pub fn helper(args: &[String]) -> ExitCode {
        rackhand_probe::logging::init();
        let mut path = rackhand_probe::helper::SOCKET.to_string();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            match (a.as_str(), it.next()) {
                ("--pipe", Some(v)) => path = v.clone(),
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
        match runtime.block_on(helper_body(path)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rackhand-probe helper: {e}");
                ExitCode::from(1)
            }
        }
    }

    /// `service probe` and `service helper`: what the Service Control Manager starts.
    pub fn service(args: &[String]) -> ExitCode {
        let result = match args {
            [which] if which == "probe" => service::dispatch("RackhandProbe", |stop: Arc<Notify>| {
                Box::pin(async move {
                    rackhand_probe::logging::init();
                    tokio::select! {
                        r = rackhand_probe::run::main(rackhand_probe::run::Paths::default()) => r.map(|_| ()),
                        () = stop.notified() => Ok(()),
                    }
                })
            }),
            [which] if which == "helper" => service::dispatch("RackhandHelper", |stop: Arc<Notify>| {
                Box::pin(async move {
                    rackhand_probe::logging::init();
                    tokio::select! {
                        r = helper_body(rackhand_probe::helper::SOCKET.to_string()) => r,
                        () = stop.notified() => Ok(()),
                    }
                })
            }),
            _ => return usage(),
        };
        match result {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("rackhand-probe service: {e}");
                ExitCode::from(1)
            }
        }
    }
}
