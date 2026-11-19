//! Detached steps (7.3.7, D97): `job-start` matches the command as usual, then starts a supervisor in its own unit
//! (`systemd-run`), as an OpenRC background daemon (`start-stop-daemon`), or in a new session. The supervisor runs the
//! command without a shell, appends its output to a file and records the exit code, so no SSH session, hub restart or
//! network break stops it. `job-status`, `job-stop` and `job-clean` take only hub-generated ids.

use std::fs::OpenOptions;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use super::matcher::{CommandList, matching};

pub const JOBS: &str = "/var/lib/rackhand-run/jobs";
const PATH: &str = "/usr/sbin:/usr/bin:/sbin:/bin";
/// The most output one status poll returns.
const MAX_CHUNK: u64 = 1 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JobRef {
    pub job: String,
    pub step: String,
}

impl JobRef {
    fn dir(&self) -> PathBuf {
        Path::new(JOBS).join(&self.job).join(&self.step)
    }

    fn unit(&self) -> String {
        format!("rackhand-job-{}-{}", self.job.to_ascii_lowercase(), self.step)
    }

    fn text(&self) -> String {
        format!("{}/{}", self.job, self.step)
    }
}

/// `<job>/<step>`: a ULID (Crockford base32, upper case) and a step id (`a-z`, `0-9`, `-`, not starting with `-`).
pub fn parse_ref(s: &str) -> Option<JobRef> {
    let (job, step) = s.split_once('/')?;
    let ulid =
        job.len() == 26 && job.bytes().all(|b| b.is_ascii_digit() || (b.is_ascii_uppercase() && !b"ILOU".contains(&b)));
    let step_ok = (1..=64).contains(&step.len())
        && step.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !step.starts_with('-');
    (ulid && step_ok).then(|| JobRef { job: job.into(), step: step.into() })
}

fn private_dir(path: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn fail(msg: &str, code: u8) -> ExitCode {
    eprintln!("run: {msg}");
    ExitCode::from(code)
}

/// `job-start <job>/<step> -- <args...>`.
pub fn start(list: &CommandList, args: &[String]) -> ExitCode {
    let (Some(r), Some("--")) = (args.first().and_then(|a| parse_ref(a)), args.get(1).map(String::as_str)) else {
        return fail("usage: job-start <job>/<step> -- <command...>", 2);
    };
    let argv = match matching(list, &args[2..]) {
        Ok(a) => a,
        Err(refusal) => return fail(&refusal.to_string(), 126),
    };
    let dir = r.dir();
    if dir.exists() {
        return fail("that step has already been started", 1);
    }
    let written = private_dir(Path::new(JOBS))
        .and_then(|_| private_dir(&dir))
        .and_then(|_| std::fs::write(dir.join("argv.json"), serde_json::to_vec(&argv).unwrap_or_default()));
    if let Err(e) = written {
        return fail(&format!("job directory: {e}"), 1);
    }
    // The fixed path, so the supervisor starts in wrapper mode however this binary was invoked.
    let supervise = [super::WRAPPER.to_string(), "job-supervise".into(), r.text()];
    let started = if Path::new("/run/systemd/system").exists() {
        Command::new("systemd-run")
            .args(["--quiet", "--collect", &format!("--unit={}", r.unit()), "--"])
            .args(&supervise)
            .env_clear()
            .env("PATH", PATH)
            .status()
            .map(|s| s.success())
    } else if which("start-stop-daemon") {
        let pidfile = dir.join("supervisor.pid");
        Command::new("start-stop-daemon")
            .args(["--start", "--background", "--make-pidfile", "--pidfile"])
            .arg(&pidfile)
            .arg("--exec")
            .arg(&supervise[0])
            .arg("--")
            .args(&supervise[1..])
            .env_clear()
            .env("PATH", PATH)
            .status()
            .map(|s| s.success())
    } else {
        Command::new("setsid")
            .args(&supervise)
            .env_clear()
            .env("PATH", PATH)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map(|_| true)
    };
    match started {
        Ok(true) => {
            println!("started {}", r.text());
            ExitCode::SUCCESS
        }
        _ => {
            let _ = std::fs::remove_dir_all(&dir);
            fail("the supervisor didn't start", 1)
        }
    }
}

fn which(program: &str) -> bool {
    PATH.split(':').any(|d| Path::new(d).join(program).exists())
}

fn write_atomic(path: &Path, text: &str) -> std::io::Result<()> {
    let tmp = path.with_extension("new");
    std::fs::write(&tmp, text)?;
    std::fs::rename(tmp, path)
}

/// `job-supervise <job>/<step>`: runs the command recorded at `job-start` and records how it ended.
pub fn supervise(args: &[String]) -> ExitCode {
    let Some(r) = args.first().and_then(|a| parse_ref(a)) else { return fail("bad job id", 2) };
    let dir = r.dir();
    if !dir.join("argv.json").exists() {
        return fail("no recorded command", 1);
    }
    // Once only: a step that has started (or ended) can't be run again by calling this through sudo.
    let claim = OpenOptions::new().write(true).create_new(true).open(dir.join("supervised"));
    if claim.is_err() || dir.join("exit").exists() {
        return fail("that step has already been supervised", 1);
    }
    let argv: Vec<String> =
        match std::fs::read(dir.join("argv.json")).ok().and_then(|b| serde_json::from_slice(&b).ok()) {
            Some(a) => a,
            None => return fail("no recorded command", 1),
        };
    let Some((program, rest)) = argv.split_first() else { return fail("empty command", 1) };
    let output = match OpenOptions::new().create(true).append(true).open(dir.join("output")) {
        Ok(f) => f,
        Err(e) => return fail(&format!("output file: {e}"), 1),
    };
    let Ok(err) = output.try_clone() else { return fail("output file", 1) };
    let child = Command::new(program)
        .args(rest)
        .env_clear()
        .env("PATH", PATH)
        .stdin(Stdio::null())
        .stdout(output)
        .stderr(err)
        .spawn();
    let mut child = match child {
        Ok(c) => c,
        Err(e) => {
            let _ = write_atomic(&dir.join("exit"), "127");
            return fail(&format!("{program}: {e}"), 127);
        }
    };
    let _ = write_atomic(&dir.join("pid"), &child.id().to_string());
    let code = match child.wait() {
        Ok(s) => match s.code() {
            Some(c) => c.to_string(),
            None => "signal".to_string(),
        },
        Err(_) => "unknown".to_string(),
    };
    let _ = write_atomic(&dir.join("exit"), &code);
    ExitCode::SUCCESS
}

fn alive(pid: &str) -> bool {
    Path::new("/proc").join(pid.trim()).exists()
}

/// `job-status <job>/<step> <offset>`: the state, the exit code and the output from the offset, as JSON.
pub fn status(args: &[String]) -> ExitCode {
    let (Some(r), Some(offset)) =
        (args.first().and_then(|a| parse_ref(a)), args.get(1).and_then(|o| o.parse::<u64>().ok()))
    else {
        return fail("usage: job-status <job>/<step> <offset>", 2);
    };
    let dir = r.dir();
    if !dir.join("argv.json").exists() {
        println!("{}", serde_json::json!({ "state": "unknown", "exit_code": null, "output": "", "next_offset": 0 }));
        return ExitCode::SUCCESS;
    }
    let exit = std::fs::read_to_string(dir.join("exit")).ok();
    let state = if dir.join("stopped").exists() {
        "stopped"
    } else if exit.is_some() {
        "exited"
    } else if let Ok(p) = std::fs::read_to_string(dir.join("pid")) {
        // The supervisor went away without recording an end (the machine rebooted, or it was killed).
        if alive(&p) { "running" } else { "lost" }
    } else {
        // Recorded, and the command hasn't been started yet.
        "starting"
    };
    let exit_code: Option<i64> = exit.and_then(|e| e.trim().parse().ok());
    let (output, next) = read_from(&dir.join("output"), offset);
    println!(
        "{}",
        serde_json::json!({ "state": state, "exit_code": exit_code, "output": String::from_utf8_lossy(&output), "next_offset": next })
    );
    ExitCode::SUCCESS
}

fn read_from(path: &Path, offset: u64) -> (Vec<u8>, u64) {
    let Ok(mut f) = std::fs::File::open(path) else { return (Vec::new(), offset) };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    if offset >= len || f.seek(SeekFrom::Start(offset)).is_err() {
        return (Vec::new(), offset.min(len));
    }
    let mut buf = Vec::new();
    let _ = f.take(MAX_CHUNK).read_to_end(&mut buf);
    let next = offset + buf.len() as u64;
    (buf, next)
}

/// `job-stop <job>/<step>`: ends the command (an approval at normal risk on the hub's side).
pub fn stop(args: &[String]) -> ExitCode {
    let Some(r) = args.first().and_then(|a| parse_ref(a)) else { return fail("usage: job-stop <job>/<step>", 2) };
    let dir = r.dir();
    if !dir.join("argv.json").exists() {
        return fail("no such step", 1);
    }
    let _ = write_atomic(&dir.join("stopped"), "1");
    if Path::new("/run/systemd/system").exists() {
        let _ = Command::new("systemctl").args(["stop", &r.unit()]).env_clear().env("PATH", PATH).status();
    }
    if let Ok(pid) = std::fs::read_to_string(dir.join("pid")) {
        if alive(&pid) {
            terminate(pid.trim());
        }
    }
    println!("stopped {}", r.text());
    ExitCode::SUCCESS
}

/// SIGTERM to the command (no `kill` binary needed: minimal images have none).
#[cfg(target_os = "linux")]
fn terminate(pid: &str) {
    if let Some(pid) = pid.parse::<i32>().ok().and_then(rustix::process::Pid::from_raw) {
        let _ = rustix::process::kill_process(pid, rustix::process::Signal::TERM);
    }
}

#[cfg(not(target_os = "linux"))]
fn terminate(_pid: &str) {}

/// `job-clean <job>/<step>`: removes the files once the step has ended.
pub fn clean(args: &[String]) -> ExitCode {
    let Some(r) = args.first().and_then(|a| parse_ref(a)) else { return fail("usage: job-clean <job>/<step>", 2) };
    let dir = r.dir();
    if !(dir.join("exit").exists() || dir.join("stopped").exists()) {
        return fail("the step hasn't ended", 1);
    }
    if let Err(e) = std::fs::remove_dir_all(&dir) {
        return fail(&format!("removing: {e}"), 1);
    }
    let _ = std::fs::remove_dir(Path::new(JOBS).join(&r.job));
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::{JobRef, parse_ref};

    #[test]
    fn ids_must_be_hub_format() {
        let ok = parse_ref("01JH9X4M7Z8KQ2V3W5Y6T1R0PA/install-updates").unwrap();
        assert_eq!(ok, JobRef { job: "01JH9X4M7Z8KQ2V3W5Y6T1R0PA".into(), step: "install-updates".into() });
        for bad in [
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/../../etc",
            "../01JH9X4M7Z8KQ2V3W5Y6T1R0PA/step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/step;rm",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/$(id)",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/Step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA",
            "01jh9x4m7z8kq2v3w5y6t1r0pa/step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0P/step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PU/step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/-step",
            "01JH9X4M7Z8KQ2V3W5Y6T1R0PA/step/more",
            "",
        ] {
            assert!(parse_ref(bad).is_none(), "{bad:?} accepted");
        }
    }
}
