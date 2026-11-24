//! The binary as a person runs it (7.7.3): every command has `--help`, and a failure exits non-zero with a message that names
//! what failed: 2 for a mistake in the command line, 1 for anything that went wrong.

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    let dir = std::env::temp_dir().join(format!("rackhand-cli-bin-{}", std::process::id()));
    Command::new(env!("CARGO_BIN_EXE_rackhand-cli"))
        .args(args)
        .env("RACKHAND_CLI_DIR", dir)
        .output()
        .expect("the binary runs")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[test]
fn every_command_has_help_and_nonzero_exit_on_error() {
    for (command, _) in rackhand_cli::COMMANDS {
        let out = run(&[command, "--help"]);
        assert_eq!(out.status.code(), Some(0), "{command} --help");
        assert!(text(&out.stdout).contains(&format!("rackhand-cli {command}")), "{command}: {}", text(&out.stdout));
    }
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("Every command takes --help"));
    // a mistake in the command line
    for args in
        [&["connect"][..], &["connect", "siteb/vm1", "ssh"], &["send", "a"], &["mcp"], &["nonsense"], &["login"]]
    {
        let out = run(args);
        assert_eq!(out.status.code(), Some(2), "{args:?}");
        assert!(text(&out.stderr).starts_with("rackhand-cli: "), "{args:?}: {}", text(&out.stderr));
    }
    // something that went wrong names what: no hub, a bad invite, a missing key
    let out = run(&["connect", "siteb/vm1", "22"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("no hub is known for `siteb`"), "{}", text(&out.stderr));
    let out = run(&["login", "not-an-invite"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(text(&out.stderr).contains("an invite is"), "{}", text(&out.stderr));
    let out = run(&["status"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(text(&out.stdout).contains("isn't enrolled"), "{}", text(&out.stdout));
    let out = run(&["--version"]);
    assert!(text(&out.stdout).starts_with("rackhand-cli 0."));
}
