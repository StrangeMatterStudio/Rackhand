//! The people-side client (design 7.2, 7.7.3): `login`, `status`, `connect`, `forward`, `send` and `mcp`, for Linux, Windows and
//! macOS. A computer is enrolled to each hub it uses with a device key of its own for that hub (D59).

pub mod commands;
pub mod config;
pub mod login;
pub mod net;

/// Every command, with the line its help starts with.
pub const COMMANDS: &[(&str, &str)] = &[
    (
        "login",
        "rackhand-cli login <invite> [--name <device name>]\n  Enrolls this computer as a device of your account on one hub. The invite is what the hub's Add page shows.",
    ),
    ("status", "rackhand-cli status\n  The hubs this computer is enrolled to, and whether each takes this device now."),
    (
        "connect",
        "rackhand-cli connect <site>/<machine> <port>\n  Standard input and output become a tunnel to the port, for SSH: ssh -o ProxyCommand='rackhand-cli connect siteb/vm1 22' vm1",
    ),
    (
        "forward",
        "rackhand-cli forward <local-port> <site>/<machine>:<port>\n  Listens on 127.0.0.1 only; each connection to the local port is a tunnel to the machine.",
    ),
    (
        "send",
        "rackhand-cli send <path> <site>/<machine>:<destination> [--allow-relay]\n  Sends a file to a machine in checked chunks, and goes on from where it stopped if it is run again. Waits for a direct path unless --allow-relay.",
    ),
    (
        "mcp",
        "rackhand-cli mcp --hub <site> [--key-file <file>]\n  A stdio MCP server for an assistant on this computer, talking to the hub. The personal MCP key from the dashboard is read from --key-file or the environment variable RACKHAND_MCP_KEY.",
    ),
];

/// The usage text of the whole tool.
pub fn usage() -> String {
    let mut text = String::from("usage: rackhand-cli <command> ...\n\n");
    for (_, help) in COMMANDS {
        text.push_str(help);
        text.push_str("\n\n");
    }
    text.push_str("Every command takes --help. A command that fails says what failed and exits non-zero.\n");
    text
}

/// What was asked: a command and its words, or a usage error.
#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    Help(String),
    Login { invite: String, name: Option<String> },
    Status,
    Connect { target: String, port: u16 },
    Forward { local: u16, target: String },
    Send { path: String, target: String, allow_relay: bool },
    Mcp { hub: String, key_file: Option<String> },
}

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).map(String::as_str)
}

fn positional(args: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
        } else if matches!(a.as_str(), "--name" | "--hub" | "--key-file") {
            skip = true;
        } else if !a.starts_with("--") {
            out.push(a.as_str());
        }
    }
    out
}

fn help_of(command: &str) -> String {
    COMMANDS.iter().find(|(c, _)| *c == command).map(|(_, h)| h.to_string()).unwrap_or_else(usage)
}

/// Reads the words of a command line; an error is the message for a usage mistake (exit status 2).
pub fn parse(args: &[String]) -> Result<Parsed, String> {
    let Some(command) = args.first().map(String::as_str) else { return Ok(Parsed::Help(usage())) };
    if matches!(command, "--help" | "-h" | "help") {
        return Ok(Parsed::Help(usage()));
    }
    let rest = &args[1..];
    if rest.iter().any(|a| a == "--help" || a == "-h") {
        return Ok(Parsed::Help(help_of(command)));
    }
    let words = positional(rest);
    let bad = |why: &str| Err(format!("{why}\n\n{}", help_of(command)));
    match command {
        "login" => match words.as_slice() {
            [invite] => Ok(Parsed::Login { invite: (*invite).into(), name: flag(rest, "--name").map(String::from) }),
            _ => bad("login takes the invite"),
        },
        "status" if words.is_empty() => Ok(Parsed::Status),
        "status" => bad("status takes nothing"),
        "connect" => match words.as_slice() {
            [target, port] => match port.parse() {
                Ok(port) => Ok(Parsed::Connect { target: (*target).into(), port }),
                Err(_) => bad(&format!("`{port}` isn't a port")),
            },
            _ => bad("connect takes <site>/<machine> and a port"),
        },
        "forward" => match words.as_slice() {
            [local, target] => match local.parse() {
                Ok(local) => Ok(Parsed::Forward { local, target: (*target).into() }),
                Err(_) => bad(&format!("`{local}` isn't a port")),
            },
            _ => bad("forward takes a local port and <site>/<machine>:<port>"),
        },
        "send" => match words.as_slice() {
            [path, target] => Ok(Parsed::Send {
                path: (*path).into(),
                target: (*target).into(),
                allow_relay: rest.iter().any(|a| a == "--allow-relay"),
            }),
            _ => bad("send takes a file and <site>/<machine>:<destination>"),
        },
        "mcp" => match flag(rest, "--hub") {
            Some(hub) if words.is_empty() => {
                Ok(Parsed::Mcp { hub: hub.into(), key_file: flag(rest, "--key-file").map(String::from) })
            }
            _ => bad("mcp takes --hub <site>"),
        },
        other => Err(format!("unknown command `{other}`\n\n{}", usage())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn every_command_has_help_and_a_usage_error_when_misused() {
        for (command, help) in COMMANDS {
            assert!(help.starts_with(&format!("rackhand-cli {command}")), "{command}");
            assert_eq!(parse(&args(&[command, "--help"])).unwrap(), Parsed::Help(help.to_string()));
            let misuse = parse(&args(&[command])).or_else(|_| parse(&args(&[command, "x", "y", "z"])));
            if *command != "status" {
                assert!(misuse.unwrap_err().contains(&format!("rackhand-cli {command}")), "{command} names its usage");
            }
        }
        assert!(parse(&args(&["fly"])).unwrap_err().contains("unknown command"));
        assert!(matches!(parse(&args(&[])).unwrap(), Parsed::Help(_)));
        assert!(parse(&args(&["connect", "siteb/vm1", "ssh"])).unwrap_err().contains("isn't a port"));
    }

    #[test]
    fn the_words_of_each_command() {
        assert_eq!(
            parse(&args(&["login", "inv#x", "--name", "laptop"])).unwrap(),
            Parsed::Login { invite: "inv#x".into(), name: Some("laptop".into()) }
        );
        assert_eq!(
            parse(&args(&["connect", "siteb/vm1", "22"])).unwrap(),
            Parsed::Connect { target: "siteb/vm1".into(), port: 22 }
        );
        assert_eq!(
            parse(&args(&["forward", "8080", "home/web:80"])).unwrap(),
            Parsed::Forward { local: 8080, target: "home/web:80".into() }
        );
        assert_eq!(
            parse(&args(&["send", "a.bin", "home/web:/var/lib/rackhand-run/incoming/a.bin", "--allow-relay"])).unwrap(),
            Parsed::Send {
                path: "a.bin".into(),
                target: "home/web:/var/lib/rackhand-run/incoming/a.bin".into(),
                allow_relay: true
            }
        );
        assert_eq!(
            parse(&args(&["mcp", "--hub", "home", "--key-file", "k"])).unwrap(),
            Parsed::Mcp { hub: "home".into(), key_file: Some("k".into()) }
        );
        assert_eq!(parse(&args(&["status"])).unwrap(), Parsed::Status);
    }
}
