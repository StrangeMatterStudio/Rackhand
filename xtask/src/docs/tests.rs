use super::{Command, commands_in, documented, ip_literals, is_documentation_address, usage_names};

#[test]
fn commands_come_from_code_blocks_only() {
    let page = "Run `rackhand hub init` first.\n\n```sh\nsudo rackhand hub backup --config /etc/rackhand/hub.toml\n\
                /usr/local/lib/rackhand/rackhand-probe set-hub <ticket>\nrackhand-cli login '<invite>'\n\
                curl -fsSL https://example.com/install.sh | sudo sh -s -- --hub\n```\n\nrackhand hub run\n";
    let got = commands_in(page);
    let want = [
        Command { bin: "rackhand".into(), words: vec!["hub".into(), "backup".into()] },
        Command { bin: "rackhand-probe".into(), words: vec!["set-hub".into()] },
        Command { bin: "rackhand-cli".into(), words: vec!["login".into()] },
    ];
    assert_eq!(got, want, "prose and other programs aren't commands");
}

#[test]
fn every_documented_command_exists() {
    let commands = documented().expect("the docs");
    assert!(commands.len() >= 10, "the docs name the commands: {commands:?}");
    let usage = usage_names().expect("the binaries' usage");
    let missing: Vec<String> = commands.iter().filter(|c| !usage.contains(&c.line())).map(Command::line).collect();
    assert!(missing.is_empty(), "documented but not in any binary's usage: {missing:?}");
}

#[test]
fn no_lab_addresses_in_docs() {
    assert!(is_documentation_address("192.0.2.10") && is_documentation_address("2001:db8::7"));
    assert!(
        is_documentation_address("127.0.0.1") && is_documentation_address("::1") && is_documentation_address("0.0.0.0")
    );
    assert!(!is_documentation_address("10.0.0.5") && !is_documentation_address("192.168.1.2"));
    assert_eq!(ip_literals("at 10.1.2.3:7443 and 2001:db8::1, version 0.1.0, 12:30:00"), ["10.1.2.3", "2001:db8::1"]);
    let found: Vec<String> = super::doc_pages()
        .expect("the docs")
        .iter()
        .flat_map(|(page, text)| {
            ip_literals(text)
                .into_iter()
                .filter(|ip| !is_documentation_address(ip))
                .map(move |ip| format!("{page}: {ip}"))
        })
        .collect();
    assert!(found.is_empty(), "only documentation addresses (D71): {found:?}");
}
