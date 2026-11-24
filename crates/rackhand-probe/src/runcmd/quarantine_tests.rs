use std::cell::RefCell;

use super::*;

/// A host that records the scripts it was asked to load.
#[derive(Default)]
struct Fake {
    scripts: RefCell<Vec<String>>,
    fail: bool,
    flushed: bool,
}

impl Host for Fake {
    fn nft(&self, script: &str) -> Result<(), String> {
        if self.fail {
            return Err("Error: Could not process rule: Operation not permitted".into());
        }
        self.scripts.borrow_mut().push(script.into());
        Ok(())
    }

    fn flush_conntrack(&self) -> bool {
        self.flushed
    }
}

fn args(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| s.to_string()).collect()
}

#[test]
fn hub_addresses_are_ip_and_port_only() {
    let ok = parse_hubs(&args(&["192.0.2.10:4433", "[2001:db8::10]:4433"])).unwrap();
    assert_eq!(ok.len(), 2);
    assert!(ok[0].is_ipv4() && ok[1].is_ipv6());
    for bad in [
        "hub.example:4433",
        "192.0.2.10",
        "192.0.2.10:0",
        "192.0.2.10:99999",
        "192.0.2.10:4433; flush ruleset",
        "192.0.2.10:4433\nflush ruleset",
        "2001:db8::10:4433",
        "",
        "0.0.0.0:4433",
        "255.255.255.255:4433",
        "224.0.0.1:4433",
    ] {
        assert!(parse_hubs(&args(&[bad])).is_err(), "{bad:?}");
    }
    assert!(parse_hubs(&[]).is_err(), "at least one hub address");
    assert!(parse_hubs(&(0..20).map(|i| format!("192.0.2.{i}:1")).collect::<Vec<_>>()).is_err(), "no more than 16");
}

#[test]
fn ruleset_has_only_the_allowed_paths() {
    let hubs = parse_hubs(&args(&["192.0.2.10:4433", "[2001:db8::10]:4433"])).unwrap();
    let got = ruleset(&hubs);
    let expected = "\
add table inet rackhand_quarantine
delete table inet rackhand_quarantine
table inet rackhand_quarantine {
  chain input {
    type filter hook input priority -300; policy drop;
    iifname \"lo\" accept
    udp sport 67 udp dport 68 accept
    ip saddr 192.0.2.10 tcp dport 22 accept
    ip saddr 192.0.2.10 icmp type echo-request accept
    ip saddr 192.0.2.10 udp sport 4433 accept
    ip6 saddr 2001:db8::10 tcp dport 22 accept
    ip6 saddr 2001:db8::10 icmpv6 type echo-request accept
    ip6 saddr 2001:db8::10 udp sport 4433 accept
  }
  chain output {
    type filter hook output priority -300; policy drop;
    oifname \"lo\" accept
    udp sport 68 udp dport 67 accept
    ip daddr 192.0.2.10 udp dport 4433 accept
    ip daddr 192.0.2.10 tcp sport 22 accept
    ip daddr 192.0.2.10 icmp type echo-reply accept
    ip6 daddr 2001:db8::10 udp dport 4433 accept
    ip6 daddr 2001:db8::10 tcp sport 22 accept
    ip6 daddr 2001:db8::10 icmpv6 type echo-reply accept
  }
}
";
    assert_eq!(got, expected);
}

#[test]
fn nothing_but_our_table_is_touched() {
    let hubs = parse_hubs(&args(&["192.0.2.10:4433"])).unwrap();
    for script in [ruleset(&hubs), off_script()] {
        assert!(!script.contains("flush"), "{script}");
        assert!(!script.contains("ruleset"), "{script}");
        for line in
            script.lines().filter(|l| l.starts_with("add ") || l.starts_with("delete ") || l.starts_with("table "))
        {
            assert!(
                line.ends_with("inet rackhand_quarantine") || line.ends_with("inet rackhand_quarantine {"),
                "{line}"
            );
        }
    }
    assert_eq!(off_script(), "add table inet rackhand_quarantine\ndelete table inet rackhand_quarantine\n");
}

#[test]
fn on_and_off_load_one_script_each() {
    let host = Fake { flushed: true, ..Fake::default() };
    let said = on(&host, &args(&["192.0.2.10:4433"])).unwrap();
    assert!(said.contains("1 hub address") && said.contains("conntrack flushed"), "{said}");
    let said = off(&host).unwrap();
    assert!(said.contains("removed"), "{said}");
    let scripts = host.scripts.borrow();
    assert_eq!(scripts.len(), 2);
    assert!(scripts[0].contains("policy drop") && !scripts[1].contains("policy"));
    // without the conntrack tool it still applies, and says so
    let host = Fake::default();
    assert!(on(&host, &args(&["192.0.2.10:4433"])).unwrap().contains("conntrack not flushed"));
}

#[test]
fn a_failed_load_is_an_error_and_a_bad_address_loads_nothing() {
    let host = Fake { fail: true, ..Fake::default() };
    assert!(on(&host, &args(&["192.0.2.10:4433"])).unwrap_err().contains("Operation not permitted"));
    assert!(off(&host).is_err());
    let host = Fake::default();
    assert!(on(&host, &args(&["not-an-address"])).is_err());
    assert!(host.scripts.borrow().is_empty());
}
