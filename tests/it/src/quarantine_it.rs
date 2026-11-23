//! In-guest quarantine (7.5.6, D104, AC17, AC18), in containers: the wrapper's `quarantine on|off` against real nftables.

mod quarantine {
    use std::process::Output;

    use crate::support::{Container, container_binary};

    const HUB_PORT: u16 = 4433;

    const GET: &str = "import sys, urllib.request\n\
try:\n    urllib.request.urlopen('http://%s:%s/' % (sys.argv[1], sys.argv[2]), timeout=3)\nexcept Exception:\n    sys.exit(1)\n";

    const LISTEN: &str = "import socket, sys\n\
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\ns.bind(('0.0.0.0', int(sys.argv[1])))\ns.settimeout(20)\n\
open('/tmp/got', 'w').write(s.recvfrom(100)[0].decode())\n";

    const SEND: &str = "import socket, sys\n\
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n\
for _ in range(5):\n    s.sendto(b'hello', (sys.argv[1], int(sys.argv[2])))\n";

    fn machine_image() -> Container {
        Container::start_with("quarantine", &["--privileged"])
    }

    fn prepare(c: &Container) {
        for (name, body) in [("get.py", GET), ("listen.py", LISTEN), ("send.py", SEND)] {
            let w = c.exec(None, &["sh", "-c", &format!("cat > /tmp/{name}")], Some(body.as_bytes()));
            assert!(w.status.success());
        }
    }

    fn can_get(from: &Container, ip: &str, port: u16) -> bool {
        from.root(&format!("python3 /tmp/get.py {ip} {port}")).status.success()
    }

    fn can_ping(from: &Container, ip: &str) -> bool {
        from.root(&format!("ping -c 1 -W 2 {ip}")).status.success()
    }

    /// Whether a datagram from `from` reaches a listener on `to`.
    fn udp_reaches(from: &Container, to: &Container, to_ip: &str) -> bool {
        to.root("rm -f /tmp/got");
        to.spawn_detached("root", &format!("python3 /tmp/listen.py {HUB_PORT}"));
        std::thread::sleep(std::time::Duration::from_millis(500));
        from.root(&format!("python3 /tmp/send.py {to_ip} {HUB_PORT}"));
        std::thread::sleep(std::time::Duration::from_millis(500));
        let got = to.root("cat /tmp/got 2>/dev/null").stdout;
        to.root("pkill -f listen.py");
        got == b"hello"
    }

    fn wrapper(c: &Container, args: &[&str]) -> Output {
        let mut all = vec!["sudo", "-n", "/usr/local/lib/rackhand/run", "quarantine"];
        all.extend_from_slice(args);
        c.exec(Some("rackhand"), &all, None)
    }

    fn text(out: &Output) -> String {
        format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr))
    }

    #[test]
    fn nftables_only_hub_paths_and_dhcp_then_removed() {
        let probe = container_binary("rackhand-probe", "rackhand-probe");
        let machine = machine_image();
        let hub = machine_image();
        let stranger = machine_image();
        for c in [&machine, &hub, &stranger] {
            prepare(c);
        }
        machine.copy_in(&probe, "/usr/local/lib/rackhand/run");
        assert!(
            machine.root("chown root:root /usr/local/lib/rackhand/run && chmod 0755 /usr/local/lib/rackhand/run").status.success()
        );
        let ((machine_ip, _), (hub_ip, _), (stranger_ip, _)) =
            (machine.ip_and_gateway(), hub.ip_and_gateway(), stranger.ip_and_gateway());
        // what each of them serves: the machine its SSH port (a web server stands in), the others a web server and a ping reply
        machine.spawn_detached("root", "python3 -m http.server 22 --bind 0.0.0.0");
        stranger.spawn_detached("root", "python3 -m http.server 8080 --bind 0.0.0.0");
        hub.spawn_detached("root", "python3 -m http.server 8081 --bind 0.0.0.0");
        // another firewall table of the machine's own, which a quarantine must leave alone
        let own = "nft add table inet other_t && nft add chain inet other_t c '{ type filter hook input priority 0; }' \
                   && nft add rule inet other_t c tcp dport 9 accept comment mine";
        let made = machine.root(own);
        assert!(made.status.success(), "nftables in the container: {}", text(&made));
        let own_before = text(&machine.root("nft list table inet other_t"));
        std::thread::sleep(std::time::Duration::from_secs(1));

        // before: everything reaches everything
        assert!(can_get(&stranger, &machine_ip, 22) && can_ping(&stranger, &machine_ip));
        assert!(can_get(&hub, &machine_ip, 22) && can_ping(&hub, &machine_ip));
        assert!(can_get(&machine, &stranger_ip, 8080) && can_get(&machine, &hub_ip, 8081) && can_ping(&machine, &hub_ip));

        // on: a bad address loads nothing, then the real ones
        let refused = wrapper(&machine, &["on", "hub.example:4433"]);
        assert!(!refused.status.success(), "{}", text(&refused));
        assert!(!text(&machine.root("nft list tables")).contains("rackhand_quarantine"));
        let on = wrapper(&machine, &["on", &format!("{hub_ip}:{HUB_PORT}")]);
        assert!(on.status.success(), "{}", text(&on));

        // while: only the hub's SSH and ping come in, only the probe's UDP port goes out, and DHCP is in the table
        assert!(can_get(&hub, &machine_ip, 22), "the hub's SSH");
        assert!(can_ping(&hub, &machine_ip), "the hub's ping");
        assert!(udp_reaches(&machine, &hub, &hub_ip), "the probe's connection to the hub");
        assert!(!can_get(&stranger, &machine_ip, 22), "another machine's SSH");
        assert!(!can_ping(&stranger, &machine_ip), "another machine's ping");
        assert!(!can_get(&machine, &stranger_ip, 8080), "out to another machine");
        assert!(!can_get(&machine, &hub_ip, 8081), "out to the hub on another port");
        assert!(!can_ping(&machine, &hub_ip), "the guest pinging the hub");
        let table = text(&machine.root("nft list table inet rackhand_quarantine"));
        assert!(table.contains("udp sport 67 udp dport 68 accept") && table.contains("udp sport 68 udp dport 67 accept"), "{table}");
        assert_eq!(text(&machine.root("nft list table inet other_t")), own_before, "the machine's own table is untouched");

        // off: reachable again, our table gone and nothing else touched
        let off = wrapper(&machine, &["off"]);
        assert!(off.status.success(), "{}", text(&off));
        assert!(!text(&machine.root("nft list tables")).contains("rackhand_quarantine"));
        assert_eq!(text(&machine.root("nft list table inet other_t")), own_before);
        assert!(can_get(&stranger, &machine_ip, 22) && can_ping(&stranger, &machine_ip));
        assert!(can_get(&machine, &stranger_ip, 8080) && can_get(&machine, &hub_ip, 8081) && can_ping(&machine, &hub_ip));
        // and off again, with nothing there, is not an error
        assert!(wrapper(&machine, &["off"]).status.success());
    }
}
