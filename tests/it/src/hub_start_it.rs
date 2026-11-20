//! The hub as its shipped unit runs it (7.1, 5.2 security, AC67): an unprivileged user, the master key as a
//! systemd credential, `/healthz` and first run over HTTPS.

mod hub_start {
    use std::time::Duration;

    use crate::support::{Container, musl_binary};

    const UNIT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../packaging/systemd/rackhand-hub.service");

    fn hub() -> Container {
        let c = Container::start_systemd("systemd");
        c.copy_in(&musl_binary("rackhand", "rackhand"), "/usr/local/bin/rackhand");
        c.copy_in(std::path::Path::new(UNIT), "/etc/systemd/system/rackhand-hub.service");
        let setup = c.root(
            "set -e
             useradd --system --no-create-home --shell /usr/sbin/nologin rackhand-hub
             rackhand hub init
             chown -R rackhand-hub:rackhand-hub /var/lib/rackhand
             chown rackhand-hub:rackhand-hub /etc/rackhand/node.key
             chgrp rackhand-hub /etc/rackhand/hub.toml
             systemctl daemon-reload
             systemctl start rackhand-hub",
        );
        assert!(setup.status.success(), "setup: {}", String::from_utf8_lossy(&setup.stderr));
        for _ in 0..60 {
            if c.root("curl -skf https://127.0.0.1:8443/healthz").status.success() {
                return c;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let logs = c.root("journalctl -u rackhand-hub --no-pager | tail -30");
        panic!("the hub didn't answer: {}", String::from_utf8_lossy(&logs.stdout));
    }

    #[test]
    fn service_runs_unprivileged_and_healthz_ok() {
        let c = hub();
        let healthz = c.root("curl -sk https://127.0.0.1:8443/healthz");
        assert_eq!(String::from_utf8_lossy(&healthz.stdout).trim(), "ok");
        let uid =
            c.root("pid=$(systemctl show -p MainPID --value rackhand-hub); awk '/^Uid:/ {print $2}' /proc/$pid/status");
        let uid = String::from_utf8_lossy(&uid.stdout).trim().to_string();
        assert!(!uid.is_empty() && uid != "0", "the hub runs as uid {uid}");
        let first_run = c.root("curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/first-run");
        assert_eq!(String::from_utf8_lossy(&first_run.stdout), "200", "first run is reachable");
    }

    #[test]
    fn hub_user_cannot_open_master_key_by_path() {
        let c = hub();
        let read = c.exec(Some("rackhand-hub"), &["cat", "/etc/rackhand/master.key"], None);
        assert!(!read.status.success(), "the hub's user can't read the master key by path");
        let mode = c.root("stat -c '%a %U' /etc/rackhand/master.key");
        assert_eq!(String::from_utf8_lossy(&mode.stdout).trim(), "600 root");
    }
}
