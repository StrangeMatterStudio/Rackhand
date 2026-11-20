//! M1 on the lab (plan L2): the hub as its shipped unit runs it (7.1, 5.2 security, AC67). These need a real
//! systemd boot: in a Docker container systemd 252 can't give a service's user its `LoadCredential` directory, so the
//! integration tier can't run them (T41, D52). The lab's `hub` machine (Debian 12) has the hub installed by the L2
//! deploy.

use crate::{ok_on, on};

#[test]
fn hub_service_runs_unprivileged_and_healthz_ok() {
    assert_eq!(on("hub", "curl -sk https://127.0.0.1:8443/healthz").trim(), "ok");
    let uid =
        on("hub", "pid=$(systemctl show -p MainPID --value rackhand-hub); awk '/^Uid:/ {print $2}' /proc/$pid/status");
    let uid = uid.trim();
    assert!(!uid.is_empty() && uid != "0", "the hub runs as uid {uid}");
    let first_run = on("hub", "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/first-run");
    assert_eq!(first_run.trim(), "200", "first run is reachable");
}

#[test]
fn hub_user_cannot_open_master_key_by_path() {
    assert!(!ok_on("hub", "sudo -u rackhand-hub cat /etc/rackhand/master.key"), "refused by path");
    assert_eq!(on("hub", "sudo stat -c '%a %U' /etc/rackhand/master.key").trim(), "600 root");
}
