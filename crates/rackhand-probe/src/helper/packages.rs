//! Package lists (7.3.3, D79): every 6 hours the helper refreshes them with a fixed command set at `nice 19` and
//! `ionice` idle, and keeps the pending updates for `UpdatesStatus`. Alpine has no security marker (D54).

use std::path::Path;

use rackhand_proto::helper::UpdateSummary;

/// How often the lists are refreshed.
pub const REFRESH_MS: i64 = 6 * 3_600_000;

/// The package manager a machine has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Apk,
}

impl Manager {
    /// The machine's package manager, if it has one of the two.
    pub fn detect(root: &Path) -> Option<Manager> {
        if root.join("usr/bin/apt-get").exists() {
            Some(Manager::Apt)
        } else if root.join("sbin/apk").exists() || root.join("usr/bin/apk").exists() {
            Some(Manager::Apk)
        } else {
            None
        }
    }

    /// The fixed commands: refresh the lists, then list what is pending. Nothing else is ever run.
    pub fn commands(self) -> [&'static [&'static str]; 2] {
        match self {
            Manager::Apt => [&["apt-get", "update", "-q"], &["apt-get", "-s", "-q", "upgrade"]],
            Manager::Apk => [&["apk", "update", "-q"], &["apk", "version", "-l", "<"]],
        }
    }

    /// The pending updates from the second command's output.
    pub fn parse(self, output: &str, reboot_required: bool) -> UpdateSummary {
        match self {
            Manager::Apt => apt_simulation(output, reboot_required),
            Manager::Apk => apk_versions(output),
        }
    }
}

/// A command run at the lowest CPU and I/O priority: `nice -n 19 ionice -c3 <command>`.
pub fn low_priority(command: &[&str]) -> Vec<String> {
    ["nice", "-n", "19", "ionice", "-c3"].iter().chain(command).map(|s| s.to_string()).collect()
}

/// `apt-get -s upgrade`: one `Inst <package> [<installed>] (<candidate> <origins> [<arch>])` line per update; an
/// origin naming a security archive marks a security update.
pub fn apt_simulation(output: &str, reboot_required: bool) -> UpdateSummary {
    let mut summary = UpdateSummary { pending: 0, security: 0, reboot_required, packages: Vec::new() };
    for line in output.lines() {
        let Some(rest) = line.strip_prefix("Inst ") else { continue };
        let Some(name) = rest.split_whitespace().next() else { continue };
        summary.pending += 1;
        let origin = rest.split_once('(').map_or("", |(_, o)| o);
        if origin.to_ascii_lowercase().contains("security") {
            summary.security += 1;
        }
        summary.packages.push(name.to_string());
    }
    summary
}

/// `apk version -l '<'`: one `<package>-<version>-r<release> < <available>` line per update. No security marker.
pub fn apk_versions(output: &str) -> UpdateSummary {
    let mut summary = UpdateSummary { pending: 0, security: 0, reboot_required: false, packages: Vec::new() };
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let (Some(installed), Some("<")) = (parts.next(), parts.next()) else { continue };
        let name = installed.rsplitn(3, '-').nth(2).unwrap_or(installed);
        summary.pending += 1;
        summary.packages.push(name.to_string());
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Recorded from a Debian 12 machine (trimmed): two security updates and one from the main archive.
    const APT: &str = "Reading package lists...
Building dependency tree...
Reading state information...
Calculating upgrade...
The following packages will be upgraded:
  libssl3 openssl tzdata
3 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.
Inst libssl3 [3.0.11-1~deb12u1] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst openssl [3.0.11-1~deb12u1] (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Inst tzdata [2024a-0+deb12u1] (2024b-0+deb12u1 Debian:12.7/stable [all])
Conf libssl3 (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Conf openssl (3.0.13-1~deb12u1 Debian-Security:12/stable-security [amd64])
Conf tzdata (2024b-0+deb12u1 Debian:12.7/stable [all])
";

    /// Recorded from an Alpine 3.20 machine (trimmed).
    const APK: &str = "Installed:                                Available:
busybox-1.36.1-r29                      < 1.36.1-r31
py3-cryptography-42.0.8-r0              < 42.0.8-r1
";

    #[test]
    fn apt_simulation_counts_security_updates() {
        let s = apt_simulation(APT, true);
        assert_eq!((s.pending, s.security, s.reboot_required), (3, 2, true));
        assert_eq!(s.packages, ["libssl3", "openssl", "tzdata"]);
        assert_eq!(apt_simulation("0 upgraded, 0 newly installed\n", false).pending, 0);
    }

    #[test]
    fn apk_version_output_counts_updates() {
        let s = apk_versions(APK);
        assert_eq!((s.pending, s.security, s.reboot_required), (2, 0, false), "no security marker on Alpine (D54)");
        assert_eq!(s.packages, ["busybox", "py3-cryptography"]);
    }

    #[test]
    fn fixed_commands_at_low_priority() {
        assert_eq!(
            low_priority(Manager::Apt.commands()[1]),
            ["nice", "-n", "19", "ionice", "-c3", "apt-get", "-s", "-q", "upgrade"]
        );
        assert_eq!(Manager::Apk.commands()[1], ["apk", "version", "-l", "<"]);
    }
}
