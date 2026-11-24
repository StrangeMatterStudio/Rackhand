//! `SocketOwners` and `ContainerOf` (7.3.3, D103): who owns a socket, and which container a process or a cgroup is. Read
//! from `/proc` and the cgroup tree by root; the requests carry numbers only (socket inodes and cgroup ids).

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use rackhand_proto::helper::SocketOwner;

use super::procscan::user_name;

/// The most inodes or cgroup ids one request may name.
pub const MAX_IDS: usize = 4096;
const CGROUP_DEPTH: usize = 6;

/// A container id (64 hex digits) in a cgroup path such as `/docker/<id>`, `/system.slice/docker-<id>.scope` or
/// `/machine.slice/libpod-<id>.scope`.
pub fn container_id(cgroup: &str) -> Option<String> {
    // the deepest one: a container inside another (or inside a machine's own container) is the process's
    for word in cgroup.split(['/', '-', '.']).collect::<Vec<_>>().into_iter().rev() {
        if word.len() == 64 && word.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(word.to_ascii_lowercase());
        }
    }
    None
}

/// The container of a process from its `cgroup` file.
fn container_of_proc(cgroup_file: &str) -> Option<String> {
    cgroup_file.lines().find_map(|l| container_id(l.rsplit(':').next()?))
}

/// The processes that own these socket inodes, with their executable, user and container (by name, through `name_of`,
/// which turns a container's id into its name).
pub fn owners(proc: &Path, passwd: &str, inodes: &[u64], name_of: &dyn Fn(&str) -> Option<String>) -> Vec<SocketOwner> {
    let wanted: std::collections::HashSet<u64> = inodes.iter().copied().take(MAX_IDS).collect();
    let Ok(entries) = std::fs::read_dir(proc) else { return Vec::new() };
    let mut out = Vec::new();
    let mut found = std::collections::HashSet::new();
    for e in entries.flatten() {
        let Some(pid) = e.file_name().to_str().and_then(|n| n.parse::<u32>().ok()) else { continue };
        let dir = e.path();
        let Ok(fds) = std::fs::read_dir(dir.join("fd")) else { continue };
        for fd in fds.flatten() {
            let Ok(link) = std::fs::read_link(fd.path()) else { continue };
            let Some(inode) =
                link.to_str().and_then(|l| l.strip_prefix("socket:[")?.strip_suffix(']')?.parse::<u64>().ok())
            else {
                continue;
            };
            if !wanted.contains(&inode) || !found.insert(inode) {
                continue;
            }
            let exe = std::fs::read_link(dir.join("exe")).map(|p| p.to_string_lossy().into_owned()).unwrap_or_default();
            let uid = std::fs::metadata(&dir).map_or(0, |m| m.uid());
            let container = std::fs::read_to_string(dir.join("cgroup"))
                .ok()
                .and_then(|c| container_of_proc(&c))
                .map(|id| name_of(&id).unwrap_or(id));
            out.push(SocketOwner { inode, pid, exe, user: user_name(passwd, uid), container });
        }
    }
    out.sort_by_key(|o| o.inode);
    out
}

/// The containers whose cgroup directories have these ids (a cgroup's id is its directory's inode, which is what the
/// kernel's `bpf_get_current_cgroup_id` gives), by name. Looks at most [`CGROUP_DEPTH`] levels down.
pub fn container_names(
    cgroup_root: &Path,
    ids: &[u64],
    name_of: &dyn Fn(&str) -> Option<String>,
) -> Vec<(u64, String)> {
    let wanted: std::collections::HashSet<u64> = ids.iter().copied().take(MAX_IDS).collect();
    let mut out = Vec::new();
    walk(cgroup_root, 0, &wanted, name_of, &mut out);
    out.sort();
    out
}

fn walk(
    dir: &Path,
    depth: usize,
    wanted: &std::collections::HashSet<u64>,
    name_of: &dyn Fn(&str) -> Option<String>,
    out: &mut Vec<(u64, String)>,
) {
    if depth > CGROUP_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_dir() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        if let (true, Some(id)) = (wanted.contains(&meta.ino()), container_id(&name)) {
            out.push((meta.ino(), name_of(&id).unwrap_or(id)));
        }
        walk(&e.path(), depth + 1, wanted, name_of, out);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use super::*;

    const ID_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const ID_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn names(id: &str) -> Option<String> {
        match &id[..1] {
            "a" => Some("web".into()),
            "b" => Some("db".into()),
            _ => None,
        }
    }

    /// A process `pid` holding socket `inode` and `exe`, in the cgroup `cgroup`.
    fn process(proc: &Path, pid: u32, inode: u64, exe: &str, cgroup: &str) {
        let p = proc.join(pid.to_string());
        std::fs::create_dir_all(p.join("fd")).unwrap();
        symlink(format!("socket:[{inode}]"), p.join("fd/3")).unwrap();
        symlink("/dev/null", p.join("fd/0")).unwrap();
        symlink(exe, p.join("exe")).unwrap();
        std::fs::write(p.join("cgroup"), cgroup).unwrap();
    }

    #[test]
    fn socket_owner_and_cgroup_to_container_name() {
        let proc = std::env::temp_dir().join(format!("rackhand-sock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&proc);
        process(&proc, 10, 5001, "/usr/bin/curl", &format!("0::/system.slice/docker-{ID_A}.scope\n"));
        process(&proc, 11, 5002, "/usr/bin/curl", &format!("12:pids:/docker/{ID_B}\n11:cpu:/docker/{ID_B}\n"));
        process(&proc, 12, 5003, "/usr/sbin/sshd", "0::/system.slice/ssh.service\n");
        process(&proc, 13, 5004, "/usr/bin/other", &format!("0::/machine.slice/libpod-{}.scope\n", "c".repeat(64)));
        let me = std::fs::metadata(&proc).unwrap().uid();
        let passwd = format!("alice:x:{me}:{me}::/home/alice:/bin/sh\n");
        let found = owners(&proc, &passwd, &[5001, 5002, 5003, 5004, 9999], &names);
        let view: Vec<(u64, u32, &str, Option<&str>)> =
            found.iter().map(|o| (o.inode, o.pid, o.exe.as_str(), o.container.as_deref())).collect();
        // the same `curl` in two containers is told apart by its container, and a host process has none
        assert_eq!(view[0], (5001, 10, "/usr/bin/curl", Some("web")));
        assert_eq!(view[1], (5002, 11, "/usr/bin/curl", Some("db")));
        assert_eq!(view[2], (5003, 12, "/usr/sbin/sshd", None));
        assert_eq!(view[3].3, Some(&"c".repeat(64)[..]), "an unknown container is named by its id");
        assert_eq!(found.len(), 4, "an inode nobody holds is left out");
        assert!(found.iter().all(|o| o.user == "alice"));

        // cgroup ids are the cgroup directories' inodes
        let cg = std::env::temp_dir().join(format!("rackhand-cg-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&cg);
        let a = cg.join(format!("system.slice/docker-{ID_A}.scope"));
        let b = cg.join(format!("docker/{ID_B}"));
        std::fs::create_dir_all(&a).unwrap();
        std::fs::create_dir_all(&b).unwrap();
        std::fs::create_dir_all(cg.join("system.slice/ssh.service")).unwrap();
        let (ino_a, ino_b) = (std::fs::metadata(&a).unwrap().ino(), std::fs::metadata(&b).unwrap().ino());
        let ssh = std::fs::metadata(cg.join("system.slice/ssh.service")).unwrap().ino();
        let named = container_names(&cg, &[ino_a, ino_b, ssh, 1], &names);
        let mut expect = vec![(ino_a, "web".to_string()), (ino_b, "db".to_string())];
        expect.sort();
        assert_eq!(named, expect, "a cgroup that isn't a container's has no name");
    }

    #[test]
    fn container_ids_are_found_in_every_cgroup_layout() {
        for path in [
            format!("/docker/{ID_A}"),
            format!("/system.slice/docker-{ID_A}.scope"),
            format!("/machine.slice/libpod-{ID_A}.scope"),
            format!("/kubepods/besteffort/pod1/{ID_A}"),
            format!("/docker/{ID_B}/system.slice/docker-{ID_A}.service"),
        ] {
            assert_eq!(container_id(&path).as_deref(), Some(ID_A), "{path}");
        }
        assert_eq!(container_id("/system.slice/ssh.service"), None);
        assert_eq!(container_id(&format!("/x/{}", "g".repeat(64))), None, "not hex");
        assert_eq!(container_id(&format!("/x/{}", "a".repeat(63))), None, "not 64 digits");
    }
}
