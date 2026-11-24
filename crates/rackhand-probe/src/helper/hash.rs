//! `HashFiles` (7.3.3, 7.8.4, FR-6): the critical files' metadata and SHA-256, never their contents. The list is compiled
//! in, plus what `sshd_config` names with `AuthorizedKeysFile`, plus a root-owned extras file of at most 500 paths. No path
//! ever comes from the socket.

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rackhand_proto::helper::FileHash;
use sha2::{Digest, Sha256};

/// The compiled-in list (7.8.4). `*` stands for any run of characters in one path component.
pub const COMPILED: &[&str] = &[
    "/etc/passwd",
    "/etc/shadow",
    "/etc/group",
    "/etc/gshadow",
    "/etc/sudoers",
    "/etc/sudoers.d/*",
    "/etc/ssh/sshd_config",
    "/etc/ssh/sshd_config.d/*",
    "/etc/pam.d/*",
    "/etc/security/*.conf",
    "/root/.ssh/authorized_keys",
    "/home/*/.ssh/authorized_keys",
    "/etc/crontab",
    "/etc/cron.d/*",
    "/var/spool/cron/crontabs/*",
    "/etc/systemd/system/*.service",
    "/etc/systemd/system/*.timer",
    "/etc/ld.so.preload",
    "/etc/hosts",
    "/etc/resolv.conf",
    "/usr/bin/sudo",
    "/usr/sbin/sshd",
    "/usr/bin/ssh",
    "/usr/local/lib/rackhand/*",
    "/etc/rackhand/commands.json",
    "/etc/rackhand-probe/probe.toml",
];

/// Root-owned extra paths, one per line.
pub const EXTRAS: &str = "/etc/rackhand/helper-extra-paths";
pub const MAX_EXTRAS: usize = 500;
/// A file bigger than this is hashed no further: the list is configuration, and a huge file is not what it names.
const MAX_HASHED: u64 = 64 << 20;

/// Where the machine's files are, and who may name extra ones.
#[derive(Debug, Clone)]
pub struct Roots {
    /// The machine's root (`/`; a directory in tests).
    pub root: PathBuf,
    pub extras: PathBuf,
    /// The only owner an extras file may have.
    pub trusted_uid: u32,
}

impl Default for Roots {
    fn default() -> Roots {
        Roots { root: "/".into(), extras: EXTRAS.into(), trusted_uid: 0 }
    }
}

/// Whether `name` matches `pattern`, where `*` matches any run of characters (not `/`).
fn wild(pattern: &str, name: &str) -> bool {
    let Some((head, rest)) = pattern.split_once('*') else { return pattern == name };
    let Some(tail) = name.strip_prefix(head) else { return false };
    if !rest.contains('*') {
        return tail.ends_with(rest) && tail.len() >= rest.len();
    }
    (0..=tail.len()).filter(|i| tail.is_char_boundary(*i)).any(|i| wild(rest, &tail[i..]))
}

/// The paths a pattern names that exist now.
fn expand(root: &Path, pattern: &str) -> Vec<PathBuf> {
    let mut found = vec![root.to_path_buf()];
    for part in pattern.trim_start_matches('/').split('/') {
        let mut next = Vec::new();
        for dir in &found {
            if part.contains('*') {
                let Ok(entries) = std::fs::read_dir(dir) else { continue };
                let mut names: Vec<String> =
                    entries.flatten().filter_map(|e| e.file_name().into_string().ok()).collect();
                names.sort();
                next.extend(names.into_iter().filter(|n| wild(part, n)).map(|n| dir.join(n)));
            } else {
                next.push(dir.join(part));
            }
        }
        found = next;
    }
    found
}

/// The files `AuthorizedKeysFile` names in `sshd_config` and its drop-ins, for every home directory.
fn authorized_keys_files(roots: &Roots) -> Vec<String> {
    let mut texts = Vec::new();
    let main = roots.root.join("etc/ssh/sshd_config");
    if let Ok(t) = std::fs::read_to_string(main) {
        texts.push(t);
    }
    for p in expand(&roots.root, "/etc/ssh/sshd_config.d/*.conf") {
        if let Ok(t) = std::fs::read_to_string(p) {
            texts.push(t);
        }
    }
    let mut homes = vec!["/root".to_string()];
    homes.extend(expand(&roots.root, "/home/*").into_iter().filter_map(|p| {
        let rel = p.strip_prefix(&roots.root).ok()?;
        Some(format!("/{}", rel.display()))
    }));
    let mut out = Vec::new();
    for line in texts.iter().flat_map(|t| t.lines()) {
        let mut words = line.split_whitespace();
        if !words.next().is_some_and(|k| k.eq_ignore_ascii_case("AuthorizedKeysFile")) {
            continue;
        }
        for token in words.take_while(|w| !w.starts_with('#')) {
            if token == "none" {
                continue;
            }
            for home in &homes {
                let user = home.rsplit('/').next().unwrap_or_default();
                let path = token.replace("%h", home).replace("%u", user).replace("%%", "%");
                out.push(if path.starts_with('/') { path } else { format!("{home}/{path}") });
            }
        }
    }
    out
}

/// The extras file's paths: only if root owns it and nobody else can write it; absolute paths, at most [`MAX_EXTRAS`].
fn extras(roots: &Roots, warnings: &mut Vec<String>) -> Vec<String> {
    let Ok(meta) = std::fs::metadata(&roots.extras) else { return Vec::new() };
    if meta.uid() != roots.trusted_uid || meta.mode() & 0o022 != 0 {
        warnings.push(format!("{} isn't owned by root or can be written by others: ignored", roots.extras.display()));
        return Vec::new();
    }
    let Ok(text) = std::fs::read_to_string(&roots.extras) else { return Vec::new() };
    let mut paths: Vec<String> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.starts_with('/') && !l.contains(['\0', '\n']))
        .map(str::to_string)
        .collect();
    if paths.len() > MAX_EXTRAS {
        warnings.push(format!("{} names more than {MAX_EXTRAS} paths: the rest are ignored", roots.extras.display()));
        paths.truncate(MAX_EXTRAS);
    }
    paths
}

/// Every path to report, in a stable order, with the reasons anything was left out.
pub fn list(roots: &Roots) -> (Vec<String>, Vec<String>) {
    let mut warnings = Vec::new();
    let mut paths: Vec<String> = Vec::new();
    let named = COMPILED.iter().map(|p| p.to_string()).chain(authorized_keys_files(roots));
    for pattern in named {
        for p in expand(&roots.root, &pattern) {
            if let Ok(rel) = p.strip_prefix(&roots.root) {
                paths.push(format!("/{}", rel.display()));
            }
        }
    }
    paths.extend(extras(roots, &mut warnings));
    paths.sort();
    paths.dedup();
    (paths, warnings)
}

/// The metadata and hash of one file; a file that isn't there says so.
fn one(roots: &Roots, path: &str) -> FileHash {
    let at = roots.root.join(path.trim_start_matches('/'));
    let missing = FileHash { path: path.into(), exists: false, sha256: None, mode: 0, uid: 0, gid: 0, mtime_ms: 0 };
    let Ok(meta) = std::fs::metadata(&at) else { return missing };
    let sha256 = (meta.is_file() && meta.len() <= MAX_HASHED)
        .then(|| std::fs::read(&at).ok())
        .flatten()
        .map(|b| Sha256::digest(&b).iter().map(|x| format!("{x:02x}")).collect::<String>());
    FileHash {
        path: path.into(),
        exists: true,
        sha256,
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        mtime_ms: meta.mtime() * 1000 + meta.mtime_nsec() / 1_000_000,
    }
}

/// Hashes the list.
pub fn hash_all(roots: &Roots) -> (Vec<FileHash>, Vec<String>) {
    let (paths, warnings) = list(roots);
    (paths.iter().map(|p| one(roots, p)).collect(), warnings)
}

/// The directories to watch for changes: the parent of every path the list names (a new file in `sudoers.d` is in the
/// list the moment it exists), and the extras file's own directory.
pub fn watch_dirs(roots: &Roots) -> Vec<PathBuf> {
    let (paths, _) = list(roots);
    let mut dirs: Vec<PathBuf> = paths
        .iter()
        .filter_map(|p| Path::new(p).parent().map(|d| roots.root.join(d.strip_prefix("/").unwrap_or(d))))
        .collect();
    for pattern in COMPILED {
        if let Some(dir) = Path::new(pattern).parent().filter(|d| !d.to_string_lossy().contains('*')) {
            dirs.push(roots.root.join(dir.strip_prefix("/").unwrap_or(dir)));
        }
    }
    dirs.sort();
    dirs.dedup();
    dirs.retain(|d| d.is_dir());
    dirs
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn tree(name: &str) -> Roots {
        let dir = std::env::temp_dir().join(format!("rackhand-hash-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for d in [
            "etc/sudoers.d",
            "etc/ssh/sshd_config.d",
            "etc/rackhand",
            "home/alice/.ssh",
            "home/bob/.ssh",
            "root/.ssh",
            "keys",
        ] {
            std::fs::create_dir_all(dir.join(d)).unwrap();
        }
        let me = std::fs::metadata(&dir).unwrap().uid();
        Roots { root: dir.clone(), extras: dir.join("etc/rackhand/helper-extra-paths"), trusted_uid: me }
    }

    fn put(roots: &Roots, path: &str, text: &str) {
        std::fs::write(roots.root.join(path), text).unwrap();
    }

    fn extras_file(roots: &Roots, lines: usize, mode: u32) {
        let text: String = (0..lines).map(|i| format!("/srv/extra/file{i:04}\n")).collect();
        put(roots, "etc/rackhand/helper-extra-paths", &text);
        std::fs::set_permissions(&roots.extras, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn list_is_compiled_in_plus_root_owned_extras_max_500() {
        let roots = tree("list");
        put(&roots, "etc/sudoers.d/x", "alice ALL=(ALL) ALL\n");
        put(&roots, "etc/passwd", "root:x:0:0\n");
        put(&roots, "etc/ssh/sshd_config.d/10.conf", "PasswordAuthentication no\n");
        put(&roots, "home/alice/.ssh/authorized_keys", "ssh-ed25519 AAAA a\n");
        put(&roots, "home/bob/.ssh/authorized_keys", "ssh-ed25519 BBBB b\n");
        let (paths, warnings) = list(&roots);
        for want in [
            "/etc/sudoers.d/x",
            "/etc/passwd",
            "/etc/ssh/sshd_config.d/10.conf",
            "/home/alice/.ssh/authorized_keys",
            "/home/bob/.ssh/authorized_keys",
        ] {
            assert!(paths.contains(&want.to_string()), "{want} in {paths:?}");
        }
        assert!(warnings.is_empty(), "{warnings:?}");
        // a root-owned extras file adds its paths, up to 500: the 501st is ignored, with a warning
        extras_file(&roots, 501, 0o644);
        let (paths, warnings) = list(&roots);
        assert!(paths.contains(&"/srv/extra/file0499".to_string()));
        assert!(!paths.contains(&"/srv/extra/file0500".to_string()), "the 501st path");
        assert_eq!(paths.iter().filter(|p| p.starts_with("/srv/extra/")).count(), 500);
        assert!(warnings.iter().any(|w| w.contains("more than 500")), "{warnings:?}");
        // one that another user owns, or that others can write, is ignored altogether
        let stranger = Roots { trusted_uid: roots.trusted_uid + 1, ..roots.clone() };
        let (paths, warnings) = list(&stranger);
        assert!(paths.iter().all(|p| !p.starts_with("/srv/extra/")), "not owned by the trusted user");
        assert!(warnings.iter().any(|w| w.contains("isn't owned")), "{warnings:?}");
        extras_file(&roots, 3, 0o666);
        let (paths, _) = list(&roots);
        assert!(paths.iter().all(|p| !p.starts_with("/srv/extra/")), "writable by others");
        // a line that isn't an absolute path names nothing, and a comment is not a path
        put(&roots, "etc/rackhand/helper-extra-paths", "relative/path\n# /etc/comment\n/srv/ok\n");
        std::fs::set_permissions(&roots.extras, std::fs::Permissions::from_mode(0o644)).unwrap();
        let (paths, _) = list(&roots);
        assert!(
            paths.contains(&"/srv/ok".to_string())
                && !paths.iter().any(|p| p.contains("relative") || p.contains("comment"))
        );
    }

    #[test]
    fn authorized_keys_file_directive_names_more_files() {
        let roots = tree("akf");
        put(
            &roots,
            "etc/ssh/sshd_config",
            "Port 22\nAuthorizedKeysFile .ssh/authorized_keys /keys/%u.pub .ssh/authorized_keys2\n",
        );
        let (paths, _) = list(&roots);
        for want in
            ["/home/alice/.ssh/authorized_keys2", "/keys/alice.pub", "/keys/bob.pub", "/root/.ssh/authorized_keys2"]
        {
            assert!(paths.contains(&want.to_string()), "{want} in {paths:?}");
        }
        put(&roots, "etc/ssh/sshd_config", "AuthorizedKeysFile none\n");
        let (paths, _) = list(&roots);
        assert!(!paths.iter().any(|p| p.contains("none")), "{paths:?}");
    }

    #[test]
    fn response_has_metadata_never_contents() {
        let roots = tree("meta");
        put(&roots, "etc/passwd", "root:x:0:0:SECRET-COMMENT\n");
        std::fs::set_permissions(roots.root.join("etc/passwd"), std::fs::Permissions::from_mode(0o640)).unwrap();
        let (hashes, _) = hash_all(&roots);
        let passwd = hashes.iter().find(|h| h.path == "/etc/passwd").unwrap();
        assert!(passwd.exists);
        assert_eq!(passwd.mode, 0o640);
        assert_eq!(passwd.sha256.as_deref().map(str::len), Some(64));
        assert_eq!(passwd.uid, roots.trusted_uid);
        let missing = hashes.iter().find(|h| h.path == "/etc/shadow").unwrap();
        assert_eq!((missing.exists, missing.sha256.clone()), (false, None));
        // what goes over the socket has exactly these fields and not a byte of the file
        let json = serde_json::to_value(passwd).unwrap();
        let mut keys: Vec<&str> = json.as_object().unwrap().keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["exists", "gid", "mode", "mtime_ms", "path", "sha256", "uid"]);
        assert!(!json.to_string().contains("SECRET-COMMENT"));
        // the same content hashes the same, another content differently
        let before = passwd.sha256.clone();
        put(&roots, "etc/passwd", "root:x:0:0:other\n");
        let after = hash_all(&roots).0.into_iter().find(|h| h.path == "/etc/passwd").unwrap().sha256;
        assert_ne!(before, after);
    }

    #[test]
    fn watched_directories_include_the_parents_of_patterns() {
        let roots = tree("watch");
        let dirs = watch_dirs(&roots);
        for want in ["etc", "etc/sudoers.d", "etc/ssh", "etc/pam.d"] {
            let d = roots.root.join(want);
            if d.is_dir() {
                assert!(dirs.contains(&d), "{want} in {dirs:?}");
            }
        }
        assert!(dirs.contains(&roots.root.join("etc/sudoers.d")));
        assert!(dirs.contains(&roots.root.join("home/alice/.ssh")));
    }

    #[test]
    fn wildcards_match_inside_one_component() {
        assert!(wild("*.conf", "a.conf") && wild("*", "x") && wild("a*b*c", "aXbYc") && wild("*.service", ".service"));
        assert!(!wild("*.conf", "a.conff") && !wild("a*", "b") && !wild("*.conf", "conf"));
    }
}
