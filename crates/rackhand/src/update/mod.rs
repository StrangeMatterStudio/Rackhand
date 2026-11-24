//! Hub, relay and operator updates (7.5.7, 7.1, D98, E63, AC67). The hub, the relay and the operator run as unprivileged
//! users, so each does the unprivileged part of its own update (it puts the signed release and a request naming the version
//! in its spool) and a root unit, the updater, does the rest: it trusts only the version in the request, checks the release
//! against its own pinned keys, copies it into the inactive slot, and starts a guard that switches and goes back.
//!
//! The slots are the shared ones of `rackhand_release::slots`, in `/usr/local/lib/rackhand-server` (`rackhand-a`,
//! `rackhand-b`, and the link `rackhand`); the units run `/usr/local/bin/rackhand`, a link to that link. They are outside
//! `/usr/local/lib/rackhand`, which a probe on the same machine watches for changes, because nothing offers the hub its own
//! update the way the hub offers probes theirs.

pub mod apply;
pub mod ask;
pub mod guard;
pub mod request;
pub mod spool;

use std::path::{Path, PathBuf};

use rackhand_release::slots::Layout;

/// The program being updated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Component {
    Hub,
    Relay,
    Operator,
}

impl Component {
    pub fn parse(name: &str) -> Option<Component> {
        match name {
            "hub" => Some(Component::Hub),
            "relay" => Some(Component::Relay),
            "operator" => Some(Component::Operator),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Component::Hub => "hub",
            Component::Relay => "relay",
            Component::Operator => "operator",
        }
    }

    /// The unit that runs it.
    pub fn unit(self) -> &'static str {
        match self {
            Component::Hub => "rackhand-hub.service",
            Component::Relay => "rackhand-relay.service",
            Component::Operator => "rackhand-operator.service",
        }
    }

    /// Its state directory, relative to the root: the spool is `update` in it.
    pub fn state_dir(self) -> &'static str {
        match self {
            Component::Hub => "var/lib/rackhand",
            Component::Relay => "var/lib/rackhand-relay",
            Component::Operator => "var/lib/rackhand-operator",
        }
    }

    /// The transient unit its guard runs as.
    pub fn guard_unit(self) -> String {
        format!("rackhand-update-guard-{}", self.name())
    }
}

/// The largest release the updater takes. The design gives the probe's spool 64 MB and nothing for the hub's, which is the bigger
/// binary; a release build is well under this, a debug build (the integration tests') is not under the probe's.
pub const MAX_SERVER_BYTES: u64 = 256 << 20;

/// The slots' directory.
pub const LIB: &str = "usr/local/lib/rackhand-server";
/// What the units run: a link to the slots' link.
pub const BIN: &str = "usr/local/bin/rackhand";
/// Root's own directory: the guard's copy of the running binary.
pub const UPDATER: &str = "var/lib/rackhand-updater";

/// The spool's files: what the unprivileged side writes, and what root answers.
pub const REQUEST: &str = "request.json";
pub const ANSWER: &str = "answer.json";
pub const ROLLED_BACK: &str = "rolled-back.json";
pub const MANIFEST: &str = "manifest.json";
pub const MANIFEST_SIG: &str = "manifest.json.minisig";
/// The hub's copy of its database from just before the update (`VACUUM INTO`), which the guard puts back on a rollback.
pub const PRE_UPDATE_DB: &str = "pre-update.db";

/// The release file of this machine's `rackhand`, as the release names it and its signature signs it.
pub fn artifact() -> String {
    format!("rackhand-{}-unknown-linux-musl", std::env::consts::ARCH)
}

/// The spool of `component`, relative to the root.
pub fn spool_dir(component: Component) -> PathBuf {
    Path::new(component.state_dir()).join("update")
}

pub fn layout(root: &Path, component: Component) -> Layout {
    Layout {
        root: root.to_path_buf(),
        lib: LIB.into(),
        slots: ["rackhand-a", "rackhand-b"],
        link: "rackhand",
        wrapper: None,
        spool_dir: spool_dir(component),
        spool_file: "rackhand",
        artifact: artifact(),
        max_bytes: MAX_SERVER_BYTES,
    }
}

/// A machine installed before there were slots, or a binary installed again over the link since, has the binary itself at
/// `/usr/local/bin/rackhand`: it moves into the slots' directory as the plain file the next update turns into slot A, and
/// `/usr/local/bin/rackhand` becomes a link to it.
pub fn prepare(root: &Path) -> std::io::Result<()> {
    let bin = root.join(BIN);
    let lib = root.join(LIB);
    let link = lib.join("rackhand");
    std::fs::create_dir_all(&lib)?;
    let meta = std::fs::symlink_metadata(&bin)?;
    if meta.file_type().is_symlink() {
        return Ok(());
    }
    // a plain file there is what was installed last, slots or not: it is what the next update goes back to
    Layout::replace(&link, &std::fs::read(&bin)?, 0o755)?;
    let tmp = bin.with_extension("link");
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(&link, &tmp)?;
    std::fs::rename(&tmp, &bin)
}

#[cfg(test)]
mod tests;
