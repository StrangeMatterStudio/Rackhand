//! The runbook format (7.8.7): TOML with parameters and ordered steps.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::error::{ModelError, parse_duration};
use crate::params::Param;
use crate::validate;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Identity {
    Automation,
    Assistant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Normal,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepKind {
    Ssh,
    Snapshot,
    Rollback,
    RebootIfRequired,
    WaitReport,
    Verify,
    ProbeCheck,
    Api,
    Transfer,
    Tunnel,
    Notify,
    /// Something the hub does itself, from a short fixed list (`call`).
    Hub,
}

/// What a `hub` step may ask the hub to do: send a machine its signed command list, replace its hub keys, revoke its
/// endpoint, or take a guest through provisioning: make its machine and token, have the hypervisor's wrapper give it its
/// enrollment, bind it to the guest, and wait until it has enrolled.
pub const HUB_CALLS: [&str; 7] =
    ["send_commands", "rotate_keys", "revoke", "provision_machine", "send_guest", "bind_guest", "await_machine"];

/// A step's `call` as a name and its `key=value` words (`clone vmid=9000 newid=120`). A word without `=` is no
/// argument. Parameters have been put in by then, and a parameter's pattern holds no space.
pub fn call_parts(call: &str) -> (&str, Vec<(String, String)>) {
    let mut words = call.split_whitespace();
    let name = words.next().unwrap_or("");
    let args = words.filter_map(|w| w.split_once('=')).map(|(k, v)| (k.to_string(), v.to_string())).collect();
    (name, args)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Targets {
    /// Machines by name: the most specific routing match (7.5.2).
    #[serde(default)]
    pub machines: Vec<String>,
    #[serde(default)]
    pub kinds: Vec<String>,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Triggers {
    #[serde(default)]
    pub incident_kinds: Vec<String>,
    #[serde(default)]
    pub auto: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OnFailure {
    pub playbook: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    pub id: String,
    pub kind: StepKind,
    /// `ssh`: the argument array; parameters substitute whole arguments (`{{name}}`).
    #[serde(default)]
    pub cmd: Option<Vec<String>>,
    /// `ssh` to Windows: a script under `C:\Program Files\Rackhand\scripts` and its JSON arguments (7.3.7).
    #[serde(default)]
    pub windows_script: Option<String>,
    #[serde(default)]
    pub windows_args: Option<BTreeMap<String, String>>,
    /// `verify`: checks such as `containers_running:{{project}}`.
    #[serde(default)]
    pub checks: Option<Vec<String>>,
    /// `api`: the driver call.
    #[serde(default)]
    pub call: Option<String>,
    /// `notify`: the message.
    #[serde(default)]
    pub message: Option<String>,
    /// `transfer`: source and destination.
    #[serde(default)]
    pub source: Option<String>,
    #[serde(default)]
    pub dest: Option<String>,
    /// `tunnel`: the port on the target.
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub timeout: Option<String>,
    #[serde(default)]
    pub on_failure: Option<OnFailure>,
    #[serde(default)]
    pub retries: u32,
    #[serde(default)]
    pub idempotent: bool,
    #[serde(default)]
    pub resumable: bool,
    #[serde(default)]
    pub detached: bool,
    /// `reboot_if_required`: reboots whether the machine wants it or not.
    #[serde(default)]
    pub always: bool,
}

impl Step {
    /// Whether the step needs an account on the machine, which a machine at access level `monitor` doesn't have: one that
    /// runs over SSH, sends a file, or sends the machine something over SSH. Revoking an endpoint is the hub's alone.
    pub fn needs_account(&self) -> bool {
        match self.kind {
            StepKind::Ssh | StepKind::Transfer => true,
            StepKind::Hub => {
                // revoking and the bookkeeping of a provisioning are the hub's own; only what goes through the
                // machine's wrapper (the command list, the keys, a guest's enrollment) needs its account
                let call = call_parts(self.call.as_deref().unwrap_or("")).0;
                !["revoke", "provision_machine", "bind_guest", "await_machine"].contains(&call)
            }
            _ => false,
        }
    }

    pub fn timeout_s(&self) -> Option<u64> {
        self.timeout.as_deref().and_then(parse_duration)
    }

    /// Whether the hub may resume the step after its own restart; a detached step always may.
    pub fn is_resumable(&self) -> bool {
        self.resumable || self.detached
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Runbook {
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub targets: Targets,
    pub identity: Identity,
    pub risk: Risk,
    pub autonomy: u8,
    #[serde(default)]
    pub triggers: Option<Triggers>,
    #[serde(default)]
    pub params: BTreeMap<String, Param>,
    #[serde(rename = "step")]
    pub steps: Vec<Step>,
}

impl Runbook {
    /// Parses and validates a runbook. Errors name the line they're about.
    pub fn parse(source: &str) -> Result<Runbook, ModelError> {
        let runbook: Runbook = toml::from_str(source).map_err(|e| ModelError::from_toml(&e, source, 0))?;
        validate::runbook(&runbook, source)?;
        Ok(runbook)
    }
}
