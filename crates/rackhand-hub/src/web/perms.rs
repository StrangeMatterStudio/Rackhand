//! The permission matrix of 7.7.2. Every guarded route names one row.

pub use crate::policy::approvals::Role;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Permission {
    /// See everything on this hub.
    SeeEverything,
    /// Acknowledge and silence incidents, add notes.
    Respond,
    /// Approve low and normal risk.
    ApproveNormal,
    /// Approve high risk (with step-up).
    ApproveHigh,
    /// Open tunnels and transfers, run diagnostics.
    Operate,
    /// Edit runbooks, playbooks, policies, quarantine rules.
    EditLibrary,
    /// Enroll and unenroll, create invites, MCP keys for others.
    Enroll,
    /// Confirm a guest binding.
    ConfirmBinding,
    /// Users, roles, notifiers, settings.
    Administer,
}

pub const ALL_PERMISSIONS: [Permission; 9] = [
    Permission::SeeEverything,
    Permission::Respond,
    Permission::ApproveNormal,
    Permission::ApproveHigh,
    Permission::Operate,
    Permission::EditLibrary,
    Permission::Enroll,
    Permission::ConfirmBinding,
    Permission::Administer,
];

pub fn allowed(role: Role, p: Permission) -> bool {
    use Permission::*;
    match role {
        Role::Admin => true,
        Role::Responder => matches!(p, SeeEverything | Respond | ApproveNormal | Operate),
        Role::Viewer => p == SeeEverything,
    }
}

pub fn role_name(role: Role) -> &'static str {
    match role {
        Role::Viewer => "viewer",
        Role::Responder => "responder",
        Role::Admin => "admin",
    }
}

pub fn parse_role(name: &str) -> Option<Role> {
    match name {
        "viewer" => Some(Role::Viewer),
        "responder" => Some(Role::Responder),
        "admin" => Some(Role::Admin),
        _ => None,
    }
}
