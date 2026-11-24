//! Probe updates across a fleet (13, 7.3.3): the hub offers the current release to its probes one canary per site first, and
//! the rest of the site an hour later if the canary opened no incident in that time. A canary that doesn't come up on the new
//! version (its guard went back) or that has an incident holds the rest of its site for that release. The planning is a
//! function of the clock, the release, the probes and what the hub remembers, so it runs the same in a test as on a hub.
//!
//! What the hub remembers (the canary of each site and release, and whether the rest were let through or held) is kept in
//! `schedule_state` rows, so a restart in the middle of a rollout goes on where it was.

use std::collections::BTreeMap;

use rackhand_proto::common::SemVer;
use rackhand_proto::probe::UpdateAvailable;
use rackhand_release::binary::Version;
use rackhand_release::manifest::Channel;

use crate::scheduler::tasks::ScheduleState;

const MIN: i64 = 60_000;
/// How long a canary runs the release before the rest of its site are offered it.
pub const CANARY_WINDOW_MS: i64 = 60 * MIN;
/// A canary that is connected and still on the old version this long after it was offered the release didn't make it: the
/// guard waits 2 minutes and the restart takes a few seconds, so this is generous.
const CANARY_FAILED_AFTER_MS: i64 = 10 * MIN;
/// A canary that has stayed away this long is replaced by another machine of its site.
const CANARY_REPLACED_AFTER_MS: i64 = 6 * 60 * MIN;
/// A machine isn't offered the same release more often than this (the probe ignores a repeat within ten minutes anyway).
const REOFFER_AFTER_MS: i64 = 10 * MIN;

const KIND_CANARY: &str = "probe_rollout";
const KIND_REST: &str = "probe_rollout_rest";
const KIND_HELD: &str = "probe_rollout_held";

/// One signed file of a release: the hash from the signed manifest and the `.minisig` file's bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFile {
    pub sha256: [u8; 32],
    pub signature: Vec<u8>,
}

/// The release the hub holds: its version and channel, and the probe file for each architecture by file name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Release {
    pub version: Version,
    pub channel: Channel,
    pub artifacts: BTreeMap<String, ReleaseFile>,
}

impl Release {
    /// The file name of the probe for `arch` (`x86_64`, `aarch64`) in a release.
    pub fn probe_file(arch: &str) -> String {
        format!("rackhand-probe-{arch}-unknown-linux-musl")
    }
}

/// A machine with a probe, as far as the rollout needs to know it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub machine: String,
    pub site: String,
    pub version: Version,
    pub arch: String,
    pub connected: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Offer {
    pub machine: String,
    pub update: UpdateAvailable,
}

/// Something the rollout wants the hub to say: `rollout.held` (an incident on the canary) or `rollout.canary_failed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolloutEvent {
    pub kind: &'static str,
    pub site: String,
    pub machine: String,
    pub version: Version,
    pub detail: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Plan {
    pub offers: Vec<Offer>,
    pub events: Vec<RolloutEvent>,
    /// Rows for `schedule_state`: what changed this tick.
    pub saved: Vec<ScheduleState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Phase {
    Canary { machine: String, offered_ms: i64 },
    Rest { canary: String },
    Held { canary: String },
}

#[derive(Debug)]
pub struct Rollout {
    channel: Channel,
    state: BTreeMap<(String, Version), Phase>,
    /// When each machine was last offered a release, since this hub started.
    offered: BTreeMap<String, i64>,
}

fn row(kind: &str, site: &str, version: Version, machine: &str, at_ms: i64) -> ScheduleState {
    ScheduleState {
        kind: kind.into(),
        key: format!("{site}/{version}/{machine}"),
        last_run_ms: Some(at_ms),
        next_run_ms: None,
    }
}

fn parse_key(key: &str) -> Option<(String, Version, String)> {
    let mut parts = key.splitn(3, '/');
    let (site, version, machine) = (parts.next()?, parts.next()?, parts.next()?);
    Some((site.to_string(), Version::parse(version)?, machine.to_string()))
}

impl Rollout {
    /// The channel the hub is on now; a change takes effect at the next tick.
    pub fn set_channel(&mut self, channel: Channel) {
        self.channel = channel;
    }

    pub fn new(channel: Channel) -> Rollout {
        Rollout { channel, state: BTreeMap::new(), offered: BTreeMap::new() }
    }

    /// Takes back what an earlier run saved: a hold outranks a started rest, which outranks a canary, and the newest canary
    /// of a site and release is the canary.
    pub fn restore(&mut self, rows: &[ScheduleState]) {
        let rank = |p: &Phase| match p {
            Phase::Canary { .. } => 0,
            Phase::Rest { .. } => 1,
            Phase::Held { .. } => 2,
        };
        for r in rows {
            let Some((site, version, machine)) = parse_key(&r.key) else { continue };
            let at = r.last_run_ms.unwrap_or(0);
            let phase = match r.kind.as_str() {
                KIND_CANARY => Phase::Canary { machine, offered_ms: at },
                KIND_REST => Phase::Rest { canary: machine },
                KIND_HELD => Phase::Held { canary: machine },
                _ => continue,
            };
            let key = (site, version);
            let keep = match self.state.get(&key) {
                None => true,
                Some(Phase::Canary { offered_ms, .. }) if rank(&phase) == 0 => at > *offered_ms,
                Some(old) => rank(&phase) > rank(old),
            };
            if keep {
                self.state.insert(key, phase);
            }
        }
    }

    fn offer(&mut self, plan: &mut Plan, p: &Probe, release: &Release, url: &dyn Fn(&str) -> String, now: i64) {
        let file = Release::probe_file(&p.arch);
        let Some(artifact) = release.artifacts.get(&file) else { return };
        self.offered.insert(p.machine.clone(), now);
        plan.offers.push(Offer {
            machine: p.machine.clone(),
            update: UpdateAvailable {
                version: Some(SemVer { version: release.version.to_string() }),
                url: url(&file),
                sha256: artifact.sha256.to_vec(),
                signature: artifact.signature.clone(),
            },
        });
    }

    /// What to do at `now_ms` with `release` and `probes`: who is offered the release, what to say and what to remember.
    /// `incident_since(machine, since_ms)` says whether an incident opened on the machine after `since_ms`; `url(file)` is
    /// where the hub serves a release file.
    pub fn tick(
        &mut self,
        now_ms: i64,
        release: &Release,
        probes: &[Probe],
        incident_since: &dyn Fn(&str, i64) -> bool,
        url: &dyn Fn(&str) -> String,
    ) -> Plan {
        let mut plan = Plan::default();
        if !self.channel.offers(release.channel) {
            return plan;
        }
        let mut sites: BTreeMap<&str, Vec<&Probe>> = BTreeMap::new();
        for p in probes {
            sites.entry(p.site.as_str()).or_default().push(p);
        }
        for (site, mut members) in sites {
            members.sort_by(|a, b| a.machine.cmp(&b.machine));
            // the machines this release can go to now: it has a file for them, they're up and behind
            let pending: Vec<&Probe> = members
                .iter()
                .copied()
                .filter(|p| {
                    p.connected
                        && p.version < release.version
                        && release.artifacts.contains_key(&Release::probe_file(&p.arch))
                })
                .collect();
            let key = (site.to_string(), release.version);
            let phase = self.state.get(&key).cloned();
            match phase {
                None => {
                    if let Some(canary) = pending.first() {
                        self.start_canary(&mut plan, site, canary, release, url, now_ms);
                    }
                }
                Some(Phase::Held { .. }) => {}
                Some(Phase::Rest { .. }) => {
                    for p in &pending {
                        if self.offered.get(&p.machine).is_none_or(|at| now_ms - at >= REOFFER_AFTER_MS) {
                            self.offer(&mut plan, p, release, url, now_ms);
                        }
                    }
                }
                Some(Phase::Canary { machine, offered_ms }) => {
                    let canary = members.iter().copied().find(|p| p.machine == machine);
                    let updated = canary.is_some_and(|p| p.version >= release.version);
                    let connected = canary.is_some_and(|p| p.connected);
                    if updated {
                        if incident_since(&machine, offered_ms) {
                            let why = "an incident opened on the canary";
                            self.held(&mut plan, (site, &machine, release.version), "rollout.held", why, now_ms);
                        } else if now_ms - offered_ms >= CANARY_WINDOW_MS {
                            self.state.insert(key, Phase::Rest { canary: machine.clone() });
                            plan.saved.push(row(KIND_REST, site, release.version, &machine, now_ms));
                            for p in pending.iter().filter(|p| p.machine != machine) {
                                self.offer(&mut plan, p, release, url, now_ms);
                            }
                        }
                    } else if connected && now_ms - offered_ms >= CANARY_FAILED_AFTER_MS {
                        let why = "the canary is back on its old version";
                        self.held(&mut plan, (site, &machine, release.version), "rollout.canary_failed", why, now_ms);
                    } else if !connected && now_ms - offered_ms >= CANARY_REPLACED_AFTER_MS {
                        if let Some(next) = pending.iter().find(|p| p.machine != machine) {
                            self.start_canary(&mut plan, site, next, release, url, now_ms);
                        }
                    } else if connected && !self.offered.contains_key(&machine) {
                        // this hub started after the canary was chosen: it may never have been told
                        if let Some(p) = canary {
                            self.offer(&mut plan, p, release, url, now_ms);
                        }
                    }
                }
            }
        }
        plan
    }

    fn start_canary(
        &mut self,
        plan: &mut Plan,
        site: &str,
        canary: &Probe,
        release: &Release,
        url: &dyn Fn(&str) -> String,
        now_ms: i64,
    ) {
        self.state.insert(
            (site.to_string(), release.version),
            Phase::Canary { machine: canary.machine.clone(), offered_ms: now_ms },
        );
        plan.saved.push(row(KIND_CANARY, site, release.version, &canary.machine, now_ms));
        self.offer(plan, canary, release, url, now_ms);
    }

    /// The rest of `site` aren't offered `version`: remembered, and said once.
    fn held(
        &mut self,
        plan: &mut Plan,
        (site, canary, version): (&str, &str, Version),
        kind: &'static str,
        why: &str,
        now_ms: i64,
    ) {
        self.state.insert((site.to_string(), version), Phase::Held { canary: canary.to_string() });
        plan.saved.push(row(KIND_HELD, site, version, canary, now_ms));
        plan.events.push(RolloutEvent {
            kind,
            site: site.to_string(),
            machine: canary.to_string(),
            version,
            detail: format!("{why}; the rest of the site isn't offered {version}"),
        });
    }
}
