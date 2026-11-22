//! Window selection (7.5.3 steps 2 and 3): which machines a patch window takes and when. Managed machines with
//! policy `auto` (or an approval) and updates pending for the window, outside maintenance windows and quarantine; at
//! most 3 per site at once; hypervisors and the hub after every other machine at their site, one at a time, the hub
//! last; a machine offline at its turn is tried again every 15 minutes until the window ends. Alpine has no security
//! marker, so it patches only in the full window (D54).

use std::collections::{BTreeMap, HashMap, HashSet};

/// How often a machine that was offline at its turn is tried again.
pub const RETRY_MS: i64 = 15 * 60_000;
/// Jobs at once per site (7.5.3; configurable).
pub const DEFAULT_PER_SITE: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Window {
    Security,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchMode {
    Auto,
    ApproveOnly,
    Hold,
}

impl PatchMode {
    pub fn parse(s: &str) -> PatchMode {
        match s {
            "auto" => PatchMode::Auto,
            "hold" => PatchMode::Hold,
            _ => PatchMode::ApproveOnly,
        }
    }
}

/// A machine as a window sees it at its start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    pub id: String,
    pub site: String,
    pub kind: String,
    pub roles: Vec<String>,
    /// Access level `managed` (a monitor machine has no account to patch with).
    pub managed: bool,
    pub patch: PatchMode,
    pub pending_security: u32,
    pub pending_total: u32,
    pub in_maintenance: bool,
    pub quarantined: bool,
    /// An approve-only machine carries an approval decided after its last window ended.
    pub approved: bool,
}

/// How a window takes a machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum How {
    Run,
    Approval,
}

/// What a window asks for now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Order {
    Start(String),
    AskApproval { id: String, expires_at_ms: i64 },
}

/// What the other windows' runs are doing, by site.
#[derive(Debug, Clone, Default)]
pub struct Others {
    /// Jobs running.
    pub running: BTreeMap<String, usize>,
    /// Sites with ordinary machines still to patch.
    pub waiting: HashSet<String>,
}

/// Whether the window takes the machine, and how.
pub fn eligible(c: &Candidate, window: Window) -> Option<How> {
    if !c.managed || c.in_maintenance || c.quarantined || c.patch == PatchMode::Hold {
        return None;
    }
    let pending = match window {
        Window::Security if c.kind == "alpine" => 0,
        Window::Security => c.pending_security,
        Window::Full => c.pending_total,
    };
    if pending == 0 {
        return None;
    }
    match c.patch {
        PatchMode::ApproveOnly if !c.approved => Some(How::Approval),
        _ => Some(How::Run),
    }
}

/// Hypervisors and the hub go after every other machine at their site, one at a time.
fn last(c: &Candidate) -> bool {
    c.roles.iter().any(|r| r == "hypervisor" || r == "hub")
}

/// One window's run: what is still to patch, what runs, and when an offline machine is tried again.
#[derive(Debug)]
pub struct Run {
    starts_ms: i64,
    ends_ms: i64,
    per_site: usize,
    /// In the order they go: ordinary machines, then hypervisors, then the hub.
    todo: Vec<Candidate>,
    waiting_approval: HashSet<String>,
    approved: HashSet<String>,
    asked: HashSet<String>,
    running: HashMap<String, String>,
    retry_at: HashMap<String, i64>,
}

impl Run {
    pub fn new(window: Window, starts_ms: i64, ends_ms: i64, candidates: Vec<Candidate>, per_site: usize) -> Run {
        let mut todo = Vec::new();
        let mut waiting_approval = HashSet::new();
        for c in candidates {
            match eligible(&c, window) {
                Some(How::Run) => todo.push(c),
                Some(How::Approval) => {
                    waiting_approval.insert(c.id.clone());
                    todo.push(c);
                }
                None => {}
            }
        }
        // ordinary machines, then hypervisors, then the hub; otherwise as given
        let rank = |c: &Candidate| u8::from(last(c)) + u8::from(c.roles.iter().any(|r| r == "hub"));
        todo.sort_by_key(rank);
        Run {
            starts_ms,
            ends_ms,
            per_site: per_site.max(1),
            todo,
            waiting_approval,
            approved: HashSet::new(),
            asked: HashSet::new(),
            running: HashMap::new(),
            retry_at: HashMap::new(),
        }
    }

    pub fn ended(&self, now_ms: i64) -> bool {
        now_ms >= self.ends_ms
    }

    /// A person approved the machine's patch at `at_ms`: it can start if the window is still open.
    pub fn approved(&mut self, id: &str, at_ms: i64) -> bool {
        if self.ended(at_ms) || !self.waiting_approval.contains(id) {
            return false;
        }
        self.approved.insert(id.to_string());
        true
    }

    /// The machines whose approval hasn't been given.
    pub fn waiting_approval(&self) -> Vec<String> {
        self.waiting_approval.iter().filter(|id| !self.approved.contains(*id)).cloned().collect()
    }

    /// The jobs running, by site.
    pub fn running_by_site(&self) -> BTreeMap<String, usize> {
        let mut by_site = BTreeMap::new();
        for site in self.running.values() {
            *by_site.entry(site.clone()).or_default() += 1;
        }
        by_site
    }

    /// The sites with ordinary machines still to patch.
    pub fn waiting_sites(&self) -> HashSet<String> {
        self.todo.iter().filter(|c| !last(c)).map(|c| c.site.clone()).collect()
    }

    /// The machine's job ended (whatever its outcome).
    pub fn finished(&mut self, id: &str) {
        self.running.remove(id);
    }

    /// What to do at `now_ms`: approvals to ask for and jobs to start, the per-site limit and the order kept.
    pub fn step(&mut self, now_ms: i64, online: impl Fn(&str) -> bool) -> Vec<Order> {
        self.step_with(now_ms, online, &Others::default())
    }

    /// `step`, counting what the other windows' runs are doing at each site.
    pub fn step_with(&mut self, now_ms: i64, online: impl Fn(&str) -> bool, others: &Others) -> Vec<Order> {
        let mut orders = Vec::new();
        if self.ended(now_ms) || now_ms < self.starts_ms {
            return orders;
        }
        for id in self.waiting_approval.iter().filter(|id| !self.asked.contains(*id)).cloned().collect::<Vec<_>>() {
            orders.push(Order::AskApproval { id: id.clone(), expires_at_ms: self.ends_ms });
            self.asked.insert(id);
        }
        let mut per_site: BTreeMap<String, usize> = others.running.clone();
        for site in self.running.values() {
            *per_site.entry(site.clone()).or_default() += 1;
        }
        let mut started = Vec::new();
        for (i, c) in self.todo.iter().enumerate() {
            if self.waiting_approval.contains(&c.id) && !self.approved.contains(&c.id) {
                continue;
            }
            if self.retry_at.get(&c.id).is_some_and(|at| *at > now_ms) {
                continue;
            }
            let busy = per_site.get(&c.site).copied().unwrap_or(0);
            if last(c) {
                // only once nothing else at the site is left to patch or running
                let before = others.waiting.contains(&c.site)
                    || self.todo.iter().any(|o| o.site == c.site && o.id != c.id && !last(o))
                    || self.todo[..i].iter().any(|o| o.site == c.site && last(o));
                if busy > 0 || before {
                    continue;
                }
            } else if busy >= self.per_site {
                continue;
            }
            if !online(&c.id) {
                self.retry_at.insert(c.id.clone(), now_ms + RETRY_MS);
                continue;
            }
            *per_site.entry(c.site.clone()).or_default() += 1;
            started.push(i);
        }
        for i in started.into_iter().rev() {
            let c = self.todo.remove(i);
            self.running.insert(c.id.clone(), c.site.clone());
            orders.push(Order::Start(c.id));
        }
        orders
    }
}

#[cfg(test)]
#[path = "select_tests.rs"]
mod tests;
