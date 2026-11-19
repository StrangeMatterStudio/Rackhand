//! Threshold rules and the defaults of design 7.6.1.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Info,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    Over,
    Under,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Threshold {
    pub op: Op,
    pub value: f64,
    pub duration_s: u32,
}

impl Threshold {
    pub fn breached_by(&self, v: f64) -> bool {
        match self.op {
            Op::Over => v > self.value,
            Op::Under => v < self.value,
        }
    }

    /// Whether `v` is on the safe side by at least `margin`.
    pub fn safe_by(&self, v: f64, margin: f64) -> bool {
        match self.op {
            Op::Over => v < self.value - margin,
            Op::Under => v > self.value + margin,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Rule {
    pub id: &'static str,
    pub metric: &'static str,
    pub warning: Option<Threshold>,
    pub critical: Option<Threshold>,
    /// Clear margin: 2 points for percentages and temperatures, 0.2 for load per core.
    pub margin: f64,
}

impl Rule {
    pub fn level(&self, severity: Severity) -> Option<&Threshold> {
        match severity {
            Severity::Warning => self.warning.as_ref(),
            Severity::Critical => self.critical.as_ref(),
            Severity::Info => None,
        }
    }
}

const fn t(op: Op, value: f64, minutes: u32) -> Option<Threshold> {
    Some(Threshold { op, value, duration_s: minutes * 60 })
}

/// The default threshold rules (7.6.1). Counted rules (services, restarts, checks, updates) are in `counted`.
pub fn default_rules() -> Vec<Rule> {
    use Op::{Over, Under};
    vec![
        Rule {
            id: "cpu.busy",
            metric: "cpu.busy_pct",
            warning: t(Over, 90.0, 15),
            critical: t(Over, 98.0, 30),
            margin: 2.0,
        },
        Rule {
            id: "mem.available",
            metric: "mem.available_pct",
            warning: t(Under, 10.0, 10),
            critical: t(Under, 5.0, 5),
            margin: 2.0,
        },
        Rule {
            id: "swap.used",
            metric: "swap.used_pct",
            warning: t(Over, 50.0, 30),
            critical: t(Over, 90.0, 10),
            margin: 2.0,
        },
        Rule {
            id: "disk.used",
            metric: "disk.used_pct",
            warning: t(Over, 85.0, 5),
            critical: t(Over, 95.0, 5),
            margin: 2.0,
        },
        Rule {
            id: "disk.inodes",
            metric: "disk.inodes_used_pct",
            warning: t(Over, 85.0, 5),
            critical: t(Over, 95.0, 5),
            margin: 2.0,
        },
        Rule {
            id: "load.per_core",
            metric: "load.15m_per_core",
            warning: t(Over, 2.0, 30),
            critical: t(Over, 4.0, 30),
            margin: 0.2,
        },
        Rule { id: "cpu.steal", metric: "cpu.steal_pct", warning: t(Over, 20.0, 15), critical: None, margin: 2.0 },
        Rule { id: "temp", metric: "temp.c", warning: t(Over, 80.0, 5), critical: t(Over, 90.0, 5), margin: 2.0 },
    ]
}
