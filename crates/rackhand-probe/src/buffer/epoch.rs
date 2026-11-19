//! Epochs and sequence numbers (7.3.2, E3, AC48).

/// What the hub's `Welcome` says it already holds for the probe's epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Received {
    pub epoch: u64,
    pub ranges: Vec<(u64, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochState {
    epoch: u64,
    next_seq: u64,
}

pub fn random_epoch() -> u64 {
    let mut b = [0u8; 8];
    // A failed random source is unusable for epochs; fall back to the clock, which still differs per start.
    if getrandom::fill(&mut b).is_err() {
        let t = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(1);
        return t as u64 | 1;
    }
    u64::from_le_bytes(b)
}

impl EpochState {
    /// `backlog` is the epoch and last seq of the newest buffered report. An empty or missing buffer starts a new
    /// random epoch at seq 1.
    pub fn start(backlog: Option<(u64, u64)>) -> EpochState {
        match backlog {
            Some((epoch, last)) => EpochState { epoch, next_seq: last + 1 },
            None => EpochState { epoch: random_epoch(), next_seq: 1 },
        }
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    pub fn peek_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn next_seq(&mut self) -> u64 {
        let s = self.next_seq;
        self.next_seq += 1;
        s
    }

    /// Starts a new epoch when the hub already holds this epoch's next seq (a guest rolled back to a snapshot with a
    /// non-empty buffer). Returns whether the epoch changed (`probe.epoch_changed`).
    pub fn on_welcome(&mut self, received: &Received) -> bool {
        let ahead = received.epoch == self.epoch && received.ranges.iter().any(|&(_, to)| to >= self.next_seq);
        if ahead {
            self.new_epoch();
        }
        ahead
    }

    pub fn new_epoch(&mut self) {
        let mut e = random_epoch();
        while e == self.epoch {
            e = random_epoch();
        }
        *self = EpochState { epoch: e, next_seq: 1 };
    }
}
