//! Candidate pairs and their state machine (`docs/design.md` §6).

use std::cmp::Reverse;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::Config;
use crate::candidate::Candidate;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairState {
    /// Eligible for checking.
    Waiting,
    /// Probes sent, awaiting authenticated responses.
    Checking,
    /// Two-way reachability proven.
    Succeeded,
    /// Retry budget exhausted.
    Failed,
}

/// One remote candidate paired with our (single) socket.
#[derive(Debug, Clone)]
pub(crate) struct CandidatePair {
    pub remote: Candidate,
    pub state: PairState,
    /// Transaction IDs we are awaiting acks for, with send times.
    outstanding: Vec<(u64, Instant)>,
    /// `None` means "probe as soon as possible".
    next_probe: Option<Instant>,
    deadline: Option<Instant>,
    /// A valid ack to one of our checks arrived: they hear us.
    got_ack: bool,
    /// A valid check from the peer arrived: we hear them.
    got_check: bool,
    pub rtt: Option<Duration>,
}

impl CandidatePair {
    pub fn new(remote: Candidate) -> Self {
        Self {
            remote,
            state: PairState::Waiting,
            outstanding: Vec::new(),
            next_probe: None,
            deadline: None,
            got_ack: false,
            got_check: false,
            rtt: None,
        }
    }

    pub fn addr(&self) -> SocketAddr {
        self.remote.addr
    }

    /// Ordering for "better pair": candidate preference, then lower RTT.
    pub fn rank(&self) -> (u8, Reverse<Duration>) {
        (
            self.remote.kind.preference(),
            Reverse(self.rtt.unwrap_or(Duration::MAX)),
        )
    }

    pub fn is_active(&self) -> bool {
        matches!(self.state, PairState::Waiting | PairState::Checking)
    }

    pub fn probe_due(&self, now: Instant) -> bool {
        self.is_active() && self.next_probe.is_none_or(|t| now >= t)
    }

    pub fn probe_sent(&mut self, txid: u64, now: Instant, cfg: &Config) {
        if self.state == PairState::Waiting {
            self.state = PairState::Checking;
            self.deadline = Some(now + cfg.pair_timeout);
        }
        self.record(txid, now);
        self.next_probe = Some(now + cfg.probe_interval);
    }

    /// Tracks a check sent outside the normal schedule (nominations, keepalives).
    pub fn record(&mut self, txid: u64, now: Instant) {
        self.outstanding.push((txid, now));
    }

    /// Handles an authenticated ack. Returns whether it matched an
    /// outstanding, unexpired check; stale and unsolicited acks are ignored.
    pub fn ack_received(&mut self, txid: u64, now: Instant, cfg: &Config) -> bool {
        let Some(i) = self
            .outstanding
            .iter()
            .position(|&(t, sent)| t == txid && now - sent <= cfg.check_timeout)
        else {
            return false;
        };
        let (_, sent) = self.outstanding.swap_remove(i);
        self.rtt = Some(now - sent);
        self.got_ack = true;
        self.update();
        true
    }

    /// Handles an authenticated check from this remote. Triggers an
    /// immediate probe back so the peer's side of the pair completes quickly.
    pub fn check_received(&mut self) {
        self.got_check = true;
        if self.is_active() {
            self.next_probe = None;
        }
        self.update();
    }

    pub fn tick(&mut self, now: Instant, cfg: &Config) {
        self.outstanding
            .retain(|&(_, sent)| now - sent <= cfg.check_timeout);
        if self.state == PairState::Checking && self.deadline.is_some_and(|d| now >= d) {
            self.state = PairState::Failed;
        }
    }

    /// Explicit retry policy: puts the pair back to `Waiting` (used when
    /// recovering a lost connection).
    pub fn retry(&mut self) {
        *self = Self::new(self.remote);
    }

    fn update(&mut self) {
        if self.got_ack && self.got_check && self.state != PairState::Failed {
            self.state = PairState::Succeeded;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn needs_both_directions() {
        let cfg = Config::default();
        let now = Instant::now();
        let mut p = CandidatePair::new(Candidate::host("10.0.0.1:1".parse().unwrap()));
        assert!(p.probe_due(now));
        p.probe_sent(7, now, &cfg);
        assert_eq!(p.state, PairState::Checking);
        assert!(!p.ack_received(8, now, &cfg), "unknown txid");
        assert!(p.ack_received(7, now, &cfg));
        assert_eq!(p.state, PairState::Checking, "an ack alone is not enough");
        p.check_received();
        assert_eq!(p.state, PairState::Succeeded);
    }

    #[test]
    fn stale_acks_and_deadline() {
        let cfg = Config::default();
        let t0 = Instant::now();
        let mut p = CandidatePair::new(Candidate::host("10.0.0.1:1".parse().unwrap()));
        p.probe_sent(1, t0, &cfg);
        let late = t0 + cfg.check_timeout + Duration::from_millis(1);
        assert!(!p.ack_received(1, late, &cfg), "stale ack accepted");
        p.tick(t0 + cfg.pair_timeout, &cfg);
        assert_eq!(p.state, PairState::Failed);
        p.retry();
        assert_eq!(p.state, PairState::Waiting);
    }
}
