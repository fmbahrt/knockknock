//! Path quality measurement over PING/PONG.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use crate::candidate::CandidateKind;
use crate::session::State;

/// How many recent pings loss is computed over.
const HISTORY: usize = 32;

/// Quality of a session's path, as measured by its pings.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SessionStats {
    pub state: State,
    /// Remote candidate kind of the selected path.
    pub path: Option<CandidateKind>,
    /// Smoothed round-trip time.
    pub rtt: Option<Duration>,
    /// RTT variation (jitter).
    pub jitter: Option<Duration>,
    /// Share of recent pings that went unanswered, 0.0–1.0.
    pub loss: f32,
}

#[derive(Debug, Clone, Copy)]
struct Ping {
    id: u32,
    sent: Instant,
    rtt: Option<Duration>,
}

/// Sends pings on a schedule and keeps RTT estimates the way TCP does
/// (RFC 6298: `srtt` and `rttvar` with gains 1/8 and 1/4).
#[derive(Debug)]
pub(crate) struct Pinger {
    next_id: u32,
    next_ping: Instant,
    history: VecDeque<Ping>,
    srtt: Option<Duration>,
    rttvar: Duration,
}

impl Pinger {
    /// `seed` is an RTT already measured during connectivity checks, so
    /// stats are available from the moment the session connects.
    pub fn new(now: Instant, seed: Option<Duration>) -> Self {
        Self {
            next_id: 0,
            next_ping: now,
            history: VecDeque::with_capacity(HISTORY),
            srtt: seed,
            rttvar: seed.map_or(Duration::ZERO, |r| r / 2),
        }
    }

    pub fn due(&self, now: Instant) -> bool {
        now >= self.next_ping
    }

    /// Restarts the schedule, e.g. after recovering a connection.
    pub fn resume(&mut self, now: Instant) {
        self.next_ping = now;
    }

    /// Records a ping about to be sent and returns its ID.
    pub fn sent(&mut self, now: Instant, interval: Duration) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        if self.history.len() == HISTORY {
            self.history.pop_front();
        }
        self.history.push_back(Ping {
            id,
            sent: now,
            rtt: None,
        });
        self.next_ping = now + interval;
        id
    }

    /// Handles a pong. Unknown and duplicate IDs are ignored.
    pub fn pong(&mut self, id: u32, now: Instant) {
        let Some(ping) = self
            .history
            .iter_mut()
            .find(|p| p.id == id && p.rtt.is_none())
        else {
            return;
        };
        let r = now - ping.sent;
        ping.rtt = Some(r);
        match self.srtt {
            None => {
                self.srtt = Some(r);
                self.rttvar = r / 2;
            }
            Some(srtt) => {
                self.rttvar = (self.rttvar * 3 + srtt.abs_diff(r)) / 4;
                self.srtt = Some((srtt * 7 + r) / 8);
            }
        }
    }

    /// Pings older than `timeout` without a pong count as lost.
    pub fn stats(
        &self,
        state: State,
        path: Option<CandidateKind>,
        now: Instant,
        timeout: Duration,
    ) -> SessionStats {
        let settled = self.history.iter().filter(|p| now - p.sent >= timeout);
        let (total, lost) = settled.fold((0, 0), |(t, l), p| {
            (t + 1, l + usize::from(p.rtt.is_none()))
        });
        SessionStats {
            state,
            path,
            rtt: self.srtt,
            jitter: self.srtt.map(|_| self.rttvar),
            loss: if total == 0 {
                0.0
            } else {
                lost as f32 / total as f32
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MS: Duration = Duration::from_millis(1);
    const SEC: Duration = Duration::from_secs(1);

    fn stats(p: &Pinger, now: Instant) -> SessionStats {
        p.stats(State::Connecting, None, now, SEC)
    }

    #[test]
    fn smooths_rtt_and_counts_loss() {
        let t0 = Instant::now();
        let mut p = Pinger::new(t0, None);
        assert_eq!(stats(&p, t0).rtt, None);

        let a = p.sent(t0, SEC);
        assert!(!p.due(t0 + 500 * MS));
        p.pong(a, t0 + 20 * MS);
        assert_eq!(stats(&p, t0).rtt, Some(20 * MS));
        assert_eq!(stats(&p, t0).jitter, Some(10 * MS));

        let b = p.sent(t0 + SEC, SEC);
        p.pong(b, t0 + SEC + 60 * MS);
        p.pong(b, t0 + SEC + 90 * MS); // duplicate: ignored
        assert_eq!(stats(&p, t0 + SEC).rtt, Some(25 * MS)); // 7/8·20 + 1/8·60

        p.sent(t0 + 2 * SEC, SEC); // never answered
        p.sent(t0 + 3 * SEC, SEC); // not settled yet
        let s = stats(&p, t0 + 3 * SEC + 500 * MS);
        assert!((s.loss - 1.0 / 3.0).abs() < 1e-6, "loss {}", s.loss);
    }

    #[test]
    fn seeded_from_checks() {
        let p = Pinger::new(Instant::now(), Some(30 * MS));
        let s = stats(&p, Instant::now());
        assert_eq!((s.rtt, s.jitter), (Some(30 * MS), Some(15 * MS)));
    }
}
