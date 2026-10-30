//! Deterministic network simulation for session tests.
//!
//! Two peers exchange packets through modelled NATs with configurable loss,
//! duplication and reordering. Time is simulated, so every run is
//! reproducible and a 20-second scenario takes milliseconds.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::Config;
use crate::candidate::{Candidate, CandidateKind};
use crate::protocol::{Message, Packet, Role};
use crate::session::{Action, FailReason, Link, SessionMachine, State};

const SERVER: &str = "192.0.2.1:7777";
const STEP: Duration = Duration::from_millis(10);
const KEY: [u8; 16] = [7; 16];
const SESSION: u64 = 42;
const HOST: usize = 0;
const JOINER: usize = 1;

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

/// xorshift64*: small, deterministic, good enough for packet fates.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn chance(&mut self, p: f64) -> bool {
        ((self.next() >> 11) as f64 / (1u64 << 53) as f64) < p
    }

    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next() % n }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mapping {
    /// One public port per local socket ("cone" NATs).
    EndpointIndependent,
    /// A new public port per destination ("symmetric" NATs).
    Symmetric,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Filtering {
    /// Anyone may send to a mapped port (full cone).
    None,
    /// Only endpoints we have sent to may reply (port-restricted cone).
    AddressPort,
}

struct Nat {
    public: IpAddr,
    mapping: Mapping,
    filtering: Filtering,
    next_port: u16,
    ports: HashMap<(SocketAddr, Option<SocketAddr>), u16>,
    owners: HashMap<u16, SocketAddr>,
    permits: HashSet<(u16, SocketAddr)>,
}

impl Nat {
    fn new(public: &str, mapping: Mapping, filtering: Filtering) -> Self {
        Self {
            public: public.parse().unwrap(),
            mapping,
            filtering,
            next_port: 40000,
            ports: HashMap::new(),
            owners: HashMap::new(),
            permits: HashSet::new(),
        }
    }

    fn full_cone(public: &str) -> Self {
        Self::new(public, Mapping::EndpointIndependent, Filtering::None)
    }

    fn port_restricted(public: &str) -> Self {
        Self::new(public, Mapping::EndpointIndependent, Filtering::AddressPort)
    }

    fn symmetric(public: &str) -> Self {
        Self::new(public, Mapping::Symmetric, Filtering::AddressPort)
    }

    fn outbound(&mut self, src: SocketAddr, dst: SocketAddr) -> SocketAddr {
        let key = match self.mapping {
            Mapping::EndpointIndependent => (src, None),
            Mapping::Symmetric => (src, Some(dst)),
        };
        let port = *self.ports.entry(key).or_insert_with(|| {
            self.next_port += 1;
            self.owners.insert(self.next_port, src);
            self.next_port
        });
        self.permits.insert((port, dst));
        SocketAddr::new(self.public, port)
    }

    fn inbound(&self, port: u16, from: SocketAddr) -> Option<SocketAddr> {
        let owner = *self.owners.get(&port)?;
        let allowed = self.filtering == Filtering::None || self.permits.contains(&(port, from));
        allowed.then_some(owner)
    }
}

struct Node {
    addr: SocketAddr,
    nat: Option<usize>,
}

struct InFlight {
    at: Instant,
    to: usize,
    from: SocketAddr,
    bytes: Vec<u8>,
}

struct Sim {
    cfg: Config,
    start: Instant,
    now: Instant,
    rng: Rng,
    nats: Vec<Nat>,
    nodes: [Node; 2],
    sessions: [Option<SessionMachine>; 2],
    flight: Vec<InFlight>,
    loss: f64,
    duplicate: f64,
    jitter: Duration,
    blackout: bool,
    received: [Vec<Vec<u8>>; 2],
    next_tick: Instant,
}

impl Sim {
    /// `nodes` are (local address, index into `nats` or None for public).
    fn new(cfg: Config, nats: Vec<Nat>, nodes: [(&str, Option<usize>); 2]) -> Self {
        let start = Instant::now();
        let mut sim = Self {
            cfg,
            start,
            now: start,
            rng: Rng(0x9e37_79b9_7f4a_7c15),
            nats,
            nodes: nodes.map(|(a, nat)| Node { addr: addr(a), nat }),
            sessions: [None, None],
            flight: Vec::new(),
            loss: 0.0,
            duplicate: 0.0,
            jitter: Duration::ZERO,
            blackout: false,
            received: [Vec::new(), Vec::new()],
            next_tick: start,
        };

        // What the rendezvous server would have told each side.
        let candidates: Vec<Vec<Candidate>> = (0..2)
            .map(|i| {
                let local = sim.nodes[i].addr;
                let observed = match sim.nodes[i].nat {
                    Some(n) => sim.nats[n].outbound(local, addr(SERVER)),
                    None => local,
                };
                let mut cs = vec![Candidate {
                    kind: CandidateKind::ServerReflexive,
                    addr: observed,
                }];
                if observed != local {
                    cs.push(Candidate::host(local));
                }
                cs
            })
            .collect();

        for (i, role) in [(HOST, Role::Controlling), (JOINER, Role::Controlled)] {
            let mut out = Vec::new();
            let s = SessionMachine::new(cfg).start().peer_info(
                Link::new(SESSION, role, KEY),
                candidates[1 - i].clone(),
                start,
                &mut out,
            );
            sim.sessions[i] = Some(s);
            sim.apply(i, out);
        }
        sim
    }

    fn state(&self, i: usize) -> State {
        self.sessions[i].as_ref().unwrap().state()
    }

    fn elapsed(&self) -> Duration {
        self.now - self.start
    }

    fn both(&self, f: impl Fn(State) -> bool) -> bool {
        f(self.state(HOST)) && f(self.state(JOINER))
    }

    /// Runs until `done` holds or `limit` of simulated time passes.
    fn run_until(&mut self, limit: Duration, done: impl Fn(&Sim) -> bool) -> bool {
        let end = self.now + limit;
        while self.now < end {
            if done(self) {
                return true;
            }
            self.step();
        }
        done(self)
    }

    fn step(&mut self) {
        self.now += STEP;
        let now = self.now;

        let (due, later): (Vec<_>, Vec<_>) = self.flight.drain(..).partition(|p| p.at <= now);
        self.flight = later;
        for p in due {
            let Ok(packet) = Packet::decode(&p.bytes) else {
                continue;
            };
            let mut out = Vec::new();
            let s = self.sessions[p.to].take().unwrap();
            self.sessions[p.to] = Some(s.handle_packet(p.from, &p.bytes, packet, now, &mut out));
            self.apply(p.to, out);
        }

        if now >= self.next_tick {
            self.next_tick = now + self.cfg.tick_interval;
            for i in [HOST, JOINER] {
                let mut out = Vec::new();
                let s = self.sessions[i].take().unwrap();
                self.sessions[i] = Some(s.tick(now, &mut out));
                self.apply(i, out);
            }
        }
    }

    fn apply(&mut self, from: usize, actions: Vec<Action>) {
        for a in actions {
            match a {
                Action::Send { to, bytes } => self.send(from, to, bytes),
                Action::Data(d) => self.received[from].push(d),
            }
        }
    }

    fn stats(&self, i: usize) -> crate::SessionStats {
        self.sessions[i].as_ref().unwrap().stats(self.now).unwrap()
    }

    fn send_data(&mut self, i: usize, data: &[u8]) {
        let mut out = Vec::new();
        let now = self.now;
        self.sessions[i]
            .as_mut()
            .unwrap()
            .send_data(data, now, &mut out)
            .unwrap();
        self.apply(i, out);
    }

    fn close(&mut self, i: usize) {
        let mut out = Vec::new();
        let s = self.sessions[i].take().unwrap();
        self.sessions[i] = Some(s.close(&mut out));
        self.apply(i, out);
    }

    /// Routes a datagram from node `from` to address `to` through the NATs.
    fn send(&mut self, from: usize, to: SocketAddr, bytes: Vec<u8>) {
        if self.blackout {
            return;
        }
        let src = self.nodes[from].addr;
        let src_nat = self.nodes[from].nat;

        // Same LAN: delivered directly, no translation.
        let lan_peer =
            (0..2).find(|&j| j != from && self.nodes[j].addr == to && self.nodes[j].nat == src_nat);
        let (dest, wire_src) = if let Some(j) = lan_peer {
            (Some(j), src)
        } else {
            let wire_src = match src_nat {
                Some(n) => self.nats[n].outbound(src, to),
                None => src,
            };
            let dest = match self.nats.iter().position(|n| n.public == to.ip()) {
                // Hairpinning (a NAT routing back to itself) is not modelled.
                Some(n) if Some(n) == src_nat => None,
                Some(n) => self.nats[n].inbound(to.port(), wire_src).and_then(|owner| {
                    (0..2).find(|&j| self.nodes[j].addr == owner && self.nodes[j].nat == Some(n))
                }),
                None => (0..2).find(|&j| self.nodes[j].nat.is_none() && self.nodes[j].addr == to),
            };
            (dest, wire_src)
        };
        let Some(dest) = dest else {
            return;
        };

        let copies = if self.rng.chance(self.duplicate) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            if self.rng.chance(self.loss) {
                continue;
            }
            let delay = Duration::from_millis(5 + self.rng.below(self.jitter.as_millis() as u64));
            self.flight.push(InFlight {
                at: self.now + delay,
                to: dest,
                from: wire_src,
                bytes: bytes.clone(),
            });
        }
    }
}

fn connected(s: State) -> bool {
    matches!(s, State::Connected { .. })
}

fn path(sim: &Sim, i: usize) -> SocketAddr {
    match sim.state(i) {
        State::Connected { addr } => addr,
        s => panic!("node {i} not connected: {s:?}"),
    }
}

fn two_nats(a: Nat, b: Nat) -> Sim {
    Sim::new(
        Config::default(),
        vec![a, b],
        [("10.0.0.2:5000", Some(0)), ("10.1.0.2:6000", Some(1))],
    )
}

#[test]
fn same_lan_uses_host_candidates() {
    let mut sim = Sim::new(
        Config::default(),
        vec![Nat::port_restricted("203.0.113.1")],
        [("10.0.0.2:5000", Some(0)), ("10.0.0.3:6000", Some(0))],
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    assert_eq!(path(&sim, HOST), addr("10.0.0.3:6000"));
    assert_eq!(path(&sim, JOINER), addr("10.0.0.2:5000"));
}

#[test]
fn public_peers() {
    let mut sim = Sim::new(
        Config::default(),
        vec![],
        [("198.51.100.1:5000", None), ("198.51.100.2:6000", None)],
    );
    assert!(sim.run_until(Duration::from_secs(2), |s| s.both(connected)));
}

#[test]
fn full_cone_nats() {
    let mut sim = two_nats(Nat::full_cone("203.0.113.1"), Nat::full_cone("203.0.113.2"));
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    assert_eq!(
        path(&sim, HOST).ip(),
        "203.0.113.2".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn port_restricted_nats() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
}

#[test]
fn symmetric_host_reaches_full_cone_via_peer_reflexive() {
    let mut sim = two_nats(Nat::symmetric("203.0.113.1"), Nat::full_cone("203.0.113.2"));
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    // The joiner talks to a mapping the server never saw.
    let joiner_path = path(&sim, JOINER);
    assert_eq!(joiner_path.ip(), "203.0.113.1".parse::<IpAddr>().unwrap());
    assert_ne!(
        joiner_path.port(),
        40001,
        "should not be the server-facing mapping"
    );
}

#[test]
fn symmetric_nats_fail_within_deadline() {
    let mut sim = two_nats(Nat::symmetric("203.0.113.1"), Nat::symmetric("203.0.113.2"));
    let limit = Config::default().connect_timeout + Duration::from_millis(500);
    let failed = |s: State| s == State::Failed(FailReason::NoPath);
    assert!(
        sim.run_until(limit, |s| s.both(failed)),
        "host {:?}, joiner {:?}",
        sim.state(HOST),
        sim.state(JOINER)
    );
}

#[test]
fn survives_loss_duplication_and_reordering() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    sim.loss = 0.3;
    sim.duplicate = 0.1;
    sim.jitter = Duration::from_millis(80);
    let limit = Config::default().connect_timeout;
    assert!(
        sim.run_until(limit, |s| s.both(connected)),
        "host {:?}, joiner {:?}",
        sim.state(HOST),
        sim.state(JOINER)
    );

    // Duplicated and reordered data is delivered at most once.
    for i in 0..20u8 {
        sim.send_data(HOST, &[i]);
    }
    sim.run_until(Duration::from_secs(1), |_| false);
    let got = &sim.received[JOINER];
    let unique: HashSet<_> = got.iter().collect();
    assert_eq!(unique.len(), got.len(), "duplicate delivered");
    assert!(got.len() >= 8, "only {} of 20 packets arrived", got.len());
}

#[test]
fn data_flows_both_ways() {
    let mut sim = two_nats(
        Nat::full_cone("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.send_data(HOST, b"welcome");
    sim.send_data(JOINER, b"hello");
    sim.run_until(Duration::from_millis(200), |_| false);
    assert_eq!(sim.received[JOINER], vec![b"welcome".to_vec()]);
    assert_eq!(sim.received[HOST], vec![b"hello".to_vec()]);
}

#[test]
fn keepalives_hold_an_idle_connection() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    let stayed = !sim.run_until(Duration::from_secs(60), |s| !s.both(connected));
    assert!(
        stayed,
        "dropped to {:?} / {:?}",
        sim.state(HOST),
        sim.state(JOINER)
    );
}

#[test]
fn short_outage_is_not_a_disconnect() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.blackout = true;
    assert!(!sim.run_until(Duration::from_secs(5), |s| !s.both(connected)));
}

#[test]
fn recovers_after_long_outage() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.blackout = true;
    let cfg = Config::default();
    assert!(
        sim.run_until(cfg.disconnect_timeout + Duration::from_secs(1), |s| s
            .both(|st| st == State::Disconnected))
    );
    sim.blackout = false;
    assert!(
        sim.run_until(cfg.recovery_timeout, |s| s.both(connected)),
        "host {:?}, joiner {:?}",
        sim.state(HOST),
        sim.state(JOINER)
    );
}

#[test]
fn unrecovered_outage_fails() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.blackout = true;
    let cfg = Config::default();
    let failed = |s: State| s == State::Failed(FailReason::ConnectionLost);
    let limit = cfg.disconnect_timeout + cfg.recovery_timeout + Duration::from_secs(1);
    assert!(sim.run_until(limit, |s| s.both(failed)));
    assert!(sim.elapsed() > cfg.disconnect_timeout);
}

#[test]
fn pings_measure_rtt_and_loss() {
    let mut sim = two_nats(
        Nat::port_restricted("203.0.113.1"),
        Nat::port_restricted("203.0.113.2"),
    );
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.run_until(Duration::from_secs(5), |_| false);

    // Each direction takes 5 ms, delivered on a 10 ms step.
    let stats = sim.stats(HOST);
    let rtt = stats.rtt.expect("rtt measured");
    assert!(
        rtt >= Duration::from_millis(10) && rtt <= Duration::from_millis(30),
        "rtt {rtt:?}"
    );
    assert_eq!(stats.loss, 0.0);
    assert_eq!(stats.path, Some(CandidateKind::ServerReflexive));

    sim.loss = 0.5;
    sim.run_until(Duration::from_secs(12), |_| false);
    let loss = sim.stats(HOST).loss;
    // A ping is lost if either it or its pong is: 1 - 0.5² = 75% expected.
    assert!((0.5..=0.95).contains(&loss), "loss {loss}");
}

#[test]
fn close_reaches_the_peer() {
    let mut sim = two_nats(Nat::full_cone("203.0.113.1"), Nat::full_cone("203.0.113.2"));
    assert!(sim.run_until(Duration::from_secs(3), |s| s.both(connected)));
    sim.close(HOST);
    assert!(
        sim.run_until(Duration::from_millis(200), |s| s.state(JOINER)
            == State::Closed)
    );
}

/// Forged, reflected and replayed checks must not be answered.
#[test]
fn rejects_forged_reflected_and_replayed_checks() {
    let now = Instant::now();
    let mut out = Vec::new();
    let peer = addr("198.51.100.2:6000");
    let mut host = SessionMachine::new(Config::default()).start().peer_info(
        Link::new(SESSION, Role::Controlling, KEY),
        vec![Candidate::host(peer)],
        now,
        &mut out,
    );

    let check = |key: &[u8; 16], dir, seq| {
        Packet {
            id: SESSION,
            seq,
            msg: Message::Check {
                txid: 1,
                nominate: false,
            },
        }
        .encode(Some((key, dir)))
        .unwrap()
    };
    let mut deliver = |raw: Vec<u8>| -> usize {
        let mut out = Vec::new();
        let packet = Packet::decode(&raw).unwrap();
        host = std::mem::replace(&mut host, SessionMachine::new(Config::default()))
            .handle_packet(peer, &raw, packet, now, &mut out);
        out.len()
    };

    use crate::auth::Dir;
    assert_eq!(
        deliver(check(&[9; 16], Dir::JoinerToHost, 0)),
        0,
        "wrong key answered"
    );
    assert_eq!(
        deliver(check(&KEY, Dir::HostToJoiner, 0)),
        0,
        "reflected packet answered"
    );
    let valid = check(&KEY, Dir::JoinerToHost, 5);
    assert_eq!(deliver(valid.clone()), 1, "valid check is acked");
    assert_eq!(deliver(valid), 0, "replay answered");
}
