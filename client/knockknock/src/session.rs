//! The per-peer session state machine (`docs/design.md` §5–7).
//!
//! Each state is its own type, following the pattern from
//! <https://hoverbear.org/blog/rust-state-machine-pattern/>: a `Session<S>`
//! can only become another state through a `From` impl, so illegal
//! transitions do not compile. [`SessionMachine`] wraps the states in an enum
//! so sessions can be stored at runtime.
//!
//! The machine is sans-IO: it is fed packets and ticks with the current time
//! and returns [`Action`]s; it never touches a socket or a clock.

use std::net::SocketAddr;
use std::time::Instant;

use crate::auth::{self, Dir, Key, ReplayWindow};
use crate::candidate::{Candidate, CandidateKind};
use crate::pair::{CandidatePair, PairState};
use crate::protocol::{self, MAX_CANDIDATES, MAX_DATA_LEN, Message, Packet, Role};
use crate::stats::{Pinger, SessionStats};
use crate::{Config, Error};

/// The public view of a session's state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    New,
    Gathering,
    Connecting,
    Connected { addr: SocketAddr },
    Disconnected,
    Failed(FailReason),
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailReason {
    /// No candidate pair worked before the deadline (e.g. symmetric NATs).
    NoPath,
    /// An established connection could not be recovered.
    ConnectionLost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Action {
    Send { to: SocketAddr, bytes: Vec<u8> },
    Data(Vec<u8>),
}

/// Session credentials and per-direction counters.
#[derive(Debug)]
pub(crate) struct Link {
    pub session_id: u64,
    pub role: Role,
    key: Key,
    send_seq: u32,
    replay: ReplayWindow,
    next_txid: u64,
}

impl Link {
    pub fn new(session_id: u64, role: Role, key: Key) -> Self {
        Self {
            session_id,
            role,
            key,
            send_seq: 0,
            replay: ReplayWindow::default(),
            next_txid: auth::random_u64(),
        }
    }

    fn dirs(&self) -> (Dir, Dir) {
        match self.role {
            Role::Controlling => (Dir::HostToJoiner, Dir::JoinerToHost),
            Role::Controlled => (Dir::JoinerToHost, Dir::HostToJoiner),
        }
    }

    fn seal(&mut self, msg: Message) -> Vec<u8> {
        let packet = Packet {
            id: self.session_id,
            seq: self.send_seq,
            msg,
        };
        self.send_seq = self.send_seq.wrapping_add(1);
        packet
            .encode(Some((&self.key, self.dirs().0)))
            .expect("session messages are validated before sealing")
    }

    /// Authenticates an incoming packet and applies the replay window.
    fn open(&mut self, raw: &[u8], packet: &Packet) -> bool {
        packet.id == self.session_id
            && protocol::verify(raw, &self.key, self.dirs().1)
            && self.replay.accept(packet.seq)
    }

    fn txid(&mut self) -> u64 {
        self.next_txid = self.next_txid.wrapping_add(1);
        self.next_txid
    }

    fn send(&mut self, to: SocketAddr, msg: Message, out: &mut Vec<Action>) {
        out.push(Action::Send {
            to,
            bytes: self.seal(msg),
        });
    }

    fn check(&mut self, to: SocketAddr, nominate: bool, out: &mut Vec<Action>) -> u64 {
        let txid = self.txid();
        self.send(to, Message::Check { txid, nominate }, out);
        txid
    }

    fn ack(&mut self, to: SocketAddr, txid: u64, nominate: bool, out: &mut Vec<Action>) {
        let observed = to;
        self.send(
            to,
            Message::CheckAck {
                txid,
                nominate,
                observed,
            },
            out,
        );
    }
}

#[derive(Debug, Clone, Copy)]
struct Nomination {
    addr: SocketAddr,
    next_send: Instant,
}

/// Runs connectivity checks over all candidate pairs and, on the host,
/// nominates the best one. Shared by `Connecting` and `Disconnected`.
#[derive(Debug)]
pub(crate) struct Checker {
    /// Kept sorted best-first.
    pairs: Vec<CandidatePair>,
    first_success: Option<Instant>,
    nomination: Option<Nomination>,
}

impl Checker {
    fn new(candidates: Vec<Candidate>) -> Self {
        let mut checker = Self {
            pairs: Vec::new(),
            first_success: None,
            nomination: None,
        };
        for c in candidates {
            checker.add(c);
        }
        checker
    }

    fn add(&mut self, c: Candidate) -> Option<&mut CandidatePair> {
        if self.pairs.len() >= 2 * MAX_CANDIDATES {
            return None;
        }
        if let Some(i) = self.pairs.iter().position(|p| p.addr() == c.addr) {
            return Some(&mut self.pairs[i]);
        }
        self.pairs.push(CandidatePair::new(c));
        self.pairs.sort_by_key(|p| std::cmp::Reverse(p.rank()));
        self.pairs.iter_mut().find(|p| p.addr() == c.addr)
    }

    fn pair_mut(&mut self, addr: SocketAddr) -> Option<&mut CandidatePair> {
        self.pairs.iter_mut().find(|p| p.addr() == addr)
    }

    /// An authenticated check arrived. Unknown sources become peer-reflexive
    /// candidates: the peer's NAT used a mapping the server never saw.
    fn on_check(&mut self, from: SocketAddr) {
        let kind = CandidateKind::PeerReflexive;
        if let Some(p) = self.add(Candidate { kind, addr: from }) {
            p.check_received();
        }
    }

    fn on_ack(&mut self, from: SocketAddr, txid: u64, now: Instant, cfg: &Config) -> bool {
        self.pair_mut(from)
            .is_some_and(|p| p.ack_received(txid, now, cfg))
    }

    fn pair(&self, addr: SocketAddr) -> Option<&CandidatePair> {
        self.pairs.iter().find(|p| p.addr() == addr)
    }

    fn nominated(&self, addr: SocketAddr) -> bool {
        self.nomination.is_some_and(|n| n.addr == addr)
    }

    fn all_failed(&self) -> bool {
        self.nomination.is_none() && self.pairs.iter().all(|p| p.state == PairState::Failed)
    }

    fn reset(&mut self) {
        self.pairs.iter_mut().for_each(CandidatePair::retry);
        self.first_success = None;
        self.nomination = None;
    }

    fn tick(&mut self, link: &mut Link, now: Instant, cfg: &Config, out: &mut Vec<Action>) {
        let mut checking = 0;
        for p in &mut self.pairs {
            p.tick(now, cfg);
            checking += usize::from(p.state == PairState::Checking);
        }
        for p in &mut self.pairs {
            if !p.probe_due(now) {
                continue;
            }
            if p.state == PairState::Waiting {
                if checking >= cfg.max_concurrent_checks {
                    continue;
                }
                checking += 1;
            }
            let txid = link.check(p.addr(), false, out);
            p.probe_sent(txid, now, cfg);
        }
        if link.role == Role::Controlling {
            self.nominate(link, now, cfg, out);
        }
    }

    /// Host only. Waits for the best pair (or `nomination_delay` after the
    /// first success), then sends nominating checks until one is acked.
    fn nominate(&mut self, link: &mut Link, now: Instant, cfg: &Config, out: &mut Vec<Action>) {
        if self.nomination.is_none() {
            let Some(best) = self
                .pairs
                .iter()
                .filter(|p| p.state == PairState::Succeeded)
                .max_by_key(|p| p.rank())
            else {
                return;
            };
            let first = *self.first_success.get_or_insert(now);
            let better_pending = self.pairs.iter().any(|p| {
                p.is_active() && p.remote.kind.preference() > best.remote.kind.preference()
            });
            if better_pending && now < first + cfg.nomination_delay {
                return;
            }
            self.nomination = Some(Nomination {
                addr: best.addr(),
                next_send: now,
            });
        }

        let Some(n) = self.nomination.as_mut() else {
            return;
        };
        if now >= n.next_send {
            n.next_send = now + cfg.probe_interval;
            let addr = n.addr;
            let txid = link.check(addr, true, out);
            if let Some(p) = self.pair_mut(addr) {
                p.record(txid, now);
            }
        }
    }
}

// ---- Typestates ---------------------------------------------------------

#[derive(Debug)]
pub(crate) struct Session<S> {
    cfg: Config,
    state: S,
}

#[derive(Debug)]
pub(crate) struct New;

#[derive(Debug)]
pub(crate) struct Gathering;

#[derive(Debug)]
pub(crate) struct Connecting {
    link: Link,
    checker: Checker,
    deadline: Instant,
}

#[derive(Debug)]
pub(crate) struct Connected {
    link: Link,
    checker: Checker,
    path: SocketAddr,
    last_recv: Instant,
    last_sent: Instant,
    pinger: Pinger,
}

#[derive(Debug)]
pub(crate) struct Disconnected {
    link: Link,
    checker: Checker,
    path: SocketAddr,
    deadline: Instant,
    /// Kept so stats survive a recovered connection.
    pinger: Pinger,
}

#[derive(Debug)]
pub(crate) struct Failed {
    reason: FailReason,
}

#[derive(Debug)]
pub(crate) struct Closed;

impl Session<New> {
    pub fn new(cfg: Config) -> Self {
        Self { cfg, state: New }
    }
}

// ---- Transitions ----------------------------------------------------------

impl From<Session<New>> for Session<Gathering> {
    fn from(s: Session<New>) -> Self {
        Self {
            cfg: s.cfg,
            state: Gathering,
        }
    }
}

impl From<(Session<Gathering>, Link, Vec<Candidate>, Instant)> for Session<Connecting> {
    fn from(
        (s, link, candidates, now): (Session<Gathering>, Link, Vec<Candidate>, Instant),
    ) -> Self {
        Self {
            state: Connecting {
                link,
                checker: Checker::new(candidates),
                deadline: now + s.cfg.connect_timeout,
            },
            cfg: s.cfg,
        }
    }
}

impl From<(Session<Connecting>, SocketAddr, Instant)> for Session<Connected> {
    fn from((s, path, now): (Session<Connecting>, SocketAddr, Instant)) -> Self {
        let seed = s.state.checker.pair(path).and_then(|p| p.rtt);
        Self {
            cfg: s.cfg,
            state: Connected {
                link: s.state.link,
                checker: s.state.checker,
                path,
                last_recv: now,
                last_sent: now,
                pinger: Pinger::new(now, seed),
            },
        }
    }
}

impl From<(Session<Connecting>, FailReason)> for Session<Failed> {
    fn from((s, reason): (Session<Connecting>, FailReason)) -> Self {
        Self {
            cfg: s.cfg,
            state: Failed { reason },
        }
    }
}

impl From<(Session<Connected>, Instant)> for Session<Disconnected> {
    fn from((s, now): (Session<Connected>, Instant)) -> Self {
        let Connected {
            link,
            mut checker,
            path,
            pinger,
            ..
        } = s.state;
        checker.reset();
        Self {
            state: Disconnected {
                link,
                checker,
                path,
                deadline: now + s.cfg.recovery_timeout,
                pinger,
            },
            cfg: s.cfg,
        }
    }
}

impl From<(Session<Disconnected>, SocketAddr, Instant)> for Session<Connected> {
    fn from((s, path, now): (Session<Disconnected>, SocketAddr, Instant)) -> Self {
        let mut pinger = s.state.pinger;
        pinger.resume(now);
        Self {
            cfg: s.cfg,
            state: Connected {
                link: s.state.link,
                checker: s.state.checker,
                path,
                last_recv: now,
                last_sent: now,
                pinger,
            },
        }
    }
}

impl From<(Session<Disconnected>, FailReason)> for Session<Failed> {
    fn from((s, reason): (Session<Disconnected>, FailReason)) -> Self {
        Self {
            cfg: s.cfg,
            state: Failed { reason },
        }
    }
}

/// Every live state may be closed. (A blanket impl would overlap with
/// `From<T> for T` for `Session<Closed>`.)
macro_rules! closable {
    ($($s:ty),*) => {$(
        impl From<Session<$s>> for Session<Closed> {
            fn from(s: Session<$s>) -> Self {
                Self { cfg: s.cfg, state: Closed }
            }
        }
    )*};
}
closable!(New, Gathering, Connecting, Connected, Disconnected, Failed);

// ---- Per-state behaviour ----------------------------------------------------

impl Session<Connecting> {
    fn on_packet(
        mut self,
        from: SocketAddr,
        raw: &[u8],
        packet: Packet,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> SessionMachine {
        let Connecting { link, checker, .. } = &mut self.state;
        if !link.open(raw, &packet) {
            return SessionMachine::Connecting(self);
        }
        match packet.msg {
            Message::Check { txid, nominate } => {
                link.ack(from, txid, nominate, out);
                checker.on_check(from);
                if nominate && link.role == Role::Controlled {
                    return SessionMachine::Connected((self, from, now).into());
                }
            }
            Message::CheckAck { txid, nominate, .. } => {
                let matched = checker.on_ack(from, txid, now, &self.cfg);
                if matched && nominate && link.role == Role::Controlling && checker.nominated(from)
                {
                    return SessionMachine::Connected((self, from, now).into());
                }
            }
            // The peer may already be connected and pinging.
            Message::Ping { id } => link.send(from, Message::Pong { id }, out),
            Message::Close { .. } => return SessionMachine::Closed(self.into()),
            _ => {}
        }
        SessionMachine::Connecting(self)
    }

    fn on_tick(mut self, now: Instant, out: &mut Vec<Action>) -> SessionMachine {
        let Connecting {
            link,
            checker,
            deadline,
        } = &mut self.state;
        checker.tick(link, now, &self.cfg, out);
        if now >= *deadline || checker.all_failed() {
            return SessionMachine::Failed((self, FailReason::NoPath).into());
        }
        SessionMachine::Connecting(self)
    }
}

impl Session<Connected> {
    fn on_packet(
        mut self,
        from: SocketAddr,
        raw: &[u8],
        packet: Packet,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> SessionMachine {
        let s = &mut self.state;
        if !s.link.open(raw, &packet) {
            return SessionMachine::Connected(self);
        }
        if from == s.path {
            s.last_recv = now;
        }
        match packet.msg {
            Message::Check { txid, nominate } => {
                s.link.ack(from, txid, nominate, out);
                // The host re-nominated a different path.
                if nominate && from != s.path && s.link.role == Role::Controlled {
                    s.path = from;
                    s.last_recv = now;
                }
            }
            Message::Ping { id } => s.link.send(from, Message::Pong { id }, out),
            Message::Pong { id } if from == s.path => s.pinger.pong(id, now),
            Message::Data(data) if from == s.path => out.push(Action::Data(data)),
            Message::Close { .. } => return SessionMachine::Closed(self.into()),
            _ => {}
        }
        SessionMachine::Connected(self)
    }

    fn on_tick(mut self, now: Instant, out: &mut Vec<Action>) -> SessionMachine {
        let s = &mut self.state;
        if now - s.last_recv >= self.cfg.disconnect_timeout {
            return SessionMachine::Disconnected((self, now).into());
        }
        if let Some(interval) = self.cfg.ping_interval
            && s.pinger.due(now)
        {
            let id = s.pinger.sent(now, interval);
            s.link.send(s.path, Message::Ping { id }, out);
            s.last_sent = now;
        }
        if now - s.last_sent >= self.cfg.keepalive_interval {
            let txid = s.link.check(s.path, false, out);
            if let Some(p) = s.checker.pair_mut(s.path) {
                p.record(txid, now);
            }
            s.last_sent = now;
        }
        SessionMachine::Connected(self)
    }

    fn send_data(&mut self, data: &[u8], now: Instant, out: &mut Vec<Action>) {
        let s = &mut self.state;
        s.link.send(s.path, Message::Data(data.to_vec()), out);
        s.last_sent = now;
    }
}

impl Session<Disconnected> {
    fn on_packet(
        mut self,
        from: SocketAddr,
        raw: &[u8],
        packet: Packet,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> SessionMachine {
        let Disconnected {
            link,
            checker,
            path,
            pinger,
            ..
        } = &mut self.state;
        if !link.open(raw, &packet) {
            return SessionMachine::Disconnected(self);
        }
        let old_path = *path;
        let mut new_path = (from == old_path).then_some(from);
        match packet.msg {
            Message::Check { txid, nominate } => {
                link.ack(from, txid, nominate, out);
                checker.on_check(from);
                if nominate && link.role == Role::Controlled {
                    new_path = Some(from);
                }
            }
            Message::CheckAck { txid, nominate, .. } => {
                let matched = checker.on_ack(from, txid, now, &self.cfg);
                if matched && nominate && link.role == Role::Controlling && checker.nominated(from)
                {
                    new_path = Some(from);
                }
            }
            Message::Ping { id } => link.send(from, Message::Pong { id }, out),
            Message::Pong { id } if from == old_path => pinger.pong(id, now),
            Message::Data(data) if from == old_path => out.push(Action::Data(data)),
            Message::Close { .. } => return SessionMachine::Closed(self.into()),
            _ => {}
        }
        match new_path {
            Some(path) => SessionMachine::Connected((self, path, now).into()),
            None => SessionMachine::Disconnected(self),
        }
    }

    fn on_tick(mut self, now: Instant, out: &mut Vec<Action>) -> SessionMachine {
        let Disconnected {
            link,
            checker,
            deadline,
            ..
        } = &mut self.state;
        checker.tick(link, now, &self.cfg, out);
        if now >= *deadline {
            return SessionMachine::Failed((self, FailReason::ConnectionLost).into());
        }
        SessionMachine::Disconnected(self)
    }
}

// ---- Runtime wrapper --------------------------------------------------------

#[derive(Debug)]
pub(crate) enum SessionMachine {
    New(Session<New>),
    Gathering(Session<Gathering>),
    Connecting(Session<Connecting>),
    Connected(Session<Connected>),
    Disconnected(Session<Disconnected>),
    Failed(Session<Failed>),
    // Holds no data anyone reads, but stays a `Session<S>` like every state.
    #[allow(dead_code)]
    Closed(Session<Closed>),
}

impl SessionMachine {
    pub fn new(cfg: Config) -> Self {
        Self::New(Session::new(cfg))
    }

    pub fn state(&self) -> State {
        match self {
            Self::New(_) => State::New,
            Self::Gathering(_) => State::Gathering,
            Self::Connecting(_) => State::Connecting,
            Self::Connected(s) => State::Connected { addr: s.state.path },
            Self::Disconnected(_) => State::Disconnected,
            Self::Failed(s) => State::Failed(s.state.reason),
            Self::Closed(_) => State::Closed,
        }
    }

    /// Path quality, for sessions that have reached `Connecting`.
    pub fn stats(&self, now: Instant) -> Option<SessionStats> {
        let state = self.state();
        let (cfg, pinger, checker, path) = match self {
            Self::Connecting(_) => {
                return Some(SessionStats {
                    state,
                    path: None,
                    rtt: None,
                    jitter: None,
                    loss: 0.0,
                });
            }
            Self::Connected(s) => (&s.cfg, &s.state.pinger, &s.state.checker, s.state.path),
            Self::Disconnected(s) => (&s.cfg, &s.state.pinger, &s.state.checker, s.state.path),
            _ => return None,
        };
        let kind = checker.pair(path).map(|p| p.remote.kind);
        Some(pinger.stats(state, kind, now, cfg.check_timeout))
    }

    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Failed(_) | Self::Closed(_))
    }

    fn link(&self) -> Option<&Link> {
        match self {
            Self::Connecting(s) => Some(&s.state.link),
            Self::Connected(s) => Some(&s.state.link),
            Self::Disconnected(s) => Some(&s.state.link),
            _ => None,
        }
    }

    /// Whether any authenticated packet has arrived from the peer.
    pub fn heard_from_peer(&self) -> bool {
        self.link().is_some_and(|l| l.replay.any())
    }

    /// New → Gathering.
    pub fn start(self) -> Self {
        match self {
            Self::New(s) => Self::Gathering(s.into()),
            other => other,
        }
    }

    /// Gathering → Connecting, once the server has told us about the peer.
    pub fn peer_info(
        self,
        link: Link,
        candidates: Vec<Candidate>,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> Self {
        match self {
            Self::Gathering(s) => {
                Self::Connecting((s, link, candidates, now).into()).tick(now, out)
            }
            other => other,
        }
    }

    pub fn handle_packet(
        self,
        from: SocketAddr,
        raw: &[u8],
        packet: Packet,
        now: Instant,
        out: &mut Vec<Action>,
    ) -> Self {
        match self {
            Self::Connecting(s) => s.on_packet(from, raw, packet, now, out),
            Self::Connected(s) => s.on_packet(from, raw, packet, now, out),
            Self::Disconnected(s) => s.on_packet(from, raw, packet, now, out),
            other => other,
        }
    }

    pub fn tick(self, now: Instant, out: &mut Vec<Action>) -> Self {
        match self {
            Self::Connecting(s) => s.on_tick(now, out),
            Self::Connected(s) => s.on_tick(now, out),
            Self::Disconnected(s) => s.on_tick(now, out),
            other => other,
        }
    }

    pub fn send_data(
        &mut self,
        data: &[u8],
        now: Instant,
        out: &mut Vec<Action>,
    ) -> Result<(), Error> {
        if data.len() > MAX_DATA_LEN {
            return Err(Error::Protocol(protocol::ProtocolError::BadField));
        }
        match self {
            Self::Connected(s) => {
                s.send_data(data, now, out);
                Ok(())
            }
            _ => Err(Error::NotConnected),
        }
    }

    /// Any state → Closed, telling the peer if we have a path to it.
    pub fn close(self, out: &mut Vec<Action>) -> Self {
        let bye = Message::Close { reason: 0 };
        match self {
            Self::New(s) => Self::Closed(s.into()),
            Self::Gathering(s) => Self::Closed(s.into()),
            Self::Connecting(s) => Self::Closed(s.into()),
            Self::Connected(mut s) => {
                s.state.link.send(s.state.path, bye, out);
                Self::Closed(s.into())
            }
            Self::Disconnected(mut s) => {
                s.state.link.send(s.state.path, bye, out);
                Self::Closed(s.into())
            }
            Self::Failed(s) => Self::Closed(s.into()),
            closed @ Self::Closed(_) => closed,
        }
    }
}
