//! The sans-IO peer: registration with the rendezvous server, lobby hosting
//! or joining, and routing of packets to sessions. One `Agent` owns one UDP
//! socket's worth of state. The caller moves bytes and time in and out:
//!
//! - feed received datagrams to [`Agent::handle_packet`],
//! - call [`Agent::handle_timeout`] when [`Agent::poll_timeout`] is reached,
//! - drain [`Agent::poll_output`] and send the datagrams it returns.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::auth::{self, Dir, Key, ReplayWindow};
use crate::candidate::Candidate;
use crate::protocol::{
    self, ErrorCode, LobbyId, MAX_STATS, Message, Packet, ReportedState, Role, StatsEntry,
};
use crate::session::{Action, Link, SessionMachine, State};
use crate::stats::SessionStats;
use crate::{Config, Error};

pub type SessionId = u64;

/// What this agent does in the lobby.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Open a lobby and accept joiners.
    Host,
    /// Join an existing lobby.
    Join(LobbyId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// Registered (or re-registered) with the rendezvous server. Hosts get
    /// their lobby ID here.
    Registered {
        observed: SocketAddr,
        lobby: Option<LobbyId>,
    },
    /// A session changed state.
    Session { id: SessionId, state: State },
    /// Application data from a connected peer.
    Data { session: SessionId, data: Vec<u8> },
    /// The rendezvous server rejected a request.
    ServerError(ErrorCode),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    Transmit { to: SocketAddr, bytes: Vec<u8> },
    Event(Event),
}

#[derive(Debug)]
enum Registration {
    Pending {
        nonce: u64,
        next_send: Instant,
    },
    Active {
        client_id: u64,
        secret: Key,
        nonce: u64,
        replay: ReplayWindow,
        observed: SocketAddr,
        lobby: Option<LobbyId>,
        next_refresh: Instant,
        refresh_interval: Duration,
    },
    Closed,
}

#[derive(Debug)]
pub struct Agent {
    cfg: Config,
    server: SocketAddr,
    local: Vec<Candidate>,
    mode: Mode,
    reg: Registration,
    server_seq: u32,
    sessions: HashMap<SessionId, SessionMachine>,
    /// The joiner's session before the server has introduced us.
    pending: Option<SessionMachine>,
    next_join: Instant,
    next_stats: Instant,
    last_tick: Instant,
    out: VecDeque<Output>,
}

impl Agent {
    /// `local` are our host candidates (see [`crate::candidate::gather_host`]).
    pub fn new(
        cfg: Config,
        server: SocketAddr,
        local: Vec<Candidate>,
        mode: Mode,
        now: Instant,
    ) -> Self {
        let pending = match mode {
            Mode::Host => None,
            Mode::Join(_) => Some(SessionMachine::new(cfg).start()),
        };
        Self {
            cfg,
            server,
            local,
            mode,
            reg: Registration::Pending {
                nonce: auth::random_u64(),
                next_send: now,
            },
            server_seq: 0,
            sessions: HashMap::new(),
            pending,
            next_join: now,
            next_stats: now + cfg.stats_interval,
            last_tick: now,
            out: VecDeque::new(),
        }
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    pub fn session_state(&self, id: SessionId) -> Option<State> {
        self.sessions.get(&id).map(SessionMachine::state)
    }

    /// Path quality for a session: RTT, jitter and loss from its pings.
    pub fn stats(&self, id: SessionId, now: Instant) -> Option<SessionStats> {
        self.sessions.get(&id)?.stats(now)
    }

    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    /// When [`Agent::handle_timeout`] should next be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let reg = match &self.reg {
            Registration::Pending { next_send, .. } => Some(*next_send),
            Registration::Active { next_refresh, .. } => Some(*next_refresh),
            Registration::Closed => None,
        };
        let join = self.wants_join().then_some(self.next_join);
        let stats = self.wants_stats().then_some(self.next_stats);
        let active = self.pending.is_some() || self.sessions.values().any(|s| !s.is_terminal());
        let tick = active.then(|| self.last_tick + self.cfg.tick_interval);
        [reg, join, stats, tick].into_iter().flatten().min()
    }

    pub fn handle_packet(&mut self, from: SocketAddr, raw: &[u8], now: Instant) {
        let Ok(packet) = Packet::decode(raw) else {
            return;
        };
        if from == self.server {
            self.handle_server(raw, packet, now);
        } else if self.sessions.contains_key(&packet.id) {
            self.step(packet.id, |s, out| {
                s.handle_packet(from, raw, packet, now, out)
            });
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.last_tick = now;
        let register = match &mut self.reg {
            Registration::Pending { nonce, next_send } if now >= *next_send => {
                *next_send = now + self.cfg.server_retry;
                Some((*nonce, None))
            }
            Registration::Active {
                secret,
                nonce,
                next_refresh,
                refresh_interval,
                ..
            } if now >= *next_refresh => {
                *next_refresh = now + *refresh_interval;
                Some((*nonce, Some(*secret)))
            }
            _ => None,
        };
        if let Some((nonce, secret)) = register {
            let msg = self.register_msg(nonce);
            self.send_server(msg, secret.as_ref());
        }

        if self.wants_join() && now >= self.next_join {
            self.next_join = now + self.cfg.server_retry;
            if let (Mode::Join(lobby), Registration::Active { secret, .. }) = (self.mode, &self.reg)
            {
                let secret = *secret;
                self.send_server(Message::Join { lobby }, Some(&secret));
            }
        }

        let ids: Vec<_> = self.sessions.keys().copied().collect();
        for id in ids {
            self.step(id, |s, out| s.tick(now, out));
        }

        if self.wants_stats() && now >= self.next_stats {
            self.next_stats = now + self.cfg.stats_interval;
            self.report_stats(now);
        }
    }

    /// Sends application data to a connected peer.
    pub fn send(&mut self, session: SessionId, data: &[u8], now: Instant) -> Result<(), Error> {
        let s = self
            .sessions
            .get_mut(&session)
            .ok_or(Error::UnknownSession)?;
        let mut actions = Vec::new();
        s.send_data(data, now, &mut actions)?;
        self.apply(session, actions);
        Ok(())
    }

    /// Closes one session, telling the peer.
    pub fn close_session(&mut self, session: SessionId) {
        if self.sessions.contains_key(&session) {
            self.step(session, |s, out| s.close(out));
        }
    }

    /// Closes every session and leaves the rendezvous server.
    pub fn close(&mut self) {
        let ids: Vec<_> = self.sessions.keys().copied().collect();
        for id in ids {
            self.close_session(id);
        }
        self.pending = None;
        if let Registration::Active { secret, .. } = self.reg {
            self.send_server(Message::Close { reason: 0 }, Some(&secret));
        }
        self.reg = Registration::Closed;
    }

    fn handle_server(&mut self, raw: &[u8], packet: Packet, now: Instant) {
        if let Message::Registered {
            nonce,
            secret,
            observed,
            lobby,
            ttl_secs,
        } = packet.msg
        {
            self.handle_registered(
                raw, packet.id, packet.seq, nonce, secret, observed, lobby, ttl_secs, now,
            );
            return;
        }

        // Only two error codes may arrive unauthenticated, and only in
        // response to one of our recent packets.
        if let Message::Error { code, ref_seq } = packet.msg
            && packet.id == 0
        {
            let recent = self.server_seq.wrapping_sub(ref_seq).wrapping_sub(1) < 16;
            if recent && matches!(code, ErrorCode::BadAuth | ErrorCode::UnknownClient) {
                self.server_error(code, now);
            }
            return;
        }

        let Registration::Active {
            client_id,
            secret,
            replay,
            ..
        } = &mut self.reg
        else {
            return;
        };
        if packet.id != *client_id
            || !protocol::verify(raw, secret, Dir::ServerToClient)
            || !replay.accept(packet.seq)
        {
            return;
        }

        match packet.msg {
            Message::PeerInfo {
                session_id,
                role,
                key,
                candidates,
            } => self.handle_peer_info(session_id, role, key, candidates, now),
            Message::Error { code, .. } => self.server_error(code, now),
            _ => {}
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn handle_registered(
        &mut self,
        raw: &[u8],
        client_id: u64,
        seq: u32,
        nonce: u64,
        secret: Key,
        observed: SocketAddr,
        lobby: Option<LobbyId>,
        ttl_secs: u16,
        now: Instant,
    ) {
        match &mut self.reg {
            Registration::Pending { nonce: ours, .. }
                if *ours == nonce && protocol::verify(raw, &secret, Dir::ServerToClient) =>
            {
                let mut replay = ReplayWindow::default();
                replay.accept(seq);
                let refresh_interval = Duration::from_secs(u64::from(ttl_secs.max(4)) / 4);
                self.reg = Registration::Active {
                    client_id,
                    secret,
                    nonce,
                    replay,
                    observed,
                    lobby,
                    next_refresh: now + refresh_interval,
                    refresh_interval,
                };
                self.next_join = now;
                self.event(Event::Registered { observed, lobby });
            }
            Registration::Active {
                client_id: id,
                secret: ours,
                replay,
                observed: known_observed,
                lobby: known_lobby,
                ..
            } if *id == client_id && protocol::verify(raw, ours, Dir::ServerToClient) => {
                if !replay.accept(seq) {
                    return;
                }
                if (*known_observed, *known_lobby) != (observed, lobby) {
                    (*known_observed, *known_lobby) = (observed, lobby);
                    self.event(Event::Registered { observed, lobby });
                }
            }
            _ => {}
        }
    }

    fn handle_peer_info(
        &mut self,
        session_id: SessionId,
        role: Role,
        key: Key,
        candidates: Vec<Candidate>,
        now: Instant,
    ) {
        if self.sessions.contains_key(&session_id) {
            return; // duplicate after a retried JOIN
        }
        let session = match (self.mode, role) {
            (Mode::Host, Role::Controlling) => SessionMachine::new(self.cfg).start(),
            (Mode::Join(_), Role::Controlled) => match self.pending.take() {
                Some(s) => s,
                None => return,
            },
            _ => return,
        };
        let link = Link::new(session_id, role, key);
        self.sessions.insert(session_id, session);
        self.step(session_id, |s, out| s.peer_info(link, candidates, now, out));
    }

    fn server_error(&mut self, code: ErrorCode, now: Instant) {
        match code {
            // The server forgot us (e.g. it restarted): register again.
            ErrorCode::BadAuth | ErrorCode::UnknownClient => {
                self.reg = Registration::Pending {
                    nonce: auth::random_u64(),
                    next_send: now,
                };
            }
            ErrorCode::LobbyNotFound | ErrorCode::LobbyFull => self.pending = None,
            ErrorCode::Unknown(_) => {}
        }
        self.event(Event::ServerError(code));
    }

    /// A joiner keeps sending JOIN until it is introduced and has heard from
    /// the host, since the host's PEER_INFO may have been lost.
    fn wants_join(&self) -> bool {
        matches!(self.mode, Mode::Join(_))
            && matches!(self.reg, Registration::Active { .. })
            && (self.pending.is_some()
                || self
                    .sessions
                    .values()
                    .any(|s| s.state() == State::Connecting && !s.heard_from_peer()))
    }

    /// Hosts report their sessions' path quality to the server.
    fn wants_stats(&self) -> bool {
        self.mode == Mode::Host
            && matches!(self.reg, Registration::Active { .. })
            && !self.sessions.is_empty()
    }

    fn report_stats(&mut self, now: Instant) {
        let Registration::Active { secret, .. } = self.reg else {
            return;
        };
        let micros = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX - 1);
        let entries: Vec<_> = self
            .sessions
            .iter()
            .filter_map(|(&session_id, s)| {
                let st = s.stats(now)?;
                let state = match st.state {
                    State::Connecting => ReportedState::Connecting,
                    State::Connected { .. } => ReportedState::Connected,
                    State::Disconnected => ReportedState::Disconnected,
                    _ => return None,
                };
                Some(StatsEntry {
                    session_id,
                    state,
                    path: st.path,
                    rtt_us: st.rtt.map(micros),
                    rttvar_us: st.jitter.map(micros),
                    loss_permille: (st.loss * 1000.0).round() as u16,
                })
            })
            .take(MAX_STATS)
            .collect();
        self.send_server(Message::Stats(entries), Some(&secret));
    }

    fn register_msg(&self, nonce: u64) -> Message {
        Message::Register {
            nonce,
            host: self.mode == Mode::Host,
            candidates: self.local.clone(),
        }
    }

    fn send_server(&mut self, msg: Message, secret: Option<&Key>) {
        let client_id = match self.reg {
            Registration::Active { client_id, .. } if secret.is_some() => client_id,
            _ => 0,
        };
        let packet = Packet {
            id: client_id,
            seq: self.server_seq,
            msg,
        };
        self.server_seq = self.server_seq.wrapping_add(1);
        if let Ok(bytes) = packet.encode(secret.map(|k| (k, Dir::ClientToServer))) {
            self.out.push_back(Output::Transmit {
                to: self.server,
                bytes,
            });
        }
    }

    /// Runs one transition on a session and reports what changed.
    fn step(
        &mut self,
        id: SessionId,
        f: impl FnOnce(SessionMachine, &mut Vec<Action>) -> SessionMachine,
    ) {
        let Some(session) = self.sessions.remove(&id) else {
            return;
        };
        let before = session.state();
        let mut actions = Vec::new();
        let session = f(session, &mut actions);
        let after = session.state();
        self.apply(id, actions);
        if after != before {
            self.event(Event::Session { id, state: after });
        }
        if !session.is_terminal() {
            self.sessions.insert(id, session);
        }
    }

    fn apply(&mut self, session: SessionId, actions: Vec<Action>) {
        for a in actions {
            self.out.push_back(match a {
                Action::Send { to, bytes } => Output::Transmit { to, bytes },
                Action::Data(data) => Output::Event(Event::Data { session, data }),
            });
        }
    }

    fn event(&mut self, e: Event) {
        self.out.push_back(Output::Event(e));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::CandidateKind;

    const SECRET: Key = [3; 16];
    const CLIENT: u64 = 77;

    fn server() -> SocketAddr {
        "192.0.2.1:7777".parse().unwrap()
    }

    /// A scripted rendezvous server: decodes what the agent sends and seals replies.
    struct FakeServer {
        seq: u32,
    }

    impl FakeServer {
        fn reply(&mut self, msg: Message) -> Vec<u8> {
            self.seq += 1;
            Packet {
                id: CLIENT,
                seq: self.seq,
                msg,
            }
            .encode(Some((&SECRET, Dir::ServerToClient)))
            .unwrap()
        }
    }

    fn drain(agent: &mut Agent) -> (Vec<Packet>, Vec<Event>) {
        let (mut sent, mut events) = (Vec::new(), Vec::new());
        while let Some(o) = agent.poll_output() {
            match o {
                Output::Transmit { to, bytes } if to == server() => {
                    sent.push(Packet::decode(&bytes).unwrap())
                }
                Output::Transmit { .. } => {}
                Output::Event(e) => events.push(e),
            }
        }
        (sent, events)
    }

    /// Runs the registration handshake and returns the resulting events.
    fn register(
        agent: &mut Agent,
        srv: &mut FakeServer,
        lobby: Option<LobbyId>,
        now: Instant,
    ) -> Vec<Event> {
        agent.handle_timeout(now);
        let (sent, _) = drain(agent);
        let Message::Register { nonce, .. } = sent[0].msg else {
            panic!("expected REGISTER, got {:?}", sent[0]);
        };
        let reply = srv.reply(Message::Registered {
            nonce,
            secret: SECRET,
            observed: "203.0.113.9:40001".parse().unwrap(),
            lobby,
            ttl_secs: 60,
        });
        agent.handle_packet(server(), &reply, now);
        drain(agent).1
    }

    #[test]
    fn host_registers_and_accepts_a_joiner() {
        let now = Instant::now();
        let local = vec![Candidate::host("10.0.0.2:5000".parse().unwrap())];
        let mut agent = Agent::new(Config::default(), server(), local, Mode::Host, now);
        let mut srv = FakeServer { seq: 0 };

        agent.handle_timeout(now);
        let (sent, _) = drain(&mut agent);
        assert!(
            matches!(&sent[0], Packet { id: 0, msg: Message::Register { host: true, candidates, .. }, .. } if candidates.len() == 1)
        );

        // A reply with the wrong nonce is ignored.
        let forged = srv.reply(Message::Registered {
            nonce: 1,
            secret: SECRET,
            observed: "203.0.113.9:40001".parse().unwrap(),
            lobby: None,
            ttl_secs: 60,
        });
        agent.handle_packet(server(), &forged, now);
        assert!(drain(&mut agent).1.is_empty());

        let lobby: LobbyId = "K7M2QX".parse().unwrap();
        // The retry carries the same nonce.
        let now = now + Config::default().server_retry;
        let events = register(&mut agent, &mut srv, Some(lobby), now);
        assert!(matches!(events[..], [Event::Registered { lobby: Some(l), .. }] if l == lobby));

        let peer_info = srv.reply(Message::PeerInfo {
            session_id: 5,
            role: Role::Controlling,
            key: [1; 16],
            candidates: vec![Candidate {
                kind: CandidateKind::ServerReflexive,
                addr: "198.51.100.7:6000".parse().unwrap(),
            }],
        });
        agent.handle_packet(server(), &peer_info, now);
        let mut checks = 0;
        let mut events = Vec::new();
        while let Some(o) = agent.poll_output() {
            match o {
                Output::Transmit { bytes, .. } => {
                    checks += usize::from(matches!(
                        Packet::decode(&bytes).unwrap().msg,
                        Message::Check { .. }
                    ))
                }
                Output::Event(e) => events.push(e),
            }
        }
        assert_eq!(checks, 1, "should probe the joiner's candidate immediately");
        assert_eq!(
            events,
            [Event::Session {
                id: 5,
                state: State::Connecting
            }]
        );

        // A duplicate PEER_INFO (retried JOIN) is ignored.
        agent.handle_packet(server(), &peer_info, now);
        assert_eq!(drain(&mut agent), (vec![], vec![]));
    }

    #[test]
    fn host_reports_stats() {
        let now = Instant::now();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Host, now);
        let mut srv = FakeServer { seq: 0 };
        register(&mut agent, &mut srv, None, now);

        // Nothing to report without sessions.
        let later = now + Config::default().stats_interval;
        agent.handle_timeout(later);
        assert!(
            !drain(&mut agent)
                .0
                .iter()
                .any(|p| matches!(p.msg, Message::Stats(_)))
        );

        let peer_info = srv.reply(Message::PeerInfo {
            session_id: 5,
            role: Role::Controlling,
            key: [1; 16],
            candidates: vec![Candidate::host("198.51.100.7:6000".parse().unwrap())],
        });
        agent.handle_packet(server(), &peer_info, later);
        drain(&mut agent);

        // The report is already due; go well before the session's checks time out.
        let report_at = later + Duration::from_secs(1);
        agent.handle_timeout(report_at);
        let (sent, _) = drain(&mut agent);
        let stats = sent.iter().find_map(|p| match &p.msg {
            Message::Stats(e) => Some(e.clone()),
            _ => None,
        });
        assert_eq!(
            stats,
            Some(vec![StatsEntry {
                session_id: 5,
                state: ReportedState::Connecting,
                path: None,
                rtt_us: None,
                rttvar_us: None,
                loss_permille: 0,
            }])
        );
        assert_eq!(
            agent.stats(5, report_at).map(|s| s.state),
            Some(State::Connecting)
        );
    }

    #[test]
    fn joiner_joins_and_stops_on_lobby_not_found() {
        let now = Instant::now();
        let lobby: LobbyId = "ZZZZZZ".parse().unwrap();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Join(lobby), now);
        let mut srv = FakeServer { seq: 0 };
        register(&mut agent, &mut srv, None, now);

        agent.handle_timeout(now);
        let (sent, _) = drain(&mut agent);
        assert!(
            matches!(sent[..], [Packet { id: CLIENT, msg: Message::Join { lobby: l }, seq, .. }] if l == lobby && seq == 1)
        );

        let err = srv.reply(Message::Error {
            code: ErrorCode::LobbyNotFound,
            ref_seq: 1,
        });
        agent.handle_packet(server(), &err, now);
        assert_eq!(
            drain(&mut agent).1,
            [Event::ServerError(ErrorCode::LobbyNotFound)]
        );

        agent.handle_timeout(now + Duration::from_secs(1));
        let (sent, _) = drain(&mut agent);
        assert!(
            !sent.iter().any(|p| matches!(p.msg, Message::Join { .. })),
            "kept joining"
        );
    }

    #[test]
    fn re_registers_when_the_server_forgets_us() {
        let now = Instant::now();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Host, now);
        let mut srv = FakeServer { seq: 0 };
        register(&mut agent, &mut srv, None, now);

        // Unauthenticated errors must reference one of our recent packets.
        let unauth = |ref_seq| {
            Packet {
                id: 0,
                seq: 0,
                msg: Message::Error {
                    code: ErrorCode::UnknownClient,
                    ref_seq,
                },
            }
            .encode(None)
            .unwrap()
        };
        agent.handle_packet(server(), &unauth(1000), now);
        assert!(
            drain(&mut agent).1.is_empty(),
            "accepted an error for a packet we never sent"
        );

        agent.handle_packet(server(), &unauth(0), now);
        assert_eq!(
            drain(&mut agent).1,
            [Event::ServerError(ErrorCode::UnknownClient)]
        );
        agent.handle_timeout(now);
        let (sent, _) = drain(&mut agent);
        assert!(matches!(
            sent[..],
            [Packet {
                id: 0,
                msg: Message::Register { .. },
                ..
            }]
        ));
    }
}
