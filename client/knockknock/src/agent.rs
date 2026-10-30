//! The sans-IO peer: signalling with the rendezvous server, lobby hosting or
//! joining, and routing of packets to sessions. One `Agent` owns one game
//! socket's worth of state. The caller moves bytes and time in and out:
//!
//! - feed UDP datagrams to [`Agent::handle_packet`] and decrypted bytes from
//!   the TLS signalling stream to [`Agent::handle_signal`],
//! - call [`Agent::handle_timeout`] when [`Agent::poll_timeout`] is reached,
//! - drain [`Agent::poll_output`]: send `Transmit`s over UDP and write
//!   `Signal`s to the TLS stream.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::auth::{Dir, Key};
use crate::candidate::Candidate;
use crate::protocol::{
    self, ErrorCode, FrameDecoder, LobbyId, MAX_STATS, Message, Packet, ReportedState, Role,
    StatsEntry,
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
    /// Open a lobby whose game port belongs to another transport (ENet): the
    /// agent's datagrams are sent through it, but nothing is ever received.
    /// Joiners verify the host's checks; the game confirms each joiner with
    /// [`Agent::confirm_peer`] or [`Agent::verify_join`].
    HostSendOnly,
    /// Join an existing lobby.
    Join(LobbyId),
}

impl Mode {
    pub fn is_host(self) -> bool {
        matches!(self, Self::Host | Self::HostSendOnly)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The server has seen our game socket's public endpoint (again, if it
    /// changed). Hosts get their lobby ID here.
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
    /// The signalling connection ended. Established sessions keep running.
    ServerLost,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Output {
    /// A UDP datagram to send from the game socket.
    Transmit {
        to: SocketAddr,
        bytes: Vec<u8>,
    },
    /// Bytes to write to the TLS signalling stream.
    Signal(Vec<u8>),
    Event(Event),
}

#[derive(Debug)]
enum Signalling {
    /// REGISTER sent; waiting for REGISTERED.
    Registering,
    Registered {
        client_id: u64,
        secret: Key,
        lobby: Option<LobbyId>,
        bind_seq: u32,
        bind_interval: Duration,
        next_bind: Instant,
        /// Our public game endpoint, once a BIND has been confirmed.
        observed: Option<SocketAddr>,
    },
    Lost,
}

#[derive(Debug)]
pub struct Agent {
    cfg: Config,
    /// The server's UDP endpoint, for BIND.
    server: SocketAddr,
    mode: Mode,
    signalling: Signalling,
    decoder: FrameDecoder,
    sessions: HashMap<SessionId, SessionMachine>,
    /// The joiner's session before the server has introduced us.
    pending: Option<SessionMachine>,
    next_heartbeat: Instant,
    heartbeat_id: u32,
    next_stats: Instant,
    /// Path stats supplied by the game transport (e.g. ENet), reported in
    /// place of our own measurements.
    external_stats: HashMap<SessionId, SessionStats>,
    /// The joiner handed its socket to the game transport: no more BINDs.
    udp_released: bool,
    last_tick: Instant,
    out: VecDeque<Output>,
}

impl Agent {
    /// `server` is the rendezvous server's address (UDP and TCP share the
    /// port); `local` are our host candidates (see
    /// [`crate::candidate::gather_host`]). The REGISTER frame is queued
    /// immediately.
    pub fn new(
        cfg: Config,
        server: SocketAddr,
        local: Vec<Candidate>,
        mode: Mode,
        now: Instant,
    ) -> Self {
        let pending = match mode {
            Mode::Host | Mode::HostSendOnly => None,
            Mode::Join(_) => Some(SessionMachine::new(cfg).start()),
        };
        let mut agent = Self {
            cfg,
            server,
            mode,
            signalling: Signalling::Registering,
            decoder: FrameDecoder::default(),
            sessions: HashMap::new(),
            pending,
            next_heartbeat: now + cfg.heartbeat_interval,
            heartbeat_id: 0,
            next_stats: now + cfg.stats_interval,
            external_stats: HashMap::new(),
            udp_released: false,
            last_tick: now,
            out: VecDeque::new(),
        };
        agent.signal(Message::Register {
            host: mode.is_host(),
            candidates: local,
        });
        agent
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// False once the signalling connection is gone (closed, corrupt, or
    /// [`Agent::close`]d); the driver should then drop it.
    pub fn signal_open(&self) -> bool {
        !matches!(self.signalling, Signalling::Lost)
    }

    pub fn session_state(&self, id: SessionId) -> Option<State> {
        self.sessions.get(&id).map(SessionMachine::state)
    }

    /// Path quality for a session: RTT, jitter and loss from its pings, or
    /// what [`Agent::set_stats`] supplied.
    pub fn stats(&self, id: SessionId, now: Instant) -> Option<SessionStats> {
        let session = self.sessions.get(&id)?;
        let own = session.stats(now);
        match self.external_stats.get(&id) {
            // The session knows its state and path; the transport its quality.
            Some(st) => Some(SessionStats {
                state: session.state(),
                path: st.path.or(own.and_then(|o| o.path)),
                ..*st
            }),
            None => own,
        }
    }

    /// Supplies path stats measured by the game transport (e.g. ENet's
    /// per-peer RTT and loss), reported to the server instead of our own.
    pub fn set_stats(&mut self, id: SessionId, stats: SessionStats) {
        if self.sessions.contains_key(&id) {
            self.external_stats.insert(id, stats);
        }
    }

    /// See the join token in `docs/design.md` §15.
    pub fn join_token(&self, id: SessionId) -> Option<String> {
        self.sessions.get(&id)?.join_token()
    }

    /// Send-only host: the game transport saw a peer connect from `addr`.
    /// Confirms the connecting session that has `addr` among its candidates.
    pub fn confirm_peer(&mut self, addr: SocketAddr, now: Instant) -> Option<SessionId> {
        let id = self
            .sessions
            .iter()
            .find(|(_, s)| s.state() == State::Connecting && s.has_candidate(addr))
            .map(|(&id, _)| id)?;
        self.step(id, |s, _| s.confirm(addr, now));
        Some(id)
    }

    /// Send-only host: a peer at `addr` presented `token` over the game
    /// transport. Returns its session if the token is valid (confirming the
    /// session if it was still connecting), or `None` for an impostor.
    pub fn verify_join(
        &mut self,
        token: &str,
        addr: SocketAddr,
        now: Instant,
    ) -> Option<SessionId> {
        use subtle::ConstantTimeEq;
        let id = self.sessions.iter().find_map(|(&id, s)| {
            let valid: bool = s.join_token()?.as_bytes().ct_eq(token.as_bytes()).into();
            valid.then_some(id)
        })?;
        self.step(id, |s, _| s.confirm(addr, now));
        Some(id)
    }

    /// Joiner: hands the game socket to another transport (ENet) once
    /// connected. Stops BINDs and session traffic; signalling stays up so the
    /// joiner keeps its seat in the lobby. Returns the session and the host
    /// address to connect the game transport to.
    pub fn hand_off(&mut self) -> Option<(SessionId, SocketAddr)> {
        let (id, addr) = self.sessions.iter().find_map(|(&id, s)| match s.state() {
            State::Connected { addr } => Some((id, addr)),
            _ => None,
        })?;
        self.sessions.remove(&id);
        self.external_stats.remove(&id);
        self.udp_released = true;
        Some((id, addr))
    }

    pub fn poll_output(&mut self) -> Option<Output> {
        self.out.pop_front()
    }

    /// When [`Agent::handle_timeout`] should next be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let bind = match &self.signalling {
            Signalling::Registered { next_bind, .. } => Some(*next_bind),
            _ => None,
        };
        let heartbeat = self.signal_open().then_some(self.next_heartbeat);
        let stats = self.wants_stats().then_some(self.next_stats);
        let active = self.pending.is_some() || self.sessions.values().any(|s| !s.is_terminal());
        let tick = active.then(|| self.last_tick + self.cfg.tick_interval);
        [bind, heartbeat, stats, tick].into_iter().flatten().min()
    }

    /// Handles a UDP datagram received on the game socket.
    pub fn handle_packet(&mut self, from: SocketAddr, raw: &[u8], now: Instant) {
        // The server never sends UDP; anything claiming to be from it is noise.
        if from == self.server {
            return;
        }
        let Ok(packet) = Packet::decode(raw) else {
            return;
        };
        if self.sessions.contains_key(&packet.id) {
            self.step(packet.id, |s, out| {
                s.handle_packet(from, raw, packet, now, out)
            });
        }
    }

    /// Handles decrypted bytes from the signalling stream.
    pub fn handle_signal(&mut self, data: &[u8], now: Instant) {
        self.decoder.push(data);
        loop {
            match self.decoder.next_frame() {
                Ok(Some(msg)) => self.handle_frame(msg, now),
                Ok(None) => return,
                Err(_) => {
                    self.signal_closed();
                    return;
                }
            }
        }
    }

    /// Tells the agent the signalling connection has ended.
    pub fn signal_closed(&mut self) {
        if self.signal_open() {
            self.signalling = Signalling::Lost;
            // A joiner that has not been introduced yet cannot proceed.
            self.pending = None;
            self.event(Event::ServerLost);
        }
    }

    pub fn handle_timeout(&mut self, now: Instant) {
        self.last_tick = now;

        if let Signalling::Registered {
            client_id,
            secret,
            bind_seq,
            bind_interval,
            next_bind,
            observed,
            ..
        } = &mut self.signalling
            && now >= *next_bind
            && !self.udp_released
        {
            // Retry quickly until the first BIND is confirmed, then refresh
            // to keep the NAT mapping (and so the candidate) alive.
            *next_bind = now
                + if observed.is_some() {
                    *bind_interval
                } else {
                    self.cfg.server_retry
                };
            let packet = Packet {
                id: *client_id,
                seq: *bind_seq,
                msg: Message::Bind,
            };
            *bind_seq = bind_seq.wrapping_add(1);
            if let Ok(bytes) = packet.encode(secret, Dir::ClientToServer) {
                self.out.push_back(Output::Transmit {
                    to: self.server,
                    bytes,
                });
            }
        }

        if self.signal_open() && now >= self.next_heartbeat {
            self.next_heartbeat = now + self.cfg.heartbeat_interval;
            self.heartbeat_id = self.heartbeat_id.wrapping_add(1);
            self.signal(Message::Ping {
                id: self.heartbeat_id,
            });
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
        if self.signal_open() {
            self.signal(Message::Close { reason: 0 });
            self.signalling = Signalling::Lost;
        }
    }

    fn handle_frame(&mut self, msg: Message, now: Instant) {
        match msg {
            Message::Registered {
                client_id,
                secret,
                lobby,
                bind_secs,
            } if matches!(self.signalling, Signalling::Registering) => {
                self.signalling = Signalling::Registered {
                    client_id,
                    secret,
                    lobby,
                    bind_seq: 0,
                    bind_interval: Duration::from_secs(u64::from(bind_secs.max(1))),
                    next_bind: now,
                    observed: None,
                };
            }
            Message::Bound { observed } => self.handle_bound(observed, now),
            // The server measures signalling latency for its dashboard.
            Message::Ping { id } => self.signal(Message::Pong { id }),
            Message::PeerInfo {
                session_id,
                role,
                key,
                candidates,
            } => self.handle_peer_info(session_id, role, key, candidates, now),
            Message::Error { code } => {
                if matches!(code, ErrorCode::LobbyNotFound | ErrorCode::LobbyFull) {
                    self.pending = None;
                }
                self.event(Event::ServerError(code));
            }
            _ => {}
        }
    }

    fn handle_bound(&mut self, new: SocketAddr, now: Instant) {
        let Signalling::Registered {
            lobby,
            observed,
            bind_interval,
            next_bind,
            ..
        } = &mut self.signalling
        else {
            return;
        };
        let first = observed.is_none();
        if *observed == Some(new) {
            return;
        }
        if first {
            // Confirmed: switch from retrying to refreshing.
            *next_bind = now + *bind_interval;
        }
        *observed = Some(new);
        let lobby = *lobby;
        self.event(Event::Registered {
            observed: new,
            lobby,
        });
        // The server introduces only bound clients, so join once bound.
        if first && let (Mode::Join(lobby), Some(_)) = (self.mode, &self.pending) {
            self.signal(Message::Join { lobby });
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
            (Mode::Host | Mode::HostSendOnly, Role::Controlling) => {
                SessionMachine::new(self.cfg).start()
            }
            (Mode::Join(_), Role::Controlled) => match self.pending.take() {
                Some(s) => s,
                None => return,
            },
            _ => return,
        };
        let mut link = Link::new(session_id, role, key);
        if self.mode == Mode::HostSendOnly {
            link = link.send_only();
        }
        self.sessions.insert(session_id, session);
        self.step(session_id, |s, out| s.peer_info(link, candidates, now, out));
    }

    /// Hosts report their sessions' path quality to the server.
    fn wants_stats(&self) -> bool {
        self.mode.is_host()
            && matches!(self.signalling, Signalling::Registered { .. })
            && !self.sessions.is_empty()
    }

    fn report_stats(&mut self, now: Instant) {
        let micros = |d: Duration| u32::try_from(d.as_micros()).unwrap_or(u32::MAX - 1);
        let entries: Vec<_> = self
            .sessions
            .keys()
            .filter_map(|&session_id| {
                let st = self.stats(session_id, now)?;
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
        self.signal(Message::Stats(entries));
    }

    fn signal(&mut self, msg: Message) {
        if let Ok(bytes) = protocol::encode_frame(&msg) {
            self.out.push_back(Output::Signal(bytes));
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
        if session.is_terminal() {
            self.external_stats.remove(&id);
        } else {
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

    fn observed() -> SocketAddr {
        "203.0.113.9:40001".parse().unwrap()
    }

    #[derive(Default)]
    struct Drained {
        signals: Vec<Message>,
        to_server: Vec<Packet>,
        to_peers: Vec<Packet>,
        events: Vec<Event>,
    }

    fn drain(agent: &mut Agent) -> Drained {
        let mut d = Drained::default();
        let mut frames = FrameDecoder::default();
        while let Some(o) = agent.poll_output() {
            match o {
                Output::Signal(bytes) => {
                    frames.push(&bytes);
                    d.signals.push(frames.next_frame().unwrap().unwrap());
                }
                Output::Transmit { to, bytes } if to == server() => {
                    assert!(
                        protocol::verify(&bytes, &SECRET, Dir::ClientToServer),
                        "BIND MAC"
                    );
                    d.to_server.push(Packet::decode(&bytes).unwrap());
                }
                Output::Transmit { bytes, .. } => d.to_peers.push(Packet::decode(&bytes).unwrap()),
                Output::Event(e) => d.events.push(e),
            }
        }
        d
    }

    fn feed(agent: &mut Agent, msg: Message, now: Instant) {
        agent.handle_signal(&protocol::encode_frame(&msg).unwrap(), now);
    }

    /// REGISTER → REGISTERED → BIND → BOUND. Returns what followed BOUND.
    fn register(agent: &mut Agent, lobby: Option<LobbyId>, now: Instant) -> Drained {
        let d = drain(agent);
        assert!(
            matches!(d.signals[..], [Message::Register { .. }]),
            "{:?}",
            d.signals
        );
        feed(
            agent,
            Message::Registered {
                client_id: CLIENT,
                secret: SECRET,
                lobby,
                bind_secs: 15,
            },
            now,
        );
        agent.handle_timeout(now);
        let d = drain(agent);
        assert!(matches!(
            d.to_server[..],
            [Packet {
                id: CLIENT,
                msg: Message::Bind,
                ..
            }]
        ));
        feed(
            agent,
            Message::Bound {
                observed: observed(),
            },
            now,
        );
        drain(agent)
    }

    fn peer_info(session_id: u64, role: Role) -> Message {
        Message::PeerInfo {
            session_id,
            role,
            key: [1; 16],
            candidates: vec![Candidate {
                kind: CandidateKind::ServerReflexive,
                addr: "198.51.100.7:6000".parse().unwrap(),
            }],
        }
    }

    #[test]
    fn host_registers_binds_and_accepts_a_joiner() {
        let now = Instant::now();
        let local = vec![Candidate::host("10.0.0.2:5000".parse().unwrap())];
        let mut agent = Agent::new(Config::default(), server(), local, Mode::Host, now);

        let lobby: LobbyId = "K7M2QX".parse().unwrap();
        let d = register(&mut agent, Some(lobby), now);
        assert_eq!(
            d.events,
            [Event::Registered {
                observed: observed(),
                lobby: Some(lobby)
            }]
        );

        // After confirmation BIND is refreshed at the bind interval.
        agent.handle_timeout(now + Duration::from_secs(1));
        assert!(
            drain(&mut agent).to_server.is_empty(),
            "refreshed too early"
        );
        agent.handle_timeout(now + Duration::from_secs(15));
        assert_eq!(drain(&mut agent).to_server.len(), 1);

        feed(&mut agent, peer_info(5, Role::Controlling), now);
        let d = drain(&mut agent);
        assert_eq!(
            d.events,
            [Event::Session {
                id: 5,
                state: State::Connecting
            }]
        );
        assert!(matches!(
            d.to_peers[..],
            [Packet {
                id: 5,
                msg: Message::Check { .. },
                ..
            }]
        ));

        // A duplicate PEER_INFO is ignored.
        feed(&mut agent, peer_info(5, Role::Controlling), now);
        let d = drain(&mut agent);
        assert!(d.events.is_empty() && d.to_peers.is_empty());
    }

    #[test]
    fn joiner_joins_once_bound_and_stops_on_lobby_not_found() {
        let now = Instant::now();
        let lobby: LobbyId = "ZZZZZZ".parse().unwrap();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Join(lobby), now);
        let d = register(&mut agent, None, now);
        assert!(matches!(d.signals[..], [Message::Join { lobby: l }] if l == lobby));

        feed(
            &mut agent,
            Message::Error {
                code: ErrorCode::LobbyNotFound,
            },
            now,
        );
        assert_eq!(
            drain(&mut agent).events,
            [Event::ServerError(ErrorCode::LobbyNotFound)]
        );

        // A rebinding (new public endpoint) does not trigger another JOIN.
        feed(
            &mut agent,
            Message::Bound {
                observed: "203.0.113.9:40002".parse().unwrap(),
            },
            now,
        );
        assert!(drain(&mut agent).signals.is_empty());
    }

    #[test]
    fn heartbeats_and_stats_go_over_signalling() {
        let now = Instant::now();
        // Report before the session's connectivity checks time out.
        let cfg = Config {
            stats_interval: Duration::from_secs(1),
            ..Config::default()
        };
        let mut agent = Agent::new(cfg, server(), vec![], Mode::Host, now);
        register(&mut agent, None, now);
        feed(&mut agent, peer_info(5, Role::Controlling), now);
        drain(&mut agent);

        agent.handle_timeout(now + cfg.stats_interval);
        let stats = drain(&mut agent).signals.into_iter().find_map(|m| match m {
            Message::Stats(e) => Some(e),
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

        agent.handle_timeout(now + cfg.heartbeat_interval);
        assert!(
            drain(&mut agent)
                .signals
                .iter()
                .any(|m| matches!(m, Message::Ping { .. }))
        );

        // The server's own pings are answered.
        feed(&mut agent, Message::Ping { id: 9 }, now);
        assert_eq!(drain(&mut agent).signals, [Message::Pong { id: 9 }]);
    }

    #[test]
    fn losing_signalling_keeps_sessions() {
        let now = Instant::now();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Host, now);
        register(&mut agent, None, now);
        feed(&mut agent, peer_info(5, Role::Controlling), now);
        drain(&mut agent);

        agent.signal_closed();
        assert!(!agent.signal_open());
        assert_eq!(drain(&mut agent).events, [Event::ServerLost]);
        assert_eq!(agent.session_state(5), Some(State::Connecting));

        // A corrupt stream counts as lost too.
        let mut other = Agent::new(Config::default(), server(), vec![], Mode::Host, now);
        drain(&mut other);
        other.handle_signal(&[0xff, 0xff, 0xff], now);
        assert!(!other.signal_open());
    }

    #[test]
    fn ignores_udp_claiming_to_be_from_the_server() {
        let now = Instant::now();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Host, now);
        register(&mut agent, None, now);
        let forged = Packet {
            id: CLIENT,
            seq: 0,
            msg: Message::Data(vec![1]),
        }
        .encode(&SECRET, Dir::ServerToClient)
        .unwrap();
        agent.handle_packet(server(), &forged, now);
        assert!(drain(&mut agent).events.is_empty());
    }

    #[test]
    fn send_only_host_confirms_peers_and_reports_external_stats() {
        let now = Instant::now();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::HostSendOnly, now);
        let d = register(&mut agent, None, now);
        assert!(matches!(d.events[..], [Event::Registered { .. }]));
        feed(&mut agent, peer_info(5, Role::Controlling), now);
        feed(
            &mut agent,
            Message::PeerInfo {
                session_id: 6,
                role: Role::Controlling,
                key: [2; 16],
                candidates: vec![Candidate::host("10.9.9.9:7000".parse().unwrap())],
            },
            now,
        );
        let d = drain(&mut agent);
        // Announcing: nominating checks to every candidate, no plain probes.
        assert!(!d.to_peers.is_empty());
        assert!(
            d.to_peers
                .iter()
                .all(|p| matches!(p.msg, Message::Check { nominate: true, .. }))
        );

        // ENet saw a peer connect from session 5's candidate address.
        let joiner: SocketAddr = "198.51.100.7:6000".parse().unwrap();
        let (confirmed, other) = (5, 6);
        assert_eq!(agent.confirm_peer(joiner, now), Some(confirmed));
        assert_eq!(
            agent.session_state(confirmed),
            Some(State::Connected { addr: joiner })
        );

        // The other joiner proves itself with its token from an unexpected
        // address (e.g. a symmetric mapping); an impostor's token fails.
        let token = agent.join_token(other).unwrap();
        let elsewhere: SocketAddr = "198.51.100.99:1234".parse().unwrap();
        assert_eq!(
            agent.verify_join("00112233445566778899aabbccddeeff", elsewhere, now),
            None
        );
        assert_eq!(agent.verify_join(&token, elsewhere, now), Some(other));
        assert_eq!(
            agent.session_state(other),
            Some(State::Connected { addr: elsewhere })
        );
        drain(&mut agent);

        // ENet's measurements are what gets reported.
        agent.set_stats(
            confirmed,
            SessionStats {
                state: State::Connecting, // overridden by the real state
                path: None,
                rtt: Some(Duration::from_millis(42)),
                jitter: Some(Duration::from_millis(3)),
                loss: 0.25,
            },
        );
        let st = agent.stats(confirmed, now).unwrap();
        assert_eq!(
            (st.state, st.rtt),
            (
                State::Connected { addr: joiner },
                Some(Duration::from_millis(42))
            )
        );
        agent.handle_timeout(now + Config::default().stats_interval);
        let reported = drain(&mut agent).signals.into_iter().find_map(|m| match m {
            Message::Stats(e) => e.into_iter().find(|e| e.session_id == confirmed),
            _ => None,
        });
        let e = reported.expect("stats for the confirmed session");
        assert_eq!(
            (e.state, e.rtt_us, e.rttvar_us, e.loss_permille),
            (ReportedState::Connected, Some(42_000), Some(3_000), 250)
        );
    }

    #[test]
    fn joiner_hands_off_and_stops_binding() {
        let now = Instant::now();
        let lobby: LobbyId = "K7M2QX".parse().unwrap();
        let mut agent = Agent::new(Config::default(), server(), vec![], Mode::Join(lobby), now);
        register(&mut agent, None, now);
        assert_eq!(
            agent.hand_off(),
            None,
            "nothing to hand off before connecting"
        );

        feed(&mut agent, peer_info(7, Role::Controlled), now);
        drain(&mut agent);
        let host: SocketAddr = "198.51.100.7:6000".parse().unwrap();
        let check = Packet {
            id: 7,
            seq: 0,
            msg: Message::Check {
                txid: 1,
                nominate: true,
            },
        }
        .encode(&[1; 16], Dir::HostToJoiner)
        .unwrap();
        agent.handle_packet(host, &check, now);
        assert!(drain(&mut agent).events.contains(&Event::Session {
            id: 7,
            state: State::Connected { addr: host }
        }));
        let token = agent.join_token(7).unwrap();

        assert_eq!(agent.hand_off(), Some((7, host)));
        assert_eq!(agent.session_state(7), None);
        assert_eq!(token.len(), 32);
        // No more BINDs, but signalling (heartbeats) continues.
        let cfg = Config::default();
        agent.handle_timeout(now + cfg.heartbeat_interval);
        let d = drain(&mut agent);
        assert!(d.to_server.is_empty());
        assert!(d.signals.iter().any(|m| matches!(m, Message::Ping { .. })));
        assert!(agent.signal_open());
    }
}
