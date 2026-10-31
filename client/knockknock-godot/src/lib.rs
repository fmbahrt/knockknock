//! Godot 4.7 GDExtension for knockknock: lobby matchmaking and authenticated
//! NAT punching, then hand-off of the punched port to Godot's own
//! `ENetMultiplayerPeer` (`docs/design.md` §15).
//!
//! Exposes one class, `KnockknockClient` (a `Node`); the addon registers it as
//! the `Knockknock` autoload. Everything runs from `_process` on the main
//! thread, except connecting to the server (DNS and TCP), which runs on a
//! short-lived background thread so the game never stalls.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::{Duration, Instant};

use godot::classes::enet_packet_peer::{PeerState, PeerStatistic};
use godot::classes::{ENetConnection, ENetPacketPeer, FileAccess, INode, Node};
use godot::global::Error as GdError;
use godot::prelude::*;
use knockknock::candidate::gather_host;
use knockknock::{
    Agent, Config, Event, LobbyId, Mode, Output, ServerTrust, SessionId, SessionStats, SignalConn,
    State, canonical,
};

/// gdext's entry point: the only unsafe code in the crate.
#[allow(unsafe_code)]
mod entry {
    use godot::prelude::*;

    struct KnockknockExtension;

    #[gdextension]
    unsafe impl ExtensionLibrary for KnockknockExtension {}
}

/// How often ENet's per-peer statistics are read and peers are matched.
const ENET_POLL: Duration = Duration::from_millis(500);
/// ENet reports packet loss scaled by `ENET_PEER_PACKET_LOSS_SCALE`.
const ENET_LOSS_SCALE: f64 = 65536.0;

/// What the next `_process` should tell GDScript. Signals are emitted after
/// internal state is consistent, so handlers may call straight back in.
enum Emit {
    LobbyOpened(String, u16),
    JoinerIncoming(SessionId),
    JoinerConnected(SessionId, SocketAddr),
    JoinerFailed(SessionId, String),
    JoinReady(SocketAddr, String),
    JoinFailed(String),
    ServerLost,
    ServerRestored,
    LobbyChanged(String),
    Error(String),
}

/// The result of connecting to the server on a background thread.
type Dialed = Result<(SignalConn, SocketAddr), String>;

/// Connects to the rendezvous server off the main thread.
fn dial(server: String, trust: ServerTrust) -> Receiver<Dialed> {
    let (tx, rx) = mpsc::channel();
    thread::spawn(move || {
        let _ = tx.send(SignalConn::connect(&server, &trust).map_err(|e| e.to_string()));
    });
    rx
}

enum Phase {
    Idle,
    /// Connecting for the first time. The agent is created once the server's
    /// address is known.
    Starting {
        dialing: Receiver<Dialed>,
        mode: Mode,
        socket: UdpSocket,
        server: String,
        trust: ServerTrust,
    },
    Running(Box<Conn>),
}

struct Conn {
    agent: Agent,
    /// The signalling connection; `None` while lost.
    signal: Option<SignalConn>,
    /// A reconnect in progress.
    dialing: Option<Receiver<Dialed>>,
    server: String,
    trust: ServerTrust,
    /// The game socket, until it is handed to ENet.
    socket: Option<UdpSocket>,
    local_port: u16,
    host: bool,
    /// The host's ENet connection, for sending and for peer statistics.
    enet: Option<Gd<ENetConnection>>,
    /// ENet peers already matched to a session.
    peers: HashMap<SocketAddr, SessionId>,
    next_enet_poll: Instant,
    lobby: Option<LobbyId>,
}

/// knockknock lobby client. Use it through the `Knockknock` autoload.
///
/// Host:
/// ```gdscript
/// Knockknock.host_lobby("rv.example.com:7777")
/// var lobby: String = (await Knockknock.lobby_opened)[0]
/// var peer := ENetMultiplayerPeer.new()
/// peer.create_server(Knockknock.get_local_port(), 7)
/// Knockknock.attach_host(peer.host)
/// ```
///
/// Joiner:
/// ```gdscript
/// Knockknock.join_lobby("rv.example.com:7777", code)
/// var ready = await Knockknock.join_ready   # [address, port, join_token]
/// var peer := ENetMultiplayerPeer.new()
/// peer.create_client(ready[0], ready[1], 0, 0, 0, Knockknock.get_local_port())
/// ```
#[derive(GodotClass)]
#[class(base=Node)]
pub struct KnockknockClient {
    base: Base<Node>,
    /// CA certificate (PEM) to trust for the server, e.g. `res://dev-ca.pem`.
    /// Empty: the public Web PKI roots.
    #[var]
    ca_file: GString,
    phase: Phase,
    pending: Vec<Emit>,
}

#[godot_api]
impl INode for KnockknockClient {
    fn init(base: Base<Node>) -> Self {
        Self {
            base,
            ca_file: GString::new(),
            phase: Phase::Idle,
            pending: Vec::new(),
        }
    }

    fn process(&mut self, _delta: f64) {
        if let Err(e) = self.pump() {
            self.pending.push(Emit::Error(e.to_string()));
            self.drop_conn();
        }
        self.emit_pending();
    }

    fn exit_tree(&mut self) {
        self.close();
    }
}

#[godot_api]
impl KnockknockClient {
    /// The lobby is open: share `lobby_id`, then start an ENet server on
    /// `local_port` and call `attach_host`.
    #[signal]
    fn lobby_opened(lobby_id: GString, local_port: i64);

    /// A player is joining; the host is punching towards it.
    #[signal]
    fn joiner_incoming(session: GString);

    /// ENet connected a joiner that was matched to `session`.
    #[signal]
    fn joiner_connected(session: GString, address: GString);

    /// A joiner could not be reached (e.g. both sides behind strict NATs).
    #[signal]
    fn joiner_failed(session: GString, reason: GString);

    /// Joiner: the path to the host is open. Create the ENet client to
    /// `address:port` from `get_local_port()`, and send `join_token` to the
    /// host in your first RPC so it can `verify_join` you.
    #[signal]
    fn join_ready(address: GString, port: i64, join_token: GString);

    #[signal]
    fn join_failed(reason: GString);

    /// The rendezvous server connection ended. Connected games keep running,
    /// and knockknock reconnects in the background.
    #[signal]
    fn server_lost();

    /// Reconnected to the rendezvous server; the lobby and its players were
    /// kept.
    #[signal]
    fn server_restored();

    /// Host: the old lobby expired while the server was unreachable, and this
    /// is the new code to share. Players already connected are unaffected.
    #[signal]
    fn lobby_changed(lobby_id: GString);

    #[signal]
    fn error(message: GString);

    /// Opens a lobby on the rendezvous server at `server` (`host:port`).
    /// Returns at once; the result arrives as `lobby_opened` or `error`.
    #[func]
    fn host_lobby(&mut self, server: GString) -> GdError {
        self.start(&server.to_string(), Mode::HostSendOnly)
    }

    /// Joins `lobby_id` on the rendezvous server at `server` (`host:port`).
    /// Returns at once; the result arrives as `join_ready` or `join_failed`.
    #[func]
    fn join_lobby(&mut self, server: GString, lobby_id: GString) -> GdError {
        match lobby_id.to_string().trim().parse::<LobbyId>() {
            Ok(lobby) => self.start(&server.to_string(), Mode::Join(lobby)),
            Err(_) => {
                self.pending
                    .push(Emit::JoinFailed("invalid lobby id".into()));
                GdError::ERR_INVALID_PARAMETER
            }
        }
    }

    /// Host: hands knockknock the ENet connection that now owns the game
    /// port (`ENetMultiplayerPeer.host`). knockknock sends its punching
    /// packets through it, matches connecting peers to joiners, and reports
    /// ENet's RTT and loss to the server.
    #[func]
    fn attach_host(&mut self, enet: Gd<ENetConnection>) {
        if let Phase::Running(conn) = &mut self.phase {
            conn.enet = Some(enet);
        }
    }

    /// Host: checks the `join_token` a peer sent. Returns false for an
    /// impostor (someone who found the port without joining the lobby).
    #[func]
    fn verify_join(&mut self, peer: Gd<ENetPacketPeer>, token: GString) -> bool {
        let Phase::Running(conn) = &mut self.phase else {
            return false;
        };
        let Some(addr) = peer_addr(&peer) else {
            return false;
        };
        match conn
            .agent
            .verify_join(&token.to_string(), addr, Instant::now())
        {
            Some(id) => {
                if conn.peers.insert(addr, id).is_none() {
                    self.pending.push(Emit::JoinerConnected(id, addr));
                }
                true
            }
            None => false,
        }
    }

    /// The game socket's local port. ENet must bind this port to use the
    /// punched NAT mapping.
    #[func]
    fn get_local_port(&self) -> i64 {
        match &self.phase {
            Phase::Running(c) => i64::from(c.local_port),
            Phase::Starting { socket, .. } => {
                socket.local_addr().map_or(0, |a| i64::from(a.port()))
            }
            Phase::Idle => 0,
        }
    }

    /// The lobby ID once open (host), else empty.
    #[func]
    fn get_lobby_id(&self) -> GString {
        match &self.phase {
            Phase::Running(conn) => conn
                .lobby
                .map_or_else(GString::new, |l| GString::from(&l.to_string())),
            _ => GString::new(),
        }
    }

    /// Leaves the lobby and closes the server connection.
    #[func]
    fn close(&mut self) {
        // A dial still in flight finishes on its own; its result is dropped.
        if let Phase::Running(mut conn) = std::mem::replace(&mut self.phase, Phase::Idle) {
            conn.agent.close();
            let _ = drain(&mut conn, &mut Vec::new());
            if let Some(signal) = conn.signal.take() {
                let _ = signal.close();
            }
        }
    }
}

impl KnockknockClient {
    /// Starts connecting in the background. Only local setup (reading the
    /// CA file, binding the game socket) happens here.
    fn start(&mut self, server: &str, mode: Mode) -> GdError {
        self.close();
        let setup = || -> io::Result<(ServerTrust, UdpSocket)> {
            let trust = self.trust()?;
            // IPv4 game socket; the server address is resolved off-thread.
            let socket = UdpSocket::bind("0.0.0.0:0")?;
            socket.set_nonblocking(true)?;
            Ok((trust, socket))
        };
        match setup() {
            Ok((trust, socket)) => {
                self.phase = Phase::Starting {
                    dialing: dial(server.to_owned(), trust.clone()),
                    mode,
                    socket,
                    server: server.to_owned(),
                    trust,
                };
                GdError::OK
            }
            Err(e) => {
                self.fail_start(mode, format!("cannot start: {e}"));
                GdError::ERR_CANT_CREATE
            }
        }
    }

    fn fail_start(&mut self, mode: Mode, msg: String) {
        self.pending.push(if mode.is_host() {
            Emit::Error(msg)
        } else {
            Emit::JoinFailed(msg)
        });
    }

    /// Finishes starting once the background connect reports back.
    fn finish_start(&mut self) {
        let Phase::Starting { dialing, .. } = &self.phase else {
            return;
        };
        let result = match dialing.try_recv() {
            Ok(result) => result,
            Err(TryRecvError::Empty) => return,
            Err(TryRecvError::Disconnected) => Err("connect thread died".into()),
        };
        let Phase::Starting {
            mode,
            socket,
            server,
            trust,
            ..
        } = std::mem::replace(&mut self.phase, Phase::Idle)
        else {
            unreachable!()
        };
        let (signal, addr) = match result {
            Ok(dialed) => dialed,
            Err(e) => return self.fail_start(mode, format!("could not reach {server}: {e}")),
        };
        let local = match socket.local_addr() {
            Ok(local) => local,
            Err(e) => return self.fail_start(mode, e.to_string()),
        };
        let candidates = gather_host(local, addr).unwrap_or_default();
        self.phase = Phase::Running(Box::new(Conn {
            agent: Agent::new(Config::default(), addr, candidates, mode, Instant::now()),
            signal: Some(signal),
            dialing: None,
            server,
            trust,
            socket: Some(socket),
            local_port: local.port(),
            host: mode.is_host(),
            enet: None,
            peers: HashMap::new(),
            next_enet_poll: Instant::now(),
            lobby: None,
        }));
    }

    fn trust(&self) -> io::Result<ServerTrust> {
        let path = self.ca_file.to_string();
        if path.is_empty() {
            return Ok(ServerTrust::PublicRoots);
        }
        let pem = FileAccess::get_file_as_bytes(&path).to_vec();
        if pem.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("cannot read {path}"),
            ));
        }
        Ok(ServerTrust::CaPem(pem))
    }

    fn pump(&mut self) -> Result<(), knockknock::Error> {
        self.finish_start();
        let Phase::Running(conn) = &mut self.phase else {
            return Ok(());
        };
        let now = Instant::now();
        reconnect(conn, now);
        pump_signal(conn)?;

        if let Some(socket) = &conn.socket {
            let mut buf = [0u8; 1500];
            loop {
                match socket.recv_from(&mut buf) {
                    Ok((n, from)) => conn.agent.handle_packet(canonical(from), &buf[..n], now),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // ICMP unreachable from earlier checks (Windows); noise.
                    Err(e) if e.kind() == io::ErrorKind::ConnectionReset => {}
                    Err(e) => return Err(e.into()),
                }
            }
        }

        if conn.host && now >= conn.next_enet_poll {
            conn.next_enet_poll = now + ENET_POLL;
            poll_enet(conn, &mut self.pending, now);
        }

        if conn.agent.poll_timeout().is_some_and(|t| t <= now) {
            conn.agent.handle_timeout(now);
        }
        drain(conn, &mut self.pending)?;
        pump_signal(conn)?;
        Ok(())
    }

    fn drop_conn(&mut self) {
        self.phase = Phase::Idle;
    }

    fn emit_pending(&mut self) {
        for e in std::mem::take(&mut self.pending) {
            let mut sig = self.signals();
            match e {
                Emit::LobbyOpened(lobby, port) => sig
                    .lobby_opened()
                    .emit(&GString::from(&lobby), i64::from(port)),
                Emit::JoinerIncoming(id) => sig.joiner_incoming().emit(&session_name(id)),
                Emit::JoinerConnected(id, addr) => sig
                    .joiner_connected()
                    .emit(&session_name(id), &GString::from(&addr.to_string())),
                Emit::JoinerFailed(id, reason) => sig
                    .joiner_failed()
                    .emit(&session_name(id), &GString::from(&reason)),
                Emit::JoinReady(addr, token) => sig.join_ready().emit(
                    &GString::from(&addr.ip().to_string()),
                    i64::from(addr.port()),
                    &GString::from(&token),
                ),
                Emit::JoinFailed(reason) => sig.join_failed().emit(&GString::from(&reason)),
                Emit::ServerLost => sig.server_lost().emit(),
                Emit::ServerRestored => sig.server_restored().emit(),
                Emit::LobbyChanged(lobby) => sig.lobby_changed().emit(&GString::from(&lobby)),
                Emit::Error(msg) => sig.error().emit(&GString::from(&msg)),
            }
        }
    }
}

/// Starts a background reconnect when the agent wants one, and hands the
/// agent the new connection when it is up.
fn reconnect(conn: &mut Conn, now: Instant) {
    if let Some(dialing) = &conn.dialing {
        match dialing.try_recv() {
            Ok(Ok((signal, _))) => {
                conn.signal = Some(signal);
                conn.agent.signal_reconnected(now);
                conn.dialing = None;
            }
            Ok(Err(_)) | Err(TryRecvError::Disconnected) => {
                conn.agent.reconnect_failed(now);
                conn.dialing = None;
            }
            Err(TryRecvError::Empty) => {}
        }
    } else if conn.signal.is_none() && conn.agent.reconnect_due(now) {
        conn.dialing = Some(dial(conn.server.clone(), conn.trust.clone()));
    }
}

fn pump_signal(conn: &mut Conn) -> Result<(), knockknock::Error> {
    if let Some(signal) = &mut conn.signal {
        signal.pump(&mut conn.agent)?;
        if !signal.is_open() {
            conn.signal = None;
        }
    }
    Ok(())
}

/// Moves the agent's output to the network and turns its events into
/// signals.
fn drain(conn: &mut Conn, pending: &mut Vec<Emit>) -> Result<(), knockknock::Error> {
    while let Some(out) = conn.agent.poll_output() {
        match out {
            Output::Transmit { to, bytes } => transmit(conn, to, &bytes),
            Output::Signal(bytes) => {
                if let Some(signal) = &mut conn.signal {
                    signal.write(&bytes)?;
                }
            }
            Output::Event(e) => on_event(conn, e, pending),
        }
    }
    Ok(())
}

/// Sends from the game socket, or through ENet once it owns the port.
fn transmit(conn: &mut Conn, to: SocketAddr, bytes: &[u8]) {
    if let Some(socket) = &conn.socket {
        // Unreachable candidates are expected; connectivity is judged by
        // what arrives, never by sends.
        let _ = socket.send_to(bytes, to);
    } else if let Some(enet) = &mut conn.enet {
        enet.socket_send(
            &to.ip().to_string(),
            i32::from(to.port()),
            &PackedByteArray::from(bytes),
        );
    }
}

fn on_event(conn: &mut Conn, event: Event, pending: &mut Vec<Emit>) {
    match event {
        Event::Registered { lobby, .. } => {
            if conn.host
                && conn.lobby.is_none()
                && let Some(lobby) = lobby
            {
                conn.lobby = Some(lobby);
                // The server has our public endpoint: release the port so
                // ENet can bind it. From now on we send through ENet.
                conn.socket = None;
                pending.push(Emit::LobbyOpened(lobby.to_string(), conn.local_port));
            }
        }
        Event::Session { id, state } => match state {
            State::Connecting if conn.host => pending.push(Emit::JoinerIncoming(id)),
            State::Connected { .. } if !conn.host => {
                let token = conn.agent.join_token(id).unwrap_or_default();
                if let Some((_, host)) = conn.agent.hand_off() {
                    conn.socket = None;
                    pending.push(Emit::JoinReady(host, token));
                }
            }
            State::Failed(reason) if conn.host => {
                conn.peers.retain(|_, s| *s != id);
                pending.push(Emit::JoinerFailed(id, format!("{reason:?}")));
            }
            State::Failed(reason) => {
                pending.push(Emit::JoinFailed(format!("no path to host ({reason:?})")))
            }
            State::Closed if conn.host => {
                conn.peers.retain(|_, s| *s != id);
            }
            _ => {}
        },
        Event::ServerError(code) if conn.host => pending.push(Emit::Error(code.to_string())),
        Event::ServerError(code) => pending.push(Emit::JoinFailed(code.to_string())),
        Event::ServerLost => pending.push(Emit::ServerLost),
        Event::ServerRestored { lobby } => {
            if conn.host
                && let Some(lobby) = lobby
                && conn.lobby.is_some_and(|old| old != lobby)
            {
                conn.lobby = Some(lobby);
                pending.push(Emit::LobbyChanged(lobby.to_string()));
            }
            pending.push(Emit::ServerRestored);
        }
        Event::Data { .. } => {}
    }
}

/// Host: matches newly connected ENet peers to joiners, closes sessions
/// whose peer left, and feeds ENet's statistics into the agent.
fn poll_enet(conn: &mut Conn, pending: &mut Vec<Emit>, now: Instant) {
    let Some(enet) = &conn.enet else {
        return;
    };
    let mut connected = HashMap::new();
    for peer in enet.get_peers().iter_shared() {
        if peer.get_state() == PeerState::CONNECTED
            && let Some(addr) = peer_addr(&peer)
        {
            connected.insert(addr, peer);
        }
    }

    for (&addr, peer) in &connected {
        let id = match conn.peers.get(&addr) {
            Some(&id) => id,
            None => match conn.agent.confirm_peer(addr, now) {
                Some(id) => {
                    conn.peers.insert(addr, id);
                    pending.push(Emit::JoinerConnected(id, addr));
                    id
                }
                // Not a candidate address (e.g. a symmetric NAT mapping):
                // the game's verify_join will match it by token.
                None => continue,
            },
        };
        let ms = |stat| Duration::from_secs_f64(peer.get_statistic(stat).max(0.0) / 1000.0);
        let loss = peer.get_statistic(PeerStatistic::PACKET_LOSS) / ENET_LOSS_SCALE;
        conn.agent.set_stats(
            id,
            SessionStats {
                state: State::Connecting, // replaced with the session's real state
                path: None,
                rtt: Some(ms(PeerStatistic::ROUND_TRIP_TIME)),
                jitter: Some(ms(PeerStatistic::ROUND_TRIP_TIME_VARIANCE)),
                loss: loss.clamp(0.0, 1.0) as f32,
            },
        );
    }

    let gone: Vec<_> = conn
        .peers
        .iter()
        .filter(|(addr, _)| !connected.contains_key(addr))
        .map(|(&addr, &id)| (addr, id))
        .collect();
    for (addr, id) in gone {
        conn.peers.remove(&addr);
        conn.agent.close_session(id);
    }
}

fn peer_addr(peer: &Gd<ENetPacketPeer>) -> Option<SocketAddr> {
    let ip: IpAddr = peer.get_remote_address().to_string().parse().ok()?;
    let port = u16::try_from(peer.get_remote_port()).ok()?;
    Some(canonical(SocketAddr::new(ip, port)))
}

fn session_name(id: SessionId) -> GString {
    GString::from(&format!("{id:016x}"))
}
