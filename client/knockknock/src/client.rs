use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use crate::agent::{Agent, Event, Mode, Output, SessionId};
use crate::candidate::gather_host;
use crate::protocol::LobbyId;
use crate::{Config, Error, SessionStats};

/// How long a blocking wait may go without servicing the TLS connection.
const SIGNAL_POLL: Duration = Duration::from_millis(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Which certificate authorities to trust for the rendezvous server.
#[derive(Debug, Clone)]
pub enum ServerTrust {
    /// The public Web PKI roots, e.g. for a Let's Encrypt certificate.
    PublicRoots,
    /// Only these CA certificates (PEM): a private CA, or the development CA
    /// the server writes when run without a certificate.
    CaPem(Vec<u8>),
}

impl ServerTrust {
    pub fn ca_file(path: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self::CaPem(std::fs::read(path)?))
    }

    fn roots(&self) -> Result<RootCertStore, Error> {
        let mut roots = RootCertStore::empty();
        match self {
            Self::PublicRoots => roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            Self::CaPem(pem) => {
                for cert in CertificateDer::pem_slice_iter(pem) {
                    let cert = cert.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                    roots.add(cert)?;
                }
            }
        }
        if roots.is_empty() {
            return Err(
                io::Error::new(io::ErrorKind::InvalidData, "no CA certificates to trust").into(),
            );
        }
        Ok(roots)
    }
}

/// The TLS signalling connection to the rendezvous server, over a
/// non-blocking `TcpStream`. It moves bytes between the socket and an
/// [`Agent`]; drivers call [`SignalConn::pump`] regularly.
pub struct SignalConn {
    tcp: TcpStream,
    tls: ClientConnection,
    open: bool,
}

impl SignalConn {
    /// Connects to `server` (`host:port`; the host part is also the name its
    /// certificate is checked against). Returns the connection and the
    /// server's address, which is also where BINDs go over UDP.
    pub fn connect(server: &str, trust: &ServerTrust) -> Result<(Self, SocketAddr), Error> {
        let invalid =
            |msg: &str| Error::Io(io::Error::new(io::ErrorKind::InvalidInput, msg.to_owned()));
        let (host, _) = server
            .rsplit_once(':')
            .ok_or_else(|| invalid("server must be host:port"))?;
        let name = ServerName::try_from(
            host.trim_start_matches('[')
                .trim_end_matches(']')
                .to_owned(),
        )
        .map_err(|_| invalid("invalid server name"))?;
        let addr = server
            .to_socket_addrs()?
            .next()
            .ok_or_else(|| invalid("server address did not resolve"))?;
        let addr = canonical(addr);

        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13])?
                .with_root_certificates(trust.roots()?)
                .with_no_client_auth();
        let tls = ClientConnection::new(Arc::new(config), name)?;
        let tcp =
            TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(|e| match e.kind() {
                io::ErrorKind::ConnectionRefused => io::Error::new(
                    e.kind(),
                    format!("nothing is listening at {addr}; is the rendezvous server running?"),
                ),
                io::ErrorKind::TimedOut => io::Error::new(
                    e.kind(),
                    format!("no answer from {addr} (firewall, or wrong address?)"),
                ),
                _ => e,
            })?;
        tcp.set_nodelay(true)?;
        tcp.set_nonblocking(true)?;
        Ok((
            Self {
                tcp,
                tls,
                open: true,
            },
            addr,
        ))
    }

    pub fn is_open(&self) -> bool {
        self.open
    }

    /// Queues signalling bytes from [`Output::Signal`]. rustls buffers them
    /// (also during the handshake) until [`SignalConn::pump`] writes them.
    pub fn write(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if self.open {
            self.tls.writer().write_all(bytes)?;
        }
        Ok(())
    }

    /// Reads whatever has arrived into `agent`, then writes what is queued.
    /// TLS failures (e.g. an untrusted certificate) are returned; a closed
    /// connection is reported to the agent, which emits `ServerLost`.
    pub fn pump(&mut self, agent: &mut Agent) -> Result<(), Error> {
        self.read(agent)?;
        self.flush(agent);
        if self.open && !agent.signal_open() {
            // The agent is done with signalling (a corrupt stream).
            self.drop_conn(agent);
        }
        Ok(())
    }

    /// Sends what is queued plus a TLS close_notify, blocking briefly.
    pub fn close(mut self) -> Result<(), Error> {
        if self.open {
            self.tls.send_close_notify();
            self.tcp.set_nonblocking(false)?;
            self.tcp.set_write_timeout(Some(CONNECT_TIMEOUT))?;
            while self.tls.wants_write() {
                self.tls.write_tls(&mut self.tcp)?;
            }
            let _ = self.tcp.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    fn read(&mut self, agent: &mut Agent) -> Result<(), Error> {
        if !self.open {
            return Ok(());
        }
        loop {
            match self.tls.read_tls(&mut self.tcp) {
                Ok(0) => {
                    self.drop_conn(agent);
                    return Ok(());
                }
                Ok(_) => {
                    let state = match self.tls.process_new_packets() {
                        Ok(state) => state,
                        Err(e) => {
                            // Send the alert, then report (e.g. a bad certificate).
                            self.flush(agent);
                            self.drop_conn(agent);
                            return Err(e.into());
                        }
                    };
                    let n = state.plaintext_bytes_to_read();
                    let closed = state.peer_has_closed();
                    if n > 0 {
                        let mut buf = vec![0; n];
                        self.tls.reader().read_exact(&mut buf)?;
                        agent.handle_signal(&buf, Instant::now());
                    }
                    if closed {
                        self.drop_conn(agent);
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.drop_conn(agent);
                    return Ok(());
                }
            }
        }
    }

    fn flush(&mut self, agent: &mut Agent) {
        while self.open && self.tls.wants_write() {
            match self.tls.write_tls(&mut self.tcp) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => self.drop_conn(agent),
            }
        }
    }

    fn drop_conn(&mut self, agent: &mut Agent) {
        if self.open {
            self.open = false;
            let _ = self.tcp.shutdown(std::net::Shutdown::Both);
            agent.signal_closed(Instant::now());
        }
    }
}

/// Drives an [`Agent`] over a TLS signalling connection and a
/// `std::net::UdpSocket`.
///
/// The UDP socket carries BINDs, connectivity checks and game data: the
/// punched NAT mappings belong to it. [`Client::hand_off`] releases it to
/// another transport once connected.
pub struct Client {
    socket: Option<UdpSocket>,
    local_port: u16,
    server: String,
    trust: ServerTrust,
    signal: SignalConn,
    agent: Agent,
    events: VecDeque<Event>,
}

impl Client {
    /// Opens a lobby on the rendezvous server at `server` (`host:port`). The
    /// lobby ID arrives as [`Event::Registered`].
    pub fn host(server: &str, trust: ServerTrust) -> Result<Self, Error> {
        Self::connect(server, Mode::Host, trust, Config::default())
    }

    /// Joins the lobby `lobby` on the rendezvous server at `server`.
    pub fn join(server: &str, lobby: LobbyId, trust: ServerTrust) -> Result<Self, Error> {
        Self::connect(server, Mode::Join(lobby), trust, Config::default())
    }

    /// Connects to `server` (`host:port`). [`Mode::HostSendOnly`] is for
    /// drivers that send through another transport and is not supported here.
    pub fn connect(
        server: &str,
        mode: Mode,
        trust: ServerTrust,
        cfg: Config,
    ) -> Result<Self, Error> {
        let (signal, addr) = SignalConn::connect(server, &trust)?;
        let any: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(any)?;
        let local = socket.local_addr()?;
        let candidates = gather_host(local, addr)?;
        let agent = Agent::new(cfg, addr, candidates, mode, Instant::now());

        let mut client = Self {
            socket: Some(socket),
            local_port: local.port(),
            server: server.to_owned(),
            trust,
            signal,
            agent,
            events: VecDeque::new(),
        };
        client.service()?;
        Ok(client)
    }

    /// The local port of the game socket. A hand-off binds the next
    /// transport (e.g. ENet) to this port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Processes whatever is ready without blocking and returns the next
    /// event, if any. Call it every frame from a game loop.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        let mut buf = [0u8; 1500];
        if let Some(socket) = &self.socket {
            socket.set_nonblocking(true)?;
        }
        while self.recv_one(&mut buf)? {}
        let now = Instant::now();
        if self.agent.poll_timeout().is_some_and(|t| t <= now) {
            self.agent.handle_timeout(now);
        }
        self.service()?;
        Ok(self.events.pop_front())
    }

    /// Blocks until an event arrives or `timeout` passes (`None` waits
    /// forever).
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, Error> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut buf = [0u8; 1500];
        loop {
            self.service()?;
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(e));
            }
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                return Ok(None);
            }
            if self.agent.poll_timeout().is_some_and(|t| t <= now) {
                self.agent.handle_timeout(now);
                continue;
            }
            let signal = self.signal.is_open().then(|| now + SIGNAL_POLL);
            let wake = [self.agent.poll_timeout(), deadline, signal]
                .into_iter()
                .flatten()
                .min();
            let wait = wake.map(|w| {
                w.saturating_duration_since(now)
                    .max(Duration::from_millis(1))
            });
            match &self.socket {
                Some(socket) => {
                    socket.set_nonblocking(false)?;
                    socket.set_read_timeout(wait)?;
                    self.recv_one(&mut buf)?;
                }
                None => std::thread::sleep(wait.unwrap_or(SIGNAL_POLL)),
            }
        }
    }

    /// Sends application data to a connected peer.
    pub fn send(&mut self, session: SessionId, data: &[u8]) -> Result<(), Error> {
        self.agent.send(session, data, Instant::now())?;
        self.service()
    }

    /// Path quality for a session: RTT, jitter and loss from its pings.
    pub fn stats(&self, session: SessionId) -> Option<SessionStats> {
        self.agent.stats(session, Instant::now())
    }

    /// Joiner: releases the game socket once connected so another transport
    /// (ENet) can bind [`Client::local_port`]. Signalling stays up, keeping
    /// the joiner's seat in the lobby; keep calling `poll`/`wait`. Returns
    /// the session and the host address to connect to.
    pub fn hand_off(&mut self) -> Option<(SessionId, SocketAddr)> {
        let handed = self.agent.hand_off()?;
        let _ = self.drain_outputs();
        self.socket = None;
        Some(handed)
    }

    /// Closes one session.
    pub fn close_session(&mut self, session: SessionId) -> Result<(), Error> {
        self.agent.close_session(session);
        self.service()
    }

    /// Closes all sessions, leaves the rendezvous server and shuts the TLS
    /// connection down cleanly.
    pub fn close(mut self) -> Result<(), Error> {
        self.agent.close();
        self.drain_outputs()?;
        self.signal.close()
    }

    /// Moves bytes between the agent and the TLS connection, and sends
    /// queued datagrams.
    fn service(&mut self) -> Result<(), Error> {
        self.reconnect();
        self.signal.pump(&mut self.agent)?;
        self.drain_outputs()?;
        self.signal.pump(&mut self.agent)
    }

    /// Re-opens the signalling connection when the agent asks for it. This
    /// blocks for up to the connect timeout; game loops that cannot afford
    /// that should drive an [`Agent`] themselves (as the Godot extension does).
    fn reconnect(&mut self) {
        if self.signal.is_open() || !self.agent.reconnect_due(Instant::now()) {
            return;
        }
        match SignalConn::connect(&self.server, &self.trust) {
            Ok((signal, _)) => {
                self.signal = signal;
                self.agent.signal_reconnected(Instant::now());
            }
            Err(_) => self.agent.reconnect_failed(Instant::now()),
        }
    }

    /// Receives and handles one datagram. Returns false if none was ready.
    fn recv_one(&mut self, buf: &mut [u8]) -> Result<bool, Error> {
        let Some(socket) = &self.socket else {
            return Ok(false);
        };
        match socket.recv_from(buf) {
            Ok((n, from)) => {
                self.agent
                    .handle_packet(canonical(from), &buf[..n], Instant::now());
                Ok(true)
            }
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok(false)
            }
            // Windows reports ICMP port-unreachable from earlier checks as a
            // reset on the next receive; it is expected noise.
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    fn drain_outputs(&mut self) -> Result<(), Error> {
        while let Some(out) = self.agent.poll_output() {
            match out {
                // A candidate may be unreachable (another network, another
                // address family); others may still work, so send errors are
                // not fatal. Connectivity is judged by acks, never by sends.
                Output::Transmit { to, bytes } => {
                    if let Some(socket) = &self.socket {
                        let _ = socket.send_to(&bytes, to);
                    }
                }
                Output::Signal(bytes) => self.signal.write(&bytes)?,
                Output::Event(e) => self.events.push_back(e),
            }
        }
        Ok(())
    }
}

/// Maps IPv4-mapped IPv6 addresses to plain IPv4, so addresses compare equal
/// however the OS reports them.
pub fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}
