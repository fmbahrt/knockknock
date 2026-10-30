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

/// Drives an [`Agent`] over a TLS signalling connection and a
/// `std::net::UdpSocket`.
///
/// The UDP socket carries BINDs, connectivity checks and game data: the
/// punched NAT mappings belong to it.
pub struct Client {
    socket: UdpSocket,
    tcp: TcpStream,
    tls: ClientConnection,
    signal_open: bool,
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

    /// Connects to `server` (`host:port`; the host part is also the name its
    /// certificate is checked against).
    pub fn connect(
        server: &str,
        mode: Mode,
        trust: ServerTrust,
        cfg: Config,
    ) -> Result<Self, Error> {
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
        let tcp = TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT)?;
        tcp.set_nodelay(true)?;
        tcp.set_nonblocking(true)?;

        let any: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let socket = UdpSocket::bind(any)?;
        let candidates = gather_host(socket.local_addr()?, addr)?;
        let agent = Agent::new(cfg, addr, candidates, mode, Instant::now());

        let mut client = Self {
            socket,
            tcp,
            tls,
            signal_open: true,
            agent,
            events: VecDeque::new(),
        };
        client.service()?;
        Ok(client)
    }

    /// The local address of the game socket. A Godot-style hand-off binds
    /// the next socket (e.g. ENet) to this port.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Processes whatever is ready without blocking and returns the next
    /// event, if any. Call it every frame from a game loop.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        self.socket.set_nonblocking(true)?;
        let result = self.poll_inner();
        self.socket.set_nonblocking(false)?;
        result
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
            let signal = self.signal_open.then(|| now + SIGNAL_POLL);
            let wake = [self.agent.poll_timeout(), deadline, signal]
                .into_iter()
                .flatten()
                .min();
            let wait = wake.map(|w| {
                w.saturating_duration_since(now)
                    .max(Duration::from_millis(1))
            });
            self.socket.set_read_timeout(wait)?;
            self.recv_one(&mut buf)?;
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
        if self.signal_open {
            self.tls.send_close_notify();
            self.tcp.set_nonblocking(false)?;
            while self.tls.wants_write() {
                self.tls.write_tls(&mut self.tcp)?;
            }
            let _ = self.tcp.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    fn poll_inner(&mut self) -> Result<Option<Event>, Error> {
        let mut buf = [0u8; 1500];
        while self.recv_one(&mut buf)? {}
        let now = Instant::now();
        if self.agent.poll_timeout().is_some_and(|t| t <= now) {
            self.agent.handle_timeout(now);
        }
        self.service()?;
        Ok(self.events.pop_front())
    }

    /// Moves bytes between the agent and the TLS connection, and sends
    /// queued datagrams.
    fn service(&mut self) -> Result<(), Error> {
        self.read_signal()?;
        self.drain_outputs()?;
        self.write_signal();
        if self.signal_open && !self.agent.signal_open() {
            // The agent is done with signalling (a corrupt stream).
            self.drop_signal();
        }
        Ok(())
    }

    fn read_signal(&mut self) -> Result<(), Error> {
        if !self.signal_open {
            return Ok(());
        }
        loop {
            match self.tls.read_tls(&mut self.tcp) {
                Ok(0) => {
                    self.drop_signal();
                    return Ok(());
                }
                Ok(_) => {
                    let state = match self.tls.process_new_packets() {
                        Ok(state) => state,
                        Err(e) => {
                            // Send the alert, then report (e.g. a bad certificate).
                            self.write_signal();
                            self.drop_signal();
                            return Err(e.into());
                        }
                    };
                    let n = state.plaintext_bytes_to_read();
                    let closed = state.peer_has_closed();
                    if n > 0 {
                        let mut buf = vec![0; n];
                        self.tls.reader().read_exact(&mut buf)?;
                        self.agent.handle_signal(&buf, Instant::now());
                    }
                    if closed {
                        self.drop_signal();
                        return Ok(());
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => {
                    self.drop_signal();
                    return Ok(());
                }
            }
        }
    }

    fn write_signal(&mut self) {
        while self.signal_open && self.tls.wants_write() {
            match self.tls.write_tls(&mut self.tcp) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => return,
                Err(_) => self.drop_signal(),
            }
        }
    }

    fn drop_signal(&mut self) {
        if self.signal_open {
            self.signal_open = false;
            let _ = self.tcp.shutdown(std::net::Shutdown::Both);
            self.agent.signal_closed();
        }
    }

    /// Receives and handles one datagram. Returns false if none was ready.
    fn recv_one(&mut self, buf: &mut [u8]) -> Result<bool, Error> {
        match self.socket.recv_from(buf) {
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
                    let _ = self.socket.send_to(&bytes, to);
                }
                // rustls buffers plaintext (also during the handshake);
                // write_signal moves it to the socket.
                Output::Signal(bytes) if self.signal_open => self.tls.writer().write_all(&bytes)?,
                Output::Signal(_) => {}
                Output::Event(e) => self.events.push_back(e),
            }
        }
        Ok(())
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}
