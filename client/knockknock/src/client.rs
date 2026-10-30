use std::collections::VecDeque;
use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

use crate::agent::{Agent, Event, Mode, Output, SessionId};
use crate::candidate::gather_host;
use crate::protocol::LobbyId;
use crate::{Config, Error};

/// Drives an [`Agent`] over a `std::net::UdpSocket`.
///
/// The same socket carries rendezvous traffic, connectivity checks and game
/// data: the punched NAT mappings belong to it.
pub struct Client {
    socket: UdpSocket,
    agent: Agent,
    events: VecDeque<Event>,
}

impl Client {
    /// Opens a lobby on the rendezvous server at `server`. The lobby ID
    /// arrives as [`Event::Registered`].
    pub fn host(server: SocketAddr) -> Result<Self, Error> {
        Self::bind("0.0.0.0:0", server, Mode::Host, Config::default())
    }

    /// Joins the lobby `lobby` on the rendezvous server at `server`.
    pub fn join(server: SocketAddr, lobby: LobbyId) -> Result<Self, Error> {
        Self::bind("0.0.0.0:0", server, Mode::Join(lobby), Config::default())
    }

    pub fn bind(
        local: impl ToSocketAddrs,
        server: SocketAddr,
        mode: Mode,
        cfg: Config,
    ) -> Result<Self, Error> {
        let socket = UdpSocket::bind(local)?;
        let candidates = gather_host(socket.local_addr()?, server)?;
        let agent = Agent::new(cfg, canonical(server), candidates, mode, Instant::now());
        Ok(Self {
            socket,
            agent,
            events: VecDeque::new(),
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    /// Processes whatever is ready without blocking and returns the next
    /// event, if any. Call it every frame from a game loop.
    pub fn poll(&mut self) -> Result<Option<Event>, Error> {
        self.socket.set_nonblocking(true)?;
        let result = self.pump_nonblocking();
        self.socket.set_nonblocking(false)?;
        result
    }

    /// Blocks until an event arrives or `timeout` passes (`None` waits
    /// forever).
    pub fn wait(&mut self, timeout: Option<Duration>) -> Result<Option<Event>, Error> {
        let deadline = timeout.map(|t| Instant::now() + t);
        let mut buf = [0u8; 1500];
        loop {
            self.flush()?;
            if let Some(e) = self.events.pop_front() {
                return Ok(Some(e));
            }
            let now = Instant::now();
            if deadline.is_some_and(|d| now >= d) {
                return Ok(None);
            }
            let wake = [self.agent.poll_timeout(), deadline]
                .into_iter()
                .flatten()
                .min();
            if let Some(wake) = wake
                && wake <= now
            {
                self.agent.handle_timeout(now);
                continue;
            }
            let wait = wake.map(|w| (w - now).max(Duration::from_millis(1)));
            self.socket.set_read_timeout(wait)?;
            self.recv_one(&mut buf)?;
        }
    }

    /// Sends application data to a connected peer.
    pub fn send(&mut self, session: SessionId, data: &[u8]) -> Result<(), Error> {
        self.agent.send(session, data, Instant::now())?;
        self.flush()
    }

    /// Closes one session.
    pub fn close_session(&mut self, session: SessionId) -> Result<(), Error> {
        self.agent.close_session(session);
        self.flush()
    }

    /// Closes all sessions and leaves the rendezvous server.
    pub fn close(mut self) -> Result<(), Error> {
        self.agent.close();
        self.flush()
    }

    fn pump_nonblocking(&mut self) -> Result<Option<Event>, Error> {
        let mut buf = [0u8; 1500];
        while self.recv_one(&mut buf)? {}
        let now = Instant::now();
        if self.agent.poll_timeout().is_some_and(|t| t <= now) {
            self.agent.handle_timeout(now);
        }
        self.flush()?;
        Ok(self.events.pop_front())
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

    fn flush(&mut self) -> Result<(), Error> {
        while let Some(out) = self.agent.poll_output() {
            match out {
                // A candidate may be unreachable (another network, another
                // address family); others may still work, so send errors are
                // not fatal. Connectivity is judged by acks, never by sends.
                Output::Transmit { to, bytes } => {
                    let _ = self.socket.send_to(&bytes, to);
                }
                Output::Event(e) => self.events.push_back(e),
            }
        }
        Ok(())
    }
}

fn canonical(addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(addr.ip().to_canonical(), addr.port())
}
