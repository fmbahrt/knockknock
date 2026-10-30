//! knockknock: lobby-based UDP NAT hole punching.
//!
//! Implements the peer side of the technique described in
//! [Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf).
//! See `docs/design.md` for the design and `docs/protocol.md` for the wire
//! format.
//!
//! [`Client`] is a ready-to-use driver over a `std::net::UdpSocket`. For
//! custom I/O (e.g. a game engine's loop), drive an [`Agent`] directly.

mod agent;
mod auth;
pub mod candidate;
mod client;
mod pair;
pub mod protocol;
mod session;
#[cfg(test)]
mod sim;

use std::time::Duration;
use std::{fmt, io};

pub use agent::{Agent, Event, Mode, Output, SessionId};
pub use client::Client;
pub use pair::PairState;
pub use protocol::{ErrorCode, LobbyId, ProtocolError};
pub use session::{FailReason, State};

/// Timers and limits. The defaults are starting points, not universal truths:
/// NAT mapping lifetimes vary between networks.
#[derive(Debug, Clone, Copy)]
pub struct Config {
    /// How often each candidate pair is probed.
    pub probe_interval: Duration,
    /// How long a check's transaction ID stays valid for a matching ack.
    pub check_timeout: Duration,
    /// How long a pair is checked before it is marked failed.
    pub pair_timeout: Duration,
    /// How long `Connecting` may take before the session fails.
    pub connect_timeout: Duration,
    /// How long the host waits for a better pair after the first success.
    pub nomination_delay: Duration,
    /// How often an idle connected session sends a keepalive check.
    pub keepalive_interval: Duration,
    /// Silence on the selected path before the session is `Disconnected`.
    pub disconnect_timeout: Duration,
    /// How long recovery may take before the session fails.
    pub recovery_timeout: Duration,
    /// Maximum number of pairs in `Checking` at once.
    pub max_concurrent_checks: usize,
    /// How often unanswered requests to the rendezvous server are resent.
    pub server_retry: Duration,
    /// Granularity of the internal timers.
    pub tick_interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            probe_interval: Duration::from_millis(200),
            check_timeout: Duration::from_secs(1),
            pair_timeout: Duration::from_secs(5),
            connect_timeout: Duration::from_secs(8),
            nomination_delay: Duration::from_millis(300),
            keepalive_interval: Duration::from_secs(5),
            disconnect_timeout: Duration::from_secs(15),
            recovery_timeout: Duration::from_secs(10),
            max_concurrent_checks: 8,
            server_retry: Duration::from_millis(500),
            tick_interval: Duration::from_millis(50),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Protocol(ProtocolError),
    /// The rendezvous server rejected the request.
    Server(ErrorCode),
    Timeout,
    /// The session is not in the `Connected` state.
    NotConnected,
    UnknownSession,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Server(code) => write!(f, "server: {code}"),
            Self::Timeout => f.write_str("timed out"),
            Self::NotConnected => f.write_str("session is not connected"),
            Self::UnknownSession => f.write_str("unknown session"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Protocol(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ProtocolError> for Error {
    fn from(e: ProtocolError) -> Self {
        Self::Protocol(e)
    }
}
