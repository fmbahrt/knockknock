//! Candidate endpoints and local candidate gathering.

use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use crate::protocol::ProtocolError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CandidateKind {
    /// A local interface address.
    Host,
    /// Our public endpoint as observed by the rendezvous server.
    ServerReflexive,
    /// A relay allocation (reserved).
    Relay,
    /// Learned from the source address of an authenticated check.
    PeerReflexive,
}

impl CandidateKind {
    /// Higher is tried first: direct LAN paths, then addresses the peer
    /// actually reached us from, then NAT mappings, then relays.
    pub fn preference(self) -> u8 {
        match self {
            Self::Host => 3,
            Self::PeerReflexive => 2,
            Self::ServerReflexive => 1,
            Self::Relay => 0,
        }
    }
}

impl TryFrom<u8> for CandidateKind {
    type Error = ProtocolError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            1 => Ok(Self::Host),
            2 => Ok(Self::ServerReflexive),
            3 => Ok(Self::Relay),
            4 => Ok(Self::PeerReflexive),
            _ => Err(ProtocolError::BadField),
        }
    }
}

impl From<CandidateKind> for u8 {
    fn from(k: CandidateKind) -> Self {
        match k {
            CandidateKind::Host => 1,
            CandidateKind::ServerReflexive => 2,
            CandidateKind::Relay => 3,
            CandidateKind::PeerReflexive => 4,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Candidate {
    pub kind: CandidateKind,
    pub addr: SocketAddr,
}

impl Candidate {
    pub fn host(addr: SocketAddr) -> Self {
        Self {
            kind: CandidateKind::Host,
            addr,
        }
    }
}

/// Gathers host candidates for a socket bound to `local` that talks to the
/// rendezvous server at `server`.
///
/// The standard library cannot enumerate interfaces, so this returns the
/// primary interface address: the one the OS would route `server` through.
/// Loopback is only advertised when the server is itself on loopback.
pub fn gather_host(local: SocketAddr, server: SocketAddr) -> io::Result<Vec<Candidate>> {
    let ip = if local.ip().is_unspecified() {
        local_ip_towards(server)?
    } else {
        local.ip()
    };
    if ip.is_loopback() && !server.ip().is_loopback() {
        return Ok(Vec::new());
    }
    Ok(vec![Candidate::host(SocketAddr::new(ip, local.port()))])
}

/// Finds the local IP the OS would use to reach `remote`. Connecting a UDP
/// socket sends nothing; it only selects a route.
fn local_ip_towards(remote: SocketAddr) -> io::Result<IpAddr> {
    let any: SocketAddr = if remote.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let probe = UdpSocket::bind(any)?;
    probe.connect(remote)?;
    Ok(probe.local_addr()?.ip())
}
