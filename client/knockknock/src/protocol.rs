//! The knockknock wire format, as described in `docs/protocol.md`.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::str::FromStr;

use crate::auth::{self, Dir, Key, TAG_LEN};
use crate::candidate::{Candidate, CandidateKind};

pub const MAGIC: [u8; 2] = *b"KK";
pub const VERSION: u8 = 2;
pub const HEADER_LEN: usize = 32;
pub const MAX_CANDIDATES: usize = 8;
pub const MAX_DATA_LEN: usize = 1168;
pub const MAX_STATS: usize = 16;
pub const LOBBY_ID_LEN: usize = 6;
/// The largest possible REGISTERED payload. REGISTER is padded to at least
/// this size so the server never amplifies.
pub const MIN_REGISTER_PAYLOAD: usize = 8 + 16 + 19 + LOBBY_ID_LEN + 2;

const TYPE_REGISTER: u8 = 0x01;
const TYPE_REGISTERED: u8 = 0x02;
const TYPE_JOIN: u8 = 0x03;
const TYPE_PEER_INFO: u8 = 0x04;
const TYPE_ERROR: u8 = 0x05;
const TYPE_CLOSE: u8 = 0x06;
const TYPE_STATS: u8 = 0x07;
const TYPE_CHECK: u8 = 0x10;
const TYPE_CHECK_ACK: u8 = 0x11;
const TYPE_PING: u8 = 0x12;
const TYPE_PONG: u8 = 0x13;
const TYPE_DATA: u8 = 0x20;

const FLAG_HOST: u8 = 1;
const FLAG_NOMINATE: u8 = 1;

/// A decoded packet. The auth tag is checked separately against the raw
/// bytes with [`verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Client ID (client↔server) or session ID (peer↔peer); 0 = none.
    pub id: u64,
    pub seq: u32,
    pub msg: Message,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Register {
        nonce: u64,
        host: bool,
        candidates: Vec<Candidate>,
    },
    Registered {
        nonce: u64,
        secret: Key,
        observed: SocketAddr,
        lobby: Option<LobbyId>,
        ttl_secs: u16,
    },
    Join {
        lobby: LobbyId,
    },
    PeerInfo {
        session_id: u64,
        role: Role,
        key: Key,
        candidates: Vec<Candidate>,
    },
    Error {
        code: ErrorCode,
        ref_seq: u32,
    },
    Close {
        reason: u8,
    },
    /// A host's report on its sessions. Never answered.
    Stats(Vec<StatsEntry>),
    Check {
        txid: u64,
        nominate: bool,
    },
    CheckAck {
        txid: u64,
        nominate: bool,
        observed: SocketAddr,
    },
    Ping {
        id: u32,
    },
    Pong {
        id: u32,
    },
    Data(Vec<u8>),
}

/// A session's state as reported to the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedState {
    Connecting = 1,
    Connected = 2,
    Disconnected = 3,
}

/// One entry of a STATS report: the host's view of the path to one joiner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatsEntry {
    pub session_id: u64,
    pub state: ReportedState,
    /// Remote candidate kind of the selected path.
    pub path: Option<CandidateKind>,
    /// Smoothed RTT in microseconds.
    pub rtt_us: Option<u32>,
    /// RTT variation (jitter) in microseconds.
    pub rttvar_us: Option<u32>,
    /// Share of recent pings that went unanswered, 0–1000.
    pub loss_permille: u16,
}

/// Encodes an unmeasured RTT.
const RTT_UNKNOWN: u32 = u32::MAX;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// The host: nominates the path.
    Controlling,
    /// A joiner: accepts the host's nomination.
    Controlled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    BadAuth,
    UnknownClient,
    LobbyNotFound,
    LobbyFull,
    Unknown(u8),
}

impl From<u8> for ErrorCode {
    fn from(v: u8) -> Self {
        match v {
            1 => Self::BadAuth,
            2 => Self::UnknownClient,
            3 => Self::LobbyNotFound,
            4 => Self::LobbyFull,
            v => Self::Unknown(v),
        }
    }
}

impl From<ErrorCode> for u8 {
    fn from(c: ErrorCode) -> Self {
        match c {
            ErrorCode::BadAuth => 1,
            ErrorCode::UnknownClient => 2,
            ErrorCode::LobbyNotFound => 3,
            ErrorCode::LobbyFull => 4,
            ErrorCode::Unknown(v) => v,
        }
    }
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BadAuth => f.write_str("bad authentication"),
            Self::UnknownClient => f.write_str("unknown client"),
            Self::LobbyNotFound => f.write_str("lobby not found"),
            Self::LobbyFull => f.write_str("lobby full"),
            Self::Unknown(v) => write!(f, "unknown error code {v}"),
        }
    }
}

/// Characters that are hard to confuse when read aloud or typed: no 0/O, 1/I/L.
const LOBBY_ALPHABET: &[u8] = b"23456789ABCDEFGHJKMNPQRSTUVWXYZ";

/// The human-shareable code a host hands out to players, e.g. `K7M2QX`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LobbyId([u8; LOBBY_ID_LEN]);

impl LobbyId {
    fn from_bytes(b: [u8; LOBBY_ID_LEN]) -> Result<Option<Self>, ProtocolError> {
        if b == [0; LOBBY_ID_LEN] {
            Ok(None)
        } else if b.iter().all(|c| LOBBY_ALPHABET.contains(c)) {
            Ok(Some(Self(b)))
        } else {
            Err(ProtocolError::BadField)
        }
    }
}

impl FromStr for LobbyId {
    type Err = ProtocolError;

    /// Parses a lobby ID case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let b: [u8; LOBBY_ID_LEN] = s
            .to_ascii_uppercase()
            .into_bytes()
            .try_into()
            .map_err(|_| ProtocolError::BadField)?;
        Self::from_bytes(b)?.ok_or(ProtocolError::BadField)
    }
}

impl fmt::Display for LobbyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Only ever constructed from LOBBY_ALPHABET, which is ASCII.
        f.write_str(std::str::from_utf8(&self.0).unwrap_or_default())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolError {
    Short,
    BadMagic,
    BadVersion(u8),
    UnknownType(u8),
    BadField,
    Trailing,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Short => f.write_str("message too short"),
            Self::BadMagic => f.write_str("bad magic"),
            Self::BadVersion(v) => write!(f, "unsupported version {v}"),
            Self::UnknownType(t) => write!(f, "unknown message type {t:#04x}"),
            Self::BadField => f.write_str("invalid field"),
            Self::Trailing => f.write_str("trailing bytes"),
        }
    }
}

impl std::error::Error for ProtocolError {}

impl Packet {
    /// Encodes the packet. With `seal`, the auth field carries the MAC;
    /// without, it is zeroed (unauthenticated packet).
    pub fn encode(&self, seal: Option<(&Key, Dir)>) -> Result<Vec<u8>, ProtocolError> {
        let mut buf = Vec::with_capacity(HEADER_LEN + 64);
        buf.extend_from_slice(&MAGIC);
        buf.push(VERSION);
        buf.push(self.msg.type_byte());
        buf.extend_from_slice(&self.id.to_be_bytes());
        buf.extend_from_slice(&self.seq.to_be_bytes());
        buf.extend_from_slice(&[0; TAG_LEN]);
        self.msg.encode_payload(&mut buf)?;
        if let Some((key, dir)) = seal {
            let tag = auth::mac(key, dir, &buf);
            buf[16..HEADER_LEN].copy_from_slice(&tag);
        }
        Ok(buf)
    }

    /// Parses a packet. It does not verify the MAC.
    pub fn decode(buf: &[u8]) -> Result<Self, ProtocolError> {
        let Some((header, payload)) = buf.split_first_chunk::<HEADER_LEN>() else {
            return Err(ProtocolError::Short);
        };
        if header[..2] != MAGIC {
            return Err(ProtocolError::BadMagic);
        }
        if header[2] != VERSION {
            return Err(ProtocolError::BadVersion(header[2]));
        }
        let id = u64::from_be_bytes(header[4..12].try_into().unwrap());
        let seq = u32::from_be_bytes(header[12..16].try_into().unwrap());

        let mut r = Reader(payload);
        let msg = match header[3] {
            TYPE_REGISTER => {
                let msg = Message::Register {
                    nonce: r.u64()?,
                    host: r.u8()? & FLAG_HOST != 0,
                    candidates: r.candidates()?,
                };
                if payload.len() < MIN_REGISTER_PAYLOAD {
                    return Err(ProtocolError::Short);
                }
                if r.0.iter().any(|&b| b != 0) {
                    return Err(ProtocolError::Trailing);
                }
                r.0 = &[];
                msg
            }
            TYPE_REGISTERED => Message::Registered {
                nonce: r.u64()?,
                secret: r.take()?,
                observed: r.endpoint()?,
                lobby: LobbyId::from_bytes(r.take()?)?,
                ttl_secs: u16::from_be_bytes(r.take()?),
            },
            TYPE_JOIN => Message::Join {
                lobby: LobbyId::from_bytes(r.take()?)?.ok_or(ProtocolError::BadField)?,
            },
            TYPE_PEER_INFO => Message::PeerInfo {
                session_id: r.u64()?,
                role: match r.u8()? {
                    1 => Role::Controlling,
                    2 => Role::Controlled,
                    _ => return Err(ProtocolError::BadField),
                },
                key: r.take()?,
                candidates: r.candidates()?,
            },
            TYPE_ERROR => Message::Error {
                code: r.u8()?.into(),
                ref_seq: u32::from_be_bytes(r.take()?),
            },
            TYPE_CLOSE => Message::Close { reason: r.u8()? },
            TYPE_STATS => Message::Stats(r.stats()?),
            TYPE_PING => Message::Ping {
                id: u32::from_be_bytes(r.take()?),
            },
            TYPE_PONG => Message::Pong {
                id: u32::from_be_bytes(r.take()?),
            },
            TYPE_CHECK => Message::Check {
                txid: r.u64()?,
                nominate: r.u8()? & FLAG_NOMINATE != 0,
            },
            TYPE_CHECK_ACK => Message::CheckAck {
                txid: r.u64()?,
                nominate: r.u8()? & FLAG_NOMINATE != 0,
                observed: r.endpoint()?,
            },
            TYPE_DATA => {
                if payload.len() > MAX_DATA_LEN {
                    return Err(ProtocolError::BadField);
                }
                r.0 = &[];
                Message::Data(payload.to_vec())
            }
            t => return Err(ProtocolError::UnknownType(t)),
        };
        if !r.0.is_empty() {
            return Err(ProtocolError::Trailing);
        }
        Ok(Self { id, seq, msg })
    }
}

/// Reports whether `buf` (a whole packet) carries a valid MAC.
pub fn verify(buf: &[u8], key: &Key, dir: Dir) -> bool {
    buf.len() >= HEADER_LEN && auth::verify(key, dir, buf)
}

impl Message {
    fn type_byte(&self) -> u8 {
        match self {
            Self::Register { .. } => TYPE_REGISTER,
            Self::Registered { .. } => TYPE_REGISTERED,
            Self::Join { .. } => TYPE_JOIN,
            Self::PeerInfo { .. } => TYPE_PEER_INFO,
            Self::Error { .. } => TYPE_ERROR,
            Self::Close { .. } => TYPE_CLOSE,
            Self::Stats(_) => TYPE_STATS,
            Self::Ping { .. } => TYPE_PING,
            Self::Pong { .. } => TYPE_PONG,
            Self::Check { .. } => TYPE_CHECK,
            Self::CheckAck { .. } => TYPE_CHECK_ACK,
            Self::Data(_) => TYPE_DATA,
        }
    }

    fn encode_payload(&self, buf: &mut Vec<u8>) -> Result<(), ProtocolError> {
        match self {
            Self::Register {
                nonce,
                host,
                candidates,
            } => {
                let start = buf.len();
                buf.extend_from_slice(&nonce.to_be_bytes());
                buf.push(if *host { FLAG_HOST } else { 0 });
                put_candidates(buf, candidates)?;
                let len = buf.len() - start;
                buf.resize(buf.len() + MIN_REGISTER_PAYLOAD.saturating_sub(len), 0);
            }
            Self::Registered {
                nonce,
                secret,
                observed,
                lobby,
                ttl_secs,
            } => {
                buf.extend_from_slice(&nonce.to_be_bytes());
                buf.extend_from_slice(secret);
                put_endpoint(buf, *observed);
                buf.extend_from_slice(&lobby.map_or([0; LOBBY_ID_LEN], |l| l.0));
                buf.extend_from_slice(&ttl_secs.to_be_bytes());
            }
            Self::Join { lobby } => buf.extend_from_slice(&lobby.0),
            Self::PeerInfo {
                session_id,
                role,
                key,
                candidates,
            } => {
                buf.extend_from_slice(&session_id.to_be_bytes());
                buf.push(match role {
                    Role::Controlling => 1,
                    Role::Controlled => 2,
                });
                buf.extend_from_slice(key);
                put_candidates(buf, candidates)?;
            }
            Self::Error { code, ref_seq } => {
                buf.push((*code).into());
                buf.extend_from_slice(&ref_seq.to_be_bytes());
            }
            Self::Close { reason } => buf.push(*reason),
            Self::Stats(entries) => {
                if entries.len() > MAX_STATS {
                    return Err(ProtocolError::BadField);
                }
                buf.push(entries.len() as u8);
                for e in entries {
                    buf.extend_from_slice(&e.session_id.to_be_bytes());
                    buf.push(e.state as u8);
                    buf.push(e.path.map_or(0, u8::from));
                    buf.extend_from_slice(&e.rtt_us.unwrap_or(RTT_UNKNOWN).to_be_bytes());
                    buf.extend_from_slice(&e.rttvar_us.unwrap_or(RTT_UNKNOWN).to_be_bytes());
                    buf.extend_from_slice(&e.loss_permille.min(1000).to_be_bytes());
                }
            }
            Self::Ping { id } | Self::Pong { id } => buf.extend_from_slice(&id.to_be_bytes()),
            Self::Check { txid, nominate } => {
                buf.extend_from_slice(&txid.to_be_bytes());
                buf.push(if *nominate { FLAG_NOMINATE } else { 0 });
            }
            Self::CheckAck {
                txid,
                nominate,
                observed,
            } => {
                buf.extend_from_slice(&txid.to_be_bytes());
                buf.push(if *nominate { FLAG_NOMINATE } else { 0 });
                put_endpoint(buf, *observed);
            }
            Self::Data(data) => {
                if data.len() > MAX_DATA_LEN {
                    return Err(ProtocolError::BadField);
                }
                buf.extend_from_slice(data);
            }
        }
        Ok(())
    }
}

fn put_candidates(buf: &mut Vec<u8>, candidates: &[Candidate]) -> Result<(), ProtocolError> {
    if candidates.len() > MAX_CANDIDATES {
        return Err(ProtocolError::BadField);
    }
    buf.push(candidates.len() as u8);
    for c in candidates {
        buf.push(c.kind.into());
        put_endpoint(buf, c.addr);
    }
    Ok(())
}

fn put_endpoint(buf: &mut Vec<u8>, addr: SocketAddr) {
    match addr.ip().to_canonical() {
        IpAddr::V4(ip) => {
            buf.push(4);
            buf.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            buf.push(6);
            buf.extend_from_slice(&ip.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
}

struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], ProtocolError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(ProtocolError::Short)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u8(&mut self) -> Result<u8, ProtocolError> {
        Ok(self.take::<1>()?[0])
    }

    fn u64(&mut self) -> Result<u64, ProtocolError> {
        Ok(u64::from_be_bytes(self.take()?))
    }

    fn endpoint(&mut self) -> Result<SocketAddr, ProtocolError> {
        let ip = match self.u8()? {
            4 => IpAddr::V4(Ipv4Addr::from(self.take::<4>()?)),
            6 => IpAddr::V6(Ipv6Addr::from(self.take::<16>()?)),
            _ => return Err(ProtocolError::BadField),
        };
        let port = u16::from_be_bytes(self.take()?);
        Ok(SocketAddr::new(ip, port))
    }

    fn stats(&mut self) -> Result<Vec<StatsEntry>, ProtocolError> {
        let n = self.u8()? as usize;
        if n > MAX_STATS {
            return Err(ProtocolError::BadField);
        }
        let known = |v: u32| (v != RTT_UNKNOWN).then_some(v);
        (0..n)
            .map(|_| {
                let session_id = self.u64()?;
                let state = match self.u8()? {
                    1 => ReportedState::Connecting,
                    2 => ReportedState::Connected,
                    3 => ReportedState::Disconnected,
                    _ => return Err(ProtocolError::BadField),
                };
                let path = match self.u8()? {
                    0 => None,
                    k => Some(CandidateKind::try_from(k)?),
                };
                let rtt_us = known(u32::from_be_bytes(self.take()?));
                let rttvar_us = known(u32::from_be_bytes(self.take()?));
                let loss_permille = u16::from_be_bytes(self.take()?);
                if loss_permille > 1000 {
                    return Err(ProtocolError::BadField);
                }
                Ok(StatsEntry {
                    session_id,
                    state,
                    path,
                    rtt_us,
                    rttvar_us,
                    loss_permille,
                })
            })
            .collect()
    }

    fn candidates(&mut self) -> Result<Vec<Candidate>, ProtocolError> {
        let n = self.u8()? as usize;
        if n > MAX_CANDIDATES {
            return Err(ProtocolError::BadField);
        }
        (0..n)
            .map(|_| {
                let kind = CandidateKind::try_from(self.u8()?)?;
                Ok(Candidate {
                    kind,
                    addr: self.endpoint()?,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: Key = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    const CLIENT: u64 = 0x1111_1111_1111_1111;
    const SESSION: u64 = 0xaabb_ccdd_eeff_0011;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// Mirrors `vectors()` in rendezvous/internal/protocol/protocol_test.go.
    fn vectors() -> Vec<(&'static str, Packet, Option<Dir>)> {
        let lobby: LobbyId = "K7M2QX".parse().unwrap();
        let p = |id, seq, msg| Packet { id, seq, msg };
        vec![
            (
                "register_initial",
                p(
                    0,
                    0,
                    Message::Register {
                        nonce: 0x0102_0304_0506_0708,
                        host: true,
                        candidates: vec![Candidate::host(addr("192.168.1.20:5000"))],
                    },
                ),
                None,
            ),
            (
                "registered",
                p(
                    CLIENT,
                    1,
                    Message::Registered {
                        nonce: 0x0102_0304_0506_0708,
                        secret: KEY,
                        observed: addr("198.51.100.25:41000"),
                        lobby: Some(lobby),
                        ttl_secs: 60,
                    },
                ),
                Some(Dir::ServerToClient),
            ),
            (
                "join",
                p(CLIENT, 2, Message::Join { lobby }),
                Some(Dir::ClientToServer),
            ),
            (
                "peer_info",
                p(
                    CLIENT,
                    3,
                    Message::PeerInfo {
                        session_id: SESSION,
                        role: Role::Controlling,
                        key: KEY,
                        candidates: vec![
                            Candidate::host(addr("10.0.0.2:4000")),
                            Candidate {
                                kind: CandidateKind::ServerReflexive,
                                addr: addr("[2001:db8::1]:9000"),
                            },
                        ],
                    },
                ),
                Some(Dir::ServerToClient),
            ),
            (
                "error_unauth",
                p(
                    0,
                    4,
                    Message::Error {
                        code: ErrorCode::UnknownClient,
                        ref_seq: 7,
                    },
                ),
                None,
            ),
            (
                "close",
                p(CLIENT, 5, Message::Close { reason: 0 }),
                Some(Dir::ClientToServer),
            ),
            (
                "check",
                p(
                    SESSION,
                    6,
                    Message::Check {
                        txid: 0x1122_3344_5566_7788,
                        nominate: true,
                    },
                ),
                Some(Dir::HostToJoiner),
            ),
            (
                "check_ack",
                p(
                    SESSION,
                    7,
                    Message::CheckAck {
                        txid: 0x1122_3344_5566_7788,
                        nominate: true,
                        observed: addr("203.0.113.7:4242"),
                    },
                ),
                Some(Dir::JoinerToHost),
            ),
            (
                "data",
                p(SESSION, 8, Message::Data(b"hello".to_vec())),
                Some(Dir::HostToJoiner),
            ),
            (
                "stats",
                p(
                    CLIENT,
                    9,
                    Message::Stats(vec![
                        StatsEntry {
                            session_id: SESSION,
                            state: ReportedState::Connected,
                            path: Some(CandidateKind::ServerReflexive),
                            rtt_us: Some(23500),
                            rttvar_us: Some(1200),
                            loss_permille: 25,
                        },
                        StatsEntry {
                            session_id: 0x0102_0304_0506_0708,
                            state: ReportedState::Connecting,
                            path: None,
                            rtt_us: None,
                            rttvar_us: None,
                            loss_permille: 0,
                        },
                    ]),
                ),
                Some(Dir::ClientToServer),
            ),
            (
                "ping",
                p(SESSION, 10, Message::Ping { id: 0xdead_beef }),
                Some(Dir::HostToJoiner),
            ),
            (
                "pong",
                p(SESSION, 11, Message::Pong { id: 0xdead_beef }),
                Some(Dir::JoinerToHost),
            ),
        ]
    }

    fn shared_vectors() -> std::collections::HashMap<String, String> {
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../docs/testdata/vectors.txt"
        );
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .filter(|l| !l.starts_with('#'))
            .filter_map(|l| l.split_once(' '))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn matches_shared_vectors() {
        let want = shared_vectors();
        for (name, packet, dir) in vectors() {
            let buf = packet.encode(dir.map(|d| (&KEY, d))).unwrap();
            assert_eq!(hex(&buf), want[name], "{name}: encoding differs from Go");
            assert_eq!(Packet::decode(&buf).unwrap(), packet, "{name}: round trip");
            if let Some(dir) = dir {
                assert!(verify(&buf, &KEY, dir), "{name}: MAC does not verify");
            }
        }
    }

    #[test]
    fn tampering_is_detected() {
        let (_, packet, dir) = &vectors()[6];
        let dir = dir.unwrap();
        let mut buf = packet.encode(Some((&KEY, dir))).unwrap();
        assert!(
            !verify(&buf, &KEY, Dir::JoinerToHost),
            "direction must matter"
        );
        *buf.last_mut().unwrap() ^= 1;
        assert!(!verify(&buf, &KEY, dir));
    }

    #[test]
    fn decode_errors() {
        use ProtocolError::*;
        let hdr = |ty: u8| {
            let mut h = vec![b'K', b'K', VERSION, ty];
            h.resize(HEADER_LEN, 0);
            h
        };
        let with = |ty: u8, payload: &[u8]| [hdr(ty), payload.to_vec()].concat();
        let register = vectors()[0].1.encode(None).unwrap();
        let mut dirty = register.clone();
        *dirty.last_mut().unwrap() = 1;

        let cases: Vec<(&str, Vec<u8>, ProtocolError)> = vec![
            ("short header", hdr(TYPE_CHECK)[..31].to_vec(), Short),
            (
                "bad magic",
                [b"X".as_slice(), &hdr(TYPE_CHECK)[1..]].concat(),
                BadMagic,
            ),
            (
                "bad version",
                [b"KK\x01".as_slice(), &hdr(TYPE_CHECK)[3..]].concat(),
                BadVersion(1),
            ),
            ("unknown type", hdr(0x7f), UnknownType(0x7f)),
            ("short payload", with(TYPE_CHECK, &[1, 2, 3]), Short),
            ("trailing", with(TYPE_CLOSE, &[0, 0]), Trailing),
            (
                "register unpadded",
                register[..register.len() - 1].to_vec(),
                Short,
            ),
            ("register dirty padding", dirty, Trailing),
            ("zero join", with(TYPE_JOIN, &[0; 6]), BadField),
            ("bad lobby char", with(TYPE_JOIN, b"K7M2QO"), BadField),
            (
                "bad role",
                with(TYPE_PEER_INFO, &[0, 0, 0, 0, 0, 0, 0, 0, 9]),
                BadField,
            ),
            (
                "data too long",
                with(TYPE_DATA, &[0; MAX_DATA_LEN + 1]),
                BadField,
            ),
        ];
        for (name, input, want) in cases {
            assert_eq!(Packet::decode(&input), Err(want), "{name}");
        }
    }

    #[test]
    fn lobby_id() {
        let l: LobbyId = "k7m2qx".parse().unwrap();
        assert_eq!(l.to_string(), "K7M2QX");
        for bad in ["", "K7M2Q", "K7M2QX1", "K7M2Q0", "K7M2QI"] {
            assert!(bad.parse::<LobbyId>().is_err(), "{bad:?} parsed");
        }
    }
}
