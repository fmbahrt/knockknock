//! Packet authentication and replay protection (`docs/protocol.md`).

use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hasher};
use std::sync::atomic::{AtomicU64, Ordering};

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

use crate::protocol::HEADER_LEN;

/// Size of the truncated MAC carried in every packet header.
pub const TAG_LEN: usize = 16;

/// A client secret or session key.
pub type Key = [u8; 16];

/// Mixed into the MAC so a packet cannot be reflected back to its sender.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Dir {
    ClientToServer = 0x01,
    ServerToClient = 0x02,
    HostToJoiner = 0x03,
    JoinerToHost = 0x04,
}

fn hmac(key: &Key, dir: Dir, packet: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(&[dir as u8]);
    mac.update(&packet[..16]);
    mac.update(&packet[HEADER_LEN..]);
    mac
}

/// `HMAC-SHA256(key, dir ‖ packet[0..16] ‖ packet[32..])`, truncated.
/// `packet` must be at least `HEADER_LEN` bytes.
pub(crate) fn mac(key: &Key, dir: Dir, packet: &[u8]) -> [u8; TAG_LEN] {
    let full = hmac(key, dir, packet).finalize().into_bytes();
    full[..TAG_LEN].try_into().unwrap()
}

/// Checks the tag in `packet[16..32]` in constant time.
pub(crate) fn verify(key: &Key, dir: Dir, packet: &[u8]) -> bool {
    hmac(key, dir, packet)
        .verify_truncated_left(&packet[16..HEADER_LEN])
        .is_ok()
}

/// Tracks the last 64 sequence numbers seen in one direction.
#[derive(Debug, Clone, Default)]
pub(crate) struct ReplayWindow {
    top: u32,
    /// Bit `i` set: `top - i` has been seen.
    bits: u64,
    init: bool,
}

impl ReplayWindow {
    /// Reports whether `seq` is new and records it. Call it only after the
    /// packet has been authenticated.
    pub fn accept(&mut self, seq: u32) -> bool {
        if !self.init {
            *self = Self {
                top: seq,
                bits: 1,
                init: true,
            };
        } else if seq > self.top {
            let shift = seq - self.top;
            self.bits = if shift < 64 {
                self.bits << shift | 1
            } else {
                1
            };
            self.top = seq;
        } else {
            let diff = self.top - seq;
            if diff >= 64 || self.bits & (1 << diff) != 0 {
                return false;
            }
            self.bits |= 1 << diff;
        }
        true
    }

    /// Whether any packet has been accepted yet.
    pub fn any(&self) -> bool {
        self.init
    }
}

/// An unpredictable 64-bit value, used for registration nonces.
///
/// The standard library has no public CSPRNG, but `RandomState` keys SipHash
/// from OS randomness. Hashing a counter with it yields values an off-path
/// attacker cannot predict, which is all a nonce needs. Keys come from the
/// server's CSPRNG, not from here.
pub(crate) fn random_u64() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut h = RandomState::new().build_hasher();
    h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replay_window() {
        let mut w = ReplayWindow::default();
        let steps = [
            (5, true),
            (5, false),
            (3, true),
            (3, false),
            (6, true),
            (4, true),
            (100, true),
            (36, false),
            (37, true),
            (37, false),
            (99, true),
            (200, true),
            (100, false),
        ];
        for (i, (seq, want)) in steps.into_iter().enumerate() {
            assert_eq!(w.accept(seq), want, "step {i}: seq {seq}");
        }
    }

    #[test]
    fn random_values_differ() {
        assert_ne!(random_u64(), random_u64());
    }
}
