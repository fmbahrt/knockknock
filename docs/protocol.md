# knockknock wire protocol (v2)

This is the source of truth for the wire format. The Go server
(`rendezvous/internal/protocol`) and the Rust client
(`client/knockknock/src/protocol.rs`) both implement it, and both check
themselves against the shared vectors in [`testdata/vectors.txt`](testdata/vectors.txt).
For the rationale, see [design.md](design.md).

All integers are big-endian. Receivers drop packets with a bad magic, wrong
version, unknown type, out-of-range field, or unexpected trailing bytes.

## Header (32 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `"KK"` |
| 2 | 1 | version = `2` |
| 3 | 1 | message type |
| 4 | 8 | `id`: client ID (client↔server) or session ID (peer↔peer); `0` = none |
| 12 | 4 | `seq`: per-direction packet counter |
| 16 | 16 | `auth`: MAC, or zeros for unauthenticated packets |

### Authentication

```
auth = HMAC-SHA256(key, dir ‖ packet[0..16] ‖ packet[32..])[0..16]
```

| `dir` | Direction | `key` |
|---|---|---|
| `0x01` | client → server | `client_secret` |
| `0x02` | server → client | `client_secret` |
| `0x03` | host → joiner | `session_key` |
| `0x04` | joiner → host | `session_key` |

Receivers verify in constant time, *then* apply the replay window: a 64-entry
sliding window over `seq`, kept per direction. Senders start `seq` at 0 and
increment it for every packet, retransmissions included.

Only these packets are unauthenticated (`id` = 0, `auth` = zeros):
- a first-time `REGISTER`;
- `ERROR` with code `BAD_AUTH` or `UNKNOWN_CLIENT`. Clients accept these only
  if `ref_seq` matches one of their recent packets.

## Field types

| Name | Encoding |
|---|---|
| `Endpoint` | `family u8` (`4` or `6`), address (4 or 16 bytes), `port u16`. IPv4-mapped IPv6 is sent as family 4. Max 19 bytes. |
| `Candidate` | `kind u8`, `Endpoint`. Kinds: `1` host, `2` server-reflexive, `3` relay, `4` peer-reflexive |
| `Candidates` | `count u8` (≤ 8), then `count × Candidate` |
| `LobbyId` | 6 bytes, each from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`; all zeros = none |
| `Key` | 16 bytes |
| `SessionStats` | `session_id u64`, `state u8` (`1` connecting, `2` connected, `3` disconnected), `path u8` (candidate kind of the selected path, `0` = none), `rtt_us u32`, `rttvar_us u32` (both `0xFFFFFFFF` = not measured), `loss_permille u16` (≤ 1000). 20 bytes. |

## Messages

### Client ↔ server

| Type | Name | Dir | `id` | Payload |
|---|---|---|---|---|
| `0x01` | `REGISTER` | C→S | 0 or client ID | `nonce u64`, `flags u8` (bit 0 = `HOST`), `Candidates`, zero padding |
| `0x02` | `REGISTERED` | S→C | client ID | `nonce u64`, `client_secret Key`, `observed Endpoint`, `lid LobbyId`, `ttl_secs u16` |
| `0x03` | `JOIN` | C→S | client ID | `lid LobbyId` (non-zero) |
| `0x04` | `PEER_INFO` | S→C | client ID | `session_id u64`, `role u8` (`1` controlling/host, `2` controlled/joiner), `session_key Key`, `Candidates` (the other peer's) |
| `0x05` | `ERROR` | S→C | client ID or 0 | `code u8`, `ref_seq u32` (the `seq` of the offending request) |
| `0x06` | `CLOSE` | C→S | client ID | `reason u8`; leaves the server (a host closes its lobby). Never answered. |
| `0x07` | `STATS` | C→S | client ID | `count u8` (≤ 16), `count × SessionStats`. Sent by hosts every few seconds. Entries for sessions outside the sender's lobby are ignored. Never answered. |

- **`REGISTER` padding:** the payload must be at least 51 bytes, the largest
  possible `REGISTERED` payload. Every byte after the candidates must be zero.
  This stops `REGISTER` from being used for amplification.
- `REGISTER` with `id` = 0 creates a client. Retrying with the same nonce
  from the same address returns the same registration. With `id` ≠ 0 it is an
  authenticated refresh. `REGISTERED` echoes the request's nonce.
- `JOIN` retries for the same lobby re-send the existing session's
  `PEER_INFO` to both peers instead of creating a new session.

### Peer ↔ peer (`id` = session ID)

| Type | Name | Payload |
|---|---|---|
| `0x06` | `CLOSE` | `reason u8`; ends the session |
| `0x10` | `CHECK` | `txid u64`, `flags u8` (bit 0 = `NOMINATE`) |
| `0x11` | `CHECK_ACK` | `txid u64`, `flags u8` (echoed), `observed Endpoint` (the check's source address as seen by the responder) |
| `0x12` | `PING` | `id u32`; answered with `PONG` in any state that has session credentials |
| `0x13` | `PONG` | `id u32` (echoed) |
| `0x20` | `DATA` | 0–1168 opaque bytes |
| `0x30`–`0x3F` | reserved for relay | |

### Error codes

| Code | Name | Authenticated |
|---|---|---|
| `1` | `BAD_AUTH` | no |
| `2` | `UNKNOWN_CLIENT` | no; the client should re-register (e.g. after a server restart) |
| `3` | `LOBBY_NOT_FOUND` | yes |
| `4` | `LOBBY_FULL` | yes |

Rate-limited requests are dropped silently.

### Close reasons

`0` normal, `1` timeout, `2` error.
