# knockknock wire protocol (v3)

This is the source of truth for the wire format. The Go server
(`rendezvous/internal/protocol`) and the Rust client
(`client/knockknock/src/protocol.rs`) both implement it, and both check
themselves against the shared vectors in [`testdata/vectors.txt`](testdata/vectors.txt).
For the rationale, see [design.md](design.md).

There are two transports, on the **same port number**:

- **Signalling:** one TLS 1.3 connection over TCP per client, carrying
  length-prefixed **frames**: registration, lobbies, introductions, errors,
  stats and heartbeats.
- **UDP packets**, sent from the client's game socket: `BIND` to the server,
  plus everything peer↔peer. **The server never sends UDP.**

All integers are big-endian. Receivers drop anything with a bad magic, wrong
version, a type not allowed on that transport, an out-of-range field, or
unexpected trailing bytes.

## Signalling frames (TLS)

```
len u16 | type u8 | body        (len counts type + body; 1 ≤ len ≤ 4096)
```

TLS supplies confidentiality, integrity, ordering and replay protection, so
frames carry no IDs, sequence numbers or MACs. The client is identified by its
connection. Clients verify the server certificate: either the public Web PKI,
or a CA the game ships (the server can generate a development CA).

| Type | Name | Dir | Body |
|---|---|---|---|
| `0x01` | `REGISTER` | C→S | `flags u8` (bit 0 = `HOST`, bit 1 = `RESUME`), `Candidates` (host candidates), then, if `RESUME`, `client_id u64` and `client_secret Key`. Must be the first frame, sent once. |
| `0x02` | `REGISTERED` | S→C | `client_id u64`, `client_secret Key`, `lid LobbyId` (zero unless host), `bind_secs u16` |
| `0x03` | `JOIN` | C→S | `lid LobbyId` (non-zero). Allowed once the client is bound. |
| `0x04` | `PEER_INFO` | S→C | `session_id u64`, `role u8` (`1` controlling/host, `2` controlled/joiner), `session_key Key`, `Candidates` (the other peer's) |
| `0x05` | `ERROR` | S→C | `code u8` |
| `0x06` | `CLOSE` | C→S | `reason u8`; leaves the server (a host closes its lobby) |
| `0x07` | `STATS` | C→S | `count u8` (≤ 16), `count × SessionStats`. Entries for sessions outside the sender's lobby are ignored. Never answered. |
| `0x09` | `BOUND` | S→C | `observed Endpoint`: the source of the client's `BIND`. Sent on the first BIND and whenever it changes. |
| `0x12` | `PING` | both | `id u32`. Clients send one every 30 s as a heartbeat (the server drops connections silent for 90 s). The server sends one every 10 s to measure signalling latency. |
| `0x13` | `PONG` | both | `id u32` (echoed); every `PING` is answered |

A client that sends `CLOSE` is removed at once, together with its lobby or its
seat in one. If the connection just drops, the server keeps the client
(lobby, sessions, binding) for a grace period (60 s). A `REGISTER` with
`RESUME` and the right ID and secret takes it back: `REGISTERED` repeats the
same ID, secret and lobby, followed by `BOUND` if the client was bound. If the
old connection still looks alive, the new one replaces it. An unknown or
expired ID, or a wrong secret, gets a fresh registration. Joins to a lobby
whose host is detached get `LOBBY_NOT_FOUND`.

### Error codes

| Code | Name | Meaning |
|---|---|---|
| `1` | `BAD_REQUEST` | Out-of-order or unexpected frame (e.g. `JOIN` before bound, a second `REGISTER`, or a first frame that is not `REGISTER`) |
| `2` | `LOBBY_NOT_FOUND` | No such lobby, the lobby is the client's own, or its host is not bound yet |
| `3` | `LOBBY_FULL` | |
| `4` | `RATE_LIMITED` | Too many joins from this IP |

## UDP packets

### Header (32 bytes)

| Offset | Size | Field |
|---|---|---|
| 0 | 2 | magic `"KK"` |
| 2 | 1 | version = `3` |
| 3 | 1 | message type |
| 4 | 8 | `id`: client ID (`BIND`) or session ID (peer↔peer) |
| 12 | 4 | `seq`: per-direction packet counter |
| 16 | 16 | `auth`: MAC |

Every packet is authenticated:

```
auth = HMAC-SHA256(key, dir ‖ packet[0..16] ‖ packet[32..])[0..16]
```

| `dir` | Direction | `key` |
|---|---|---|
| `0x01` | client → server (`BIND`) | `client_secret` |
| `0x03` | host → joiner | `session_key` |
| `0x04` | joiner → host | `session_key` |

(`0x02` is reserved; the server sends no UDP.) Receivers verify in constant
time, *then* apply a 64-entry sliding replay window over `seq`, kept per
direction. Senders start `seq` at 0 and increment it for every packet,
retransmissions included.

### Messages

| Type | Name | Dir | Payload |
|---|---|---|---|
| `0x08` | `BIND` | C→S | empty. Sent until `BOUND` arrives (every 500 ms), then every `bind_secs`. |
| `0x06` | `CLOSE` | P↔P | `reason u8`; ends the session |
| `0x10` | `CHECK` | P↔P | `txid u64`, `flags u8` (bit 0 = `NOMINATE`) |
| `0x11` | `CHECK_ACK` | P↔P | `txid u64`, `flags u8` (echoed), `observed Endpoint` (the check's source address as seen by the responder) |
| `0x12` | `PING` | P↔P | `id u32`; answered with `PONG` in any state that has session credentials |
| `0x13` | `PONG` | P↔P | `id u32` (echoed) |
| `0x20` | `DATA` | P↔P | 0–1168 opaque bytes |
| `0x30`–`0x3F` | reserved for relay | | |

## Field types

| Name | Encoding |
|---|---|
| `Endpoint` | `family u8` (`4` or `6`), address (4 or 16 bytes), `port u16`. IPv4-mapped IPv6 is sent as family 4. |
| `Candidate` | `kind u8`, `Endpoint`. Kinds: `1` host, `2` server-reflexive, `3` relay, `4` peer-reflexive |
| `Candidates` | `count u8` (≤ 8), then `count × Candidate` |
| `LobbyId` | 6 bytes, each from `23456789ABCDEFGHJKMNPQRSTUVWXYZ`; all zeros = none |
| `Key` | 16 bytes |
| `SessionStats` | `session_id u64`, `state u8` (`1` connecting, `2` connected, `3` disconnected), `path u8` (candidate kind of the selected path, `0` = none), `rtt_us u32`, `rttvar_us u32` (both `0xFFFFFFFF` = not measured), `loss_permille u16` (≤ 1000). 20 bytes. |

## Close reasons

`0` normal, `1` timeout, `2` error.
