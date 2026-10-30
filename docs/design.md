# knockknock design (v0.2)

knockknock lets players of a Godot game connect directly over UDP even when
both sit behind NAT routers. It follows
[Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf)
(Ford, Srisuresh, Kegel; "the paper" below), borrowing structure from ICE
(RFC 8445) without trying to be ICE. The wire format is in
[protocol.md](protocol.md).

This document revises the original v0.1 sketch. Section 9 lists what changed
and why.

## 1. Goals

- Simple, deterministic state machines.
- Small binary packets, minimal dependencies.
- Authenticated connectivity checks and replay protection.
- Bounded retries and clear failure reporting. **We do not claim universal
  NAT traversal**: when no direct path exists, the session ends in `Failed`
  with a reason.
- Relay fallback supported architecturally, not built yet.
- Connection establishment kept separate from application data.

## 2. Components

**Rendezvous server** (Go, `rendezvous/`). A publicly reachable UDP server. It
registers clients, observes their public endpoints, creates lobbies, introduces
joiners to hosts, issues session credentials, rate-limits, and expires stale
state. It never carries game traffic, except later as an optional relay
(paper §2.1).

**Peer** (Rust, `client/`). Owns **one UDP socket**, used for rendezvous,
connectivity checks and game data alike. This is essential: the public
endpoint the server observes is a NAT mapping of *that* socket (paper §3.2).

**Lobby.** A host registers with the `HOST` flag and receives a 6-character
Lobby ID (`lid`, e.g. `K7M2QX`). Players join with the `lid`. A lobby is a
star: one host, up to `max-lobby − 1` joiners, and one session per joiner.
The host is always the controlling side of each session. That fits Godot's
server/client multiplayer model.

## 3. Rendezvous flow

```
 Host H                     Rendezvous S                     Joiner J
   |-- REGISTER(HOST, cands) ->|                                 |
   |<- REGISTERED(id, secret,  |                                 |
   |   observed, lid) ---------|                                 |
   |   (host shares lid out of band, e.g. in the game's UI)      |
   |                           |<---------- REGISTER(cands) -----|
   |                           |--- REGISTERED(id, secret, obs) ->|
   |                           |<---------- JOIN(lid) -----------|
   |<- PEER_INFO(sid, key,     |--- PEER_INFO(sid, key,         ->|
   |   controlling, J's cands) |    controlled, H's cands)       |
   |                                                             |
   |<=========== CHECK / CHECK_ACK on every candidate pair =====>|
   |------------ CHECK(NOMINATE) on the chosen pair ------------>|
   |<----------- CHECK_ACK(NOMINATE) ----------------------------|
   |                    CONNECTED: DATA flows                    |
```

1. **REGISTER**: the peer reports its host candidates. S records the
   packet's source address as the peer's server-reflexive candidate and
   returns it in `REGISTERED`, along with a `client_id` and `client_secret`.
   Hosts also get a `lid`. Peers re-register every `ttl/4` while active. That
   keeps S's state and the NAT mapping alive (paper §3.6).
2. **JOIN(lid)**: S creates a session with a random `session_id` and
   `session_key` and sends `PEER_INFO` to **both** peers (paper §3.3: S
   forwards each peer's endpoints to the other).
3. Both peers immediately start sending checks to all of the other's
   candidates (§6). Neither waits for the other.
4. The host nominates a path (§7) and the session becomes `Connected`.

## 4. Candidates

| Kind | Source | Notes |
|---|---|---|
| host | local socket address | Useful on a shared LAN (paper §3.4). Loopback is only advertised when S itself is on loopback (development). |
| server-reflexive | observed by S in REGISTER | Replaces STUN: S *is* the reflector (paper §3.2). Valid only for the socket that registered. Not guaranteed reachable: the NAT may map per destination. |
| peer-reflexive | source address of an authenticated CHECK from an unknown address | Learned during checks. It is how a peer behind a symmetric NAT can still reach a full-cone peer. |
| relay | relay allocation | Reserved. |

Pairs are prioritised host > peer-reflexive > server-reflexive > relay. With
one socket per peer, a pair is identified by its **remote endpoint**.

Rust's standard library cannot enumerate network interfaces. The client finds
the primary interface address by "connecting" a throwaway UDP socket towards
S, which sends nothing. Multi-interface gathering needs `getifaddrs` FFI and is
deferred.

## 5. Session state machine

```
New → Gathering → Connecting → Connected ⇄ Disconnected
                       │            ↑           │
                       │      (Relaying)        │
                       └──→ Failed ←────────────┘
any state → Closed   (application close, or CLOSE from the peer)
```

| From | To | Trigger |
|---|---|---|
| New | Gathering | `start()` |
| Gathering | Connecting | `PEER_INFO` received (remote candidates and credentials known) |
| Connecting | Connected | host: `CHECK_ACK(NOMINATE)` for its nomination; joiner: valid `CHECK(NOMINATE)`, which it acks |
| Connecting | Failed(`NoPath`) | `connect_timeout` elapsed, or every pair failed |
| Connected | Disconnected | no authenticated packet from the path for `disconnect_timeout` |
| Disconnected | Connected | any authenticated packet on the old path (the loss was temporary), or a new nomination completes |
| Disconnected | Failed(`ConnectionLost`) | `recovery_timeout` elapsed |
| any | Closed | `close()`, or an authenticated `CLOSE` from the peer |

`Relaying` will slot in between `Connecting`/`Disconnected` and `Connected`
when relay support lands.

In Rust each state is a type: `Session<Connecting>`, `Session<Connected>`
and so on. Legal transitions exist only as `From` impls, so an illegal
transition does not compile. A wrapper enum holds sessions at runtime
(the [hoverbear pattern](https://hoverbear.org/blog/rust-state-machine-pattern/)).
The core is *sans-IO*: it consumes packets and timer ticks and emits datagrams
and events, with time passed in. This makes the network simulations in tests
deterministic.

## 6. Candidate pairs and connectivity checks

Pair states: `Waiting → Checking → Succeeded | Failed`. `Failed → Waiting`
happens only through the explicit retry during recovery.

- Each probe is a `CHECK` with a fresh `txid`. Outstanding txids are kept for
  `check_timeout`. Probes repeat every `probe_interval`, and at most
  `max_concurrent_checks` pairs are in `Checking` at once, highest priority
  first.
- Every authenticated `CHECK` is answered with `CHECK_ACK` to its source
  address, echoing the txid and the observed source endpoint. If the source is
  not a known candidate, a peer-reflexive pair is added. Receiving a check also
  triggers an immediate probe on that pair.
- A pair is **Succeeded** once (a) a `CHECK_ACK` matched one of our
  outstanding txids, *and* (b) an authenticated `CHECK` arrived from that
  remote. Together these prove two-way reachability. A successful
  `send_to()` proves nothing.
- A pair is **Failed** after `pair_timeout` without success. Failed pairs never
  block other pairs.
- Wrong-token packets are dropped. This matters because a private candidate
  may point at an unrelated host on a different LAN (paper §3.3).

## 7. Path selection

The host is always controlling, so there is nothing to negotiate:

1. Once a pair succeeds, the host waits until the best possible pair
   succeeds, or `nomination_delay` passes. The first success is not
   necessarily the best.
2. The host picks the best succeeded pair (priority, then RTT) and sends
   `CHECK(NOMINATE)` on it until acknowledged.
3. The joiner answers `CHECK_ACK(NOMINATE)` and enters `Connected` on that
   path. The host enters `Connected` on the ack.

The nominate exchange is itself the final authenticated confirmation of the
path.

## 8. Security

**Threat model: off-path attackers.** Credentials travel in plaintext UDP,
so an attacker who can read the first packets of a session can learn them. The
upgrade path is to move signalling to TLS (§14). Game data that needs
confidentiality should use authenticated encryption on top.

- `client_secret` (per client) and `session_key` (per session) are 128-bit
  values from the server's CSPRNG. Identifiers (`client_id`, `session_id`,
  `lid`) are **not** credentials.
- Every packet except the first `REGISTER` and two specific errors carries
  `HMAC-SHA256(key, dir ‖ header[0..16] ‖ payload)` truncated to 16 bytes and
  compared in constant time. `dir` is a direction byte (§protocol). Without it,
  an attacker could reflect a peer's own packet back to it.
- **Replay:** each direction has its own `seq` counter. Receivers keep a
  64-packet sliding window and drop duplicates and anything older. `seq` is
  per packet; `txid` is per check. They are different things.
- `REGISTERED` echoes a random nonce from `REGISTER`, so an off-path attacker
  cannot forge registration replies.
- **Amplification:** the unauthenticated `REGISTER` is padded so it is at
  least as large as the largest `REGISTERED`. Every other reply requires a
  packet authenticated by a registered client, which proves its return
  address. `CLOSE` is never answered.
- **Rate limiting:** per source IP token bucket on new registrations, joins and
  authentication failures.
- **Lobby IDs** are about 30 bits and act as capabilities. Joins are
  rate-limited, and a full or unknown lobby reveals nothing beyond the error
  code. Host approval and passwords are future work.
- A retried `REGISTER` (same address and nonce) or `JOIN` returns the existing
  registration or session instead of creating another.

## 9. Changes from the v0.1 sketch

| v0.1 | v0.2 | Why |
|---|---|---|
| STUN server for server-reflexive candidates | The rendezvous server reports the observed endpoint | Paper §3.2; one less server and dependency |
| PUNCH, HELLO, ACK message types | `CHECK` / `CHECK_ACK`; the first check is the punch | §6 and §10 of the sketch disagreed |
| Both peers propose paths and a tie-break resolves conflicts | Host always nominates | Lobby roles make it deterministic, with one round trip |
| Header session ID undefined for server traffic | `id` = client ID for client↔server, session ID for peer↔peer | Needed to look up the authentication key |
| 16-byte auth field "to be defined" | Truncated HMAC-SHA256 with a direction byte; keys issued by the server | §8 |
| Replay protection unspecified | Per-direction `seq` + 64-entry window | §8 |
| CONNECT to a peer identifier | REGISTER with `HOST` → `lid`; JOIN(`lid`) | Lobby model; prevents connecting to arbitrary peer IDs |
| No NAT behaviour detection | Planned: `PROBE` to a second server port to detect per-destination mapping (paper §6 "NAT Check") and fail fast | |
| DATA semantics unspecified | Unreliable, unordered, ≤ 1168 bytes, authenticated | §10 |

## 10. Application data

`DATA` is unreliable and unordered, with at most 1168 payload bytes so that
header plus payload stays at 1200 bytes, well under common path MTUs. It
is authenticated but not encrypted. Duplicates are dropped by the replay
window; reordering is left to the application. Reliable channels (needed for
Godot RPCs) and the Godot `MultiplayerPeerExtension` are a later stage.

## 11. Path statistics and dashboard

Once connected, each side sends `PING` on the selected path every
`ping_interval` and matches `PONG`s by ID. It keeps:

- **RTT**: smoothed the way TCP does (RFC 6298, gain 1/8), seeded with the RTT
  of the nominated pair's checks so a value exists from the first moment.
- **Jitter**: RFC 6298's `rttvar` (gain 1/4).
- **Loss**: the share of the last 32 pings with no pong within `check_timeout`.
- **Path kind**: host, server-reflexive or peer-reflexive, i.e. whether the
  peers ended up on a LAN path, a punched NAT mapping, or a mapping learned
  during checks.

Pings count as traffic, so they also stand in for keepalives. The game can read
the numbers through `Client::stats` / `Agent::stats`.

Hosts send a `STATS` report for all their sessions to the rendezvous server
every `stats_interval` (5 s). Only the lobby's host may report on its
sessions, and the server never answers. The server serves a read-only
**dashboard** (`-http`, default `127.0.0.1:8080`): a page listing every lobby
with each joiner's state, path, RTT, jitter and loss, refreshed every 2 s from
`/api/lobbies` (JSON). The dashboard shows lobby IDs, which are join
capabilities (§8). Keep it on localhost or behind authentication.

## 12. Timers (all configurable)

| Parameter | Default |
|---|---|
| `probe_interval` | 200 ms |
| `check_timeout` (txid lifetime) | 1 s |
| `pair_timeout` | 5 s |
| `connect_timeout` | 8 s |
| `nomination_delay` | 300 ms |
| `keepalive_interval` (when idle) | 5 s |
| `disconnect_timeout` | 15 s |
| `recovery_timeout` | 10 s |
| `ping_interval` | 1 s (`None` disables) |
| `stats_interval` (host → server) | 5 s |
| server retry | 500 ms |
| registration TTL (server) | 60 s, refreshed every TTL/4 |

NAT mapping lifetimes vary, often as low as 20–30 s for UDP. That is why these
are settings, not constants.

## 13. Known limitations

- **Symmetric NAT on both sides** (or symmetric against port-restricted) cannot
  be punched; the session fails with `NoPath`. Relay is the fix.
- **Restrictive firewalls** that block outbound UDP defeat everything here.
- **NAT hairpinning:** peers behind the same NAT connect over their host
  candidates. With multiple NAT levels, the server-reflexive path needs the
  outer NAT to hairpin (paper §3.5).
- Single host candidate (primary interface) only.
- No relay, no NAT probe, no signalling encryption yet (see §14).

## 14. Planned: signalling over TCP/TLS

Today every client↔server message goes over UDP. Signalling (register,
lobby, join, introductions) should move to a reliable, encrypted TCP
connection. Address discovery has to stay on UDP.

### Why UDP cannot go away entirely

The server-reflexive candidate is only useful if it is the NAT mapping of the
**UDP socket that will punch** (paper §3.2). NATs map TCP and UDP
independently, so an address observed on a TCP connection says nothing about
the UDP socket's public port. The paper's TCP punching (§4) works only because
there the punched connection is TCP as well. This is the split WebRTC uses:
signalling over a reliable channel, and STUN over UDP from the media socket.

### Proposed split

| Channel | Carries |
|---|---|
| TCP + TLS, one long-lived connection per client | `REGISTER` / `REGISTERED`, `JOIN`, `PEER_INFO` (pushed by the server), `ERROR`, `CLOSE`, heartbeat |
| UDP, from the game socket | `BIND(token)` and the server's reply; nothing else goes to the server |

1. The client opens TLS to the server and registers. `REGISTERED` carries the
   client secret, the lobby ID for hosts, and a **bind token**.
2. The client sends `BIND(token)` over UDP from its game socket, MAC'd with the
   client secret, and retries until confirmed. The server records the source
   address as the server-reflexive candidate and confirms it over TCP
   (`BOUND(observed)`).
3. The client re-sends `BIND` every ~15 s (configurable). This keeps the UDP
   mapping alive and the candidate current; if the observed address changes,
   the server confirms the new one.
4. `JOIN` and `PEER_INFO` work as today, but over TCP. Peer↔peer UDP (checks,
   data) is unchanged.

Framing: each message is length-prefixed (`u16` length, then the existing
message encoding without the UDP header's `id`/`seq`/`auth`). TLS provides
integrity, ordering and replay protection, so those fields are redundant on the
TCP channel.

### What it buys

- **Real security for key delivery.** Client secrets and session keys never
  appear in plaintext, so the existing HMAC-protected UDP traffic also holds
  against on-path attackers, not just off-path ones (§8). Plain TCP without TLS
  does not give this.
- **Less code.** No retry timers or idempotent-retry handling for
  `REGISTER`/`JOIN`, no registration nonce, no unauthenticated error rules, and
  no `REGISTER` padding (the TCP handshake rules out spoofed sources). Only
  `BIND` keeps a retry loop.
- **Presence.** A dropped connection means the client is gone: the server
  closes a host's lobby immediately instead of after the 60 s TTL.
- **Firewall reach.** TCP to port 443 gets through networks that block UDP.
  Punching still fails there, but the failure is reported clearly, and a TCP
  relay becomes possible later.

### What it costs

- **Dependencies.** Go's standard library has `crypto/tls`. Rust needs `rustls`
  plus a crypto backend (`ring` or `aws-lc-rs`), a few dozen crates, far more
  than `hmac` + `sha2`. Option: put TLS behind a cargo feature, and design the
  framing so plain TCP can be wrapped in TLS later without protocol changes.
- **Two listeners** on the server (TCP and UDP, which can share a port number).
- **Heartbeats remain.** A TCP heartbeat every few minutes is enough (NATs keep
  established TCP mappings far longer than UDP ones; RFC 5382 recommends at
  least 2 h 4 min). The UDP `BIND` refresh is still needed for the UDP mapping.

### What does not need encryption

Peer↔peer UDP stays authenticated but unencrypted. Checks and `BIND` reveal
nothing useful, and once keys arrive over TLS, an on-path attacker can observe
or drop these packets but not forge, modify or replay them. Game `DATA` can opt
into confidentiality later by swapping the HMAC in the 16-byte auth field for
an AEAD tag (AES-GCM or ChaCha20-Poly1305), with the header as associated data
and direction + `seq` as the nonce. That needs no wire-format change and affects
only the Rust client, since the server never sees game data. Session keys still
come from the server, so the server operator could read game traffic; peer-only
keys would need an X25519 exchange between peers, which is out of scope.

## 15. Roadmap

1. ✅ Basic UDP + rendezvous (v1 scaffold)
2. ✅ Lobbies, authenticated rendezvous (this version)
3. ✅ Authenticated simultaneous checks, nomination
4. ✅ Session and pair state machines
5. ✅ Keepalive, failure detection, recovery
6. ✅ Path statistics (PING/PONG), host reports, server dashboard
7. Signalling over TCP/TLS with UDP `BIND` (§14)
8. Relay through the rendezvous server
9. Hardening: NAT probe, fuzzing, diagnostics, multi-interface
10. Godot GDExtension + reliable channels
