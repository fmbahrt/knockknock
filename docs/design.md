# knockknock design (v0.2)

knockknock lets players of a Godot game connect directly over UDP even when
both sit behind NAT routers. It follows
[Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf)
(Ford, Srisuresh, Kegel; "the paper" below), borrowing structure from ICE
(RFC 8445) without trying to be ICE. The wire format is in
[protocol.md](protocol.md).

This document revises the original v0.1 sketch. Section 9 lists what changed
and why. Section 18 covers the repository layout, building, testing and using
the library.

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

**Rendezvous server** (Go, `rendezvous/`). A publicly reachable server with
TLS signalling over TCP and BIND observation over UDP, on one port. It
registers clients, observes their public game endpoints, creates lobbies,
introduces joiners to hosts, issues session credentials, rate-limits, and
forgets clients when their connection closes. It never carries game traffic, except later as an optional relay
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
 Host H                       Rendezvous S                       Joiner J
   |== TLS: REGISTER(HOST, cands) =>|                                 |
   |<= TLS: REGISTERED(id, secret,  |                                 |
   |        lid, bind_secs) ========|                                 |
   |-- UDP: BIND (game socket) ---->|                                 |
   |<= TLS: BOUND(observed) ========|                                 |
   |   (host shares lid out of band, e.g. in the game's UI)           |
   |                                |<= TLS: REGISTER(cands) ========|
   |                                |== TLS: REGISTERED(id, secret) =>|
   |                                |<-------- UDP: BIND ------------|
   |                                |== TLS: BOUND(observed) =======>|
   |                                |<= TLS: JOIN(lid) ==============|
   |<= TLS: PEER_INFO(sid, key, ====|==== TLS: PEER_INFO(sid, key, ==>|
   |   controlling, J's cands)      |     controlled, H's cands)      |
   |                                                                  |
   |<============ CHECK / CHECK_ACK on every candidate pair ========>|
   |------------- CHECK(NOMINATE) on the chosen pair --------------->|
   |<------------ CHECK_ACK(NOMINATE) -------------------------------|
   |                     CONNECTED: game traffic                      |
```

1. **REGISTER over TLS**: the peer reports its host candidates and receives a
   `client_id`, a `client_secret` and, for hosts, a `lid`.
2. **BIND over UDP**: from the game socket, authenticated with the secret. S
   records the source address as the peer's server-reflexive candidate (paper
   §3.2) and confirms it over TLS as `BOUND`. The peer re-sends `BIND` every
   `bind_secs`, which keeps the NAT mapping alive (paper §3.6). S never answers
   over UDP. Address discovery has to stay on UDP because NATs map TCP and UDP
   separately (§14).
3. **JOIN(lid)** once bound: S creates a session with a random `session_id`
   and `session_key` and sends `PEER_INFO` to **both** peers (paper §3.3).
4. Both peers immediately start sending checks to all of the other's
   candidates (§6). Neither waits for the other.
5. The host nominates a path (§7) and the session becomes `Connected`.

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

**Threat model.** Signalling runs over TLS 1.3 with server certificate
verification, so client secrets and session keys are never visible on the
wire. On-path attackers can observe and drop UDP packets, but cannot forge,
modify or replay them. Game data that needs confidentiality should use
authenticated encryption on top (ENet DTLS in Godot; §15).

- **Trust:** clients trust either the public Web PKI roots or a CA the game
  ships. Run without a certificate, the server generates a development CA and
  writes it to a file for clients to load, so verification still happens.
- **Secrets:** `client_secret` (per client) and `session_key` (per session)
  are 128-bit values from the server's CSPRNG. Identifiers (`client_id`,
  `session_id`, `lid`) are **not** credentials.
- **MACs:** every UDP packet carries `HMAC-SHA256(key, dir ‖ header[0..16] ‖
  payload)` truncated to 16 bytes and compared in constant time. `dir` is a
  direction byte (§protocol). Without it, an attacker could reflect a peer's
  own packet back to it.
- **Replay:** each UDP direction has its own `seq` counter. Receivers keep a
  64-packet sliding window and drop duplicates and anything older. `seq` is
  per packet; `txid` is per check. They are different things.
- **No amplification by construction:** the server never sends UDP. A
  replayed or spoofed `BIND` is dropped by the replay window or the MAC
  check, and in any case only ever changes what the server tells the
  legitimate client over TLS.
- **Rate limiting:** per source IP token bucket on new connections and joins.
  A client too slow to read its frames is disconnected rather than allowed to
  queue without bound.
- **Lobby IDs** are about 30 bits and act as capabilities. Joins are
  rate-limited, and a full or unknown lobby reveals nothing beyond the error
  code. Host approval and passwords are future work.

## 9. Changes from the v0.1 sketch

| v0.1 | v0.2 | Why |
|---|---|---|
| STUN server for server-reflexive candidates | The rendezvous server reports the observed endpoint | Paper §3.2; one less server and dependency |
| PUNCH, HELLO, ACK message types | `CHECK` / `CHECK_ACK`; the first check is the punch | §6 and §10 of the sketch disagreed |
| Both peers propose paths and a tie-break resolves conflicts | Host always nominates | Lobby roles make it deterministic, with one round trip |
| Header session ID undefined for server traffic | Signalling over TLS; UDP `id` = client ID for `BIND`, session ID for peer↔peer | Needed to look up the authentication key |
| 16-byte auth field "to be defined" | Truncated HMAC-SHA256 with a direction byte; keys issued by the server | §8 |
| Replay protection unspecified | Per-direction `seq` + 64-entry window | §8 |
| CONNECT to a peer identifier | REGISTER with `HOST` → `lid`; JOIN(`lid`) | Lobby model; prevents connecting to arbitrary peer IDs |
| No NAT behaviour detection | Planned: `PROBE` to a second server port to detect per-destination mapping (paper §6 "NAT Check") and fail fast | |
| DATA semantics unspecified | Unreliable, unordered, ≤ 1168 bytes, authenticated | §10 |

## 10. Application data

`DATA` is unreliable and unordered, with at most 1168 payload bytes so that
header plus payload stays at 1200 bytes, well under common path MTUs. It
is authenticated but not encrypted. Duplicates are dropped by the replay
window; reordering is left to the application.

In Godot, game traffic does **not** use `DATA`: after the handshake the port is
handed to ENet (§15). `DATA` remains for the test harness, non-Godot users, and
anything that wants the knockknock socket directly.

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
over the signalling connection every `stats_interval` (5 s).

The server adds what it sees itself:

- **Per client:**
  - Role and lobby.
  - The TLS connection's IP next to the UDP game endpoint, flagged when they
    differ (carrier-grade NAT, VPN, multiple uplinks).
  - **Unbound** clients whose `BIND` never arrived. That usually means UDP is
    blocked on their network, and it explains a failed join before any
    punching happens.
  - NAT **rebinds** (the public game port changing mid-session).
  - Time since the last `BIND`, and how long the client has been connected.
  - **Signalling latency** from server `PING`s every 10 s. It includes the
    client's servicing delay, up to 10 ms with the std driver.
- **Server counters since start:**
  - Connections accepted, rate-limited and failing the TLS handshake.
  - Registrations by role.
  - Joins by outcome.
  - `BIND`s rejected by reason (bad MAC, replay, unknown client, malformed),
    and NAT rebinds.
  - Clients dropped for reading too slowly.
  - Disconnects by reason (left, connection closed, idle timeout, protocol
    error, …).
- **Lifetimes:** count, median, 90th percentile and maximum of how long
  clients stayed connected and lobbies stayed open (over the last 1000). Only the lobby's host may report on its
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
| BIND retry until confirmed | 500 ms |
| BIND refresh (`bind_secs`, server) | 15 s |
| signalling heartbeat | 30 s (the server drops silent connections after 90 s) |
| reconnect backoff | 1 s, doubling to 30 s |
| resume grace (server) | 60 s |

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
- No relay and no NAT probe yet.
- If the server itself restarts, its in-memory state is gone: reconnecting
  clients register afresh and hosts get a new lobby code (`lobby_changed` in
  Godot). Established games are unaffected.
- A joiner behind a symmetric NAT cannot reach a send-only (Godot) host
  (§15). Relay is the fix.
- With gdext 0.5.5 and Godot 4.7.2, the headless editor crashes on exit after
  a project's very first import. It reproduces with an empty gdext extension,
  so it is upstream. Later imports and game runs are unaffected, and
  `just godot-smoke` retries.

## 14. Signalling over TCP/TLS

Signalling (register, lobby, join, introductions, stats) runs over a reliable,
encrypted TCP connection. Address discovery stays on UDP. Implemented in
protocol v3; this section keeps the reasoning.

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
   client ID and secret, and the lobby ID for hosts.
2. The client sends `BIND` over UDP from its game socket (header `id` =
   client ID, MAC'd with the client secret), and retries until confirmed. The server records the source
   address as the server-reflexive candidate and confirms it over TCP
   (`BOUND(observed)`).
3. The client re-sends `BIND` every ~15 s (configurable). This keeps the UDP
   mapping alive and the candidate current; if the observed address changes,
   the server confirms the new one.
4. `JOIN` and `PEER_INFO` work as today, but over TCP. Peer↔peer UDP (checks,
   data) is unchanged.

Framing: each message is length-prefixed (`u16` length, then the message
type and body, without the UDP header's `id`/`seq`/`auth`). TLS provides
integrity, ordering and replay protection, so those fields are redundant on the
TCP channel.

### What it buys

- **Real security for key delivery.** Client secrets and session keys never
  appear in plaintext, so the existing HMAC-protected UDP traffic also holds
  against on-path attackers, not just off-path ones (§8). Plain TCP without TLS
  does not give this.
- **Less code.** No retry timers or idempotent-retry handling for
  `REGISTER`/`JOIN`, no registration nonce, no unauthenticated error rules, no
  `REGISTER` padding, and no registration TTL. Only `BIND` keeps a retry loop.
- **Presence.** A dropped connection means the client is gone: the server
  closes a host's lobby immediately instead of after the 60 s TTL.
- **Firewall reach.** TCP to port 443 gets through networks that block UDP.
  Punching still fails there, but the failure is reported clearly, and a TCP
  relay becomes possible later.

### What it costs

- **Dependencies.** Go's standard library has `crypto/tls`. Rust uses `rustls`
  with the `ring` backend and `webpki-roots`. `ring` also supplies HMAC-SHA256
  and the CSPRNG, replacing `hmac` + `sha2`. The client's tree is 12 crates in
  all. TLS is mandatory; there is no plaintext mode to misconfigure.
- **Two listeners** on the server (TCP and UDP, which can share a port number).
- **Heartbeats remain.** A TCP heartbeat (every 30 s here) is plenty (NATs keep
  established TCP mappings far longer than UDP ones; RFC 5382 recommends at
  least 2 h 4 min). The UDP `BIND` refresh is still needed for the UDP mapping.

### Reconnecting

Losing the signalling connection never ends a game: peer↔peer sessions and
ENet keep running. The agent keeps its registration and asks the driver to
reconnect with backoff (`reconnect_due`, `signal_reconnected`,
`reconnect_failed`).
- **Resume:** it re-registers with `RESUME` and its client ID and secret.
  The server holds a dropped client's lobby, sessions and binding for 60 s,
  hands them back, and replaces the old connection if it had not noticed it
  die.
- **Too late:** after the grace period the client registers afresh, and a
  host gets a new lobby code.
- **Drivers:** the std `Client` reconnects inline (blocking for up to the
  connect timeout). The Godot extension dials on a background thread, as it
  does for the first connect, so `_process` never blocks.
- **Dashboard:** it shows detached clients as "reconnecting" and counts
  resumes.

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

## 15. Godot integration: hand-off to ENet

Target: **Godot 4.7.2**, through a GDExtension written with
[gdext](https://github.com/godot-rust/gdext) in its own crate
(`client/knockknock-godot`), so the core library keeps its small dependency
set. The model follows [netfox.noray](https://foxssake.github.io/netfox/latest/netfox.noray/guides/noray/):
knockknock does matchmaking and the handshake, then Godot's own
`ENetMultiplayerPeer` takes over the punched port. That gives reliable
channels, RPCs, `MultiplayerSynchronizer` and optional DTLS without
reimplementing ENet. (A custom `MultiplayerPeerExtension` over `DATA` was
considered and rejected: it would mean rebuilding reliability, ordering and
fragmentation.)

### Flow

**Joiner.** It owns a normal socket until it hands off:
1. Connect to the server over TCP/TLS, register, and `BIND` from the game port.
2. `JOIN(lid)`, then run the full authenticated handshake (§6–7).
3. Close the knockknock socket and `create_client(host_addr, host_port, …,
   local_port)` on the same local port. The NAT mapping outlives the socket.

**Host.** Its ENet server owns the port from the start. It can **send** raw
datagrams (`ENetConnection.socket_send`) but cannot **receive** anything
ENet does not understand. So:
1. Connect over TCP/TLS and register. `BIND` is sent through `socket_send`,
   and the server confirms it over TCP. **This is why §14 is a prerequisite.**
2. For each `PEER_INFO`, the host's sans-IO agent produces authenticated
   CHECKs, sent to every joiner candidate through `socket_send` on a schedule.
3. The joiner verifies them, so it knows the packets really come from the
   host (noray's one-way `over_enet` cannot tell). It learns the host's working
   address and treats a verified host CHECK on a pair as success. Its own
   checks open its NAT, and then it ENet-connects.
4. The host learns the outcome when ENet reports `peer_connected` (matched to
   the session by address) or when the session's deadline passes.

The joiner needs no special mode. A send-only host's checks all carry the
`NOMINATE` flag, and a joiner already enters `Connected` on the first
authenticated nominating check, on the path it arrived from. The host side is
`Mode::HostSendOnly`:
- It announces (sends nominating checks to every joiner candidate every
  `probe_interval`) until the game confirms the joiner, or the session
  deadline passes.
- It is confirmed with `Agent::confirm_peer(addr)`, when ENet sees a peer
  connect from a candidate address, or with `Agent::verify_join(token, addr)`.
- Once connected it goes quiet; ENet owns liveness.
- `Agent::set_stats` feeds ENet's RTT, jitter and loss into the `STATS`
  reports.

**Limitation:** a send-only host can only aim at the joiner's server-reflexive
mapping, and it never hears the joiner's checks, so it cannot learn a
peer-reflexive one. A joiner behind a symmetric NAT therefore fails with
`NoPath` even when the host is behind a forgiving NAT. (A full two-way host
could still reach it.) Relay is the fix.

### Admission

ENet authenticates nothing, so anyone who learns the host's port can connect.
Each joiner receives a `join_token = HMAC(session_key, "enet-join")` and sends
it in the game's first RPC; the host calls `Knockknock.verify_join(peer_id,
token)` and kicks impostors. Games that need confidentiality can enable ENet's
DTLS.

### GDScript API

Built in `client/knockknock-godot` (gdext 0.5, `api-4-7`). The example project
in `godot/` exercises all of it, and `just godot-smoke` runs it headless. Signal
names below are as built:
`lobby_opened(lobby_id, local_port)`, `joiner_incoming(session)`,
`joiner_connected(session, address)`, `joiner_failed(session, reason)`,
`join_ready(address, port, join_token)`, `join_failed(reason)`, `server_lost`,
`server_restored`, `lobby_changed(lobby_id)`, `error(message)`. §18 has a
usage example.

The original sketch follows; the as-built API differs in the details noted
after it.

Two autoload Nodes (Nodes, so they can poll in `_process`):

```gdscript
# Host
await Knockknock.connect_to_server("rv.example.com", 7777)
var lobby_id: String = await Knockknock.host_lobby()
var peer := ENetMultiplayerPeer.new()
peer.create_server(Knockknock.local_port, 7)
Knockknock.attach_host(peer.host)    # punches for late joiners, reports ENet stats
multiplayer.multiplayer_peer = peer

# Joiner
await Knockknock.connect_to_server("rv.example.com", 7777)
var target = await Knockknock.join_lobby("K7M2QX")   # {error, address, port, join_token}
var peer := ENetMultiplayerPeer.new()
peer.create_client(target.address, target.port, 0, 0, 0, Knockknock.local_port)
multiplayer.multiplayer_peer = peer
Knockknock.attach_client(peer.host)  # optional: report the joiner's view too
```

- **`Knockknock`** (like `Noray`): `connect_to_server`, `host_lobby`,
  `join_lobby`, `attach_host` / `attach_client`, `verify_join`, `local_port`,
  and `telemetry_level`. Signals: `lobby_opened(lobby_id)`,
  `joiner_incoming(address, port)`, `join_failed(reason)`, `disconnected`.
- **`Handshake`** (like `PacketHandshake`), for custom setups:
  `over_packet_peer(udp, session)` (full, two-way) and `over_enet(enet_host,
  address, port, session)` (send-only host). Unlike noray's `$rwx` status
  strings, every packet is authenticated with the session key.

As built:
- **No `connect_to_server` step.** `host_lobby(server)` and
  `join_lobby(server, code)` connect, the server certificate's CA is the
  `ca_file` property, and results arrive as signals rather than return values.
- **`verify_join` takes the `ENetPacketPeer`**
  (`multiplayer.multiplayer_peer.get_peer(id)`).
- **The handshake is built into `join_lobby`**, not exposed as a separate
  `Handshake` singleton yet. A standalone one needs session credentials, which
  only come from the server.
- **No `attach_client` yet.** Joiners don't send ENet stats.

## 16. Telemetry

Hosts **and** joiners can send stats and debug information to the rendezvous
server, which aggregates them on the dashboard. It is opt-in per game through
`telemetry_level`:

| Level | Sends |
|---|---|
| `off` | Nothing beyond the protocol itself |
| `metrics` (default) | Periodic path stats and handshake reports |
| `debug` | Also the client's structured event log |

Telemetry rides the TCP/TLS signalling connection (§14). That makes it
reliable, ordered, and free of UDP size and amplification concerns. Today's
`STATS` frame is its first piece.

### What is reported

- **Client info, once per connection:** knockknock version, Godot version,
  OS/platform, role (host or joiner), telemetry level.
- **Path metrics, every `stats_interval`, per session, from both ends:** RTT,
  RTT variance, loss, and the path kind. In Godot these come from ENet
  (`ENetPacketPeer.get_statistic`: round-trip time and variance, packet loss
  and variance, throttle); outside Godot, from PING/PONG (§11). Also bytes and
  packets sent and received (`ENetConnection.pop_statistic`). Having both ends'
  view exposes asymmetric paths.
- **Handshake report, once per session, on success or failure:** time to
  connect, every candidate pair with its kind, final state, RTT and probe count,
  the nominated pair, the failure reason, and NAT hints. Hints include whether
  peer-reflexive candidates appeared (a sign of per-destination mapping) and
  whether host candidates on the same subnet worked. This is the data that
  explains *why* a connection failed.
- **Events, `debug` only:** timestamped, levelled, structured entries
  (`kind` plus key/value fields). Examples: state transitions, retries, server
  errors, ENet connect/disconnect, and recovery attempts. The client buffers
  a bounded ring and drops the oldest entries under pressure.

User content and game data are never sent. The server already sees peers'
public addresses; telemetry adds nothing more identifying than client info.

### Server side

- **Storage:** in memory. Per-client and per-session ring buffers, with
  aggregates kept over a sliding window (default 24 h).
- **Dashboard additions:**
  - Both ends' view per session, side by side.
  - Handshake reports with the pair table.
  - A per-client event timeline.
  - Aggregates: connect success rate, `NoPath` rate, path-kind distribution,
    time-to-connect percentiles, and RTT and loss distributions. These can be
    filtered by platform and version.
- **Export:** an optional JSON Lines log of every report (`-telemetry-log`) for
  offline analysis.
- **Limits:** a per-client byte budget and message rate, and a cap on events
  per report. Anything over the limit is dropped and counted (a
  `dropped_events` stat), never answered.

### Encoding

Binary, like the rest of the protocol (Rust has no JSON in std).

- **Metrics and handshake reports:** fixed fields.
- **Events:** `timestamp_ms u64, level u8, kind u16`, then `count u8` ×
  (`key`, `value`) as length-prefixed UTF-8, with bounded lengths.

The server decodes into structs and only turns them into JSON for the
dashboard and log.

## 17. Roadmap

1. ✅ Basic UDP + rendezvous (v1 scaffold)
2. ✅ Lobbies, authenticated rendezvous (this version)
3. ✅ Authenticated simultaneous checks, nomination
4. ✅ Session and pair state machines
5. ✅ Keepalive, failure detection, recovery
6. ✅ Path statistics (PING/PONG), host reports, server dashboard
7. ✅ Signalling over TCP/TLS with UDP `BIND` (§14)
8. ✅ Send-only host handshake and joiner hand-off (§15)
9. ✅ `knockknock-godot` (gdext, Godot 4.7.2): `Knockknock` autoload, ENet
   stats → `STATS`, join tokens, example project, headless smoke test.
   Still to do: a standalone `Handshake` singleton and joiner-side stats.
10. Telemetry (§16): joiner reports, handshake reports, events; dashboard
    both-ends view, timelines, aggregates, JSONL log
11. Relay through the rendezvous server (the `NoPath` fallback)
12. Hardening: NAT probe, fuzzing, multi-interface

## 18. Repository and usage

- **`rendezvous/`**: the rendezvous server, in Go (standard library only).
- **`client/`**: the peer library, in Rust (`rustls` + `ring` + `webpki-roots`).
- **`client/knockknock-godot/`** + **`godot/`**: the Godot 4.7 GDExtension and an
  example project.
- **`docs/protocol.md`**: the wire format, plus shared test vectors in `docs/testdata/`.

### Layout

```
.
├── mise.toml                 # pinned Go, Rust, Python, Godot and just versions
├── justfile                  # top-level tasks; delegates to the modules below
├── docs/
│   ├── design.md             # design spec
│   ├── protocol.md           # wire format (source of truth)
│   └── testdata/vectors.txt  # encoded packets both languages must match
├── charts/rendezvous/        # Helm chart for the server
├── rendezvous/               # Go module: knockknock/rendezvous
│   ├── Dockerfile            # distroless, non-root image
│   ├── cmd/rendezvous/       # binary entry point
│   └── internal/
│       ├── protocol/         # packet encoding/decoding, lobby IDs
│       ├── auth/             # HMAC tags, replay window
│       ├── devcert/          # development CA + certificate generation
│       ├── ratelimit/        # per-IP token bucket
│       ├── registry/         # clients, lobbies, sessions, stats snapshot
│       └── dashboard/        # web view of lobbies and connection stats
├── godot/                    # example Godot project
│   ├── main.gd               # host/join UI + chat; headless smoke test mode
│   └── addons/knockknock/    # the addon: .gdextension, plugin, Knockknock autoload
└── client/                   # Cargo workspace
    ├── knockknock-godot/     # GDExtension (gdext) wrapping the library
    └── knockknock/           # library crate
        ├── src/protocol.rs   # packet encoding/decoding
        ├── src/auth.rs       # HMAC tags, replay window
        ├── src/candidate.rs  # candidates and host gathering
        ├── src/pair.rs       # candidate-pair state machine
        ├── src/session.rs    # session typestate machine (sans-IO)
        ├── src/agent.rs      # registration, lobby, session routing (sans-IO)
        ├── src/stats.rs      # PING/PONG RTT, jitter and loss
        ├── src/client.rs     # TLS + UdpSocket driver
        ├── src/sim.rs        # NAT/loss simulation tests
        └── examples/         # host.rs, join.rs, bridge.rs (stdin/stdout driver)
scripts/
├── datatest.py               # traffic tests over real connections (stdlib only)
└── godot                     # runs the Godot pinned in mise.toml
```

### Getting started

Install [mise](https://mise.jdx.dev), then:

```sh
mise install     # installs Go, Rust, just, Python and Godot at the pinned versions
just             # list tasks
just check       # lint + test everything
just demo        # local server + a host + two joiners
just live        # same, long-running, with the dashboard at http://127.0.0.1:8080
```

To run the pieces by hand:

```sh
just rendezvous::run -addr :7777            # writes its dev CA to bin/dev-ca.pem
just client::host 127.0.0.1:7777            # prints "lobby K7M2QX"
just client::join 127.0.0.1:7777 K7M2QX bob
```

### Deploying the server

The image (`rendezvous/Dockerfile`, `just rendezvous::image <version>`) is a
static binary on `gcr.io/distroless/static-debian13:nonroot`: about 17 MB,
no shell, user 65532, base images pinned by digest. Without certificate flags
it keeps a development CA in `/home/nonroot/dev-ca.pem` (`docker cp` it out).
`-health :8081` serves `/healthz` separately from the dashboard, because the
dashboard shows lobby codes.

The Helm chart (`charts/rendezvous`, Helm 4) runs it with these settings:

- **Exactly one replica, `Recreate` strategy.** Lobbies live in memory, and two
  pods would split players between them.
- **Pod Security Standard `restricted`,** plus a read-only root filesystem,
  no service account token and no service links. Enforce it on the namespace
  with `pod-security.kubernetes.io/enforce=restricted`.
- **A NetworkPolicy:** the signalling port is open to everyone (or
  `networkPolicy.signallingFrom`), the dashboard is closed, and all egress is
  denied. The server only answers connections and never sends UDP.
- **`GOMEMLIMIT`** is taken from the memory limit.
- **TLS** (`tls.mode`):
  - `selfSigned` (default): Helm generates a CA, keeps it across upgrades and
    reissues the server certificate. Ship the Secret's `ca.crt` with the game.
  - `certManager`: a cert-manager `Certificate`; clients then use public roots.
  - `secret`: a `kubernetes.io/tls` Secret you manage.

  The server re-reads its certificate every minute, so renewals need no restart.
- **A `LoadBalancer` Service with `externalTrafficPolicy: Local`.** This is
  the important part. The server must see each client's real public IP and
  port, because that is the endpoint it hands to peers. Anything that rewrites
  source addresses breaks punching: SNAT, proxying load balancers, and most
  Gateway API implementations. If it happens, clients print the proxy as their
  public endpoint, the dashboard shows the same IP for everyone, and the
  per-IP rate limit lumps all players together.
- **Gateway API (`gateway.enabled`)** is supported. The chart creates (or
  attaches to) a Gateway with a `TCPRoute` (or a TLS-passthrough `TLSRoute`)
  and a `UDPRoute` on the same port, and optionally an `HTTPRoute` for the
  dashboard. These route kinds are in the experimental channel. Only use it
  with an implementation that preserves client addresses for UDP.

```sh
helm install rv charts/rendezvous -n knockknock \
  --set image.repository=registry.example.com/knockknock/rendezvous \
  --set 'tls.selfSigned.hosts={rv.example.com}'
kubectl get secret -n knockknock rv-rendezvous-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > godot/dev-ca.pem
```

Publishing a GitHub release tagged `vX.Y.Z` runs `.github/workflows/release.yml`.
It verifies the release (Go lint and tests, chart lint), builds the image for
amd64 and arm64, and pushes it to `ghcr.io/<owner>/knockknock-rendezvous`. It
then pushes the chart to `oci://ghcr.io/<owner>/charts/rendezvous`, with the
image pinned by digest, and attaches the `.tgz` to the release. Both get signed
build provenance; the image also gets an SBOM. Prereleases (`v1.2.0-rc.1`)
don't move `latest`.

```sh
helm install rv oci://ghcr.io/<owner>/charts/rendezvous --version X.Y.Z -n knockknock -f values.yaml
gh attestation verify oci://ghcr.io/<owner>/knockknock-rendezvous:X.Y.Z --owner <owner>
```

### Testing data over real connections

`scripts/datatest.py` starts a local server (or uses `--server`), a host and
N joiners. Each peer is the real Rust client, driven through the `bridge`
example.

```sh
just datatest bench                                   # echo test: loss, dupes, corruption, RTT
just datatest --players 4 bench --count 2000 --size 1000 --rate 250
just datatest chat                                    # type messages between host and players
just datatest --server rv.example.com:7777 bench      # across real NATs (add --ca for a private CA)
just datatest --dashboard 127.0.0.1:8080 chat         # watch it on the dashboard
```

`bench` checks that a 1168-byte payload round-trips and that 1169 bytes is
rejected. It then sends paced, verifiable payloads that the host echoes back,
and reports loss, duplicates, corruption and round-trip percentiles, followed by
the library's own ping stats. The harness itself (Python, plus hex over pipes)
tops out at roughly 2,000 echoed messages per second on a laptop; beyond that,
its own queues add latency and loss. That is far above typical game rates.

### TLS certificates

Clients verify the server's certificate. In production, give the server a
real certificate (`-tls-cert`, `-tls-key`); clients use the public roots
(`ServerTrust::PublicRoots`). Without a certificate, the server keeps a
development CA at `-tls-dev-ca` (reused across restarts) and serves a
certificate for `-tls-dev-hosts` (localhost by default; add your LAN IP or
hostname to test across machines). Clients then trust that file
(`ServerTrust::ca_file`, `Knockknock.ca_file` in Godot). The examples and the
test script read it from `$KNOCKKNOCK_CA`.

### Using the Rust library

```rust
let mut host = Client::host("rv.example.com:7777", ServerTrust::PublicRoots)?;
loop {
    match host.poll()? {          // non-blocking: call once per frame
        Some(Event::Registered { lobby: Some(lobby), .. }) => show_code(lobby),
        Some(Event::Session { id, state: State::Connected { .. } }) => host.send(id, b"hi")?,
        Some(Event::Data { session, data }) => handle(session, data),
        _ => {}
    }
}
```

`Client` drives the TLS connection and a `std::net::UdpSocket`. To own the
I/O yourself, drive an `Agent` instead. It is sans-IO: you feed it datagrams,
decrypted signalling bytes and the current time, and it hands back datagrams,
signalling bytes and events.

### Using the Godot addon

```sh
just rendezvous::run          # local server; writes bin/dev-ca.pem
just godot-editor             # builds the extension, opens godot/ in the editor
just godot-smoke              # headless host + joiner end to end in real Godot
```

```gdscript
# Host
Knockknock.host_lobby("rv.example.com:7777")
var opened = await Knockknock.lobby_opened            # [lobby_id, local_port]
var peer := ENetMultiplayerPeer.new()
peer.create_server(opened[1], 7)
Knockknock.attach_host(peer.host)   # punches for joiners via ENet, reports ENet stats
multiplayer.multiplayer_peer = peer

# Joiner
Knockknock.join_lobby("rv.example.com:7777", "K7M2QX")
var ready = await Knockknock.join_ready                # [address, port, join_token]
var peer := ENetMultiplayerPeer.new()
peer.create_client(ready[0], ready[1], 0, 0, 0, Knockknock.get_local_port())
multiplayer.multiplayer_peer = peer
# …then send ready[2] to the host in your first RPC; the host checks it with
# Knockknock.verify_join(multiplayer.multiplayer_peer.get_peer(id), token)
```

Connecting happens in the background: `host_lobby`/`join_lobby` return at
once and report through signals. If the server connection drops, knockknock
reconnects by itself and keeps the lobby (`server_lost`, then
`server_restored`; `lobby_changed` if the server forgot it). Games in progress
are unaffected throughout.

Set `Knockknock.ca_file` to a CA file (e.g. `res://dev-ca.pem`) for a server
without a public certificate. To use the addon in your own project, copy
`godot/addons/knockknock` (with the built library in `bin/`) and enable the
plugin; it registers the `Knockknock` autoload.
