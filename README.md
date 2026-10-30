# knockknock

Lobby-based UDP NAT hole punching for peer-to-peer multiplayer in Godot, based
on [Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf)
(Ford, Srisuresh, Kegel).

A host opens a lobby and gets a short code like `K7M2QX`. Players join with
the code. Signalling with the rendezvous server runs over TLS; each client
also sends an authenticated UDP `BIND` from its game socket so the server
learns its public endpoint. The server introduces each joiner to the host,
both sides punch through their NATs with authenticated checks, and game data
then flows directly between them.

- **`rendezvous/`**: the rendezvous server, in Go (standard library only).
- **`client/`**: the peer library, in Rust (`rustls` + `ring` + `webpki-roots`).
- **`client/knockknock-godot/`** + **`godot/`**: the Godot 4.7 GDExtension and an
  example project.
- **`docs/design.md`**: design, state machines, security model, limitations.
- **`docs/protocol.md`**: the wire format, plus shared test vectors in `docs/testdata/`.

## Layout

```
.
├── mise.toml                 # pinned Go, Rust, Python, Godot and just versions
├── justfile                  # top-level tasks; delegates to the modules below
├── docs/
│   ├── design.md             # design spec
│   ├── protocol.md           # wire format (source of truth)
│   └── testdata/vectors.txt  # encoded packets both languages must match
├── rendezvous/               # Go module: knockknock/rendezvous
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

## Getting started

Install [mise](https://mise.jdx.dev), then:

```sh
mise install     # installs Go, Rust and just at the pinned versions
just             # list tasks
just check       # lint + test everything
just demo        # local server + a host + two joiners
just live        # same, long-running, with the dashboard at http://127.0.0.1:8080
```

## Testing data over real connections

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

To run the pieces by hand:

```sh
just rendezvous::run -addr :7777            # writes its dev CA to bin/dev-ca.pem
just client::host 127.0.0.1:7777            # prints "lobby K7M2QX"
just client::join 127.0.0.1:7777 K7M2QX bob
```

### TLS

Clients verify the server's certificate. In production, give the server a
real certificate (`-tls-cert`, `-tls-key`); clients use the public roots
(`ServerTrust::PublicRoots`). Without a certificate, the server generates a
development CA, writes it to `-tls-dev-ca`, and serves a certificate for
`-tls-dev-hosts` (localhost by default; add your LAN IP or hostname to test
across machines). Clients then trust that file (`ServerTrust::ca_file`). The
examples and the test script read it from `$KNOCKKNOCK_CA`.

## Using the library

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

## Dashboard

The rendezvous server serves a stats page (`-http`, default
`127.0.0.1:8080`), refreshed every 2 s:

- **Lobbies:** for each joiner, its state, path type, RTT, jitter and loss, as
  measured by the host's pings and reported every 5 s.
- **Clients:** everyone connected, with their TLS IP and UDP endpoint and
  server-measured signalling latency. Clients are flagged when their UDP
  `BIND` never arrived (UDP probably blocked), when their TLS and UDP IPs
  differ, or when their NAT rebinds.
- **Server counters:** connections, joins by outcome, rejected `BIND`s,
  disconnects by reason, and client and lobby lifetimes.

It shows lobby IDs, so keep it private. The same data is at `/api/lobbies` as
JSON.

## Godot

Target: Godot 4.7.2. knockknock does matchmaking and the authenticated
handshake, then hands the punched port to Godot's own `ENetMultiplayerPeer`,
in the style of netfox.noray. Reliable RPCs, `MultiplayerSynchronizer` and the
rest of Godot's high-level multiplayer work unchanged.

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

Set `Knockknock.ca_file` to a CA file (e.g. `res://dev-ca.pem`) for a server
without a public certificate. To use the addon in your own project, copy
`godot/addons/knockknock` (with the built library in `bin/`) and enable the
plugin; it registers the `Knockknock` autoload. See
[design.md §15](docs/design.md#15-godot-integration-hand-off-to-enet) for how
the hand-off works.

Known issues:
- With gdext 0.5.5 and Godot 4.7.2, the headless editor crashes on exit after
  a project's very first import. It reproduces with an empty gdext extension,
  so it is upstream. Later imports and game runs are unaffected, and
  `just godot-smoke` retries.
- A joiner behind a symmetric NAT cannot reach a send-only host
  (design §15). Relay will fix this.

## Limitations

See [design.md §13](docs/design.md#13-known-limitations). In short: no relay
yet, so two symmetric NATs fail with `NoPath`. Only the primary network
interface is used as a host candidate, and clients do not yet reconnect to the
server automatically.
