# knockknock

Lobby-based UDP NAT hole punching for peer-to-peer multiplayer in Godot, based
on [Peer-to-Peer Communication Across Network Address Translators](https://pdos.csail.mit.edu/papers/p2pnat.pdf)
(Ford, Srisuresh, Kegel).

A host opens a lobby and gets a short code like `K7M2QX`. Players join with
the code. The rendezvous server introduces each joiner to the host, both sides
punch through their NATs with authenticated checks, and game data then flows
directly between them.

- **`rendezvous/`**: the rendezvous server, in Go (standard library only).
- **`client/`**: the peer library, in Rust (only `hmac` + `sha2`).
- **`docs/design.md`**: design, state machines, security model, limitations.
- **`docs/protocol.md`**: the wire format, plus shared test vectors in `docs/testdata/`.

## Layout

```
.
├── mise.toml                 # pinned Go, Rust, Python and just versions
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
│       ├── ratelimit/        # per-IP token bucket
│       ├── registry/         # clients, lobbies, sessions, stats snapshot
│       └── dashboard/        # web view of lobbies and connection stats
└── client/                   # Cargo workspace
    └── knockknock/           # library crate
        ├── src/protocol.rs   # packet encoding/decoding
        ├── src/auth.rs       # HMAC tags, replay window
        ├── src/candidate.rs  # candidates and host gathering
        ├── src/pair.rs       # candidate-pair state machine
        ├── src/session.rs    # session typestate machine (sans-IO)
        ├── src/agent.rs      # registration, lobby, session routing (sans-IO)
        ├── src/stats.rs      # PING/PONG RTT, jitter and loss
        ├── src/client.rs     # std::net::UdpSocket driver
        ├── src/sim.rs        # NAT/loss simulation tests
        └── examples/         # host.rs, join.rs, bridge.rs (stdin/stdout driver)
scripts/
└── datatest.py               # traffic tests over real connections (stdlib only)
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
just datatest --server 1.2.3.4:7777 bench             # across real NATs
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
just rendezvous::run -addr :7777
just client::host 1.2.3.4:7777            # prints "lobby K7M2QX"
just client::join 1.2.3.4:7777 K7M2QX bob
```

## Using the library

```rust
let mut host = Client::host(server)?;
loop {
    match host.poll()? {          // non-blocking: call once per frame
        Some(Event::Registered { lobby: Some(lobby), .. }) => show_code(lobby),
        Some(Event::Session { id, state: State::Connected { .. } }) => host.send(id, b"hi")?,
        Some(Event::Data { session, data }) => handle(session, data),
        _ => {}
    }
}
```

`Client` drives a `std::net::UdpSocket`. To own the I/O yourself, drive an
`Agent` instead. It is sans-IO: you feed it datagrams and the current time, and
it hands back datagrams to send and events.

## Dashboard

The rendezvous server serves a stats page (`-http`, default
`127.0.0.1:8080`). It lists every lobby, and for each joiner shows its state,
path type, RTT, jitter and loss, as measured by the host's pings and reported
every 5 s. It shows lobby IDs, so keep it private.

## Godot

Game traffic stays on the knockknock socket as authenticated `DATA` packets.
That keeps the punched NAT mappings in use and lets the host accept late
joiners. The planned Godot integration is a GDExtension exposing a
`MultiplayerPeerExtension`, built on the [`godot`](https://github.com/godot-rust/gdext)
crate in its own workspace member so the core library keeps its small
dependency set. `DATA` is unreliable for now; reliable channels for RPCs come
with that work.

## Limitations

See [design.md §13](docs/design.md#13-known-limitations). In short: no relay
yet, so two symmetric NATs fail with `NoPath`. There is no signalling
encryption (the threat model is off-path attackers), and only the primary
network interface is used as a host candidate.
