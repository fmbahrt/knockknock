# knockknock monorepo tasks. Run `just` to list them.

mod rendezvous
mod client

server_addr := "127.0.0.1:7777"

[private]
default:
    @just --list --list-submodules

# Install the pinned toolchains (Go, Rust, just) via mise
setup:
    mise install

# Build the server and client
build:
    @just rendezvous::build
    @just client::build

# Run all tests
test:
    @just rendezvous::test
    @just client::test

# Lint and check formatting
lint:
    @just rendezvous::lint
    @just client::lint

# Format all code
fmt:
    @just rendezvous::fmt
    @just client::fmt

# Lint and test everything (run this before committing)
check: lint test

# Local end-to-end run: server, a host, and two joiners using its lobby ID
demo: build
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
    ./bin/rendezvous -addr {{ server_addr }} &
    examples=client/target/debug/examples
    $examples/host {{ server_addr }} 2 > "$tmp/host.log" &
    host=$!
    until lobby=$(grep -om1 'lobby [A-Z0-9]*' "$tmp/host.log"); do sleep 0.1; done
    lobby=${lobby#lobby }
    $examples/join {{ server_addr }} "$lobby" alice &
    $examples/join {{ server_addr }} "$lobby" bob
    wait $host
    cat "$tmp/host.log"

# Long-running local setup for the dashboard: server, a host and two joiners
live: build
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
    ./bin/rendezvous -addr {{ server_addr }} -http 127.0.0.1:8080 2> "$tmp/server.log" &
    examples=client/target/debug/examples
    $examples/host {{ server_addr }} > "$tmp/host.log" &
    until lobby=$(grep -om1 'lobby [A-Z0-9]*' "$tmp/host.log"); do sleep 0.1; done
    lobby=${lobby#lobby }
    $examples/join {{ server_addr }} "$lobby" alice --stay > /dev/null &
    $examples/join {{ server_addr }} "$lobby" bob --stay > /dev/null &
    echo "lobby $lobby is up; dashboard at http://127.0.0.1:8080 (Ctrl-C to stop)"
    tail -f "$tmp/host.log"

# Send test traffic over real connections: just datatest bench | chat (see --help)
datatest *args: build
    python scripts/datatest.py {{ args }}

# Remove build artifacts
clean:
    @just rendezvous::clean
    @just client::clean
