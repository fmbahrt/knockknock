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

# Remove build artifacts
clean:
    @just rendezvous::clean
    @just client::clean
