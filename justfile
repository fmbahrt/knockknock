# knockknock monorepo tasks. Run `just` to list them.

mod rendezvous
mod client

server_addr := "127.0.0.1:7777"
# The Godot smoke test runs its own server here, so it can run next to yours.
smoke_addr := "127.0.0.1:7790"

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
    @just chart-lint

# Lint the Helm chart and render its main variants
chart-lint:
    helm lint --strict charts/rendezvous
    helm template t charts/rendezvous > /dev/null
    helm template t charts/rendezvous --set tls.mode=certManager --set tls.certManager.issuerRef.name=le --set 'tls.certManager.dnsNames[0]=rv.example.com' > /dev/null
    helm template t charts/rendezvous --set gateway.enabled=true --set gateway.create=true --set gateway.className=gc --set dashboard.enabled=true --set dashboard.httpRoute.enabled=true --set 'dashboard.httpRoute.parentRefs[0].name=web' > /dev/null
    helm template t charts/rendezvous --set gateway.enabled=true --set gateway.signallingRoute=TLSRoute --set 'gateway.hostnames[0]=rv.example.com' --set 'gateway.parentRefs.tcp[0].name=g' --set 'gateway.parentRefs.udp[0].name=g' > /dev/null

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
    ./bin/rendezvous -addr {{ server_addr }} -tls-dev-ca "$tmp/ca.pem" &
    until [ -s "$tmp/ca.pem" ]; do sleep 0.1; done
    export KNOCKKNOCK_CA="$tmp/ca.pem"
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
    ./bin/rendezvous -addr {{ server_addr }} -http 127.0.0.1:8080 -tls-dev-ca "$tmp/ca.pem" 2> "$tmp/server.log" &
    until [ -s "$tmp/ca.pem" ]; do sleep 0.1; done
    export KNOCKKNOCK_CA="$tmp/ca.pem"
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

# Build the Godot extension into the example project (godot/addons/knockknock/bin)
godot:
    #!/usr/bin/env bash
    set -euo pipefail
    cargo build --manifest-path client/Cargo.toml -p knockknock-godot
    case "$(uname -s)" in
      Darwin) lib=libknockknock_godot.dylib ;;
      MINGW*|MSYS*|CYGWIN*) lib=knockknock_godot.dll ;;
      *) lib=libknockknock_godot.so ;;
    esac
    mkdir -p godot/addons/knockknock/bin
    # Replace, don't overwrite: an open editor has the old library mapped, and
    # macOS kills processes whose mapped code changes in place.
    cp "client/target/debug/$lib" "godot/addons/knockknock/bin/.$lib.tmp"
    mv -f "godot/addons/knockknock/bin/.$lib.tmp" "godot/addons/knockknock/bin/$lib"
    # Trust the dev CA from `just rendezvous::run`, if there is one.
    if [ -f bin/dev-ca.pem ]; then cp bin/dev-ca.pem godot/dev-ca.pem; fi

# Open the example project in the Godot editor
godot-editor: godot
    scripts/godot --path godot --editor

# End-to-end test in real (headless) Godot: server, host and joiner, ENet hand-off, chat
godot-smoke: godot
    #!/usr/bin/env bash
    set -euo pipefail
    tmp=$(mktemp -d)
    trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$tmp"' EXIT
    go build -C rendezvous -o ../bin/rendezvous ./cmd/rendezvous
    # Godot's first headless import of a fresh project can crash; retry once.
    scripts/godot --headless --path godot --import >/dev/null 2>&1 \
      || scripts/godot --headless --path godot --import >/dev/null 2>&1
    # Same persistent dev CA as `just rendezvous::run`, so godot/dev-ca.pem
    # stays valid for both.
    ./bin/rendezvous -addr {{ smoke_addr }} -http "" -tls-dev-ca bin/dev-ca.pem 2> "$tmp/server.log" &
    until grep -q listening "$tmp/server.log"; do sleep 0.1; done
    cp bin/dev-ca.pem godot/dev-ca.pem
    scripts/godot --headless --path godot -- --host {{ smoke_addr }} > "$tmp/host.log" 2>&1 &
    host=$!
    until grep -q '^LOBBY ' "$tmp/host.log"; do
      kill -0 $host 2>/dev/null || { cat "$tmp/host.log"; exit 1; }
      sleep 0.2
    done
    lobby=$(grep -m1 '^LOBBY ' "$tmp/host.log" | cut -d' ' -f2)
    if scripts/godot --headless --path godot -- --join {{ smoke_addr }} "$lobby" > "$tmp/join.log" 2>&1 && wait $host; then
      grep -h -E 'GOT|joined|connected from' "$tmp/host.log" "$tmp/join.log"
      echo "godot smoke test passed (lobby $lobby)"
    else
      echo "--- host"; cat "$tmp/host.log"; echo "--- joiner"; cat "$tmp/join.log"; echo "--- server"; cat "$tmp/server.log"
      exit 1
    fi

# Remove build artifacts
clean:
    @just rendezvous::clean
    @just client::clean
