Batteries-included UDP NAT hole punching for Godot multiplayer: a Go rendezvous server, a Rust client and a Godot addon.

## Godot addon

Each [release](https://github.com/fmbahrt/knockknock/releases) has a
`knockknock-godot-addon-<version>.zip` with prebuilt libraries for Windows
(x86_64), Linux (x86_64, arm64) and macOS (universal). No Rust toolchain needed:

1. Unzip it into your Godot project root, so you get `addons/knockknock/`.
2. Enable the plugin under Project → Project Settings → Plugins.

Requires Godot 4.7 or later. Verify a download with
`gh attestation verify knockknock-godot-addon-<version>.zip --repo fmbahrt/knockknock`.
