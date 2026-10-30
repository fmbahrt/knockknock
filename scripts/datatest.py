#!/usr/bin/env python3
"""Send test traffic over real knockknock connections.

Starts a rendezvous server (unless --server is given), a host and N joiners.
Each peer is the real Rust client, driven through the `bridge` example over
stdin/stdout. Then either benchmarks echo traffic or lets you chat.

    just datatest bench                      # 2 joiners, 500 messages each
    just datatest bench --players 4 --count 2000 --size 1000 --rate 500
    just datatest chat
    just datatest --server 1.2.3.4:7777 bench   # against a remote server

Latencies measured here include the bridge's stdin/stdout hop (about a
millisecond or two); the "library stats" section shows the client's own
PING-based measurements.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import queue
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BRIDGE = ROOT / "client/target/debug/examples/bridge"
SERVER = ROOT / "bin/rendezvous"
MAX_DATA = 1168  # protocol limit for one DATA payload
HEADER = struct.Struct("!IQ")  # sequence number, send time (ns)

print_lock = threading.Lock()


def log(*args: object) -> None:
    with print_lock:
        print(*args, flush=True)


class Bridge:
    """One knockknock peer, running as a `bridge` subprocess."""

    def __init__(self, name: str, server: str, lobby: str | None = None) -> None:
        self.name = name
        mode = ["host"] if lobby is None else ["join", lobby]
        self.proc = subprocess.Popen(
            [str(BRIDGE), server, *mode],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.lobby: str | None = None
        self.sessions: dict[str, str] = {}  # session id -> state
        self.errors: queue.Queue[str] = queue.Queue()
        self.stats: queue.Queue[tuple[str, str, str, float]] = queue.Queue()
        self.on_data: Callable[[str, bytes], None] = lambda sid, data: None
        self.verbose = False
        self.expect_errors = False  # set while a test provokes errors on purpose
        self._write_lock = threading.Lock()
        self._changed = threading.Condition()
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout
        for line in self.proc.stdout:
            kind, _, rest = line.rstrip("\n").partition(" ")
            if kind == "data":
                sid, _, payload = rest.partition(" ")
                self.on_data(sid, bytes.fromhex(payload))
                continue
            if self.verbose or (kind == "error" and not self.expect_errors):
                log(f"  [{self.name}] {kind} {rest}")
            with self._changed:
                if kind == "registered":
                    self.lobby = rest.split()[1]
                elif kind == "state":
                    sid, _, state = rest.partition(" ")
                    self.sessions[sid] = state
                elif kind == "stats":
                    sid, rtt, jitter, loss = rest.split()
                    self.stats.put((sid, rtt, jitter, float(loss)))
                elif kind == "error":
                    self.errors.put(rest)
                self._changed.notify_all()

    def wait_until(self, check: Callable[[], bool], timeout: float, what: str) -> None:
        with self._changed:
            if not self._changed.wait_for(check, timeout):
                raise TimeoutError(f"{self.name}: timed out waiting for {what}")

    def connected(self) -> list[str]:
        return [sid for sid, st in self.sessions.items() if st.startswith("connected")]

    def command(self, line: str) -> None:
        assert self.proc.stdin
        with self._write_lock:
            self.proc.stdin.write(line + "\n")
            self.proc.stdin.flush()

    def send(self, session: str, data: bytes) -> None:
        self.command(f"send {session} {data.hex()}")

    def query_stats(self, timeout: float = 0.5) -> list[tuple[str, str, str, float]]:
        self.command("stats")
        out, deadline = [], time.monotonic() + timeout
        while len(out) < len(self.connected()):
            try:
                out.append(self.stats.get(timeout=max(0.0, deadline - time.monotonic())))
            except queue.Empty:
                break
        return out

    def close(self) -> None:
        if self.proc.poll() is None:
            try:
                self.command("close")
                self.proc.wait(timeout=2)
            except (OSError, subprocess.TimeoutExpired):
                self.proc.kill()


@dataclass
class Lobby:
    host: Bridge
    joiners: list[Bridge]
    server: subprocess.Popen | None = None
    names: dict[str, str] = field(default_factory=dict)  # session id -> joiner name

    def close(self) -> None:
        for peer in [*self.joiners, self.host]:
            peer.close()
        if self.server:
            self.server.terminate()
            self.server.wait()


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start(args: argparse.Namespace) -> Lobby:
    missing = [p for p in (BRIDGE, SERVER) if not p.exists() and (p is BRIDGE or not args.server)]
    if missing:
        sys.exit(f"missing {', '.join(map(str, missing))}; run `just build` first")

    server_proc = None
    server = args.server
    if not server:
        server = f"127.0.0.1:{free_udp_port()}"
        http = ["-http", args.dashboard] if args.dashboard else ["-http", ""]
        server_proc = subprocess.Popen(
            [str(SERVER), "-addr", server, *http],
            stderr=None if args.verbose else subprocess.DEVNULL,
        )
        time.sleep(0.2)
        log(f"server   {server}" + (f"  (dashboard http://{args.dashboard})" if args.dashboard else ""))

    host = Bridge("host", server)
    host.verbose = args.verbose
    lobby = Lobby(host, [], server_proc)
    try:
        host.wait_until(lambda: host.lobby is not None, 5, "lobby")
        log(f"lobby    {host.lobby}")
        for i in range(args.players):
            j = Bridge(NAMES[i] if i < len(NAMES) else f"player{i + 1}", server, host.lobby)
            j.verbose = args.verbose
            lobby.joiners.append(j)
        for j in lobby.joiners:
            j.wait_until(lambda j=j: bool(j.connected()), 15, "connection")
            sid = j.connected()[0]
            lobby.names[sid] = j.name
            log(f"joined   {j.name:<8} session {sid}  ({j.sessions[sid]})")
        host.wait_until(lambda: len(host.connected()) == args.players, 5, "all players")
    except BaseException:
        lobby.close()
        raise
    return lobby


NAMES = ["alice", "bob", "carol", "dave", "erin", "frank", "grace"]

# ---- bench ------------------------------------------------------------------


def make_payload(seq: int, size: int) -> bytes:
    """Header plus filler derived from seq, so the receiver can verify it."""
    head = HEADER.pack(seq, time.monotonic_ns())
    seed = hashlib.blake2b(seq.to_bytes(4, "big"), digest_size=64).digest()
    filler = (seed * (size // len(seed) + 1))[: size - len(head)]
    return head + filler


def verify(payload: bytes) -> bool:
    seq, _ = HEADER.unpack_from(payload)
    return make_payload(seq, len(payload))[HEADER.size :] == payload[HEADER.size :]


@dataclass
class Results:
    sent: int = 0
    rtts: list[float] = field(default_factory=list)
    seen: set[int] = field(default_factory=set)
    duplicates: int = 0
    corrupt: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def record(self, _session: str, payload: bytes) -> None:
        now = time.monotonic_ns()
        seq, sent_ns = HEADER.unpack_from(payload)
        with self.lock:
            if seq in self.seen:
                self.duplicates += 1
                return
            self.seen.add(seq)
            if not verify(payload):
                self.corrupt += 1
            self.rtts.append((now - sent_ns) / 1e6)


def check_limits(lobby: Lobby) -> bool:
    """A max-size payload round-trips; one byte more is rejected."""
    j = lobby.joiners[0]
    sid = j.connected()[0]
    got = threading.Event()
    j.on_data = lambda s, d: got.set() if len(d) == MAX_DATA else None
    j.send(sid, make_payload(0, MAX_DATA))
    max_ok = got.wait(2)
    j.expect_errors = True
    j.send(sid, bytes(MAX_DATA + 1))
    try:
        oversize_rejected = j.errors.get(timeout=2).startswith("send")
    except queue.Empty:
        oversize_rejected = False
    j.expect_errors = False
    log(f"limits   {MAX_DATA}-byte payload echoed: {'ok' if max_ok else 'FAILED'}; "
        f"{MAX_DATA + 1}-byte payload rejected: {'ok' if oversize_rejected else 'FAILED'}")
    return max_ok and oversize_rejected


def bench(lobby: Lobby, args: argparse.Namespace) -> int:
    if args.size < HEADER.size or args.size > MAX_DATA:
        sys.exit(f"--size must be between {HEADER.size} and {MAX_DATA}")

    # The host echoes everything back to whoever sent it.
    lobby.host.on_data = lambda sid, data: lobby.host.send(sid, data)
    ok = check_limits(lobby)

    results = {j.name: Results() for j in lobby.joiners}
    for j in lobby.joiners:
        j.on_data = results[j.name].record

    log(f"\nsending  {args.count} x {args.size} bytes per player at {args.rate}/s, echoed by the host…")
    interval = 1 / args.rate
    start_t = time.monotonic()
    for seq in range(args.count):
        for j in lobby.joiners:
            j.send(j.connected()[0], make_payload(seq, args.size))
            results[j.name].sent += 1
        # Pace against the start time so slow iterations don't accumulate.
        delay = start_t + (seq + 1) * interval - time.monotonic()
        if delay > 0:
            time.sleep(delay)
    elapsed = time.monotonic() - start_t
    time.sleep(1.0)  # let the last echoes arrive

    log()
    log(f"{'player':<8} {'sent':>6} {'echoed':>7} {'lost':>6} {'dup':>4} {'bad':>4} "
        f"{'min':>7} {'avg':>7} {'p50':>7} {'p95':>7} {'max':>7}  (round trip, ms)")
    for name, r in results.items():
        got = len(r.seen)
        lost = 100 * (r.sent - got) / r.sent if r.sent else 0
        if r.rtts:
            q = statistics.quantiles(r.rtts, n=20) if len(r.rtts) > 1 else [r.rtts[0]] * 19
            lat = [min(r.rtts), statistics.fmean(r.rtts), statistics.median(r.rtts), q[18], max(r.rtts)]
            lat_s = " ".join(f"{v:.2f}".rjust(7) for v in lat)
        else:
            lat_s = " ".join(["      -"] * 5)
        kib = r.sent * args.size / elapsed / 1024
        log(f"{name:<8} {r.sent:>6} {got:>7} {lost:>5.1f}% {r.duplicates:>4} {r.corrupt:>4} {lat_s}  {kib:,.0f} KiB/s each way")
        ok &= r.corrupt == 0

    log("\nlibrary stats (host's PING measurements)")
    for sid, rtt, jitter, loss in sorted(lobby.host.query_stats()):
        log(f"  {lobby.names.get(sid, sid):<8} rtt {rtt} ms  jitter {jitter} ms  loss {loss:.0%}")
    return 0 if ok else 1


# ---- chat -------------------------------------------------------------------


def chat(lobby: Lobby, _args: argparse.Namespace) -> int:
    def show(receiver: str, sender: str, data: bytes) -> None:
        log(f"  [{receiver}] {sender}: {data.decode(errors='replace')}")

    lobby.host.on_data = lambda sid, d: show("host", lobby.names.get(sid, sid), d)
    for j in lobby.joiners:
        j.on_data = lambda sid, d, j=j: show(j.name, "host", d)

    by_name = {j.name: j for j in lobby.joiners}
    log(f"\nplayers: {', '.join(by_name)}")
    log("type `<player> <message>` to send to the host, `host <message>` to send to everyone,")
    log("`host:<player> <message>` to send to one player, `stats`, or `quit`\n")
    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            return 0
        who, _, text = line.partition(" ")
        if who in ("quit", "exit"):
            return 0
        if who == "stats":
            for sid, rtt, jitter, loss in sorted(lobby.host.query_stats()):
                log(f"  {lobby.names.get(sid, sid):<8} rtt {rtt} ms  jitter {jitter} ms  loss {loss:.0%}")
        elif who == "host":
            lobby.host.send("*", text.encode())
        elif who.startswith("host:") and who[5:] in by_name:
            lobby.host.send(by_name[who[5:]].connected()[0], text.encode())
        elif who in by_name:
            j = by_name[who]
            j.send(j.connected()[0], text.encode())
        elif line:
            log(f"  unknown sender {who!r}")
        time.sleep(0.05)  # let replies print before the next prompt


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--server", help="use this rendezvous server instead of starting one")
    p.add_argument("--players", type=int, default=2, help="number of joiners (default 2, max 7)")
    p.add_argument("--dashboard", metavar="ADDR", help="serve the local server's dashboard here, e.g. 127.0.0.1:8080")
    p.add_argument("-v", "--verbose", action="store_true", help="show every bridge event and the server log")
    sub = p.add_subparsers(dest="mode", required=True)
    b = sub.add_parser("bench", help="echo traffic through the host and report loss and latency")
    b.add_argument("--count", type=int, default=500, help="messages per player (default 500)")
    b.add_argument("--size", type=int, default=256, help=f"payload bytes, {HEADER.size}-{MAX_DATA} (default 256)")
    b.add_argument("--rate", type=float, default=200, help="messages per second per player (default 200)")
    sub.add_parser("chat", help="type messages between the host and players")
    args = p.parse_args()

    if not 1 <= args.players <= 7:
        sys.exit("--players must be 1-7 (a lobby holds 8 peers)")
    lobby = start(args)
    try:
        return bench(lobby, args) if args.mode == "bench" else chat(lobby, args)
    finally:
        lobby.close()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
