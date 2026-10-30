package registry

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"knockknock/rendezvous/internal/auth"
	"knockknock/rendezvous/internal/devcert"
	"knockknock/rendezvous/internal/protocol"
)

type testServer struct {
	srv   *Server
	addr  netip.AddrPort // same port for TCP and UDP
	roots *x509.CertPool
}

func startServer(t *testing.T, cfg Config) *testServer {
	t.Helper()
	cert, caPEM, err := devcert.Generate([]string{"127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port})
	if err != nil {
		t.Fatal(err)
	}
	srv := New(udp, &tls.Config{Certificates: []tls.Certificate{cert}}, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	return &testServer{srv, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)), roots}
}

// testClient is a minimal protocol client: a TLS signalling connection plus a
// UDP "game" socket for BIND.
type testClient struct {
	t      *testing.T
	ts     *testServer
	conn   *tls.Conn
	udp    *net.UDPConn
	id     uint64
	secret auth.Key
	seq    uint32
}

func newClient(t *testing.T, ts *testServer) *testClient {
	t.Helper()
	conn, err := tls.Dial("tcp", ts.addr.String(), &tls.Config{RootCAs: ts.roots})
	if err != nil {
		t.Fatal(err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(); udp.Close() })
	return &testClient{t: t, ts: ts, conn: conn, udp: udp}
}

func (c *testClient) gameAddr() netip.AddrPort { return c.udp.LocalAddr().(*net.UDPAddr).AddrPort() }

func (c *testClient) send(m protocol.Message) {
	c.t.Helper()
	b, err := protocol.AppendFrame(nil, m)
	if err != nil {
		c.t.Fatal(err)
	}
	if _, err := c.conn.Write(b); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) tryRecv(timeout time.Duration) (protocol.Message, error) {
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	return protocol.ReadFrame(c.conn)
}

func (c *testClient) recv() protocol.Message {
	c.t.Helper()
	m, err := c.tryRecv(2 * time.Second)
	if err != nil {
		c.t.Fatalf("recv: %v", err)
	}
	return m
}

// bindPacket returns an authenticated BIND with the next sequence number.
func (c *testClient) bindPacket(key auth.Key) []byte {
	c.t.Helper()
	b, err := protocol.Seal(nil, protocol.Packet{ID: c.id, Seq: c.seq, Msg: &protocol.Bind{}}, key, auth.ClientToServer)
	if err != nil {
		c.t.Fatal(err)
	}
	c.seq++
	return b
}

func (c *testClient) sendUDP(b []byte) {
	c.t.Helper()
	if _, err := c.udp.WriteToUDPAddrPort(b, c.ts.addr); err != nil {
		c.t.Fatal(err)
	}
}

func (c *testClient) register(host bool) *protocol.Registered {
	c.t.Helper()
	c.send(&protocol.Register{Host: host, Candidates: []protocol.Candidate{
		{Kind: protocol.KindHost, Addr: netip.MustParseAddrPort("10.0.0.9:1234")},
	}})
	r := c.recv().(*protocol.Registered)
	c.id, c.secret = r.ClientID, r.Secret
	c.sendUDP(c.bindPacket(c.secret))
	if b := c.recv().(*protocol.Bound); b.Observed != c.gameAddr() {
		c.t.Fatalf("bound to %v, want %v", b.Observed, c.gameAddr())
	}
	return r
}

func TestHostAndJoin(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	host, joiner := newClient(t, ts), newClient(t, ts)

	hr := host.register(true)
	if hr.Lobby.IsZero() || hr.BindSecs != 15 {
		t.Fatalf("host registered: %+v", hr)
	}
	if jr := joiner.register(false); !jr.Lobby.IsZero() {
		t.Fatalf("joiner got a lobby: %+v", jr)
	}

	joiner.send(&protocol.Join{Lobby: hr.Lobby})
	toJoiner := joiner.recv().(*protocol.PeerInfo)
	toHost := host.recv().(*protocol.PeerInfo)

	if toHost.SessionID != toJoiner.SessionID || toHost.Key != toJoiner.Key {
		t.Fatalf("sides disagree: %+v vs %+v", toHost, toJoiner)
	}
	if toHost.Role != protocol.RoleControlling || toJoiner.Role != protocol.RoleControlled {
		t.Errorf("roles: host %d, joiner %d", toHost.Role, toJoiner.Role)
	}
	want := []protocol.Candidate{
		{Kind: protocol.KindServerReflexive, Addr: host.gameAddr()},
		{Kind: protocol.KindHost, Addr: netip.MustParseAddrPort("10.0.0.9:1234")},
	}
	if len(toJoiner.Candidates) != 2 || toJoiner.Candidates[0] != want[0] || toJoiner.Candidates[1] != want[1] {
		t.Errorf("joiner got host candidates %+v", toJoiner.Candidates)
	}
	if toHost.Candidates[0].Addr != joiner.gameAddr() {
		t.Errorf("host got joiner candidates %+v", toHost.Candidates)
	}
}

func TestBindIsAuthenticated(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	c := newClient(t, ts)
	c.send(&protocol.Register{})
	r := c.recv().(*protocol.Registered)
	c.id, c.secret = r.ClientID, r.Secret

	c.sendUDP(c.bindPacket(auth.Key{1})) // wrong key
	if m, err := c.tryRecv(200 * time.Millisecond); err == nil {
		t.Fatalf("forged BIND answered with %T", m)
	}

	good := c.bindPacket(c.secret)
	c.sendUDP(good)
	if _, ok := c.recv().(*protocol.Bound); !ok {
		t.Fatal("valid BIND not confirmed")
	}

	// A replay from another address must not move the binding.
	other := newClient(t, ts)
	other.sendUDP(good)
	if m, err := c.tryRecv(200 * time.Millisecond); err == nil {
		t.Fatalf("replayed BIND answered with %T", m)
	}

	// A fresh BIND from a new address (NAT rebinding) does.
	c.udp = other.udp
	c.sendUDP(c.bindPacket(c.secret))
	if b := c.recv().(*protocol.Bound); b.Observed != other.gameAddr() {
		t.Errorf("rebound to %v, want %v", b.Observed, other.gameAddr())
	}
}

func TestJoinErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxLobby = 2
	ts := startServer(t, cfg)
	host, a, b := newClient(t, ts), newClient(t, ts), newClient(t, ts)
	lobby := host.register(true).Lobby
	a.register(false)
	b.register(false)

	missing, _ := protocol.ParseLobbyID("ZZZZZZ")
	a.send(&protocol.Join{Lobby: missing})
	if e := a.recv().(*protocol.Error); e.Code != protocol.ErrLobbyNotFound {
		t.Errorf("unknown lobby: code %d", e.Code)
	}

	host.send(&protocol.Join{Lobby: lobby})
	if e := host.recv().(*protocol.Error); e.Code != protocol.ErrLobbyNotFound {
		t.Errorf("host joining own lobby: code %d", e.Code)
	}

	a.send(&protocol.Join{Lobby: lobby})
	a.recv()
	host.recv()
	b.send(&protocol.Join{Lobby: lobby})
	if e := b.recv().(*protocol.Error); e.Code != protocol.ErrLobbyFull {
		t.Errorf("full lobby: code %d", e.Code)
	}
}

func TestJoinBeforeBindIsRejected(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	host, joiner := newClient(t, ts), newClient(t, ts)
	lobby := host.register(true).Lobby
	joiner.send(&protocol.Register{})
	joiner.recv()
	joiner.send(&protocol.Join{Lobby: lobby})
	if e := joiner.recv().(*protocol.Error); e.Code != protocol.ErrBadRequest {
		t.Errorf("unbound join: code %d", e.Code)
	}
}

func TestFirstFrameMustBeRegister(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	c := newClient(t, ts)
	c.send(&protocol.Ping{ID: 1})
	if e := c.recv().(*protocol.Error); e.Code != protocol.ErrBadRequest {
		t.Errorf("code %d", e.Code)
	}
	if _, err := c.tryRecv(time.Second); err == nil {
		t.Error("connection left open")
	}
}

func TestHeartbeat(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	c := newClient(t, ts)
	c.register(false)
	c.send(&protocol.Ping{ID: 42})
	if p := c.recv().(*protocol.Pong); p.ID != 42 {
		t.Errorf("pong id %d", p.ID)
	}
}

func TestDisconnectClosesLobby(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	host, joiner := newClient(t, ts), newClient(t, ts)
	lobby := host.register(true).Lobby
	joiner.register(false)

	host.conn.Close()
	deadline := time.Now().Add(2 * time.Second)
	for len(ts.srv.Snapshot().Lobbies) != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	joiner.send(&protocol.Join{Lobby: lobby})
	if e := joiner.recv().(*protocol.Error); e.Code != protocol.ErrLobbyNotFound {
		t.Errorf("closed lobby: code %d", e.Code)
	}
}

func TestConnectionRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate, cfg.Burst = 0.001, 2
	ts := startServer(t, cfg)
	for i := range 3 {
		conn, err := tls.Dial("tcp", ts.addr.String(), &tls.Config{RootCAs: ts.roots})
		if want := i < 2; (err == nil) != want {
			t.Errorf("connection %d succeeded = %v, want %v (err %v)", i, err == nil, want, err)
		}
		if conn != nil {
			defer conn.Close()
		}
	}
}

func TestStatsReachSnapshot(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	host, joiner, other := newClient(t, ts), newClient(t, ts), newClient(t, ts)
	lobby := host.register(true).Lobby
	joiner.register(false)
	other.register(true)

	joiner.send(&protocol.Join{Lobby: lobby})
	sid := joiner.recv().(*protocol.PeerInfo).SessionID
	host.recv()

	// The other host cannot report on sessions outside its lobby.
	other.send(&protocol.Stats{Sessions: []protocol.SessionStats{{SessionID: sid, State: protocol.StateDisconnected}}})
	host.send(&protocol.Stats{Sessions: []protocol.SessionStats{{
		SessionID: sid, State: protocol.StateConnected, PathKind: protocol.KindHost,
		RTTMicros: 12500, RTTVarMicros: protocol.RTTUnknown, LossPermille: 15,
	}}})

	var got SessionSnapshot
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if got = ts.srv.Snapshot().Lobbies[0].Sessions[0]; got.State != "" {
			break
		}
	}
	if got.State != "connected" || got.Path != "host" || got.RTTMs == nil || *got.RTTMs != 12.5 ||
		got.JitterMs != nil || got.LossPercent == nil || *got.LossPercent != 1.5 {
		t.Errorf("snapshot session: %+v", got)
	}
	if got.Joiner != joiner.gameAddr().String() {
		t.Errorf("joiner endpoint %q", got.Joiner)
	}
}

// eventually polls the snapshot until check passes.
func eventually(t *testing.T, ts *testServer, what string, check func(Snapshot) bool) Snapshot {
	t.Helper()
	var snap Snapshot
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if snap = ts.srv.Snapshot(); check(snap) {
			return snap
		}
	}
	t.Fatalf("timed out waiting for %s; last snapshot: %+v", what, snap)
	return snap
}

func TestUnboundAndRebindStats(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	c := newClient(t, ts)
	c.send(&protocol.Register{})
	r := c.recv().(*protocol.Registered)
	c.id, c.secret = r.ClientID, r.Secret

	snap := ts.srv.Snapshot()
	if snap.Unbound != 1 || snap.ClientList[0].Bound || snap.ClientList[0].UDPAddr != "unbound" {
		t.Fatalf("before BIND: unbound=%d %+v", snap.Unbound, snap.ClientList)
	}

	c.sendUDP(c.bindPacket(c.secret))
	c.recv()
	snap = ts.srv.Snapshot()
	cs := snap.ClientList[0]
	if snap.Unbound != 0 || !cs.Bound || cs.UDPAddr != c.gameAddr().String() || cs.Rebinds != 0 || cs.AddrMismatch {
		t.Fatalf("after BIND: %+v", cs)
	}
	if cs.TLSAddr != "127.0.0.1" || cs.Role != "idle" {
		t.Errorf("client details: %+v", cs)
	}

	// The game socket's public endpoint changes (NAT rebinding).
	other := newClient(t, ts)
	c.udp = other.udp
	c.sendUDP(c.bindPacket(c.secret))
	c.recv()
	snap = ts.srv.Snapshot()
	if snap.ClientList[0].Rebinds != 1 && snap.ClientList[1].Rebinds != 1 {
		t.Errorf("rebind not counted: %+v", snap.ClientList)
	}
	if snap.Counters.Rebinds != 1 {
		t.Errorf("counters.rebinds = %d", snap.Counters.Rebinds)
	}
}

func TestCounters(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxLobby = 2
	ts := startServer(t, cfg)
	host, a, b := newClient(t, ts), newClient(t, ts), newClient(t, ts)
	lobby := host.register(true).Lobby
	a.register(false)
	b.register(false)

	missing, _ := protocol.ParseLobbyID("ZZZZZZ")
	a.send(&protocol.Join{Lobby: missing})
	a.recv()
	a.send(&protocol.Join{Lobby: lobby})
	a.recv()
	host.recv()
	b.send(&protocol.Join{Lobby: lobby})
	b.recv()

	// Rejected BINDs: wrong key, unknown client, replay.
	b.sendUDP(b.bindPacket(auth.Key{9}))
	unknown := *b
	unknown.id = 12345
	b.sendUDP(unknown.bindPacket(b.secret))
	replay := b.bindPacket(b.secret)
	b.sendUDP(replay)
	b.sendUDP(replay)
	// UDP and TLS are processed independently; let the BINDs land first.
	eventually(t, ts, "bind rejections", func(s Snapshot) bool {
		r := s.Counters.BindsRejected
		return r[bindBadMAC]+r[bindUnknownClient]+r[bindReplay] == 3
	})

	// Disconnects: one polite, one abrupt.
	b.send(&protocol.Close{})
	a.conn.Close()

	snap := eventually(t, ts, "disconnects", func(s Snapshot) bool {
		return s.Counters.Disconnects[reasonLeft] == 1 && s.Counters.Disconnects[reasonClosed] == 1
	})
	c := snap.Counters
	if c.Hosts != 1 || c.Players != 2 || c.Connections != 3 {
		t.Errorf("registrations: %+v", c)
	}
	if c.Joins[joinOK] != 1 || c.Joins[joinNotFound] != 1 || c.Joins[joinFull] != 1 {
		t.Errorf("joins: %v", c.Joins)
	}
	if c.BindsRejected[bindBadMAC] != 1 || c.BindsRejected[bindUnknownClient] != 1 || c.BindsRejected[bindReplay] != 1 {
		t.Errorf("binds rejected: %v", c.BindsRejected)
	}
	if snap.Lifetimes.Clients.Count != 2 || snap.Lifetimes.Lobbies.Count != 0 {
		t.Errorf("lifetimes: %+v", snap.Lifetimes)
	}

	host.conn.Close()
	snap = eventually(t, ts, "lobby lifetime", func(s Snapshot) bool { return s.Lifetimes.Lobbies.Count == 1 })
	if snap.Lifetimes.Clients.Count != 3 || snap.Lifetimes.Clients.Max <= 0 {
		t.Errorf("lifetimes: %+v", snap.Lifetimes)
	}
}

func TestHandshakeFailuresCounted(t *testing.T) {
	ts := startServer(t, DefaultConfig())
	// Plain TCP, no TLS: the handshake fails.
	conn, err := net.Dial("tcp", ts.addr.String())
	if err != nil {
		t.Fatal(err)
	}
	conn.Write([]byte("not tls\n"))
	conn.Close()
	eventually(t, ts, "handshake failure", func(s Snapshot) bool { return s.Counters.HandshakeFailures == 1 })
}

func TestServerMeasuresLatency(t *testing.T) {
	cfg := DefaultConfig()
	cfg.PingInterval = 20 * time.Millisecond
	ts := startServer(t, cfg)
	c := newClient(t, ts)
	c.register(false)

	// Answer the server's pings, like a real client.
	for range 3 {
		ping := c.recv().(*protocol.Ping)
		c.send(&protocol.Pong{ID: ping.ID})
	}
	snap := eventually(t, ts, "server rtt", func(s Snapshot) bool { return s.ClientList[0].ServerRTTMs != nil })
	if rtt := *snap.ClientList[0].ServerRTTMs; rtt <= 0 || rtt > 1000 {
		t.Errorf("server rtt %v ms", rtt)
	}

	// A pong for a stale ping is ignored.
	before := *snap.ClientList[0].ServerRTTMs
	c.send(&protocol.Pong{ID: 99999})
	time.Sleep(50 * time.Millisecond)
	if got := ts.srv.Snapshot().ClientList[0].ServerRTTMs; got == nil || *got <= 0 {
		t.Errorf("rtt after stale pong: %v (before %v)", got, before)
	}
}
