package registry

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"
	"time"

	"knockknock/rendezvous/internal/auth"
	"knockknock/rendezvous/internal/protocol"
)

func startServer(t *testing.T, cfg Config) netip.AddrPort {
	t.Helper()
	_, addr := startServerWith(t, cfg)
	return addr
}

func startServerWith(t *testing.T, cfg Config) (*Server, netip.AddrPort) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	srv := New(conn, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	go func() { done <- srv.Serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	return srv, conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

// testClient is a minimal protocol client for driving the server.
type testClient struct {
	t      *testing.T
	conn   *net.UDPConn
	server netip.AddrPort
	id     uint64
	secret auth.Key
	seq    uint32
}

func newClient(t *testing.T, server netip.AddrPort) *testClient {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &testClient{t: t, conn: conn, server: server}
}

func (c *testClient) addr() netip.AddrPort { return c.conn.LocalAddr().(*net.UDPAddr).AddrPort() }

func (c *testClient) sendRaw(b []byte) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDPAddrPort(b, c.server); err != nil {
		c.t.Fatal(err)
	}
}

// send seals m with the client's secret (or sends it unauthenticated before
// registration) and returns the raw packet.
func (c *testClient) send(m protocol.Message) []byte {
	c.t.Helper()
	var key *auth.Key
	if c.id != 0 {
		key = &c.secret
	}
	b, err := protocol.Seal(nil, protocol.Packet{ID: c.id, Seq: c.seq, Msg: m}, key, auth.ClientToServer)
	if err != nil {
		c.t.Fatal(err)
	}
	c.seq++
	c.sendRaw(b)
	return b
}

// recv returns the next message, checking its MAC when it is addressed to us.
func (c *testClient) recv() protocol.Message {
	c.t.Helper()
	m, ok := c.tryRecv(2 * time.Second)
	if !ok {
		c.t.Fatal("timed out waiting for a message")
	}
	return m
}

func (c *testClient) tryRecv(timeout time.Duration) (protocol.Message, bool) {
	c.t.Helper()
	buf := make([]byte, 1500)
	c.conn.SetReadDeadline(time.Now().Add(timeout))
	n, _, err := c.conn.ReadFromUDPAddrPort(buf)
	if err != nil {
		return nil, false
	}
	p, err := protocol.Decode(buf[:n])
	if err != nil {
		c.t.Fatal(err)
	}
	if r, ok := p.Msg.(*protocol.Registered); ok && c.id == 0 {
		c.id, c.secret = p.ID, r.Secret
	}
	if p.ID != 0 && !protocol.Verify(buf[:n], c.secret, auth.ServerToClient) {
		c.t.Fatalf("bad MAC on %T", p.Msg)
	}
	return p.Msg, true
}

func (c *testClient) register(host bool) *protocol.Registered {
	c.t.Helper()
	c.send(&protocol.Register{Nonce: 42, Host: host, Candidates: []protocol.Candidate{
		{Kind: protocol.KindHost, Addr: netip.MustParseAddrPort("10.0.0.9:1234")},
	}})
	return c.recv().(*protocol.Registered)
}

func TestHostAndJoin(t *testing.T) {
	srv := startServer(t, DefaultConfig())
	host, joiner := newClient(t, srv), newClient(t, srv)

	hr := host.register(true)
	if hr.Lobby.IsZero() || hr.Observed != host.addr() || hr.Nonce != 42 {
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
	wantHost := []protocol.Candidate{
		{Kind: protocol.KindServerReflexive, Addr: host.addr()},
		{Kind: protocol.KindHost, Addr: netip.MustParseAddrPort("10.0.0.9:1234")},
	}
	if len(toJoiner.Candidates) != 2 || toJoiner.Candidates[0] != wantHost[0] || toJoiner.Candidates[1] != wantHost[1] {
		t.Errorf("joiner got host candidates %+v", toJoiner.Candidates)
	}
	if toHost.Candidates[0].Addr != joiner.addr() {
		t.Errorf("host got joiner candidates %+v", toHost.Candidates)
	}

	// A retried JOIN re-sends the same session rather than creating another.
	joiner.send(&protocol.Join{Lobby: hr.Lobby})
	if again := joiner.recv().(*protocol.PeerInfo); again.SessionID != toJoiner.SessionID {
		t.Errorf("retried join created session %x, want %x", again.SessionID, toJoiner.SessionID)
	}
}

func TestRegisterRetryIsIdempotent(t *testing.T) {
	srv := startServer(t, DefaultConfig())
	c := newClient(t, srv)
	first := c.register(true)
	id := c.id
	c.id, c.seq = 0, 0 // pretend the reply was lost and retry
	second := c.register(true)
	if c.id != id || second.Lobby != first.Lobby || second.Secret != first.Secret {
		t.Errorf("retry created a new registration")
	}
}

func TestJoinErrors(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxLobby = 2
	srv := startServer(t, cfg)
	host, a, b := newClient(t, srv), newClient(t, srv), newClient(t, srv)
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

func TestAuthentication(t *testing.T) {
	srv := startServer(t, DefaultConfig())
	c := newClient(t, srv)
	lobby := c.register(true).Lobby

	// Unknown client.
	b, _ := protocol.Seal(nil, protocol.Packet{ID: 99, Seq: 7, Msg: &protocol.Join{Lobby: lobby}}, &c.secret, auth.ClientToServer)
	c.sendRaw(b)
	if e := c.recv().(*protocol.Error); e.Code != protocol.ErrUnknownClient || e.RefSeq != 7 {
		t.Errorf("unknown client: %+v", e)
	}

	// Wrong key.
	wrong := auth.Key{1}
	b, _ = protocol.Seal(nil, protocol.Packet{ID: c.id, Seq: 8, Msg: &protocol.Join{Lobby: lobby}}, &wrong, auth.ClientToServer)
	c.sendRaw(b)
	if e := c.recv().(*protocol.Error); e.Code != protocol.ErrBadAuth {
		t.Errorf("bad auth: %+v", e)
	}

	// Replay: the same authenticated refresh twice gets one answer.
	refresh := c.send(&protocol.Register{Nonce: 1})
	c.recv()
	c.sendRaw(refresh)
	if m, ok := c.tryRecv(200 * time.Millisecond); ok {
		t.Errorf("replayed packet answered with %T", m)
	}
}

func TestCloseRemovesLobby(t *testing.T) {
	srv := startServer(t, DefaultConfig())
	host, joiner := newClient(t, srv), newClient(t, srv)
	lobby := host.register(true).Lobby
	joiner.register(false)

	host.send(&protocol.Close{})
	joiner.send(&protocol.Join{Lobby: lobby})
	if e := joiner.recv().(*protocol.Error); e.Code != protocol.ErrLobbyNotFound {
		t.Errorf("closed lobby: code %d", e.Code)
	}
}

func TestRateLimit(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Rate, cfg.Burst = 0.001, 2
	srv := startServer(t, cfg)
	for i := range 3 {
		c := newClient(t, srv)
		c.send(&protocol.Register{Nonce: uint64(i)})
		_, ok := c.tryRecv(200 * time.Millisecond)
		if want := i < 2; ok != want {
			t.Errorf("registration %d answered = %v, want %v", i, ok, want)
		}
	}
}

func TestStatsReachSnapshot(t *testing.T) {
	srv, addr := startServerWith(t, DefaultConfig())
	host, joiner, other := newClient(t, addr), newClient(t, addr), newClient(t, addr)
	lobby := host.register(true).Lobby
	joiner.register(false)
	other.register(true)

	joiner.send(&protocol.Join{Lobby: lobby})
	sid := joiner.recv().(*protocol.PeerInfo).SessionID
	host.recv()

	if s := srv.Snapshot().Lobbies; len(s) != 2 || s[0].Sessions[0].State != "" {
		t.Fatalf("before report: %+v", s)
	}

	// The other host cannot report on sessions outside its lobby.
	other.send(&protocol.Stats{Sessions: []protocol.SessionStats{{SessionID: sid, State: protocol.StateDisconnected}}})
	host.send(&protocol.Stats{Sessions: []protocol.SessionStats{{
		SessionID: sid, State: protocol.StateConnected, PathKind: protocol.KindHost,
		RTTMicros: 12500, RTTVarMicros: protocol.RTTUnknown, LossPermille: 15,
	}}})

	var got SessionSnapshot
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if got = srv.Snapshot().Lobbies[0].Sessions[0]; got.State != "" {
			break
		}
	}
	if got.State != "connected" || got.Path != "host" || got.RTTMs == nil || *got.RTTMs != 12.5 ||
		got.JitterMs != nil || got.LossPercent == nil || *got.LossPercent != 1.5 {
		t.Errorf("snapshot session: %+v", got)
	}
	if m, ok := host.tryRecv(100 * time.Millisecond); ok {
		t.Errorf("STATS was answered with %T", m)
	}
}
