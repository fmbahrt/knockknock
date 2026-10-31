// Package registry implements the knockknock rendezvous server: clients
// register over TLS, hosts get lobby IDs, and joiners are introduced to hosts
// so they can punch through their NATs. Over UDP the server only receives
// BINDs, which reveal each client's public game endpoint; it never sends UDP.
package registry

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"knockknock/rendezvous/internal/auth"
	"knockknock/rendezvous/internal/protocol"
	"knockknock/rendezvous/internal/ratelimit"
)

type Config struct {
	// BindInterval is how often clients refresh their UDP binding.
	BindInterval time.Duration
	// IdleTimeout drops signalling connections that send nothing (clients
	// heartbeat well within it).
	IdleTimeout time.Duration
	// HandshakeTimeout bounds the TLS handshake plus REGISTER.
	HandshakeTimeout time.Duration
	// PingInterval is how often the server pings each client over TLS to
	// measure client↔server latency.
	PingInterval time.Duration
	// ResumeGrace is how long a client whose connection dropped (without
	// CLOSE) keeps its lobby and sessions, waiting to resume.
	ResumeGrace time.Duration
	// MaxLobby is the maximum number of peers in a lobby, host included.
	MaxLobby int
	// Rate and Burst limit new connections and joins per source IP.
	Rate  float64
	Burst int
}

func DefaultConfig() Config {
	return Config{
		BindInterval:     15 * time.Second,
		IdleTimeout:      90 * time.Second,
		HandshakeTimeout: 10 * time.Second,
		PingInterval:     10 * time.Second,
		ResumeGrace:      60 * time.Second,
		MaxLobby:         8,
		Rate:             5,
		Burst:            20,
	}
}

// outQueue bounds how many frames may wait for a slow client before it is
// disconnected.
const outQueue = 64

type client struct {
	id         uint64
	secret     auth.Key
	ip         netip.Addr // of the signalling connection
	conn       net.Conn
	out        chan []byte    // nil while detached
	closed     bool           // removed for good
	gen        uint64         // bumped on every (re)attach, so a replaced connection cannot detach the new one
	detachedAt time.Time      // when the connection dropped; zero while attached
	observed   netip.AddrPort // public game endpoint; invalid until the first BIND
	candidates []protocol.Candidate
	recvWindow auth.ReplayWindow
	connected  time.Time
	lastBind   time.Time
	rebinds    int    // public endpoint changes after the first BIND
	dropReason string // why the server closed the connection, if it did

	// Latency of the signalling connection, from server PINGs.
	pingID   uint32
	pingSent time.Time // zero when no ping is outstanding
	srtt     time.Duration

	lobby   *lobby   // set if this client hosts a lobby
	session *session // set if this client joined a lobby
}

func (c *client) bound() bool { return c.observed.IsValid() }

func (c *client) detached() bool { return !c.detachedAt.IsZero() }

type lobby struct {
	id       protocol.LobbyID
	host     *client
	sessions map[uint64]*session
	created  time.Time
}

type session struct {
	id      uint64
	key     auth.Key
	lobby   *lobby
	joiner  *client
	created time.Time
	stats   protocol.SessionStats // latest report from the host
	statsAt time.Time             // zero until the host reports
}

// Server state is shared between the UDP loop, one goroutine per signalling
// connection, and Snapshot; mu guards all of it.
type Server struct {
	udp     *net.UDPConn
	tls     *tls.Config
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	started time.Time

	mu       sync.Mutex
	limiter  *ratelimit.Limiter
	clients  map[uint64]*client
	lobbies  map[protocol.LobbyID]*lobby
	sessions map[uint64]*session

	counters        Counters
	clientLifetimes durations
	lobbyLifetimes  durations
}

func New(udp *net.UDPConn, tlsConfig *tls.Config, cfg Config, log *slog.Logger) *Server {
	return &Server{
		udp:      udp,
		tls:      tlsConfig,
		cfg:      cfg,
		log:      log,
		now:      time.Now,
		started:  time.Now(),
		limiter:  ratelimit.New(cfg.Rate, cfg.Burst),
		clients:  make(map[uint64]*client),
		lobbies:  make(map[protocol.LobbyID]*lobby),
		sessions: make(map[uint64]*session),
		counters: newCounters(),
	}
}

// Serve accepts signalling connections on ln (plain TCP; TLS is added here)
// and BINDs on the UDP socket until ctx is cancelled. It closes both.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		s.udp.Close()
		ln.Close()
	}()

	var conns sync.WaitGroup
	errc := make(chan error, 2)
	go func() { errc <- s.serveUDP(ctx) }()
	go func() { errc <- s.serveTCP(ctx, tls.NewListener(ln, s.tls), &conns) }()
	go s.pruneLimiter(ctx)
	go s.pingClients(ctx)
	go s.expireDetached(ctx)

	err := <-errc
	cancel()
	<-errc
	conns.Wait()
	return err
}

func (s *Server) serveTCP(ctx context.Context, ln net.Listener, conns *sync.WaitGroup) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		ip := addrOf(conn.RemoteAddr()).Addr()
		s.mu.Lock()
		s.counters.Connections++
		allowed := s.limiter.Allow(ip, s.now())
		if !allowed {
			s.counters.RateLimited++
		}
		s.mu.Unlock()
		if !allowed {
			s.log.Debug("rate limited connection", "ip", ip)
			conn.Close()
			continue
		}
		conns.Add(1)
		go func() {
			defer conns.Done()
			s.serveConn(ctx, conn, ip)
		}()
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn, ip netip.Addr) {
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// The first frame (read through the TLS handshake) must be REGISTER.
	conn.SetDeadline(s.now().Add(s.cfg.HandshakeTimeout))
	msg, err := protocol.ReadFrame(conn)
	reg, ok := msg.(*protocol.Register)
	if err != nil || !ok {
		s.log.Debug("handshake failed", "ip", ip, "err", err)
		s.mu.Lock()
		s.counters.HandshakeFailures++
		s.mu.Unlock()
		if err == nil {
			if b, err := protocol.AppendFrame(nil, &protocol.Error{Code: protocol.ErrBadRequest}); err == nil {
				conn.Write(b)
			}
		}
		return
	}
	conn.SetDeadline(time.Time{})

	c, gen := s.register(conn, ip, reg)
	reason := reasonError
	defer func() { s.disconnect(c, gen, reason) }()
	for {
		conn.SetReadDeadline(s.now().Add(s.cfg.IdleTimeout))
		msg, err := protocol.ReadFrame(conn)
		if err != nil {
			reason = s.readFailure(ctx, c, err)
			s.log.Debug("connection ended", "client", c.id, "reason", reason, "err", err)
			return
		}
		if ok, why := s.handleFrame(c, msg); !ok {
			reason = why
			return
		}
	}
}

// readFailure classifies why reading from a client's connection failed.
func (s *Server) readFailure(ctx context.Context, c *client, err error) string {
	s.mu.Lock()
	dropped := c.dropReason
	s.mu.Unlock()
	var netErr net.Error
	switch {
	case ctx.Err() != nil:
		return reasonShutdown
	case dropped != "":
		return dropped
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return reasonClosed
	case errors.As(err, &netErr) && netErr.Timeout():
		return reasonIdle
	case errors.Is(err, protocol.ErrBadField), errors.Is(err, protocol.ErrUnknownType),
		errors.Is(err, protocol.ErrShort), errors.Is(err, protocol.ErrTrailing):
		return reasonProtocol
	default:
		return reasonError
	}
}

// register attaches conn to a new client, or to the client it resumes. It
// returns the client and the attachment generation.
func (s *Server) register(conn net.Conn, ip netip.Addr, m *protocol.Register) (*client, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if m.ResumeID != 0 {
		if c, ok := s.clients[m.ResumeID]; ok && subtle.ConstantTimeCompare(c.secret[:], m.ResumeSecret[:]) == 1 {
			s.resume(c, conn, ip)
			return c, c.gen
		}
		// Expired or unknown: fall through to a fresh registration.
		s.counters.ResumeFailed++
	}

	c := &client{
		id:         s.newID(func(id uint64) bool { return s.clients[id] != nil }),
		secret:     auth.NewKey(),
		candidates: m.Candidates,
		connected:  s.now(),
	}
	s.attach(c, conn, ip)
	s.clients[c.id] = c
	if m.Host {
		s.counters.Hosts++
	} else {
		s.counters.Players++
	}
	if m.Host {
		l := &lobby{id: s.newLobbyID(), host: c, sessions: make(map[uint64]*session), created: s.now()}
		s.lobbies[l.id] = l
		c.lobby = l
	}
	s.log.Info("registered", "client", c.id, "ip", ip, "lobby", c.lobbyID())
	s.sendRegistered(c)
	return c, c.gen
}

// resume moves an existing client onto a new connection. If its old
// connection still looks alive (the server has not noticed it die yet), it is
// replaced.
func (s *Server) resume(c *client, conn net.Conn, ip netip.Addr) {
	if !c.detached() {
		// The old connection's cleanup will see a newer generation and do
		// nothing, so count it here.
		s.counters.Disconnects[reasonReplaced]++
		c.dropReason = reasonReplaced
		c.conn.Close()
		close(c.out)
	}
	s.attach(c, conn, ip)
	s.counters.Resumed++
	s.log.Info("resumed", "client", c.id, "ip", ip, "lobby", c.lobbyID())
	s.sendRegistered(c)
	if c.bound() {
		s.send(c, &protocol.Bound{Observed: c.observed})
	}
}

func (s *Server) attach(c *client, conn net.Conn, ip netip.Addr) {
	c.gen++
	c.conn, c.ip = conn, ip
	c.out = make(chan []byte, outQueue)
	c.detachedAt = time.Time{}
	c.dropReason = ""
	c.pingSent = time.Time{}
	go s.writeLoop(c, conn, c.out, c.gen)
}

func (s *Server) sendRegistered(c *client) {
	s.send(c, &protocol.Registered{
		ClientID: c.id,
		Secret:   c.secret,
		Lobby:    c.lobbyID(),
		BindSecs: uint16(s.cfg.BindInterval / time.Second),
	})
}

func (s *Server) writeLoop(c *client, conn net.Conn, out <-chan []byte, gen uint64) {
	for b := range out {
		conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := conn.Write(b); err != nil {
			s.mu.Lock()
			if c.gen == gen && c.dropReason == "" {
				c.dropReason = reasonWrite
			}
			s.mu.Unlock()
			conn.Close() // ends the read loop, which cleans up
			return
		}
	}
}

// disconnect handles the end of attachment gen. A client that left
// politely is removed; one whose connection just dropped is detached and
// keeps its lobby and sessions for ResumeGrace.
func (s *Server) disconnect(c *client, gen uint64, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.gen != gen || c.closed {
		return // replaced by a resumed connection, or already gone
	}
	s.counters.Disconnects[reason]++
	switch reason {
	case reasonLeft, reasonBadRequest, reasonShutdown:
		s.log.Info("client left", "client", c.id, "reason", reason)
		s.finish(c, s.now())
	default:
		s.log.Info("client detached", "client", c.id, "reason", reason, "grace", s.cfg.ResumeGrace)
		close(c.out)
		c.out, c.conn = nil, nil
		c.detachedAt = s.now()
	}
}

// finish removes a client for good and records its lifetime.
func (s *Server) finish(c *client, end time.Time) {
	s.clientLifetimes.add(end.Sub(c.connected))
	if c.lobby != nil {
		s.lobbyLifetimes.add(end.Sub(c.lobby.created))
	}
	s.removeClient(c)
}

// expireDetached removes clients that did not resume within ResumeGrace.
func (s *Server) expireDetached(ctx context.Context) {
	t := time.NewTicker(max(s.cfg.ResumeGrace/4, 10*time.Millisecond))
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for _, c := range s.clients {
				if c.detached() && now.Sub(c.detachedAt) > s.cfg.ResumeGrace {
					s.log.Info("client expired", "client", c.id)
					s.counters.ResumeExpired++
					s.finish(c, c.detachedAt)
				}
			}
			s.mu.Unlock()
		}
	}
}

// handleFrame processes one frame from a registered client. It returns false
// and a disconnect reason when the connection should be closed.
func (s *Server) handleFrame(c *client, msg protocol.Message) (bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch m := msg.(type) {
	case *protocol.Join:
		s.join(c, m)
	case *protocol.Stats:
		s.recordStats(c, m)
	case *protocol.Ping:
		s.send(c, &protocol.Pong{ID: m.ID})
	case *protocol.Pong:
		s.recordPong(c, m.ID)
	case *protocol.Close:
		return false, reasonLeft
	default:
		s.send(c, &protocol.Error{Code: protocol.ErrBadRequest})
		return false, reasonBadRequest
	}
	return true, ""
}

// pingClients periodically pings every client over TLS so the dashboard can
// show client↔server latency.
func (s *Server) pingClients(ctx context.Context) {
	t := time.NewTicker(s.cfg.PingInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			for _, c := range s.clients {
				if c.detached() {
					continue
				}
				c.pingID++
				c.pingSent = now
				s.send(c, &protocol.Ping{ID: c.pingID})
			}
			s.mu.Unlock()
		}
	}
}

// recordPong updates the smoothed latency (RFC 6298 gain, as on the client)
// when a pong answers the outstanding ping. It includes the time the client
// takes to service its connection.
func (s *Server) recordPong(c *client, id uint32) {
	if id != c.pingID || c.pingSent.IsZero() {
		return
	}
	rtt := s.now().Sub(c.pingSent)
	c.pingSent = time.Time{}
	if c.srtt == 0 {
		c.srtt = rtt
	} else {
		c.srtt = (7*c.srtt + rtt) / 8
	}
}

func (s *Server) serveUDP(ctx context.Context) error {
	buf := make([]byte, 1500)
	for {
		n, from, err := s.udp.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.handleBind(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
	}
}

// handleBind records the public endpoint an authenticated BIND came from and
// tells the client over TLS when it changes. Nothing is ever sent over UDP, so
// spoofed or forged packets cost the sender more than the server.
func (s *Server) handleBind(b []byte, from netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt, err := protocol.Decode(b)
	if err != nil {
		s.counters.BindsRejected[bindMalformed]++
		return
	}
	if _, ok := pkt.Msg.(*protocol.Bind); !ok {
		s.counters.BindsRejected[bindMalformed]++
		return
	}
	c, ok := s.clients[pkt.ID]
	switch {
	case !ok || c.closed:
		s.counters.BindsRejected[bindUnknownClient]++
		return
	case !protocol.Verify(b, c.secret, auth.ClientToServer):
		s.counters.BindsRejected[bindBadMAC]++
		return
	case !c.recvWindow.Accept(pkt.Seq):
		s.counters.BindsRejected[bindReplay]++
		return
	}
	c.lastBind = s.now()
	if c.observed != from {
		if c.bound() {
			c.rebinds++
			s.counters.Rebinds++
		}
		c.observed = from
		s.log.Info("bound", "client", c.id, "observed", from)
		s.send(c, &protocol.Bound{Observed: from})
	}
}

func (s *Server) join(c *client, m *protocol.Join) {
	if c.session != nil && c.session.lobby.id == m.Lobby {
		s.counters.Joins[joinRetry]++
		s.introduce(c.session)
		return
	}
	fail := func(outcome string, code protocol.ErrorCode) {
		s.counters.Joins[outcome]++
		s.send(c, &protocol.Error{Code: code})
	}
	if !s.limiter.Allow(c.ip, s.now()) {
		fail(joinRateLimit, protocol.ErrRateLimited)
		return
	}
	if !c.bound() {
		fail(joinNotBound, protocol.ErrBadRequest)
		return
	}
	l, ok := s.lobbies[m.Lobby]
	// A detached host could not receive the introduction.
	if !ok || l.host == c || !l.host.bound() || l.host.detached() {
		fail(joinNotFound, protocol.ErrLobbyNotFound)
		return
	}
	if len(l.sessions)+1 >= s.cfg.MaxLobby {
		fail(joinFull, protocol.ErrLobbyFull)
		return
	}
	s.counters.Joins[joinOK]++
	if c.session != nil {
		s.removeSession(c.session)
	}

	sess := &session{
		id:      s.newID(func(id uint64) bool { return s.sessions[id] != nil }),
		key:     auth.NewKey(),
		lobby:   l,
		joiner:  c,
		created: s.now(),
	}
	s.sessions[sess.id] = sess
	l.sessions[sess.id] = sess
	c.session = sess
	s.log.Info("joined", "lobby", l.id, "client", c.id, "session", sess.id)
	s.introduce(sess)
}

// recordStats stores a host's report. Entries for sessions outside the
// host's own lobby are ignored. STATS is never answered.
func (s *Server) recordStats(c *client, m *protocol.Stats) {
	if c.lobby == nil {
		return
	}
	now := s.now()
	for _, st := range m.Sessions {
		if sess, ok := c.lobby.sessions[st.SessionID]; ok {
			sess.stats, sess.statsAt = st, now
		}
	}
}

// introduce sends each side of a session the other's candidates.
func (s *Server) introduce(sess *session) {
	host, joiner := sess.lobby.host, sess.joiner
	s.send(host, &protocol.PeerInfo{SessionID: sess.id, Role: protocol.RoleControlling, Key: sess.key, Candidates: joiner.allCandidates()})
	s.send(joiner, &protocol.PeerInfo{SessionID: sess.id, Role: protocol.RoleControlled, Key: sess.key, Candidates: host.allCandidates()})
}

// send queues a frame for c. A client too slow to drain its queue is
// disconnected rather than allowed to stall the server. Callers hold mu.
func (s *Server) send(c *client, m protocol.Message) {
	if c.closed || c.out == nil {
		return
	}
	b, err := protocol.AppendFrame(nil, m)
	if err != nil {
		s.log.Error("encode", "type", m.Type(), "err", err)
		return
	}
	select {
	case c.out <- b:
	default:
		s.log.Warn("client too slow, disconnecting", "client", c.id)
		if c.dropReason == "" {
			c.dropReason = reasonSlow
			s.counters.SlowDropped++
		}
		c.conn.Close()
	}
}

func (s *Server) removeClient(c *client) {
	if c.closed {
		return
	}
	if c.lobby != nil {
		for _, sess := range c.lobby.sessions {
			s.removeSession(sess)
		}
		delete(s.lobbies, c.lobby.id)
	}
	if c.session != nil {
		s.removeSession(c.session)
	}
	delete(s.clients, c.id)
	c.closed = true
	if c.out != nil {
		close(c.out)
		c.out = nil
	}
}

func (s *Server) removeSession(sess *session) {
	delete(s.sessions, sess.id)
	delete(sess.lobby.sessions, sess.id)
	sess.joiner.session = nil
}

func (s *Server) pruneLimiter(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			s.mu.Lock()
			s.limiter.Prune(now)
			s.mu.Unlock()
		}
	}
}

// newID returns a random non-zero ID for which taken returns false.
func (s *Server) newID(taken func(uint64) bool) uint64 {
	for {
		var b [8]byte
		rand.Read(b[:]) // never returns an error since Go 1.24
		if id := binary.BigEndian.Uint64(b[:]); id != 0 && !taken(id) {
			return id
		}
	}
}

func (s *Server) newLobbyID() protocol.LobbyID {
	for {
		if l := protocol.NewLobbyID(); s.lobbies[l] == nil {
			return l
		}
	}
}

func (c *client) lobbyID() protocol.LobbyID {
	if c.lobby == nil {
		return protocol.LobbyID{}
	}
	return c.lobby.id
}

// allCandidates is what the other peer should try: the reported host
// candidates plus the observed server-reflexive endpoint.
func (c *client) allCandidates() []protocol.Candidate {
	cs := []protocol.Candidate{{Kind: protocol.KindServerReflexive, Addr: c.observed}}
	for _, h := range c.candidates {
		if h.Addr != c.observed && len(cs) < protocol.MaxCandidates {
			cs = append(cs, h)
		}
	}
	return cs
}

func addrOf(a net.Addr) netip.AddrPort {
	if tcp, ok := a.(*net.TCPAddr); ok {
		ap := tcp.AddrPort()
		return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
	}
	return netip.AddrPort{}
}
