// Package registry implements the knockknock rendezvous server: it registers
// clients, hands out lobby IDs to hosts, and introduces joiners to hosts so
// they can punch through their NATs.
package registry

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"knockknock/rendezvous/internal/auth"
	"knockknock/rendezvous/internal/protocol"
	"knockknock/rendezvous/internal/ratelimit"
)

type Config struct {
	// TTL is how long a client stays registered without refreshing.
	TTL time.Duration
	// MaxLobby is the maximum number of peers in a lobby, host included.
	MaxLobby int
	// Rate and Burst limit unauthenticated requests and joins per source IP.
	Rate  float64
	Burst int
}

func DefaultConfig() Config {
	return Config{TTL: 60 * time.Second, MaxLobby: 8, Rate: 5, Burst: 20}
}

type client struct {
	id         uint64
	secret     auth.Key
	pending    pendingKey
	observed   netip.AddrPort
	candidates []protocol.Candidate
	seen       time.Time
	recvWindow auth.ReplayWindow
	sendSeq    uint32

	lobby   *lobby   // set if this client hosts a lobby
	session *session // set if this client joined a lobby
}

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

// pendingKey identifies a first-time registration so retries are idempotent.
type pendingKey struct {
	addr  netip.AddrPort
	nonce uint64
}

// Server handles all packets on a single goroutine. mu guards its state
// against concurrent Snapshot calls.
type Server struct {
	conn    *net.UDPConn
	cfg     Config
	log     *slog.Logger
	limiter *ratelimit.Limiter
	now     func() time.Time
	started time.Time

	mu       sync.Mutex
	clients  map[uint64]*client
	pending  map[pendingKey]*client
	lobbies  map[protocol.LobbyID]*lobby
	sessions map[uint64]*session
}

func New(conn *net.UDPConn, cfg Config, log *slog.Logger) *Server {
	return &Server{
		conn:     conn,
		cfg:      cfg,
		log:      log,
		limiter:  ratelimit.New(cfg.Rate, cfg.Burst),
		now:      time.Now,
		started:  time.Now(),
		clients:  make(map[uint64]*client),
		pending:  make(map[pendingKey]*client),
		lobbies:  make(map[protocol.LobbyID]*lobby),
		sessions: make(map[uint64]*session),
	}
}

// Serve handles packets until ctx is cancelled. It closes conn on return.
func (s *Server) Serve(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		s.conn.Close()
	}()

	buf := make([]byte, 1500)
	nextReap := s.now().Add(s.cfg.TTL / 4)
	for {
		s.conn.SetReadDeadline(nextReap)
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		switch {
		case ctx.Err() != nil:
			return nil
		case errors.Is(err, os.ErrDeadlineExceeded):
		case err != nil:
			return err
		default:
			s.handle(buf[:n], netip.AddrPortFrom(from.Addr().Unmap(), from.Port()))
		}
		if now := s.now(); !now.Before(nextReap) {
			s.reap(now)
			nextReap = now.Add(s.cfg.TTL / 4)
		}
	}
}

func (s *Server) handle(b []byte, from netip.AddrPort) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pkt, err := protocol.Decode(b)
	if err != nil {
		s.log.Debug("dropping packet", "from", from, "err", err)
		return
	}

	if m, ok := pkt.Msg.(*protocol.Register); ok && pkt.ID == 0 {
		s.registerNew(m, from)
		return
	}

	c := s.authenticate(pkt, b, from)
	if c == nil {
		return
	}
	switch m := pkt.Msg.(type) {
	case *protocol.Register:
		c.candidates = m.Candidates
		s.sendRegistered(c, m.Nonce)
	case *protocol.Join:
		s.join(c, m, pkt.Seq, from)
	case *protocol.Stats:
		s.recordStats(c, m)
	case *protocol.Close:
		s.log.Info("client left", "client", c.id)
		s.removeClient(c)
	default:
		s.log.Debug("unexpected message", "from", from, "type", pkt.Msg.Type())
	}
}

func (s *Server) registerNew(m *protocol.Register, from netip.AddrPort) {
	key := pendingKey{from, m.Nonce}
	if c, ok := s.pending[key]; ok {
		s.sendRegistered(c, m.Nonce)
		return
	}
	if !s.limiter.Allow(from.Addr(), s.now()) {
		s.log.Debug("rate limited", "from", from)
		return
	}

	c := &client{
		id:         s.newID(func(id uint64) bool { return s.clients[id] != nil }),
		secret:     auth.NewKey(),
		pending:    key,
		observed:   from,
		candidates: m.Candidates,
		seen:       s.now(),
	}
	s.clients[c.id] = c
	s.pending[key] = c
	if m.Host {
		l := &lobby{id: s.newLobbyID(), host: c, sessions: make(map[uint64]*session), created: s.now()}
		s.lobbies[l.id] = l
		c.lobby = l
	}
	s.log.Info("registered", "client", c.id, "observed", from, "lobby", c.lobbyID())
	s.sendRegistered(c, m.Nonce)
}

// authenticate returns the client that sent pkt, or nil (after replying with
// an error where appropriate) if the packet is not authentic.
func (s *Server) authenticate(pkt protocol.Packet, b []byte, from netip.AddrPort) *client {
	c, ok := s.clients[pkt.ID]
	var code protocol.ErrorCode
	switch {
	case !ok:
		code = protocol.ErrUnknownClient
	case !protocol.Verify(b, c.secret, auth.ClientToServer):
		code = protocol.ErrBadAuth
	case !c.recvWindow.Accept(pkt.Seq):
		s.log.Debug("replayed packet", "client", c.id, "seq", pkt.Seq)
		return nil
	default:
		c.seen = s.now()
		c.observed = from // follow NAT rebinding
		return c
	}

	// CLOSE is never answered, and errors are rate limited, so neither can
	// be used for reflection.
	if pkt.Msg.Type() != protocol.TypeClose && s.limiter.Allow(from.Addr(), s.now()) {
		s.sendUnauthenticated(from, &protocol.Error{Code: code, RefSeq: pkt.Seq})
	}
	return nil
}

func (s *Server) join(c *client, m *protocol.Join, seq uint32, from netip.AddrPort) {
	if c.session != nil && c.session.lobby.id == m.Lobby {
		s.introduce(c.session) // retried JOIN
		return
	}
	if !s.limiter.Allow(from.Addr(), s.now()) {
		s.log.Debug("rate limited", "from", from)
		return
	}
	l, ok := s.lobbies[m.Lobby]
	if !ok || l.host == c {
		s.send(c, &protocol.Error{Code: protocol.ErrLobbyNotFound, RefSeq: seq})
		return
	}
	if len(l.sessions)+1 >= s.cfg.MaxLobby {
		s.send(c, &protocol.Error{Code: protocol.ErrLobbyFull, RefSeq: seq})
		return
	}
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

func (s *Server) sendRegistered(c *client, nonce uint64) {
	s.send(c, &protocol.Registered{
		Nonce:    nonce,
		Secret:   c.secret,
		Observed: c.observed,
		Lobby:    c.lobbyID(),
		TTLSecs:  uint16(s.cfg.TTL / time.Second),
	})
}

func (s *Server) send(c *client, m protocol.Message) {
	b, err := protocol.Seal(nil, protocol.Packet{ID: c.id, Seq: c.sendSeq, Msg: m}, &c.secret, auth.ServerToClient)
	if err != nil {
		s.log.Error("encode", "type", m.Type(), "err", err)
		return
	}
	c.sendSeq++
	s.write(b, c.observed)
}

func (s *Server) sendUnauthenticated(to netip.AddrPort, m protocol.Message) {
	b, err := protocol.Seal(nil, protocol.Packet{Msg: m}, nil, 0)
	if err != nil {
		s.log.Error("encode", "type", m.Type(), "err", err)
		return
	}
	s.write(b, to)
}

func (s *Server) write(b []byte, to netip.AddrPort) {
	if _, err := s.conn.WriteToUDPAddrPort(b, to); err != nil {
		s.log.Warn("send", "to", to, "err", err)
	}
}

func (s *Server) reap(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.clients {
		if now.Sub(c.seen) > s.cfg.TTL {
			s.log.Info("expired", "client", c.id)
			s.removeClient(c)
		}
	}
	s.limiter.Prune(now)
}

func (s *Server) removeClient(c *client) {
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
	delete(s.pending, c.pending)
}

func (s *Server) removeSession(sess *session) {
	delete(s.sessions, sess.id)
	delete(sess.lobby.sessions, sess.id)
	sess.joiner.session = nil
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
