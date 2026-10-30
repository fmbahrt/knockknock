package registry

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"knockknock/rendezvous/internal/protocol"
)

// Snapshot is a point-in-time view of the server for monitoring.
type Snapshot struct {
	Time       time.Time        `json:"time"`
	Uptime     Duration         `json:"uptime"`
	Clients    int              `json:"clients"`
	Unbound    int              `json:"unbound"` // connected clients whose BIND has not arrived
	Lobbies    []LobbySnapshot  `json:"lobbies"`
	ClientList []ClientSnapshot `json:"clientList"`
	MaxLobby   int              `json:"maxLobby"`
	Counters   Counters         `json:"counters"`
	Lifetimes  Lifetimes        `json:"lifetimes"`
}

// ClientSnapshot is one connected client, as the server sees it.
type ClientSnapshot struct {
	ID    string `json:"id"`
	Role  string `json:"role"` // host, player, or idle (registered, not in a lobby)
	Lobby string `json:"lobby,omitempty"`
	// TLSAddr is the IP of the signalling connection; UDPAddr is the game
	// socket's public endpoint ("unbound" until the first BIND).
	TLSAddr string `json:"tlsAddr"`
	UDPAddr string `json:"udpAddr"`
	Bound   bool   `json:"bound"`
	// AddrMismatch: TLS and UDP leave from different public IPs (carrier-
	// grade NAT, a VPN, multiple uplinks).
	AddrMismatch bool     `json:"addrMismatch"`
	Rebinds      int      `json:"rebinds"`
	Connected    Duration `json:"connected"`
	LastBind     Duration `json:"lastBind,omitempty"` // seconds ago
	ServerRTTMs  *float64 `json:"serverRttMs,omitempty"`
}

// Lifetimes summarizes how long clients stayed connected and lobbies stayed
// open, over those that have ended.
type Lifetimes struct {
	Clients LifetimeSummary `json:"clients"`
	Lobbies LifetimeSummary `json:"lobbies"`
}

type LobbySnapshot struct {
	ID       string            `json:"id"`
	Host     string            `json:"host"` // host's public endpoint
	Age      Duration          `json:"age"`
	Sessions []SessionSnapshot `json:"sessions"`
}

type SessionSnapshot struct {
	ID     string   `json:"id"`
	Joiner string   `json:"joiner"` // joiner's public endpoint
	Age    Duration `json:"age"`
	// The fields below come from the host's latest STATS report and are
	// empty until it sends one.
	State       string   `json:"state,omitempty"`
	Path        string   `json:"path,omitempty"`
	RTTMs       *float64 `json:"rttMs,omitempty"`
	JitterMs    *float64 `json:"jitterMs,omitempty"`
	LossPercent *float64 `json:"lossPercent,omitempty"`
	ReportAge   Duration `json:"reportAge,omitempty"`
}

// Duration marshals as seconds.
type Duration float64

func seconds(d time.Duration) Duration { return Duration(d.Seconds()) }

// Snapshot returns the current lobbies, oldest first.
func (s *Server) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	snap := Snapshot{
		Time:     now,
		Uptime:   seconds(now.Sub(s.started)),
		Clients:  len(s.clients),
		Lobbies:  make([]LobbySnapshot, 0, len(s.lobbies)),
		MaxLobby: s.cfg.MaxLobby,
		Counters: s.counters.clone(),
		Lifetimes: Lifetimes{
			Clients: s.clientLifetimes.summary(),
			Lobbies: s.lobbyLifetimes.summary(),
		},
	}

	snap.ClientList = make([]ClientSnapshot, 0, len(s.clients))
	for _, c := range s.clients {
		cs := clientSnapshot(c, now)
		if !cs.Bound {
			snap.Unbound++
		}
		snap.ClientList = append(snap.ClientList, cs)
	}
	slices.SortFunc(snap.ClientList, func(a, b ClientSnapshot) int { return cmp.Compare(b.Connected, a.Connected) })
	lobbies := make([]*lobby, 0, len(s.lobbies))
	for _, l := range s.lobbies {
		lobbies = append(lobbies, l)
	}
	slices.SortFunc(lobbies, func(a, b *lobby) int { return a.created.Compare(b.created) })

	for _, l := range lobbies {
		ls := LobbySnapshot{
			ID:       l.id.String(),
			Host:     endpoint(l.host.observed),
			Age:      seconds(now.Sub(l.created)),
			Sessions: make([]SessionSnapshot, 0, len(l.sessions)),
		}
		for _, sess := range l.sessions {
			ls.Sessions = append(ls.Sessions, sessionSnapshot(sess, now))
		}
		slices.SortFunc(ls.Sessions, func(a, b SessionSnapshot) int { return cmp.Compare(b.Age, a.Age) })
		snap.Lobbies = append(snap.Lobbies, ls)
	}
	return snap
}

func clientSnapshot(c *client, now time.Time) ClientSnapshot {
	cs := ClientSnapshot{
		ID:        fmt.Sprintf("%016x", c.id),
		Role:      "idle",
		TLSAddr:   c.ip.String(),
		UDPAddr:   endpoint(c.observed),
		Bound:     c.bound(),
		Rebinds:   c.rebinds,
		Connected: seconds(now.Sub(c.connected)),
	}
	switch {
	case c.lobby != nil:
		cs.Role, cs.Lobby = "host", c.lobby.id.String()
	case c.session != nil:
		cs.Role, cs.Lobby = "player", c.session.lobby.id.String()
	}
	if c.bound() {
		cs.AddrMismatch = c.observed.Addr() != c.ip
		cs.LastBind = seconds(now.Sub(c.lastBind))
	}
	if c.srtt > 0 {
		cs.ServerRTTMs = ptr(float64(c.srtt.Microseconds()) / 1000)
	}
	return cs
}

func sessionSnapshot(sess *session, now time.Time) SessionSnapshot {
	ss := SessionSnapshot{
		ID:     fmt.Sprintf("%016x", sess.id),
		Joiner: endpoint(sess.joiner.observed),
		Age:    seconds(now.Sub(sess.created)),
	}
	if sess.statsAt.IsZero() {
		return ss
	}
	st := sess.stats
	ss.State = stateNames[st.State]
	ss.Path = pathNames[st.PathKind]
	ss.ReportAge = seconds(now.Sub(sess.statsAt))
	if st.RTTMicros != protocol.RTTUnknown {
		ss.RTTMs = ptr(float64(st.RTTMicros) / 1000)
	}
	if st.RTTVarMicros != protocol.RTTUnknown {
		ss.JitterMs = ptr(float64(st.RTTVarMicros) / 1000)
	}
	ss.LossPercent = ptr(float64(st.LossPermille) / 10)
	return ss
}

var stateNames = map[protocol.SessionState]string{
	protocol.StateConnecting:   "connecting",
	protocol.StateConnected:    "connected",
	protocol.StateDisconnected: "disconnected",
}

var pathNames = map[protocol.CandidateKind]string{
	protocol.KindHost:            "host",
	protocol.KindServerReflexive: "server-reflexive",
	protocol.KindRelay:           "relay",
	protocol.KindPeerReflexive:   "peer-reflexive",
}

func ptr[T any](v T) *T { return &v }

func endpoint(ap netip.AddrPort) string {
	if !ap.IsValid() {
		return "unbound"
	}
	return ap.String()
}
