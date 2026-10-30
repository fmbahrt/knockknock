package registry

import (
	"cmp"
	"fmt"
	"slices"
	"time"

	"knockknock/rendezvous/internal/protocol"
)

// Snapshot is a point-in-time view of the server for monitoring.
type Snapshot struct {
	Time     time.Time       `json:"time"`
	Uptime   Duration        `json:"uptime"`
	Clients  int             `json:"clients"`
	Lobbies  []LobbySnapshot `json:"lobbies"`
	MaxLobby int             `json:"maxLobby"`
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
	}
	lobbies := make([]*lobby, 0, len(s.lobbies))
	for _, l := range s.lobbies {
		lobbies = append(lobbies, l)
	}
	slices.SortFunc(lobbies, func(a, b *lobby) int { return a.created.Compare(b.created) })

	for _, l := range lobbies {
		ls := LobbySnapshot{
			ID:       l.id.String(),
			Host:     l.host.observed.String(),
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

func sessionSnapshot(sess *session, now time.Time) SessionSnapshot {
	ss := SessionSnapshot{
		ID:     fmt.Sprintf("%016x", sess.id),
		Joiner: sess.joiner.observed.String(),
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
