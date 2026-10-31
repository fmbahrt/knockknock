package registry

import (
	"maps"
	"slices"
	"time"
)

// Disconnect reasons, as counted and shown on the dashboard.
const (
	reasonLeft       = "left"              // the client sent CLOSE
	reasonClosed     = "connection closed" // EOF without CLOSE
	reasonIdle       = "idle timeout"
	reasonProtocol   = "protocol error"
	reasonBadRequest = "bad request"
	reasonSlow       = "slow client"
	reasonWrite      = "write error"
	reasonShutdown   = "server shutdown"
	reasonReplaced   = "replaced by resume"
	reasonError      = "connection error"
)

// Join outcomes.
const (
	joinOK        = "ok"
	joinRetry     = "retry"
	joinNotFound  = "lobby not found"
	joinFull      = "lobby full"
	joinRateLimit = "rate limited"
	joinNotBound  = "not bound"
)

// BIND rejection reasons.
const (
	bindMalformed     = "malformed"
	bindUnknownClient = "unknown client"
	bindBadMAC        = "bad mac"
	bindReplay        = "replay"
)

// Counters are cumulative since the server started. Guarded by Server.mu.
type Counters struct {
	Connections       int            `json:"connections"`
	RateLimited       int            `json:"rateLimited"`
	HandshakeFailures int            `json:"handshakeFailures"`
	Hosts             int            `json:"hosts"`
	Players           int            `json:"players"`
	Joins             map[string]int `json:"joins"`
	SlowDropped       int            `json:"slowDropped"`
	BindsRejected     map[string]int `json:"bindsRejected"`
	Rebinds           int            `json:"rebinds"`
	Disconnects       map[string]int `json:"disconnects"`
	Resumed           int            `json:"resumed"`       // reconnected and took back their lobby/session
	ResumeFailed      int            `json:"resumeFailed"`  // asked to resume an unknown or expired client
	ResumeExpired     int            `json:"resumeExpired"` // dropped and never came back within the grace period
}

func newCounters() Counters {
	return Counters{Joins: map[string]int{}, BindsRejected: map[string]int{}, Disconnects: map[string]int{}}
}

func (c Counters) clone() Counters {
	c.Joins = maps.Clone(c.Joins)
	c.BindsRejected = maps.Clone(c.BindsRejected)
	c.Disconnects = maps.Clone(c.Disconnects)
	return c
}

// durations keeps the most recent completed lifetimes for percentiles.
type durations struct {
	recent []time.Duration // ring buffer
	next   int
	total  int
}

const durationHistory = 1000

func (d *durations) add(v time.Duration) {
	if len(d.recent) < durationHistory {
		d.recent = append(d.recent, v)
	} else {
		d.recent[d.next] = v
		d.next = (d.next + 1) % durationHistory
	}
	d.total++
}

// LifetimeSummary describes completed lifetimes: Count is all-time, the
// percentiles cover the most recent 1000.
type LifetimeSummary struct {
	Count int      `json:"count"`
	P50   Duration `json:"p50"`
	P90   Duration `json:"p90"`
	Max   Duration `json:"max"`
}

func (d *durations) summary() LifetimeSummary {
	if len(d.recent) == 0 {
		return LifetimeSummary{Count: d.total}
	}
	sorted := slices.Clone(d.recent)
	slices.Sort(sorted)
	at := func(q float64) Duration { return seconds(sorted[int(q*float64(len(sorted)-1))]) }
	return LifetimeSummary{Count: d.total, P50: at(0.5), P90: at(0.9), Max: seconds(sorted[len(sorted)-1])}
}
