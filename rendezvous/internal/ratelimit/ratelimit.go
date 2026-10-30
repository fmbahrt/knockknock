// Package ratelimit provides a per-IP token bucket.
package ratelimit

import (
	"net/netip"
	"time"
)

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter allows each IP rate events per second with bursts of up to burst.
// It is not safe for concurrent use.
type Limiter struct {
	rate    float64
	burst   float64
	buckets map[netip.Addr]*bucket
}

func New(rate float64, burst int) *Limiter {
	return &Limiter{rate: rate, burst: float64(burst), buckets: make(map[netip.Addr]*bucket)}
}

// Allow reports whether ip may perform one more event at now.
func (l *Limiter) Allow(ip netip.Addr, now time.Time) bool {
	b, ok := l.buckets[ip]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[ip] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Prune forgets buckets that would have refilled completely by now.
func (l *Limiter) Prune(now time.Time) {
	refill := time.Duration(l.burst / l.rate * float64(time.Second))
	for ip, b := range l.buckets {
		if now.Sub(b.last) > refill {
			delete(l.buckets, ip)
		}
	}
}
