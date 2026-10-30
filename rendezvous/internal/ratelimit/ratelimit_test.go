package ratelimit

import (
	"net/netip"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := New(2, 3)
	ip := netip.MustParseAddr("192.0.2.1")
	now := time.Unix(0, 0)
	for i := range 3 {
		if !l.Allow(ip, now) {
			t.Fatalf("burst event %d denied", i)
		}
	}
	if l.Allow(ip, now) {
		t.Fatal("event beyond burst allowed")
	}
	if !l.Allow(netip.MustParseAddr("192.0.2.2"), now) {
		t.Fatal("other IP denied")
	}
	if !l.Allow(ip, now.Add(500*time.Millisecond)) {
		t.Fatal("refilled token denied")
	}
	l.Prune(now.Add(time.Hour))
	if len(l.buckets) != 0 {
		t.Fatalf("%d buckets left after prune", len(l.buckets))
	}
}
