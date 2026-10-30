// Package auth implements packet authentication and replay protection as
// described in docs/protocol.md.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
)

// TagLen is the size of the truncated MAC carried in every packet header.
const TagLen = 16

// Key is a client secret or session key.
type Key [16]byte

// Dir is mixed into the MAC so a packet cannot be reflected back to its sender.
type Dir byte

const (
	ClientToServer Dir = 0x01
	ServerToClient Dir = 0x02
	HostToJoiner   Dir = 0x03
	JoinerToHost   Dir = 0x04
)

// NewKey returns a key from the system CSPRNG.
func NewKey() Key {
	var k Key
	rand.Read(k[:]) // never returns an error since Go 1.24
	return k
}

// MAC returns HMAC-SHA256(key, dir || parts...) truncated to TagLen bytes.
func MAC(key Key, dir Dir, parts ...[]byte) [TagLen]byte {
	h := hmac.New(sha256.New, key[:])
	h.Write([]byte{byte(dir)})
	for _, p := range parts {
		h.Write(p)
	}
	var tag [TagLen]byte
	copy(tag[:], h.Sum(nil))
	return tag
}

// Verify reports, in constant time, whether tag is the MAC of parts.
func Verify(key Key, dir Dir, tag []byte, parts ...[]byte) bool {
	want := MAC(key, dir, parts...)
	return hmac.Equal(want[:], tag)
}

// ReplayWindow tracks the last 64 sequence numbers seen in one direction.
// The zero value is ready to use.
type ReplayWindow struct {
	top  uint32
	bits uint64 // bit i set: top-i has been seen
	init bool
}

// Accept reports whether seq is new and records it. Call it only after the
// packet has been authenticated.
func (w *ReplayWindow) Accept(seq uint32) bool {
	switch {
	case !w.init:
		w.init, w.top, w.bits = true, seq, 1
	case seq > w.top:
		if shift := seq - w.top; shift < 64 {
			w.bits = w.bits<<shift | 1
		} else {
			w.bits = 1
		}
		w.top = seq
	default:
		diff := w.top - seq
		if diff >= 64 || w.bits&(1<<diff) != 0 {
			return false
		}
		w.bits |= 1 << diff
	}
	return true
}
