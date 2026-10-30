package protocol

import (
	"crypto/rand"
	"fmt"
	"strings"
)

const LobbyIDLen = 6

// lobbyAlphabet leaves out characters that are easily confused: 0/O, 1/I/L.
const lobbyAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// LobbyID is the human-shareable code a host hands out to players. The zero
// value means "no lobby".
type LobbyID [LobbyIDLen]byte

// NewLobbyID returns a random lobby ID.
func NewLobbyID() LobbyID {
	var l LobbyID
	rand.Read(l[:]) // never returns an error since Go 1.24
	for i, b := range l {
		// 256 % 31 != 0, so this is very slightly biased. That is fine for
		// a short-lived invite code.
		l[i] = lobbyAlphabet[int(b)%len(lobbyAlphabet)]
	}
	return l
}

// ParseLobbyID parses a lobby ID case-insensitively.
func ParseLobbyID(s string) (LobbyID, error) {
	var l LobbyID
	if len(s) != LobbyIDLen {
		return l, fmt.Errorf("%w: lobby id must be %d characters", ErrBadField, LobbyIDLen)
	}
	copy(l[:], strings.ToUpper(s))
	if !l.valid() {
		return LobbyID{}, fmt.Errorf("%w: lobby id %q has invalid characters", ErrBadField, s)
	}
	return l, nil
}

func (l LobbyID) IsZero() bool { return l == LobbyID{} }

func (l LobbyID) String() string {
	if l.IsZero() {
		return ""
	}
	return string(l[:])
}

func (l LobbyID) valid() bool {
	for _, c := range l {
		if !strings.ContainsRune(lobbyAlphabet, rune(c)) {
			return false
		}
	}
	return true
}
