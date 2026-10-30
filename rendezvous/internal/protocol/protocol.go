// Package protocol implements the knockknock wire format described in
// docs/protocol.md.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"knockknock/rendezvous/internal/auth"
)

const (
	Version       byte = 2
	HeaderLen          = 32
	MaxCandidates      = 8
	MaxDataLen         = 1168
	MaxStats           = 16
	// RTTUnknown marks an RTT that has not been measured yet.
	RTTUnknown = ^uint32(0)
	// MinRegisterPayload is the largest possible REGISTERED payload. REGISTER
	// is padded to at least this size so the server never amplifies.
	MinRegisterPayload = 8 + 16 + 19 + LobbyIDLen + 2
)

var magic = [2]byte{'K', 'K'}

type Type byte

const (
	TypeRegister   Type = 0x01
	TypeRegistered Type = 0x02
	TypeJoin       Type = 0x03
	TypePeerInfo   Type = 0x04
	TypeError      Type = 0x05
	TypeClose      Type = 0x06
	TypeStats      Type = 0x07
	TypeCheck      Type = 0x10
	TypeCheckAck   Type = 0x11
	TypePing       Type = 0x12
	TypePong       Type = 0x13
	TypeData       Type = 0x20
)

type ErrorCode byte

const (
	ErrBadAuth       ErrorCode = 1
	ErrUnknownClient ErrorCode = 2
	ErrLobbyNotFound ErrorCode = 3
	ErrLobbyFull     ErrorCode = 4
)

type Role byte

const (
	RoleControlling Role = 1 // host
	RoleControlled  Role = 2 // joiner
)

type CandidateKind byte

const (
	KindHost            CandidateKind = 1
	KindServerReflexive CandidateKind = 2
	KindRelay           CandidateKind = 3
	KindPeerReflexive   CandidateKind = 4
)

// SessionState is a session's state as reported by its host.
type SessionState byte

const (
	StateConnecting   SessionState = 1
	StateConnected    SessionState = 2
	StateDisconnected SessionState = 3
)

// SessionStats is one entry of a STATS report: the host's view of the path
// to one joiner.
type SessionStats struct {
	SessionID uint64
	State     SessionState
	// PathKind is the remote candidate kind of the selected path, or 0.
	PathKind     CandidateKind
	RTTMicros    uint32 // smoothed RTT, or RTTUnknown
	RTTVarMicros uint32 // RTT variation (jitter), or RTTUnknown
	LossPermille uint16 // share of recent pings that went unanswered
}

type Candidate struct {
	Kind CandidateKind
	Addr netip.AddrPort
}

const flagHost, flagNominate = 1, 1

var (
	ErrShort       = errors.New("protocol: message too short")
	ErrBadMagic    = errors.New("protocol: bad magic")
	ErrBadVersion  = errors.New("protocol: unsupported version")
	ErrUnknownType = errors.New("protocol: unknown message type")
	ErrBadField    = errors.New("protocol: invalid field")
	ErrTrailing    = errors.New("protocol: trailing bytes")
)

// Message is the payload of a packet.
type Message interface {
	Type() Type
}

type Register struct {
	Nonce      uint64
	Host       bool
	Candidates []Candidate
}

type Registered struct {
	Nonce    uint64
	Secret   auth.Key
	Observed netip.AddrPort
	Lobby    LobbyID // zero unless the client registered as host
	TTLSecs  uint16
}

type Join struct {
	Lobby LobbyID
}

type PeerInfo struct {
	SessionID  uint64
	Role       Role
	Key        auth.Key
	Candidates []Candidate
}

type Error struct {
	Code   ErrorCode
	RefSeq uint32
}

type Close struct {
	Reason byte
}

// Stats is sent by a host to report its sessions. It is never answered.
type Stats struct {
	Sessions []SessionStats
}

type Ping struct {
	ID uint32
}

type Pong struct {
	ID uint32
}

type Check struct {
	TxID     uint64
	Nominate bool
}

type CheckAck struct {
	TxID     uint64
	Nominate bool
	Observed netip.AddrPort
}

type Data struct {
	Payload []byte
}

func (*Register) Type() Type   { return TypeRegister }
func (*Registered) Type() Type { return TypeRegistered }
func (*Join) Type() Type       { return TypeJoin }
func (*PeerInfo) Type() Type   { return TypePeerInfo }
func (*Error) Type() Type      { return TypeError }
func (*Close) Type() Type      { return TypeClose }
func (*Stats) Type() Type      { return TypeStats }
func (*Ping) Type() Type       { return TypePing }
func (*Pong) Type() Type       { return TypePong }
func (*Check) Type() Type      { return TypeCheck }
func (*CheckAck) Type() Type   { return TypeCheckAck }
func (*Data) Type() Type       { return TypeData }

// Packet is a decoded header plus message. The auth tag is checked with
// Verify against the raw bytes.
type Packet struct {
	ID  uint64
	Seq uint32
	Msg Message
}

// Seal encodes p, appends it to b, and fills in the MAC. A nil key leaves
// the auth field zeroed (unauthenticated packet).
func Seal(b []byte, p Packet, key *auth.Key, dir auth.Dir) ([]byte, error) {
	start := len(b)
	b = append(b, magic[0], magic[1], Version, byte(p.Msg.Type()))
	b = binary.BigEndian.AppendUint64(b, p.ID)
	b = binary.BigEndian.AppendUint32(b, p.Seq)
	b = append(b, make([]byte, auth.TagLen)...)

	b, err := appendPayload(b, p.Msg)
	if err != nil {
		return nil, err
	}
	if key != nil {
		pkt := b[start:]
		tag := auth.MAC(*key, dir, pkt[:16], pkt[HeaderLen:])
		copy(pkt[16:HeaderLen], tag[:])
	}
	return b, nil
}

// Verify reports whether pkt (a whole packet) carries a valid MAC.
func Verify(pkt []byte, key auth.Key, dir auth.Dir) bool {
	if len(pkt) < HeaderLen {
		return false
	}
	return auth.Verify(key, dir, pkt[16:HeaderLen], pkt[:16], pkt[HeaderLen:])
}

func appendPayload(b []byte, m Message) ([]byte, error) {
	var err error
	switch m := m.(type) {
	case *Register:
		start := len(b)
		b = binary.BigEndian.AppendUint64(b, m.Nonce)
		b = append(b, boolFlag(m.Host, flagHost))
		if b, err = appendCandidates(b, m.Candidates); err != nil {
			return nil, err
		}
		if pad := MinRegisterPayload - (len(b) - start); pad > 0 {
			b = append(b, make([]byte, pad)...)
		}
	case *Registered:
		b = binary.BigEndian.AppendUint64(b, m.Nonce)
		b = append(b, m.Secret[:]...)
		b = appendEndpoint(b, m.Observed)
		b = append(b, m.Lobby[:]...)
		b = binary.BigEndian.AppendUint16(b, m.TTLSecs)
	case *Join:
		if m.Lobby.IsZero() {
			return nil, fmt.Errorf("%w: empty lobby id", ErrBadField)
		}
		b = append(b, m.Lobby[:]...)
	case *PeerInfo:
		b = binary.BigEndian.AppendUint64(b, m.SessionID)
		b = append(b, byte(m.Role))
		b = append(b, m.Key[:]...)
		if b, err = appendCandidates(b, m.Candidates); err != nil {
			return nil, err
		}
	case *Error:
		b = append(b, byte(m.Code))
		b = binary.BigEndian.AppendUint32(b, m.RefSeq)
	case *Close:
		b = append(b, m.Reason)
	case *Stats:
		if len(m.Sessions) > MaxStats {
			return nil, fmt.Errorf("%w: too many stats entries", ErrBadField)
		}
		b = append(b, byte(len(m.Sessions)))
		for _, st := range m.Sessions {
			b = binary.BigEndian.AppendUint64(b, st.SessionID)
			b = append(b, byte(st.State), byte(st.PathKind))
			b = binary.BigEndian.AppendUint32(b, st.RTTMicros)
			b = binary.BigEndian.AppendUint32(b, st.RTTVarMicros)
			b = binary.BigEndian.AppendUint16(b, st.LossPermille)
		}
	case *Ping:
		b = binary.BigEndian.AppendUint32(b, m.ID)
	case *Pong:
		b = binary.BigEndian.AppendUint32(b, m.ID)
	case *Check:
		b = binary.BigEndian.AppendUint64(b, m.TxID)
		b = append(b, boolFlag(m.Nominate, flagNominate))
	case *CheckAck:
		b = binary.BigEndian.AppendUint64(b, m.TxID)
		b = append(b, boolFlag(m.Nominate, flagNominate))
		b = appendEndpoint(b, m.Observed)
	case *Data:
		if len(m.Payload) > MaxDataLen {
			return nil, fmt.Errorf("%w: data too long", ErrBadField)
		}
		b = append(b, m.Payload...)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnknownType, m)
	}
	return b, nil
}

// Decode parses a packet. It does not verify the MAC.
func Decode(b []byte) (Packet, error) {
	if len(b) < HeaderLen {
		return Packet{}, ErrShort
	}
	if b[0] != magic[0] || b[1] != magic[1] {
		return Packet{}, ErrBadMagic
	}
	if b[2] != Version {
		return Packet{}, ErrBadVersion
	}
	p := Packet{
		ID:  binary.BigEndian.Uint64(b[4:12]),
		Seq: binary.BigEndian.Uint32(b[12:16]),
	}

	payload := b[HeaderLen:]
	r := reader{b: payload}
	switch Type(b[3]) {
	case TypeRegister:
		m := &Register{Nonce: r.u64(), Host: r.u8()&flagHost != 0, Candidates: r.candidates()}
		if r.err == nil && len(payload) < MinRegisterPayload {
			r.err = ErrShort
		}
		r.zeroPadding()
		p.Msg = m
	case TypeRegistered:
		m := &Registered{Nonce: r.u64()}
		copy(m.Secret[:], r.take(16))
		m.Observed = r.endpoint()
		m.Lobby = r.lobbyID()
		m.TTLSecs = r.u16()
		p.Msg = m
	case TypeJoin:
		m := &Join{Lobby: r.lobbyID()}
		if r.err == nil && m.Lobby.IsZero() {
			r.err = ErrBadField
		}
		p.Msg = m
	case TypePeerInfo:
		m := &PeerInfo{SessionID: r.u64(), Role: Role(r.u8())}
		if r.err == nil && m.Role != RoleControlling && m.Role != RoleControlled {
			r.err = ErrBadField
		}
		copy(m.Key[:], r.take(16))
		m.Candidates = r.candidates()
		p.Msg = m
	case TypeError:
		p.Msg = &Error{Code: ErrorCode(r.u8()), RefSeq: r.u32()}
	case TypeClose:
		p.Msg = &Close{Reason: r.u8()}
	case TypeStats:
		p.Msg = &Stats{Sessions: r.stats()}
	case TypePing:
		p.Msg = &Ping{ID: r.u32()}
	case TypePong:
		p.Msg = &Pong{ID: r.u32()}
	case TypeCheck:
		p.Msg = &Check{TxID: r.u64(), Nominate: r.u8()&flagNominate != 0}
	case TypeCheckAck:
		p.Msg = &CheckAck{TxID: r.u64(), Nominate: r.u8()&flagNominate != 0, Observed: r.endpoint()}
	case TypeData:
		if len(payload) > MaxDataLen {
			return Packet{}, ErrBadField
		}
		p.Msg = &Data{Payload: append([]byte(nil), r.take(len(payload))...)}
	default:
		return Packet{}, ErrUnknownType
	}
	if r.err != nil {
		return Packet{}, r.err
	}
	if len(r.b) != 0 {
		return Packet{}, ErrTrailing
	}
	return p, nil
}

func boolFlag(set bool, flag byte) byte {
	if set {
		return flag
	}
	return 0
}

func appendCandidates(b []byte, cs []Candidate) ([]byte, error) {
	if len(cs) > MaxCandidates {
		return nil, fmt.Errorf("%w: too many candidates", ErrBadField)
	}
	b = append(b, byte(len(cs)))
	for _, c := range cs {
		b = append(b, byte(c.Kind))
		b = appendEndpoint(b, c.Addr)
	}
	return b, nil
}

func appendEndpoint(b []byte, ep netip.AddrPort) []byte {
	addr := ep.Addr().Unmap()
	if addr.Is4() {
		b = append(b, 4)
	} else {
		b = append(b, 6)
	}
	b = append(b, addr.AsSlice()...)
	return binary.BigEndian.AppendUint16(b, ep.Port())
}

// reader consumes fields from a payload, recording the first error so that
// callers can decode a whole message and check once at the end.
type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if len(r.b) < n {
		r.err = ErrShort
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

func (r *reader) u8() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}

func (r *reader) u32() uint32 {
	if v := r.take(4); v != nil {
		return binary.BigEndian.Uint32(v)
	}
	return 0
}

func (r *reader) u64() uint64 {
	if v := r.take(8); v != nil {
		return binary.BigEndian.Uint64(v)
	}
	return 0
}

func (r *reader) endpoint() netip.AddrPort {
	var addr netip.Addr
	switch family := r.u8(); family {
	case 4:
		if v := r.take(4); v != nil {
			addr = netip.AddrFrom4([4]byte(v))
		}
	case 6:
		if v := r.take(16); v != nil {
			addr = netip.AddrFrom16([16]byte(v))
		}
	default:
		r.fail(ErrBadField)
	}
	return netip.AddrPortFrom(addr, r.u16())
}

func (r *reader) candidates() []Candidate {
	n := int(r.u8())
	if n > MaxCandidates {
		r.fail(ErrBadField)
		return nil
	}
	cs := make([]Candidate, 0, n)
	for range n {
		kind := CandidateKind(r.u8())
		if kind < KindHost || kind > KindPeerReflexive {
			r.fail(ErrBadField)
		}
		cs = append(cs, Candidate{Kind: kind, Addr: r.endpoint()})
	}
	return cs
}

func (r *reader) stats() []SessionStats {
	n := int(r.u8())
	if n > MaxStats {
		r.fail(ErrBadField)
		return nil
	}
	ss := make([]SessionStats, 0, n)
	for range n {
		st := SessionStats{
			SessionID:    r.u64(),
			State:        SessionState(r.u8()),
			PathKind:     CandidateKind(r.u8()),
			RTTMicros:    r.u32(),
			RTTVarMicros: r.u32(),
			LossPermille: r.u16(),
		}
		if st.State < StateConnecting || st.State > StateDisconnected ||
			st.PathKind > KindPeerReflexive || st.LossPermille > 1000 {
			r.fail(ErrBadField)
		}
		ss = append(ss, st)
	}
	return ss
}

func (r *reader) lobbyID() LobbyID {
	var l LobbyID
	copy(l[:], r.take(LobbyIDLen))
	if r.err == nil && !l.IsZero() && !l.valid() {
		r.fail(ErrBadField)
	}
	return l
}

func (r *reader) zeroPadding() {
	for _, c := range r.take(len(r.b)) {
		if c != 0 {
			r.fail(ErrTrailing)
		}
	}
}
