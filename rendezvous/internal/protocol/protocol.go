// Package protocol implements the knockknock wire format described in
// docs/protocol.md: UDP packets with an authenticated header, and
// length-prefixed frames on the TLS signalling connection.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"

	"knockknock/rendezvous/internal/auth"
)

const (
	Version       byte = 3
	HeaderLen          = 32
	MaxCandidates      = 8
	MaxDataLen         = 1168
	MaxStats           = 16
	// MaxFrameLen bounds a signalling frame's type byte plus body.
	MaxFrameLen = 4096
	// RTTUnknown marks an RTT that has not been measured yet.
	RTTUnknown = ^uint32(0)
)

var magic = [2]byte{'K', 'K'}

type Type byte

const (
	TypeRegister   Type = 0x01 // frame, C→S
	TypeRegistered Type = 0x02 // frame, S→C
	TypeJoin       Type = 0x03 // frame, C→S
	TypePeerInfo   Type = 0x04 // frame, S→C
	TypeError      Type = 0x05 // frame, S→C
	TypeClose      Type = 0x06 // frame C→S (leave) and packet P↔P (end session)
	TypeStats      Type = 0x07 // frame, C→S
	TypeBind       Type = 0x08 // packet, C→S
	TypeBound      Type = 0x09 // frame, S→C
	TypeCheck      Type = 0x10 // packet, P↔P
	TypeCheckAck   Type = 0x11 // packet, P↔P
	TypePing       Type = 0x12 // frame (heartbeat) and packet (path RTT)
	TypePong       Type = 0x13 // frame and packet
	TypeData       Type = 0x20 // packet, P↔P
)

// Which message types each transport carries.
var (
	packetTypes = map[Type]bool{TypeBind: true, TypeClose: true, TypeCheck: true, TypeCheckAck: true, TypePing: true, TypePong: true, TypeData: true}
	frameTypes  = map[Type]bool{TypeRegister: true, TypeRegistered: true, TypeJoin: true, TypePeerInfo: true, TypeError: true, TypeClose: true, TypeStats: true, TypeBound: true, TypePing: true, TypePong: true}
)

type ErrorCode byte

const (
	ErrBadRequest    ErrorCode = 1
	ErrLobbyNotFound ErrorCode = 2
	ErrLobbyFull     ErrorCode = 3
	ErrRateLimited   ErrorCode = 4
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

// SessionStats is one entry of a STATS report: the reporter's view of the
// path to one peer.
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

const (
	flagHost     = 1
	flagResume   = 2
	flagNominate = 1
)

var (
	ErrShort       = errors.New("protocol: message too short")
	ErrBadMagic    = errors.New("protocol: bad magic")
	ErrBadVersion  = errors.New("protocol: unsupported version")
	ErrUnknownType = errors.New("protocol: unknown message type")
	ErrBadField    = errors.New("protocol: invalid field")
	ErrTrailing    = errors.New("protocol: trailing bytes")
)

// Message is the payload of a packet or frame.
type Message interface {
	Type() Type
}

type Register struct {
	Host       bool
	Candidates []Candidate
	// Resume, when ResumeID is non-zero, asks to take back an earlier
	// registration (its lobby and sessions) after a lost connection. The
	// secret is safe to send: signalling runs over TLS.
	ResumeID     uint64
	ResumeSecret auth.Key
}

type Registered struct {
	ClientID uint64
	Secret   auth.Key
	Lobby    LobbyID // zero unless the client registered as host
	// BindSecs is how often the client should refresh its UDP binding.
	BindSecs uint16
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
	Code ErrorCode
}

type Close struct {
	Reason byte
}

// Stats reports sessions' path quality. It is never answered.
type Stats struct {
	Sessions []SessionStats
}

// Bind is sent over UDP from the client's game socket so the server can
// observe its public endpoint. It is never answered over UDP.
type Bind struct{}

// Bound tells the client the public endpoint its BIND came from.
type Bound struct {
	Observed netip.AddrPort
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
func (*Bind) Type() Type       { return TypeBind }
func (*Bound) Type() Type      { return TypeBound }
func (*Ping) Type() Type       { return TypePing }
func (*Pong) Type() Type       { return TypePong }
func (*Check) Type() Type      { return TypeCheck }
func (*CheckAck) Type() Type   { return TypeCheckAck }
func (*Data) Type() Type       { return TypeData }

// ---- UDP packets ------------------------------------------------------------

// Packet is a decoded UDP header plus message. The auth tag is checked with
// Verify against the raw bytes.
type Packet struct {
	ID  uint64
	Seq uint32
	Msg Message
}

// Seal encodes p, appends it to b, and fills in the MAC.
func Seal(b []byte, p Packet, key auth.Key, dir auth.Dir) ([]byte, error) {
	if !packetTypes[p.Msg.Type()] {
		return nil, fmt.Errorf("%w: %T is not sent over UDP", ErrUnknownType, p.Msg)
	}
	start := len(b)
	b = append(b, magic[0], magic[1], Version, byte(p.Msg.Type()))
	b = binary.BigEndian.AppendUint64(b, p.ID)
	b = binary.BigEndian.AppendUint32(b, p.Seq)
	b = append(b, make([]byte, auth.TagLen)...)

	b, err := appendPayload(b, p.Msg)
	if err != nil {
		return nil, err
	}
	pkt := b[start:]
	tag := auth.MAC(key, dir, pkt[:16], pkt[HeaderLen:])
	copy(pkt[16:HeaderLen], tag[:])
	return b, nil
}

// Verify reports whether pkt (a whole packet) carries a valid MAC.
func Verify(pkt []byte, key auth.Key, dir auth.Dir) bool {
	if len(pkt) < HeaderLen {
		return false
	}
	return auth.Verify(key, dir, pkt[16:HeaderLen], pkt[:16], pkt[HeaderLen:])
}

// Decode parses a UDP packet. It does not verify the MAC.
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
	ty := Type(b[3])
	if !packetTypes[ty] {
		return Packet{}, ErrUnknownType
	}
	msg, err := decodePayload(ty, b[HeaderLen:])
	if err != nil {
		return Packet{}, err
	}
	return Packet{
		ID:  binary.BigEndian.Uint64(b[4:12]),
		Seq: binary.BigEndian.Uint32(b[12:16]),
		Msg: msg,
	}, nil
}

// ---- Signalling frames --------------------------------------------------------

// AppendFrame encodes m as a signalling frame: len u16, type u8, body.
func AppendFrame(b []byte, m Message) ([]byte, error) {
	if !frameTypes[m.Type()] {
		return nil, fmt.Errorf("%w: %T is not a signalling message", ErrUnknownType, m)
	}
	start := len(b)
	b = append(b, 0, 0, byte(m.Type()))
	b, err := appendPayload(b, m)
	if err != nil {
		return nil, err
	}
	n := len(b) - start - 2
	if n > MaxFrameLen {
		return nil, fmt.Errorf("%w: frame too long", ErrBadField)
	}
	binary.BigEndian.PutUint16(b[start:], uint16(n))
	return b, nil
}

// ReadFrame reads and decodes one signalling frame.
func ReadFrame(r io.Reader) (Message, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > MaxFrameLen {
		return nil, fmt.Errorf("%w: frame length %d", ErrBadField, n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return DecodeFrame(body)
}

// DecodeFrame decodes a frame's type byte and body (without the length).
func DecodeFrame(b []byte) (Message, error) {
	if len(b) == 0 {
		return nil, ErrShort
	}
	ty := Type(b[0])
	if !frameTypes[ty] {
		return nil, ErrUnknownType
	}
	return decodePayload(ty, b[1:])
}

// ---- Payloads -------------------------------------------------------------

func appendPayload(b []byte, m Message) ([]byte, error) {
	var err error
	switch m := m.(type) {
	case *Register:
		b = append(b, boolFlag(m.Host, flagHost)|boolFlag(m.ResumeID != 0, flagResume))
		if b, err = appendCandidates(b, m.Candidates); err != nil {
			return nil, err
		}
		if m.ResumeID != 0 {
			b = binary.BigEndian.AppendUint64(b, m.ResumeID)
			b = append(b, m.ResumeSecret[:]...)
		}
	case *Registered:
		b = binary.BigEndian.AppendUint64(b, m.ClientID)
		b = append(b, m.Secret[:]...)
		b = append(b, m.Lobby[:]...)
		b = binary.BigEndian.AppendUint16(b, m.BindSecs)
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
	case *Bind:
	case *Bound:
		b = appendEndpoint(b, m.Observed)
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

func decodePayload(ty Type, payload []byte) (Message, error) {
	r := reader{b: payload}
	var m Message
	switch ty {
	case TypeRegister:
		flags := r.u8()
		reg := &Register{Host: flags&flagHost != 0, Candidates: r.candidates()}
		if flags&flagResume != 0 {
			reg.ResumeID = r.u64()
			copy(reg.ResumeSecret[:], r.take(16))
			if r.err == nil && reg.ResumeID == 0 {
				r.err = ErrBadField
			}
		}
		m = reg
	case TypeRegistered:
		reg := &Registered{ClientID: r.u64()}
		copy(reg.Secret[:], r.take(16))
		reg.Lobby = r.lobbyID()
		reg.BindSecs = r.u16()
		m = reg
	case TypeJoin:
		j := &Join{Lobby: r.lobbyID()}
		if r.err == nil && j.Lobby.IsZero() {
			r.err = ErrBadField
		}
		m = j
	case TypePeerInfo:
		pi := &PeerInfo{SessionID: r.u64(), Role: Role(r.u8())}
		if r.err == nil && pi.Role != RoleControlling && pi.Role != RoleControlled {
			r.err = ErrBadField
		}
		copy(pi.Key[:], r.take(16))
		pi.Candidates = r.candidates()
		m = pi
	case TypeError:
		m = &Error{Code: ErrorCode(r.u8())}
	case TypeClose:
		m = &Close{Reason: r.u8()}
	case TypeStats:
		m = &Stats{Sessions: r.stats()}
	case TypeBind:
		m = &Bind{}
	case TypeBound:
		m = &Bound{Observed: r.endpoint()}
	case TypePing:
		m = &Ping{ID: r.u32()}
	case TypePong:
		m = &Pong{ID: r.u32()}
	case TypeCheck:
		m = &Check{TxID: r.u64(), Nominate: r.u8()&flagNominate != 0}
	case TypeCheckAck:
		m = &CheckAck{TxID: r.u64(), Nominate: r.u8()&flagNominate != 0, Observed: r.endpoint()}
	case TypeData:
		if len(payload) > MaxDataLen {
			return nil, ErrBadField
		}
		m = &Data{Payload: append([]byte(nil), r.take(len(payload))...)}
	default:
		return nil, ErrUnknownType
	}
	if r.err != nil {
		return nil, r.err
	}
	if len(r.b) != 0 {
		return nil, ErrTrailing
	}
	return m, nil
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
