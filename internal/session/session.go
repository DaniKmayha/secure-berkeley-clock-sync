// Package session manages the pairwise secure sessions of one node: it runs
// handshakes on demand (Control Plane) and seals/opens every application
// message with AES-256-GCM (Data Plane).
//
// Per-message rules (spec §4):
//   - AAD = protocol_version || session_id || seq_no || transaction_id || message_type
//   - nonce derived from seq_no (see package symmetric) -> unique per key
//   - receiver rejects: unknown/expired session, invalid AEAD, duplicate
//     tx_id, and any seq_no that is not exactly last+1 (core sequential mode;
//     the transport is FIFO per link, like TCP)
//
// Rotation: a fresh hybrid re-handshake after MaxMessages sent messages or
// MaxAge, and on demand (leader change). The previous session is kept for
// receiving only, so messages already in flight are not lost.
//
// The Manager is NOT goroutine-safe: it is owned by the node event loop.
package session

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/crypto/symmetric"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/wire"
)

// Rejection reasons (counted for the security experiments).
var (
	ErrUnknownSession = errors.New("session: unknown or expired session")
	ErrReplay         = errors.New("session: replayed / out-of-order sequence number")
	ErrDuplicateTx    = errors.New("session: duplicate transaction id")
	ErrAEAD           = errors.New("session: AEAD authentication failed")
)

// Session is one established, directional-keyed secure channel.
type Session struct {
	ID        []byte
	Peer      uint32
	Initiator bool
	Created   time.Time
	Policy    handshake.Policy

	send, recv *symmetric.AEAD
	sendSeq    uint64 // last sequence number used for sending
	recvSeq    uint64 // last sequence number accepted
	seenTx     map[[16]byte]struct{}
	txOrder    [][16]byte // FIFO for bounding seenTx
	sentCount  uint64
	retired    bool // forced re-key requested: receive-only from now on
}

// expiredForSending reports whether the rotation policy requires a re-key.
func (s *Session) expiredForSending(now time.Time) bool {
	if s.retired {
		return true
	}
	if s.Policy.MaxMessages > 0 && s.sentCount >= s.Policy.MaxMessages {
		return true
	}
	if s.Policy.MaxAgeSec > 0 && now.Sub(s.Created) >= time.Duration(s.Policy.MaxAgeSec)*time.Second {
		return true
	}
	return false
}

const maxSeenTx = 4096

func (s *Session) rememberTx(id [16]byte) {
	s.seenTx[id] = struct{}{}
	s.txOrder = append(s.txOrder, id)
	if len(s.txOrder) > maxSeenTx {
		delete(s.seenTx, s.txOrder[0])
		s.txOrder = s.txOrder[1:]
	}
}

func newSession(peer uint32, r *handshake.Result) (*Session, error) {
	// Initiator sends with c2s, responder sends with s2c.
	sendKey, recvKey := r.Keys.C2S, r.Keys.S2C
	if !r.Initiator {
		sendKey, recvKey = r.Keys.S2C, r.Keys.C2S
	}
	snd, err := symmetric.New(sendKey)
	if err != nil {
		return nil, err
	}
	rcv, err := symmetric.New(recvKey)
	if err != nil {
		return nil, err
	}
	// The AEAD objects hold their own expanded key schedule; wipe our copies.
	r.Keys.Destroy()
	return &Session{
		ID: r.SessionID, Peer: peer, Initiator: r.Initiator, Created: time.Now(),
		Policy: r.Policy, send: snd, recv: rcv, seenTx: map[[16]byte]struct{}{},
	}, nil
}

func aad(sessionID []byte, seq uint64, txID []byte, t wire.AppType) []byte {
	return wire.Marshal([]any{wire.ProtocolVersion, sessionID, seq, txID, uint8(t)})
}

// ------------------------------------------------------------ Manager ---

// Stats are cumulative counters (read by the metrics layer).
type Stats struct {
	HandshakesInitiated atomic.Uint64
	HandshakesCompleted atomic.Uint64
	HandshakesFailed    atomic.Uint64
	MessagesSealed      atomic.Uint64
	MessagesOpened      atomic.Uint64
	RejectedReplay      atomic.Uint64
	RejectedAEAD        atomic.Uint64
	RejectedUnknown     atomic.Uint64
	HandshakeBytes      atomic.Uint64
}

// HandshakeEvent is reported for every completed handshake (cold-start metrics).
type HandshakeEvent struct {
	Peer      uint32
	Initiator bool
	Result    *handshake.Result
}

type outgoing struct {
	t       wire.AppType
	payload []byte
}

type peerState struct {
	current    *Session
	previous   *Session
	initiator  *handshake.Initiator
	initSent   time.Time
	responders map[string]*handshake.Responder
	queue      []outgoing
}

// Config of a Manager.
type Config struct {
	Self             uint32
	Suite            handshake.Suite
	Signer           identity.Signer
	Peers            map[uint32]identity.Verifier
	Policy           handshake.Policy
	HandshakeTimeout time.Duration
	// Send hands a raw envelope to the transport.
	Send func(wire.Envelope)
	// OnHandshake is called after each successful handshake (optional).
	OnHandshake func(HandshakeEvent)
	// Logf for diagnostics (optional).
	Logf func(format string, args ...any)
}

// Manager owns all sessions of one node.
type Manager struct {
	cfg   Config
	peers map[uint32]*peerState
	Stats Stats
}

// NewManager builds a session manager.
func NewManager(cfg Config) *Manager {
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 2 * time.Second
	}
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	m := &Manager{cfg: cfg, peers: map[uint32]*peerState{}}
	for id := range cfg.Peers {
		m.peers[id] = &peerState{responders: map[string]*handshake.Responder{}}
	}
	return m
}

func (m *Manager) hsConfig(peer uint32) handshake.Config {
	return handshake.Config{
		Suite: m.cfg.Suite, Self: m.cfg.Self, Peer: peer,
		Signer: m.cfg.Signer, PeerVerifier: m.cfg.Peers[peer], Policy: m.cfg.Policy,
	}
}

func (m *Manager) emit(to uint32, t wire.FrameType, body []byte) {
	if t != wire.FrameData {
		m.Stats.HandshakeBytes.Add(uint64(len(body)))
	}
	m.cfg.Send(wire.Envelope{From: m.cfg.Self, To: to, Type: t, Body: body})
}

// Connect starts a handshake with peer if no usable session exists.
func (m *Manager) Connect(peer uint32) {
	ps := m.peers[peer]
	if ps == nil || ps.initiator != nil {
		return
	}
	if ps.current != nil && !ps.current.expiredForSending(time.Now()) {
		return
	}
	m.startHandshake(peer)
}

// Rekey forces a fresh hybrid handshake with peer (leader change, or the
// naive per-round mode C2). The current session is retired for sending, so
// every later message waits for — and is protected by — the new session.
// It stays valid for receiving frames that are already in flight.
func (m *Manager) Rekey(peer uint32) {
	ps := m.peers[peer]
	if ps == nil {
		return
	}
	if ps.current != nil {
		ps.current.retired = true
	}
	if ps.initiator == nil {
		m.startHandshake(peer)
	}
}

func (m *Manager) startHandshake(peer uint32) {
	ps := m.peers[peer]
	in, ch, err := handshake.NewInitiator(m.hsConfig(peer))
	if err != nil {
		m.cfg.Logf("handshake init with %d: %v", peer, err)
		return
	}
	ps.initiator, ps.initSent = in, time.Now()
	m.Stats.HandshakesInitiated.Add(1)
	m.emit(peer, wire.FrameClientHello, wire.Marshal(ch))
}

// HasSession reports whether a session usable for sending exists.
func (m *Manager) HasSession(peer uint32) bool {
	ps := m.peers[peer]
	return ps != nil && ps.current != nil && !ps.current.expiredForSending(time.Now())
}

// Send seals payload for peer. Without a usable session the message is
// queued and a handshake is started; the queue is flushed on completion.
func (m *Manager) Send(peer uint32, t wire.AppType, payload []byte) {
	ps := m.peers[peer]
	if ps == nil {
		return
	}
	if ps.current == nil || ps.current.expiredForSending(time.Now()) {
		ps.queue = append(ps.queue, outgoing{t, payload})
		if ps.initiator == nil {
			m.startHandshake(peer)
		}
		return
	}
	m.seal(ps.current, t, payload)
}

func (m *Manager) seal(s *Session, t wire.AppType, payload []byte) {
	s.sendSeq++
	s.sentCount++
	var tx [16]byte
	_, _ = rand.Read(tx[:])
	ct, err := s.send.Seal(s.sendSeq, payload, aad(s.ID, s.sendSeq, tx[:], t))
	if err != nil {
		m.cfg.Logf("seal: %v", err)
		return
	}
	m.Stats.MessagesSealed.Add(1)
	df := wire.DataFrame{SessionID: s.ID, Seq: s.sendSeq, TxID: tx[:], AppType: t, Ciphertext: ct}
	m.emit(s.Peer, wire.FrameData, wire.Marshal(df))
}

func (m *Manager) activate(peer uint32, r *handshake.Result) {
	ps := m.peers[peer]
	s, err := newSession(peer, r)
	if err != nil {
		m.cfg.Logf("activate session with %d: %v", peer, err)
		return
	}
	ps.previous, ps.current = ps.current, s
	m.Stats.HandshakesCompleted.Add(1)
	if m.cfg.OnHandshake != nil {
		m.cfg.OnHandshake(HandshakeEvent{Peer: peer, Initiator: r.Initiator, Result: r})
	}
	q := ps.queue
	ps.queue = nil
	for _, o := range q {
		m.seal(s, o.t, o.payload)
	}
}

// Tick retries handshakes that timed out and starts policy-driven rotation.
func (m *Manager) Tick(now time.Time) {
	for peer, ps := range m.peers {
		if ps.initiator != nil && now.Sub(ps.initSent) > m.cfg.HandshakeTimeout {
			ps.initiator = nil
			m.Stats.HandshakesFailed.Add(1)
			if len(ps.queue) > 0 || ps.current != nil {
				m.startHandshake(peer)
			}
		}
		// Proactive rotation: whichever side notices first initiates.
		if ps.initiator == nil && ps.current != nil && ps.current.expiredForSending(now) && len(ps.queue) > 0 {
			m.startHandshake(peer)
		}
	}
}

// Handle processes an incoming envelope. For Data frames it returns the
// decrypted application message (ok=true). Handshake frames are consumed.
func (m *Manager) Handle(env wire.Envelope) (t wire.AppType, payload []byte, ok bool, err error) {
	ps := m.peers[env.From]
	if ps == nil || env.To != m.cfg.Self {
		return 0, nil, false, fmt.Errorf("session: frame from unknown node %d", env.From)
	}
	switch env.Type {
	case wire.FrameClientHello:
		var ch handshake.ClientHello
		if err := wire.Unmarshal(env.Body, &ch); err != nil {
			return 0, nil, false, err
		}
		// Simultaneous open: both sides initiated. The lower id keeps its
		// own attempt; the higher id abandons its own and responds.
		if ps.initiator != nil && m.cfg.Self < env.From {
			return 0, nil, false, nil
		}
		ps.initiator = nil
		r, sh, err := handshake.NewResponder(m.hsConfig(env.From), &ch)
		if err != nil {
			m.Stats.HandshakesFailed.Add(1)
			return 0, nil, false, err
		}
		if len(ps.responders) > 8 { // bound state created by unauthenticated hellos
			ps.responders = map[string]*handshake.Responder{}
		}
		ps.responders[string(r.SessionID())] = r
		m.emit(env.From, wire.FrameServerHello, wire.Marshal(sh))
		return 0, nil, false, nil

	case wire.FrameServerHello:
		var sh handshake.ServerHello
		if err := wire.Unmarshal(env.Body, &sh); err != nil {
			return 0, nil, false, err
		}
		if ps.initiator == nil {
			return 0, nil, false, handshake.ErrUnexpected
		}
		cf, err := ps.initiator.HandleServerHello(&sh)
		if err != nil {
			ps.initiator = nil
			m.Stats.HandshakesFailed.Add(1)
			return 0, nil, false, err
		}
		m.emit(env.From, wire.FrameClientFinish, wire.Marshal(cf))
		return 0, nil, false, nil

	case wire.FrameClientFinish:
		var cf handshake.ClientFinish
		if err := wire.Unmarshal(env.Body, &cf); err != nil {
			return 0, nil, false, err
		}
		r := ps.responders[string(cf.SessionID)]
		if r == nil {
			m.Stats.HandshakesFailed.Add(1)
			return 0, nil, false, handshake.ErrUnexpected // replayed or unknown
		}
		delete(ps.responders, string(cf.SessionID))
		sf, res, err := r.HandleClientFinish(&cf)
		if err != nil {
			m.Stats.HandshakesFailed.Add(1)
			return 0, nil, false, err
		}
		m.emit(env.From, wire.FrameServerFinish, wire.Marshal(sf))
		m.activate(env.From, res)
		return 0, nil, false, nil

	case wire.FrameServerFinish:
		var sf handshake.ServerFinish
		if err := wire.Unmarshal(env.Body, &sf); err != nil {
			return 0, nil, false, err
		}
		if ps.initiator == nil {
			return 0, nil, false, handshake.ErrUnexpected
		}
		res, err := ps.initiator.HandleServerFinish(&sf)
		ps.initiator = nil
		if err != nil {
			m.Stats.HandshakesFailed.Add(1)
			return 0, nil, false, err
		}
		m.activate(env.From, res)
		return 0, nil, false, nil

	case wire.FrameData:
		var df wire.DataFrame
		if err := wire.Unmarshal(env.Body, &df); err != nil {
			return 0, nil, false, err
		}
		pt, err := m.open(ps, &df)
		if err != nil {
			return 0, nil, false, err
		}
		return df.AppType, pt, true, nil
	}
	return 0, nil, false, fmt.Errorf("session: unknown frame type %v", env.Type)
}

func (m *Manager) open(ps *peerState, df *wire.DataFrame) ([]byte, error) {
	var s *Session
	switch {
	case ps.current != nil && bytes.Equal(ps.current.ID, df.SessionID):
		s = ps.current
	case ps.previous != nil && bytes.Equal(ps.previous.ID, df.SessionID):
		s = ps.previous
	default:
		m.Stats.RejectedUnknown.Add(1)
		return nil, ErrUnknownSession
	}
	// Replay / ordering check BEFORE decryption (cheap rejection).
	if df.Seq != s.recvSeq+1 {
		m.Stats.RejectedReplay.Add(1)
		return nil, fmt.Errorf("%w: got %d, expected %d", ErrReplay, df.Seq, s.recvSeq+1)
	}
	if len(df.TxID) != 16 {
		m.Stats.RejectedReplay.Add(1)
		return nil, ErrDuplicateTx
	}
	var tx [16]byte
	copy(tx[:], df.TxID)
	if _, dup := s.seenTx[tx]; dup {
		m.Stats.RejectedReplay.Add(1)
		return nil, ErrDuplicateTx
	}
	pt, err := s.recv.Open(df.Seq, df.Ciphertext, aad(df.SessionID, df.Seq, df.TxID, df.AppType))
	if err != nil {
		m.Stats.RejectedAEAD.Add(1)
		return nil, ErrAEAD
	}
	// Only advance state after successful authentication, so a forged
	// frame cannot desynchronise the counter.
	s.recvSeq = df.Seq
	s.rememberTx(tx)
	m.Stats.MessagesOpened.Add(1)
	return pt, nil
}
