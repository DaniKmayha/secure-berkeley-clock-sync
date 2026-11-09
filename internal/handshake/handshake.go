// Package handshake implements the Control Plane: the authenticated hybrid
// session establishment between two nodes.
//
// Message flow (I = initiator, R = responder). The initiator is the node
// that needs the session first; ties are broken by node id (see session).
//
//	I -> R  ClientHello : version, suite, ids, nonce_c, X25519_pub_c
//	R -> I  ServerHello : nonce_s, X25519_pub_s, MLKEM_pub_s (ephemeral),
//	                      session_id, rotation params,
//	                      sig_R( H("SH" || CH || SH\sig) )
//	I -> R  ClientFinish: MLKEM_ciphertext (I encapsulates to MLKEM_pub_s),
//	                      sig_I( H("CF" || CH || SH || CF\sig) )
//	R -> I  ServerFinish: HMAC(k_confirm, "server finished" || TH)
//
// TH (the transcript hash) = SHA-384(CH || SH || CF) over the canonical CBOR
// encodings. It is bound into the key schedule:
//
//	K = HKDF(SS_X25519 || SS_MLKEM, TH || session_id)
//
// Authentication policy: MUTUAL. Both nodes are replicas (Berkeley slaves
// and PBFT backups) whose messages must be attributable, so both sign the
// transcript. This choice is fixed for all experiments.
//
// What each signature covers (the spec asks this to be explicit):
//   - sig_R covers: version, suite, both node ids, nonce_c, X25519_pub_c,
//     nonce_s, X25519_pub_s, MLKEM_pub_s, session_id, rotation params.
//   - sig_I covers all of the above plus sig_R and the ML-KEM ciphertext.
//
// Classical suite (C1/C4): identical flow, no ML-KEM fields, Ed25519 sigs.
//
// Security properties exercised by the tests:
//   - invalid signature           -> handshake fails, no session
//   - tampered/invalid ciphertext -> key confirmation fails, no session
//   - replayed ClientHello        -> fresh nonce_s/session_id: new context
//     that the replayer cannot finish (needs I's signing key)
//   - replayed ClientFinish       -> no pending state for it: rejected
package handshake

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"fmt"
	"time"

	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/crypto/pqc"
	keyschedule "secure-distributed-system/internal/key_schedule"
	"secure-distributed-system/internal/wire"
)

// Suite selects the algorithm profile.
type Suite uint8

const (
	// SuiteClassical = X25519 + Ed25519 + HKDF-SHA384 + AES-256-GCM.
	SuiteClassical Suite = 1
	// SuiteHybrid = X25519 + ML-KEM-768 + ML-DSA-65 + HKDF-SHA384 + AES-256-GCM.
	SuiteHybrid Suite = 2
)

func (s Suite) String() string {
	switch s {
	case SuiteClassical:
		return "X25519+Ed25519+HKDF-SHA384+AES-256-GCM"
	case SuiteHybrid:
		return "X25519+ML-KEM-768+ML-DSA-65+HKDF-SHA384+AES-256-GCM"
	}
	return fmt.Sprintf("Suite(%d)", uint8(s))
}

// SignatureAlgorithm is the identity algorithm a suite requires.
func (s Suite) SignatureAlgorithm() string {
	if s == SuiteHybrid {
		return identity.AlgMLDSA65
	}
	return identity.AlgEd25519
}

// Policy is the session rotation policy carried in ServerHello
// ("expiry/rotation parameters" field). A fresh hybrid re-handshake is
// required after MaxMessages messages or MaxAge, whichever comes first.
type Policy struct {
	MaxMessages uint64 `cbor:"1,keyasint"`
	MaxAgeSec   uint64 `cbor:"2,keyasint"`
}

// ------------------------------------------------------------ messages ---

type ClientHello struct {
	Version  uint16 `cbor:"1,keyasint"`
	Suite    Suite  `cbor:"2,keyasint"`
	ClientID uint32 `cbor:"3,keyasint"`
	ServerID uint32 `cbor:"4,keyasint"`
	NonceC   []byte `cbor:"5,keyasint"`
	X25519C  []byte `cbor:"6,keyasint"`
}

type ServerHello struct {
	NonceS    []byte `cbor:"1,keyasint"`
	X25519S   []byte `cbor:"2,keyasint"`
	MLKEMPubS []byte `cbor:"3,keyasint"` // empty in classical suite
	SessionID []byte `cbor:"4,keyasint"`
	Policy    Policy `cbor:"5,keyasint"`
	Signature []byte `cbor:"6,keyasint"`
}

type ClientFinish struct {
	SessionID  []byte `cbor:"1,keyasint"`
	MLKEMCt    []byte `cbor:"2,keyasint"` // empty in classical suite
	Signature  []byte `cbor:"3,keyasint"`
}

type ServerFinish struct {
	SessionID []byte `cbor:"1,keyasint"`
	Confirm   []byte `cbor:"2,keyasint"`
}

// Result is what a completed handshake hands to the session layer.
type Result struct {
	SessionID      []byte
	Keys           *keyschedule.SessionKeys
	TranscriptHash []byte
	Policy         Policy
	Initiator      bool
	Duration       time.Duration // cold-start latency (measured by the initiator)
	BytesSent      int
	BytesReceived  int
}

// Config holds the static inputs of one handshake.
type Config struct {
	Suite        Suite
	Self, Peer   uint32
	Signer       identity.Signer   // our long-term identity
	PeerVerifier identity.Verifier // peer's pre-provisioned public key
	Policy       Policy            // only used by the responder
}

// Errors (exported so tests can assert on them).
var (
	ErrBadSignature   = errors.New("handshake: invalid transcript signature")
	ErrKeyConfirm     = errors.New("handshake: key confirmation failed")
	ErrUnexpected     = errors.New("handshake: unexpected message")
	ErrSuiteMismatch  = errors.New("handshake: suite / version mismatch")
	ErrWrongIdentity  = errors.New("handshake: identity algorithm does not match suite")
)

const (
	nonceLen     = 32
	sessionIDLen = 16
)

func randBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err) // RNG failure is out of scope (threat model)
	}
	return b
}

// hashParts = SHA-384(label || len||part || len||part ...). Length prefixes
// make the concatenation unambiguous.
func hashParts(label string, parts ...[]byte) []byte {
	h := sha512.New384()
	h.Write([]byte(label))
	for _, p := range parts {
		var l [4]byte
		l[0], l[1], l[2], l[3] = byte(len(p)>>24), byte(len(p)>>16), byte(len(p)>>8), byte(len(p))
		h.Write(l[:])
		h.Write(p)
	}
	return h.Sum(nil)
}

func shWithoutSig(sh ServerHello) []byte { sh.Signature = nil; return wire.Marshal(sh) }
func cfWithoutSig(cf ClientFinish) []byte { cf.Signature = nil; return wire.Marshal(cf) }

func confirmMAC(key, th []byte) []byte {
	m := hmac.New(sha512.New384, key)
	m.Write([]byte("server finished"))
	m.Write(th)
	return m.Sum(nil)
}

func checkConfig(c Config) error {
	if c.Signer == nil || c.PeerVerifier == nil {
		return errors.New("handshake: missing identity keys")
	}
	want := c.Suite.SignatureAlgorithm()
	if c.Signer.Algorithm() != want || c.PeerVerifier.Algorithm() != want {
		return ErrWrongIdentity
	}
	return nil
}

// ============================================================ Initiator ==

// Initiator is the client side state machine.
type Initiator struct {
	cfg     Config
	ch      ClientHello
	chBytes []byte
	x       *classical.X25519KeyPair
	start   time.Time
	sent    int
	recv    int
	// after ServerHello
	sh        ServerHello
	shBytes   []byte
	keys      *keyschedule.SessionKeys
	th        []byte
	sessionID []byte
}

// NewInitiator creates the ClientHello.
func NewInitiator(cfg Config) (*Initiator, *ClientHello, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, nil, err
	}
	x, err := classical.NewX25519()
	if err != nil {
		return nil, nil, err
	}
	in := &Initiator{cfg: cfg, x: x, start: time.Now()}
	in.ch = ClientHello{
		Version: wire.ProtocolVersion, Suite: cfg.Suite,
		ClientID: cfg.Self, ServerID: cfg.Peer,
		NonceC: randBytes(nonceLen), X25519C: x.Public(),
	}
	in.chBytes = wire.Marshal(in.ch)
	in.sent += len(in.chBytes)
	return in, &in.ch, nil
}

// HandleServerHello verifies the responder, encapsulates, derives keys and
// returns the ClientFinish.
func (in *Initiator) HandleServerHello(sh *ServerHello) (*ClientFinish, error) {
	if in.keys != nil {
		return nil, ErrUnexpected
	}
	in.recv += len(wire.Marshal(sh))
	if len(sh.SessionID) != sessionIDLen || len(sh.NonceS) != nonceLen {
		return nil, ErrUnexpected
	}
	if (in.cfg.Suite == SuiteHybrid) != (len(sh.MLKEMPubS) > 0) {
		return nil, ErrSuiteMismatch
	}
	// 1. Authenticate the responder over CH || SH\sig.
	sigInput := hashParts("SH", in.chBytes, shWithoutSig(*sh))
	if !in.cfg.PeerVerifier.Verify(sigInput, sh.Signature) {
		return nil, ErrBadSignature
	}
	// 2. Classical component.
	ssX, err := in.x.SharedSecret(sh.X25519S)
	if err != nil {
		return nil, err
	}
	in.x.Destroy() // ephemeral sk no longer needed (best effort)
	defer keyschedule.Zero(ssX)

	// 3. PQ component: encapsulate to the responder's ephemeral ML-KEM key.
	var ct, ssPQ []byte
	if in.cfg.Suite == SuiteHybrid {
		ct, ssPQ, err = pqc.Encapsulate(sh.MLKEMPubS)
		if err != nil {
			return nil, err
		}
		defer keyschedule.Zero(ssPQ)
	}

	// 4. ClientFinish + our signature over the whole transcript so far.
	in.sh = *sh
	in.shBytes = wire.Marshal(*sh)
	cf := ClientFinish{SessionID: sh.SessionID, MLKEMCt: ct}
	cfSig, err := in.cfg.Signer.Sign(hashParts("CF", in.chBytes, in.shBytes, cfWithoutSig(cf)))
	if err != nil {
		return nil, err
	}
	cf.Signature = cfSig
	cfBytes := wire.Marshal(cf)
	in.sent += len(cfBytes)

	// 5. Key schedule bound to the full transcript and the session id.
	in.th = hashParts("TH", in.chBytes, in.shBytes, cfBytes)
	in.keys, err = keyschedule.Derive(ssX, ssPQ, in.th, sh.SessionID)
	if err != nil {
		return nil, err
	}
	in.sessionID = append([]byte(nil), sh.SessionID...)
	return &cf, nil
}

// HandleServerFinish checks key confirmation; on success the session is live.
func (in *Initiator) HandleServerFinish(sf *ServerFinish) (*Result, error) {
	if in.keys == nil {
		return nil, ErrUnexpected
	}
	in.recv += len(wire.Marshal(sf))
	if !bytes.Equal(sf.SessionID, in.sessionID) {
		return nil, ErrUnexpected
	}
	if !hmac.Equal(sf.Confirm, confirmMAC(in.keys.Confirm, in.th)) {
		in.keys.Destroy()
		return nil, ErrKeyConfirm
	}
	return &Result{
		SessionID: in.sessionID, Keys: in.keys, TranscriptHash: in.th,
		Policy: in.sh.Policy, Initiator: true, Duration: time.Since(in.start),
		BytesSent: in.sent, BytesReceived: in.recv,
	}, nil
}

// ============================================================ Responder ==

// Responder is the server side state machine (one per pending handshake).
type Responder struct {
	cfg     Config
	chBytes []byte
	shBytes []byte
	sh      ServerHello
	x       *classical.X25519KeyPair
	kem     *pqc.MLKEMKeyPair
	ssX     []byte
	done    bool
	start   time.Time
	sent    int
	recv    int
}

// NewResponder handles a ClientHello and produces the signed ServerHello.
func NewResponder(cfg Config, ch *ClientHello) (*Responder, *ServerHello, error) {
	if err := checkConfig(cfg); err != nil {
		return nil, nil, err
	}
	if ch.Version != wire.ProtocolVersion || ch.Suite != cfg.Suite {
		return nil, nil, ErrSuiteMismatch
	}
	if ch.ClientID != cfg.Peer || ch.ServerID != cfg.Self || len(ch.NonceC) != nonceLen {
		return nil, nil, ErrUnexpected
	}
	r := &Responder{cfg: cfg, chBytes: wire.Marshal(ch), start: time.Now()}
	r.recv += len(r.chBytes)

	var err error
	if r.x, err = classical.NewX25519(); err != nil {
		return nil, nil, err
	}
	// Compute SS_X25519 now; the ephemeral X25519 key can then be dropped.
	if r.ssX, err = r.x.SharedSecret(ch.X25519C); err != nil {
		return nil, nil, err
	}
	sh := ServerHello{
		NonceS: randBytes(nonceLen), X25519S: r.x.Public(),
		SessionID: randBytes(sessionIDLen), Policy: cfg.Policy,
	}
	r.x.Destroy()
	if cfg.Suite == SuiteHybrid {
		if r.kem, err = pqc.NewMLKEM(); err != nil {
			return nil, nil, err
		}
		sh.MLKEMPubS = r.kem.Public()
	}
	sig, err := cfg.Signer.Sign(hashParts("SH", r.chBytes, shWithoutSig(sh)))
	if err != nil {
		return nil, nil, err
	}
	sh.Signature = sig
	r.sh = sh
	r.shBytes = wire.Marshal(sh)
	r.sent += len(r.shBytes)
	return r, &sh, nil
}

// SessionID of the pending handshake (used to match ClientFinish).
func (r *Responder) SessionID() []byte { return r.sh.SessionID }

// HandleClientFinish authenticates the initiator, decapsulates, derives the
// keys and returns the key-confirmation message.
func (r *Responder) HandleClientFinish(cf *ClientFinish) (*ServerFinish, *Result, error) {
	if r.done {
		return nil, nil, ErrUnexpected // replayed ClientFinish
	}
	r.done = true // single use, whatever the outcome
	defer keyschedule.Zero(r.ssX)
	if !bytes.Equal(cf.SessionID, r.sh.SessionID) {
		return nil, nil, ErrUnexpected
	}
	cfBytes := wire.Marshal(cf)
	r.recv += len(cfBytes)
	if !r.cfg.PeerVerifier.Verify(hashParts("CF", r.chBytes, r.shBytes, cfWithoutSig(*cf)), cf.Signature) {
		return nil, nil, ErrBadSignature
	}
	var ssPQ []byte
	if r.cfg.Suite == SuiteHybrid {
		var err error
		ssPQ, err = r.kem.Decapsulate(cf.MLKEMCt)
		r.kem.Destroy() // ephemeral decapsulation key: destroy right away
		if err != nil {
			return nil, nil, err
		}
		defer keyschedule.Zero(ssPQ)
	}
	th := hashParts("TH", r.chBytes, r.shBytes, cfBytes)
	keys, err := keyschedule.Derive(r.ssX, ssPQ, th, r.sh.SessionID)
	if err != nil {
		return nil, nil, err
	}
	sf := &ServerFinish{SessionID: r.sh.SessionID, Confirm: confirmMAC(keys.Confirm, th)}
	r.sent += len(wire.Marshal(sf))
	return sf, &Result{
		SessionID: r.sh.SessionID, Keys: keys, TranscriptHash: th, Policy: r.sh.Policy,
		Initiator: false, Duration: time.Since(r.start),
		BytesSent: r.sent, BytesReceived: r.recv,
	}, nil
}
