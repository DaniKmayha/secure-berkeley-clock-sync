// Package wire defines the on-the-wire framing shared by every node and a
// canonical (deterministic) encoder used for everything that is hashed or
// signed.
//
// We use CBOR with the "Core Deterministic Encoding" rules (RFC 8949 §4.2).
// Deterministic encoding matters because:
//   - the handshake transcript hash must be identical on both sides,
//   - PBFT digests must be identical on every replica,
//   - signatures over readings / proposals must verify everywhere.
//
// CBOR is also compact (raw byte strings, no base64), which keeps the byte
// counts reported in the experiments honest.
package wire

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

// ProtocolVersion is bound into the handshake transcript and into the AEAD
// associated data of every data-plane frame (prevents version ambiguity /
// downgrade inside the prototype).
const ProtocolVersion uint16 = 2

// FrameType distinguishes Control Plane (handshake) frames from Data Plane
// (AEAD-protected) frames.
type FrameType uint8

const (
	FrameClientHello  FrameType = 1
	FrameServerHello  FrameType = 2
	FrameClientFinish FrameType = 3
	FrameServerFinish FrameType = 4
	FrameData         FrameType = 5
)

func (t FrameType) String() string {
	switch t {
	case FrameClientHello:
		return "ClientHello"
	case FrameServerHello:
		return "ServerHello"
	case FrameClientFinish:
		return "ClientFinish"
	case FrameServerFinish:
		return "ServerFinish"
	case FrameData:
		return "Data"
	}
	return fmt.Sprintf("Frame(%d)", uint8(t))
}

// AppType identifies the application message carried inside a Data frame.
// It is also part of the AEAD associated data ("message_type" in the spec),
// so an attacker cannot re-label a ciphertext as a different message type.
type AppType uint8

const (
	// Berkeley clock-synchronisation messages.
	AppPoll     AppType = 10 // master -> slave: "a new round started, give me your offset"
	AppTimeReq  AppType = 11 // slave -> master: Cristian-style time request
	AppTimeResp AppType = 12 // master -> slave: master's clock value
	AppReading  AppType = 13 // slave -> master: signed (committed) offset reading
	AppOpening  AppType = 14 // slave -> master only: private opening of the commitment (ZKP mode)
	AppAdjust   AppType = 15 // master -> slave: "speed up / slow down by X" (classic Berkeley step)

	AppPeerTimeReq  AppType = 16 // slave -> slave witness check
	AppPeerTimeResp AppType = 17

	// PBFT consensus messages.
	AppPrePrepare AppType = 20
	AppPrepare    AppType = 21
	AppCommit     AppType = 22
	AppViewChange AppType = 23
	AppNewView    AppType = 24
	AppEvidence   AppType = 25 // gossip of provable misbehaviour
)

func (t AppType) String() string {
	names := map[AppType]string{
		AppPoll: "Poll", AppTimeReq: "TimeReq", AppTimeResp: "TimeResp",
		AppReading: "Reading", AppOpening: "Opening", AppAdjust: "Adjust",
		AppPeerTimeReq: "PeerTimeReq", AppPeerTimeResp: "PeerTimeResp",
		AppPrePrepare: "PrePrepare", AppPrepare: "Prepare", AppCommit: "Commit",
		AppViewChange: "ViewChange", AppNewView: "NewView", AppEvidence: "Evidence",
	}
	if n, ok := names[t]; ok {
		return n
	}
	return fmt.Sprintf("App(%d)", uint8(t))
}

// Envelope is the outermost frame exchanged by the transport layer.
// From/To are logical node identifiers (0..n-1).
type Envelope struct {
	From uint32    `cbor:"1,keyasint"`
	To   uint32    `cbor:"2,keyasint"`
	Type FrameType `cbor:"3,keyasint"`
	Body []byte    `cbor:"4,keyasint"`
}

// DataFrame is the Data Plane frame. Only Ciphertext is confidential; the
// header fields travel in clear but are authenticated through the AAD.
type DataFrame struct {
	SessionID  []byte  `cbor:"1,keyasint"` // 16 random bytes, fixed by the handshake
	Seq        uint64  `cbor:"2,keyasint"` // monotonic per-session, per-direction counter
	TxID       []byte  `cbor:"3,keyasint"` // 16 random bytes, unique per message (idempotency)
	AppType    AppType `cbor:"4,keyasint"`
	Ciphertext []byte  `cbor:"5,keyasint"` // AES-256-GCM output (ciphertext || tag)
}

var (
	encMode cbor.EncMode
	decMode cbor.DecMode
)

func init() {
	var err error
	encMode, err = cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
	decMode, err = cbor.DecOptions{
		// Reject duplicate map keys: two different decoders must never
		// disagree on what a message means.
		DupMapKey: cbor.DupMapKeyEnforcedAPF,
		// Bound allocations from attacker-controlled input.
		MaxArrayElements: 1 << 16,
		MaxMapPairs:      1 << 16,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes v deterministically.
func Marshal(v any) []byte {
	b, err := encMode.Marshal(v)
	if err != nil {
		// Only happens for unsupported Go types, i.e. a programming error.
		panic(fmt.Sprintf("wire.Marshal(%T): %v", v, err))
	}
	return b
}

// Unmarshal decodes data into v.
func Unmarshal(data []byte, v any) error {
	return decMode.Unmarshal(data, v)
}
