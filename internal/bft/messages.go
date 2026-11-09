// Package bft implements a PBFT-style consensus engine (Castro & Liskov)
// for n = 3f+1 replicas, plus evidence-based leader exclusion.
//
// Normal case, per sequence number (= Berkeley round):
//
//	primary  --PRE-PREPARE(v, s, digest, payload, sig_primary)--> backups
//	backups  --PREPARE(v, s, digest, signed header)-------------> all
//	all      --COMMIT(v, s, digest)------------------------------> all
//	execute after PRE-PREPARE + 2f matching PREPAREs + 2f+1 matching COMMITs
//
// Authentication: PREPARE/COMMIT are protected by the pairwise AES-GCM
// sessions (MAC-style PBFT). PRE-PREPARE headers, VIEW-CHANGE and NEW-VIEW
// are additionally signed with the identity key because they must be
// transferable: they serve as evidence or certificates for third parties.
// Each PREPARE echoes the primary's signed header, so two backups that got
// different proposals obtain a transferable proof of equivocation.
//
// Leader election / view change:
//
//	primary(v) = v mod n
//
// A view whose primary is in the EXCLUDED set is skipped. A node is
// excluded only on PROVABLE misbehaviour — self-verifying evidence that any
// honest replica can check independently:
//
//	EvBadProposal  : a signed PRE-PREPARE whose payload fails validation
//	EvEquivocation : two signed PRE-PREPARE headers for the same (v, s)
//	EvApp          : application evidence (e.g. a signed Berkeley reading
//	                 with an invalid range proof)
//
// Evidence is gossiped and attached to every VIEW-CHANGE, so all honest
// replicas converge on the same excluded set and therefore on the same next
// primary. Crashed / silent primaries are not provably malicious: they are
// skipped by the ordinary timeout-driven view change.
//
// Simplifications w.r.t. full PBFT (documented for the thesis):
//   - Berkeley rounds are independent, so the log may have gaps: a seq is
//     executed iff it commits and seq > lastExecuted. No checkpoints are
//     needed.
//   - NEW-VIEW re-proposes the highest-view prepared payload per seq taken
//     from the 2f+1 VIEW-CHANGE messages; replicas re-validate it as a
//     normal PRE-PREPARE rather than recomputing the whole set.
package bft

import (
	"crypto/sha256"

	"secure-distributed-system/internal/wire"
)

// Header is the part of a PRE-PREPARE that the primary signs.
type Header struct {
	View    uint64 `cbor:"1,keyasint"`
	Seq     uint64 `cbor:"2,keyasint"`
	Digest  []byte `cbor:"3,keyasint"`
	Primary uint32 `cbor:"4,keyasint"`
}

func (h Header) signedBytes() []byte {
	return append([]byte("pbft-preprepare|"), wire.Marshal(h)...)
}

// SignedHeader is a header plus the primary's identity signature.
type SignedHeader struct {
	Header    Header `cbor:"1,keyasint"`
	Signature []byte `cbor:"2,keyasint"`
}

// PrePrepare carries the proposal payload.
type PrePrepare struct {
	Signed  SignedHeader `cbor:"1,keyasint"`
	Payload []byte       `cbor:"2,keyasint"`
}

// Prepare echoes the primary's signed header (equivocation detection).
type Prepare struct {
	Replica uint32       `cbor:"1,keyasint"`
	Signed  SignedHeader `cbor:"2,keyasint"`
}

// Commit is session-authenticated only.
type Commit struct {
	View    uint64 `cbor:"1,keyasint"`
	Seq     uint64 `cbor:"2,keyasint"`
	Digest  []byte `cbor:"3,keyasint"`
	Replica uint32 `cbor:"4,keyasint"`
}

// Evidence kinds.
const (
	EvBadProposal  uint8 = 1
	EvEquivocation uint8 = 2
	EvApp          uint8 = 3
)

// Evidence is a self-verifying proof that Accused misbehaved.
type Evidence struct {
	Kind    uint8  `cbor:"1,keyasint"`
	Accused uint32 `cbor:"2,keyasint"`
	A       []byte `cbor:"3,keyasint"` // encoded PrePrepare / SignedHeader / app data
	B       []byte `cbor:"4,keyasint,omitempty"`
}

// ViewChange is signed by its sender.
type ViewChange struct {
	NewView      uint64       `cbor:"1,keyasint"`
	Replica      uint32       `cbor:"2,keyasint"`
	LastExecuted uint64       `cbor:"3,keyasint"`
	Prepared     []PrePrepare `cbor:"4,keyasint"` // prepared but not executed
	Evidence     []Evidence   `cbor:"5,keyasint"`
	Signature    []byte       `cbor:"6,keyasint"`
}

func (vc ViewChange) signedBytes() []byte {
	vc.Signature = nil
	return append([]byte("pbft-viewchange|"), wire.Marshal(vc)...)
}

// NewView is signed by the new primary and carries the 2f+1 certificate.
type NewView struct {
	View        uint64       `cbor:"1,keyasint"`
	Primary     uint32       `cbor:"2,keyasint"`
	ViewChanges []ViewChange `cbor:"3,keyasint"`
	ReProposals []PrePrepare `cbor:"4,keyasint"`
	Signature   []byte       `cbor:"5,keyasint"`
}

func (nv NewView) signedBytes() []byte {
	nv.Signature = nil
	return append([]byte("pbft-newview|"), wire.Marshal(nv)...)
}

// Digest of a payload (the PBFT request digest).
func Digest(payload []byte) []byte {
	d := sha256.Sum256(payload)
	return d[:]
}
