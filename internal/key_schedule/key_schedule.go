// Package keyschedule turns the handshake shared secrets into session keys.
//
// Specification (Architecture & Security Specification v2, §3):
//
//	K_session = HKDF(SS_X25519 || SS_MLKEM, transcript_hash || session_id)
//
// Concretely (RFC 5869, HKDF with SHA-384):
//
//	PRK      = HKDF-Extract(salt = transcript_hash || session_id,
//	                        IKM  = SS_X25519 || SS_MLKEM)
//	k_c2s    = HKDF-Expand(PRK, "sds v2 c2s traffic", 32)
//	k_s2c    = HKDF-Expand(PRK, "sds v2 s2c traffic", 32)
//	k_confirm= HKDF-Expand(PRK, "sds v2 key confirm", 32)
//
// Directional keys mean the two directions never share a key, so the
// sequence-number nonces of the two directions can never collide.
//
// In classical mode SS_MLKEM is empty and only SS_X25519 is used.
//
// Concatenating both secrets as IKM is the standard "concatenation combiner"
// (also used by X25519MLKEM768 in RFC 10024): the session key remains secure
// as long as at least ONE of the two components is unbroken, under the
// stated assumptions. This is what is intended to mitigate
// harvest-now-decrypt-later exposure.
package keyschedule

import (
	"crypto/hkdf"
	"crypto/sha512"
	"fmt"
)

// Labels (domain separation between derived keys).
const (
	labelC2S     = "sds v2 c2s traffic"
	labelS2C     = "sds v2 s2c traffic"
	labelConfirm = "sds v2 key confirm"
	keyLen       = 32
)

// SessionKeys are the outputs of the key schedule. They are endpoint-local
// and are NEVER put into PBFT replicated state.
type SessionKeys struct {
	C2S     []byte // initiator -> responder traffic key
	S2C     []byte // responder -> initiator traffic key
	Confirm []byte // key confirmation (ServerFinish MAC)
}

// Derive runs Extract-then-Expand. ssClassical must be non-empty; ssPQ may be
// empty (classical suite).
func Derive(ssClassical, ssPQ, transcriptHash, sessionID []byte) (*SessionKeys, error) {
	if len(ssClassical) == 0 {
		return nil, fmt.Errorf("keyschedule: missing classical shared secret")
	}
	ikm := make([]byte, 0, len(ssClassical)+len(ssPQ))
	ikm = append(ikm, ssClassical...)
	ikm = append(ikm, ssPQ...)
	defer Zero(ikm)

	salt := make([]byte, 0, len(transcriptHash)+len(sessionID))
	salt = append(salt, transcriptHash...)
	salt = append(salt, sessionID...)

	prk, err := hkdf.Extract(sha512.New384, ikm, salt)
	if err != nil {
		return nil, err
	}
	defer Zero(prk)

	expand := func(label string) ([]byte, error) {
		return hkdf.Expand(sha512.New384, prk, label, keyLen)
	}
	k := &SessionKeys{}
	if k.C2S, err = expand(labelC2S); err != nil {
		return nil, err
	}
	if k.S2C, err = expand(labelS2C); err != nil {
		return nil, err
	}
	if k.Confirm, err = expand(labelConfirm); err != nil {
		return nil, err
	}
	return k, nil
}

// Zero overwrites a byte slice. Best effort only: the Go runtime may have
// copied the data elsewhere (GC moves, registers, stack copies), so this is
// NOT a verified secure erasure (spec §7 wording rules).
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// Destroy zeroes all keys (called on session expiry / rotation).
func (k *SessionKeys) Destroy() {
	if k == nil {
		return
	}
	Zero(k.C2S)
	Zero(k.S2C)
	Zero(k.Confirm)
}
