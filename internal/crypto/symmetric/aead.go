// Package symmetric implements the Data Plane protection: AES-256-GCM with a
// strict nonce discipline.
//
// Nonce rule (spec §4): "never use the same key/nonce pair twice".
// Every traffic key is used in exactly ONE direction (c2s or s2c), and the
// 96-bit nonce is derived deterministically from the monotonic sequence
// number of that direction:
//
//	nonce = 0x00000000 || seq_no (64-bit big endian)
//
// Because seq_no strictly increases and is never reset for a given key
// (rotation creates a brand-new key), every nonce is unique per key. The
// sender refuses to seal once the counter would wrap.
package symmetric

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// KeySize is 32 bytes (AES-256).
const KeySize = 32

// ErrNonceExhausted is returned when a key has been used 2^64-1 times.
var ErrNonceExhausted = errors.New("aead: sequence space exhausted, re-key required")

// AEAD is one directional traffic key.
type AEAD struct {
	gcm cipher.AEAD
}

// New builds an AES-256-GCM instance from a 32-byte traffic key.
func New(key []byte) (*AEAD, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("aead: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &AEAD{gcm: gcm}, nil
}

// NonceFromSeq maps a sequence number to its unique 12-byte nonce.
func NonceFromSeq(seq uint64) []byte {
	n := make([]byte, 12)
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

// Seal encrypts and authenticates plaintext; aad is authenticated only.
func (a *AEAD) Seal(seq uint64, plaintext, aad []byte) ([]byte, error) {
	if seq == math.MaxUint64 {
		return nil, ErrNonceExhausted
	}
	return a.gcm.Seal(nil, NonceFromSeq(seq), plaintext, aad), nil
}

// Open verifies and decrypts. Any modification of ciphertext, tag or AAD
// (e.g. a changed seq_no, session_id or message type) makes it fail.
func (a *AEAD) Open(seq uint64, ciphertext, aad []byte) ([]byte, error) {
	pt, err := a.gcm.Open(nil, NonceFromSeq(seq), ciphertext, aad)
	if err != nil {
		return nil, errors.New("aead: authentication failed")
	}
	return pt, nil
}

// Overhead is the tag size (16 bytes), reported in bytes/message metrics.
func (a *AEAD) Overhead() int { return a.gcm.Overhead() }
