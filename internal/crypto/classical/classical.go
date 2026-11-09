// Package classical wraps the classical primitives used by the baseline
// configurations (C1, C4) and the classical half of the hybrid handshake:
//   - X25519 ephemeral Diffie-Hellman (Go standard library crypto/ecdh)
//   - Ed25519 identity signatures     (Go standard library crypto/ed25519)
package classical

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"

	"secure-distributed-system/internal/crypto/identity"
)

// ---------------------------------------------------------------- X25519 --

// X25519KeyPair is an *ephemeral* key pair: created per handshake and dropped
// immediately after the shared secret has been derived.
type X25519KeyPair struct {
	priv *ecdh.PrivateKey
}

// NewX25519 generates a fresh ephemeral key pair.
func NewX25519() (*X25519KeyPair, error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &X25519KeyPair{priv: k}, nil
}

// Public returns the 32-byte public value that goes into the hello message.
func (k *X25519KeyPair) Public() []byte { return k.priv.PublicKey().Bytes() }

// SharedSecret computes SS_X25519 with the peer's public value. It rejects
// low-order points (crypto/ecdh returns an error for the all-zero output).
func (k *X25519KeyPair) SharedSecret(peerPub []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, fmt.Errorf("x25519: key already destroyed")
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("x25519: bad peer public key: %w", err)
	}
	return k.priv.ECDH(pub)
}

// Destroy drops the reference to the private scalar. Go gives no way to
// overwrite the memory held inside crypto/ecdh, so this is *best effort*
// zeroization (spec §5: "no absolute guarantee of secure memory erasure").
func (k *X25519KeyPair) Destroy() { k.priv = nil }

// --------------------------------------------------------------- Ed25519 --

// Ed25519Signer is the classical long-term identity.
type Ed25519Signer struct{ priv ed25519.PrivateKey }

// Ed25519Verifier is the matching public key.
type Ed25519Verifier struct{ pub ed25519.PublicKey }

// GenerateEd25519 creates a new identity key.
func GenerateEd25519() (*Ed25519Signer, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519Signer{priv: priv}, nil
}

// ParseEd25519Private loads a private key produced by MarshalPrivate.
func ParseEd25519Private(b []byte) (*Ed25519Signer, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ed25519: bad private key length %d", len(b))
	}
	return &Ed25519Signer{priv: ed25519.PrivateKey(append([]byte(nil), b...))}, nil
}

// ParseEd25519Public loads a public key.
func ParseEd25519Public(b []byte) (*Ed25519Verifier, error) {
	if len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ed25519: bad public key length %d", len(b))
	}
	return &Ed25519Verifier{pub: ed25519.PublicKey(append([]byte(nil), b...))}, nil
}

func (s *Ed25519Signer) Sign(msg []byte) ([]byte, error) { return ed25519.Sign(s.priv, msg), nil }
func (s *Ed25519Signer) Public() identity.Verifier {
	return &Ed25519Verifier{pub: s.priv.Public().(ed25519.PublicKey)}
}
func (s *Ed25519Signer) Algorithm() string      { return identity.AlgEd25519 }
func (s *Ed25519Signer) MarshalPrivate() []byte { return append([]byte(nil), s.priv...) }

func (v *Ed25519Verifier) Verify(msg, sig []byte) bool { return ed25519.Verify(v.pub, msg, sig) }
func (v *Ed25519Verifier) Bytes() []byte               { return append([]byte(nil), v.pub...) }
func (v *Ed25519Verifier) Algorithm() string           { return identity.AlgEd25519 }
