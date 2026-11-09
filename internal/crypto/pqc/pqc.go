// Package pqc wraps the post-quantum primitives from Cloudflare CIRCL:
//   - ML-KEM-768 (FIPS 203) : the PQ half of the hybrid key establishment
//   - ML-DSA-65  (FIPS 204) : PQ identity signatures over the transcript
//
// CIRCL is suitable for research / experimental deployment; it is not
// presented as production assurance (Study Guide §13).
package pqc

import (
	"crypto/rand"
	"fmt"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"secure-distributed-system/internal/crypto/identity"
)

// Sizes, re-exported so the experiments can report them (FIPS 203/204 final).
const (
	MLKEMPublicKeySize  = mlkem768.PublicKeySize  // 1,184 B
	MLKEMCiphertextSize = mlkem768.CiphertextSize // 1,088 B
	MLDSAPublicKeySize  = mldsa65.PublicKeySize   // 1,952 B
	MLDSASignatureSize  = mldsa65.SignatureSize   // 3,309 B
)

// --------------------------------------------------------------- ML-KEM ---

var kemScheme kem.Scheme = mlkem768.Scheme()

// MLKEMKeyPair is the responder's *ephemeral* decapsulation key, generated
// per handshake and destroyed right after decapsulation.
type MLKEMKeyPair struct {
	pub  kem.PublicKey
	priv kem.PrivateKey
}

// NewMLKEM generates a fresh ephemeral ML-KEM-768 key pair.
func NewMLKEM() (*MLKEMKeyPair, error) {
	pk, sk, err := kemScheme.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &MLKEMKeyPair{pub: pk, priv: sk}, nil
}

// Public returns the packed encapsulation key (goes into ServerHello).
func (k *MLKEMKeyPair) Public() []byte {
	b, _ := k.pub.MarshalBinary()
	return b
}

// Decapsulate recovers SS_MLKEM from the initiator's ciphertext.
//
// ML-KEM uses *implicit rejection*: a malformed-but-correctly-sized
// ciphertext does not return an error, it returns a pseudo-random secret.
// The handshake detects this through key confirmation (ServerFinish), so an
// invalid ciphertext still results in "handshake fails" as required by the
// security test matrix.
func (k *MLKEMKeyPair) Decapsulate(ct []byte) ([]byte, error) {
	if k.priv == nil {
		return nil, fmt.Errorf("mlkem: key already destroyed")
	}
	if len(ct) != MLKEMCiphertextSize {
		return nil, fmt.Errorf("mlkem: bad ciphertext length %d", len(ct))
	}
	return kemScheme.Decapsulate(k.priv, ct)
}

// Destroy drops the decapsulation key (best-effort zeroization).
func (k *MLKEMKeyPair) Destroy() { k.priv = nil }

// Encapsulate is run by the initiator against the responder's ephemeral key.
// It returns (ciphertext, SS_MLKEM).
func Encapsulate(peerPub []byte) (ct, ss []byte, err error) {
	if len(peerPub) != MLKEMPublicKeySize {
		return nil, nil, fmt.Errorf("mlkem: bad public key length %d", len(peerPub))
	}
	pk, err := kemScheme.UnmarshalBinaryPublicKey(peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("mlkem: %w", err)
	}
	return kemScheme.Encapsulate(pk)
}

// --------------------------------------------------------------- ML-DSA ---

// MLDSASigner is the PQ long-term identity.
type MLDSASigner struct {
	priv *mldsa65.PrivateKey
	pub  *mldsa65.PublicKey
}

// MLDSAVerifier is the matching public key.
type MLDSAVerifier struct{ pub *mldsa65.PublicKey }

// GenerateMLDSA creates a new ML-DSA-65 identity key.
func GenerateMLDSA() (*MLDSASigner, error) {
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &MLDSASigner{priv: sk, pub: pk}, nil
}

// ParseMLDSAPrivate loads a private key produced by MarshalPrivate.
func ParseMLDSAPrivate(b []byte) (*MLDSASigner, error) {
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("mldsa: %w", err)
	}
	pk := sk.Public().(*mldsa65.PublicKey)
	return &MLDSASigner{priv: &sk, pub: pk}, nil
}

// ParseMLDSAPublic loads a public key.
func ParseMLDSAPublic(b []byte) (*MLDSAVerifier, error) {
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(b); err != nil {
		return nil, fmt.Errorf("mldsa: %w", err)
	}
	return &MLDSAVerifier{pub: &pk}, nil
}

// Sign produces a hedged (randomized) ML-DSA-65 signature with our context string.
func (s *MLDSASigner) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa65.SignatureSize)
	if err := mldsa65.SignTo(s.priv, msg, identity.SignContext(), true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}
func (s *MLDSASigner) Public() identity.Verifier { return &MLDSAVerifier{pub: s.pub} }
func (s *MLDSASigner) Algorithm() string         { return identity.AlgMLDSA65 }
func (s *MLDSASigner) MarshalPrivate() []byte {
	b, _ := s.priv.MarshalBinary()
	return b
}

func (v *MLDSAVerifier) Verify(msg, sig []byte) bool {
	if len(sig) != mldsa65.SignatureSize {
		return false
	}
	return mldsa65.Verify(v.pub, msg, identity.SignContext(), sig)
}
func (v *MLDSAVerifier) Bytes() []byte     { return v.pub.Bytes() }
func (v *MLDSAVerifier) Algorithm() string { return identity.AlgMLDSA65 }
