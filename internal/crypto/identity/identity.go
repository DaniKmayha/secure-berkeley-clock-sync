// Package identity defines the long-term node identity used for
// authentication: in the handshake transcript, on Berkeley readings and on
// the few PBFT messages that must be transferable as evidence.
//
// Two profiles exist (Architecture & Security Specification v2, §3):
//   - classical baseline : Ed25519
//   - PQ mode            : ML-DSA-65 (FIPS 204; pk 1,952 B, signature 3,309 B)
//
// Long-term keys are pre-provisioned (no PKI): every node knows the public
// key of every other node from configuration.
package identity

// Algorithm names used in configs, the handshake suite and the results.
const (
	AlgEd25519  = "Ed25519"
	AlgMLDSA65  = "ML-DSA-65"
	signContext = "sds-berkeley-v2" // ML-DSA context string (domain separation)
)

// SignContext is the ML-DSA "ctx" string (FIPS 204 §5.2). Ed25519 has no
// context, so for uniformity callers also prefix messages with a label.
func SignContext() []byte { return []byte(signContext) }

// Signer is a long-term private identity key.
type Signer interface {
	Sign(msg []byte) ([]byte, error)
	Public() Verifier
	Algorithm() string
	// MarshalPrivate exports the private key (keygen tool only).
	MarshalPrivate() []byte
}

// Verifier is the matching public key.
type Verifier interface {
	Verify(msg, sig []byte) bool
	Bytes() []byte
	Algorithm() string
}
