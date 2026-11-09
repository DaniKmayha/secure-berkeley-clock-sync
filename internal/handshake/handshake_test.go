package handshake

import (
	"bytes"
	"errors"
	"testing"

	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/crypto/pqc"
)

func keys(t *testing.T, s Suite) (identity.Signer, identity.Signer) {
	t.Helper()
	gen := func() identity.Signer {
		if s == SuiteHybrid {
			k, err := pqc.GenerateMLDSA()
			if err != nil {
				t.Fatal(err)
			}
			return k
		}
		k, err := classical.GenerateEd25519()
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	return gen(), gen()
}

func configs(s Suite, a, b identity.Signer) (Config, Config) {
	ca := Config{Suite: s, Self: 0, Peer: 1, Signer: a, PeerVerifier: b.Public()}
	cb := Config{Suite: s, Self: 1, Peer: 0, Signer: b, PeerVerifier: a.Public(), Policy: Policy{MaxMessages: 10}}
	return ca, cb
}

func TestHandshakeBothSuites(t *testing.T) {
	for _, s := range []Suite{SuiteClassical, SuiteHybrid} {
		a, b := keys(t, s)
		ca, cb := configs(s, a, b)
		in, ch, err := NewInitiator(ca)
		if err != nil {
			t.Fatal(err)
		}
		resp, sh, err := NewResponder(cb, ch)
		if err != nil {
			t.Fatal(err)
		}
		cf, err := in.HandleServerHello(sh)
		if err != nil {
			t.Fatal(err)
		}
		sf, rr, err := resp.HandleClientFinish(cf)
		if err != nil {
			t.Fatal(err)
		}
		ir, err := in.HandleServerFinish(sf)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(ir.Keys.C2S, rr.Keys.C2S) || !bytes.Equal(ir.Keys.S2C, rr.Keys.S2C) {
			t.Fatalf("%v: keys differ", s)
		}
		if bytes.Equal(ir.Keys.C2S, ir.Keys.S2C) {
			t.Fatalf("%v: directional keys must differ", s)
		}
		t.Logf("%v: %v, initiator sent %d B, received %d B", s, ir.Duration, ir.BytesSent, ir.BytesReceived)
		// Replayed ClientFinish must be rejected.
		if _, _, err := resp.HandleClientFinish(cf); err == nil {
			t.Fatal("replayed ClientFinish accepted")
		}
	}
}

func TestInvalidServerSignature(t *testing.T) {
	a, b := keys(t, SuiteHybrid)
	ca, cb := configs(SuiteHybrid, a, b)
	in, ch, _ := NewInitiator(ca)
	_, sh, _ := NewResponder(cb, ch)
	sh.Signature[5] ^= 1
	if _, err := in.HandleServerHello(sh); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestTamperedServerHelloField(t *testing.T) {
	// A MITM replacing the ephemeral ML-KEM key breaks the signature.
	a, b := keys(t, SuiteHybrid)
	ca, cb := configs(SuiteHybrid, a, b)
	in, ch, _ := NewInitiator(ca)
	_, sh, _ := NewResponder(cb, ch)
	evil, _ := pqc.NewMLKEM()
	sh.MLKEMPubS = evil.Public()
	if _, err := in.HandleServerHello(sh); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestInvalidMLKEMCiphertext(t *testing.T) {
	// A signed-but-wrong ciphertext (buggy/malicious initiator): ML-KEM
	// implicit rejection gives a different secret, so key confirmation fails.
	a, b := keys(t, SuiteHybrid)
	ca, cb := configs(SuiteHybrid, a, b)
	in, ch, _ := NewInitiator(ca)
	resp, sh, _ := NewResponder(cb, ch)
	cf, err := in.HandleServerHello(sh)
	if err != nil {
		t.Fatal(err)
	}
	cf.MLKEMCt[0] ^= 1
	// Re-sign so that the responder accepts the (now wrong) ciphertext.
	cf.Signature = nil
	sig, _ := a.Sign(hashParts("CF", in.chBytes, in.shBytes, cfWithoutSig(*cf)))
	cf.Signature = sig
	sf, _, err := resp.HandleClientFinish(cf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := in.HandleServerFinish(sf); !errors.Is(err, ErrKeyConfirm) {
		t.Fatalf("expected ErrKeyConfirm, got %v", err)
	}
}

func TestTamperedCiphertextByMITM(t *testing.T) {
	a, b := keys(t, SuiteHybrid)
	ca, cb := configs(SuiteHybrid, a, b)
	in, ch, _ := NewInitiator(ca)
	resp, sh, _ := NewResponder(cb, ch)
	cf, _ := in.HandleServerHello(sh)
	cf.MLKEMCt[0] ^= 1 // not re-signed: the client signature covers it
	if _, _, err := resp.HandleClientFinish(cf); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("expected ErrBadSignature, got %v", err)
	}
}

func TestReplayedClientHelloGivesFreshContext(t *testing.T) {
	a, b := keys(t, SuiteClassical)
	ca, cb := configs(SuiteClassical, a, b)
	_, ch, _ := NewInitiator(ca)
	_, sh1, _ := NewResponder(cb, ch)
	_, sh2, _ := NewResponder(cb, ch)
	if bytes.Equal(sh1.SessionID, sh2.SessionID) || bytes.Equal(sh1.NonceS, sh2.NonceS) {
		t.Fatal("replayed ClientHello produced the same session context")
	}
}

func TestSuiteMismatch(t *testing.T) {
	a, b := keys(t, SuiteClassical)
	_, cb := configs(SuiteClassical, a, b)
	ch := &ClientHello{Version: 1, Suite: SuiteClassical, ClientID: 0, ServerID: 1, NonceC: make([]byte, 32), X25519C: make([]byte, 32)}
	if _, _, err := NewResponder(cb, ch); !errors.Is(err, ErrSuiteMismatch) {
		t.Fatalf("expected ErrSuiteMismatch for old version, got %v", err)
	}
}
