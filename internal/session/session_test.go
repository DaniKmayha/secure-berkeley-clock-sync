package session

import (
	"errors"
	"testing"

	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/wire"
)

// pair wires two managers together through an in-memory "wire" that the
// test can intercept, acting as the network adversary.
type pair struct {
	a, b    *Manager
	inflight []wire.Envelope
	log      []wire.Envelope // every frame ever sent (for replays)
}

func newPair(t *testing.T, policy handshake.Policy) *pair {
	ka, _ := classical.GenerateEd25519()
	kb, _ := classical.GenerateEd25519()
	p := &pair{}
	send := func(e wire.Envelope) { p.inflight = append(p.inflight, e); p.log = append(p.log, e) }
	p.a = NewManager(Config{Self: 0, Suite: handshake.SuiteClassical, Signer: ka,
		Peers: map[uint32]identity.Verifier{1: kb.Public()}, Policy: policy, Send: send})
	p.b = NewManager(Config{Self: 1, Suite: handshake.SuiteClassical, Signer: kb,
		Peers: map[uint32]identity.Verifier{0: ka.Public()}, Policy: policy, Send: send})
	return p
}

type delivered struct {
	to      uint32
	t       wire.AppType
	payload string
}

// pump delivers frames until quiet and returns application messages.
func (p *pair) pump(t *testing.T) []delivered {
	var out []delivered
	for len(p.inflight) > 0 {
		e := p.inflight[0]
		p.inflight = p.inflight[1:]
		m := p.a
		if e.To == 1 {
			m = p.b
		}
		at, pl, ok, err := m.Handle(e)
		if err != nil {
			t.Logf("rejected %v: %v", e.Type, err)
			continue
		}
		if ok {
			out = append(out, delivered{e.To, at, string(pl)})
		}
	}
	return out
}

func TestSendQueuesUntilHandshakeAndDelivers(t *testing.T) {
	p := newPair(t, handshake.Policy{})
	p.a.Send(1, wire.AppPoll, []byte("hello"))
	p.b.Send(0, wire.AppTimeReq, []byte("hi back"))
	got := p.pump(t)
	if len(got) != 2 {
		t.Fatalf("expected 2 deliveries, got %+v", got)
	}
}

func TestReplayedDataFrameRejected(t *testing.T) {
	p := newPair(t, handshake.Policy{})
	p.a.Send(1, wire.AppPoll, []byte("round 1"))
	p.pump(t)
	var data wire.Envelope
	for _, e := range p.log {
		if e.Type == wire.FrameData {
			data = e
		}
	}
	_, _, _, err := p.b.Handle(data)
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("replay not rejected: %v", err)
	}
	if p.b.Stats.RejectedReplay.Load() != 1 {
		t.Fatal("replay counter not incremented")
	}
}

func TestModifiedCiphertextAndAADRejected(t *testing.T) {
	p := newPair(t, handshake.Policy{})
	p.a.Send(1, wire.AppPoll, []byte("x")) // establishes the session
	p.pump(t)

	// 1) flip a ciphertext bit
	p.a.Send(1, wire.AppPoll, []byte("payload"))
	e := p.inflight[0]
	p.inflight = nil
	var df wire.DataFrame
	_ = wire.Unmarshal(e.Body, &df)
	df.Ciphertext[0] ^= 1
	e.Body = wire.Marshal(df)
	if _, _, _, err := p.b.Handle(e); !errors.Is(err, ErrAEAD) {
		t.Fatalf("tampered ciphertext: %v", err)
	}

	// 2) relabel the message type (bound through AAD); same seq is still expected
	df.Ciphertext[0] ^= 1
	df.AppType = wire.AppAdjust
	e.Body = wire.Marshal(df)
	if _, _, _, err := p.b.Handle(e); !errors.Is(err, ErrAEAD) {
		t.Fatalf("relabelled message type: %v", err)
	}

	// 3) the untouched frame still verifies (counter not desynchronised)
	df.AppType = wire.AppPoll
	e.Body = wire.Marshal(df)
	if _, pl, ok, err := p.b.Handle(e); err != nil || !ok || string(pl) != "payload" {
		t.Fatalf("original frame rejected after forgeries: %v", err)
	}
}

func TestOutOfOrderRejected(t *testing.T) {
	p := newPair(t, handshake.Policy{})
	p.a.Send(1, wire.AppPoll, []byte("x"))
	p.pump(t)
	p.a.Send(1, wire.AppPoll, []byte("1"))
	p.a.Send(1, wire.AppPoll, []byte("2"))
	first, second := p.inflight[0], p.inflight[1]
	p.inflight = nil
	if _, _, _, err := p.b.Handle(second); !errors.Is(err, ErrReplay) {
		t.Fatalf("out-of-order frame accepted: %v", err)
	}
	if _, _, ok, err := p.b.Handle(first); err != nil || !ok {
		t.Fatalf("in-order frame rejected: %v", err)
	}
}

func TestRotationAfterNMessages(t *testing.T) {
	p := newPair(t, handshake.Policy{MaxMessages: 3})
	for i := 0; i < 10; i++ {
		p.a.Send(1, wire.AppPoll, []byte{byte(i)})
		p.pump(t)
	}
	hs := p.a.Stats.HandshakesCompleted.Load()
	if hs < 3 {
		t.Fatalf("expected re-handshakes every 3 messages, got %d handshakes", hs)
	}
	t.Logf("10 messages, policy N=3 -> %d handshakes", hs)
}

func TestRekeyRetiresSession(t *testing.T) {
	p := newPair(t, handshake.Policy{})
	p.a.Send(1, wire.AppPoll, []byte("x"))
	p.pump(t)
	before := p.a.Stats.HandshakesCompleted.Load()
	p.a.Rekey(1)
	p.a.Send(1, wire.AppPoll, []byte("after leader change"))
	got := p.pump(t)
	if p.a.Stats.HandshakesCompleted.Load() != before+1 || len(got) != 1 {
		t.Fatalf("rekey did not run a fresh handshake before sending (got %v)", got)
	}
}
