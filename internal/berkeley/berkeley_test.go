package berkeley

import (
	"errors"
	"testing"

	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/zkp"
)

func TestEstimateOffset(t *testing.T) {
	// Slave clock is 1000 µs ahead; symmetric 50 µs one-way delay.
	// Master time 10_000 at the midpoint; slave sends at 10_950, receives at 11_050.
	if d := EstimateOffset(10_950, 11_050, 10_000); d != 1000 {
		t.Fatalf("got %d", d)
	}
}

func TestFTFilterDropsOutlier(t *testing.T) {
	offs := map[uint32]int64{0: 0, 1: 1200, 2: -800, 3: 190_000}
	keep := FTFilter(offs, 50_000, 3)
	if len(keep) != 3 || keep[2] != 2 {
		t.Fatalf("got %v", keep)
	}
	// Fallback: if too few survive, keep all.
	offs = map[uint32]int64{0: 0, 1: 100_000, 2: -100_000, 3: 150_000}
	if keep := FTFilter(offs, 10_000, 3); len(keep) != 4 {
		t.Fatalf("fallback failed: %v", keep)
	}
}

type fixture struct {
	cfg     Config
	signers []identity.Signer
	val     *Validator
	params  *zkp.Params
}

func newFixture(t *testing.T, useZKP bool) *fixture {
	f := &fixture{cfg: Config{N: 4, F: 1, Bound: 200_000, Band: 50_000, ZKP: useZKP}}
	vers := map[uint32]identity.Verifier{}
	for i := 0; i < 4; i++ {
		s, _ := classical.GenerateEd25519()
		f.signers = append(f.signers, s)
		vers[uint32(i)] = s.Public()
	}
	if useZKP {
		p, err := zkp.Setup(4)
		if err != nil {
			t.Fatal(err)
		}
		f.params = p
	}
	f.val = &Validator{Cfg: f.cfg, Verifiers: vers, Params: f.params}
	return f
}

func (f *fixture) proposal(t *testing.T, offsets []int64) *Proposal {
	contribs := map[uint32]*Contribution{}
	for i, d := range offsets {
		r, op, err := MakeReading(f.cfg, f.params, f.signers[i], 5, 0, uint32(i), d, false)
		if err != nil {
			t.Fatal(err)
		}
		c := &Contribution{Reading: *r, Offset: d}
		if op != nil {
			c.E, c.R = op.E, op.R
		}
		contribs[uint32(i)] = c
	}
	p, err := BuildProposal(f.cfg, f.params, 5, 0, 0, contribs)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func testProposalValidation(t *testing.T, useZKP bool) {
	f := newFixture(t, useZKP)
	p := f.proposal(t, []int64{0, 3000, -1000, 180_000})
	if err := f.val.ValidateProposal(p); err != nil {
		t.Fatalf("honest proposal rejected: %v", err)
	}
	if len(p.Included) != 3 {
		t.Fatalf("outlier not filtered: %v", p.Included)
	}
	if p.Mean != FloorMean(map[uint32]int64{0: 0, 1: 3000, 2: -1000}, []uint32{0, 1, 2}, f.cfg.Bound) {
		t.Fatalf("unexpected mean %d", p.Mean)
	}

	// Byzantine master: wrong average.
	bad := *p
	bad.Mean += 50_000
	if err := f.val.ValidateProposal(&bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("wrong mean accepted")
	}
	// Byzantine master: altered reading (signature breaks).
	bad = *p
	bad.Readings = append([]Reading(nil), p.Readings...)
	bad.Readings[1].Round = 6
	if f.val.ValidateProposal(&bad) == nil {
		t.Fatal("altered reading accepted")
	}
	// Byzantine master: too few readings.
	bad = *p
	bad.Included = p.Included[:2]
	if f.val.ValidateProposal(&bad) == nil {
		t.Fatal("proposal with < n-f readings accepted")
	}
}

func TestProposalValidationPlain(t *testing.T) { testProposalValidation(t, false) }
func TestProposalValidationZKP(t *testing.T)   { testProposalValidation(t, true) }

func TestProvablyBadReading(t *testing.T) {
	f := newFixture(t, true)
	r, _, _ := MakeReading(f.cfg, f.params, f.signers[2], 1, 0, 2, 500, false)
	if f.val.IsProvablyBad(r) {
		t.Fatal("honest reading flagged")
	}
	r.RangeProof[20] ^= 0xFF
	sig, _ := f.signers[2].Sign(r.SignedBytes())
	r.Signature = sig
	if !f.val.IsProvablyBad(r) {
		t.Fatal("signed reading with corrupt proof is not evidence")
	}
	// Corrupt but signed by nobody: not attributable.
	r.Signature[0] ^= 1
	if f.val.IsProvablyBad(r) {
		t.Fatal("unsigned garbage treated as evidence")
	}
}

func TestOpeningCheck(t *testing.T) {
	f := newFixture(t, true)
	r, op, _ := MakeReading(f.cfg, f.params, f.signers[1], 1, 0, 1, -700, false)
	if err := CheckOpening(f.cfg, r, op); err != nil {
		t.Fatal(err)
	}
	op.E++
	if CheckOpening(f.cfg, r, op) == nil {
		t.Fatal("wrong opening accepted")
	}
}

// Regression (audit): a Byzantine master must not be able to choose which
// readings are averaged, nor report its own offset as non-zero, in EITHER
// mode. Previously ZKP mode accepted a hand-picked included set.
func TestByzantineMasterCannotPickIncludedSet(t *testing.T) {
	for _, useZKP := range []bool{false, true} {
		f := newFixture(t, useZKP)
		contribsFor := func(offs []int64) map[uint32]*Contribution {
			m := map[uint32]*Contribution{}
			for i, d := range offs {
				r, op, err := MakeReading(f.cfg, f.params, f.signers[i], 5, 0, uint32(i), d, false)
				if err != nil {
					t.Fatal(err)
				}
				c := &Contribution{Reading: *r, Offset: d}
				if op != nil {
					c.E, c.R = op.E, op.R
				}
				m[uint32(i)] = c
			}
			return m
		}

		// 1. Keep a filtered outlier (node 3 at +180 ms) in the average,
		//    reusing the honest proof and recomputing the mean.
		honest := f.proposal(t, []int64{0, 3000, -1000, 180_000})
		bad := *honest
		bad.Included = []uint32{0, 1, 2, 3}
		bad.Mean = FloorMean(map[uint32]int64{0: 0, 1: 3000, 2: -1000, 3: 180_000}, bad.Included, f.cfg.Bound)
		if f.val.ValidateProposal(&bad) == nil {
			t.Fatalf("zkp=%v: hand-picked included set accepted", useZKP)
		}

		// 2. Drop an honest in-band reading from the average.
		bad = *honest
		bad.Included = []uint32{0, 1}
		if f.val.ValidateProposal(&bad) == nil {
			t.Fatalf("zkp=%v: dropped honest reading accepted", useZKP)
		}

		// 3. Master claims its own offset is +180 ms (the audit attack).
		c := contribsFor([]int64{180_000, 3000, -1000, 500})
		p, err := BuildProposal(f.cfg, f.params, 5, 0, 0, c)
		if useZKP {
			if err == nil {
				t.Fatal("zkp: proof generated for a non-zero leader reading")
			}
		} else if err == nil && f.val.ValidateProposal(p) == nil {
			t.Fatal("plain: non-zero leader reading accepted")
		}

		// 4. The filter's fallback (too few in band -> keep all) still works.
		p = f.proposal(t, []int64{0, 100_000, -100_000, 150_000})
		if len(p.Included) != 4 {
			t.Fatalf("zkp=%v: fallback did not keep all: %v", useZKP, p.Included)
		}
		if err := f.val.ValidateProposal(p); err != nil {
			t.Fatalf("zkp=%v: honest fallback proposal rejected: %v", useZKP, err)
		}
	}
}
