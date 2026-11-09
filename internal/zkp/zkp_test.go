package zkp

import (
	"sync"
	"testing"
)

const bound = 200_000 // L = 200 ms

var (
	paramsOnce sync.Once
	params     *Params
)

func testParams(t *testing.T) *Params {
	paramsOnce.Do(func() {
		p, err := Setup(4)
		if err != nil {
			t.Fatal(err)
		}
		params = p
	})
	return params
}

func TestRangeProofValidAndInvalid(t *testing.T) {
	p := testParams(t)
	rc, ac := p.Constraints()
	t.Logf("constraints: range=%d aggregate=%d, setup=%v", rc, ac, p.SetupTime)

	e := Shift(-12_345, bound)
	r := NewBlinding()
	c, err := Commit(e, r, 7, 2)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := p.ProveRange(e, r, c, 7, 2, bound)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("range proof size: %d bytes", len(proof))
	if err := p.VerifyRange(proof, c, 7, 2, bound); err != nil {
		t.Fatalf("valid proof rejected: %v", err)
	}
	// Wrong public inputs (replay into another round / as another node).
	if p.VerifyRange(proof, c, 8, 2, bound) == nil {
		t.Fatal("proof accepted for a different round")
	}
	if p.VerifyRange(proof, c, 7, 3, bound) == nil {
		t.Fatal("proof accepted for a different node")
	}
	// Tampered proof bytes.
	bad := append([]byte(nil), proof...)
	bad[10] ^= 1
	if p.VerifyRange(bad, c, 7, 2, bound) == nil {
		t.Fatal("tampered proof accepted")
	}
	// An out-of-range value cannot be proven at all.
	eBig := Shift(bound+1, bound)
	cBig, _ := Commit(eBig, r, 7, 2)
	if _, err := p.ProveRange(eBig, r, cBig, 7, 2, bound); err == nil {
		t.Fatal("proved an out-of-range offset")
	}
}

func aggSlots(offsets []int64, included []bool, round uint64) []AggInput {
	slots := make([]AggInput, len(offsets))
	for i, d := range offsets {
		e := Shift(d, bound)
		r := NewBlinding()
		c, _ := Commit(e, r, round, uint32(i))
		slots[i] = AggInput{Present: true, Included: included[i], Commitment: c, E: e, R: r}
	}
	return slots
}

func split(slots []AggInput) (comms [][]byte, present, inc []bool) {
	for _, s := range slots {
		comms = append(comms, s.Commitment)
		present = append(present, s.Present)
		inc = append(inc, s.Included)
	}
	return
}

func TestAggregateProof(t *testing.T) {
	p := testParams(t)
	rule := AggRule{Band: 50_000, MinKeep: 3, Half: uint64(bound), Leader: 0}
	// Node 0 is the leader (offset 0); node 3 is an outlier the filter drops.
	slots := aggSlots([]int64{0, 1500, -800, 199_000}, []bool{true, true, true, false}, 3)
	proof, mean, err := p.ProveAggregate(3, slots, rule)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := Unshift(mean, bound), int64((0+1500-800)/3); got != want {
		t.Fatalf("mean = %d, want %d", got, want)
	}
	comms, present, inc := split(slots)
	if err := p.VerifyAggregate(proof, 3, comms, present, inc, mean, rule); err != nil {
		t.Fatalf("valid aggregate rejected: %v", err)
	}
	if p.VerifyAggregate(proof, 3, comms, present, inc, mean+1, rule) == nil {
		t.Fatal("wrong mean accepted")
	}
	if p.VerifyAggregate(proof, 3, comms, present, []bool{true, true, true, true}, mean, rule) == nil {
		t.Fatal("different inclusion set accepted")
	}
	r2 := rule
	r2.Band = 500_000
	if p.VerifyAggregate(proof, 3, comms, present, inc, mean, r2) == nil {
		t.Fatal("proof accepted under a different band")
	}
}

// A Byzantine master cannot even PRODUCE a proof for a hand-picked set.
func TestAggregateRejectsWrongFilter(t *testing.T) {
	p := testParams(t)
	rule := AggRule{Band: 50_000, MinKeep: 3, Half: uint64(bound), Leader: 0}
	cases := map[string]struct {
		offsets  []int64
		included []bool
	}{
		"outlier kept":           {[]int64{0, 1500, -800, 199_000}, []bool{true, true, true, true}},
		"honest reading dropped": {[]int64{0, 1500, -800, 900}, []bool{true, true, true, false}},
		"leader offset not 0":    {[]int64{180_000, 3000, -1000, 500}, []bool{true, true, true, true}},
	}
	for name, c := range cases {
		slots := aggSlots(c.offsets, c.included, 4)
		if _, _, err := p.ProveAggregate(4, slots, rule); err == nil {
			t.Errorf("%s: proof generated for an invalid aggregation", name)
		}
	}
	// Fallback: fewer than MinKeep in band -> every reading is included.
	slots := aggSlots([]int64{0, 100_000, -100_000, 150_000}, []bool{true, true, true, true}, 5)
	if _, _, err := p.ProveAggregate(5, slots, rule); err != nil {
		t.Fatalf("fallback (keep all) rejected: %v", err)
	}
}
