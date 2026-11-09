package cluster

import (
	"testing"
	"time"

	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/handshake"
)

// These are end-to-end tests: 4 real nodes, real crypto, real PBFT, real
// clocks. They take a few seconds each. Run with: go test ./internal/cluster -v
// (skipped with -short).

func runCluster(t *testing.T, o Options, d time.Duration) *Cluster {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	c, err := Build(o)
	if err != nil {
		t.Fatal(err)
	}
	c.RunFor(d, 100*time.Millisecond)
	return c
}

func finalSpreadUs(c *Cluster) int64 {
	s := c.Rec.Spread
	var worst int64
	for _, x := range s[len(s)*3/4:] { // last quarter of the run
		if x.SpreadUs > worst {
			worst = x.SpreadUs
		}
	}
	return worst
}

func TestHonestClusterSynchronises(t *testing.T) {
	o := Defaults()
	o.Suite, o.ZKP = handshake.SuiteClassical, false // fast variant (C1)
	c := runCluster(t, o, 6*time.Second)
	if w := finalSpreadUs(c); w > 10_000 {
		t.Fatalf("clocks not synchronised: worst spread %dus", w)
	}
	if len(c.Rec.Rounds) == 0 {
		t.Fatal("no committed rounds")
	}
}

func TestByzantineMasterIsExcludedAndReplaced(t *testing.T) {
	o := Defaults()
	o.Suite, o.ZKP = handshake.SuiteClassical, false
	o.Behaviours = map[uint32]byzantine.Behaviour{0: {BadAverage: true}}
	c := runCluster(t, o, 8*time.Second)
	for _, i := range c.Honest() {
		ex := c.Nodes[i].PBFT().Excluded()
		if len(ex) != 1 || ex[0] != 0 {
			t.Fatalf("node %d excluded set = %v, want [0]", i, ex)
		}
		if c.Nodes[i].PBFT().Primary() == 0 {
			t.Fatalf("node %d still follows the Byzantine master", i)
		}
	}
	// No round with the Byzantine master as leader was ever committed.
	for _, r := range c.Rec.Rounds {
		if r.Leader == 0 {
			t.Fatalf("round %d committed with Byzantine leader", r.Round)
		}
	}
	if w := finalSpreadUs(c); w > 10_000 {
		t.Fatalf("not synchronised after leader change: %dus", w)
	}
}

func TestCrashedMasterTriggersViewChange(t *testing.T) {
	o := Defaults()
	o.Suite, o.ZKP = handshake.SuiteClassical, false
	o.ProgressTimeout = 2 * time.Second
	o.Behaviours = map[uint32]byzantine.Behaviour{0: {Crash: true}}
	c := runCluster(t, o, 8*time.Second)
	if len(c.Rec.Rounds) == 0 {
		t.Fatal("no progress after the master crashed")
	}
	for _, i := range c.Honest() {
		if c.Nodes[i].PBFT().View() == 0 {
			t.Fatalf("node %d never left view 0", i)
		}
	}
}
