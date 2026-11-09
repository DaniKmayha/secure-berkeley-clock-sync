// Package cluster builds a complete in-process cluster (keys, clocks,
// network, nodes) for simulations, experiments and integration tests.
package cluster

import (
	"context"
	"fmt"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"secure-distributed-system/internal/berkeley"
	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/clock"
	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/crypto/pqc"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/metrics"
	"secure-distributed-system/internal/network"
	"secure-distributed-system/internal/node"
	"secure-distributed-system/internal/zkp"
)

// Options describe one experiment configuration.
type Options struct {
	N     int
	Suite handshake.Suite
	ZKP   bool

	BoundUs int64 // L
	BandUs  int64 // fault-tolerant averaging band

	InitialOffsetUs int64   // clocks start uniformly in ±InitialOffsetUs of real time
	DriftPPM        float64 // each clock drifts uniformly in ±DriftPPM
	Seed            uint64  // RNG seed for clock initialisation (reproducibility)

	Link network.LinkConfig

	RoundInterval  time.Duration
	CollectTimeout time.Duration
	SlewPeriod     time.Duration

	TimeSamples        int   // Cristian exchanges per round (min-RTT filter)
	SuspectThresholdUs int64 // witness check threshold
	SuspectAfter       int   // consecutive witness failures before suspicion

	Policy             handshake.Policy
	RekeyOnLeaderChange bool
	RehandshakePerRound bool

	ProgressTimeout   time.Duration
	ViewChangeTimeout time.Duration

	Behaviours map[uint32]byzantine.Behaviour
	Params     *zkp.Params // reuse an existing setup (optional)
	Verbose    bool
	// Logf receives protocol log lines when set (overrides Verbose).
	Logf func(format string, args ...any)
}

// Defaults returns sensible values for a 4-node, f=1 cluster.
func Defaults() Options {
	return Options{
		N: 4, Suite: handshake.SuiteHybrid, ZKP: true,
		BoundUs: 200_000, BandUs: 50_000,
		InitialOffsetUs: 150_000, DriftPPM: 200, Seed: 1,
		Link:          network.LinkConfig{BaseLatency: 2 * time.Millisecond, Jitter: 1 * time.Millisecond},
		RoundInterval: time.Second, CollectTimeout: 400 * time.Millisecond, SlewPeriod: 250 * time.Millisecond,
		TimeSamples: 4, SuspectThresholdUs: 20_000, SuspectAfter: 3,
		Policy:              handshake.Policy{MaxMessages: 1000, MaxAgeSec: 600},
		RekeyOnLeaderChange: true,
		ProgressTimeout:     4 * time.Second, ViewChangeTimeout: 3 * time.Second,
		Behaviours: map[uint32]byzantine.Behaviour{},
	}
}

// Cluster is a running set of nodes.
type Cluster struct {
	Opts   Options
	Nodes  []*node.Node
	Clocks []*clock.Clock
	Net    *network.MemNetwork
	Rec    *metrics.Recorder
	Params *zkp.Params

	transports []network.Transport
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

// GenerateIdentity creates an identity key for the suite.
func GenerateIdentity(s handshake.Suite) (identity.Signer, error) {
	if s == handshake.SuiteHybrid {
		return pqc.GenerateMLDSA()
	}
	return classical.GenerateEd25519()
}

// Build creates (but does not start) a cluster.
func Build(o Options) (*Cluster, error) {
	if o.N < 3*1+1 {
		return nil, fmt.Errorf("cluster: need n >= 4 for f >= 1")
	}
	f := (o.N - 1) / 3
	c := &Cluster{Opts: o, Rec: metrics.NewRecorder(), Net: network.NewMemNetwork(o.N, o.Link)}

	if o.ZKP {
		c.Params = o.Params
		if c.Params == nil || c.Params.N != o.N {
			p, err := zkp.Setup(o.N)
			if err != nil {
				return nil, err
			}
			c.Params = p
		}
	}

	signers := make([]identity.Signer, o.N)
	verifiers := map[uint32]identity.Verifier{}
	for i := 0; i < o.N; i++ {
		s, err := GenerateIdentity(o.Suite)
		if err != nil {
			return nil, err
		}
		signers[i] = s
		verifiers[uint32(i)] = s.Public()
	}

	rng := rand.New(rand.NewPCG(o.Seed, o.Seed^0x9e3779b97f4a7c15))
	logf := func(string, ...any) {}
	if o.Verbose {
		logf = log.Printf
	}
	if o.Logf != nil {
		logf = o.Logf
	}
	bcfg := berkeley.Config{N: o.N, F: f, Bound: o.BoundUs, Band: o.BandUs, ZKP: o.ZKP}
	for i := 0; i < o.N; i++ {
		id := uint32(i)
		off := rng.Int64N(2*o.InitialOffsetUs+1) - o.InitialOffsetUs
		drift := (rng.Float64()*2 - 1) * o.DriftPPM
		clk := clock.New(off, drift)
		c.Clocks = append(c.Clocks, clk)
		tr := c.Net.Endpoint(id)
		c.transports = append(c.transports, tr)
		nd := node.New(node.Config{
			ID: id, Suite: o.Suite, Berkeley: bcfg,
			RoundInterval: o.RoundInterval, CollectTimeout: o.CollectTimeout, SlewPeriod: o.SlewPeriod,
			TimeSamples: o.TimeSamples, SuspectThresholdUs: o.SuspectThresholdUs, SuspectAfter: o.SuspectAfter,
			Policy: o.Policy, RekeyOnLeaderChange: o.RekeyOnLeaderChange, RehandshakePerRound: o.RehandshakePerRound,
			ProgressTimeout: o.ProgressTimeout, ViewChangeTimeout: o.ViewChangeTimeout,
			Behaviour: o.Behaviours[id], Logf: logf,
		}, node.Deps{
			Clock: clk, Transport: tr, Signer: signers[i],
			Verifiers: verifiers, Params: c.Params, Recorder: c.Rec,
		})
		c.Nodes = append(c.Nodes, nd)
	}
	return c, nil
}

// Honest returns the ids of nodes without Byzantine behaviour.
func (c *Cluster) Honest() []int {
	var ids []int
	for i := range c.Nodes {
		if c.Opts.Behaviours[uint32(i)].IsHonest() {
			ids = append(ids, i)
		}
	}
	return ids
}

// Start runs every non-crashed node in its own goroutine.
func (c *Cluster) Start() {
	ctx, cancel := context.WithCancel(context.Background())
	c.cancel = cancel
	for i, nd := range c.Nodes {
		if c.Opts.Behaviours[uint32(i)].Crash {
			c.Net.SetDown(uint32(i), true)
			continue
		}
		c.wg.Add(1)
		go func(nd *node.Node) {
			defer c.wg.Done()
			nd.Run(ctx)
		}(nd)
	}
}

// Stop cancels all nodes and waits for them.
func (c *Cluster) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	c.wg.Wait()
	for _, t := range c.transports {
		_ = t.Close() // unblocks the network pumps of this cluster
	}
}

// Sample records the ground-truth spread among honest, running nodes.
func (c *Cluster) Sample() metrics.SpreadSample {
	s := metrics.SpreadSample{At: time.Now()}
	var lo, hi int64
	first := true
	for _, i := range c.Honest() {
		o := c.Clocks[i].OffsetFromReal()
		s.OffsetsUs = append(s.OffsetsUs, o)
		if first || o < lo {
			lo = o
		}
		if first || o > hi {
			hi = o
		}
		first = false
	}
	s.SpreadUs = hi - lo
	c.Rec.Sample(s)
	return s
}

// RunFor starts the cluster, samples the spread every `every`, and stops after d.
func (c *Cluster) RunFor(d, every time.Duration) {
	c.Start()
	c.Sample()
	t := time.NewTicker(every)
	defer t.Stop()
	end := time.After(d)
	for {
		select {
		case <-t.C:
			c.Sample()
		case <-end:
			c.Stop()
			return
		}
	}
}
