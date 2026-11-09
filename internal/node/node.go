// Package node wires all layers into one running replica:
//
//	transport -> session (handshake / AES-GCM) -> dispatch
//	                                     |-> Berkeley messages (this file)
//	                                     |-> PBFT messages     (package bft)
//
// Every node is simultaneously a Berkeley participant and a PBFT replica.
// The Berkeley MASTER is always the current PBFT PRIMARY, so leader election
// for the clock protocol is exactly the PBFT view change with evidence-based
// exclusion (package bft).
//
// Concurrency: one event-loop goroutine owns all protocol state. Slow work
// (Groth16 proving) runs in worker goroutines that post their result back
// to the loop through n.tasks, so the loop never blocks on cryptography for
// long and PBFT messages keep flowing.
package node

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"secure-distributed-system/internal/berkeley"
	"secure-distributed-system/internal/bft"
	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/clock"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/metrics"
	"secure-distributed-system/internal/network"
	"secure-distributed-system/internal/session"
	"secure-distributed-system/internal/wire"
	"secure-distributed-system/internal/zkp"
)

// Config of one node.
type Config struct {
	ID       uint32
	Suite    handshake.Suite
	Berkeley berkeley.Config

	RoundInterval  time.Duration // time between Berkeley rounds
	CollectTimeout time.Duration // master waits this long for readings
	SlewPeriod     time.Duration // adjustments are slewed over this period

	TimeSamples        int   // Cristian exchanges per round, min-RTT one is kept
	SuspectThresholdUs int64 // witness check: max tolerated offset to a peer slave
	SuspectAfter       int   // consecutive witness failures before suspecting the master

	Policy              handshake.Policy // session rotation (N messages / T seconds)
	RekeyOnLeaderChange bool             // fresh hybrid handshake with the new primary
	RehandshakePerRound bool             // C2: naive fresh handshake for every round

	ProgressTimeout   time.Duration
	ViewChangeTimeout time.Duration

	Behaviour byzantine.Behaviour
	Logf      func(format string, args ...any)
}

// Deps are the external objects a node needs.
type Deps struct {
	Clock     *clock.Clock
	Transport network.Transport
	Signer    identity.Signer
	Verifiers map[uint32]identity.Verifier // all nodes, including self
	Params    *zkp.Params                  // nil in plain mode
	Recorder  *metrics.Recorder            // may be nil
}

// masterRound is the master-side state of the round in progress.
type masterRound struct {
	round, view uint64
	started     time.Time
	deadline    time.Time
	contribs    map[uint32]*berkeley.Contribution
	waitingOpen map[uint32]*berkeley.Reading // ZKP: reading received, opening not yet
	finalizing  bool
	proposed    bool
	ownStarted  bool // master's own proof is delayed until slaves finished timing
}

// slaveRound is the slave-side state of one round.
type slaveRound struct {
	view    uint64
	master  uint32
	t1      int64 // local send time of the current TimeReq
	sample  uint8 // index of the current TimeReq
	bestRTT int64 // smallest RTT so far (-1: none)
	bestD   int64 // offset estimate of that sample
}

// witness is the state of the slave-to-slave consistency check.
type witness struct {
	due       time.Time // when to run the next check (0: none scheduled)
	peer      uint32
	nonce     uint64
	t1        int64
	failures  int
	suspected uint64 // view in which we already raised suspicion
	// Only peers INCLUDED in the last committed average are used as
	// witnesses: an outlier (e.g. a Byzantine slave reporting +L) is known
	// to be out of sync and would otherwise make us blame an honest master.
	inSync map[uint32]bool
}

// Node is one replica.
type Node struct {
	cfg  Config
	deps Deps

	sess  *session.Manager
	pbft  *bft.Engine
	val   *berkeley.Validator
	tasks chan func()

	// master side
	cur         *masterRound
	lastStarted uint64
	nextRoundAt time.Time
	// Nodes that contributed to the last committed round we led: the master
	// does not keep waiting for nodes that have gone silent (crashed). Every
	// fullWaitEvery rounds it waits for everyone again so recovered nodes rejoin.
	lastContributors map[uint32]bool
	roundsLed        int

	wit witness

	statusMu sync.Mutex
	status   Status

	// slave side
	pending   map[uint64]*slaveRound
	myOffsets map[uint64]int64 // round -> my offset d (what I committed to)
	adjusts   map[uint64]int64 // round -> Adjust received from master
	applied   map[uint64]int64 // round -> adjustment applied from committed value
}

// New builds a node. Call Run to start it.
func New(cfg Config, deps Deps) *Node {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.TimeSamples < 1 {
		cfg.TimeSamples = 1
	}
	n := &Node{
		cfg: cfg, deps: deps,
		tasks:   make(chan func(), 256),
		pending: map[uint64]*slaveRound{}, myOffsets: map[uint64]int64{},
		adjusts: map[uint64]int64{}, applied: map[uint64]int64{},
	}
	n.val = &berkeley.Validator{Cfg: cfg.Berkeley, Verifiers: deps.Verifiers, Params: deps.Params}

	peers := map[uint32]identity.Verifier{}
	for id, v := range deps.Verifiers {
		if id != cfg.ID {
			peers[id] = v
		}
	}
	n.sess = session.NewManager(session.Config{
		Self: cfg.ID, Suite: cfg.Suite, Signer: deps.Signer, Peers: peers, Policy: cfg.Policy,
		Send: func(env wire.Envelope) {
			_ = deps.Transport.Send(env.To, wire.Marshal(env))
		},
		OnHandshake: n.onHandshake,
		Logf:        n.logf,
	})
	n.pbft = bft.New(bft.Config{
		Self: cfg.ID, N: cfg.Berkeley.N, F: cfg.Berkeley.F,
		Signer: deps.Signer, Verifiers: deps.Verifiers,
		ProgressTimeout: cfg.ProgressTimeout, ViewChangeTimeout: cfg.ViewChangeTimeout,
		OnNewView: n.onNewView, OnExclude: n.onExclude, Logf: n.logf,
	}, (*app)(n), (*outbound)(n))
	return n
}

func (n *Node) logf(format string, args ...any) {
	n.cfg.Logf("[node %d] "+format, append([]any{n.cfg.ID}, args...)...)
}

func (n *Node) event(kind, detail string) {
	if n.deps.Recorder != nil {
		n.deps.Recorder.Event(n.cfg.ID, kind, detail)
	}
}

// Status is a thread-safe snapshot of a node's protocol state, refreshed by
// the event loop. It exists for observers (the GUI); the protocol never reads it.
type Status struct {
	View         uint64
	Primary      uint32
	LastRound    uint64
	InViewChange bool
	Excluded     []uint32
	Handshakes   uint64
}

// Status returns the latest snapshot (safe to call from any goroutine).
func (n *Node) Status() Status {
	n.statusMu.Lock()
	defer n.statusMu.Unlock()
	return n.status
}

func (n *Node) refreshStatus() {
	s := Status{
		View: n.pbft.View(), Primary: n.pbft.Primary(), LastRound: n.pbft.LastExecuted(),
		InViewChange: n.pbft.InViewChange(), Excluded: n.pbft.Excluded(),
		Handshakes: n.sess.Stats.HandshakesCompleted.Load(),
	}
	n.statusMu.Lock()
	n.status = s
	n.statusMu.Unlock()
}

// Sessions / PBFT accessors (tests and experiments).
func (n *Node) Sessions() *session.Manager { return n.sess }
func (n *Node) PBFT() *bft.Engine          { return n.pbft }
func (n *Node) Clock() *clock.Clock        { return n.deps.Clock }

// Run is the event loop. It returns when ctx is cancelled.
func (n *Node) Run(ctx context.Context) {
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	// Control Plane warm-up: establish sessions with every peer.
	for id := range n.deps.Verifiers {
		if id != n.cfg.ID {
			n.sess.Connect(id)
		}
	}
	n.nextRoundAt = time.Now().Add(n.cfg.RoundInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-n.deps.Transport.Inbox():
			n.onPacket(pkt)
		case f := <-n.tasks:
			f()
		case now := <-tick.C:
			n.sess.Tick(now)
			n.pbft.Tick(now)
			n.onTick(now)
			n.refreshStatus()
		}
	}
}

// post runs f on the event loop (from worker goroutines).
func (n *Node) post(f func()) { n.tasks <- f }

func (n *Node) send(to uint32, t wire.AppType, v any) {
	n.sess.Send(to, t, wire.Marshal(v))
}

func (n *Node) onPacket(pkt network.Packet) {
	var env wire.Envelope
	if err := wire.Unmarshal(pkt.Data, &env); err != nil {
		return
	}
	if env.From != pkt.From { // routing hint must agree; auth is done by the session layer
		return
	}
	t, payload, ok, err := n.sess.Handle(env)
	if err != nil {
		n.event("session_reject", err.Error())
		return
	}
	if !ok {
		return
	}
	n.dispatch(env.From, t, payload)
}

func (n *Node) dispatch(from uint32, t wire.AppType, body []byte) {
	switch t {
	case wire.AppPoll:
		var m berkeley.Poll
		if wire.Unmarshal(body, &m) == nil {
			n.onPoll(from, &m)
		}
	case wire.AppTimeReq:
		var m berkeley.TimeReq
		if wire.Unmarshal(body, &m) == nil {
			n.onTimeReq(from, &m)
		}
	case wire.AppTimeResp:
		var m berkeley.TimeResp
		if wire.Unmarshal(body, &m) == nil {
			n.onTimeResp(from, &m)
		}
	case wire.AppReading:
		var m berkeley.Reading
		if wire.Unmarshal(body, &m) == nil {
			n.onReading(from, &m, body)
		}
	case wire.AppOpening:
		var m berkeley.Opening
		if wire.Unmarshal(body, &m) == nil {
			n.onOpening(from, &m)
		}
	case wire.AppAdjust:
		var m berkeley.Adjust
		if wire.Unmarshal(body, &m) == nil {
			n.onAdjust(from, &m)
		}
	case wire.AppPeerTimeReq:
		var m berkeley.PeerTimeReq
		if wire.Unmarshal(body, &m) == nil {
			n.send(from, wire.AppPeerTimeResp, berkeley.PeerTimeResp{Nonce: m.Nonce, Time: n.deps.Clock.Now()})
		}
	case wire.AppPeerTimeResp:
		var m berkeley.PeerTimeResp
		if wire.Unmarshal(body, &m) == nil {
			n.onPeerTimeResp(from, &m)
		}
	case wire.AppPrePrepare, wire.AppPrepare, wire.AppCommit, wire.AppViewChange, wire.AppNewView, wire.AppEvidence:
		n.pbft.Handle(from, t, body)
	}
}

// ================================================================ master ==

func (n *Node) onTick(now time.Time) {
	n.witnessTick(now)
	if !n.pbft.IsPrimary() {
		return
	}
	if n.cfg.Behaviour.SilentLeader {
		return // Byzantine: never drive rounds; backups will time out
	}
	if r := n.cur; r != nil {
		// Collection deadline reached: propose with what we have.
		// Start the master's own proof once the slaves are done with their
		// timing exchanges (proving saturates the CPU and would add
		// asymmetric delays to the Cristian measurements).
		if !r.ownStarted && now.Sub(r.started) > n.cfg.CollectTimeout/4 {
			n.startOwnReading()
		}
		if !r.finalizing && now.After(r.deadline) {
			n.finalize()
		}
		// Still in progress: wait for its commit (execute clears n.cur),
		// unless it has stalled for too long, in which case abandon it.
		if n.cur != nil && now.Sub(r.started) < 4*n.cfg.RoundInterval {
			return
		}
		n.cur = nil
	}
	if now.Before(n.nextRoundAt) {
		return
	}
	n.startRound(now)
}

func (n *Node) startRound(now time.Time) {
	round := n.pbft.LastExecuted() + 1
	if n.lastStarted >= round {
		round = n.lastStarted + 1
	}
	n.lastStarted = round
	view := n.pbft.View()
	n.cur = &masterRound{
		round: round, view: view, started: now, deadline: now.Add(n.cfg.CollectTimeout),
		contribs: map[uint32]*berkeley.Contribution{}, waitingOpen: map[uint32]*berkeley.Reading{},
	}
	n.nextRoundAt = now.Add(n.cfg.RoundInterval)
	n.logf("MASTER round %d (view %d): polling", round, view)

	for id := range n.deps.Verifiers {
		if id == n.cfg.ID || n.pbft.IsExcluded(id) {
			continue
		}
		if n.cfg.RehandshakePerRound {
			n.sess.Rekey(id) // C2: fresh hybrid handshake for every round
		}
		n.send(id, wire.AppPoll, berkeley.Poll{Round: round, View: view})
	}
	n.roundsLed++
}

// startOwnReading creates the master's own reading: by definition offset 0
// w.r.t. itself.
func (n *Node) startOwnReading() {
	r := n.cur
	if r == nil || r.ownStarted {
		return
	}
	r.ownStarted = true
	n.makeOwnReading(r.round, r.view, n.cfg.ID, 0, false)
}

func (n *Node) onTimeReq(from uint32, m *berkeley.TimeReq) {
	r := n.cur
	if r == nil || m.Round != r.round || !n.pbft.IsPrimary() {
		return
	}
	t := n.deps.Clock.Now()
	if lie := n.cfg.Behaviour.LieTimestampUs; lie != 0 {
		// Byzantine: a consistent but DIFFERENT lie per slave (by id parity),
		// trying to pull the slaves apart from each other.
		if from%2 == 0 {
			t += lie
		} else {
			t -= lie
		}
	}
	n.send(from, wire.AppTimeResp, berkeley.TimeResp{Round: m.Round, Sample: m.Sample, MasterTime: t})
}

func (n *Node) onReading(from uint32, m *berkeley.Reading, raw []byte) {
	r := n.cur
	if r == nil || r.finalizing || m.Round != r.round || m.View != r.view || m.NodeID != from {
		return
	}
	if n.pbft.IsExcluded(from) {
		return
	}
	n.startOwnReading() // a slave has finished timing: safe to start proving
	start := time.Now()
	err := n.val.ValidateReading(m)
	if n.cfg.Berkeley.ZKP {
		n.recordProof("range_verify", time.Since(start), len(m.RangeProof))
	}
	if err != nil {
		n.logf("rejected reading from %d: %v", from, err)
		n.event("reading_rejected", fmt.Sprintf("node=%d %v", from, err))
		if n.val.IsProvablyBad(m) {
			// Signed + invalid = transferable evidence: exclude the slave.
			n.pbft.AddEvidence(bft.Evidence{Kind: bft.EvApp, Accused: from, A: raw})
		}
		return
	}
	if n.cfg.Berkeley.ZKP {
		r.waitingOpen[from] = m
		return
	}
	r.contribs[from] = &berkeley.Contribution{Reading: *m, Offset: m.Offset}
	n.maybeFinalize()
}

func (n *Node) onOpening(from uint32, op *berkeley.Opening) {
	r := n.cur
	if r == nil || r.finalizing || op.Round != r.round {
		return
	}
	rd := r.waitingOpen[from]
	if rd == nil {
		return
	}
	delete(r.waitingOpen, from)
	if err := berkeley.CheckOpening(n.cfg.Berkeley, rd, op); err != nil {
		n.event("opening_rejected", fmt.Sprintf("node=%d %v", from, err))
		return
	}
	r.contribs[from] = &berkeley.Contribution{
		Reading: *rd, Offset: zkp.Unshift(op.E, n.cfg.Berkeley.Bound), E: op.E, R: op.R,
	}
	n.maybeFinalize()
}

const fullWaitEvery = 5

// maybeFinalize proposes as soon as every node we expect has contributed.
// Expected = non-excluded nodes that contributed last round (so a crashed
// node does not cost a full CollectTimeout every round), except every
// fullWaitEvery rounds, when we wait for everyone so recovered nodes rejoin.
func (n *Node) maybeFinalize() {
	r := n.cur
	if _, own := r.contribs[n.cfg.ID]; !own {
		return
	}
	waitAll := n.lastContributors == nil || n.roundsLed%fullWaitEvery == 0
	for id := range n.deps.Verifiers {
		if n.pbft.IsExcluded(id) || (!waitAll && !n.lastContributors[id]) {
			continue
		}
		if _, ok := r.contribs[id]; !ok {
			return
		}
	}
	n.finalize()
}

// finalize builds the proposal (aggregation proof in a worker) and hands it to PBFT.
func (n *Node) finalize() {
	r := n.cur
	if r == nil || r.finalizing {
		return
	}
	r.finalizing = true
	if len(r.contribs) < n.cfg.Berkeley.MinReadings() {
		n.logf("round %d: only %d readings (need %d), abandoning", r.round, len(r.contribs), n.cfg.Berkeley.MinReadings())
		n.event("round_abandoned", fmt.Sprintf("round=%d readings=%d", r.round, len(r.contribs)))
		n.cur = nil
		return
	}
	contribs := map[uint32]*berkeley.Contribution{}
	for id, c := range r.contribs {
		contribs[id] = c
	}
	cfg, params, beh, self := n.cfg.Berkeley, n.deps.Params, n.cfg.Behaviour, n.cfg.ID
	round, view := r.round, r.view
	go func() {
		start := time.Now()
		prop, err := berkeley.BuildProposal(cfg, params, round, view, self, contribs)
		dur := time.Since(start)
		var alt *berkeley.Proposal
		if err == nil && beh.Equivocate {
			// A second, individually VALID proposal built without one slave.
			reduced := map[uint32]*berkeley.Contribution{}
			dropped := false
			for id, c := range contribs {
				if !dropped && id != self && len(contribs) > cfg.MinReadings() {
					dropped = true
					continue
				}
				reduced[id] = c
			}
			if dropped {
				alt, _ = berkeley.BuildProposal(cfg, params, round, view, self, reduced)
			}
		}
		n.post(func() {
			if err != nil {
				n.logf("round %d: build proposal: %v", round, err)
				return
			}
			if cfg.ZKP {
				n.recordProof("agg_prove", dur, len(prop.AggProof))
			}
			n.propose(prop, alt)
		})
	}()
}

func (n *Node) propose(prop, alt *berkeley.Proposal) {
	r := n.cur
	if r == nil || r.round != prop.Round || !n.pbft.IsPrimary() {
		return
	}
	r.proposed = true
	if n.cfg.Behaviour.BadAverage {
		prop.Mean += 50_000 // Byzantine: lie about the average by 50 ms
		if prop.Mean > n.cfg.Berkeley.Bound {
			prop.Mean = n.cfg.Berkeley.Bound
		}
	}
	if n.cfg.Behaviour.Equivocate && alt != nil {
		// Byzantine: proposal A to half of the backups, B to the other half.
		var a, b []uint32
		for id := 0; id < n.cfg.Berkeley.N; id++ {
			if uint32(id) == n.cfg.ID {
				continue
			}
			if len(a) <= len(b) {
				a = append(a, uint32(id))
			} else {
				b = append(b, uint32(id))
			}
		}
		n.logf("BYZANTINE: equivocating on round %d (A->%v, B->%v)", prop.Round, a, b)
		_ = n.pbft.ProposeTo(prop.Round, wire.Marshal(prop), a)
		_ = n.pbft.ProposeTo(prop.Round, wire.Marshal(alt), b)
		return
	}
	n.logf("round %d: proposing mean=%dus over %d/%d readings", prop.Round, prop.Mean, len(prop.Included), len(prop.Readings))
	if err := n.pbft.Propose(prop.Round, wire.Marshal(prop)); err != nil {
		n.logf("propose: %v", err)
	}
}

// ================================================================= slave ==

func (n *Node) onPoll(from uint32, m *berkeley.Poll) {
	if from != n.pbft.Primary() || m.View != n.pbft.View() || n.pbft.InViewChange() {
		return // only the legitimate current master may poll
	}
	if m.Round <= n.pbft.LastExecuted() {
		return // stale round
	}
	n.pending[m.Round] = &slaveRound{view: m.View, master: from, t1: n.deps.Clock.Now(), bestRTT: -1}
	n.send(from, wire.AppTimeReq, berkeley.TimeReq{Round: m.Round, Sample: 0})
	// Forget very old rounds.
	for r := range n.pending {
		if r+8 < m.Round {
			delete(n.pending, r)
		}
	}
}

func (n *Node) onTimeResp(from uint32, m *berkeley.TimeResp) {
	sr := n.pending[m.Round]
	if sr == nil || sr.master != from || m.Sample != sr.sample {
		return
	}
	t2 := n.deps.Clock.Now()
	if rtt := t2 - sr.t1; sr.bestRTT < 0 || rtt < sr.bestRTT {
		sr.bestRTT = rtt
		sr.bestD = berkeley.EstimateOffset(sr.t1, t2, m.MasterTime)
	}
	if int(sr.sample)+1 < n.cfg.TimeSamples {
		// Next timing sample.
		sr.sample++
		sr.t1 = n.deps.Clock.Now()
		n.send(from, wire.AppTimeReq, berkeley.TimeReq{Round: m.Round, Sample: sr.sample})
		return
	}
	delete(n.pending, m.Round)
	d, clamped := berkeley.Clamp(sr.bestD, n.cfg.Berkeley.Bound)
	if n.cfg.Behaviour.ExtremeOffset {
		d, clamped = n.cfg.Berkeley.Bound, false // Byzantine: drag the average
	}
	n.makeOwnReading(m.Round, sr.view, from, d, clamped)
}

// makeOwnReading builds (and proves, in a worker) this node's reading and
// sends it to the master. For the master itself it is stored locally.
func (n *Node) makeOwnReading(round, view uint64, master uint32, d int64, clamped bool) {
	n.myOffsets[round] = d
	for r := range n.myOffsets {
		if r+16 < round {
			delete(n.myOffsets, r)
		}
	}
	cfg, params, signer, self, beh := n.cfg.Berkeley, n.deps.Params, n.deps.Signer, n.cfg.ID, n.cfg.Behaviour
	go func() {
		start := time.Now()
		if beh.InvalidProof && !cfg.ZKP {
			d = cfg.Bound * 3 // plain-mode equivalent of an invalid proof
		}
		rd, op, err := berkeley.MakeReading(cfg, params, signer, round, view, self, d, clamped)
		dur := time.Since(start)
		if err == nil && beh.InvalidProof && cfg.ZKP {
			// Byzantine: corrupt the proof but keep a valid signature over it,
			// which makes the misbehaviour provable.
			rd.RangeProof[len(rd.RangeProof)/2] ^= 0xFF
			sig, _ := signer.Sign(rd.SignedBytes())
			rd.Signature = sig
		}
		n.post(func() {
			if err != nil {
				n.logf("round %d: make reading: %v", round, err)
				return
			}
			if cfg.ZKP {
				n.recordProof("range_prove", dur, len(rd.RangeProof))
			}
			if master == self {
				// Master: add own contribution directly.
				if r := n.cur; r != nil && r.round == round && !r.finalizing {
					c := &berkeley.Contribution{Reading: *rd, Offset: d}
					if op != nil {
						c.E, c.R = op.E, op.R
					}
					r.contribs[self] = c
					n.maybeFinalize()
				}
				return
			}
			n.send(master, wire.AppReading, rd)
			if op != nil {
				n.send(master, wire.AppOpening, op) // private: only the master sees it
			}
		})
	}()
}

func (n *Node) onAdjust(from uint32, m *berkeley.Adjust) {
	n.adjusts[m.Round] = m.DeltaUs
	n.crossCheckAdjust(m.Round)
}

// crossCheckAdjust compares the master's Adjust message with the value this
// node derived from the COMMITTED proposal. A mismatch means the master
// lied: we always apply the committed value and raise suspicion.
func (n *Node) crossCheckAdjust(round uint64) {
	got, ok1 := n.adjusts[round]
	want, ok2 := n.applied[round]
	if !ok1 || !ok2 {
		return
	}
	delete(n.adjusts, round)
	if got != want {
		n.logf("master's Adjust for round %d is %dus but committed value is %dus: SUSPECT master", round, got, want)
		n.event("adjust_mismatch", fmt.Sprintf("round=%d got=%d want=%d", round, got, want))
		n.pbft.SuspectPrimary()
	}
}

// ============================================================ execution ==

// execute applies a committed round on this node.
func (n *Node) execute(seq, view uint64, payload []byte) {
	var p berkeley.Proposal
	if err := wire.Unmarshal(payload, &p); err != nil {
		return
	}
	mine := false
	for _, r := range p.Readings {
		if r.NodeID == n.cfg.ID {
			mine = true
		}
	}
	d, have := n.myOffsets[p.Round]
	var adj int64
	if mine && have {
		// adj_i = A - d_i  ("speed up" if positive, "slow down" if negative)
		adj = berkeley.Adjustment(p.Mean, d)
		if adj != 0 {
			if err := n.deps.Clock.Slew(adj, n.cfg.SlewPeriod); err != nil {
				n.deps.Clock.Step(adj)
			}
		}
		n.applied[p.Round] = adj
		n.logf("round %d committed: mean=%dus, my offset=%dus -> %s by %dus",
			p.Round, p.Mean, d, clock.Direction(adj), abs(adj))
	} else {
		n.logf("round %d committed without my reading: no adjustment", p.Round)
	}
	for r := range n.applied {
		if r+16 < p.Round {
			delete(n.applied, r)
		}
	}

	// Schedule the witness check for after the slew has been absorbed.
	if mine && have && p.Leader != n.cfg.ID && n.cfg.SuspectThresholdUs > 0 {
		n.wit.due = time.Now().Add(n.cfg.SlewPeriod + 50*time.Millisecond)
		n.wit.inSync = map[uint32]bool{}
		for _, id := range p.Included {
			n.wit.inSync[id] = true
		}
	}

	var latency float64
	if r := n.cur; r != nil && r.round == p.Round && p.Leader == n.cfg.ID {
		latency = float64(time.Since(r.started).Microseconds()) / 1000
		n.lastContributors = map[uint32]bool{}
		for _, rd := range p.Readings {
			n.lastContributors[rd.NodeID] = true
		}
		// Classic Berkeley: the master tells each slave its correction.
		for _, rd := range p.Readings {
			if rd.NodeID == n.cfg.ID {
				continue
			}
			c := r.contribs[rd.NodeID]
			if c == nil {
				continue
			}
			delta := berkeley.Adjustment(p.Mean, c.Offset)
			if n.cfg.Behaviour.WrongAdjust {
				delta += 30_000 // Byzantine: inconsistent instruction
			}
			n.send(rd.NodeID, wire.AppAdjust, berkeley.Adjust{Round: p.Round, DeltaUs: delta})
		}
		n.cur = nil
	}
	if n.deps.Recorder != nil {
		n.deps.Recorder.Round(metrics.RoundRecord{
			At: time.Now(), Node: n.cfg.ID, Round: p.Round, View: view, Leader: p.Leader,
			MeanUs: p.Mean, AdjustUs: adj, Readings: len(p.Readings), Included: len(p.Included),
			LatencyMs: latency,
		})
	}
	n.crossCheckAdjust(p.Round)
}

// =============================================================== witness ==

// witnessTick sends one PeerTimeReq to the next slave in the ring (skipping
// ourselves, the master and excluded nodes) when a check is due.
func (n *Node) witnessTick(now time.Time) {
	if n.wit.due.IsZero() || now.Before(n.wit.due) {
		return
	}
	n.wit.due = time.Time{}
	N := uint32(n.cfg.Berkeley.N)
	for k := uint32(1); k < N; k++ {
		peer := (n.cfg.ID + k) % N
		if peer == n.pbft.Primary() || n.pbft.IsExcluded(peer) || !n.wit.inSync[peer] {
			continue
		}
		n.wit.peer = peer
		n.wit.nonce++
		n.wit.t1 = n.deps.Clock.Now()
		n.send(peer, wire.AppPeerTimeReq, berkeley.PeerTimeReq{Nonce: n.wit.nonce})
		return
	}
}

func (n *Node) onPeerTimeResp(from uint32, m *berkeley.PeerTimeResp) {
	if from != n.wit.peer || m.Nonce != n.wit.nonce {
		return
	}
	n.wit.nonce++ // single use
	d := berkeley.EstimateOffset(n.wit.t1, n.deps.Clock.Now(), m.Time)
	if abs(d) <= n.cfg.SuspectThresholdUs {
		n.wit.failures = 0
		return
	}
	n.wit.failures++
	n.logf("witness: offset to slave %d is %dus (> %dus), failure %d/%d",
		from, d, n.cfg.SuspectThresholdUs, n.wit.failures, n.cfg.SuspectAfter)
	if n.wit.failures >= n.cfg.SuspectAfter && n.wit.suspected != n.pbft.View()+1 {
		n.wit.failures = 0
		n.wit.suspected = n.pbft.View() + 1
		n.event("witness_suspect", fmt.Sprintf("view=%d peer=%d offset_us=%d", n.pbft.View(), from, d))
		n.logf("witness: slaves are being desynchronised: SUSPECT master %d", n.pbft.Primary())
		n.pbft.SuspectPrimary()
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

// ============================================================ callbacks ==

func (n *Node) onNewView(view uint64, primary uint32) {
	n.event("new_view", fmt.Sprintf("view=%d primary=%d", view, primary))
	n.cur = nil
	n.pending = map[uint64]*slaveRound{}
	if primary == n.cfg.ID {
		n.logf("elected MASTER for view %d", view)
		n.nextRoundAt = time.Now() // start immediately
		if n.cfg.RekeyOnLeaderChange {
			// Spec: leader change -> fresh hybrid handshake with the new primary.
			for id := range n.deps.Verifiers {
				if id != n.cfg.ID && !n.pbft.IsExcluded(id) {
					n.sess.Rekey(id)
				}
			}
		}
	}
}

func (n *Node) onExclude(id uint32, ev bft.Evidence) {
	n.event("excluded", fmt.Sprintf("accused=%d kind=%d", id, ev.Kind))
	if r := n.cur; r != nil {
		delete(r.contribs, id)
		delete(r.waitingOpen, id)
	}
}

func (n *Node) onHandshake(ev session.HandshakeEvent) {
	if n.deps.Recorder == nil || !ev.Initiator {
		return // record each handshake once, on the initiator side
	}
	n.deps.Recorder.Handshake(metrics.HandshakeRecord{
		At: time.Now(), Node: n.cfg.ID, Peer: ev.Peer, Initiator: ev.Initiator,
		Suite: n.cfg.Suite.String(), DurationMs: float64(ev.Result.Duration.Microseconds()) / 1000,
		BytesSent: ev.Result.BytesSent, BytesRecv: ev.Result.BytesReceived,
	})
}

func (n *Node) recordProof(kind string, d time.Duration, size int) {
	if n.deps.Recorder != nil {
		n.deps.Recorder.Proof(metrics.ProofRecord{Node: n.cfg.ID, Kind: kind, DurationMs: float64(d.Microseconds()) / 1000, SizeBytes: size})
	}
}

// ==================================================== PBFT integration ==

// app adapts the node to bft.App.
type app Node

func (a *app) Validate(primary uint32, seq uint64, payload []byte) error {
	n := (*Node)(a)
	var p berkeley.Proposal
	if err := wire.Unmarshal(payload, &p); err != nil {
		return fmt.Errorf("undecodable proposal: %w", err)
	}
	if p.Round != seq {
		return fmt.Errorf("proposal round %d != seq %d", p.Round, seq)
	}
	if !n.cfg.Berkeley.ZKP {
		// The leader is the reference clock: its own offset must be 0.
		for _, r := range p.Readings {
			if r.NodeID == p.Leader && r.Offset != 0 {
				return fmt.Errorf("leader reading has non-zero offset")
			}
		}
	}
	start := time.Now()
	err := n.val.ValidateProposal(&p)
	if n.cfg.Berkeley.ZKP {
		n.recordProof("agg_verify", time.Since(start), len(p.AggProof))
	}
	return err
}

func (a *app) Execute(seq, view uint64, payload []byte) { (*Node)(a).execute(seq, view, payload) }

func (a *app) VerifyEvidence(data []byte) (uint32, bool) {
	n := (*Node)(a)
	var r berkeley.Reading
	if wire.Unmarshal(data, &r) != nil {
		return 0, false
	}
	return r.NodeID, n.val.IsProvablyBad(&r)
}

// outbound adapts the session manager to bft.Outbound.
type outbound Node

func (o *outbound) Send(to uint32, t wire.AppType, body []byte) { (*Node)(o).sess.Send(to, t, body) }

// SortedIDs is a small helper for deterministic iteration.
func SortedIDs(m map[uint32]identity.Verifier) []uint32 {
	ids := make([]uint32, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
