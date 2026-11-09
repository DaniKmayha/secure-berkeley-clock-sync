package bft

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/wire"
)

// App is the replicated application (here: the Berkeley protocol).
type App interface {
	// Validate must be deterministic and independent of local state:
	// every honest replica must return the same verdict for the same bytes.
	Validate(primary uint32, seq uint64, payload []byte) error
	// Execute is called once per committed sequence number, in increasing
	// order (gaps allowed).
	Execute(seq, view uint64, payload []byte)
	// VerifyEvidence checks application-level evidence and returns the accused node.
	VerifyEvidence(data []byte) (accused uint32, ok bool)
}

// Outbound sends a consensus message to one replica over its secure session.
type Outbound interface {
	Send(to uint32, t wire.AppType, body []byte)
}

// Config of the engine.
type Config struct {
	Self      uint32
	N, F      int
	Signer    identity.Signer
	Verifiers map[uint32]identity.Verifier
	// ProgressTimeout: a backup that sees no execution for this long suspects
	// the primary and starts a view change.
	ProgressTimeout time.Duration
	// ViewChangeTimeout: initial timeout for a view change to complete
	// (doubles on every consecutive failure, as in PBFT).
	ViewChangeTimeout time.Duration
	// OnNewView is called when the replica enters a new view.
	OnNewView func(view uint64, primary uint32)
	// OnExclude is called when a node becomes provably Byzantine.
	OnExclude func(id uint32, ev Evidence)
	Logf      func(format string, args ...any)
}

// Stats are counters for the BFT metrics (message count, commits, ...).
type Stats struct {
	PrePreparesSent atomic.Uint64
	PreparesSent    atomic.Uint64
	CommitsSent     atomic.Uint64
	ViewChangesSent atomic.Uint64
	NewViews        atomic.Uint64
	Executed        atomic.Uint64
	Rejected        atomic.Uint64 // invalid proposals
}

type slot struct{ view, seq uint64 }

type entry struct {
	pp         *PrePrepare
	digest     []byte
	prepares   map[uint32][]byte
	commits    map[uint32][]byte
	sentCommit bool
	executed   bool
}

type queued struct {
	from uint32
	t    wire.AppType
	body []byte
}

// Engine is a single PBFT replica. Not goroutine-safe (owned by the node loop).
type Engine struct {
	cfg Config
	app App
	out Outbound

	view         uint64
	inViewChange bool
	targetView   uint64
	vcStarted    time.Time
	vcTimeout    time.Duration
	lastProgress time.Time

	log          map[slot]*entry
	headers      map[slot]SignedHeader // first signed header seen per (v, s)
	prepared     map[uint64]PrePrepare // seq -> prepared, not yet executed
	lastExecuted uint64

	vcVotes  map[uint64]map[uint32]ViewChange
	future   []queued
	excluded map[uint32]Evidence

	Stats Stats
}

// New creates a replica in view 0.
func New(cfg Config, app App, out Outbound) *Engine {
	if cfg.Logf == nil {
		cfg.Logf = func(string, ...any) {}
	}
	if cfg.ProgressTimeout == 0 {
		cfg.ProgressTimeout = 5 * time.Second
	}
	if cfg.ViewChangeTimeout == 0 {
		cfg.ViewChangeTimeout = 3 * time.Second
	}
	return &Engine{
		cfg: cfg, app: app, out: out,
		vcTimeout: cfg.ViewChangeTimeout, lastProgress: time.Now(),
		log: map[slot]*entry{}, headers: map[slot]SignedHeader{}, prepared: map[uint64]PrePrepare{},
		vcVotes: map[uint64]map[uint32]ViewChange{}, excluded: map[uint32]Evidence{},
	}
}

// ------------------------------------------------------------ queries ---

func (e *Engine) View() uint64         { return e.view }
func (e *Engine) InViewChange() bool   { return e.inViewChange }
func (e *Engine) LastExecuted() uint64 { return e.lastExecuted }
func (e *Engine) PrimaryOf(v uint64) uint32 {
	return uint32(v % uint64(e.cfg.N))
}
func (e *Engine) Primary() uint32  { return e.PrimaryOf(e.view) }
func (e *Engine) IsPrimary() bool  { return !e.inViewChange && e.Primary() == e.cfg.Self }
func (e *Engine) quorum() int      { return 2*e.cfg.F + 1 }
func (e *Engine) IsExcluded(id uint32) bool {
	_, ok := e.excluded[id]
	return ok
}

// Excluded returns a copy of the excluded set.
func (e *Engine) Excluded() []uint32 {
	ids := make([]uint32, 0, len(e.excluded))
	for id := range e.excluded {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

// nextEligible returns the smallest view > v whose primary is not excluded.
// This IS the leader-election rule: round-robin that skips provably
// Byzantine nodes.
func (e *Engine) nextEligible(v uint64) uint64 {
	for c := v + 1; c <= v+uint64(e.cfg.N)+1; c++ {
		if !e.IsExcluded(e.PrimaryOf(c)) {
			return c
		}
	}
	return v + 1 // everyone excluded: impossible with <= f Byzantine
}

func (e *Engine) broadcast(t wire.AppType, body []byte) {
	for id := 0; id < e.cfg.N; id++ {
		if uint32(id) != e.cfg.Self {
			e.out.Send(uint32(id), t, body)
		}
	}
}

func (e *Engine) getEntry(v, s uint64) *entry {
	k := slot{v, s}
	en := e.log[k]
	if en == nil {
		en = &entry{prepares: map[uint32][]byte{}, commits: map[uint32][]byte{}}
		e.log[k] = en
	}
	return en
}

// ----------------------------------------------------------- proposing ---

// Propose starts consensus on payload for sequence seq (primary only).
func (e *Engine) Propose(seq uint64, payload []byte) error {
	return e.ProposeTo(seq, payload, nil)
}

// ProposeTo is Propose restricted to some backups. targets == nil means
// everyone. Only used to emulate an EQUIVOCATING Byzantine primary.
func (e *Engine) ProposeTo(seq uint64, payload []byte, targets []uint32) error {
	if !e.IsPrimary() {
		return errors.New("bft: not the primary")
	}
	if seq <= e.lastExecuted {
		return fmt.Errorf("bft: seq %d already executed", seq)
	}
	pp, err := e.makePrePrepare(e.view, seq, payload)
	if err != nil {
		return err
	}
	body := wire.Marshal(pp)
	if targets == nil {
		e.broadcast(wire.AppPrePrepare, body)
	} else {
		for _, t := range targets {
			e.out.Send(t, wire.AppPrePrepare, body)
		}
	}
	e.Stats.PrePreparesSent.Add(1)
	en := e.getEntry(e.view, seq)
	if en.pp == nil {
		en.pp, en.digest = pp, pp.Signed.Header.Digest
		e.headers[slot{e.view, seq}] = pp.Signed
	}
	e.checkProgress(e.view, seq)
	return nil
}

func (e *Engine) makePrePrepare(view, seq uint64, payload []byte) (*PrePrepare, error) {
	h := Header{View: view, Seq: seq, Digest: Digest(payload), Primary: e.cfg.Self}
	sig, err := e.cfg.Signer.Sign(h.signedBytes())
	if err != nil {
		return nil, err
	}
	return &PrePrepare{Signed: SignedHeader{Header: h, Signature: sig}, Payload: payload}, nil
}

func (e *Engine) verifyHeader(sh SignedHeader) bool {
	v, ok := e.cfg.Verifiers[sh.Header.Primary]
	return ok && sh.Header.Primary == e.PrimaryOf(sh.Header.View) && v.Verify(sh.Header.signedBytes(), sh.Signature)
}

// ------------------------------------------------------------ handling ---

// Handle processes one consensus message from replica `from` (already
// authenticated and decrypted by the session layer).
func (e *Engine) Handle(from uint32, t wire.AppType, body []byte) {
	switch t {
	case wire.AppPrePrepare:
		var pp PrePrepare
		if wire.Unmarshal(body, &pp) == nil {
			e.handlePrePrepare(from, &pp, body)
		}
	case wire.AppPrepare:
		var p Prepare
		if wire.Unmarshal(body, &p) == nil {
			e.handlePrepare(from, &p, body)
		}
	case wire.AppCommit:
		var c Commit
		if wire.Unmarshal(body, &c) == nil {
			e.handleCommit(from, &c, body)
		}
	case wire.AppViewChange:
		var vc ViewChange
		if wire.Unmarshal(body, &vc) == nil {
			e.handleViewChange(from, &vc)
		}
	case wire.AppNewView:
		var nv NewView
		if wire.Unmarshal(body, &nv) == nil {
			e.handleNewView(from, &nv)
		}
	case wire.AppEvidence:
		var ev Evidence
		if wire.Unmarshal(body, &ev) == nil {
			e.AddEvidence(ev)
		}
	}
}

// deferIfFuture buffers messages for a view we have not entered yet.
func (e *Engine) deferIfFuture(view uint64, from uint32, t wire.AppType, body []byte) bool {
	if view > e.view || (view == e.view && e.inViewChange) {
		if len(e.future) < 1024 {
			e.future = append(e.future, queued{from, t, body})
		}
		return true
	}
	return false
}

func (e *Engine) handlePrePrepare(from uint32, pp *PrePrepare, raw []byte) {
	h := pp.Signed.Header
	if e.deferIfFuture(h.View, from, wire.AppPrePrepare, raw) || h.View < e.view {
		return
	}
	if from != h.Primary || !e.verifyHeader(pp.Signed) || !bytes.Equal(h.Digest, Digest(pp.Payload)) {
		return // not attributable: drop silently
	}
	if !e.checkEquivocation(pp.Signed) {
		return
	}
	if h.Seq <= e.lastExecuted {
		return // stale
	}
	en := e.getEntry(h.View, h.Seq)
	if en.pp != nil {
		return // already accepted one for this slot
	}
	// Independent validation BEFORE prepare (spec: backups verify independently).
	if err := e.app.Validate(h.Primary, h.Seq, pp.Payload); err != nil {
		e.Stats.Rejected.Add(1)
		e.cfg.Logf("rejecting proposal v=%d s=%d from %d: %v", h.View, h.Seq, h.Primary, err)
		e.AddEvidence(Evidence{Kind: EvBadProposal, Accused: h.Primary, A: raw})
		return
	}
	en.pp, en.digest = pp, h.Digest
	prep := Prepare{Replica: e.cfg.Self, Signed: pp.Signed}
	body := wire.Marshal(prep)
	en.prepares[e.cfg.Self] = h.Digest
	e.broadcast(wire.AppPrepare, body)
	e.Stats.PreparesSent.Add(1)
	e.checkProgress(h.View, h.Seq)
}

// checkEquivocation remembers the first signed header per slot and raises
// evidence if a conflicting one shows up. Returns false on conflict.
func (e *Engine) checkEquivocation(sh SignedHeader) bool {
	k := slot{sh.Header.View, sh.Header.Seq}
	prev, ok := e.headers[k]
	if !ok {
		e.headers[k] = sh
		return true
	}
	if bytes.Equal(prev.Header.Digest, sh.Header.Digest) {
		return true
	}
	e.AddEvidence(Evidence{Kind: EvEquivocation, Accused: sh.Header.Primary,
		A: wire.Marshal(prev), B: wire.Marshal(sh)})
	return false
}

func (e *Engine) handlePrepare(from uint32, p *Prepare, raw []byte) {
	h := p.Signed.Header
	if e.deferIfFuture(h.View, from, wire.AppPrepare, raw) || h.View < e.view {
		return
	}
	if p.Replica != from || from == h.Primary || !e.verifyHeader(p.Signed) {
		return
	}
	if !e.checkEquivocation(p.Signed) {
		return
	}
	en := e.getEntry(h.View, h.Seq)
	if _, dup := en.prepares[from]; dup {
		return
	}
	en.prepares[from] = h.Digest
	e.checkProgress(h.View, h.Seq)
}

func (e *Engine) handleCommit(from uint32, c *Commit, raw []byte) {
	if e.deferIfFuture(c.View, from, wire.AppCommit, raw) || c.View < e.view {
		return
	}
	if c.Replica != from {
		return
	}
	en := e.getEntry(c.View, c.Seq)
	if _, dup := en.commits[from]; dup {
		return
	}
	en.commits[from] = c.Digest
	e.checkProgress(c.View, c.Seq)
}

func countMatching(m map[uint32][]byte, d []byte, exclude uint32, excludeSet bool) int {
	n := 0
	for id, x := range m {
		if excludeSet && id == exclude {
			continue
		}
		if bytes.Equal(x, d) {
			n++
		}
	}
	return n
}

// checkProgress advances an entry through prepared -> committed -> executed.
func (e *Engine) checkProgress(v, s uint64) {
	en := e.log[slot{v, s}]
	if en == nil || en.pp == nil || en.executed {
		return
	}
	primary := en.pp.Signed.Header.Primary
	// prepared: pre-prepare + 2f PREPAREs from distinct backups (ours included)
	if !en.sentCommit && countMatching(en.prepares, en.digest, primary, true) >= 2*e.cfg.F {
		en.sentCommit = true
		e.prepared[s] = *en.pp
		c := Commit{View: v, Seq: s, Digest: en.digest, Replica: e.cfg.Self}
		en.commits[e.cfg.Self] = en.digest
		e.broadcast(wire.AppCommit, wire.Marshal(c))
		e.Stats.CommitsSent.Add(1)
	}
	// committed-local: prepared + 2f+1 matching COMMITs
	if en.sentCommit && countMatching(en.commits, en.digest, 0, false) >= e.quorum() {
		en.executed = true
		if s > e.lastExecuted {
			e.lastExecuted = s
			e.lastProgress = time.Now()
			e.vcTimeout = e.cfg.ViewChangeTimeout
			for seq := range e.prepared {
				if seq <= s {
					delete(e.prepared, seq)
				}
			}
			e.Stats.Executed.Add(1)
			e.app.Execute(s, v, en.pp.Payload)
		}
		e.gc()
	}
}

// gc drops log entries that can no longer matter.
func (e *Engine) gc() {
	for k := range e.log {
		if k.seq+8 < e.lastExecuted || k.view+2 < e.view {
			delete(e.log, k)
		}
	}
	for k := range e.headers {
		if k.seq+64 < e.lastExecuted {
			delete(e.headers, k)
		}
	}
}

// ------------------------------------------------------------ evidence ---

func (e *Engine) verifyEvidence(ev *Evidence) bool {
	switch ev.Kind {
	case EvBadProposal:
		var pp PrePrepare
		if wire.Unmarshal(ev.A, &pp) != nil || !e.verifyHeader(pp.Signed) ||
			pp.Signed.Header.Primary != ev.Accused || !bytes.Equal(pp.Signed.Header.Digest, Digest(pp.Payload)) {
			return false
		}
		// The proposal is signed by the accused AND fails deterministic validation.
		return e.app.Validate(ev.Accused, pp.Signed.Header.Seq, pp.Payload) != nil
	case EvEquivocation:
		var a, b SignedHeader
		if wire.Unmarshal(ev.A, &a) != nil || wire.Unmarshal(ev.B, &b) != nil {
			return false
		}
		return a.Header.Primary == ev.Accused && b.Header.Primary == ev.Accused &&
			a.Header.View == b.Header.View && a.Header.Seq == b.Header.Seq &&
			!bytes.Equal(a.Header.Digest, b.Header.Digest) &&
			e.verifyHeader(a) && e.verifyHeader(b)
	case EvApp:
		accused, ok := e.app.VerifyEvidence(ev.A)
		return ok && accused == ev.Accused
	}
	return false
}

// AddEvidence verifies, records and gossips evidence. If the accused is the
// current primary, a view change starts immediately.
func (e *Engine) AddEvidence(ev Evidence) {
	if e.IsExcluded(ev.Accused) || int(ev.Accused) >= e.cfg.N || !e.verifyEvidence(&ev) {
		return
	}
	// Never exclude more than f nodes: beyond f the BFT model gives no guarantee anyway.
	if len(e.excluded) >= e.cfg.F {
		e.cfg.Logf("evidence against %d ignored: already %d excluded (f=%d)", ev.Accused, len(e.excluded), e.cfg.F)
		return
	}
	e.excluded[ev.Accused] = ev
	e.cfg.Logf("node %d EXCLUDED from leader election (evidence kind %d)", ev.Accused, ev.Kind)
	if e.cfg.OnExclude != nil {
		e.cfg.OnExclude(ev.Accused, ev)
	}
	e.broadcast(wire.AppEvidence, wire.Marshal(ev))
	switch {
	case !e.inViewChange && e.Primary() == ev.Accused:
		e.startViewChange(e.nextEligible(e.view))
	case e.inViewChange && e.IsExcluded(e.PrimaryOf(e.targetView)):
		e.startViewChange(e.nextEligible(e.targetView))
	}
}

// --------------------------------------------------------- view change ---

// Tick drives the timeouts.
func (e *Engine) Tick(now time.Time) {
	if e.inViewChange {
		if now.Sub(e.vcStarted) > e.vcTimeout {
			e.vcTimeout *= 2 // exponential back-off (PBFT liveness)
			e.startViewChange(e.nextEligible(e.targetView))
		}
		return
	}
	if e.Primary() != e.cfg.Self && now.Sub(e.lastProgress) > e.cfg.ProgressTimeout {
		e.cfg.Logf("no progress for %v: suspecting primary %d", now.Sub(e.lastProgress), e.Primary())
		e.startViewChange(e.nextEligible(e.view))
	}
}

// SuspectPrimary lets the application trigger a view change (e.g. the
// master sent an inconsistent Adjust). Unprovable, so no exclusion.
func (e *Engine) SuspectPrimary() {
	if !e.inViewChange {
		e.startViewChange(e.nextEligible(e.view))
	}
}

func (e *Engine) startViewChange(target uint64) {
	e.inViewChange = true
	e.targetView = target
	e.vcStarted = time.Now()
	vc := ViewChange{NewView: target, Replica: e.cfg.Self, LastExecuted: e.lastExecuted}
	for _, pp := range e.prepared {
		if pp.Signed.Header.Seq > e.lastExecuted {
			vc.Prepared = append(vc.Prepared, pp)
		}
	}
	sort.Slice(vc.Prepared, func(i, j int) bool { return vc.Prepared[i].Signed.Header.Seq < vc.Prepared[j].Signed.Header.Seq })
	for _, ev := range e.excluded {
		vc.Evidence = append(vc.Evidence, ev)
	}
	sig, err := e.cfg.Signer.Sign(vc.signedBytes())
	if err != nil {
		return
	}
	vc.Signature = sig
	e.cfg.Logf("VIEW-CHANGE -> view %d (primary %d)", target, e.PrimaryOf(target))
	e.Stats.ViewChangesSent.Add(1)
	e.recordVC(vc)
	e.broadcast(wire.AppViewChange, wire.Marshal(vc))
}

func (e *Engine) verifyVC(vc *ViewChange) bool {
	v, ok := e.cfg.Verifiers[vc.Replica]
	return ok && v.Verify(vc.signedBytes(), vc.Signature)
}

func (e *Engine) recordVC(vc ViewChange) {
	m := e.vcVotes[vc.NewView]
	if m == nil {
		m = map[uint32]ViewChange{}
		e.vcVotes[vc.NewView] = m
	}
	m[vc.Replica] = vc
	e.maybeSendNewView(vc.NewView)
}

func (e *Engine) handleViewChange(from uint32, vc *ViewChange) {
	if vc.Replica != from || vc.NewView <= e.view || !e.verifyVC(vc) {
		return
	}
	// Merge the sender's evidence first: it may change who is eligible.
	for _, ev := range vc.Evidence {
		e.AddEvidence(ev)
	}
	e.recordVC(*vc)

	// PBFT "f+1" rule: if f+1 replicas want a higher view, at least one
	// honest replica does, so join instead of waiting for our own timeout.
	if !e.inViewChange || vc.NewView > e.targetView {
		wanting := map[uint32]bool{}
		minTarget := uint64(0)
		for v, votes := range e.vcVotes {
			if v <= e.view || e.IsExcluded(e.PrimaryOf(v)) {
				continue
			}
			for id := range votes {
				wanting[id] = true
			}
			if minTarget == 0 || v < minTarget {
				minTarget = v
			}
		}
		if len(wanting) >= e.cfg.F+1 && minTarget > 0 && (!e.inViewChange || minTarget > e.targetView) {
			e.startViewChange(minTarget)
		}
	}
}

// maybeSendNewView: the designated primary of v, holding 2f+1 VIEW-CHANGEs,
// installs the view.
func (e *Engine) maybeSendNewView(v uint64) {
	if e.PrimaryOf(v) != e.cfg.Self || v <= e.view || e.IsExcluded(e.cfg.Self) {
		return
	}
	votes := e.vcVotes[v]
	if len(votes) < e.quorum() {
		return
	}
	nv := NewView{View: v, Primary: e.cfg.Self}
	ids := make([]uint32, 0, len(votes))
	for id := range votes {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	best := map[uint64]PrePrepare{}
	for _, id := range ids[:e.quorum()] {
		vc := votes[id]
		nv.ViewChanges = append(nv.ViewChanges, vc)
		for _, pp := range vc.Prepared {
			s := pp.Signed.Header.Seq
			if cur, ok := best[s]; !ok || pp.Signed.Header.View > cur.Signed.Header.View {
				best[s] = pp
			}
		}
	}
	seqs := make([]uint64, 0, len(best))
	for s := range best {
		seqs = append(seqs, s)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	for _, s := range seqs {
		if s <= e.lastExecuted {
			continue
		}
		old := best[s]
		if e.app.Validate(old.Signed.Header.Primary, s, old.Payload) != nil {
			continue
		}
		pp, err := e.makePrePrepare(v, s, old.Payload)
		if err == nil {
			nv.ReProposals = append(nv.ReProposals, *pp)
		}
	}
	sig, err := e.cfg.Signer.Sign(nv.signedBytes())
	if err != nil {
		return
	}
	nv.Signature = sig
	e.broadcast(wire.AppNewView, wire.Marshal(nv))
	e.enterView(&nv)
}

func (e *Engine) handleNewView(from uint32, nv *NewView) {
	if nv.View <= e.view || nv.Primary != from || nv.Primary != e.PrimaryOf(nv.View) {
		return
	}
	v, ok := e.cfg.Verifiers[nv.Primary]
	if !ok || !v.Verify(nv.signedBytes(), nv.Signature) {
		return
	}
	// Certificate: 2f+1 distinct, valid VIEW-CHANGEs for exactly this view.
	seen := map[uint32]bool{}
	for i := range nv.ViewChanges {
		vc := &nv.ViewChanges[i]
		if vc.NewView != nv.View || seen[vc.Replica] || !e.verifyVC(vc) {
			return
		}
		seen[vc.Replica] = true
		for _, ev := range vc.Evidence {
			e.AddEvidence(ev)
		}
	}
	if len(seen) < e.quorum() || e.IsExcluded(nv.Primary) {
		return
	}
	e.enterView(nv)
}

func (e *Engine) enterView(nv *NewView) {
	e.view = nv.View
	e.inViewChange = false
	e.lastProgress = time.Now()
	for v := range e.vcVotes {
		if v <= e.view {
			delete(e.vcVotes, v)
		}
	}
	e.Stats.NewViews.Add(1)
	e.cfg.Logf("entered view %d, primary %d", e.view, e.Primary())
	if e.cfg.OnNewView != nil {
		e.cfg.OnNewView(e.view, e.Primary())
	}
	// Re-proposals are processed like normal PRE-PREPAREs of the new view.
	for i := range nv.ReProposals {
		pp := nv.ReProposals[i]
		if pp.Signed.Header.Primary == e.cfg.Self {
			en := e.getEntry(e.view, pp.Signed.Header.Seq)
			en.pp, en.digest = &pp, pp.Signed.Header.Digest
			e.headers[slot{e.view, pp.Signed.Header.Seq}] = pp.Signed
			continue
		}
		e.handlePrePrepare(pp.Signed.Header.Primary, &pp, wire.Marshal(pp))
	}
	// Replay messages that arrived early for this view.
	q := e.future
	e.future = nil
	for _, m := range q {
		e.Handle(m.from, m.t, m.body)
	}
}
