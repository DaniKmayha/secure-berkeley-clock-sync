// Package berkeley contains the deterministic core of the secure Berkeley
// clock-synchronisation protocol: message formats, offset estimation,
// fault-tolerant averaging, proposal construction and proposal validation.
//
// It contains no networking and no timers (those live in package node), so
// every function here is easy to unit-test and — crucially — validation is
// a pure function of the proposal bytes and static configuration. That is
// what allows PBFT backups to agree on accept/reject and lets a signed
// invalid proposal serve as transferable evidence against a Byzantine master.
//
// One synchronisation round r (master M = current PBFT primary):
//
//  1. M -> all   Poll{r, view}
//  2. S -> M     TimeReq{r}                     (S records local t1)
//  3. M -> S     TimeResp{r, T_M}               (M's clock when replying)
//  4. S          t2 = now;  d_S = (t1+t2)/2 - T_M   (Cristian estimate of
//                S's offset w.r.t. M; error <= RTT/2), clamp to [-L, L]
//  5. S -> M     Reading{r, view, S, C_S = Commit(d_S+L, r_S), RangeProof, sig_S}
//                Opening{r, d_S+L, r_S}  (private, only to M, inside AES-GCM)
//     (plain mode: Reading carries d_S in clear instead of C_S/proof)
//  6. M          fault-tolerant average over the readings: drop readings
//                farther than Band from the median, A = floor(mean(d))
//                ZKP mode: AggregateProof that A matches the commitments
//  7. M -> PBFT  Proposal{r, readings, included set, A, aggProof}
//  8. every replica validates the proposal independently, PBFT commits it
//  9. every node i applies  adj_i = A - d_i   (speed up if > 0, slow down if < 0)
//     and M also sends Adjust{r, adj_i} to each slave as in classic Berkeley;
//     a slave cross-checks it against the committed value.
//
// Threat-model notes (documented limitations):
//   - A Byzantine slave can choose any d in [-L, L]; the range proof bounds
//     its influence on A to at most f*2L/k, and the median band filter
//     removes it entirely in practice.
//   - The median-band filter is enforced for EVERY master, not just honest
//     ones: plain mode recomputes it, ZKP mode proves it in the aggregation
//     circuit over all readings in the proposal. The leader's own reading
//     must be offset 0 in both modes (it is the reference clock).
//   - A Byzantine master cannot commit a wrong A (aggregation proof /
//     deterministic recomputation, checked by >= 2f+1 replicas), cannot
//     hand-pick which readings are averaged, and cannot forge/alter readings
//     (slave signatures). It CAN leave a reading out of the proposal
//     altogether (claiming it never arrived), as long as n - f remain; this
//     is indistinguishable from network loss. It CAN also lie in TimeResp, which
//     biases a slave's own estimate by at most L per round. This is inherent
//     to Berkeley, where the master's clock is the reference; it cannot be
//     proven to third parties. Mitigation: the slave-to-slave witness check
//     (PeerTimeReq) detects the resulting desynchronisation and the honest
//     slaves force a view change away from that master.
package berkeley

import (
	"errors"
	"fmt"
	"sort"

	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/wire"
	"secure-distributed-system/internal/zkp"
)

// Config holds the static protocol parameters. All replicas must use the
// same values (they are part of the "frozen configuration" of an experiment).
type Config struct {
	N     int   // number of nodes
	F     int   // tolerated Byzantine nodes, N >= 3F+1
	Bound int64 // L: maximum |offset| accepted in one round (µs)
	Band  int64 // fault-tolerant averaging band around the median (µs)
	ZKP   bool  // commitments + range/aggregation proofs (C4/C5) vs plain offsets
}

// MinReadings is the minimum number of readings a proposal must average.
// With N-F readings at least N-2F >= F+1 of them come from honest nodes.
func (c Config) MinReadings() int { return c.N - c.F }

// aggRule is the averaging rule the aggregation proof enforces; it must
// match FTFilter / FloorMean exactly.
func (c Config) aggRule(leader uint32) zkp.AggRule {
	return zkp.AggRule{Band: uint64(c.Band), MinKeep: uint64(c.MinReadings()), Half: uint64(c.Bound), Leader: leader}
}

// ------------------------------------------------------------ messages ---

type Poll struct {
	Round uint64 `cbor:"1,keyasint"`
	View  uint64 `cbor:"2,keyasint"`
}

// TimeReq / TimeResp are repeated K times per round; the slave keeps the
// sample with the smallest round-trip time (NTP-style filtering): queuing
// and scheduling delays only ever ADD to the RTT, so the fastest exchange
// has the most symmetric delays and the smallest Cristian error.
type TimeReq struct {
	Round  uint64 `cbor:"1,keyasint"`
	Sample uint8  `cbor:"2,keyasint"`
}

type TimeResp struct {
	Round      uint64 `cbor:"1,keyasint"`
	Sample     uint8  `cbor:"2,keyasint"`
	MasterTime int64  `cbor:"3,keyasint"` // µs, master's local clock
}

// PeerTimeReq / PeerTimeResp implement the slave-to-slave WITNESS check.
// After a committed round all honest clocks should agree; a slave measures
// its offset to a neighbouring slave and, if it stays above a threshold for
// several rounds, the master must have fed different slaves inconsistent
// reference times (the "lying master" attack). This is not transferable
// evidence, so it triggers a view change (suspicion) but not an exclusion.
type PeerTimeReq struct {
	Nonce uint64 `cbor:"1,keyasint"`
}

type PeerTimeResp struct {
	Nonce uint64 `cbor:"1,keyasint"`
	Time  int64  `cbor:"2,keyasint"`
}

// Reading is a slave's signed contribution to one round.
type Reading struct {
	Round  uint64 `cbor:"1,keyasint"`
	View   uint64 `cbor:"2,keyasint"`
	NodeID uint32 `cbor:"3,keyasint"`
	// Plain mode: the offset itself (µs). Zero in ZKP mode.
	Offset int64 `cbor:"4,keyasint"`
	// ZKP mode: commitment to e = d + L and a Groth16 range proof.
	Commitment []byte `cbor:"5,keyasint,omitempty"`
	RangeProof []byte `cbor:"6,keyasint,omitempty"`
	Clamped    bool   `cbor:"7,keyasint"`
	Signature  []byte `cbor:"8,keyasint"`
}

// SignedBytes is the canonical encoding covered by the reading signature.
func (r Reading) SignedBytes() []byte {
	r.Signature = nil
	return append([]byte("berkeley-reading|"), wire.Marshal(r)...)
}

// Opening reveals a commitment to the master only (sent inside AES-GCM).
type Opening struct {
	Round uint64 `cbor:"1,keyasint"`
	E     uint64 `cbor:"2,keyasint"`
	R     []byte `cbor:"3,keyasint"`
}

// Proposal is the payload the master submits to PBFT for one round.
type Proposal struct {
	Round    uint64    `cbor:"1,keyasint"`
	View     uint64    `cbor:"2,keyasint"`
	Leader   uint32    `cbor:"3,keyasint"`
	Readings []Reading `cbor:"4,keyasint"` // every valid reading received, sorted by NodeID
	Included []uint32  `cbor:"5,keyasint"` // readings used in the average, sorted
	Mean     int64     `cbor:"6,keyasint"` // A: average offset w.r.t. the leader clock (µs)
	AggProof []byte    `cbor:"7,keyasint,omitempty"`
}

// Adjust is the classic Berkeley instruction from master to slave.
type Adjust struct {
	Round   uint64 `cbor:"1,keyasint"`
	DeltaUs int64  `cbor:"2,keyasint"`
}

// --------------------------------------------------- offset estimation ---

// EstimateOffset is Cristian's estimate of (slave clock - master clock):
// the master's reading T_M is assumed to have been taken half-way between
// the slave's send time t1 and receive time t2.
func EstimateOffset(t1, t2, masterTime int64) int64 {
	return (t1+t2)/2 - masterTime
}

// Clamp limits d to [-L, L]. Honest slaves clamp so that they can always
// produce a valid range proof; a large offset is then corrected over
// several rounds.
func Clamp(d, bound int64) (int64, bool) {
	switch {
	case d > bound:
		return bound, true
	case d < -bound:
		return -bound, true
	}
	return d, false
}

// --------------------------------------------- fault-tolerant averaging ---

// FTFilter returns the ids whose offset lies within band of the median
// (lower median for even counts, so the result is deterministic). If fewer
// than minKeep values survive, it falls back to keeping everything.
func FTFilter(offsets map[uint32]int64, band int64, minKeep int) []uint32 {
	ids := make([]uint32, 0, len(offsets))
	vals := make([]int64, 0, len(offsets))
	for id, d := range offsets {
		ids = append(ids, id)
		vals = append(vals, d)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	if len(vals) == 0 {
		return nil
	}
	median := vals[(len(vals)-1)/2]
	var keep []uint32
	for _, id := range ids {
		d := offsets[id] - median
		if d < 0 {
			d = -d
		}
		if d <= band {
			keep = append(keep, id)
		}
	}
	if len(keep) < minKeep {
		return ids
	}
	return keep
}

// FloorMean is floor(sum/k) — the same rounding the aggregation circuit
// enforces (computed in shifted space so both modes round identically).
func FloorMean(offsets map[uint32]int64, ids []uint32, bound int64) int64 {
	var sum uint64
	for _, id := range ids {
		sum += zkp.Shift(offsets[id], bound)
	}
	return zkp.Unshift(sum/uint64(len(ids)), bound)
}

// --------------------------------------------------------- validation ---

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("berkeley: invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

// Validator checks readings and proposals. It is stateless apart from its
// static configuration, which makes its verdicts reproducible by anyone.
type Validator struct {
	Cfg       Config
	Verifiers map[uint32]identity.Verifier // every node's identity public key
	Params    *zkp.Params                  // nil in plain mode
}

// ValidateReading checks one signed reading on its own.
func (v *Validator) ValidateReading(r *Reading) error {
	ver, ok := v.Verifiers[r.NodeID]
	if !ok {
		return invalid("reading from unknown node %d", r.NodeID)
	}
	if !ver.Verify(r.SignedBytes(), r.Signature) {
		return invalid("bad signature on reading of node %d", r.NodeID)
	}
	if v.Cfg.ZKP {
		if len(r.Commitment) == 0 || len(r.RangeProof) == 0 || r.Offset != 0 {
			return invalid("node %d: malformed ZKP reading", r.NodeID)
		}
		if err := v.Params.VerifyRange(r.RangeProof, r.Commitment, r.Round, r.NodeID, v.Cfg.Bound); err != nil {
			return invalid("node %d: range proof: %v", r.NodeID, err)
		}
	} else if r.Offset > v.Cfg.Bound || r.Offset < -v.Cfg.Bound {
		return invalid("node %d: offset %d outside ±%d", r.NodeID, r.Offset, v.Cfg.Bound)
	}
	return nil
}

// IsProvablyBad reports whether a correctly signed reading is invalid — i.e.
// the signer provably misbehaved (evidence-grade).
func (v *Validator) IsProvablyBad(r *Reading) bool {
	ver, ok := v.Verifiers[r.NodeID]
	if !ok || !ver.Verify(r.SignedBytes(), r.Signature) {
		return false // not attributable to anyone
	}
	return v.ValidateReading(r) != nil
}

// ValidateProposal is executed by EVERY replica before PREPARE.
// It never depends on local state, so all honest replicas reach the same verdict.
func (v *Validator) ValidateProposal(p *Proposal) error {
	if len(p.Readings) > v.Cfg.N {
		return invalid("too many readings")
	}
	byID := map[uint32]*Reading{}
	var last int64 = -1
	for i := range p.Readings {
		r := &p.Readings[i]
		if int64(r.NodeID) <= last {
			return invalid("readings not sorted / duplicated")
		}
		last = int64(r.NodeID)
		if r.Round != p.Round || r.View != p.View {
			return invalid("reading of node %d is for another round/view", r.NodeID)
		}
		if err := v.ValidateReading(r); err != nil {
			return err
		}
		byID[r.NodeID] = r
	}
	if _, ok := byID[p.Leader]; !ok {
		return invalid("leader's own reading missing")
	}
	if len(p.Included) < v.Cfg.MinReadings() {
		return invalid("only %d readings included, need %d", len(p.Included), v.Cfg.MinReadings())
	}
	last = -1
	for _, id := range p.Included {
		if int64(id) <= last {
			return invalid("included set not sorted / duplicated")
		}
		last = int64(id)
		if _, ok := byID[id]; !ok {
			return invalid("included node %d has no reading", id)
		}
	}
	if p.Mean > v.Cfg.Bound || p.Mean < -v.Cfg.Bound {
		return invalid("mean out of range")
	}

	if v.Cfg.ZKP {
		// Backups cannot see the offsets: they check the aggregation proof,
		// which covers EVERY reading in the proposal (present), proves that
		// the included set is the median-band filter over them, that the
		// leader's own reading is offset 0, and that the mean is correct.
		comms := make([][]byte, v.Cfg.N)
		present := make([]bool, v.Cfg.N)
		inc := make([]bool, v.Cfg.N)
		for id, r := range byID {
			if int(id) >= v.Cfg.N {
				return invalid("node id out of range")
			}
			comms[id] = r.Commitment
			present[id] = true
		}
		for _, id := range p.Included {
			inc[id] = true
		}
		if err := v.Params.VerifyAggregate(p.AggProof, p.Round, comms, present, inc, zkp.Shift(p.Mean, v.Cfg.Bound), v.Cfg.aggRule(p.Leader)); err != nil {
			return invalid("aggregation proof: %v", err)
		}
		return nil
	}

	// Plain mode: the leader is the reference clock, so its own offset is 0.
	if byID[p.Leader].Offset != 0 {
		return invalid("leader's own reading is %d, must be 0", byID[p.Leader].Offset)
	}
	// Recompute the fault-tolerant average deterministically.
	offsets := map[uint32]int64{}
	for id, r := range byID {
		offsets[id] = r.Offset
	}
	want := FTFilter(offsets, v.Cfg.Band, v.Cfg.MinReadings())
	if !equalIDs(want, p.Included) {
		return invalid("included set %v differs from fault-tolerant filter %v", p.Included, want)
	}
	if m := FloorMean(offsets, want, v.Cfg.Bound); m != p.Mean {
		return invalid("mean %d differs from recomputed %d", p.Mean, m)
	}
	return nil
}

func equalIDs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------ construction ---

// Contribution is what the master holds for one received reading.
type Contribution struct {
	Reading Reading
	Offset  int64  // known to the master (plain: from reading; ZKP: from opening)
	E       uint64 // ZKP opening
	R       []byte // ZKP blinding
}

// BuildProposal runs the fault-tolerant average and (in ZKP mode) the
// aggregation proof. contribs must contain the leader's own contribution.
func BuildProposal(cfg Config, params *zkp.Params, round, view uint64, leader uint32, contribs map[uint32]*Contribution) (*Proposal, error) {
	if len(contribs) < cfg.MinReadings() {
		return nil, fmt.Errorf("berkeley: only %d readings, need %d", len(contribs), cfg.MinReadings())
	}
	offsets := map[uint32]int64{}
	for id, c := range contribs {
		offsets[id] = c.Offset
	}
	included := FTFilter(offsets, cfg.Band, cfg.MinReadings())

	p := &Proposal{Round: round, View: view, Leader: leader, Included: included}
	ids := make([]uint32, 0, len(contribs))
	for id := range contribs {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		p.Readings = append(p.Readings, contribs[id].Reading)
	}

	if !cfg.ZKP {
		p.Mean = FloorMean(offsets, included, cfg.Bound)
		return p, nil
	}
	slots := make([]zkp.AggInput, cfg.N)
	for id, c := range contribs {
		slots[id] = zkp.AggInput{Present: true, Commitment: c.Reading.Commitment, E: c.E, R: c.R}
	}
	for _, id := range included {
		slots[id].Included = true
	}
	proof, mean, err := params.ProveAggregate(round, slots, cfg.aggRule(leader))
	if err != nil {
		return nil, err
	}
	p.AggProof = proof
	p.Mean = zkp.Unshift(mean, cfg.Bound)
	return p, nil
}

// MakeReading builds and signs a reading for offset d (already clamped).
// In ZKP mode it also returns the private opening for the master.
func MakeReading(cfg Config, params *zkp.Params, signer identity.Signer, round, view uint64, self uint32, d int64, clamped bool) (*Reading, *Opening, error) {
	r := &Reading{Round: round, View: view, NodeID: self, Clamped: clamped}
	var op *Opening
	if cfg.ZKP {
		e := zkp.Shift(d, cfg.Bound)
		blind := zkp.NewBlinding()
		c, err := zkp.Commit(e, blind, round, self)
		if err != nil {
			return nil, nil, err
		}
		proof, err := params.ProveRange(e, blind, c, round, self, cfg.Bound)
		if err != nil {
			return nil, nil, err
		}
		r.Commitment, r.RangeProof = c, proof
		op = &Opening{Round: round, E: e, R: blind}
	} else {
		r.Offset = d
	}
	sig, err := signer.Sign(r.SignedBytes())
	if err != nil {
		return nil, nil, err
	}
	r.Signature = sig
	return r, op, nil
}

// CheckOpening is run by the master on a slave's private opening.
func CheckOpening(cfg Config, r *Reading, op *Opening) error {
	if op.Round != r.Round || op.E > uint64(2*cfg.Bound) {
		return invalid("opening does not match round/range")
	}
	c, err := zkp.Commit(op.E, op.R, r.Round, r.NodeID)
	if err != nil {
		return invalid("opening: %v", err)
	}
	if string(c) != string(r.Commitment) {
		return invalid("opening does not match commitment")
	}
	return nil
}

// Adjustment for node i once proposal p is committed: adj_i = A - d_i.
func Adjustment(mean, ownOffset int64) int64 { return mean - ownOffset }
