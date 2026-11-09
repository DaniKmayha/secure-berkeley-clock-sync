// Package zkp contains the zero-knowledge layer of the Berkeley protocol,
// implemented with gnark / Groth16 over BN254.
//
// Why ZKPs in a clock-synchronisation protocol?
//
// In classic Berkeley every participant reveals its clock offset to the
// master. In our design an offset is a private witness:
//
//   - each slave publishes only a COMMITMENT to its (shifted) offset and a
//     RANGE PROOF that the committed offset lies in [-L, +L]
//     (RangeCircuit). Backups therefore know that no slave can inject an
//     absurd value, without learning the value itself;
//   - the master, who receives the openings privately over its AES-GCM
//     sessions, publishes the average and an AGGREGATION PROOF that the
//     included set is exactly the median-band filter over ALL readings in
//     the proposal, that its own reading is offset 0, and that the average
//     really is floor(sum/k) of the included committed values
//     (AggregateCircuit). A Byzantine master therefore can neither push a
//     wrong average nor hand-pick which readings to average: every honest
//     backup verifies the proof. (It can still leave a reading out of the
//     proposal entirely, claiming it never arrived: the same as in plain
//     mode, bounded by needing n - f readings.)
//
// Encoding: an offset d in microseconds, |d| <= L, is shifted to
// e = d + L in [0, 2L] so that it is a small non-negative field element.
//
// Commitment: C = MiMC(e, r, round, nodeID) with a random blinding r.
// round/nodeID give domain separation, so a commitment from one round or one
// node can never be replayed as another.
//
// Limitation (spec §6, wording rules): Groth16 relies on classical pairing
// assumptions and on a trusted setup; this ZKP layer is NOT claimed to be
// post-quantum secure. In the prototype the setup is run locally (Setup) —
// a real deployment would need an MPC ceremony.
package zkp

import (
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/math/cmp"
)

// Bit widths used to bound values before comparisons. 40 bits of
// microseconds is ~12.7 days, far beyond any sensible L.
const (
	valueBits = 40
	remBits   = 16
)

// RangeCircuit proves knowledge of (e, r) such that
//
//	Commitment == MiMC(e, r, Round, NodeID)   and   0 <= e <= Bound (= 2L)
type RangeCircuit struct {
	Commitment frontend.Variable `gnark:",public"`
	Round      frontend.Variable `gnark:",public"`
	NodeID     frontend.Variable `gnark:",public"`
	Bound      frontend.Variable `gnark:",public"`

	E frontend.Variable // private: shifted offset
	R frontend.Variable // private: blinding factor
}

// Define declares the constraints.
func (c *RangeCircuit) Define(api frontend.API) error {
	// Bound e to valueBits first: AssertIsLessOrEqual is only meaningful for
	// values that cannot wrap around the field.
	api.ToBinary(c.E, valueBits)
	api.AssertIsLessOrEqual(c.E, c.Bound)

	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	h.Write(c.E, c.R, c.Round, c.NodeID)
	api.AssertIsEqual(h.Sum(), c.Commitment)
	return nil
}

// AggregateCircuit proves, over the readings the master put in its proposal,
// that the published average was computed exactly like berkeley.FTFilter +
// FloorMean, without revealing any offset:
//
//  1. every PRESENT slot opens its public commitment: C_i = MiMC(e_i, r_i, round, i);
//  2. Med is the lower median of the present e_i (the value at sorted index
//     m = floor((k-1)/2), k = number of present slots);
//  3. the INCLUDED set is exactly the median-band filter:
//     included_i = present_i AND (|e_i - Med| <= Band), unless fewer than
//     MinKeep readings survive, in which case every present reading is
//     included (the same fallback as FTFilter);
//  4. Mean = floor( sum_{included} e_i / Count );
//  5. the leader's own reading is offset 0 (e_Leader = Half = L): the master
//     is the reference clock, so its offset to itself is 0 by definition.
//
// Without 2-3 a Byzantine master could choose which in-range readings to
// average (e.g. keep its own fake +L reading) and still produce a valid
// proof; without 5 it could report its own offset as anything in ±L.
//
// The circuit has one slot per node (N fixed at compile time).
type AggregateCircuit struct {
	Commitments []frontend.Variable `gnark:",public"`
	Present     []frontend.Variable `gnark:",public"` // reading of node i is in the proposal
	Included    []frontend.Variable `gnark:",public"`
	Round       frontend.Variable   `gnark:",public"`
	Count       frontend.Variable   `gnark:",public"`
	Mean        frontend.Variable   `gnark:",public"`
	Band        frontend.Variable   `gnark:",public"` // median band, µs
	MinKeep     frontend.Variable   `gnark:",public"` // n - f
	Half        frontend.Variable   `gnark:",public"` // L (shifted value of offset 0)
	Leader      frontend.Variable   `gnark:",public"`

	E      []frontend.Variable // private openings
	R      []frontend.Variable // private blindings
	Rem    frontend.Variable   // private: sum - Count*Mean, in [0, Count)
	Med    frontend.Variable   // private: lower median of the present e_i
	MedSel []frontend.Variable // private: one-hot, which present slot holds Med
	MedIdx frontend.Variable   // private: m = floor((k-1)/2)
}

// NewAggregateCircuit allocates the slots for an n-node cluster.
func NewAggregateCircuit(n int) *AggregateCircuit {
	return &AggregateCircuit{
		Commitments: make([]frontend.Variable, n),
		Present:     make([]frontend.Variable, n),
		Included:    make([]frontend.Variable, n),
		E:           make([]frontend.Variable, n),
		R:           make([]frontend.Variable, n),
		MedSel:      make([]frontend.Variable, n),
	}
}

// Define declares the constraints.
func (c *AggregateCircuit) Define(api frontend.API) error {
	h, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	// Every compared quantity is < 2^41 in absolute value (values are
	// 40-bit), so a bounded comparator with this bound is sound and cheap.
	bc := cmp.NewBoundedComparator(api, new(big.Int).Lsh(big.NewInt(1), valueBits+2), false)

	api.ToBinary(c.Band, valueBits)
	api.ToBinary(c.Half, valueBits)
	api.ToBinary(c.Med, valueBits)

	n := len(c.Commitments)
	k := frontend.Variable(0)
	selSum := frontend.Variable(0)
	leaderSum := frontend.Variable(0)
	for i := 0; i < n; i++ {
		api.AssertIsBoolean(c.Present[i])
		api.AssertIsBoolean(c.Included[i])
		api.AssertIsBoolean(c.MedSel[i])
		api.ToBinary(c.E[i], valueBits) // keep sums/differences far from field overflow

		// (1) commitment binding for every present slot.
		h.Reset()
		h.Write(c.E[i], c.R[i], c.Round, i)
		api.AssertIsEqual(api.Mul(c.Present[i], api.Sub(h.Sum(), c.Commitments[i])), 0)

		k = api.Add(k, c.Present[i])

		// Med is the value of a present slot.
		api.AssertIsEqual(api.Mul(c.MedSel[i], api.Sub(1, c.Present[i])), 0)
		api.AssertIsEqual(api.Mul(c.MedSel[i], api.Sub(c.E[i], c.Med)), 0)
		selSum = api.Add(selSum, c.MedSel[i])

		// (5) the leader's slot is present and holds offset 0.
		isLeader := api.IsZero(api.Sub(c.Leader, i))
		leaderSum = api.Add(leaderSum, isLeader)
		api.AssertIsEqual(api.Mul(isLeader, api.Sub(1, c.Present[i])), 0)
		api.AssertIsEqual(api.Mul(isLeader, api.Sub(c.E[i], c.Half)), 0)
	}
	api.AssertIsEqual(selSum, 1)
	api.AssertIsEqual(leaderSum, 1) // Leader is a valid slot index

	// (2) lower median: m = floor((k-1)/2)  <=>  k-1-2m in {0,1};
	// #(e_j < Med) <= m  and  #(e_j <= Med) >= m+1  pins Med to sorted[m].
	api.ToBinary(c.MedIdx, 8)
	t := api.Sub(api.Sub(k, 1), api.Mul(2, c.MedIdx))
	api.AssertIsBoolean(t)
	lt, le := frontend.Variable(0), frontend.Variable(0)
	inBand := make([]frontend.Variable, n)
	kept := frontend.Variable(0)
	for i := 0; i < n; i++ {
		lt = api.Add(lt, api.Mul(c.Present[i], bc.IsLess(c.E[i], c.Med)))
		le = api.Add(le, api.Mul(c.Present[i], bc.IsLessEq(c.E[i], c.Med)))
		// (3) |e_i - Med| <= Band
		inBand[i] = api.Mul(bc.IsLessEq(c.E[i], api.Add(c.Med, c.Band)), bc.IsLessEq(c.Med, api.Add(c.E[i], c.Band)))
		kept = api.Add(kept, api.Mul(c.Present[i], inBand[i]))
	}
	bc.AssertIsLessEq(lt, c.MedIdx)
	bc.AssertIsLessEq(api.Add(c.MedIdx, 1), le)

	fallback := bc.IsLess(kept, c.MinKeep)
	sum := frontend.Variable(0)
	count := frontend.Variable(0)
	for i := 0; i < n; i++ {
		// included = present AND (inBand OR fallback)
		orv := api.Sub(api.Add(inBand[i], fallback), api.Mul(inBand[i], fallback))
		api.AssertIsEqual(c.Included[i], api.Mul(c.Present[i], orv))
		sum = api.Add(sum, api.Mul(c.Included[i], c.E[i]))
		count = api.Add(count, c.Included[i])
	}
	api.AssertIsEqual(count, c.Count)

	// (4) sum == Count*Mean + Rem with 0 <= Rem < Count  <=>  Mean = floor(sum/Count)
	api.ToBinary(c.Mean, valueBits)
	api.ToBinary(c.Rem, remBits)
	api.AssertIsEqual(sum, api.Add(api.Mul(c.Count, c.Mean), c.Rem))
	bc.AssertIsLessEq(api.Add(c.Rem, 1), c.Count)
	return nil
}
