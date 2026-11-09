package zkp

import (
	"bytes"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	nativemimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/logger"
)

var curve = ecc.BN254

// gnark logs every proof at debug level; timings are recorded by our own
// metrics instead, so silence it.
func init() { logger.Disable() }

// ErrInvalidProof is returned for any proof that does not verify.
var ErrInvalidProof = errors.New("zkp: invalid proof")

// Params are the compiled circuits and Groth16 keys for an n-node cluster.
// The proving keys are needed by provers (slaves: range, master: aggregate);
// every replica needs the verifying keys.
type Params struct {
	N int

	RangeCS constraint.ConstraintSystem
	RangePK groth16.ProvingKey
	RangeVK groth16.VerifyingKey

	AggCS constraint.ConstraintSystem
	AggPK groth16.ProvingKey
	AggVK groth16.VerifyingKey

	SetupTime time.Duration
}

// Constraints reports circuit sizes (thesis metric "constraints/circuit size").
func (p *Params) Constraints() (rangeC, aggC int) {
	return p.RangeCS.GetNbConstraints(), p.AggCS.GetNbConstraints()
}

// Setup compiles both circuits and runs a LOCAL Groth16 setup.
// Prototype only: whoever runs this knows the toxic waste.
func Setup(n int) (*Params, error) {
	start := time.Now()
	p := &Params{N: n}
	var err error
	if p.RangeCS, err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, &RangeCircuit{}); err != nil {
		return nil, fmt.Errorf("compile range circuit: %w", err)
	}
	if p.RangePK, p.RangeVK, err = groth16.Setup(p.RangeCS); err != nil {
		return nil, err
	}
	if p.AggCS, err = frontend.Compile(curve.ScalarField(), r1cs.NewBuilder, NewAggregateCircuit(n)); err != nil {
		return nil, fmt.Errorf("compile aggregate circuit: %w", err)
	}
	if p.AggPK, p.AggVK, err = groth16.Setup(p.AggCS); err != nil {
		return nil, err
	}
	p.SetupTime = time.Since(start)
	return p, nil
}

// --------------------------------------------------------- commitments ---

// Shift maps an offset d in [-L, L] to e = d + L in [0, 2L].
func Shift(d, bound int64) uint64 { return uint64(d + bound) }

// Unshift is the inverse of Shift.
func Unshift(e uint64, bound int64) int64 { return int64(e) - bound }

// NewBlinding returns a uniformly random field element (as 32 bytes).
func NewBlinding() []byte {
	var r fr.Element
	if _, err := r.SetRandom(); err != nil {
		panic(err)
	}
	b := r.Bytes()
	return b[:]
}

func elem(v uint64) fr.Element {
	var x fr.Element
	x.SetUint64(v)
	return x
}

// Commit computes C = MiMC(e, r, round, nodeID) natively, exactly matching
// the in-circuit computation. Returns the 32-byte big-endian encoding.
func Commit(e uint64, r []byte, round uint64, nodeID uint32) ([]byte, error) {
	var re fr.Element
	if err := re.SetBytesCanonical(r); err != nil {
		return nil, fmt.Errorf("zkp: blinding is not a canonical field element: %w", err)
	}
	h := nativemimc.NewMiMC()
	for _, x := range []fr.Element{elem(e), re, elem(round), elem(uint64(nodeID))} {
		b := x.Bytes()
		h.Write(b[:])
	}
	return h.Sum(nil), nil
}

func toBig(b []byte) *big.Int { return new(big.Int).SetBytes(b) }

// ------------------------------------------------------------- range ---

// ProveRange proves that the commitment opens to e <= 2L.
func (p *Params) ProveRange(e uint64, r, commitment []byte, round uint64, nodeID uint32, bound int64) ([]byte, error) {
	assignment := &RangeCircuit{
		Commitment: toBig(commitment), Round: round, NodeID: uint64(nodeID), Bound: uint64(2 * bound),
		E: e, R: toBig(r),
	}
	w, err := frontend.NewWitness(assignment, curve.ScalarField())
	if err != nil {
		return nil, err
	}
	proof, err := groth16.Prove(p.RangeCS, p.RangePK, w)
	if err != nil {
		return nil, fmt.Errorf("zkp: range prove: %w", err)
	}
	var buf bytes.Buffer
	if _, err := proof.WriteTo(&buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// VerifyRange checks a range proof against public inputs only.
func (p *Params) VerifyRange(proofBytes, commitment []byte, round uint64, nodeID uint32, bound int64) error {
	proof := groth16.NewProof(curve)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return ErrInvalidProof
	}
	pub := &RangeCircuit{Commitment: toBig(commitment), Round: round, NodeID: uint64(nodeID), Bound: uint64(2 * bound)}
	w, err := frontend.NewWitness(pub, curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return ErrInvalidProof
	}
	if err := groth16.Verify(proof, p.RangeVK, w); err != nil {
		return ErrInvalidProof
	}
	return nil
}

// ---------------------------------------------------------- aggregate ---

// AggInput is one slot of the aggregation (the master knows all openings).
type AggInput struct {
	Present    bool // this node's reading is in the proposal
	Included   bool // kept by the median-band filter
	Commitment []byte
	E          uint64
	R          []byte
}

// AggRule holds the public parameters of the fault-tolerant average that
// the aggregation circuit enforces (see berkeley.FTFilter).
type AggRule struct {
	Band    uint64 // median band (µs)
	MinKeep uint64 // n - f: below this many in-band readings, keep all
	Half    uint64 // L: the shifted value of offset 0
	Leader  uint32 // proposer, whose own reading must be offset 0
}

// MeanOf computes floor(sum/k) over included slots, the exact semantics
// enforced by the circuit.
func MeanOf(slots []AggInput) (mean uint64, rem uint64, count uint64) {
	var sum uint64
	for _, s := range slots {
		if s.Included {
			sum += s.E
			count++
		}
	}
	if count == 0 {
		return 0, 0, 0
	}
	return sum / count, sum % count, count
}

// lowerMedian returns the value at sorted index floor((k-1)/2) of the
// present slots, the slot holding it, and that index.
func lowerMedian(slots []AggInput) (med uint64, sel int, idx uint64) {
	var vals []uint64
	for _, s := range slots {
		if s.Present {
			vals = append(vals, s.E)
		}
	}
	if len(vals) == 0 {
		return 0, 0, 0
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	idx = uint64((len(vals) - 1) / 2)
	med = vals[idx]
	for i, s := range slots {
		if s.Present && s.E == med {
			return med, i, idx
		}
	}
	return med, 0, idx
}

func aggPublic(n int, round uint64, commitments [][]byte, present, included []bool, count, mean uint64, rule AggRule) *AggregateCircuit {
	c := NewAggregateCircuit(n)
	c.Round, c.Count, c.Mean = round, count, mean
	c.Band, c.MinKeep, c.Half, c.Leader = rule.Band, rule.MinKeep, rule.Half, uint64(rule.Leader)
	for i := 0; i < n; i++ {
		c.Commitments[i], c.Present[i], c.Included[i] = 0, 0, 0
		if present[i] {
			c.Present[i] = 1
			c.Commitments[i] = toBig(commitments[i])
		}
		if included[i] {
			c.Included[i] = 1
		}
	}
	return c
}

// ProveAggregate proves that the included set is the median-band filter of
// the present openings and that `mean` is their floor-average. It fails if
// the slots do not satisfy the rule (e.g. a hand-picked included set).
func (p *Params) ProveAggregate(round uint64, slots []AggInput, rule AggRule) (proof []byte, mean uint64, err error) {
	if len(slots) != p.N {
		return nil, 0, fmt.Errorf("zkp: expected %d slots, got %d", p.N, len(slots))
	}
	mean, rem, count := MeanOf(slots)
	if count == 0 {
		return nil, 0, errors.New("zkp: nothing to aggregate")
	}
	commitments := make([][]byte, p.N)
	present := make([]bool, p.N)
	included := make([]bool, p.N)
	for i, s := range slots {
		present[i], included[i] = s.Present, s.Included
		commitments[i] = s.Commitment
	}
	med, sel, idx := lowerMedian(slots)
	a := aggPublic(p.N, round, commitments, present, included, count, mean, rule)
	a.Rem, a.Med, a.MedIdx = rem, med, idx
	for i, s := range slots {
		a.E[i], a.R[i], a.MedSel[i] = 0, 0, 0
		if s.Present {
			a.E[i], a.R[i] = s.E, toBig(s.R)
		}
		if i == sel {
			a.MedSel[i] = 1
		}
	}
	w, err := frontend.NewWitness(a, curve.ScalarField())
	if err != nil {
		return nil, 0, err
	}
	pr, err := groth16.Prove(p.AggCS, p.AggPK, w)
	if err != nil {
		return nil, 0, fmt.Errorf("zkp: aggregate prove: %w", err)
	}
	var buf bytes.Buffer
	if _, err := pr.WriteTo(&buf); err != nil {
		return nil, 0, err
	}
	return buf.Bytes(), mean, nil
}

// VerifyAggregate checks the master's aggregation proof using public data
// only: the commitments of every reading in the proposal (present), the
// claimed included set, the mean and the averaging rule.
func (p *Params) VerifyAggregate(proofBytes []byte, round uint64, commitments [][]byte, present, included []bool, mean uint64, rule AggRule) error {
	if len(commitments) != p.N || len(present) != p.N || len(included) != p.N {
		return ErrInvalidProof
	}
	var count uint64
	for i, in := range included {
		if in && !present[i] {
			return ErrInvalidProof
		}
		if in {
			count++
		}
	}
	proof := groth16.NewProof(curve)
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return ErrInvalidProof
	}
	w, err := frontend.NewWitness(aggPublic(p.N, round, commitments, present, included, count, mean, rule), curve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		return ErrInvalidProof
	}
	if err := groth16.Verify(proof, p.AggVK, w); err != nil {
		return ErrInvalidProof
	}
	return nil
}

// ------------------------------------------------------- persistence ---

// Save writes the keys to dir (used by cmd/keygen for the Docker deployment,
// where all nodes must share the same setup).
func (p *Params) Save(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	write := func(name string, wt func(*os.File) error) error {
		f, err := os.Create(filepath.Join(dir, name))
		if err != nil {
			return err
		}
		defer f.Close()
		return wt(f)
	}
	steps := []struct {
		name string
		fn   func(*os.File) error
	}{
		{"range.ccs", func(f *os.File) error { _, err := p.RangeCS.WriteTo(f); return err }},
		{"range.pk", func(f *os.File) error { _, err := p.RangePK.WriteTo(f); return err }},
		{"range.vk", func(f *os.File) error { _, err := p.RangeVK.WriteTo(f); return err }},
		{"agg.ccs", func(f *os.File) error { _, err := p.AggCS.WriteTo(f); return err }},
		{"agg.pk", func(f *os.File) error { _, err := p.AggPK.WriteTo(f); return err }},
		{"agg.vk", func(f *os.File) error { _, err := p.AggVK.WriteTo(f); return err }},
	}
	for _, s := range steps {
		if err := write(s.name, s.fn); err != nil {
			return fmt.Errorf("zkp: save %s: %w", s.name, err)
		}
	}
	return os.WriteFile(filepath.Join(dir, "n.txt"), []byte(fmt.Sprint(p.N)), 0o644)
}

// Load reads keys written by Save.
func Load(dir string) (*Params, error) {
	nb, err := os.ReadFile(filepath.Join(dir, "n.txt"))
	if err != nil {
		return nil, err
	}
	p := &Params{}
	if _, err := fmt.Sscan(string(nb), &p.N); err != nil {
		return nil, err
	}
	p.RangeCS, p.AggCS = groth16.NewCS(curve), groth16.NewCS(curve)
	p.RangePK, p.AggPK = groth16.NewProvingKey(curve), groth16.NewProvingKey(curve)
	p.RangeVK, p.AggVK = groth16.NewVerifyingKey(curve), groth16.NewVerifyingKey(curve)
	files :=[]struct {
		name string
		fn   func(*os.File) error
	}{
		{"range.ccs", func(f *os.File) error { _, err := p.RangeCS.ReadFrom(f); return err }},
		{"range.pk", func(f *os.File) error { _, err := p.RangePK.ReadFrom(f); return err }},
		{"range.vk", func(f *os.File) error { _, err := p.RangeVK.ReadFrom(f); return err }},
		{"agg.ccs", func(f *os.File) error { _, err := p.AggCS.ReadFrom(f); return err }},
		{"agg.pk", func(f *os.File) error { _, err := p.AggPK.ReadFrom(f); return err }},
		{"agg.vk", func(f *os.File) error { _, err := p.AggVK.ReadFrom(f); return err }},
	}
	for _, s := range files {
		f, err := os.Open(filepath.Join(dir, s.name))
		if err != nil {
			return nil, err
		}
		err = s.fn(f)
		f.Close()
		if err != nil {
			return nil, fmt.Errorf("zkp: load %s: %w", s.name, err)
		}
	}
	return p, nil
}
