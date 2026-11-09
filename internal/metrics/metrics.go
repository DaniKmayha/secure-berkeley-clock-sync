// Package metrics records raw measurements during an experiment and writes
// them as CSV (raw data is kept separate from plots and from the report, as
// required by the study guide). It also computes p50/p95/p99 summaries.
package metrics

import (
	"encoding/csv"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"
)

// RoundRecord: one node applying one committed Berkeley round.
type RoundRecord struct {
	At        time.Time
	Node      uint32
	Round     uint64
	View      uint64
	Leader    uint32
	MeanUs    int64 // committed average offset w.r.t. the leader
	AdjustUs  int64 // adjustment applied by this node
	Readings  int
	Included  int
	LatencyMs float64 // leader only: Poll -> Execute (0 for slaves)
}

// HandshakeRecord: one completed handshake (cold-start cost).
type HandshakeRecord struct {
	At         time.Time
	Node, Peer uint32
	Initiator  bool
	Suite      string
	DurationMs float64
	BytesSent  int
	BytesRecv  int
}

// ProofRecord: one ZKP operation.
type ProofRecord struct {
	Node       uint32
	Kind       string // range_prove, range_verify, agg_prove, agg_verify
	DurationMs float64
	SizeBytes  int
}

// SpreadSample: ground-truth synchronisation quality at one instant.
type SpreadSample struct {
	At        time.Time
	SpreadUs  int64   // max - min clock among honest nodes
	OffsetsUs []int64 // each honest node's clock - real time
}

// Event: a security / fault event (exclusion, view change, rejection...).
type Event struct {
	At     time.Time
	Node   uint32
	Kind   string
	Detail string
}

// Recorder is safe for concurrent use.
type Recorder struct {
	mu         sync.Mutex
	Start      time.Time
	Rounds     []RoundRecord
	Handshakes []HandshakeRecord
	Proofs     []ProofRecord
	Spread     []SpreadSample
	Events     []Event
}

// NewRecorder creates an empty recorder.
func NewRecorder() *Recorder { return &Recorder{Start: time.Now()} }

func (r *Recorder) Round(x RoundRecord)         { r.mu.Lock(); r.Rounds = append(r.Rounds, x); r.mu.Unlock() }
func (r *Recorder) Handshake(x HandshakeRecord) { r.mu.Lock(); r.Handshakes = append(r.Handshakes, x); r.mu.Unlock() }
func (r *Recorder) Proof(x ProofRecord)         { r.mu.Lock(); r.Proofs = append(r.Proofs, x); r.mu.Unlock() }
func (r *Recorder) Sample(x SpreadSample)       { r.mu.Lock(); r.Spread = append(r.Spread, x); r.mu.Unlock() }
func (r *Recorder) Event(node uint32, kind, detail string) {
	r.mu.Lock()
	r.Events = append(r.Events, Event{At: time.Now(), Node: node, Kind: kind, Detail: detail})
	r.mu.Unlock()
}

// Read runs fn while holding the recorder lock, so an observer (the GUI) can
// look at the tables while the experiment keeps appending to them.
// fn must not keep references to the slices after it returns.
func (r *Recorder) Read(fn func(r *Recorder)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	fn(r)
}

// CountEvents returns how many events of a kind were recorded.
func (r *Recorder) CountEvents(kind string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.Events {
		if e.Kind == kind {
			n++
		}
	}
	return n
}

// ------------------------------------------------------------ summaries ---

// Summary holds central tendency and tail percentiles.
type Summary struct {
	N             int
	Mean, StdDev  float64
	P50, P95, P99 float64
	Min, Max      float64
}

// Summarize computes a Summary (nearest-rank percentiles).
func Summarize(xs []float64) Summary {
	s := Summary{N: len(xs)}
	if len(xs) == 0 {
		return s
	}
	v := append([]float64(nil), xs...)
	sort.Float64s(v)
	var sum float64
	for _, x := range v {
		sum += x
	}
	s.Mean = sum / float64(len(v))
	for _, x := range v {
		s.StdDev += (x - s.Mean) * (x - s.Mean)
	}
	s.StdDev = math.Sqrt(s.StdDev / float64(len(v)))
	pct := func(p float64) float64 {
		i := int(math.Ceil(p*float64(len(v)))) - 1
		if i < 0 {
			i = 0
		}
		return v[i]
	}
	s.P50, s.P95, s.P99 = pct(0.50), pct(0.95), pct(0.99)
	s.Min, s.Max = v[0], v[len(v)-1]
	return s
}

func (s Summary) String() string {
	return fmt.Sprintf("n=%d mean=%.3f sd=%.3f p50=%.3f p95=%.3f p99=%.3f min=%.3f max=%.3f",
		s.N, s.Mean, s.StdDev, s.P50, s.P95, s.P99, s.Min, s.Max)
}

// ------------------------------------------------------------------ CSV ---

func writeCSV(path string, header []string, rows [][]string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	if err := w.Write(header); err != nil {
		return err
	}
	if err := w.WriteAll(rows); err != nil {
		return err
	}
	w.Flush()
	return w.Error()
}

func ms(t, start time.Time) string { return strconv.FormatFloat(float64(t.Sub(start).Microseconds())/1000, 'f', 3, 64) }
func f3(x float64) string          { return strconv.FormatFloat(x, 'f', 3, 64) }
func i64(x int64) string           { return strconv.FormatInt(x, 10) }
func u64(x uint64) string          { return strconv.FormatUint(x, 10) }

// WriteCSV dumps every table into dir with the given file prefix.
func (r *Recorder) WriteCSV(dir, prefix string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := func(name string) string { return filepath.Join(dir, prefix+"_"+name+".csv") }

	var rows [][]string
	for _, x := range r.Rounds {
		rows = append(rows, []string{ms(x.At, r.Start), u64(uint64(x.Node)), u64(x.Round), u64(x.View), u64(uint64(x.Leader)),
			i64(x.MeanUs), i64(x.AdjustUs), strconv.Itoa(x.Readings), strconv.Itoa(x.Included), f3(x.LatencyMs)})
	}
	if err := writeCSV(p("rounds"), []string{"t_ms", "node", "round", "view", "leader", "mean_us", "adjust_us", "readings", "included", "round_latency_ms"}, rows); err != nil {
		return err
	}

	rows = nil
	for _, x := range r.Handshakes {
		rows = append(rows, []string{ms(x.At, r.Start), u64(uint64(x.Node)), u64(uint64(x.Peer)), strconv.FormatBool(x.Initiator), x.Suite,
			f3(x.DurationMs), strconv.Itoa(x.BytesSent), strconv.Itoa(x.BytesRecv)})
	}
	if err := writeCSV(p("handshakes"), []string{"t_ms", "node", "peer", "initiator", "suite", "duration_ms", "bytes_sent", "bytes_recv"}, rows); err != nil {
		return err
	}

	rows = nil
	for _, x := range r.Proofs {
		rows = append(rows, []string{u64(uint64(x.Node)), x.Kind, f3(x.DurationMs), strconv.Itoa(x.SizeBytes)})
	}
	if err := writeCSV(p("zkp"), []string{"node", "kind", "duration_ms", "size_bytes"}, rows); err != nil {
		return err
	}

	rows = nil
	for _, x := range r.Spread {
		row := []string{ms(x.At, r.Start), i64(x.SpreadUs)}
		for _, o := range x.OffsetsUs {
			row = append(row, i64(o))
		}
		rows = append(rows, row)
	}
	hdr := []string{"t_ms", "spread_us"}
	if len(r.Spread) > 0 {
		for i := range r.Spread[0].OffsetsUs {
			hdr = append(hdr, fmt.Sprintf("honest%d_offset_us", i))
		}
	}
	if err := writeCSV(p("spread"), hdr, rows); err != nil {
		return err
	}

	rows = nil
	for _, x := range r.Events {
		rows = append(rows, []string{ms(x.At, r.Start), u64(uint64(x.Node)), x.Kind, x.Detail})
	}
	return writeCSV(p("events"), []string{"t_ms", "node", "kind", "detail"}, rows)
}
