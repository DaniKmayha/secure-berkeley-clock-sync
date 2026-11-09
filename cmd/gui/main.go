// Command gui is a graphical front-end for the secure Berkeley clock
// synchronisation experiments.
//
//	go run ./cmd/gui                 (or build it: go build -o BerkeleyGUI.exe ./cmd/gui)
//
// It starts a small web server on 127.0.0.1 and opens it in an app-style
// window (Microsoft Edge / Chrome "app mode", falling back to the default
// browser). Everything runs locally; the page needs no internet access.
//
// In the window you choose a configuration (C1..C5) and a fault scenario,
// press Start, and watch the cluster live: every node's ticking clock, the
// offset and spread charts, who the master is, view changes, exclusions,
// each committed round and the protocol log.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/cluster"
	"secure-distributed-system/internal/experiments"
	"secure-distributed-system/internal/metrics"
	"secure-distributed-system/internal/network"
	"secure-distributed-system/internal/zkp"
)

//go:embed web
var webFS embed.FS

// ------------------------------------------------------------- stream hub ---

// hub fans out JSON messages to every connected window (Server-Sent Events).
type hub struct {
	mu      sync.Mutex
	clients map[chan []byte]struct{}
}

func newHub() *hub { return &hub{clients: map[chan []byte]struct{}{}} }

func (h *hub) broadcast(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for c := range h.clients {
		select {
		case c <- b:
		default: // slow window: drop this frame rather than block the experiment
		}
	}
}

func (h *hub) serve(w http.ResponseWriter, r *http.Request, hello any) {
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	c := make(chan []byte, 64)
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	defer func() {
		h.mu.Lock()
		delete(h.clients, c)
		h.mu.Unlock()
	}()
	if b, err := json.Marshal(hello); err == nil {
		fmt.Fprintf(w, "data: %s\n\n", b)
		fl.Flush()
	}
	ping := time.NewTicker(15 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-c:
			fmt.Fprintf(w, "data: %s\n\n", b)
			fl.Flush()
		case <-ping.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

// ---------------------------------------------------------------- messages ---

// StartRequest is what the Start button sends.
type StartRequest struct {
	Config       string  `json:"config"`
	Scenario     string  `json:"scenario"`
	N            int     `json:"n"`
	DurationS    float64 `json:"duration_s"`
	IntervalMs   int     `json:"interval_ms"`
	LatencyMs    float64 `json:"latency_ms"`
	JitterMs     float64 `json:"jitter_ms"`
	InitOffsetMs float64 `json:"init_offset_ms"`
	DriftPPM     float64 `json:"drift_ppm"`
	Seed         uint64  `json:"seed"`
	// Behaviours is used when Scenario == "custom": node id (as a string,
	// JSON object keys) -> behaviour picked in the node builder.
	Behaviours map[string]byzantine.Behaviour `json:"behaviours"`
}

// customScenario builds a scenario from the node builder's choices.
func customScenario(n int, in map[string]byzantine.Behaviour) (experiments.Scenario, error) {
	sc := experiments.Scenario{Name: "custom", Behaviours: map[uint32]byzantine.Behaviour{}}
	var parts []string
	for k, b := range in {
		id, err := strconv.Atoi(k)
		if err != nil || id < 0 || id >= n {
			return sc, fmt.Errorf("custom scenario: node %q does not exist with n=%d", k, n)
		}
		if b.IsHonest() {
			continue
		}
		sc.Behaviours[uint32(id)] = b
	}
	ids := make([]int, 0, len(sc.Behaviours))
	for id := range sc.Behaviours {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	for _, id := range ids {
		parts = append(parts, fmt.Sprintf("node %d: %s", id, sc.Behaviours[uint32(id)]))
	}
	if len(parts) == 0 {
		sc.Description = "Custom: all nodes honest."
	} else {
		sc.Description = "Custom: " + strings.Join(parts, ", ") + "."
	}
	sc.Expected = "See the scenario explanation panel."
	return sc, nil
}

type nodeView struct {
	ID           uint32  `json:"id"`
	OffsetMs     float64 `json:"offset_ms"` // ground truth: clock - real time
	View         uint64  `json:"view"`
	Primary      uint32  `json:"primary"`
	LastRound    uint64  `json:"last_round"`
	InViewChange bool    `json:"in_view_change"`
	Behaviour    string  `json:"behaviour"`
	Crashed      bool    `json:"crashed"`
	Excluded     bool    `json:"excluded"` // excluded by the honest nodes
}

type roundView struct {
	Node      uint32  `json:"node"`
	Round     uint64  `json:"round"`
	View      uint64  `json:"view"`
	Leader    uint32  `json:"leader"`
	MeanMs    float64 `json:"mean_ms"`
	AdjustMs  float64 `json:"adjust_ms"`
	Readings  int     `json:"readings"`
	Included  int     `json:"included"`
	LatencyMs float64 `json:"latency_ms"`
	T         float64 `json:"t"`
}

type eventView struct {
	T      float64 `json:"t"`
	Node   uint32  `json:"node"`
	Kind   string  `json:"kind"`
	Detail string  `json:"detail"`
}

type statsView struct {
	Rounds        int     `json:"rounds"`
	Handshakes    int     `json:"handshakes"`
	HandshakeMs   float64 `json:"handshake_ms"`
	HandshakeB    int     `json:"handshake_bytes"`
	ProveMs       float64 `json:"prove_ms"`
	VerifyMs      float64 `json:"verify_ms"`
	AggProveMs    float64 `json:"agg_prove_ms"`
	RoundLatMs    float64 `json:"round_latency_ms"`
	KBPerNode     float64 `json:"kb_per_node"`
	ViewChanges   int     `json:"view_changes"`
	Exclusions    int     `json:"exclusions"`
	SessionReject uint64  `json:"session_rejects"`
}

type tickMsg struct {
	Type     string      `json:"type"` // "tick"
	T        float64     `json:"t"`
	SpreadMs float64     `json:"spread_ms"`
	Nodes    []nodeView  `json:"nodes"`
	Rounds   []roundView `json:"rounds"`
	Events   []eventView `json:"events"`
	Logs     []string    `json:"logs"`
	Stats    statsView   `json:"stats"`
}

// ------------------------------------------------------------------ runner ---

type runner struct {
	h *hub

	mu      sync.Mutex
	running bool
	stop    chan struct{}
	params  map[int]*zkp.Params // Groth16 setups cached per cluster size
	logBuf  []string
	outDir  string
}

func (rn *runner) status(state, text string) {
	rn.h.broadcast(map[string]any{"type": "status", "state": state, "text": text})
}

func (rn *runner) logf(format string, args ...any) {
	line := time.Now().Format("15:04:05.000 ") + fmt.Sprintf(format, args...)
	rn.mu.Lock()
	if len(rn.logBuf) < 500 {
		rn.logBuf = append(rn.logBuf, line)
	}
	rn.mu.Unlock()
}

func (rn *runner) takeLogs() []string {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	l := rn.logBuf
	rn.logBuf = nil
	return l
}

func (rn *runner) start(req StartRequest) error {
	cfg, err := experiments.FindConfig(req.Config)
	if err != nil {
		return err
	}
	if req.N != 4 && req.N != 7 {
		return fmt.Errorf("n must be 4 or 7")
	}
	var sc experiments.Scenario
	if req.Scenario == "custom" {
		sc, err = customScenario(req.N, req.Behaviours)
	} else {
		sc, err = experiments.FindScenario(req.Scenario)
	}
	if err != nil {
		return err
	}
	if req.DurationS < 3 || req.DurationS > 600 {
		return fmt.Errorf("duration must be between 3 and 600 s")
	}
	rn.mu.Lock()
	if rn.running {
		rn.mu.Unlock()
		return fmt.Errorf("an experiment is already running")
	}
	rn.running = true
	rn.stop = make(chan struct{})
	rn.mu.Unlock()

	o := cluster.Defaults()
	o.N = req.N
	if req.IntervalMs >= 200 {
		o.RoundInterval = time.Duration(req.IntervalMs) * time.Millisecond
		o.CollectTimeout = o.RoundInterval * 2 / 5
		o.SlewPeriod = o.RoundInterval / 4
	}
	o.Link = network.LinkConfig{
		BaseLatency: time.Duration(req.LatencyMs * float64(time.Millisecond)),
		Jitter:      time.Duration(req.JitterMs * float64(time.Millisecond)),
	}
	o.InitialOffsetUs = int64(req.InitOffsetMs * 1000)
	o.DriftPPM = req.DriftPPM
	if req.Seed != 0 {
		o.Seed = req.Seed
	}
	experiments.Apply(&o, cfg, sc)
	o.Logf = rn.logf

	go rn.run(o, cfg, sc, time.Duration(req.DurationS*float64(time.Second)))
	return nil
}

func (rn *runner) requestStop() {
	rn.mu.Lock()
	defer rn.mu.Unlock()
	if rn.running && rn.stop != nil {
		select {
		case <-rn.stop:
		default:
			close(rn.stop)
		}
	}
}

func (rn *runner) run(o cluster.Options, cfg experiments.Config, sc experiments.Scenario, d time.Duration) {
	defer func() {
		rn.mu.Lock()
		rn.running = false
		rn.mu.Unlock()
	}()
	if cfg.UsesZKP() {
		rn.mu.Lock()
		p := rn.params[o.N]
		rn.mu.Unlock()
		if p == nil {
			rn.status("setup", fmt.Sprintf("Running the Groth16 setup for n=%d (once)...", o.N))
			var err error
			if p, err = zkp.Setup(o.N); err != nil {
				rn.status("error", err.Error())
				return
			}
			rn.mu.Lock()
			rn.params[o.N] = p
			rn.mu.Unlock()
		}
		o.Params = p
	}
	rn.status("setup", "Generating identity keys and building the cluster...")
	c, err := cluster.Build(o)
	if err != nil {
		rn.status("error", err.Error())
		return
	}
	rn.takeLogs()
	rn.h.broadcast(map[string]any{"type": "started", "config": cfg, "scenario": sc, "n": o.N,
		"duration_s": d.Seconds(), "bound_ms": float64(o.BoundUs) / 1000, "suite": o.Suite.String()})
	rn.status("running", fmt.Sprintf("%s · %s", cfg.Name, sc.Name))

	c.Start()
	start := c.Rec.Start
	sample := time.NewTicker(100 * time.Millisecond)
	defer sample.Stop()
	end := time.After(d)
	sentRounds, sentEvents, tick := 0, 0, 0
	stopped := false

loop:
	for {
		select {
		case <-rn.stop:
			stopped = true
			break loop
		case <-end:
			break loop
		case <-sample.C:
			s := c.Sample()
			tick++
			if tick%2 == 0 {
				rn.h.broadcast(rn.snapshot(c, s, start, &sentRounds, &sentEvents))
			}
		}
	}
	c.Stop()
	s := c.Sample()
	rn.h.broadcast(rn.snapshot(c, s, start, &sentRounds, &sentEvents))

	// Keep the raw data, exactly like the command-line simulator.
	prefix := fmt.Sprintf("gui_%s_%s_%s", cfg.Name, sc.Name, time.Now().Format("20060102-150405"))
	saved := ""
	if err := c.Rec.WriteCSV(rn.outDir, prefix); err == nil {
		saved, _ = filepath.Abs(filepath.Join(rn.outDir, prefix+"_*.csv"))
	}
	text := "Finished"
	if stopped {
		text = "Stopped"
	}
	rn.h.broadcast(map[string]any{"type": "done", "stopped": stopped, "saved": saved})
	rn.status("done", text)
}

func ms(us int64) float64 { return float64(us) / 1000 }

// snapshot builds one live update (only NEW rounds/events since the last one).
func (rn *runner) snapshot(c *cluster.Cluster, s metrics.SpreadSample, start time.Time, sentRounds, sentEvents *int) tickMsg {
	// Empty (not nil) slices, so the page always receives JSON arrays.
	m := tickMsg{Type: "tick", T: s.At.Sub(start).Seconds(), SpreadMs: ms(s.SpreadUs), Logs: rn.takeLogs(),
		Rounds: []roundView{}, Events: []eventView{}}
	if m.Logs == nil {
		m.Logs = []string{}
	}

	excluded := map[uint32]bool{}
	for _, i := range c.Honest() {
		for _, id := range c.Nodes[i].Status().Excluded {
			excluded[id] = true
		}
	}
	for i, nd := range c.Nodes {
		st := nd.Status()
		b := c.Opts.Behaviours[uint32(i)]
		m.Nodes = append(m.Nodes, nodeView{
			ID: uint32(i), OffsetMs: ms(c.Clocks[i].OffsetFromReal()),
			View: st.View, Primary: st.Primary, LastRound: st.LastRound, InViewChange: st.InViewChange,
			Behaviour: b.String(), Crashed: b.Crash, Excluded: excluded[uint32(i)],
		})
	}

	var hsMs, rlat []float64
	prove, verify, agg := []float64{}, []float64{}, []float64{}
	c.Rec.Read(func(r *metrics.Recorder) {
		for _, x := range r.Rounds[*sentRounds:] {
			m.Rounds = append(m.Rounds, roundView{Node: x.Node, Round: x.Round, View: x.View, Leader: x.Leader,
				MeanMs: ms(x.MeanUs), AdjustMs: ms(x.AdjustUs), Readings: x.Readings, Included: x.Included,
				LatencyMs: x.LatencyMs, T: x.At.Sub(start).Seconds()})
		}
		*sentRounds = len(r.Rounds)
		for _, e := range r.Events[*sentEvents:] {
			m.Events = append(m.Events, eventView{T: e.At.Sub(start).Seconds(), Node: e.Node, Kind: e.Kind, Detail: e.Detail})
		}
		*sentEvents = len(r.Events)

		rounds := map[uint64]bool{}
		for _, x := range r.Rounds {
			rounds[x.Round] = true
			if x.LatencyMs > 0 {
				rlat = append(rlat, x.LatencyMs)
			}
		}
		m.Stats.Rounds = len(rounds)
		bytes := 0
		for _, h := range r.Handshakes {
			hsMs = append(hsMs, h.DurationMs)
			bytes += h.BytesSent + h.BytesRecv
		}
		m.Stats.Handshakes = len(r.Handshakes)
		if len(r.Handshakes) > 0 {
			m.Stats.HandshakeB = bytes / len(r.Handshakes)
		}
		for _, p := range r.Proofs {
			switch p.Kind {
			case "range_prove":
				prove = append(prove, p.DurationMs)
			case "range_verify", "agg_verify":
				verify = append(verify, p.DurationMs)
			case "agg_prove":
				agg = append(agg, p.DurationMs)
			}
		}
		honest := max(1, len(c.Honest()))
		vc, ex := 0, 0
		for _, e := range r.Events {
			switch e.Kind {
			case "new_view":
				vc++
			case "excluded":
				ex++
			}
		}
		m.Stats.ViewChanges = vc / honest
		m.Stats.Exclusions = (ex + honest - 1) / honest
	})
	m.Stats.HandshakeMs = metrics.Summarize(hsMs).P50
	m.Stats.ProveMs = metrics.Summarize(prove).P50
	m.Stats.VerifyMs = metrics.Summarize(verify).P50
	m.Stats.AggProveMs = metrics.Summarize(agg).P50
	m.Stats.RoundLatMs = metrics.Summarize(rlat).P50
	var total uint64
	for i := range c.Nodes {
		total += c.Net.BytesSent[i].Load()
		m.Stats.SessionReject += c.Nodes[i].Sessions().Stats.RejectedReplay.Load() + c.Nodes[i].Sessions().Stats.RejectedAEAD.Load()
	}
	m.Stats.KBPerNode = float64(total) / 1024 / float64(len(c.Nodes))
	return m
}

// -------------------------------------------------------------------- main ---

func openWindow(url string) {
	if runtime.GOOS == "windows" {
		// Prefer an app-style window (no tabs / address bar).
		for _, p := range []string{
			os.Getenv("ProgramFiles(x86)") + `\Microsoft\Edge\Application\msedge.exe`,
			os.Getenv("ProgramFiles") + `\Microsoft\Edge\Application\msedge.exe`,
			os.Getenv("ProgramFiles") + `\Google\Chrome\Application\chrome.exe`,
			os.Getenv("LocalAppData") + `\Google\Chrome\Application\chrome.exe`,
		} {
			if _, err := os.Stat(p); err == nil {
				if exec.Command(p, "--app="+url, "--window-size=1500,950").Start() == nil {
					return
				}
			}
		}
		_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		return
	}
	if runtime.GOOS == "darwin" {
		_ = exec.Command("open", url).Start()
		return
	}
	_ = exec.Command("xdg-open", url).Start()
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8765", "listen address (local only)")
	noOpen := flag.Bool("no-window", false, "do not open a window automatically")
	out := flag.String("out", "results", "directory for raw CSV results of each run")
	flag.Parse()

	h := newHub()
	rn := &runner{h: h, params: map[int]*zkp.Params{}, outDir: *out}

	web, _ := fs.Sub(webFS, "web")
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(web)))
	mux.HandleFunc("/api/meta", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Per-scenario behaviours (hidden from Scenario's JSON) so the node
		// builder can show which node does what in each preset.
		beh := map[string]map[uint32]byzantine.Behaviour{}
		for _, s := range experiments.Scenarios {
			beh[s.Name] = s.Behaviours
		}
		type cfgView struct {
			experiments.Config
			Hybrid   bool `json:"hybrid"`
			ZKP      bool `json:"zkp"`
			PerRound bool `json:"per_round"`
		}
		var cfgs []cfgView
		for _, c := range experiments.Configs {
			cfgs = append(cfgs, cfgView{c, c.Hybrid(), c.UsesZKP(), c.PerRound()})
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"configs": cfgs, "scenarios": experiments.Scenarios, "behaviours": beh})
	})
	mux.HandleFunc("/api/start", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		var req StartRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if err := rn.start(req); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/stop", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "POST only", http.StatusMethodNotAllowed)
			return
		}
		rn.requestStop()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/api/stream", func(w http.ResponseWriter, r *http.Request) {
		rn.mu.Lock()
		running := rn.running
		rn.mu.Unlock()
		h.serve(w, r, map[string]any{"type": "hello", "running": running})
	})

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		// Port busy (e.g. a second copy): take any free local port.
		if ln, err = net.Listen("tcp", "127.0.0.1:0"); err != nil {
			log.Fatal(err)
		}
	}
	url := "http://" + ln.Addr().String() + "/"
	fmt.Printf("Secure Berkeley GUI running at %s\n(close this window or press Ctrl+C to quit)\n", url)
	if !*noOpen {
		openWindow(url)
	}
	log.Fatal(http.Serve(ln, mux))
}
