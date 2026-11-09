 // Command simulate runs the secure Berkeley clock synchronisation on an
// in-process cluster and writes raw CSV results.
//
// Examples:
//
//	go run ./cmd/simulate                                  # C5, honest, 20 s
//	go run ./cmd/simulate -config C1 -duration 30s
//	go run ./cmd/simulate -scenario master-bad-average -v
//	go run ./cmd/simulate -all-configs                     # C1..C5, honest
//	go run ./cmd/simulate -all-scenarios -config C5        # security matrix
//
// Configurations (study guide §7, mapped onto the Berkeley use case):
//
//	C1 classical session (X25519+Ed25519), AES-GCM, PBFT, no ZKP
//	C2 naive hybrid: fresh X25519+ML-KEM-768+ML-DSA-65 handshake EVERY round
//	C3 hybrid session once, AES-GCM warm state, PBFT, no ZKP
//	C4 classical session + ZKP + PBFT
//	C5 hybrid session + ZKP + PBFT  (full proposed system)
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"secure-distributed-system/internal/cluster"
	"secure-distributed-system/internal/experiments"
	"secure-distributed-system/internal/metrics"
	"secure-distributed-system/internal/zkp"
)


func main() {
	var (
		config       = flag.String("config", "C5", "experiment configuration C1..C5")
		scenario     = flag.String("scenario", "honest", "fault scenario (see -list)")
		list         = flag.Bool("list", false, "list scenarios and exit")
		n            = flag.Int("n", 4, "number of nodes (n >= 3f+1)")
		duration     = flag.Duration("duration", 20*time.Second, "simulated run time")
		interval     = flag.Duration("interval", time.Second, "Berkeley round interval")
		bound        = flag.Int64("bound", 200_000, "L: max |offset| per round (µs)")
		band         = flag.Int64("band", 50_000, "fault-tolerant averaging band (µs)")
		initOff      = flag.Int64("init-offset", 150_000, "initial clock offsets in ±value (µs)")
		drift        = flag.Float64("drift", 200, "clock drift in ±ppm")
		latency      = flag.Duration("latency", 2*time.Millisecond, "one-way link latency")
		jitter       = flag.Duration("jitter", time.Millisecond, "link jitter")
		maxMsgs      = flag.Uint64("rekey-messages", 1000, "session rotation after N messages")
		seed         = flag.Uint64("seed", 1, "RNG seed for the clocks")
		out          = flag.String("out", "results", "output directory for CSV files")
		verbose      = flag.Bool("v", false, "verbose protocol log")
		allConfigs   = flag.Bool("all-configs", false, "run C1..C5 (honest) and print a comparison")
		allScenarios = flag.Bool("all-scenarios", false, "run every scenario with -config")
	)
	flag.Parse()
	log.SetFlags(log.Lmicroseconds)

	if *list {
		for _, s := range experiments.Scenarios {
			fmt.Printf("%-22s %s\n", s.Name, s.Description)
		}
		return
	}

	base := cluster.Defaults()
	base.N, base.BoundUs, base.BandUs = *n, *bound, *band
	base.InitialOffsetUs, base.DriftPPM, base.Seed = *initOff, *drift, *seed
	base.Link.BaseLatency, base.Link.Jitter = *latency, *jitter
	base.RoundInterval = *interval
	base.Policy.MaxMessages = *maxMsgs
	base.Verbose = *verbose

	// One Groth16 setup shared by all runs of this process.
	var params *zkp.Params
	getParams := func() *zkp.Params {
		if params == nil {
			p, err := zkp.Setup(*n)
			if err != nil {
				log.Fatal(err)
			}
			rc, ac := p.Constraints()
			fmt.Printf("Groth16 setup: %v (range circuit %d constraints, aggregate %d)\n", p.SetupTime.Round(time.Millisecond), rc, ac)
			params = p
		}
		return params
	}

	type job struct{ config, scenario string }
	var jobs []job
	switch {
	case *allConfigs:
		for _, c := range []string{"C1", "C2", "C3", "C4", "C5"} {
			jobs = append(jobs, job{c, *scenario})
		}
	case *allScenarios:
		for _, s := range experiments.ScenarioNames() {
			jobs = append(jobs, job{*config, s})
		}
	default:
		jobs = []job{{*config, *scenario}}
	}

	var summaries []string
	for _, j := range jobs {
		o := base
		cfg, err := experiments.FindConfig(j.config)
		if err != nil {
			log.Fatal(err)
		}
		sc, err := experiments.FindScenario(j.scenario)
		if err != nil {
			log.Fatalf("%v (use -list)", err)
		}
		experiments.Apply(&o, cfg, sc)
		j.config = cfg.Name
		if o.ZKP {
			o.Params = getParams()
		}
		summaries = append(summaries, run(o, j.config, j.scenario, *duration, *out))
	}
	if len(summaries) > 1 {
		fmt.Println("\n================ comparison ================")
		fmt.Printf("%-4s %-22s %7s %6s %5s %11s %11s %11s %10s\n", "cfg", "scenario", "rounds", "views", "excl", "spread_p50", "spread_p95", "round_p50", "KB/node")
		for _, s := range summaries {
			fmt.Println(s)
		}
	}
}

func run(o cluster.Options, cfgName, scenario string, d time.Duration, out string) string {
	fmt.Printf("\n=== %s | scenario=%s | suite=%s | zkp=%v | n=%d ===\n", cfgName, scenario, o.Suite, o.ZKP, o.N)
	c, err := cluster.Build(o)
	if err != nil {
		log.Fatal(err)
	}
	c.RunFor(d, 100*time.Millisecond)
	rec := c.Rec

	// --- synchronisation quality (ground truth) -------------------------
	var spreadAll, spreadTail []float64
	for i, s := range rec.Spread {
		spreadAll = append(spreadAll, float64(s.SpreadUs)/1000)
		if i >= len(rec.Spread)/2 {
			spreadTail = append(spreadTail, float64(s.SpreadUs)/1000)
		}
	}
	converged := "never"
	for _, s := range rec.Spread {
		if s.SpreadUs < 5_000 {
			converged = s.At.Sub(rec.Start).Round(10 * time.Millisecond).String()
			break
		}
	}
	initial := 0.0
	if len(spreadAll) > 0 {
		initial = spreadAll[0]
	}
	fmt.Printf("clock spread (honest nodes): initial %.2f ms, converged(<5ms) after %s\n", initial, converged)
	tail := metrics.Summarize(spreadTail)
	fmt.Printf("  spread, second half of run [ms]: %v\n", tail)

	// --- rounds / consensus --------------------------------------------
	rounds := map[uint64]bool{}
	var lat []float64
	maxView := uint64(0)
	for _, r := range rec.Rounds {
		rounds[r.Round] = true
		if r.LatencyMs > 0 {
			lat = append(lat, r.LatencyMs)
		}
		if r.View > maxView {
			maxView = r.View
		}
	}
	latS := metrics.Summarize(lat)
	fmt.Printf("committed rounds: %d, final view: %d, view changes entered: %d, exclusions: %d\n",
		len(rounds), maxView, rec.CountEvents("new_view")/max(1, len(c.Honest())), rec.CountEvents("excluded")/max(1, len(c.Honest())))
	fmt.Printf("  round latency Poll->commit [ms]: %v\n", latS)
	for i, nd := range c.Nodes {
		if ex := nd.PBFT().Excluded(); len(ex) > 0 && o.Behaviours[uint32(i)].IsHonest() {
			fmt.Printf("  node %d excluded set: %v\n", i, ex)
			break
		}
	}

	// --- control plane --------------------------------------------------
	var hs []float64
	hsBytes := 0
	for _, h := range rec.Handshakes {
		hs = append(hs, h.DurationMs)
		hsBytes += h.BytesSent + h.BytesRecv
	}
	fmt.Printf("handshakes: %d, latency [ms]: %v\n", len(hs), metrics.Summarize(hs))
	if len(hs) > 0 {
		fmt.Printf("  bytes per handshake (both directions): %d\n", hsBytes/len(hs))
	}

	// --- ZKP ------------------------------------------------------------
	if o.ZKP {
		byKind := map[string][]float64{}
		sizes := map[string]int{}
		for _, p := range rec.Proofs {
			byKind[p.Kind] = append(byKind[p.Kind], p.DurationMs)
			sizes[p.Kind] = p.SizeBytes
		}
		for _, k := range []string{"range_prove", "range_verify", "agg_prove", "agg_verify"} {
			s := metrics.Summarize(byKind[k])
			fmt.Printf("  zkp %-12s [ms] p50=%.2f p95=%.2f p99=%.2f (n=%d, %d B)\n", k, s.P50, s.P95, s.P99, s.N, sizes[k])
		}
	}

	// --- network / security counters -----------------------------------
	var total uint64
	for i := range c.Nodes {
		total += c.Net.BytesSent[i].Load()
	}
	var rejReplay, rejAEAD uint64
	for _, nd := range c.Nodes {
		rejReplay += nd.Sessions().Stats.RejectedReplay.Load()
		rejAEAD += nd.Sessions().Stats.RejectedAEAD.Load()
	}
	kbPerNode := float64(total) / 1024 / float64(o.N)
	fmt.Printf("network: %.1f KB sent per node; session rejections: replay=%d aead=%d; adjust mismatches=%d\n",
		kbPerNode, rejReplay, rejAEAD, rec.CountEvents("adjust_mismatch"))

	prefix := fmt.Sprintf("%s_%s", cfgName, scenario)
	if err := rec.WriteCSV(out, prefix); err != nil {
		log.Printf("writing CSV: %v", err)
	} else {
		fmt.Printf("raw data: %s%c%s_*.csv\n", out, os.PathSeparator, prefix)
	}
	return fmt.Sprintf("%-4s %-22s %7d %6d %5d %11.2f %11.2f %11.2f %10.1f",
		cfgName, scenario, len(rounds), maxView, rec.CountEvents("excluded")/max(1, len(c.Honest())),
		tail.P50, tail.P95, latS.P50, kbPerNode)
}
