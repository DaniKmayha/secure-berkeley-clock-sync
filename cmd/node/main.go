// Command node runs ONE replica of the secure Berkeley cluster over TCP.
// It is what each Docker container runs.
//
//	go run ./cmd/node -config configs/local.json -id 0 -listen :7000
//
// The clock is simulated (synthetic data): -offset and -drift set how far
// this node's clock starts from real time and how fast it drifts. The node
// prints a status line every few seconds and writes its raw measurements to
// -out on exit (Ctrl+C).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"secure-distributed-system/internal/berkeley"
	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/clock"
	"secure-distributed-system/internal/config"
	"secure-distributed-system/internal/handshake"
	"secure-distributed-system/internal/metrics"
	"secure-distributed-system/internal/network"
	"secure-distributed-system/internal/node"
	"secure-distributed-system/internal/zkp"
)

func parseByzantine(s string) (byzantine.Behaviour, error) {
	var b byzantine.Behaviour
	for _, f := range strings.Split(s, ",") {
		switch strings.TrimSpace(f) {
		case "", "honest":
		case "extreme-offset":
			b.ExtremeOffset = true
		case "invalid-proof":
			b.InvalidProof = true
		case "bad-average":
			b.BadAverage = true
		case "equivocate":
			b.Equivocate = true
		case "silent-leader":
			b.SilentLeader = true
		case "lie-timestamp":
			b.LieTimestampUs = 40_000
		case "wrong-adjust":
			b.WrongAdjust = true
		default:
			return b, fmt.Errorf("unknown behaviour %q", f)
		}
	}
	return b, nil
}

func main() {
	cfgPath := flag.String("config", "configs/local.json", "cluster configuration")
	id := flag.Uint("id", 0, "this node's id")
	listen := flag.String("listen", "", "listen address (default: this node's addr from the config)")
	offset := flag.Int64("offset", 0, "initial clock offset (µs)")
	drift := flag.Float64("drift", 0, "clock drift (ppm)")
	byz := flag.String("byzantine", "honest", "comma-separated Byzantine behaviours (for experiments)")
	out := flag.String("out", "results", "directory for raw CSV results")
	verbose := flag.Bool("v", true, "log protocol events")
	flag.Parse()
	log.SetFlags(log.Lmicroseconds)

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		log.Fatal(err)
	}
	suite, err := cfg.SuiteValue()
	if err != nil {
		log.Fatal(err)
	}
	beh, err := parseByzantine(*byz)
	if err != nil {
		log.Fatal(err)
	}
	self := uint32(*id)
	addrs := map[uint32]string{}
	var ids []uint32
	for _, n := range cfg.Nodes {
		addrs[n.ID] = n.Addr
		ids = append(ids, n.ID)
	}
	if _, ok := addrs[self]; !ok {
		log.Fatalf("node id %d not in config", self)
	}
	if *listen == "" {
		// Listen on all interfaces at the port of our configured address.
		a := addrs[self]
		*listen = a[strings.LastIndex(a, ":"):]
	}

	signer, err := config.LoadSigner(cfg.KeysDir, self, suite)
	if err != nil {
		log.Fatalf("load identity (run cmd/keygen first): %v", err)
	}
	verifiers, err := config.LoadVerifiers(cfg.KeysDir, ids, suite)
	if err != nil {
		log.Fatal(err)
	}
	var params *zkp.Params
	if cfg.ZKP {
		if params, err = zkp.Load(cfg.KeysDir + "/zkp"); err != nil {
			log.Fatalf("load Groth16 keys: %v", err)
		}
	}

	tr, err := network.NewTCPTransport(self, *listen, addrs)
	if err != nil {
		log.Fatal(err)
	}
	defer tr.Close()

	n := len(cfg.Nodes)
	rec := metrics.NewRecorder()
	clk := clock.New(*offset, *drift)
	logf := func(string, ...any) {}
	if *verbose {
		logf = log.Printf
	}
	nd := node.New(node.Config{
		ID: self, Suite: suite,
		Berkeley:      berkeley.Config{N: n, F: (n - 1) / 3, Bound: cfg.BoundUs, Band: cfg.BandUs, ZKP: cfg.ZKP},
		RoundInterval: cfg.RoundInterval.Duration, CollectTimeout: cfg.CollectTimeout.Duration, SlewPeriod: cfg.SlewPeriod.Duration,
		TimeSamples: cfg.TimeSamples, SuspectThresholdUs: cfg.SuspectThresholdUs, SuspectAfter: cfg.SuspectAfter,
		Policy:              handshake.Policy{MaxMessages: cfg.RekeyMessages, MaxAgeSec: cfg.RekeySeconds},
		RekeyOnLeaderChange: cfg.RekeyOnLeaderChange,
		ProgressTimeout:     cfg.ProgressTimeout.Duration, ViewChangeTimeout: cfg.ViewChangeTimeout.Duration,
		Behaviour: beh, Logf: logf,
	}, node.Deps{Clock: clk, Transport: tr, Signer: signer, Verifiers: verifiers, Params: params, Recorder: rec})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("node %d (%s, zkp=%v, %s) listening on %s", self, suite, cfg.ZKP, beh, *listen)

	// Status line: this node's offset from the HOST clock. In Docker all
	// containers share the host clock, so these values are comparable.
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				log.Printf("STATUS node %d: offset from host clock %+.3f ms, view %d, primary %d, last round %d",
					self, float64(clk.OffsetFromReal())/1000, nd.PBFT().View(), nd.PBFT().Primary(), nd.PBFT().LastExecuted())
			}
		}
	}()
	nd.Run(ctx)
	if err := rec.WriteCSV(*out, fmt.Sprintf("node%d", self)); err != nil {
		log.Printf("write results: %v", err)
	}
}
