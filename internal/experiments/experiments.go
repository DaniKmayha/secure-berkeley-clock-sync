// Package experiments defines the experiment configurations (C1..C5) and the
// fault scenarios, shared by the command-line simulator and the GUI so both
// always run exactly the same setups.
package experiments

import (
	"fmt"
	"sort"
	"strings"

	"secure-distributed-system/internal/byzantine"
	"secure-distributed-system/internal/cluster"
	"secure-distributed-system/internal/handshake"
)

// Config is one of the C1..C5 configurations (study guide §7).
type Config struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	suite       handshake.Suite
	zkp         bool
	perRound    bool
}

// Configs in display order.
var Configs = []Config{
	{"C1", "Classical session", "X25519 + Ed25519 handshake once, AES-GCM, PBFT, no ZKP. Reference baseline.", handshake.SuiteClassical, false, false},
	{"C2", "Naive hybrid per round", "Fresh X25519 + ML-KEM-768 + ML-DSA-65 handshake EVERY round, PBFT, no ZKP. Upper bound of PQC cost.", handshake.SuiteHybrid, false, true},
	{"C3", "Hybrid session", "Hybrid handshake once, AES-GCM warm state, PBFT, no ZKP. Shows the session amortisation benefit.", handshake.SuiteHybrid, false, false},
	{"C4", "Classical + ZKP", "Classical session + Groth16 range/aggregation proofs + PBFT. Isolates the ZKP cost.", handshake.SuiteClassical, true, false},
	{"C5", "Full system", "Hybrid session + AES-GCM + ZKP + PBFT. The final proposed architecture.", handshake.SuiteHybrid, true, false},
}

// Scenario is a fault / attack setup.
type Scenario struct {
	Name        string                         `json:"name"`
	Description string                         `json:"description"`
	Expected    string                         `json:"expected"`
	Behaviours  map[uint32]byzantine.Behaviour `json:"-"`
}

// Scenarios in display order. Node 0 is the initial master (primary of
// view 0); node 3 is a slave.
var Scenarios = []Scenario{
	{"honest", "All nodes follow the protocol.", "Clocks converge to well under 1 ms.", map[uint32]byzantine.Behaviour{}},
	{"slave-extreme", "Slave 3 always reports the maximum offset +L, trying to drag the average.", "Filtered as an outlier; the honest clocks are unaffected.", map[uint32]byzantine.Behaviour{3: {ExtremeOffset: true}}},
	{"slave-invalid-proof", "Slave 3 sends a corrupted (but signed) range proof.", "Rejected before commit; node 3 is excluded with evidence.", map[uint32]byzantine.Behaviour{3: {InvalidProof: true}}},
	{"slave-crash", "Slave 3 is down from the start.", "The other 3 nodes keep synchronising (n-f = 3).", map[uint32]byzantine.Behaviour{3: {Crash: true}}},
	{"master-bad-average", "Master 0 proposes an average shifted by 50 ms.", "Backups reject it, node 0 is excluded and a new master is elected.", map[uint32]byzantine.Behaviour{0: {BadAverage: true}}},
	{"master-equivocate", "Master 0 sends different proposals to different backups.", "Detected from the signed headers; node 0 is excluded.", map[uint32]byzantine.Behaviour{0: {Equivocate: true}}},
	{"master-silent", "Master 0 never starts a round.", "Timeout, view change, node 1 becomes master.", map[uint32]byzantine.Behaviour{0: {SilentLeader: true}}},
	{"master-crash", "Master 0 is down from the start.", "Timeout, view change, node 1 becomes master.", map[uint32]byzantine.Behaviour{0: {Crash: true}}},
	{"master-lie-timestamp", "Master 0 gives slaves reference times off by ±40 ms.", "The witness check detects desync and forces a view change.", map[uint32]byzantine.Behaviour{0: {LieTimestampUs: 40_000}}},
	{"master-wrong-adjust", "Master 0 sends wrong Adjust instructions.", "Slaves apply the COMMITTED value instead and suspect the master.", map[uint32]byzantine.Behaviour{0: {WrongAdjust: true}}},
	{"f-exceeded", "Two Byzantine nodes with n=4 (f=1): outside the threat model.", "No guarantee is claimed.", map[uint32]byzantine.Behaviour{0: {BadAverage: true}, 3: {ExtremeOffset: true}}},
}

// FindConfig looks up a configuration by name (case-insensitive).
func FindConfig(name string) (Config, error) {
	for _, c := range Configs {
		if strings.EqualFold(c.Name, name) {
			return c, nil
		}
	}
	return Config{}, fmt.Errorf("unknown config %q (use C1..C5)", name)
}

// FindScenario looks up a scenario by name.
func FindScenario(name string) (Scenario, error) {
	for _, s := range Scenarios {
		if s.Name == name {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("unknown scenario %q", name)
}

// ScenarioNames returns all scenario names, sorted.
func ScenarioNames() []string {
	var names []string
	for _, s := range Scenarios {
		names = append(names, s.Name)
	}
	sort.Strings(names)
	return names
}

// Apply sets the crypto/ZKP options of a configuration and the behaviours of a scenario.
func Apply(o *cluster.Options, c Config, s Scenario) {
	o.Suite, o.ZKP, o.RehandshakePerRound = c.suite, c.zkp, c.perRound
	o.Behaviours = s.Behaviours
}

// UsesZKP reports whether the configuration needs a Groth16 setup.
func (c Config) UsesZKP() bool { return c.zkp }

// Hybrid reports whether the configuration uses the hybrid PQC handshake.
func (c Config) Hybrid() bool { return c.suite == handshake.SuiteHybrid }

// PerRound reports whether a fresh handshake is run every round (C2).
func (c Config) PerRound() bool { return c.perRound }
