// Package config loads the JSON configuration and key material used by the
// multi-process deployment (cmd/node, Docker Compose).
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"secure-distributed-system/internal/crypto/classical"
	"secure-distributed-system/internal/crypto/identity"
	"secure-distributed-system/internal/crypto/pqc"
	"secure-distributed-system/internal/handshake"
)

// Duration is a time.Duration that unmarshals from "1s"-style strings.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	d.Duration = v
	return err
}

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(d.String()) }

// NodeAddr is one cluster member.
type NodeAddr struct {
	ID   uint32 `json:"id"`
	Addr string `json:"addr"` // host:port other nodes dial
}

// Cluster is the shared (frozen) configuration of an experiment.
type Cluster struct {
	Suite   string     `json:"suite"` // "classical" | "hybrid"
	ZKP     bool       `json:"zkp"`
	Nodes   []NodeAddr `json:"nodes"`
	KeysDir string     `json:"keys_dir"`

	BoundUs int64 `json:"bound_us"`
	BandUs  int64 `json:"band_us"`

	RoundInterval  Duration `json:"round_interval"`
	CollectTimeout Duration `json:"collect_timeout"`
	SlewPeriod     Duration `json:"slew_period"`
	TimeSamples    int      `json:"time_samples"`

	SuspectThresholdUs int64 `json:"suspect_threshold_us"`
	SuspectAfter       int   `json:"suspect_after"`

	RekeyMessages       uint64 `json:"rekey_messages"`
	RekeySeconds        uint64 `json:"rekey_seconds"`
	RekeyOnLeaderChange bool   `json:"rekey_on_leader_change"`

	ProgressTimeout   Duration `json:"progress_timeout"`
	ViewChangeTimeout Duration `json:"view_change_timeout"`
}

// Load reads a cluster configuration file.
func Load(path string) (*Cluster, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Cluster
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	if len(c.Nodes) < 4 {
		return nil, fmt.Errorf("config: need at least 4 nodes")
	}
	return &c, nil
}

// SuiteValue converts the suite name.
func (c *Cluster) SuiteValue() (handshake.Suite, error) {
	switch c.Suite {
	case "classical":
		return handshake.SuiteClassical, nil
	case "hybrid":
		return handshake.SuiteHybrid, nil
	}
	return 0, fmt.Errorf("config: unknown suite %q", c.Suite)
}

// ------------------------------------------------------------- keys ---

func keyPath(dir string, id uint32, suite handshake.Suite, ext string) string {
	alg := "ed25519"
	if suite == handshake.SuiteHybrid {
		alg = "mldsa65"
	}
	return filepath.Join(dir, fmt.Sprintf("node%d.%s.%s", id, alg, ext))
}

// WriteIdentity stores a node's key pair (cmd/keygen).
func WriteIdentity(dir string, id uint32, suite handshake.Suite, s identity.Signer) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath(dir, id, suite, "key"), s.MarshalPrivate(), 0o600); err != nil {
		return err
	}
	return os.WriteFile(keyPath(dir, id, suite, "pub"), s.Public().Bytes(), 0o644)
}

// LoadSigner loads this node's private identity key.
func LoadSigner(dir string, id uint32, suite handshake.Suite) (identity.Signer, error) {
	b, err := os.ReadFile(keyPath(dir, id, suite, "key"))
	if err != nil {
		return nil, err
	}
	if suite == handshake.SuiteHybrid {
		return pqc.ParseMLDSAPrivate(b)
	}
	return classical.ParseEd25519Private(b)
}

// LoadVerifiers loads every node's public key (pre-provisioned, no PKI).
func LoadVerifiers(dir string, ids []uint32, suite handshake.Suite) (map[uint32]identity.Verifier, error) {
	out := map[uint32]identity.Verifier{}
	for _, id := range ids {
		b, err := os.ReadFile(keyPath(dir, id, suite, "pub"))
		if err != nil {
			return nil, err
		}
		var v identity.Verifier
		if suite == handshake.SuiteHybrid {
			v, err = pqc.ParseMLDSAPublic(b)
		} else {
			v, err = classical.ParseEd25519Public(b)
		}
		if err != nil {
			return nil, err
		}
		out[id] = v
	}
	return out, nil
}
