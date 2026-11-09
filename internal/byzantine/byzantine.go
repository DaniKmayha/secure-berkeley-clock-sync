// Package byzantine describes the malicious behaviours a node can be
// configured with for the security / fault experiments. Each flag is a
// deliberate deviation from the protocol, implemented in package node.
//
// The scenarios map to the Security/Fault Testing Matrix of the study guide:
//   - invalid ZKP                     -> InvalidProof        (reject before commit)
//   - malicious slave value           -> ExtremeOffset       (bounded / filtered)
//   - Byzantine master, wrong result  -> BadAverage          (no incorrect commit, excluded)
//   - replica equivocation            -> Equivocate          (no incorrect commit, excluded)
//   - silent / crashed leader         -> SilentLeader, Crash (view change)
//   - master lying about its clock    -> LieTimestampUs      (bounded by L, documented)
//   - master lying in Adjust          -> WrongAdjust         (slaves apply committed value)
package byzantine

import "strings"

// Behaviour is the set of deviations of one node. The zero value is honest.
type Behaviour struct {
	// Crash: the node never runs (fail-stop). Handled by the simulator.
	Crash bool `json:"crash,omitempty"`

	// --- as a slave ---
	// ExtremeOffset: always report +L, trying to drag the average.
	ExtremeOffset bool `json:"extreme_offset,omitempty"`
	// InvalidProof: send a corrupted range proof (or out-of-range plain offset).
	InvalidProof bool `json:"invalid_proof,omitempty"`

	// --- as the master / PBFT primary ---
	// BadAverage: propose a mean shifted by 50 ms (invalid aggregation proof).
	BadAverage bool `json:"bad_average,omitempty"`
	// Equivocate: send two different (individually valid) proposals to
	// different backups.
	Equivocate bool `json:"equivocate,omitempty"`
	// SilentLeader: never start rounds while being the primary.
	SilentLeader bool `json:"silent_leader,omitempty"`
	// LieTimestampUs: add ±value to the master time given to slaves
	// (alternating sign per slave), trying to desynchronise them.
	LieTimestampUs int64 `json:"lie_timestamp_us,omitempty"`
	// WrongAdjust: send slaves an Adjust that differs from the committed one.
	WrongAdjust bool `json:"wrong_adjust,omitempty"`
}

// IsHonest reports whether no deviation is configured.
func (b Behaviour) IsHonest() bool { return b == Behaviour{} }

// String gives a compact label for logs and CSV files.
func (b Behaviour) String() string {
	if b.IsHonest() {
		return "honest"
	}
	var p []string
	add := func(on bool, s string) {
		if on {
			p = append(p, s)
		}
	}
	add(b.Crash, "crash")
	add(b.ExtremeOffset, "extreme-offset")
	add(b.InvalidProof, "invalid-proof")
	add(b.BadAverage, "bad-average")
	add(b.Equivocate, "equivocate")
	add(b.SilentLeader, "silent-leader")
	add(b.LieTimestampUs != 0, "lie-timestamp")
	add(b.WrongAdjust, "wrong-adjust")
	return strings.Join(p, "+")
}
