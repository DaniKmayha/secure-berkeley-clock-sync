# Secure Berkeley Clock Synchronisation

Prototype for the thesis *Design and Evaluation of a Secure Distributed System
Integrating Hybrid Classical/Post-Quantum Cryptography, Byzantine Fault
Tolerance and Zero-Knowledge Proofs* (Neapolis University Paphos).

The use case is a small-scale variation of the **Berkeley algorithm**: a master
polls every slave, computes a fault-tolerant average of the clock offsets and
tells each node to speed up or slow down. Here the master can be Byzantine,
and so can any slave, as long as there are at most f of them in total (n = 3f+1).
The prototype uses synthetic clocks only and is meant for running the
benchmarks. It is not a production system.

## Architecture (dual plane)

| Plane | What | Package |
|---|---|---|
| Control | Pairwise **hybrid handshake**: X25519 + ML-KEM-768, mutual ML-DSA-65 transcript signatures, `K = HKDF-SHA384(SS_X25519 ‖ SS_MLKEM, TH ‖ session_id)`, directional keys, key confirmation. Classical baseline: X25519 + Ed25519. | `internal/handshake`, `internal/key_schedule`, `internal/crypto/*` |
| Data | **AES-256-GCM** per message, nonce = seq_no, AAD = version ‖ session_id ‖ seq_no ‖ tx_id ‖ type; strict sequence + tx_id replay checks; rotation after N messages / T seconds / leader change. | `internal/session`, `internal/crypto/symmetric` |
| Berkeley | Cristian offset estimation (min-RTT of K samples), clamp to ±L, **commitment + Groth16 range proof** per slave, median-band fault-tolerant average, **Groth16 aggregation proof** by the master, slave-to-slave witness check. | `internal/berkeley`, `internal/zkp` |
| Consensus | **PBFT** (pre-prepare / prepare / commit, view change, new view). Master = PBFT primary. Leader election = round-robin over views that **skips provably Byzantine nodes**. | `internal/bft` |

### One synchronisation round

```
master M (= PBFT primary)                 slave S
  Poll{r, view}  ─────────────────────────►
                 ◄───────────────────────── TimeReq{r, k}      ×K samples (keep min RTT)
  TimeResp{r, k, T_M} ────────────────────►  d = (t1+t2)/2 − T_M, clamp to ±L
                 ◄───────────────────────── Reading{C = MiMC(d+L, ρ, r, S), range proof, sig_S}
                 ◄───────────────────────── Opening{d+L, ρ}     (private, only to M)
  median-band filter, A = ⌊mean⌋, aggregation proof
  PBFT: PRE-PREPARE(Proposal) → PREPARE → COMMIT  (every replica re-verifies all proofs)
  every node: adj = A − d  →  slew ("speed up" / "slow down")
  Adjust{r, adj_S} ───────────────────────►  cross-checked against the committed value
```

The backups never see the individual offsets. They check the range proofs and
the aggregation proof. The aggregation proof covers **every** reading in the
proposal and proves that (a) the included set is exactly the median-band
filter over them (including its keep-all fallback), (b) the master's own
reading is offset 0, and (c) the average is ⌊sum/k⌋ of the included values.
So a Byzantine master **cannot commit a wrong average or hand-pick which
readings are averaged**, and a Byzantine slave **cannot report a value outside
±L**. Plain mode (C1–C3) gives the same guarantees by recomputation, at the
cost of every replica seeing every offset.

What remains possible (and is documented as a limitation): a master can leave
a reading out of the proposal altogether, claiming it never arrived, as long
as n − f readings remain (indistinguishable from message loss), and it can
lie in TimeResp, which is bounded by L and caught by the witness check.

> Changing the aggregation circuit changes the Groth16 keys: re-run
> `go run ./cmd/keygen` for the Docker deployment, and re-run the C4/C5
> experiments, since results produced before this change used the older circuit.

### How the cluster avoids electing a malicious leader

`primary(v) = v mod n`, but the next view always skips nodes for which a
replica holds **self-verifying evidence**:

| Evidence | Produced when |
|---|---|
| `EvBadProposal` | a PRE-PREPARE signed by the primary fails deterministic validation (e.g. a wrong average) |
| `EvEquivocation` | two signed PRE-PREPARE headers for the same (view, seq). Every PREPARE echoes the primary's signed header, so a split proposal gets caught |
| `EvApp` | a signed Berkeley reading with an invalid range proof |

Evidence is gossiped and attached to every VIEW-CHANGE, so all honest
replicas converge on the same excluded set. Misbehaviour that can't be proven
(a crash, a silent leader, a master lying about its clock or sending wrong
Adjust messages) leads to a timeout or suspicion-driven view change, but not
to exclusion.

## GUI (easiest way to use it)

Double-click **`BerkeleyGUI.exe`**, or run:

```bash
go run ./cmd/gui
```

A window opens (Edge/Chrome app mode, or your default browser). Pick a
configuration (C1–C5) and a ready-made attack scenario, or click any node in the
cluster picker to choose its behaviour yourself (custom combinations, 4 or 7
nodes). The **Scenario explained** panel describes the chosen combination: what
each faulty node does, where in the round it strikes, who will end up master,
how the configuration (hybrid/classical, session/per-round, ZKP on/off) changes
detection, and what each change you make does. Then press **Start**. Expected
milestones are ticked off live as they happen. You'll also see live:

- every node's **ticking clock**, its role (MASTER / slave), any Byzantine
  behaviour, and EXCLUDED / VIEW CHANGE / DOWN tags
- whether each node is told to **speed up or slow down**, and by how much
- a **clock-alignment ruler** with every clock as a dot around real time, auto-zooming as the clocks converge
- charts of each clock's offset and of the sync spread (log scale), with view changes and exclusions marked
- committed rounds (master, average, readings, latency, per-node adjustment), the event feed and the raw protocol log
- stats: handshake cost, ZKP prove/verify time, data sent, rejected frames

Each run's raw CSV files are saved to `results/` (the path is shown in the window).
To rebuild the exe after code changes: `go build -o BerkeleyGUI.exe ./cmd/gui`.

## Running

Requires Go 1.27+.

```bash
go test ./...                       # unit + end-to-end tests
go test -short ./...                # skip the multi-second cluster tests

go run ./cmd/simulate               # C5, honest, 20 s, CSV -> results/
go run ./cmd/simulate -list         # fault scenarios
go run ./cmd/simulate -scenario master-bad-average -v
go run ./cmd/simulate -all-configs  # C1..C5 comparison table
go run ./cmd/simulate -all-scenarios -config C5
```

| Config | Meaning |
|---|---|
| C1 | classical session (X25519 + Ed25519) + AES-GCM + PBFT, no ZKP |
| C2 | naive: a fresh hybrid handshake **every round** + PBFT, no ZKP |
| C3 | hybrid session once + AES-GCM warm state + PBFT, no ZKP |
| C4 | classical session + ZKP + PBFT |
| C5 | hybrid session + ZKP + PBFT (full proposed system) |

Scenarios: `honest`, `slave-extreme`, `slave-invalid-proof`, `slave-crash`,
`master-bad-average`, `master-equivocate`, `master-silent`, `master-crash`,
`master-lie-timestamp`, `master-wrong-adjust`, `f-exceeded` (outside the threat model).

Raw output per run: `results/<cfg>_<scenario>_{rounds,handshakes,zkp,spread,events}.csv`.

### Multi-process / Docker

```bash
go run ./cmd/keygen -n 4 -out keys          # identities + Groth16 keys
go run ./cmd/node -config configs/local.json -id 0    # one terminal per id 0..3

docker compose -f docker/docker-compose.yml run --rm keygen
docker compose -f docker/docker-compose.yml up node0 node1 node2 node3
```

## Repository layout

```
cmd/gui           graphical app: live clocks, charts, rounds, events (web/ = the window's page)
cmd/simulate      in-process experiments (C1..C5, fault scenarios, CSV output)
cmd/node          one replica over TCP (Docker)
cmd/keygen        identity keys + Groth16 setup
internal/wire          canonical CBOR encoding, frame/message types
internal/clock         simulated drifting clock with slewing
internal/crypto/       classical (X25519, Ed25519), pqc (ML-KEM-768, ML-DSA-65), symmetric (AES-GCM), identity
internal/key_schedule  HKDF session key derivation
internal/handshake     Control Plane state machines
internal/session       Data Plane, replay protection, rotation
internal/zkp           Groth16 range + aggregation circuits
internal/berkeley      Berkeley protocol core (pure, deterministic)
internal/bft           PBFT engine, view change, evidence, leader exclusion
internal/node          event loop wiring everything together
internal/byzantine     malicious behaviours for experiments
internal/cluster       in-process cluster builder (+ end-to-end tests)
internal/experiments   C1..C5 configurations and fault scenarios (shared by GUI and CLI)
internal/metrics       raw CSV + p50/p95/p99 summaries
internal/network       in-memory network (latency, jitter, faults) + TCP transport
configs/, docker/
```

## Security boundaries (wording rules from the specification)

- The hybrid ephemeral key-establishment design is *intended to mitigate
  harvest-now-decrypt-later exposure* under the stated assumptions. No claim
  of proven post-quantum forward secrecy is made.
- Groth16/BN254 is **not** post-quantum secure, and its setup runs locally
  (trusted setup), which is acceptable only for a prototype.
- Ephemeral secret material is zeroised on a best-effort basis. Verified
  secure erasure isn't possible in the Go runtime.
- More than f Byzantine replicas is out of scope: no guarantee is claimed
  (the `f-exceeded` scenario only illustrates the boundary).
- No PKI: public keys are pre-provisioned. Host, OS and side channels are out of scope.
- Berkeley-specific: the master's clock is the reference, so a master that
  lies in TimeResp can bias a slave by up to L per round without leaving
  transferable evidence. The witness check detects the resulting
  desynchronisation and forces a view change, but doesn't exclude the node.
