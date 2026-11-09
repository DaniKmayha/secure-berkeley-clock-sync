// explain.js: turns a chosen combination (configuration + cluster size +
// per-node behaviour) into a plain-language explanation of what the system
// will do, plus a list of milestones the dashboard ticks off live.
//
// The facts here mirror the Go code:
//   L = ±200 ms (range bound), median band = ±50 ms, progress timeout ≈ 4 s,
//   bad average = +50 ms, lie = ±40 ms, wrong adjust = +30 ms,
//   witness threshold = 20 ms for 3 rounds, primary(v) = v mod n skipping
//   excluded nodes, a round needs n − f readings, PBFT quorum = 2f + 1.
"use strict";

const BEH = {
  honest: { label: "Honest", icon: "✓", role: "any", short: "Follows the protocol." },
  crash: { label: "Offline (crash)", icon: "⏻", role: "any", short: "Down from the start (fail-stop)." },
  extreme_offset: { label: "Extreme offset", icon: "⇡", role: "slave", short: "Always reports +L = +200 ms to drag the average." },
  invalid_proof: { label: "Forged proof", icon: "✗", role: "slave", short: "Sends a corrupted (but signed) range proof." },
  bad_average: { label: "Wrong average", icon: "±", role: "master", short: "As master, proposes the average shifted by +50 ms." },
  equivocate: { label: "Equivocation", icon: "⑂", role: "master", short: "As master, sends different proposals to different backups." },
  silent_leader: { label: "Silent master", icon: "…", role: "master", short: "As master, never starts a round." },
  lie_timestamp_us: { label: "Lies about time", icon: "⌚", role: "master", short: "As master, gives slaves reference times off by ±40 ms." },
  wrong_adjust: { label: "Wrong corrections", icon: "↯", role: "master", short: "As master, sends Adjust messages 30 ms off the committed value." },
};
const BEH_ORDER = ["honest", "crash", "extreme_offset", "invalid_proof", "bad_average", "equivocate", "silent_leader", "lie_timestamp_us", "wrong_adjust"];

// Friendly names / grouping for the preset scenarios (names come from Go).
const PRESETS = {
  "honest": { group: "Normal", title: "Everyone honest", icon: "✓" },
  "slave-extreme": { group: "Malicious slave", title: "Slave drags the average", icon: "⇡" },
  "slave-invalid-proof": { group: "Malicious slave", title: "Slave forges its proof", icon: "✗" },
  "slave-crash": { group: "Malicious slave", title: "Slave goes offline", icon: "⏻" },
  "master-bad-average": { group: "Malicious master", title: "Master lies about the average", icon: "±" },
  "master-equivocate": { group: "Malicious master", title: "Master tells two stories", icon: "⑂" },
  "master-silent": { group: "Malicious master", title: "Master goes silent", icon: "…" },
  "master-crash": { group: "Malicious master", title: "Master goes offline", icon: "⏻" },
  "master-lie-timestamp": { group: "Malicious master", title: "Master lies about its time", icon: "⌚" },
  "master-wrong-adjust": { group: "Malicious master", title: "Master sends wrong corrections", icon: "↯" },
  "f-exceeded": { group: "Beyond the threat model", title: "Two attackers at once", icon: "⚠" },
};

// What a behaviour does to a node's turn as master.
//   timeout: no progress -> view change, no proof -> not excluded
//   excluded: signed, self-verifying evidence -> excluded from leader election
//   suspect: honest nodes notice and vote a view change, not provable
const AS_MASTER = {
  crash: "timeout", silent_leader: "timeout",
  bad_average: "excluded", equivocate: "excluded", invalid_proof: "excluded",
  lie_timestamp_us: "suspect", wrong_adjust: "suspect",
};

const fOf = (n) => Math.floor((n - 1) / 3);
const nodeName = (id) => `node ${id}`;
const B = (s) => `<b>${s}</b>`;

/** Walk the round-robin leader rule to predict which nodes lead which views. */
function predictLeaders(n, beh) {
  const steps = [];
  const excluded = new Set();
  const nextView = (v) => {
    for (let c = v + 1; c <= v + n + 1; c++) if (!excluded.has(c % n)) return c;
    return v + 1;
  };
  let v = 0;
  for (let guard = 0; guard < n + 2; guard++) {
    const p = v % n;
    const k = beh[p] || "honest";
    const effect = AS_MASTER[k];
    // A master that runs rounds catches forged-proof slaves before they lead.
    if (!effect || effect === "suspect") {
      for (let i = 0; i < n; i++) if (i !== p && beh[i] === "invalid_proof" && !excluded.has(i)) {
        excluded.add(i);
        steps.push({ kind: "slave-excluded", node: i, view: v, by: p });
      }
    }
    if (!effect) { steps.push({ kind: "stable", view: v, primary: p }); break; }
    if (effect === "excluded") excluded.add(p);
    const nv = nextView(v);
    steps.push({ kind: "takeover", view: v, primary: p, beh: k, effect, next: nv % n, nextView: nv });
    v = nv;
  }
  const leaders = new Set(steps.filter((s) => s.kind !== "slave-excluded").map((s) => s.primary));
  const stable = steps.find((s) => s.kind === "stable");
  return { steps, excluded, leaders, finalMaster: stable ? stable.primary : null };
}

/** Main entry: everything the UI needs to describe a combination. */
function explain(cfg, n, beh) {
  const f = fOf(n);
  const ids = [...Array(n).keys()];
  const faulty = ids.filter((i) => beh[i] && beh[i] !== "honest");
  const crashed = ids.filter((i) => beh[i] === "crash");
  const pred = predictLeaders(n, beh);
  const needed = n - f, quorum = 2 * f + 1;
  const alive = n - crashed.length;
  const zkp = cfg.zkp, hybrid = cfg.hybrid;
  const sig = hybrid ? "ML-DSA-65 (post-quantum)" : "Ed25519";

  // ---------------------------------------------------------- verdict --
  let verdict;
  if (faulty.length === 0) {
    verdict = { level: "good", label: "Normal operation", text: "No faulty nodes. This is the baseline: clocks should converge to well under 1 ms." };
  } else if (faulty.length <= f) {
    verdict = { level: "good", label: "Protected", text: `${faulty.length} faulty node${faulty.length > 1 ? "s" : ""} ≤ f = ${f}. This is inside the threat model (n = 3f + 1), so no wrong average can be committed and the cluster keeps synchronising.` };
  } else {
    const stall = alive < quorum || alive < needed;
    verdict = { level: "bad", label: "No guarantee", text: `${faulty.length} faulty nodes > f = ${f}. With n = ${n} the protocol only tolerates ${f}. ` +
      (stall ? `Only ${alive} node${alive === 1 ? " is" : "s are"} up, below the PBFT quorum of ${quorum} / the ${needed} readings a round needs, so the cluster will most likely stall.`
             : "Honest nodes can be outvoted, so neither correctness nor progress is promised. Watch what actually happens.") };
  }

  // ------------------------------------------------------- node stories --
  const takeoverOf = (id) => pred.steps.find((s) => s.kind === "takeover" && s.primary === id);
  const slaveExcl = (id) => pred.steps.find((s) => s.kind === "slave-excluded" && s.node === id);
  const leads = (id) => pred.leaders.has(id);
  const nodes = [];
  for (const id of faulty) {
    const k = beh[id];
    const t = takeoverOf(id);
    const nxt = t ? `${nodeName(t.next)} becomes master (view ${t.nextView})` : "";
    let story = "", short = "", detect = "", active = true;
    switch (k) {
      case "crash":
        if (leads(id)) {
          story = `${B(nodeName(id))} should be master of view ${t.view} but is offline, so nobody polls the slaves and no round is committed. ` +
            `After the progress timeout (about 4 s) the backups vote a view change and ${nxt}. A crash cannot be proven (it looks the same as a slow network), so ${nodeName(id)} is ${B("not excluded")}: it just loses its turn.`;
          short = `Clocks drift freely for ~4 s, then ${nxt}.`;
          detect = "Timeout → view change";
        } else {
          story = `${B(nodeName(id))} is a slave and is offline. A round only needs n − f = ${needed} readings and PBFT needs ${quorum} votes, and ${alive} nodes are still up, ` +
            (alive >= needed ? "so rounds keep committing with one reading fewer (watch the Readings column)." : "which is not enough: rounds cannot complete.");
          short = alive >= needed ? `Tolerated: rounds go on with ${alive} readings.` : "Too few nodes left: rounds stall.";
          detect = "Tolerated";
        }
        break;
      case "extreme_offset":
        if (leads(id) && pred.finalMaster === id) {
          active = false;
          story = `${B(nodeName(id))} is the master. A master's own reading is 0 by definition (it is the reference clock), so this slave attack is ${B("dormant")} while ${nodeName(id)} leads.`;
          short = "Dormant: a master's own reading is always 0.";
          detect = "None needed";
        } else {
          story = `Every round ${B(nodeName(id))} reports +L = +200 ms to pull the average its way. The fault-tolerant average only keeps readings within ±50 ms of the median, ` +
            `so once the honest clocks are close the +200 ms value is ${B("filtered out")} (Readings shows ${n - 1}/${n} included). ` +
            `It is ${B("not excluded")}: +200 ms is inside ±L, and its signature${zkp ? " and range proof are" : " is"} valid, so the system can tell it is an outlier but cannot prove it lied. ` +
            `Since it corrects its own clock from the fake value, its own clock drifts off. That only hurts itself (the spread chart counts honest clocks only).`;
          short = "Its reading is filtered as an outlier; honest clocks unaffected.";
          detect = "Median-band filter";
        }
        break;
      case "invalid_proof": {
        const asSlave = slaveExcl(id);
        story = zkp
          ? `${B(nodeName(id))} attaches a corrupted Groth16 range proof but signs the reading properly. The proof fails verification, so the reading is ${B("rejected before anything is committed")}. ` +
            `Because it carries ${nodeName(id)}'s ${sig} signature, the bad proof is self-verifying evidence: it is gossiped to every replica and ${nodeName(id)} is ${B("excluded")} from leader election for good.`
          : `This configuration has no ZKP, so there is no proof to forge. The attack is emulated by sending a plain offset of 3L = 600 ms, which breaks the ±200 ms rule. ` +
            `The reading is ${B("rejected")}, and since it is signed (${sig}) it still counts as evidence: ${nodeName(id)} is ${B("excluded")}.`;
        if (!asSlave && t) story += ` It gets to lead view ${t.view} before anyone has caught it. Its proposals contain its own invalid reading, so the backups reject them, exclude it, and ${nxt}.`;
        short = `Reading rejected, ${nodeName(id)} excluded with evidence.`;
        detect = zkp ? "Range proof fails → evidence" : "Out of range → evidence";
        break;
      }
      case "bad_average":
        if (t) {
          story = `As master of view ${t.view}, ${B(nodeName(id))} computes the correct average but proposes it ${B("+50 ms")} off. ` +
            (zkp ? "With ZKP every proposal must carry a Groth16 aggregation proof that the average matches the committed readings, and the shifted value fails that proof at every backup. "
                 : "Without ZKP the readings travel in plain text, so every backup recomputes the median-band average itself and sees the mismatch. Detection works, but every replica learns every node's offset (no privacy). ") +
            `The backups refuse to PREPARE, so ${B("no wrong average is ever committed")}. The signed bad PRE-PREPARE is evidence: ${nodeName(id)} is excluded and ${nxt}.`;
          short = `Proposal rejected, ${nodeName(id)} excluded, ${nxt}.`;
          detect = zkp ? "Aggregation proof fails → evidence" : "Backups recompute → evidence";
        }
        break;
      case "equivocate":
        if (t) {
          story = `As master of view ${t.view}, ${B(nodeName(id))} builds two individually valid proposals (one leaves a slave out) and sends A to half the backups and B to the other half, hoping they commit different averages. ` +
            `Every PREPARE echoes the master's signed header, so the backups see ${B("two different signed headers for the same round")}. That is equivocation evidence (${sig} signatures): ${nodeName(id)} is excluded and ${nxt}.`;
          short = `Caught from its own signatures, excluded, ${nxt}.`;
          detect = "Two signed headers → evidence";
        }
        break;
      case "silent_leader":
        if (t) {
          story = `${B(nodeName(id))} is master of view ${t.view} but never starts a round. The clocks drift freely (the spread creeps up) until the progress timeout (about 4 s), then ${nxt}. ` +
            `Silence cannot be proven, so it is ${B("not excluded")}. If leadership ever came back to it, the stall would repeat.`;
          short = `~4 s stall, then ${nxt}. Not excluded.`;
          detect = "Timeout → view change";
        }
        break;
      case "lie_timestamp_us":
        if (t) {
          story = `As master, ${B(nodeName(id))} answers even-numbered slaves with its time +40 ms and odd ones with −40 ms, so the slaves measure different offsets and are pulled apart. ` +
            `Each slave honestly reports what it measured, so every reading is in range and ${zkp ? "every range proof is valid. ZKP cannot help here: it proves readings are in range, not that the master's reference time was true" : "passes the range check"}. ` +
            `The defence is the ${B("witness check")}: slaves ask each other for the time directly. When two slaves differ by more than 20 ms for 3 rounds in a row they suspect the master and vote a view change, and ${nxt}. ` +
            `This is not provable, so there is no exclusion. Expect a temporary bump in the spread, capped by L.`;
          short = `Slaves drift apart until the witness check triggers, then ${nxt}.`;
          detect = "Witness check → view change";
        }
        break;
      case "wrong_adjust":
        if (t) {
          story = `After each committed round, ${B(nodeName(id))} sends every slave an Adjust instruction 30 ms off. Each slave computes its own correction from the ${B("committed")} average (A − d) and applies that instead, ` +
            `so the clocks are ${B("not affected")}. The mismatch makes the slaves suspect the master and vote a view change, and ${nxt}. Not provable, so no exclusion.`;
          short = `Ignored (slaves use the committed value), then ${nxt}.`;
          detect = "Cross-check → view change";
        }
        break;
    }
    if (!story) { // master-only behaviour on a node that never leads
      active = false;
      const master = pred.finalMaster ?? 0;
      story = `${B(nodeName(id))} only misbehaves ${B("as master")}. With round-robin leadership it would lead view ${id}, but the cluster settles on ${nodeName(master)} first, so this attack stays ${B("dormant")} for the whole run. ` +
        `It still counts towards the f = ${f} budget. It would only get a turn if ${id === 1 ? "node 0" : `every node from 0 to ${id - 1}`} failed as master first${id >= f ? `, which needs more than f = ${f} faults` : ""}.`;
      short = "Dormant: it never becomes master in this run.";
      detect = "Never triggered";
    }
    nodes.push({ id, k, story, short, detect, active, leads: leads(id) });
  }

  // ------------------------------------------- how the config shapes it --
  const cfgNotes = [];
  cfgNotes.push(hybrid
    ? { icon: "🔐", title: "Hybrid post-quantum handshake", text: "X25519 + ML-KEM-768 key exchange with ML-DSA-65 signatures. It stays secure against a future quantum computer, but handshakes are several KB bigger and slower than classical ones." }
    : { icon: "🔑", title: "Classical handshake", text: "X25519 + Ed25519. Small and fast, but a quantum computer could break it later (harvest-now, decrypt-later)." });
  cfgNotes.push(cfg.per_round
    ? { icon: "🔁", title: "New handshake every round", text: "Every round starts with a fresh hybrid handshake to every slave. Watch the Handshakes tile climb and round latency rise: this is the worst-case cost of PQC." }
    : { icon: "♻", title: "One handshake, then a session", text: "Each pair shakes hands once, then reuses AES-256-GCM session keys (rotated after N messages, T seconds or a leader change). The handshake cost is paid once." });
  cfgNotes.push(zkp
    ? { icon: "🕶", title: "Zero-knowledge proofs on", text: "Slaves send a commitment plus a Groth16 range proof instead of their offset. Only the master sees the real values. It proves in zero knowledge that it applied the median filter to every reading, that its own reading is 0, and that the average is right, so it cannot hand-pick which readings count. This costs extra CPU every round (see the ZKP tiles)." }
    : { icon: "👁", title: "Zero-knowledge proofs off", text: "Offsets are sent in plain text (still encrypted on the wire). Backups check the master by recomputing the average, so correctness holds, but every replica sees every node's offset." });

  // Combination-specific notes: how THIS config changes THIS attack.
  const combo = [];
  const has = (k) => nodes.some((x) => x.k === k && x.active);
  if (has("invalid_proof")) combo.push(zkp ? "Forged proof + ZKP: caught by Groth16 verification." : "Forged proof without ZKP: there is no proof to forge, so it becomes an out-of-range plain value. Same outcome, but caught by a simple range check.");
  if (has("bad_average")) combo.push(zkp ? "Wrong average + ZKP: the aggregation proof catches it without anyone seeing the individual offsets." : "Wrong average without ZKP: caught by recomputing, at the cost of revealing every offset to every replica.");
  if (has("extreme_offset")) combo.push(zkp ? "Extreme offset + ZKP: the range proof does not stop it (+L is a valid value); the median filter does. The aggregation proof shows the backups the filter was applied, while the value stays hidden from them." : "Extreme offset without ZKP: the median filter drops it; the 200 ms value is visible to everyone.");
  if (has("lie_timestamp_us")) combo.push("Lying about time is the same with or without ZKP: proofs check readings, not the master's clock. Only the slave-to-slave witness check catches it.");
  if (has("equivocate")) combo.push(`Equivocation is caught from the master's own ${sig} signatures, so it works the same in every configuration.`);
  const vcs = pred.steps.filter((s) => s.kind === "takeover").length;
  if (vcs > 0) {
    combo.push(cfg.per_round
      ? "After a view change the new master already handshakes every round, so the takeover adds little extra cost."
      : `Sessions are re-keyed after a leader change, so each view change triggers ${hybrid ? "hybrid (bigger, slower)" : "classical"} handshakes. Watch the Handshakes tile jump.`);
  }
  if (faulty.length > f) combo.push(`n = ${n} only tolerates f = ${f} faults. ${n === 4 ? "Switch to 7 nodes (f = 2) to bring two attackers back inside the threat model." : "Remove an attacker to get back inside the threat model."}`);
  if (zkp && n === 7) combo.push("With 7 nodes the Groth16 circuits are larger, so proving takes longer than with 4.");

  // ------------------------------------------------------- what to watch --
  const watch = [];
  if (vcs > 0) watch.push("Orange dashed lines on the charts mark view changes, and the 👑 MASTER tag moves to the new leader.");
  if (pred.excluded.size) watch.push("Red EXCLUDED tags and red dashed lines show nodes caught with signed evidence.");
  if (has("extreme_offset")) watch.push(`Readings column in Committed rounds: ${n - 1}/${n} means one reading was filtered out.`);
  if (crashed.length && alive >= needed) watch.push(`Readings column shows ${alive}/${alive}: the offline node is simply missing.`);
  if (has("lie_timestamp_us")) watch.push("The spread chart bumps up while slaves are pulled apart, then falls after the view change.");
  if (has("wrong_adjust")) watch.push("Events feed: “master's Adjust differs from the committed value”.");
  if (cfg.per_round) watch.push("Handshakes and Sent per node tiles grow every round.");
  if (zkp) watch.push("ZKP prove/verify tiles show the per-round proof cost.");
  watch.push("The spread chart (log scale) shows how closely the honest clocks agree.");

  // ----------------------------------------------------------- milestones --
  const ms = [{ text: "First round committed", match: (e) => e.type === "round" }];
  for (const s of pred.steps) {
    if (s.kind === "slave-excluded") {
      ms.push({ text: `Master rejects ${nodeName(s.node)}'s reading`, match: (e) => e.type === "event" && e.kind === "reading_rejected" });
      ms.push({ text: `${nodeName(s.node)} excluded with evidence`, match: (e) => e.type === "event" && e.kind === "excluded" && e.accused === s.node });
    } else if (s.kind === "takeover") {
      if (s.beh === "lie_timestamp_us") ms.push({ text: "Slaves detect desync (witness check)", match: (e) => e.type === "event" && e.kind === "witness_suspect" });
      if (s.beh === "wrong_adjust") ms.push({ text: "Slaves notice the wrong Adjust", match: (e) => e.type === "event" && e.kind === "adjust_mismatch" });
      if (s.effect === "excluded") ms.push({ text: `${nodeName(s.primary)} excluded with evidence`, match: (e) => e.type === "event" && e.kind === "excluded" && e.accused === s.primary });
      ms.push({ text: `${nodeName(s.next)} becomes master (view ${s.nextView})`, match: (e) => e.type === "event" && e.kind === "new_view" && e.primary === s.next });
    }
  }
  if (has("extreme_offset")) ms.push({ text: "Outlier reading filtered out", match: (e) => e.type === "round" && e.included < e.readings });
  if (crashed.some((i) => !pred.leaders.has(i)) && alive >= needed) ms.push({ text: `Rounds continue with ${alive} readings`, match: (e) => e.type === "round" && e.readings === alive });
  ms.push({ text: "Honest clocks within 1 ms of each other", match: (e) => e.type === "tick" && e.t > 2 && e.spread < 1 });

  // ------------------------------------------------------------ summary --
  const title = faulty.length === 0 ? `${cfg.name} · all ${n} nodes honest`
    : `${cfg.name} · ${faulty.map((i) => `${nodeName(i)} ${BEH[beh[i]].label.toLowerCase()}`).join(" + ")}`;
  return { f, n, needed, quorum, faulty, pred, verdict, nodes, cfgNotes, combo, watch, milestones: ms, title };
}

/** Describe what changed between two selections, and how it moves the system. */
function describeChange(prev, next, cfgs) {
  if (!prev) return null;
  const out = [];
  const cA = cfgs.find((c) => c.name === prev.config), cB = cfgs.find((c) => c.name === next.config);
  const eA = explain(cA, prev.n, prev.beh), eB = explain(cB, next.n, next.beh);
  if (prev.config !== next.config) {
    out.push(`<b>${cA.name} → ${cB.name}</b> (${cB.title})`);
    if (cA.hybrid !== cB.hybrid) out.push(cB.hybrid ? "Handshake becomes <b>post-quantum hybrid</b>: quantum-safe, but bigger and slower handshakes." : "Handshake becomes <b>classical</b>: faster and smaller, but not quantum-safe.");
    if (cA.per_round !== cB.per_round) out.push(cB.per_round ? "A <b>fresh handshake every round</b>: expect much higher latency and traffic." : "Back to <b>one handshake + session keys</b>: the PQC cost is paid once.");
    if (cA.zkp !== cB.zkp) out.push(cB.zkp ? "<b>ZKP on</b>: offsets are hidden behind commitments and proofs; costs CPU per round." : "<b>ZKP off</b>: offsets are visible to all replicas, verified by recomputing; cheaper.");
    // Attacks whose explanation changed because of the config.
    for (const nb of eB.nodes) {
      const na = eA.nodes.find((x) => x.id === nb.id && x.k === nb.k);
      if (na && na.detect !== nb.detect) out.push(`Node ${nb.id} (${BEH[nb.k].label}) is now caught by <b>${nb.detect}</b> instead of ${na.detect}.`);
    }
  }
  if (prev.n !== next.n) {
    out.push(`<b>${prev.n} → ${next.n} nodes</b>: tolerates f = ${eB.f} fault${eB.f > 1 ? "s" : ""} (was ${eA.f}); each round needs ${eB.needed} readings and PBFT needs ${eB.quorum} votes.`);
  }
  for (let i = 0; i < Math.max(prev.n, next.n); i++) {
    const a = prev.beh[i] || "honest", b = i < next.n ? (next.beh[i] || "honest") : "honest";
    if (a === b || i >= next.n) continue;
    const nb = eB.nodes.find((x) => x.id === i);
    out.push(`<b>Node ${i}: ${BEH[a].label} → ${BEH[b].label}</b>. ${nb ? nb.short : "It now follows the protocol."}`);
  }
  if (eA.verdict.label !== eB.verdict.label) {
    out.push(`Verdict: <span class="v-${eA.verdict.level}">${eA.verdict.label}</span> → <span class="v-${eB.verdict.level}">${eB.verdict.label}</span>`);
  }
  const vcA = eA.pred.steps.filter((s) => s.kind === "takeover").length, vcB = eB.pred.steps.filter((s) => s.kind === "takeover").length;
  if (vcA !== vcB) out.push(`Expected view changes: ${vcA} → ${vcB}. Final master: node ${eA.pred.finalMaster ?? "?"} → node ${eB.pred.finalMaster ?? "?"}.`);
  return out.length ? out : null;
}
