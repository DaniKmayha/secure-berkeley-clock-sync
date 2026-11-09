// Secure Berkeley GUI: receives live snapshots from the Go server
// (Server-Sent Events on /api/stream) and draws everything on canvases.
// The scenario explanation logic lives in explain.js.
"use strict";

const COLORS = ["#5b8cff", "#2ec4a6", "#f2b33d", "#e8657a", "#a77bf3", "#4fc3f7", "#9ccc65"];
const $ = (id) => document.getElementById(id);
const SVGNS = "http://www.w3.org/2000/svg";
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const ADV_DEFAULTS = { duration: 20, interval: 1000, latency: 2, jitter: 1, initOffset: 150, drift: 200, seed: 1 };

// ------------------------------------------------------------------ state --
let meta = { configs: [], scenarios: [], behaviours: {} };
// What the user has chosen. beh maps node id -> behaviour key (see BEH).
const sel = { config: "C5", n: 4, preset: "honest", beh: {} };
let prevSel = null;
let run = null; // data of the current / last run
let running = false;

const cfgOf = (name) => meta.configs.find((c) => c.name === name);
const snapshotSel = () => ({ config: sel.config, n: sel.n, preset: sel.preset, beh: { ...sel.beh } });

function newRun(msg) {
  return {
    n: msg.n, config: msg.config, scenario: msg.scenario, bound: msg.bound_ms, duration: msg.duration_s,
    t: 0, nodes: [], offsets: Array.from({ length: msg.n }, () => []), spread: [],
    markers: [], rounds: new Map(), lastAdjust: {}, seenViews: new Set(), seenExcl: new Set(),
    lastT: 0, lastWall: performance.now(), stats: null, prev: {}, master: null,
    explain: null, milestones: [],
  };
}

/** Convert a preset's Go behaviours ({id: {flag: true}}) into {id: key}. */
function presetBeh(name) {
  const out = {};
  const src = meta.behaviours[name] || {};
  for (const [id, b] of Object.entries(src)) {
    const k = BEH_ORDER.find((key) => key !== "honest" && b[key]);
    if (k) out[id] = k;
  }
  return out;
}
const sameBeh = (a, b, n) => {
  for (let i = 0; i < n; i++) if ((a[i] || "honest") !== (b[i] || "honest")) return false;
  return true;
};

// ---------------------------------------------------------------- startup --
async function init() {
  meta = await (await fetch("/api/meta")).json();
  renderConfigs();
  renderScenarios();
  buildRing($("picker"), sel.n, true);
  setupSeg();
  setupCollapsers();
  setupAdvanced();

  $("startBtn").onclick = start;
  $("stopBtn").onclick = () => fetch("/api/stop", { method: "POST" });
  $("showLog").onchange = (e) => {
    $("log").classList.toggle("hidden", !e.target.checked);
    $("events").classList.toggle("hidden", e.target.checked);
  };
  $("zoomOffsets").onchange = drawCharts;
  window.addEventListener("resize", () => { drawCharts(); closePopover(); });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("#popover") && !e.target.closest(".rn")) closePopover();
  });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closePopover(); });
  refresh(false);
  connect();
  requestAnimationFrame(animate);
}

// ------------------------------------------------------- step 1: configs --
function renderConfigs() {
  const cc = $("configs");
  cc.innerHTML = "";
  for (const c of meta.configs) {
    const d = document.createElement("button");
    d.type = "button";
    d.className = "card" + (c.name === sel.config ? " sel" : "");
    d.dataset.name = c.name;
    const chip = (on, a, b, cls) => `<span class="fchip ${on ? cls : "off"}">${on ? a : b}</span>`;
    d.innerHTML = `<div class="t"><b>${c.name}</b>${c.title}<span class="check">✓</span></div>
      <div class="chips">${chip(c.hybrid, "🔐 PQC hybrid", "🔑 Classical", "pq")}${chip(c.per_round, "🔁 handshake / round", "♻ session reuse", "warn")}${chip(c.zkp, "🕶 ZKP", "no ZKP", "zk")}</div>
      <div class="d">${c.description}</div>`;
    d.onclick = () => {
      if (running || sel.config === c.name) return;
      sel.config = c.name;
      [...cc.children].forEach((x) => x.classList.toggle("sel", x === d));
      refresh(true);
    };
    cc.appendChild(d);
  }
}

// ----------------------------------------------------- step 2: scenarios --
function renderScenarios() {
  const box = $("scenarios");
  box.innerHTML = "";
  const groups = {};
  for (const s of meta.scenarios) {
    const p = PRESETS[s.name] || { group: "Other", title: s.name, icon: "•" };
    (groups[p.group] ||= []).push({ ...s, ...p });
  }
  groups["Your own"] = [{ name: "custom", title: "Build your own", icon: "✎", description: "Pick any behaviour for any node in step 3." }];
  for (const [g, list] of Object.entries(groups)) {
    const h = document.createElement("div");
    h.className = "sgroup";
    h.textContent = g;
    box.appendChild(h);
    const grid = document.createElement("div");
    grid.className = "tiles";
    for (const s of list) {
      const t = document.createElement("button");
      t.type = "button";
      t.className = "tile" + (s.name === sel.preset ? " sel" : "") + (s.name === "custom" ? " custom" : "");
      t.dataset.name = s.name;
      t.title = s.description;
      t.innerHTML = `<span class="ic">${s.icon}</span><span class="tt">${s.title}</span>`;
      t.onclick = () => choosePreset(s.name);
      grid.appendChild(t);
    }
    box.appendChild(grid);
  }
}

function choosePreset(name) {
  if (running) return;
  if (name === "custom") {
    sel.preset = "custom";
    markPreset();
    pulsePicker();
    refresh(false);
    return;
  }
  sel.preset = name;
  sel.beh = presetBeh(name);
  markPreset();
  refresh(true);
}

function markPreset() {
  document.querySelectorAll("#scenarios .tile").forEach((t) => t.classList.toggle("sel", t.dataset.name === sel.preset));
}

function pulsePicker() {
  const w = document.querySelector(".picker-wrap");
  w.classList.remove("attn"); void w.offsetWidth; w.classList.add("attn");
}

// ---------------------------------------------------- step 3: node ring --
function ringPos(i, n) {
  const a = -Math.PI / 2 + (i * 2 * Math.PI) / n;
  return [150 + 96 * Math.cos(a), 122 + 86 * Math.sin(a)];
}
function svgEl(tag, attrs, parent) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  if (parent) parent.appendChild(e);
  return e;
}

/** Build the ring diagram (used by the node picker and the live view). */
function buildRing(svg, n, interactive) {
  svg.innerHTML = "";
  svg.dataset.n = n;
  const links = svgEl("g", { class: "links" }, svg);
  for (let i = 0; i < n; i++) for (let j = i + 1; j < n; j++) {
    const [x1, y1] = ringPos(i, n), [x2, y2] = ringPos(j, n);
    svgEl("line", { x1, y1, x2, y2, "data-a": i, "data-b": j }, links);
  }
  svgEl("g", { class: "dots" }, svg);
  const nodes = svgEl("g", { class: "nodes" }, svg);
  for (let i = 0; i < n; i++) {
    const [x, y] = ringPos(i, n);
    const g = svgEl("g", { class: "rn", "data-id": i }, nodes);
    g.style.transform = `translate(${x}px, ${y}px)`;
    g.style.setProperty("--c", COLORS[i]);
    g.style.setProperty("--i", i);
    const inner = svgEl("g", { class: "rn-in" }, g);
    svgEl("circle", { class: "halo", r: 27 }, inner);
    svgEl("circle", { class: "body", r: 20 }, inner);
    const t = svgEl("text", { class: "id", y: 1 }, inner); t.textContent = i;
    const lab = svgEl("text", { class: "lab", y: 35 }, inner); lab.textContent = "slave";
    const xg = svgEl("g", { class: "xmark" }, inner);
    svgEl("path", { d: "M-11 -11 L11 11 M11 -11 L-11 11" }, xg);
    const bg = svgEl("g", { class: "badge", transform: "translate(15,-15)" }, inner);
    svgEl("circle", { r: 10 }, bg);
    svgEl("text", { y: 1 }, bg);
    if (interactive) {
      g.setAttribute("tabindex", "0");
      g.setAttribute("role", "button");
      g.setAttribute("aria-label", `Node ${i}: choose behaviour`);
      g.addEventListener("click", (e) => { e.stopPropagation(); openPopover(i); });
      g.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); openPopover(i); } });
    }
  }
  const crown = svgEl("text", { class: "crown" }, svg);
  crown.textContent = "👑";
}

/** Update the ring's state (CSS transitions do the animation). */
function updateRing(svg, st) {
  const n = Number(svg.dataset.n);
  const [mx, my] = ringPos(st.master ?? 0, n);
  const crown = svg.querySelector(".crown");
  crown.style.transform = `translate(${mx}px, ${my - 30}px)`;
  crown.classList.toggle("gone", st.master == null);
  svg.querySelectorAll(".links line").forEach((l) => {
    const a = +l.dataset.a, b = +l.dataset.b;
    const hot = st.master != null && (a === st.master || b === st.master);
    const dead = [a, b].some((x) => st.crashed.has(x) || st.excluded.has(x));
    l.classList.toggle("hot", hot && !dead);
    l.classList.toggle("dead", dead);
  });
  svg.querySelectorAll(".rn").forEach((g) => {
    const id = +g.dataset.id;
    const k = st.beh[id] || "honest";
    g.classList.toggle("master", id === st.master);
    g.classList.toggle("byz", k !== "honest");
    g.classList.toggle("crashed", st.crashed.has(id));
    g.classList.toggle("excluded", st.excluded.has(id));
    g.classList.toggle("vc", !!st.vc);
    g.classList.toggle("dormant", !!(st.dormant && st.dormant.has(id)));
    g.querySelector(".badge text").textContent = k === "honest" ? "" : BEH[k].icon;
    g.querySelector(".lab").textContent = st.excluded.has(id) ? "excluded" : st.crashed.has(id) ? "offline" : id === st.master ? "MASTER" : "slave";
  });
}

/** Animate a message dot travelling from one node to another. */
function sendDot(svg, from, to, color, delay) {
  if (reduceMotion || document.hidden) return;
  const n = Number(svg.dataset.n);
  const [x1, y1] = ringPos(from, n), [x2, y2] = ringPos(to, n);
  const c = svgEl("circle", { r: 4.5, class: "pkt", fill: color }, svg.querySelector(".dots"));
  const tr = (p) => `translate(${x1 + (x2 - x1) * p}px, ${y1 + (y2 - y1) * p}px)`;
  const a = c.animate([
    { transform: tr(0), opacity: 0 }, { transform: tr(0.12), opacity: 1, offset: 0.12 },
    { transform: tr(0.88), opacity: 1, offset: 0.88 }, { transform: tr(1), opacity: 0 },
  ], { duration: 620, delay, easing: "cubic-bezier(.45,.05,.35,1)", fill: "both" });
  a.onfinish = () => c.remove();
}

// ------------------------------------------------- behaviour popover menu --
function openPopover(id) {
  if (running) return;
  const pop = $("popover");
  const cfg = cfgOf(sel.config);
  const f = fOf(sel.n);
  const cur = sel.beh[id] || "honest";
  const others = Object.entries(sel.beh).filter(([k, v]) => +k !== id && v !== "honest").length;
  let html = `<div class="pop-h"><span class="sw" style="background:${COLORS[id]}"></span>Node ${id}<span class="muted">${id === 0 ? " · starts as master" : " · starts as slave"}</span></div>`;
  for (const k of BEH_ORDER) {
    const b = BEH[k];
    let note = "";
    if (k !== "honest") {
      const trial = { ...sel.beh, [id]: k };
      const ex = explain(cfg, sel.n, trial);
      const nd = ex.nodes.find((x) => x.id === id);
      if (nd && !nd.active) note = `<span class="pn dorm">dormant here</span>`;
      if (others + 1 > f) note += `<span class="pn over">exceeds f = ${f}</span>`;
    }
    const role = b.role === "master" ? "acts as master" : b.role === "slave" ? "acts as slave" : "";
    html += `<button type="button" class="pop-item${k === cur ? " on" : ""}" data-k="${k}">
      <span class="pi-ic ${k === "honest" ? "h" : ""}">${b.icon}</span>
      <span class="pi-tx"><span class="pi-t">${b.label} ${role ? `<span class="role">${role}</span>` : ""}</span><span class="pi-d">${b.short}</span>${note}</span></button>`;
  }
  pop.innerHTML = html;
  pop.querySelectorAll(".pop-item").forEach((btn) => btn.onclick = (e) => {
    e.stopPropagation();
    setBehaviour(id, btn.dataset.k);
    closePopover();
  });
  // Position next to the node.
  const svg = $("picker");
  const r = svg.getBoundingClientRect(), wrap = svg.parentElement.getBoundingClientRect();
  const s = r.width / 300;
  const [x, y] = ringPos(id, sel.n);
  pop.classList.remove("hidden");
  const pw = pop.offsetWidth;
  let left = r.left - wrap.left + x * s - pw / 2;
  left = Math.max(0, Math.min(left, wrap.width - pw));
  pop.style.left = left + "px";
  pop.style.top = (r.top - wrap.top + y * s + 28 * s) + "px";
  pop.classList.remove("show"); void pop.offsetWidth; pop.classList.add("show");
  svg.querySelectorAll(".rn").forEach((g) => g.classList.toggle("editing", +g.dataset.id === id));
  pop.querySelector(".pop-item.on")?.focus({ preventScroll: true });
}
function closePopover() {
  const pop = $("popover");
  if (pop.classList.contains("hidden")) return;
  pop.classList.add("hidden");
  $("picker").querySelectorAll(".rn.editing").forEach((g) => g.classList.remove("editing"));
}

function setBehaviour(id, k) {
  if ((sel.beh[id] || "honest") === k) return;
  if (k === "honest") delete sel.beh[id]; else sel.beh[id] = k;
  // Does this match a preset? Otherwise it is a custom combination.
  const match = meta.scenarios.find((s) => sameBeh(presetBeh(s.name), sel.beh, sel.n));
  sel.preset = match ? match.name : "custom";
  markPreset();
  const g = $("picker").querySelector(`.rn[data-id="${id}"] .rn-in`);
  if (g && !reduceMotion) g.animate([{ transform: "scale(1)" }, { transform: "scale(1.25)" }, { transform: "scale(1)" }], { duration: 380, easing: "ease-out" });
  refresh(true);
}

function setupSeg() {
  const seg = $("nSeg");
  seg.querySelectorAll("button").forEach((b, idx) => b.onclick = () => {
    if (running) return;
    const n = +b.dataset.n;
    if (n === sel.n) return;
    sel.n = n;
    for (const k of Object.keys(sel.beh)) if (+k >= n) delete sel.beh[k];
    seg.querySelectorAll("button").forEach((x) => { x.classList.toggle("on", x === b); x.setAttribute("aria-checked", x === b); });
    seg.style.setProperty("--pos", idx);
    if (sel.preset !== "custom" && !sameBeh(presetBeh(sel.preset), sel.beh, n)) sel.preset = "custom";
    markPreset();
    buildRing($("picker"), n, true);
    refresh(true);
  });
}

function renderBudget(ex) {
  const f = ex.f, k = ex.faulty.length;
  let segs = "";
  for (let i = 0; i < Math.max(f, k); i++) segs += `<i class="${i < k ? (i < f ? "used" : "over") : ""}"></i>`;
  const msg = k === 0 ? "No faulty nodes" : k <= f ? `${k} of ${f} tolerated` : `${k} faulty: only ${f} tolerated`;
  $("budget").className = "budget " + (k > f ? "bad" : k ? "ok" : "");
  $("budget").innerHTML = `<span>Faulty nodes</span><span class="segs">${segs}</span><b>${msg}</b>`;
  const chips = ex.faulty.map((id) => {
    const kk = sel.beh[id];
    const nd = ex.nodes.find((x) => x.id === id);
    return `<span class="nchip${nd && !nd.active ? " dorm" : ""}" style="--c:${COLORS[id]}"><i></i>N${id} · ${BEH[kk].icon} ${BEH[kk].label}${nd && !nd.active ? " <em>dormant</em>" : ""}<button type="button" data-id="${id}" title="Make node ${id} honest" aria-label="Make node ${id} honest">×</button></span>`;
  }).join("");
  $("nodeChips").innerHTML = chips || `<span class="muted small">Tip: click a node above to make it malicious.</span>`;
  $("nodeChips").querySelectorAll("button").forEach((b) => b.onclick = () => setBehaviour(+b.dataset.id, "honest"));
}

// ------------------------------------------------------ advanced settings --
function setupCollapsers() {
  const wire = (btn, body, onToggle) => {
    $(btn).onclick = () => {
      const open = !$(body).classList.contains("open");
      $(body).classList.toggle("open", open);
      $(btn).setAttribute("aria-expanded", open);
      if (onToggle) onToggle(open);
    };
  };
  wire("advToggle", "advBody");
  wire("briefToggle", "briefBody", (open) => { $("briefToggle").textContent = open ? "Hide details" : "Show details"; });
}
function setBrief(open) {
  $("briefBody").classList.toggle("open", open);
  $("briefToggle").setAttribute("aria-expanded", open);
  $("briefToggle").textContent = open ? "Hide details" : "Show details";
}
function setupAdvanced() {
  $("resetAdv").onclick = () => {
    for (const [k, v] of Object.entries(ADV_DEFAULTS)) $(k).value = v;
    document.querySelectorAll(".grid2 input").forEach((i) => { i.classList.remove("flash"); void i.offsetWidth; i.classList.add("flash"); });
  };
  document.querySelectorAll(".grid2 input").forEach((i) => i.addEventListener("input", () => {
    const bad = i.value === "" || (i.min !== "" && +i.value < +i.min) || (i.max !== "" && +i.value > +i.max);
    i.classList.toggle("invalid", bad);
  }));
}

// ------------------------------------------------------- explanation panel --
function refresh(changed) {
  const cfg = cfgOf(sel.config);
  if (!cfg) return;
  const ex = explain(cfg, sel.n, sel.beh);
  const dormant = new Set(ex.nodes.filter((x) => !x.active).map((x) => x.id));
  updateRing($("picker"), { master: 0, beh: sel.beh, crashed: new Set(), excluded: new Set(), dormant });
  renderBudget(ex);
  renderExplain(ex, cfg);
  const cur = snapshotSel();
  if (changed) showImpact(describeChange(prevSel, cur, meta.configs));
  prevSel = cur;
}

const FLOW = [
  { k: "poll", t: "Poll", d: "Master asks every slave for a reading" },
  { k: "time", t: "Time exchange", d: "Slaves measure their offset (Cristian, best of 4)" },
  { k: "read", t: "Reading", d: "Signed offset, or commitment + range proof" },
  { k: "avg", t: "Average", d: "Median-band average ± aggregation proof" },
  { k: "pbft", t: "PBFT commit", d: "Backups re-verify everything and vote" },
  { k: "adj", t: "Adjust", d: "Every node speeds up / slows down" },
];
const FLOW_HIT = {
  crash: ["poll"], silent_leader: ["poll"], lie_timestamp_us: ["time"], extreme_offset: ["read", "avg"],
  invalid_proof: ["read"], bad_average: ["avg", "pbft"], equivocate: ["pbft"], wrong_adjust: ["adj"],
};

function renderExplain(ex, cfg) {
  $("briefTitle").textContent = ex.title;
  const v = $("verdict");
  v.className = "verdict " + ex.verdict.level;
  v.textContent = ex.verdict.label;

  const hits = new Set();
  for (const nd of ex.nodes) if (nd.active) for (const h of FLOW_HIT[nd.k] || []) hits.add(h);
  const flow = FLOW.map((s, i) => `<div class="fstep${hits.has(s.k) ? " hit" : ""}" style="--i:${i}"><span class="fn">${i + 1}</span><b>${s.t}</b><small>${s.d}</small></div>`).join('<span class="farr">→</span>');

  const nodes = ex.nodes.length
    ? ex.nodes.map((nd) => `<div class="story${nd.active ? "" : " dorm"}" style="--c:${COLORS[nd.id]}">
        <div class="story-h"><span class="sw"></span>Node ${nd.id} · ${BEH[nd.k].icon} ${BEH[nd.k].label}
        <span class="det">${nd.detect}</span>${nd.active ? "" : '<span class="det dormtag">dormant</span>'}</div>
        <p>${nd.story}</p></div>`).join("")
    : `<div class="story" style="--c:var(--good)"><div class="story-h"><span class="sw"></span>All nodes follow the protocol</div>
        <p>Each round node 0 (the master) polls the slaves. Each slave measures its offset with the min-RTT of 4 Cristian exchanges and sends it back,
        ${cfg.zkp ? "hidden in a commitment with a Groth16 range proof" : "as a signed plain value"}. The master takes the median-band average,
        PBFT commits it, and every node slews its clock by <i>average − own offset</i>. Clocks start up to ±${$("initOffset").value} ms apart and should end up well under 1 ms apart.</p></div>`;

  const lead = ex.pred.steps.filter((s) => s.kind !== "slave-excluded").map((s) => {
    const why = s.kind === "stable" ? "leads from here on"
      : s.effect === "excluded" ? "caught → excluded" : s.effect === "timeout" ? "times out" : "suspected";
    return `<span class="lchip ${s.kind === "stable" ? "ok" : s.effect}" style="--c:${COLORS[s.primary]}"><b>View ${s.view}</b> node ${s.primary}<small>${why}</small></span>`;
  }).join('<span class="larr">→</span>');

  const cfgTiles = ex.cfgNotes.map((c) => `<div class="ctile"><div class="ct-h">${c.icon} ${c.title}</div><p>${c.text}</p></div>`).join("");
  const combo = ex.combo.length ? `<ul class="combo">${ex.combo.map((x) => `<li>${x}</li>`).join("")}</ul>` : "";
  const watch = `<ul class="watch">${ex.watch.map((x) => `<li>${x}</li>`).join("")}</ul>`;
  const msl = `<ol class="mspre">${ex.milestones.map((m) => `<li>${m.text}</li>`).join("")}</ol>`;

  const el = $("explain");
  el.innerHTML = `
    <div class="vbox ${ex.verdict.level}"><b>${ex.verdict.label}.</b> ${ex.verdict.text}</div>
    <div class="xsec"><h4>One synchronisation round <span class="muted">(highlighted = where the attack strikes)</span></h4><div class="flow">${flow}</div></div>
    <div class="xsec"><h4>What each node does</h4>${nodes}</div>
    <div class="xsec"><h4>Who will be master <span class="muted">(round-robin, skipping excluded nodes)</span></h4><div class="leaders">${lead}</div></div>
    <div class="xsec"><h4>How ${cfg.name} shapes this</h4><div class="ctiles">${cfgTiles}</div>${combo}</div>
    <div class="xcols">
      <div class="xsec"><h4>What to watch on the dashboard</h4>${watch}</div>
      <div class="xsec"><h4>Expected sequence</h4>${msl}</div>
    </div>`;
  if (!reduceMotion) { el.classList.remove("swap"); void el.offsetWidth; el.classList.add("swap"); }
}

function showImpact(lines) {
  const box = $("impact");
  if (!lines) { box.classList.add("hidden"); return; }
  box.innerHTML = `<div class="imp-h">⚡ What your last change does <button type="button" class="x" aria-label="Dismiss">×</button></div><ul>${lines.map((l) => `<li>${l}</li>`).join("")}</ul>`;
  box.querySelector(".x").onclick = () => box.classList.add("hidden");
  box.classList.remove("hidden", "pop"); void box.offsetWidth; box.classList.add("pop");
}

// ------------------------------------------------------------------ start --
async function start() {
  closePopover();
  const num = (id) => Number($(id).value);
  const custom = sel.preset === "custom";
  const behaviours = {};
  if (custom) for (const [id, k] of Object.entries(sel.beh)) {
    behaviours[id] = k === "lie_timestamp_us" ? { lie_timestamp_us: 40000 } : { [k]: true };
  }
  const body = {
    config: sel.config, scenario: custom ? "custom" : sel.preset, behaviours, n: sel.n,
    duration_s: num("duration"), interval_ms: num("interval"), latency_ms: num("latency"),
    jitter_ms: num("jitter"), init_offset_ms: num("initOffset"), drift_ppm: num("drift"), seed: num("seed"),
  };
  pendingSel = snapshotSel();
  $("startBtn").classList.add("loading");
  const r = await fetch("/api/start", { method: "POST", body: JSON.stringify(body) });
  if (!r.ok) { $("startBtn").classList.remove("loading"); setStatus("error", await r.text()); }
  else { $("savedText").textContent = ""; setRunning(true); }
}
let pendingSel = null;

function setRunning(on) {
  running = on;
  $("startBtn").disabled = on;
  $("stopBtn").disabled = !on;
  $("controls").classList.toggle("locked", on);
  if (!on) $("startBtn").classList.remove("loading");
}

function setStatus(state, text) {
  const p = $("statusPill");
  p.className = "pill " + state;
  p.querySelector(".txt").textContent = { idle: "Idle", setup: "Setting up", running: "Running", done: "Finished", error: "Error" }[state] || state;
  if (!reduceMotion) p.animate([{ transform: "scale(.85)" }, { transform: "scale(1.06)" }, { transform: "scale(1)" }], { duration: 320, easing: "ease-out" });
  $("statusText").textContent = text || "";
  if (state === "done" || state === "error") { setRunning(false); finishMilestones(); }
  if (state === "setup" || state === "running") setRunning(true);
  if (state === "running") $("startBtn").classList.remove("loading");
}

// ----------------------------------------------------------------- stream --
function connect() {
  const es = new EventSource("/api/stream");
  es.onmessage = (e) => handle(JSON.parse(e.data));
  es.onerror = () => setStatus("error", "Lost connection to the GUI server. Is it still running?");
}

function handle(m) {
  switch (m.type) {
    case "hello": if (m.running) setRunning(true); break;
    case "status": setStatus(m.state, m.text); break;
    case "started": onStarted(m); break;
    case "tick": onTick(m); break;
    case "done":
      if (m.saved) $("savedText").textContent = "Raw data saved: " + m.saved;
      break;
  }
}

function onStarted(m) {
  run = newRun(m);
  alignHalf = null;
  const s = pendingSel || snapshotSel();
  const cfg = cfgOf(m.config.name) || cfgOf(s.config);
  run.beh = s.beh;
  run.explain = explain(cfg, m.n, s.beh);
  $("dash").classList.remove("hidden");
  setBrief(false);
  $("impact").classList.add("hidden");
  const scName = m.scenario.name === "custom" ? "custom combination" : (PRESETS[m.scenario.name]?.title || m.scenario.name);
  $("runTitle").innerHTML = `<b>${m.config.name} · ${m.config.title}</b> · scenario <b>${scName}</b> · ` +
    `${m.n} nodes (f=${Math.floor((m.n - 1) / 3)}) · ${m.suite} · ZKP bound L = ±${m.bound_ms} ms`;
  $("rounds").querySelector("tbody").innerHTML = "";
  $("events").innerHTML = "";
  $("log").textContent = "";
  $("stats").innerHTML = "";
  buildNodeCards(m.n);
  buildRing($("topo"), m.n, false);
  updateRing($("topo"), { master: 0, beh: s.beh, crashed: new Set(), excluded: new Set() });
  buildMilestones(run.explain.milestones);
  $("legend").innerHTML = Array.from({ length: m.n }, (_, i) =>
    `<span><i style="background:${COLORS[i]}"></i>node ${i}</span>`).join("");
  addEvent(0, "info", `Started ${m.config.name} with ${scName}. ${run.explain.verdict.label}: ${run.explain.verdict.text}`);
  // Stagger the dashboard in.
  if (!reduceMotion) {
    [...$("dash").children].forEach((c, i) => c.animate(
      [{ opacity: 0, transform: "translateY(14px)" }, { opacity: 1, transform: "none" }],
      { duration: 450, delay: 60 * i, easing: "cubic-bezier(.2,.7,.2,1)", fill: "backwards" }));
  }
  requestAnimationFrame(drawCharts);
}

function buildNodeCards(n) {
  const box = $("nodes");
  box.innerHTML = "";
  for (let i = 0; i < n; i++) {
    const d = document.createElement("div");
    d.className = "node"; d.id = "node" + i;
    d.style.setProperty("--c", COLORS[i]);
    d.style.setProperty("--i", i);
    d.innerHTML = `
      <div class="hd"><span class="name">Node ${i}</span><span class="tags"></span></div>
      <div class="clock">--:--:--.---</div>
      <div class="msbar"><i></i></div>
      <div class="row"><span>offset vs real time</span><span class="off">–</span></div>
      <div class="row"><span>offset vs master</span><span class="vsm">–</span></div>
      <div class="row"><span>view / last round</span><span class="vr">–</span></div>
      <div class="act"></div>`;
    box.appendChild(d);
  }
}

function fmtMs(v, digits = 3) {
  if (v === undefined || v === null || isNaN(v)) return "–";
  return (v >= 0 ? "+" : "−") + Math.abs(v).toFixed(digits) + " ms";
}

function onTick(m) {
  if (!run) return;
  run.t = m.t; run.lastT = m.t; run.lastWall = performance.now();
  run.nodes = m.nodes;
  run.stats = m.stats;
  for (const nd of m.nodes) {
    if (!nd.crashed) run.offsets[nd.id].push([m.t, nd.offset_ms]);
  }
  run.spread.push([m.t, Math.max(m.spread_ms, 0.001)]);

  for (const r of m.rounds || []) onRound(r);
  for (const e of m.events || []) onEvent(e);
  if (m.logs && m.logs.length) {
    const lg = $("log");
    lg.textContent += m.logs.join("\n") + "\n";
    if (lg.textContent.length > 120000) lg.textContent = lg.textContent.slice(-90000);
    lg.scrollTop = lg.scrollHeight;
  }
  checkMilestones({ type: "tick", t: m.t, spread: m.spread_ms });
  updateCards();
  updateTopo();
  updateStats();
  drawCharts();
}

// ------------------------------------------------------------- milestones --
function buildMilestones(list) {
  run.milestones = list.map((m) => ({ ...m, done: false }));
  $("milestones").innerHTML = run.milestones.map((m, i) =>
    `<li id="ms${i}" style="--i:${i}"><span class="mk"></span><span class="mt">${m.text}</span><span class="mtime"></span></li>`).join("");
  updateMsCount();
}
function checkMilestones(e) {
  if (!run || !run.milestones) return;
  run.milestones.forEach((m, i) => {
    if (m.done) return;
    let hit = false;
    try { hit = m.match(e); } catch { hit = false; }
    if (!hit) return;
    m.done = true;
    const li = $("ms" + i);
    li.classList.add("done");
    li.querySelector(".mtime").textContent = run.t.toFixed(1) + " s";
    updateMsCount();
  });
}
function updateMsCount() {
  const d = run.milestones.filter((m) => m.done).length;
  $("msCount").textContent = `${d} / ${run.milestones.length}`;
}
function finishMilestones() {
  if (!run || !run.milestones) return;
  run.milestones.forEach((m, i) => { if (!m.done) $("ms" + i)?.classList.add("missed"); });
}

// ------------------------------------------------------------ rounds/events --
function onRound(r) {
  let row = run.rounds.get(r.round);
  const isNew = !row;
  if (!row) { row = { round: r.round, view: r.view, leader: r.leader, mean: r.mean_ms, readings: r.readings, included: r.included, latency: 0, adj: {} }; run.rounds.set(r.round, row); }
  row.adj[r.node] = r.adjust_ms;
  if (r.latency_ms > 0) row.latency = r.latency_ms;
  run.lastAdjust[r.node] = { round: r.round, adj: r.adjust_ms, at: performance.now() };
  renderRound(row, isNew);
  if (isNew) {
    addEvent(r.t, "good", `Round ${r.round} committed (master ${r.leader}): average offset ${fmtMs(r.mean_ms)} over ${r.included}/${r.readings} readings`);
    checkMilestones({ type: "round", included: r.included, readings: r.readings, leader: r.leader });
    animateRound(r);
  }
}

function animateRound(r) {
  const svg = $("topo");
  const ph = $("phase");
  ph.textContent = `round ${r.round} committed`;
  ph.classList.remove("blink"); void ph.offsetWidth; ph.classList.add("blink");
  const n = run.n;
  const excl = new Set(run.nodes.filter((x) => x.excluded).map((x) => x.id));
  const crashed = new Set(run.nodes.filter((x) => x.crashed).map((x) => x.id));
  for (let i = 0; i < n; i++) {
    if (i === r.leader || excl.has(i) || crashed.has(i)) continue;
    sendDot(svg, i, r.leader, COLORS[i], 0);           // reading in
    sendDot(svg, r.leader, i, "#2ec4a6", 650);         // correction out
  }
}

function renderRound(row, isNew) {
  const tb = $("rounds").querySelector("tbody");
  let tr = document.getElementById("r" + row.round);
  if (!tr) {
    tr = document.createElement("tr");
    tr.id = "r" + row.round;
    tb.prepend(tr);
    while (tb.children.length > 60) tb.lastChild.remove();
  }
  if (isNew) { tr.classList.remove("newrow"); void tr.offsetWidth; tr.classList.add("newrow"); }
  const chips = Object.keys(row.adj).sort().map((k) => {
    const v = row.adj[k];
    return `<span class="chip" style="color:${COLORS[k]}">N${k} ${v >= 0 ? "+" : "−"}${Math.abs(v).toFixed(2)}</span>`;
  }).join("");
  const filtered = row.included < row.readings ? ' class="filt" title="Some readings were filtered out as outliers"' : "";
  tr.innerHTML = `<td>${row.round}</td><td>${row.view}</td><td style="color:${COLORS[row.leader]}">node ${row.leader}</td>` +
    `<td>${fmtMs(row.mean, 2)}</td><td${filtered}>${row.included}/${row.readings}</td>` +
    `<td>${row.latency ? row.latency.toFixed(0) + " ms" : "–"}</td><td class="adj">${chips}</td>`;
}

function onEvent(e) {
  const d = e.detail || "";
  switch (e.kind) {
    case "new_view": {
      const m = /view=(\d+) primary=(\d+)/.exec(d);
      if (m) checkMilestones({ type: "event", kind: "new_view", view: +m[1], primary: +m[2] });
      if (!m || run.seenViews.has(m[1])) return;
      run.seenViews.add(m[1]);
      run.markers.push({ t: e.t, color: "#f2b33d", label: "view " + m[1] });
      addEvent(e.t, "warn", `View change → view ${m[1]}: node ${m[2]} is the new master`);
      return;
    }
    case "excluded": {
      const m = /accused=(\d+) kind=(\d+)/.exec(d);
      if (m) checkMilestones({ type: "event", kind: "excluded", accused: +m[1] });
      if (!m || run.seenExcl.has(m[1])) return;
      run.seenExcl.add(m[1]);
      const kinds = { 1: "signed invalid proposal", 2: "equivocation (two signed proposals)", 3: "signed invalid reading / proof" };
      run.markers.push({ t: e.t, color: "#e8657a", label: "excl " + m[1] });
      addEvent(e.t, "bad", `Node ${m[1]} EXCLUDED from leader election, evidence: ${kinds[m[2]] || "kind " + m[2]}`);
      return;
    }
  }
  checkMilestones({ type: "event", kind: e.kind, node: e.node });
  switch (e.kind) {
    case "reading_rejected": addEvent(e.t, "bad", `Master rejected a reading: ${d}`); return;
    case "opening_rejected": addEvent(e.t, "bad", `Master rejected an opening: ${d}`); return;
    case "adjust_mismatch": addEvent(e.t, "warn", `Node ${e.node}: master's Adjust differs from the committed value (${d}). Applying the committed value and suspecting the master`); return;
    case "witness_suspect": addEvent(e.t, "warn", `Node ${e.node}: witness check found slaves out of sync (${d}). Suspecting the master`); return;
    case "round_abandoned": addEvent(e.t, "warn", `Round abandoned: ${d}`); return;
    case "session_reject": addEvent(e.t, "bad", `Node ${e.node} rejected a frame: ${d}`); return;
    default: addEvent(e.t, "info", `${e.kind}: ${d}`);
  }
}

function addEvent(t, cls, text) {
  const f = $("events");
  const d = document.createElement("div");
  d.className = "ev " + cls;
  d.innerHTML = `<span class="tm">${t.toFixed(1)}s</span>${text}`;
  f.prepend(d);
  while (f.children.length > 200) f.lastChild.remove();
}

// ------------------------------------------------------------- node cards --
function refNode() {
  const honest = run.nodes.filter((x) => x.behaviour === "honest");
  return honest[0] || run.nodes[0];
}

function updateCards() {
  const nodes = run.nodes;
  const ref = refNode();
  for (const nd of nodes) {
    const card = $("node" + nd.id);
    if (!card) continue;
    const prev = run.prev[nd.id] || {};
    // "Master" according to the honest majority's view.
    const isMaster = ref && ref.primary === nd.id && !nd.crashed;
    card.classList.toggle("master", isMaster);
    card.classList.toggle("dead", nd.crashed);
    card.classList.toggle("excl", nd.excluded);
    card.classList.toggle("vchg", nd.in_view_change && !nd.crashed);
    if (!reduceMotion) {
      if (isMaster && prev.master === false) card.animate([{ transform: "scale(1)" }, { transform: "scale(1.04)" }, { transform: "scale(1)" }], { duration: 500, easing: "ease-out" });
      if (nd.excluded && prev.excluded === false) card.animate([{ transform: "translateX(0)" }, { transform: "translateX(-6px)" }, { transform: "translateX(6px)" }, { transform: "translateX(-4px)" }, { transform: "translateX(0)" }], { duration: 450 });
    }
    run.prev[nd.id] = { master: isMaster, excluded: nd.excluded };
    let tags = isMaster ? `<span class="tag m">👑 MASTER</span>` : `<span class="tag s">slave</span>`;
    if (nd.behaviour !== "honest") tags += `<span class="tag byz" title="Byzantine behaviour">${nd.behaviour.toUpperCase()}</span>`;
    if (nd.excluded) tags += `<span class="tag ex">EXCLUDED</span>`;
    if (nd.crashed) tags += `<span class="tag dead">DOWN</span>`;
    else if (nd.in_view_change) tags += `<span class="tag vc">VIEW CHANGE</span>`;
    const tg = card.querySelector(".tags");
    if (tg.dataset.h !== tags) { tg.innerHTML = tags; tg.dataset.h = tags; }
    card.querySelector(".off").textContent = fmtMs(nd.offset_ms);
    const master = nodes.find((x) => x.id === (ref ? ref.primary : 0));
    card.querySelector(".vsm").textContent = master ? fmtMs(nd.offset_ms - master.offset_ms) : "–";
    card.querySelector(".vr").textContent = `${nd.view} / ${nd.last_round}`;
    const la = run.lastAdjust[nd.id];
    const act = card.querySelector(".act");
    let html = "";
    if (la && la.adj !== 0) {
      const up = la.adj > 0;
      html = `<span class="${up ? "up" : "down"}"><span class="arr">${up ? "▲" : "▼"}</span> ${up ? "speed up" : "slow down"} by ${Math.abs(la.adj).toFixed(3)} ms</span> <span class="muted">(round ${la.round})</span>`;
    } else if (la) html = `<span class="muted">no change (round ${la.round})</span>`;
    if (act.dataset.r !== String(la?.round)) {
      act.innerHTML = html;
      act.dataset.r = String(la?.round);
      if (la && !reduceMotion) act.animate([{ opacity: 0, transform: "translateY(-4px)" }, { opacity: 1, transform: "none" }], { duration: 300 });
    }
  }
}

function updateTopo() {
  const ref = refNode();
  if (!ref) return;
  const master = ref.primary;
  if (run.master !== null && run.master !== master) {
    const ph = $("phase");
    ph.textContent = `view change → node ${master} is master`;
    ph.classList.remove("blink"); void ph.offsetWidth; ph.classList.add("blink");
  }
  run.master = master;
  updateRing($("topo"), {
    master, beh: run.beh || {},
    crashed: new Set(run.nodes.filter((x) => x.crashed).map((x) => x.id)),
    excluded: new Set(run.nodes.filter((x) => x.excluded).map((x) => x.id)),
    vc: run.nodes.some((x) => x.in_view_change && !x.crashed && x.behaviour === "honest"),
  });
}

function updateStats() {
  const s = run.stats;
  if (!s) return;
  const ref = refNode();
  const last = run.spread.length ? run.spread[run.spread.length - 1][1] : 0;
  const tiles = [
    ["Current spread", last < 1 ? (last * 1000).toFixed(0) + " µs" : last.toFixed(2) + " ms", last < 1 ? "good" : last > 20 ? "bad" : ""],
    ["Committed rounds", s.rounds],
    ["View / master", ref ? `${ref.view} / node ${ref.primary}` : "–"],
    ["View changes", s.view_changes, s.view_changes ? "warn" : ""],
    ["Exclusions", s.exclusions, s.exclusions ? "bad" : ""],
    ["Round latency p50", s.round_latency_ms ? s.round_latency_ms.toFixed(0) + " ms" : "–"],
    ["Handshakes", `${s.handshakes} · ${s.handshake_ms.toFixed(1)} ms`],
    ["Bytes / handshake", s.handshake_bytes ? s.handshake_bytes.toLocaleString() + " B" : "–"],
    ["ZKP prove p50", s.prove_ms ? s.prove_ms.toFixed(1) + " ms" : "off"],
    ["ZKP verify p50", s.verify_ms ? s.verify_ms.toFixed(2) + " ms" : "off"],
    ["Sent per node", s.kb_per_node.toFixed(1) + " KB"],
    ["Rejected frames", s.session_rejects],
  ];
  const box = $("stats");
  if (box.children.length !== tiles.length) {
    box.innerHTML = tiles.map(([l], i) => `<div class="stat" style="--i:${i}"><div class="v"></div><div class="l">${l}</div></div>`).join("");
  }
  tiles.forEach(([, v, cls], i) => {
    const tile = box.children[i];
    const ve = tile.querySelector(".v");
    const sv = String(v);
    tile.className = "stat" + (cls ? " " + cls : "");
    if (ve.textContent !== sv) {
      const first = ve.textContent === "";
      ve.textContent = sv;
      // Only flash the "event-like" tiles, not values that change every tick.
      if (!first && [1, 2, 3, 4].includes(i)) { tile.classList.remove("bump"); void tile.offsetWidth; tile.classList.add("bump"); }
    }
  });
}

// ------------------------------------------- live clocks (every frame) --
function pad(n, w = 2) { return String(n).padStart(w, "0"); }
function fmtClock(ms) {
  const d = new Date(ms);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.${pad(d.getMilliseconds(), 3)}`;
}

function animate() {
  const now = Date.now();
  $("realTime").textContent = fmtClock(now);
  if (run && run.nodes.length) {
    for (const nd of run.nodes) {
      const card = $("node" + nd.id);
      if (!card) continue;
      // Each node's clock = real time + its current offset.
      const t = now + nd.offset_ms;
      card.querySelector(".clock").textContent = fmtClock(t);
      card.querySelector(".msbar i").style.width = ((((t % 1000) + 1000) % 1000) / 10).toFixed(1) + "%";
    }
    drawAlign();
  }
  requestAnimationFrame(animate);
}

// ---------------------------------------------------------------- charts --
function setupCanvas(cv) {
  const dpr = window.devicePixelRatio || 1;
  // The CSS height is fixed once from the markup; cv.height is then the
  // high-resolution backing size (must not be read back as the CSS size).
  if (!cv.dataset.h) cv.dataset.h = cv.getAttribute("height");
  const w = cv.clientWidth, h = Number(cv.dataset.h);
  if (cv.width !== Math.round(w * dpr) || cv.height !== Math.round(h * dpr)) {
    cv.width = Math.round(w * dpr); cv.height = Math.round(h * dpr);
    cv.style.height = h + "px";
  }
  const ctx = cv.getContext("2d");
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);
  return { ctx, w, h };
}

function niceStep(range, target) {
  const raw = range / target;
  const p = Math.pow(10, Math.floor(Math.log10(raw)));
  const f = raw / p;
  return (f < 1.5 ? 1 : f < 3.5 ? 2 : f < 7.5 ? 5 : 10) * p;
}

function fmtTick(v) {
  const a = Math.abs(v);
  if (a === 0) return "0";
  if (a >= 100) return v.toFixed(0);
  if (a >= 1) return +v.toFixed(1) + "";
  if (a >= 0.01) return +v.toFixed(3) + "";
  return v.toExponential(0);
}

/** drawChart draws line series with axes, grid and vertical event markers. */
function drawChart(cv, series, o) {
  const { ctx, w, h } = setupCanvas(cv);
  const L = 54, R = 10, T = 14, B = 22;
  const pw = w - L - R, ph = h - T - B;
  const xmax = Math.max(o.xmax, 1), xmin = o.xmin ?? 0;
  let ymin = Infinity, ymax = -Infinity;
  for (const s of series) for (const [x, y] of s.pts) {
    if (x < xmin) continue;
    if (y < ymin) ymin = y;
    if (y > ymax) ymax = y;
  }
  if (!isFinite(ymin)) { ymin = o.log ? 0.1 : -1; ymax = o.log ? 100 : 1; }
  const fy = o.log ? (v) => Math.log10(Math.max(v, 1e-4)) : (v) => v;
  let lo, hi;
  if (o.log) {
    lo = Math.floor(fy(ymin)); hi = Math.ceil(fy(ymax));
    if (hi - lo < 1) hi = lo + 1;
  } else {
    const pad = Math.max((ymax - ymin) * 0.08, 0.05);
    lo = ymin - pad; hi = ymax + pad;
  }
  const X = (x) => L + ((x - xmin) / (xmax - xmin)) * pw;
  const Y = (v) => T + ph - ((fy(v) - lo) / (hi - lo)) * ph;

  // grid + y labels
  ctx.font = "11px Segoe UI, sans-serif";
  ctx.textBaseline = "middle"; ctx.textAlign = "right";
  ctx.strokeStyle = "#232c42"; ctx.fillStyle = "#8b94aa"; ctx.lineWidth = 1;
  if (o.log) {
    for (let e = lo; e <= hi; e++) {
      const y = T + ph - ((e - lo) / (hi - lo)) * ph;
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + pw, y); ctx.stroke();
      ctx.fillText(fmtTick(Math.pow(10, e)), L - 6, y);
    }
  } else {
    const st = niceStep(hi - lo, 5);
    for (let v = Math.ceil(lo / st) * st; v <= hi; v += st) {
      const y = Y(v);
      ctx.strokeStyle = Math.abs(v) < st / 1e6 ? "#3a4766" : "#232c42";
      ctx.beginPath(); ctx.moveTo(L, y); ctx.lineTo(L + pw, y); ctx.stroke();
      ctx.fillText(fmtTick(v), L - 6, y);
    }
  }
  // x labels
  ctx.textAlign = "center"; ctx.textBaseline = "top"; ctx.strokeStyle = "#232c42";
  const xs = niceStep(xmax - xmin, 8);
  for (let x = Math.ceil(xmin / xs) * xs; x <= xmax; x += xs) {
    const px = X(x);
    ctx.beginPath(); ctx.moveTo(px, T); ctx.lineTo(px, T + ph); ctx.stroke();
    ctx.fillText(+x.toFixed(1) + "s", px, T + ph + 5);
  }
  // markers
  ctx.save();
  for (const m of o.markers || []) {
    if (m.t < xmin) continue;
    const px = X(m.t);
    ctx.strokeStyle = m.color; ctx.setLineDash([4, 4]);
    ctx.beginPath(); ctx.moveTo(px, T); ctx.lineTo(px, T + ph); ctx.stroke();
    ctx.setLineDash([]); ctx.fillStyle = m.color; ctx.textAlign = "left"; ctx.textBaseline = "top";
    ctx.fillText(m.label, px + 3, T);
  }
  ctx.restore();
  // lines
  ctx.save();
  ctx.beginPath(); ctx.rect(L, T, pw, ph); ctx.clip();
  for (const s of series) {
    ctx.strokeStyle = s.color; ctx.lineWidth = s.width || 1.8; ctx.lineJoin = "round";
    ctx.beginPath();
    let started = false;
    for (const [x, y] of s.pts) {
      if (x < xmin - 1) continue;
      const px = X(x), py = Y(y);
      if (!started) { ctx.moveTo(px, py); started = true; } else ctx.lineTo(px, py);
    }
    ctx.stroke();
  }
  ctx.restore();
}

function drawCharts() {
  if (!run) return;
  const zoom = $("zoomOffsets").checked;
  const xmax = Math.max(run.t, 1);
  drawChart($("offsets"), run.offsets.map((pts, i) => ({ pts, color: COLORS[i] })),
    { xmin: zoom ? Math.max(0, xmax - 5) : 0, xmax, markers: run.markers });
  drawChart($("spread"), [{ pts: run.spread, color: "#2ec4a6", width: 2.2 }],
    { log: true, xmin: 0, xmax, markers: run.markers });
}

/** drawAlign: every clock as a dot on a ruler centred on real time (auto-zoom).
 *  The ruler's scale is eased between frames so zooming in looks smooth. */
let alignHalf = null;
function drawAlign() {
  const cv = $("align");
  const { ctx, w, h } = setupCanvas(cv);
  const nodes = run.nodes.filter((x) => !x.crashed);
  let maxAbs = 0.5;
  for (const nd of nodes) maxAbs = Math.max(maxAbs, Math.abs(nd.offset_ms));
  const range = niceStep(maxAbs * 2.4, 1) * 1; // half-width of the ruler
  const target = Math.max(range, maxAbs * 1.15);
  alignHalf = alignHalf == null || reduceMotion ? target : alignHalf + (target - alignHalf) * 0.12;
  const half = alignHalf;
  $("alignRange").textContent = `ruler ±${half < 1 ? (half * 1000).toFixed(0) + " µs" : half.toFixed(half < 10 ? 1 : 0) + " ms"}`;
  const L = 20, R = 20, mid = h / 2;
  const X = (v) => L + ((v + half) / (2 * half)) * (w - L - R);
  ctx.strokeStyle = "#2a3550"; ctx.lineWidth = 2;
  ctx.beginPath(); ctx.moveTo(L, mid); ctx.lineTo(w - R, mid); ctx.stroke();
  ctx.fillStyle = "#8b94aa"; ctx.font = "11px Segoe UI, sans-serif"; ctx.textAlign = "center";
  for (let k = -4; k <= 4; k++) {
    const v = (k / 4) * half, px = X(v);
    ctx.fillRect(px - 0.5, mid - (k === 0 ? 14 : 6), 1, k === 0 ? 28 : 12);
    if (k % 2 === 0) ctx.fillText((v >= 0 ? "+" : "") + (half < 1 ? (v * 1000).toFixed(0) + "µs" : v.toFixed(half < 10 ? 1 : 0) + "ms"), px, h - 4);
  }
  ctx.fillStyle = "#e7eaf1"; ctx.fillText("real time", X(0), 10);
  nodes.forEach((nd, i) => {
    const px = Math.max(L, Math.min(w - R, X(nd.offset_ms))), py = mid + ((i % 2) ? 9 : -9);
    ctx.fillStyle = COLORS[nd.id];
    ctx.beginPath(); ctx.arc(px, py, 6, 0, Math.PI * 2); ctx.fill();
    ctx.fillStyle = "#0e1320"; ctx.font = "bold 9px Segoe UI"; ctx.textBaseline = "middle";
    ctx.fillText(nd.id, px, py + 0.5);
    ctx.textBaseline = "alphabetic"; ctx.font = "11px Segoe UI, sans-serif";
  });
}

init();
