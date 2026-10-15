// Angerona web UI - vanilla JS SPA (no build step, no deps).
"use strict";

const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const joinRel = (prefix, rel) => [prefix, rel].filter(Boolean).join("/").replace(/\/+/g, "/");
const shorten = (s, n = 140) => {
  const v = String(s ?? "");
  return v.length > n ? v.slice(0, n - 1) + "…" : v;
};

let currentRun = null;      // run id
let runDetail = null;       // cached detail
let liveTimer = null;       // live poll interval
let liveSince = 0;
let traceSince = 0;
let lastDetailRefresh = 0;
let pollTimer = null;       // run-list auto-refresh
let formMode = "start";
let editRunId = null;
let pickerEntries = [];
let pickerSelected = "";
const DETAIL_REFRESH_MS = 6000;
// The fragment is never sent to the HTTP server, so the bearer token cannot
// appear in access logs. Open remote UI links as /#token=<value>.
const initialFragment = new URLSearchParams(window.location.hash.slice(1));
if (initialFragment.has("token")) {
  sessionStorage.setItem("angerona_web_token", initialFragment.get("token") || "");
  history.replaceState(null, "", window.location.pathname + window.location.search);
}
const webAuthToken = sessionStorage.getItem("angerona_web_token") || "";

// ---------------------------------------------------------------- API helpers
async function api(path, opts) {
  const request = { ...(opts || {}) };
  request.headers = { ...(request.headers || {}) };
  if (webAuthToken) request.headers.Authorization = "Bearer " + webAuthToken;
  const r = await fetch(path, request);
  const txt = await r.text();
  let j; try { j = txt ? JSON.parse(txt) : {}; } catch { j = { error: txt }; }
  if (!r.ok) throw new Error(j.error || ("HTTP " + r.status));
  return j;
}

// ---------------------------------------------------------------- runs list
async function loadEngines() {
  try {
    const e = await api("/api/engines");
    $("#engineBadges").innerHTML =
      `<span class="badge ${e.ida.ready ? "ok" : "no"}">IDA ${e.ida.ready ? "ready" : "✕"}</span>` +
      `<span class="badge ${e.ghidra.ready ? "ok" : "no"}">Ghidra ${e.ghidra.ready ? "ready" : "✕"}</span>`;
  } catch {}
}

async function loadRuns() {
  const body = $("#runsBody");
  const active = $("#activeRuns");
  if (!body.children.length) body.innerHTML = `<div class="runs-empty"><span class="spinner"></span> loading…</div>`;
  try {
    const { runs } = await api("/api/runs");
    const activeRuns = runs.filter(r => normalizeStatus(r.status) === "running");
    active.innerHTML = activeRuns.map(r => `
      <div class="active-card" data-run="${esc(r.id)}" tabindex="0" role="button">
        <div><span class="dot running"></span><b>Running now</b></div>
        <div class="active-title"><b>${esc(r.binary_name)}</b><span class="muted mono">${esc(r.id)}</span></div>
        <div>${esc(r.engine || "—")} · ${esc(r.agent || "—")}</div>
        <div class="muted">${esc(shorten(r.last_event_text || `${r.live_event_count || 0} live events`, 120))}</div>
      </div>`).join("");
    if (!runs.length) {
      body.innerHTML = `<div class="runs-empty">No runs yet. Click <b>＋ New run</b> to start one.</div>`;
      return;
    }
    body.innerHTML = runs.map(r => `
      <div class="runs-row" data-run="${esc(r.id)}" tabindex="0" role="button">
        <div><span class="dot ${normalizeStatus(r.status)}"></span>${statusLabel(normalizeStatus(r.status))}</div>
        <div><div>${esc(r.binary_name)}</div><div class="muted mono" style="font-size:11px">${esc(r.id)}</div></div>
        <div class="muted">${esc(r.engine || "—")}</div>
        <div class="muted">${esc(r.agent || "—")}</div>
        <div class="muted">${esc(r.started || "—")}</div>
        <div>${r.worker_count} <span class="muted">(${r.workers_converged}✓)</span></div>
        <div>${r.coverage_complete ? "✓ complete" : (normalizeStatus(r.status) === "running" ? "in progress" : "partial")}</div>
        <div class="muted">${esc(shorten(r.last_event_text || r.note || "—", 90))}</div>
      </div>`).join("");
  } catch (e) {
    active.innerHTML = "";
    body.innerHTML = `<div class="runs-empty" style="color:var(--red)">${esc(e.message)}</div>`;
  }
}

function statusLabel(s) {
  return { running: "Running", paused: "Paused", completed: "Done", partial: "Partial", failed: "Failed" }[s] || "Partial";
}

function normalizeStatus(s) {
  return (["running", "paused", "completed", "partial", "failed"].includes(s)) ? s : "partial";
}

// ---------------------------------------------------------------- run detail
async function openRun(id) {
  currentRun = id;
  liveSince = 0;
  traceSince = 0;
  lastDetailRefresh = 0;
  $("#tab-live").innerHTML = "";
  $("#tab-trace").innerHTML = "";
  $("#fileViewer").hidden = true;
  $("#listView").hidden = true;
  $("#detailView").hidden = false;
  stopListPoll();
  await refreshDetail();
  startLivePoll();
  switchTab("overview");
}

async function refreshDetail() {
  if (!currentRun) return;
  try {
    runDetail = await api(`/api/runs/${encodeURIComponent(currentRun)}`);
    renderDetail(runDetail);
    lastDetailRefresh = Date.now();
  } catch (e) {
    $("#detailTitle").textContent = "Error: " + e.message;
  }
}

function renderDetail(r) {
  $("#detailTitle").innerHTML = `${esc(r.binary_name)} <span class="muted" style="font-weight:400;font-size:13px">— ${esc(r.id)}</span>`;
  const status = normalizeStatus(r.status);
  const pill = $("#detailStatus");
  pill.className = "status-pill status-" + status;
  pill.innerHTML = `<span class="dot ${status}"></span> ${statusLabel(status)}`;
  const running = status === "running";
  const canResume = !running && status !== "completed" && Boolean(r.resumable);
  $("#detailActions").innerHTML = `
    <button class="btn" data-run-action="edit" ${running ? "disabled" : ""}>Edit</button>
    ${running ? '<button class="btn" data-run-action="pause">Pause safely</button>' : ""}
    ${canResume ? '<button class="btn primary" data-run-action="resume">Resume</button>' : ""}
    <button class="btn primary" data-run-action="rerun">Rerun</button>
    <button class="btn danger" data-run-action="delete" ${running ? "disabled" : ""}>Delete</button>`;

  $("#detailMeta").innerHTML = `
    <span><b>Binary:</b> <code>${esc(r.binary)}</code></span>
    <span><b>Engine:</b> ${esc(r.engine || "—")}</span>
    <span><b>Agent:</b> ${esc(r.agent || "—")}</span>
    <span><b>Reviewer:</b> ${esc(r.reviewer || "—")}</span>
    <span><b>Sandbox:</b> ${r.sandbox ? "on" : "off"}</span>
    <span><b>Started:</b> ${esc(r.started || "—")}</span>
    <span><b>Finished:</b> ${esc(r.finished || (status === "running" ? "in progress" : "—"))}</span>
    <span><b>Rounds:</b> ${r.total_rounds ?? "—"}</span>
    <span><b>Workers:</b> ${r.worker_count} (${r.workers_converged} converged)</span>
    <span><b>Coverage:</b> ${r.coverage_complete ? "complete" : (status === "running" ? "in progress" : "partial")}</span>
    ${r.note ? `<span class="muted">(${esc(r.note)})</span>` : ""}`;

  renderOverview(r);
  renderDocs(r);
  renderCode(r);
  renderWorkers(r);
  renderArtifacts(r);
  renderRaw(r);
}

// ----- overview
function renderOverview(r) {
  const swarm = r.swarm || {};
  const workers = swarm.workers || [];
  const rawFiles = (r.tree.children || []).filter(c => c.name === "raw")[0]?.children || [];
  const docs = (r.tree.children || []).filter(c => c.name === "docs")[0]?.children || [];
  const counts = r.export?.counts || {};
  const md = r.export?.metadata || {};
  const artifacts = r.artifacts || {};
  const latest = artifacts.latest || [];
  $("#tab-overview").innerHTML = `
    <div class="card"><h3>Run summary</h3>
      <div class="summary-band">
        <div class="summary-tile"><div class="label">Status</div><div class="value">${statusLabel(normalizeStatus(r.status))}</div></div>
        <div class="summary-tile"><div class="label">Engine / agent</div><div class="value">${esc(r.engine || "—")} / ${esc(r.agent || "—")}</div></div>
        <div class="summary-tile"><div class="label">Workers</div><div class="value">${workers.length} total · ${r.workers_converged} converged</div></div>
        <div class="summary-tile"><div class="label">Artifacts</div><div class="value">${artifacts.total_files ?? 0} files · ${humanSize(artifacts.total_bytes || 0)}</div></div>
      </div>
    </div>
    <div class="card"><h3>Binary and code export</h3>
      <div class="grid">
        <div class="kv"><span class="k">Format</span><span class="v">${esc(md.executable_format || r.security?.format || "—")}</span></div>
        <div class="kv"><span class="k">Architecture</span><span class="v">${esc(md.language_id || "—")}</span></div>
        <div class="kv"><span class="k">Functions</span><span class="v">${counts.functions ?? "—"}</span></div>
        <div class="kv"><span class="k">Decompiled</span><span class="v">${counts.decompiled_functions ?? "—"}</span></div>
        <div class="kv"><span class="k">Strings</span><span class="v">${counts.strings ?? "—"}</span></div>
        <div class="kv"><span class="k">Imports</span><span class="v">${counts.imports ?? "—"}</span></div>
        <div class="kv"><span class="k">Converged</span><span class="v">${r.converged ? "✓ yes" : "✕ no"}</span></div>
        <div class="kv"><span class="k">Coverage complete</span><span class="v">${r.coverage_complete ? "✓" : "✕"}</span></div>
        <div class="kv"><span class="k">Supervisor rounds</span><span class="v">${swarm.supervisor_rounds ?? "—"}</span></div>
        <div class="kv"><span class="k">Started / Finished</span><span class="v">${esc(r.started)} → ${esc(r.finished || "—")}</span></div>
        <div class="kv"><span class="k">Binary</span><span class="v mono" style="font-size:11px">${esc(r.binary)}</span></div>
      </div>
    </div>
    <div class="card"><h3>Exploit mitigations</h3>
      ${r.security?.summary ? `<div class="fg2">${esc(r.security.summary)}</div>` : `<div class="muted">No security_properties.json yet.</div>`}
      ${r.security?.mitigations ? `<div class="finding-tags" style="margin-top:10px">${Object.entries(r.security.mitigations).map(([k, v]) =>
        `<span class="tag">${esc(k)}: ${esc(v)}</span>`).join("")}</div>` : ""}
    </div>
    <div class="card"><h3>Workers (${workers.length})</h3>
      ${workers.length ? workers.map(w => `
        <div class="worker-card">
          <div class="worker-head" data-worker-jump="${esc(w.id)}" tabindex="0" role="button">
            <span class="wid">${esc(w.id)}</span>
            <span class="wtitle">${esc(w.title)}</span>
            <span class="muted">${w.converged ? "✓ converged" : "✕ not converged"} · ${w.rounds} round(s)</span>
          </div>
        </div>`).join("") : `<div class="muted">No workers recorded yet.</div>`}
    </div>
    <div class="card"><h3>Quick links</h3>
      <div class="finding-tags">
        ${docs.find(d => d.name === "consolidated_report.md") ? `<span class="tag" data-file="docs/consolidated_report.md" tabindex="0" role="button">consolidated_report.md</span>` : ""}
        ${docs.find(d => d.name === "findings.md") ? `<span class="tag" data-file="docs/findings.md" tabindex="0" role="button">findings.md</span>` : ""}
        ${docs.find(d => d.name === "progress.md") ? `<span class="tag" data-file="docs/progress.md" tabindex="0" role="button">progress.md</span>` : ""}
        ${docs.find(d => d.name === "review.md") ? `<span class="tag" data-file="docs/review.md" tabindex="0" role="button">review.md</span>` : ""}
        ${rawFiles.length ? `<span class="tag" data-file="${esc(rawFiles[0].rel)}" tabindex="0" role="button">${esc(rawFiles[0].name)}</span>` : ""}
      </div>
    </div>
    <div class="card"><h3>Latest produced files</h3>
      ${latest.length ? artifactRows(latest.slice(0, 12)) : `<div class="muted">No artifacts written yet.</div>`}
    </div>`;
}

// ----- docs
function renderDocs(r) {
  const docs = (r.tree.children || []).filter(c => c.name === "docs")[0]?.children || [];
  $("#tab-docs").innerHTML = `
    <div class="card"><h3>Docs (agent-written reports)</h3>
      ${docs.length ? `<div class="tree">${docs.map(d => fileRow(d)).join("")}</div>`
        : `<div class="muted">No docs yet.</div>`}
    </div>`;
}

// ----- code
function renderCode(r) {
  const code = (r.tree.children || []).filter(c => c.name === "code")[0]?.children || [];
  $("#tab-code").innerHTML = `
    <div class="card"><h3>Exported code (full binary → code dump)</h3>
      ${code.length ? `<div class="tree">${code.map(c => c.type === "dir" ? dirRow(c) : fileRow(c)).join("")}</div>`
        : `<div class="muted">No code export yet (run may still be in pre-analyze/export phase).</div>`}
    </div>`;
}

// ----- workers
function renderWorkers(r) {
  const workers = r.workers || [];
  $("#tab-workers").innerHTML = `
    <div class="card"><h3>Workers (each runs analyst ↔ reviewer loop)</h3>
      ${workers.length ? workers.map(w => workerCard(w)).join("")
        : `<div class="muted">No workers spawned (supervisor decided the target was small enough, or planning failed).</div>`}
    </div>`;
}

function workerCard(w) {
  const rounds = w.rounds || [];
  return `
    <div class="worker-card">
      <div class="worker-head" data-worker-toggle id="worker-${esc(w.id)}" tabindex="0" role="button">
        <span class="wid">${esc(w.id)}</span>
        <span class="wtitle">${esc(w.title)}</span>
        <span class="muted">${w.converged ? "✓ converged" : "✕"} · ${w.total_rounds ?? 0} round(s) · ${esc(w.started || "")}</span>
      </div>
      <div class="worker-body">
        <div class="worker-rounds">
          ${rounds.length ? rounds.map(rd => `
            <div class="round-row">
              <span><b>Round ${rd.round}</b></span>
              <span class="verdict ${rd.verdict}">${esc(rd.verdict)}</span>
              <span class="muted">analyst ${esc(rd.analyst_seconds)}s · review ${esc(rd.review_seconds)}s</span>
            </div>`).join("") : `<div class="muted">No round data.</div>`}
        </div>
        <div style="padding:0 14px 14px">
          <b style="font-size:12px;color:var(--fg2)">Files in this worker's workspace:</b>
          <div class="tree" style="margin-top:6px">${(w.tree.children || []).map(c =>
            c.type === "dir" ? dirRow(c, w.root) : fileRow(c, w.root)).join("")}</div>
        </div>
      </div>
    </div>`;
}

// ----- raw / files
function renderRaw(r) {
  const raw = (r.tree.children || []).filter(c => c.name === "raw")[0]?.children || [];
  $("#tab-raw").innerHTML = `
    <div class="card"><h3>Raw (plans, analyst/review transcripts, events)</h3>
      ${raw.length ? `<div class="tree">${raw.map(d => d.type === "dir" ? dirRow(d) : fileRow(d)).join("")}</div>`
        : `<div class="muted">No raw artifacts yet.</div>`}
    </div>`;
}

// ----- artifacts
function renderArtifacts(r) {
  const artifacts = r.artifacts || {};
  const files = artifacts.latest || [];
  const roles = artifacts.by_role || {};
  $("#tab-artifacts").innerHTML = `
    <div class="card"><h3>Artifact inventory</h3>
      <div class="summary-band">
        <div class="summary-tile"><div class="label">Total files</div><div class="value">${artifacts.total_files ?? 0}</div></div>
        <div class="summary-tile"><div class="label">Total size</div><div class="value">${humanSize(artifacts.total_bytes || 0)}</div></div>
        <div class="summary-tile"><div class="label">Artifact roles</div><div class="value">${Object.keys(roles).length}</div></div>
      </div>
      <div class="finding-tags" style="margin-top:12px">
        ${Object.entries(roles).map(([role, count]) => `<span class="tag">${esc(role)}: ${count}</span>`).join("")}
      </div>
    </div>
    <div class="card"><h3>Files written by the workflow</h3>
      ${files.length ? artifactRows(files) : `<div class="muted">No artifacts found.</div>`}
    </div>`;
}

// ----- tree helpers
function fileRow(node, prefix) {
  const rel = joinRel(prefix, node.rel);
  return `<div class="tree-row file" data-file="${esc(rel)}" tabindex="0" role="button">
    <span class="tree-icon">•</span><span>${esc(node.name)}</span>
    <span class="tree-size">${humanSize(node.size)}</span></div>`;
}
function dirRow(node, prefix) {
  const kids = (node.children || []).map(c => c.type === "dir" ? dirRow(c, prefix) : fileRow(c, prefix)).join("");
  return `<div class="tree-node">
    <div class="tree-row dir" data-dir-toggle tabindex="0" role="button">
      <span class="tree-icon">▾</span><span>${esc(node.name)}</span></div>
    <div class="tree-children">${kids}</div></div>`;
}
function artifactRows(files) {
  return `<div class="artifact-list">${files.map(f => `
    <div class="artifact-row" data-file="${esc(f.path)}" tabindex="0" role="button">
      <div class="artifact-path mono">${esc(f.path)}</div>
      <div class="artifact-role">${esc(f.role || "artifact")}</div>
      <div class="artifact-meta">${humanSize(f.size || 0)}</div>
      <div class="artifact-meta">${esc(f.mtime || "")}</div>
    </div>`).join("")}</div>`;
}
function humanSize(n) {
  if (!n) return "0 B"; const u = ["B", "KB", "MB", "GB"]; let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return v.toFixed(i ? 1 : 0) + " " + u[i];
}

// ---------------------------------------------------------------- file viewer
async function viewFile(rel) {
  const fv = $("#fileViewer");
  $("#fvPath").textContent = rel;
  $("#fvMeta").innerHTML = `<span class="spinner"></span> loading…`;
  $("#fvContent").textContent = "";
  $$(".fv-trunc", fv).forEach(n => n.remove());
  fv.hidden = false;
  try {
    const f = await api(`/api/runs/${encodeURIComponent(currentRun)}/file?path=${encodeURIComponent(rel)}`);
    if (f.error) {
      $("#fvMeta").textContent = "";
      $("#fvContent").textContent = "Error: " + f.error;
      return;
    }
    $("#fvMeta").textContent = `${humanSize(f.size)}${f.mtime ? " · " + f.mtime : ""}${f.truncated ? ` · truncated (${humanSize(f.full_size)} full)` : ""}`;
    $("#fvContent").textContent = f.content || "(empty file)";
    if (f.truncated) {
      const note = document.createElement("div");
      note.className = "fv-trunc";
      note.textContent = `File truncated at 2MB for display. Full path: ${f.full_path || rel}`;
      fv.querySelector(".fv-content").after(note);
    }
  } catch (e) {
    $("#fvContent").textContent = "Error: " + e.message;
  }
  fv.scrollIntoView({ behavior: "smooth", block: "start" });
  $("#fvClose").focus();
}

// ---------------------------------------------------------------- live stream
function startLivePoll() {
  stopLivePoll();
  liveTick();
  liveTimer = setInterval(liveTick, 1500);
}
function stopLivePoll() {
  if (liveTimer) { clearInterval(liveTimer); liveTimer = null; }
}

async function liveTick() {
  if (!currentRun) return;
  try {
    const data = await api(`/api/runs/${encodeURIComponent(currentRun)}/live?since=${liveSince}`);
    const feed = $("#tab-live");
    if (!feed.querySelector(".live-bar")) {
      feed.innerHTML = `<div class="live-bar">
          <span id="liveStatus" class="status-pill status-running"><span class="dot running"></span> running</span>
          <span class="muted" id="liveCount">0 events</span>
          <span class="muted">auto-refresh 1.5s</span>
        </div>
        <div class="live-feed" id="liveFeed"></div>`;
    }
    if (data.events && data.events.length) {
      const f = $("#liveFeed");
      f.insertAdjacentHTML("beforeend", data.events.map(renderEvent).join(""));
      liveSince = data.total;
      f.scrollTop = f.scrollHeight;
    }
    $("#liveCount").textContent = `${liveSince} events`;
    if (!data.running) {
      await refreshDetail();
      const finalStatus = normalizeStatus(runDetail?.status || "completed");
      $("#liveStatus").className = "status-pill status-" + finalStatus;
      $("#liveStatus").innerHTML = `<span class="dot ${finalStatus}"></span> ${statusLabel(finalStatus)}`;
      stopLivePoll();
    } else {
      // Keep worker/status cards fresh without re-rendering the full detail every poll.
      const now = Date.now();
      if (now - lastDetailRefresh >= DETAIL_REFRESH_MS) {
        await refreshDetail();
      }
    }
    if ($('[data-tab="trace"]').classList.contains("active")) traceTick();
  } catch {}
}

async function traceTick() {
  if (!currentRun) return;
  const panel = $("#tab-trace");
  if (!panel.querySelector(".trace-bar")) {
    panel.innerHTML = `<div class="trace-bar">
      <span id="traceIntegrity" class="status-pill status-running">verifying…</span>
      <span id="traceCount" class="muted">0 durable events</span>
      <span class="muted">trace/span/parent correlation · secret-safe descriptors · external authority</span>
    </div><div class="trace-feed" id="traceFeed"></div>`;
  }
  try {
    const verify = traceSince === 0 ? 1 : 0;
    const data = await api(`/api/runs/${encodeURIComponent(currentRun)}/trace?since=${traceSince}&limit=500&verify=${verify}`);
    if (data.verification) {
      const badge = $("#traceIntegrity");
      badge.className = "status-pill status-completed";
      badge.textContent = `✓ hash chain valid · ${data.verification.events} events`;
    }
    if (data.events?.length) {
      $("#traceFeed").insertAdjacentHTML("beforeend", data.events.map(renderTraceEvent).join(""));
      traceSince = Number(data.events[data.events.length - 1].sequence || traceSince);
    }
    $("#traceCount").textContent = `${traceSince} durable events`;
  } catch (e) {
    const badge = $("#traceIntegrity");
    badge.className = "status-pill status-failed";
    badge.textContent = `✕ ${e.message}`;
  }
}

function renderTraceEvent(ev) {
  const time = new Date(Number(ev.time_ns || 0) / 1e6).toISOString();
  const parent = ev.parent_span_id ? String(ev.parent_span_id).slice(0, 8) : "—";
  const attrs = shorten(JSON.stringify(ev.attributes || {}), 1200);
  return `<details class="trace-event ${esc(ev.status || "ok")}">
    <summary><span class="trace-seq">#${esc(ev.sequence)}</span>
      <span class="trace-time">${esc(time)}</span>
      <b>${esc(ev.component)}.${esc(ev.category)}</b>
      <span>${esc(ev.action)}/${esc(ev.phase)}</span>
      <span class="trace-status">${esc(ev.status)}</span>
      <span class="trace-trust">${esc(ev.trust)}</span></summary>
    <div class="trace-correlation">trace ${esc(ev.trace_id)} · span ${esc(ev.span_id)} · parent ${esc(parent)} · pid ${esc(ev.pid)} · thread ${esc(ev.thread_id)}${ev.duration_ms == null ? "" : ` · ${esc(ev.duration_ms)}ms`}</div>
    <pre>${esc(attrs)}</pre>
  </details>`;
}

function renderEvent(ev) {
  let body = "";
  if (ev.kind === "tool_use") {
    const inp = ev.input ? JSON.stringify(ev.input) : "";
    body = `${esc(ev.name || "")}${inp ? " " + esc(inp.slice(0, 200)) : ""}`;
  } else if (ev.kind === "text") {
    body = esc((ev.text || "").slice(0, 300));
  } else if (ev.kind === "tool_result") {
    const c = typeof ev.content === "string" ? ev.content : JSON.stringify(ev.content || "");
    const rc = ev.exit_code == null ? "" : ` rc=${ev.exit_code}`;
    const duration = ev.duration_ms == null ? "" : ` ${ev.duration_ms}ms`;
    body = `${esc(ev.name || "tool")} ${esc(ev.status || "completed")}${esc(rc)}${esc(duration)} ${esc(c.slice(0, 150))}`;
  } else if (ev.kind === "result") {
    body = esc((ev.text || "").slice(0, 500));
  } else if (ev.kind === "log" || ev.kind === "error") {
    body = `[${esc(ev.phase || "")}] ${esc(ev.text || "")}`;
  } else {
    body = esc(JSON.stringify(ev).slice(0, 200));
  }
  const kind = String(ev.kind || "log").replace(/[^A-Za-z0-9_-]/g, "");
  const phase = ev.phase ? `<span class="phase">${esc(ev.phase)}</span>` : "";
  return `<div class="ev ${esc(kind)}"><span class="ts">${esc(ev.ts || "")}</span>
    <span class="kind">${esc(ev.kind)}</span>${phase}<span class="body">${body}</span></div>`;
}

// ---------------------------------------------------------------- tabs
function switchTab(name) {
  $$(".tab").forEach(t => t.classList.toggle("active", t.dataset.tab === name));
  $$(".tab-panel").forEach(p => p.classList.toggle("active", p.id === "tab-" + name));
  if (name === "trace") traceTick();
}

// ---------------------------------------------------------------- new run modal
async function openNewRun(opts = {}) {
  formMode = opts.mode || "start";
  editRunId = opts.runId || null;
  $("#newRunModal").hidden = false;
  $("#startError").hidden = true;
  $("#modalTitle").textContent = formMode === "edit" ? "Edit run settings" : "Start a new analysis run";
  $("#startRunBtn").textContent = formMode === "edit" ? "Save settings" : "Start run";
  $("#fBinary").disabled = formMode === "edit";
  $("#fBinaryCustom").disabled = formMode === "edit";
  $("#browseTargetBtn").disabled = formMode === "edit";
  try {
    const { samples } = await api("/api/samples");
    $("#fBinary").innerHTML = samples.map(s => `<option value="${esc(s.path)}">${esc(s.name)} (${humanSize(s.size)})</option>`).join("");
  } catch {}
  if (formMode === "edit" && opts.detail) {
    fillRunForm(opts.detail);
  } else {
    $("#fBinaryCustom").value = "";
    $("#fEngine").value = "ida";
    $("#fAgent").value = "claude";
    $("#fModel").value = "";
    $("#fRounds").value = 2;
    $("#fParallel").value = 3;
    $("#fObjective").value = "";
    $("#fSandbox").checked = false;
  }
}
function closeNewRun() {
  $("#newRunModal").hidden = true;
  formMode = "start";
  editRunId = null;
  $("#fBinary").disabled = false;
  $("#fBinaryCustom").disabled = false;
  $("#browseTargetBtn").disabled = false;
}

async function openFilePicker() {
  pickerSelected = "";
  $("#filePickerSelected").textContent = "";
  $("#filePickerChoose").disabled = true;
  $("#filePickerFilter").value = "";
  $("#filePickerModal").hidden = false;
  const current = $("#fBinaryCustom").value.trim() || $("#fBinary").value || "";
  await loadFilePicker(current);
  $("#filePickerPath").focus();
}

function closeFilePicker() {
  $("#filePickerModal").hidden = true;
}

async function loadFilePicker(path) {
  $("#filePickerError").hidden = true;
  $("#filePickerList").innerHTML = `<div class="runs-empty"><span class="spinner"></span> loading…</div>`;
  try {
    const data = await api(`/api/files?path=${encodeURIComponent(path || "")}`);
    pickerEntries = data.entries || [];
    pickerSelected = "";
    $("#filePickerPath").value = data.path || "";
    $("#filePickerUp").dataset.pickerPath = data.parent || "";
    $("#filePickerSelected").textContent = "";
    $("#filePickerChoose").disabled = true;
    $("#filePickerRoots").innerHTML = (data.roots || []).map(r =>
      `<button class="btn" type="button" data-picker-path="${esc(r.path)}">${esc(r.label)}</button>`).join("");
    renderFilePicker();
  } catch (e) {
    pickerEntries = [];
    $("#filePickerList").innerHTML = "";
    $("#filePickerError").textContent = e.message;
    $("#filePickerError").hidden = false;
  }
}

function renderFilePicker() {
  const q = $("#filePickerFilter").value.trim().toLowerCase();
  const rows = pickerEntries.filter(e => !q || e.name.toLowerCase().includes(q));
  $("#filePickerList").innerHTML = rows.length ? rows.map(e => {
    const kind = e.type === "dir" ? "dir" : "file";
    const action = e.type === "dir" ? "data-picker-path" : "data-picker-file";
    return `<div class="file-picker-row ${kind}" ${action}="${esc(e.path)}" tabindex="0" role="button">
      <span class="file-kind">${e.type === "dir" ? "▸" : "•"}</span>
      <span class="file-name">${esc(e.name)}</span>
      ${e.candidate ? `<span class="file-badge">IDA</span>` : ""}
      <span class="file-size">${e.type === "dir" ? "" : humanSize(e.size || 0)}</span>
      <span class="file-time">${esc(e.mtime || "")}</span>
    </div>`;
  }).join("") : `<div class="runs-empty">No matching files.</div>`;
}

function selectPickerFile(path) {
  pickerSelected = path;
  $("#filePickerSelected").textContent = path;
  $("#filePickerChoose").disabled = false;
  $$(".file-picker-row").forEach(r => r.classList.toggle("selected", r.dataset.pickerFile === path));
}

function choosePickerFile() {
  if (!pickerSelected) return;
  $("#fBinaryCustom").value = pickerSelected;
  closeFilePicker();
}

function fillRunForm(r) {
  $("#fBinaryCustom").value = r.binary || "";
  $("#fEngine").value = r.engine || "ida";
  $("#fAgent").value = r.agent || "claude";
  $("#fModel").value = r.model || "";
  $("#fAnchorIdl").value = r.anchor_idl || "";
  $("#fSimilarityCorpora").value = (r.similarity_corpora || []).join("\n");
  $("#fRounds").value = r.requested_rounds || r.total_rounds || 2;
  $("#fParallel").value = r.requested_parallel || 3;
  $("#fObjective").value = r.objective || "";
  $("#fSandbox").checked = !!r.sandbox;
}

function runFormBody(includeBinary) {
  const similarityCorpora = $("#fSimilarityCorpora").value.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
  const body = {
    engine: $("#fEngine").value,
    agent: $("#fAgent").value,
    model: $("#fModel").value.trim(),
    anchor_idl: $("#fAnchorIdl").value.trim(),
    rounds: parseInt($("#fRounds").value, 10) || 2,
    parallel: parseInt($("#fParallel").value, 10) || 3,
    objective: $("#fObjective").value,
    sandbox: $("#fSandbox").checked,
  };
  if (similarityCorpora.length || formMode === "edit") body.similarity_corpora = similarityCorpora;
  if (includeBinary) {
    body.binary = $("#fBinaryCustom").value.trim() || $("#fBinary").value;
  }
  return body;
}

async function startRunFromForm() {
  const err = $("#startError");
  err.hidden = true;
  const body = runFormBody(formMode !== "edit");
  if (formMode !== "edit" && !body.binary) {
    err.textContent = "Pick or enter a target binary.";
    err.hidden = false;
    return;
  }
  $("#startRunBtn").disabled = true;
  $("#startRunBtn").textContent = formMode === "edit" ? "Saving…" : "Starting…";
  try {
    const wasEdit = formMode === "edit";
    const url = formMode === "edit"
      ? `/api/runs/${encodeURIComponent(editRunId)}/edit`
      : "/api/runs/start";
    const res = await api(url, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    closeNewRun();
    if (wasEdit) {
      runDetail = res;
      renderDetail(res);
      await loadRuns();
    } else {
      await loadRuns();
      openRun(res.run_id);
    }
  } catch (e) {
    err.textContent = e.message;
    err.hidden = false;
  } finally {
    $("#startRunBtn").disabled = false;
    $("#startRunBtn").textContent = formMode === "edit" ? "Save settings" : "Start run";
  }
}

async function editCurrentRun() {
  if (!runDetail) return;
  await openNewRun({ mode: "edit", runId: currentRun, detail: runDetail });
}

async function rerunCurrentRun() {
  if (!currentRun) return;
  const btn = $('[data-run-action="rerun"]');
  if (btn) { btn.disabled = true; btn.textContent = "Starting…"; }
  try {
    const res = await api(`/api/runs/${encodeURIComponent(currentRun)}/rerun`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
    });
    await loadRuns();
    openRun(res.run_id);
  } catch (e) {
    alert(e.message);
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = "Rerun"; }
  }
}

async function pauseCurrentRun() {
  if (!currentRun) return;
  const btn = $('[data-run-action="pause"]');
  if (btn) { btn.disabled = true; btn.textContent = "Draining…"; }
  try {
    await api(`/api/runs/${encodeURIComponent(currentRun)}/pause`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
    });
    await refreshDetail();
  } catch (e) {
    alert(e.message);
    if (btn) { btn.disabled = false; btn.textContent = "Pause safely"; }
  }
}

async function resumeCurrentRun() {
  if (!currentRun) return;
  const btn = $('[data-run-action="resume"]');
  if (btn) { btn.disabled = true; btn.textContent = "Resuming…"; }
  try {
    const body = {};
    const checkpointIdl = (runDetail && runDetail.anchor_idl) || "";
    if (checkpointIdl) {
      const selectedIdl = window.prompt(
        "Anchor IDL path for resume (change this only if the identical IDL moved):",
        checkpointIdl,
      );
      if (selectedIdl === null) {
        if (btn) { btn.disabled = false; btn.textContent = "Resume"; }
        return;
      }
      body.anchor_idl = selectedIdl.trim();
    }
    const checkpointCorpora = (runDetail && runDetail.similarity_corpora) || [];
    if (checkpointCorpora.length && window.confirm(
      "Only choose OK if the pinned similarity corpus snapshots moved. Cancel uses the checkpoint snapshots automatically."
    )) {
      const relocated = window.prompt(
        "Relocated byte-identical corpus paths (one per line):",
        checkpointCorpora.join("\n"),
      );
      if (relocated === null) {
        if (btn) { btn.disabled = false; btn.textContent = "Resume"; }
        return;
      }
      body.similarity_corpora = relocated.split(/\r?\n/).map(v => v.trim()).filter(Boolean);
    }
    await api(`/api/runs/${encodeURIComponent(currentRun)}/resume`, {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    await refreshDetail();
    startLivePoll();
  } catch (e) {
    alert(e.message);
    if (btn) { btn.disabled = false; btn.textContent = "Resume"; }
  }
}

async function deleteCurrentRun() {
  if (!currentRun || !runDetail) return;
  const label = runDetail.binary_name || currentRun;
  if (!confirm(`Delete run "${label}"? This removes its workspace from disk.`)) return;
  try {
    await api(`/api/runs/${encodeURIComponent(currentRun)}`, { method: "DELETE" });
    goBack();
  } catch (e) {
    alert(e.message);
  }
}

// ---------------------------------------------------------------- list polling
function startListPoll() {
  stopListPoll();
  pollTimer = setInterval(loadRuns, 4000);
}
function stopListPoll() { if (pollTimer) { clearInterval(pollTimer); pollTimer = null; } }

// ---------------------------------------------------------------- init
function goBack() {
  stopLivePoll();
  currentRun = null;
  $("#detailView").hidden = true;
  $("#listView").hidden = false;
  loadRuns();
  startListPoll();
}

document.addEventListener("DOMContentLoaded", () => {
  $("#newRunBtn").onclick = openNewRun;
  $("#refreshBtn").onclick = () => { loadRuns(); loadEngines(); };
  $("#backBtn").onclick = goBack;
  $("#modalClose").onclick = closeNewRun;
  $("#newRunModal").onclick = (e) => { if (e.target.id === "newRunModal") closeNewRun(); };
  $("#startRunBtn").onclick = startRunFromForm;
  $("#browseTargetBtn").onclick = openFilePicker;
  $("#filePickerClose").onclick = closeFilePicker;
  $("#filePickerModal").onclick = (e) => { if (e.target.id === "filePickerModal") closeFilePicker(); };
  $("#filePickerGo").onclick = () => loadFilePicker($("#filePickerPath").value);
  $("#filePickerUp").onclick = () => loadFilePicker($("#filePickerUp").dataset.pickerPath || "");
  $("#filePickerFilter").oninput = renderFilePicker;
  $("#filePickerChoose").onclick = choosePickerFile;
  $("#fvClose").onclick = () => { $("#fileViewer").hidden = true; };
  $$(".tab").forEach(t => t.onclick = () => switchTab(t.dataset.tab));
  document.body.addEventListener("click", (e) => {
    const file = e.target.closest("[data-file]");
    if (file) {
      e.preventDefault();
      viewFile(file.dataset.file);
      return;
    }
    const run = e.target.closest("[data-run]");
    if (run) {
      e.preventDefault();
      openRun(run.dataset.run);
      return;
    }
    const dir = e.target.closest("[data-dir-toggle]");
    if (dir) {
      e.preventDefault();
      dir.parentElement.classList.toggle("collapsed");
      return;
    }
    const workerToggle = e.target.closest("[data-worker-toggle]");
    if (workerToggle) {
      e.preventDefault();
      const body = workerToggle.parentElement.querySelector(".worker-body");
      if (body) body.hidden = !body.hidden;
      return;
    }
    const workerJump = e.target.closest("[data-worker-jump]");
    if (workerJump) {
      e.preventDefault();
      switchTab("workers");
      const target = document.getElementById("worker-" + CSS.escape(workerJump.dataset.workerJump));
      if (target) target.scrollIntoView({ behavior: "smooth", block: "center" });
      return;
    }
    const runAction = e.target.closest("[data-run-action]");
    if (runAction) {
      e.preventDefault();
      const action = runAction.dataset.runAction;
      if (action === "edit") editCurrentRun();
      if (action === "pause") pauseCurrentRun();
      if (action === "resume") resumeCurrentRun();
      if (action === "rerun") rerunCurrentRun();
      if (action === "delete") deleteCurrentRun();
      return;
    }
    const pickerPath = e.target.closest("[data-picker-path]");
    if (pickerPath) {
      e.preventDefault();
      loadFilePicker(pickerPath.dataset.pickerPath || "");
      return;
    }
    const pickerFile = e.target.closest("[data-picker-file]");
    if (pickerFile) {
      e.preventDefault();
      selectPickerFile(pickerFile.dataset.pickerFile);
    }
  });
  document.body.addEventListener("keydown", (e) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    if (!(e.target instanceof Element)) return;
    const action = e.target.closest("[data-file], [data-run], [data-dir-toggle], [data-worker-toggle], [data-worker-jump], [data-run-action], [data-picker-path], [data-picker-file]");
    if (!action) return;
    e.preventDefault();
    action.click();
  });
  loadRuns();
  loadEngines();
  startListPoll();
});
