# Architecture

## System Purpose

Angerona is a local-first reverse-engineering and binary-security workspace. It
combines IDA Pro or Ghidra extraction, deterministic analysis passes, optional
runtime/symbolic probes, agent-driven investigation, evidence verification, and
workspace-backed reporting. The same capabilities are exposed through a Python
CLI, stdio MCP servers, and a local HTTP control plane.

This is a modular monolith today. `src/services/contracts.py` and
`docs/architecture/MICROSERVICES.md` define extraction boundaries, not an already
deployed microservice system.

## Runtime Shapes

### Agent-driven analysis

```text
CLI/web request
  -> Orchestrator.swarm_run
  -> engine pre-analysis and workspace export
  -> Supervisor plans bounded slices
  -> analyst workers run ConvergenceLoop instances
  -> independent reviewer checks each report
  -> deterministic verification gates can override reviewer satisfaction
  -> Supervisor consolidates accepted worker evidence
  -> RunWorkspace persists reports, logs, traces, and metadata
  -> external observability authority correlates every boundary and mutation
```

Ownership:

- `src/agents/orchestrator.py`: top-level wiring, engine pre-analysis, tool setup,
  worker/reviewer dispatch, and run lifecycle.
- `src/agents/supervisor.py`: planning, worker fan-out, respawn/retry handling,
  coverage accounting, report consolidation, and adaptive topology support.
- `src/agents/loop.py`: bounded analyst/reviewer convergence plus binary-backed
  verification gates; K trajectories are isolated and only execution-successful,
  output-admissible, target-bound candidates can enter deterministic scoring. A
  no-follow, quota-bound immutable round seed freezes code/raw input; one full clone
  is live at a time and only bounded reconstruction snapshots survive selection.
- `src/agents/runtime.py`: Claude Code and Codex subprocess adapters, streaming,
  bounded output capture, timeouts, model-agnostic context/retry recovery, sealed
  payload transport, crash-safe recursive-instruction quarantine, environment policy,
  and result normalization.
- `src/observability.py` and `src/subprocess_observability.py`: supervisor-only
  SQLite/WAL authority, trace/span/parent correlation, hash-chain verification,
  secret-safe payload descriptors, validated untrusted child import, readable mirror,
  host subprocess coverage, and exact per-path mutation events. The web/CLI timeline
  reads this authority; the model-writable JSONL copy is never trusted.
- `src/agents/context_harness.py`, `retry_harness.py`, and `scratch_quota.py`: adaptive
  compaction, exact checkpoint/retry authority, immutable execution binding, and
  cumulative type-faithful required-sandbox recovery.
- `src/agents/respawn_policy.py`: trusted runtime-failure classification and
  checkpoint-safe split/retry/reroute/stop control records.
- `src/agents/spawn_plan.py`: candidate-task search, routing, budgets,
  dependency-DAG scheduling, and adaptive worker plans.
- `src/agents/prompts.py`: engine-aware analyst, reviewer, planner, and first-step
  prompts.

### Deterministic batch pipeline

```text
CLI `sota-batch` or `full-re --no-ai`
  -> select engine
  -> BatchJobSpec
  -> BatchSpine.run
  -> triage
  -> analyze
  -> graph
  -> signatures
  -> types
  -> xref
  -> sinks
  -> cpp
  -> final checkpoint and batch_report.json
```

`src/orchestration/batch_spine.py` owns this linear pipeline. Each requested stage
is timed and traced. Failures become stage-log entries; dependent stages are
skipped when their required graph is unavailable. A run succeeds only when every
requested stage log is `ok`.

The analyze stage selects IDA/Ghidra, detects Solana targets, optionally fuses
multiple Solana engine results, collects auxiliary Solana utility evidence, and
builds the shared analysis graph. Later stages enrich that graph rather than
starting independent representations.

### Direct capability commands

The CLI also exposes individual subsystems without either full orchestration path:

- engine status, analysis, decompilation, and installation;
- graph queries and checkpoint operations;
- backend selection and distinct native/Unicorn/QEMU-user/symbolic probes;
- CFG, stack-frame, gadget, indirect-flow, compiler, custom-ISA, pseudocode, and
  function-summary operations;
- workspace guard checks, MCP serving, web serving, and Ghidra updates.

These commands are implemented by `_cmd_*` handlers in `src/cli.py`; user-facing
command families are mapped in `INTERFACES.md`. Read the current handlers for exact
arguments and behavior.

## Layers And Boundaries

### Entrypoints and control planes

- `src/cli.py`: canonical packaged entry point (`angerona = src.cli:main`).
- `src/__main__.py`: `python -m src` bridge.
- `bin/angerona`: repository launcher.
- `src/web/server.py`: stdlib HTTP server, local run control, file browsing,
  event delivery, and artifact reads.
- `src/mcp/server.py`: native Ghidra-oriented JSON-RPC/MCP stdio server.
- `src/mcp/ida_proxy.py`: safety proxy around upstream IDA MCP.
- `demo_flow.py`: demonstration harness, not a production entry point.

### Engine abstraction

- `src/engines/__init__.py`: engine construction and shared exports.
- `src/engines/selector.py`: automatic engine selection and fallback rationale.
- `src/engines/ida.py`: IDA status, launch, analysis-cache, metadata, and
  decompilation adapter.
- `src/engines/ghidra.py`: `analyzeHeadless` adapter and eBPF/Solana handling.
- `src/scripts/ida_dump.py`, `ida_idat_dump.py`, and `REDump.java`: extraction code
  executed inside or alongside the reverse-engineering engines.

Engine output is normalized into dictionaries containing metadata, functions,
strings, imports, exports, symbols, and related evidence. Higher layers should not
depend on raw tool-specific output when a normalized model exists.

### Canonical analysis models

- `src/models/analysis_graph.py`: graph nodes, edges, mutations, serialization,
  lookup indexes, address/range resolution, and confidence/evidence fields.
- `src/models/triage_profile.py`: multi-source binary format, architecture,
  linker/compiler, stripping, entropy, and confidence profile.
- `src/models/checkpoint_db.py`: SQLite-backed checkpoints, mutations, audit log,
  rollback, and integrity operations.
- `src/models/type_library.py`: reusable type definitions and graph application.
- `src/models/type_recovery.py`: staged type inference and evidence-backed updates.
- `src/models/cpp_recovery.py`: C++ object/class/vtable/RTTI/layout reconstruction.

`AnalysisGraph` is the central enrichment substrate for the newer deterministic
pipeline. `RunWorkspace` is the central persistence substrate for both pipeline
styles.

### Deterministic analysis

`src/analysis/` is intentionally broad. Its modules fall into these functional
groups:

- extraction and facts: `export`, `binprops`, `firmware_extract`, `provenance`;
- structural recovery: `cfg_spine`, `stack_frame_recovery`, `indirect_flow`,
  `xref_graph`, `structrecovery`, `pcode_struct`, `vector_recovery`;
- naming and typing: `symbolrecovery`, `library_signatures`, `typefidelity`,
  `compiler_personality`;
- vulnerability focus: `sink_hunter`, `security_slices`, `gadget_finder`,
  `variant_analysis`, `pov_oracle`, `redteam`;
- equivalence and verification: `bindiff`, `verify`, `bequiv`, `differential`,
  `composite`, `semantics`, `coverage_tier`, `evidence_ledger`, `auto_reexec`;
- difficult targets: `deobfuscate`, `obfuscation`, `obfuscation_detect`,
  `binary_bpe`, `bcrl`, `lift_confidence`, `sleigh_draft`, `unicorn_oracle`;
- evaluation and operations: `re_analysis`, `rebench_eval`, `cost`,
  `corpus_caveat`, `anchor_retrieval`, `simindex`, `topology`, `sandbox`,
  `detonate`, and `scan_injection`.

`FEATURES.md` describes every module individually.

### Execution and feedback

- `src/execution/backend_selector.py`: ranks native, Unicorn, QEMU-user, and symbolic
  backends against target/profile requirements.
- `src/execution/probe_runner.py`: backend registry and dispatch.
- `src/execution/runners/`: native, Unicorn, and symbolic function-probe implementations;
  real QEMU Linux process planning lives in `src/execution/providers.py`.
- `src/execution/symbolic/`: symbolic request/result models and fallback logic.
- `src/execution/snapshot_applier.py`: writes captured state and constraints back
  to the analysis graph.
- `src/execution/enrichment_loop.py`: iteratively probes and applies new evidence.
- `src/execution/models.py`: request, snapshot, and result contracts.

Runtime evidence is optional and capability-dependent. Missing optional tooling is
represented as unavailable/skipped/error state; it must not be turned into positive
verification evidence.

### Processor and platform extensions

- `src/processors/`: registry, loader, analyzer, base contracts, and decoders for
  Solana BPF and EVM/custom bytecode.
- `src/solana/`: binary detection, adapter discovery/runtime probes, multi-engine
  fusion, helper/syscall normalization, and external utility evidence.
- `src/summary/`: graph-backed function summaries and pseudocode/report models.
- `src/services/contracts.py`: transport-neutral command/result/artifact contracts
  for future service extraction.

## Persistent State

`RunWorkspace.create` builds a per-run directory under the configured state root.
The established layout includes:

```text
run.json                    run identity and status
live.log                    human-readable live stream
events.jsonl                structured event stream when emitted
code/                       normalized engine exports and facts
docs/                       progress, findings, review, and reports
raw/                        plans, transcripts, stage outputs, batch report
workers/                    worker-specific sub-workspaces
checkpoints.sqlite          mutation/checkpoint audit database
```

Exact contents vary by command, engine, enabled stages, optional tools, and whether
agents are used. Code must treat absent optional artifacts as an explicit state,
not silently assume success.

Agent control authority is deliberately split from the model-writable workspace.
By default, the observability SQLite/WAL ledger and other supervisor control records
live below `$XDG_STATE_HOME/angerona/agent-control/` (falling back to
`~/.local/state/angerona/agent-control/`); `ANGERONA_AGENT_CONTROL_STATE_DIR` can
relocate that root. Workspace JSONL/retry copies are readable mirrors. Audit snapshots
exclude `raw/observability`, so mirror updates do not create resume drift.

## Trust And Security Boundaries

1. Target binaries and all derived strings/tool output are untrusted data.
2. MCP results are wrapped with untrusted-data markers in `src/mcp/server.py` and
   `src/mcp/ida_proxy.py`; error messages receive the same treatment.
3. MCP write-capable tools require explicit authorization through the configured
   allow-write policy.
4. Agent subprocesses receive bounded tool lists, timeout controls, output caps,
   nested-agent restrictions, and a privacy policy. Codex shell access is opt-in.
5. Parser sandboxing uses bubblewrap when enabled and is designed to fail closed
   when isolation is requested but unavailable.
6. Dynamic detonation is explicit, Docker-based, disposable, and network-denied.
7. The web server refuses non-loopback binding unless `--allow-remote` is supplied;
   it remains an unauthenticated local control plane.
8. Verification distinguishes positive evidence, contradiction, lack of evidence,
   and infrastructure failure. Reviewer prose alone is not sufficient proof.
9. Evidence records and planned service contracts bind artifacts to source-binary
   identity; synthetic evidence must remain labeled.
10. Agent prose cannot authorize retry or provider selection. Adaptive respawn uses
    typed runtime events/process status only, respects the whole-audit budget, reroutes
    analyst and reviewer roles independently, and rejects incompatible resume policy.
11. Worker attempt history is immutable, while coverage/consolidation/blackboard state
    is derived from validated active leaves. Replacement transactions authenticate the
    parent scope; splits are atomic exact partitions, and `completed` is persisted only
    for a converged terminal result.
12. Candidate execution state is separate from candidate prose. Failed/off-target
    rows have no score authority; selected artifacts cross a bounded no-follow
    promotion boundary; policy-v7 resume recomputes and byte/directory-binds the winner
    plus its numeric scratch contract. K>1 requires an attested dispatch adapter,
    active Linux Bubblewrap filesystem/IPC isolation, storage seccomp, and a delegated
    cgroup v2 scope, failing closed before provider launch when unavailable. One sized
    tmpfs backs the workspace, `/tmp`, and `/dev/shm`; `/run` is private; alternate
    shmem, namespace/mount, SCM_RIGHTS, async-file, and Landlock retention paths are
    denied; FD/mmap-held inodes are accounted; the quota runner is non-dumpable; and
    only successful providers export through a trusted preconnected channel. Provider
    launchers are resolved and pinned as narrow read-only executable mounts so symlinked
    Claude, Codex, and other adapters share one policy. The exact-manifest seed is
    the content boundary; provider worktrees remain lifecycle isolation rather than a
    security boundary. Required candidates also use a private network namespace with a
    bounded inherited-channel proxy. Host-side policy enforces exact/scoped endpoints,
    DNS/address/rebinding checks, TLS SNI, and byte/connection limits. Direct loopback,
    private, metadata, and alternate Unix-socket egress are unavailable. A trusted
    local provider gateway is exposed only through a synthetic alias mapped to its one
    configured endpoint; its plain HTTP base path and single length-delimited request
    are enforced. Generic private endpoints cannot acquire loopback authority. Required
    Claude settings/state omit host hooks, plugins, projects, marketplaces, execution
    environment controls, and proxy bypass; required Codex ignores host config/rules.
    Raw host config/auth paths are not mounted—bounded snapshots cross runner-only FDs
    and are closed before provider launch. Network/gateway identity is pinned in the
    immutable run and checkpoint contracts. Input
    materialization rejects links/special files and enforces aggregate file,
    directory, and byte bounds before a candidate becomes model-visible.
13. Context overflow and transient failure cannot switch execution identity or trust
    agent-writable state. Oversized initial/recovery text uses sealed inherited FDs;
    checkpoint and retry chains bind the attempt, snapshot, provider/model command,
    target, MCP/config, isolation, backend, and original deadline. Retry authority is
    supervisor-only and workspace copies are observability mirrors. Required-sandbox
    retries install one cumulative exact-type delta while excluding immutable input and
    runtime authority. Every launch shares the same supervisor lock; recovery alone
    quarantines recursive instruction symlinks through a synced, descriptor-relative
    journal, restores them byte-exactly, preserves provider auth/MCP state, and rejects
    aliases, traversal, parent replacement, races, or extra-entry tampering before
    mutation.
14. Model/provider dispatches, streamed events, MCP JSON-RPC, network decisions,
    subprocesses, retries, budgets, checkpoints, artifacts/databases, lifecycle state,
    and per-path filesystem changes share trace/span lineage in an external SQLite/WAL
    hash chain. Raw prose is represented by bounded descriptors and secret-like values
    are redacted. Child telemetry remains explicitly untrusted, and the workspace JSONL
    can be rebuilt only after the authority verifies.

## Planned Service Architecture

`docs/architecture/MICROSERVICES.md` defines intake, analysis, execution,
verification, orchestration, workspace, and web-gateway boundaries. The checked-in
implementation currently provides transport-neutral dataclasses/contracts and
local adapters, but not separately deployed authenticated services, queues,
OpenTelemetry, or dead-letter handling. Treat those deployment items as roadmap
requirements, not current runtime guarantees.

## Change Guidance

- Add normalized evidence to `AnalysisGraph`; do not create an unrelated graph
  model for a single feature.
- Persist run-visible state through `RunWorkspace` and checkpoint mutations.
- Keep engine-specific logic inside engines/scripts/adapters.
- Keep CLI/web/MCP layers thin: validate, dispatch, serialize, and enforce policy.
- Preserve fail-closed semantics for requested isolation and strict verification.
- Any new stage needs stage logs, artifacts, trace events, failure/skip semantics,
  CLI wiring, and focused tests.
- Document new externally visible commands in `INTERFACES.md` and update the
  affected module descriptions when behavior changes.
