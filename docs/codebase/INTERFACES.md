# Interfaces And Configuration

## Process Entrypoints

| Entrypoint | Target |
|---|---|
| Installed `angerona` command | `src.cli:main` from `pyproject.toml` |
| `python -m src` | `src/__main__.py` -> `src.cli.main` |
| `./bin/angerona` | Repository launcher -> Python CLI |
| `python -m src.mcp.server` | Ghidra-oriented MCP stdio server |
| `python -m src.mcp.ida_proxy` | IDA MCP safety proxy |
| `python -m src.web.server` | Local HTTP control plane |
| `python benchmarks/complex_fixture/run_benchmark.py` | Build/evaluate recovery benchmark |

## CLI Commands

`src.cli.build_parser` defines the primary subcommands and the `full-re` alias.

| Command | Behavior |
|---|---|
| `run` | Agent-supervised analysis with worker planning, convergence, verification, and consolidation. |
| `status` | Show IDA and Ghidra readiness/status. |
| `install` | Register one or both engine MCP servers with Claude Code/Codex. |
| `analyze` | Raw headless engine analysis summary without an agent. |
| `decompile` | Decompile one function through the selected engine. |
| `update-ghidra` | Check for or install/update the managed Ghidra distribution. |
| `mcp-serve` | Serve the selected engine over MCP stdio. |
| `web` | Start the local web UI/API. |
| `guard-workspace` | Validate workspace/path safety and state assumptions. |
| `sota-analyze` | Run the direct advanced analysis/recovery stack and write graph artifacts. |
| `graph-query` | Query a persisted `AnalysisGraph`. |
| `checkpoint-list` | List mutation checkpoints/audit information. |
| `checkpoint-revert` | Revert graph mutations to a checkpoint. |
| `audit-status` | Validate and inspect whole-audit snapshot, lease, phase, worker progress, context-policy windows, and audit-wide budget usage. |
| `audit-trace` | Verify and inspect the external-authority event chain; filter by sequence, component, action, or status; optionally rebuild the readable mirror. |
| `audit-pause` | Request a cooperative pause at committed worker/supervisor safe points. |
| `audit-instruct` | Queue a controller-authored, hash-verified focus/reporting instruction for the next supervisor safe point without overriding immutable audit gates. |
| `audit-resume` | Resume the exact checkpointed audit configuration after target/artifact verification. |
| `sota-batch` | Run the deterministic `BatchSpine` pipeline. |
| `full-re` | Alias of `sota-batch`; can combine deterministic analysis with agent flow depending on flags. |
| `backend-select` | Explain native/QEMU/symbolic backend selection for a target. |
| `execution-status` | Report runner, runtime-provider, and analysis-MCP availability. |
| `qemu-plan` | Emit a shell-free real QEMU Linux user-mode plan; optional syscall trace. |
| `bpftrace-plan` | Emit a shell-free bpftrace NDJSON plan. |
| `radare2-mcp-plan` | Emit a read-only, sandbox-locked official radare2 MCP stdio plan. |
| `enrich-function` | Probe and enrich one graph function. |
| `symbolic-probe` | Run a bounded symbolic request. |
| `pseudocode` | Generate graph-backed pseudocode for one/all functions. |
| `function-summary` | Generate deterministic function summaries. |
| `cfg-build` | Recover and persist function CFGs. |
| `stack-frames` | Recover stack-frame/slot evidence. |
| `gadget-find` | Search for exact/return-oriented gadgets. |
| `indirect-flow` | Recover switch tables, pointer tables, and indirect targets. |
| `compiler-detect` | Detect compiler/linker/packer/ABI personality evidence. |
| `custom-isa-list` | List registered custom instruction-set processors. |
| `analyze-custom` | Decode and graph Solana BPF, EVM, or another registered processor target. |
| `execution-status` | Show available execution backends and selection status. |
| `probe-run` | Run a bounded native/emulation function probe and capture observations. |
| `enrich-workspace` | Apply runtime probes iteratively across a workspace graph. |

Run `angerona <command> --help` for the authoritative option set. Parser flags are
not duplicated here because defaults and choices change more often than command
ownership.

## Audit Runtime Contracts

Adaptive context observations in orchestrated audits are committed and applied under
one context-policy controller lock. The returned configuration is an immutable in-flight
snapshot for that recovery; subsequent dispatches resolve the latest durable policy.
Shared model/provider profiles use a separate cross-process lock and reject stale
expansions, preserving safe learning across audit workspaces. Oversized initial and
recovery payloads use sealed inherited descriptors. Recovery chains bind the exact
attempt, candidate snapshot, execution contract, and original deadline; required
sandboxes carry cumulative type-faithful changes while excluding immutable inputs and
runtime authority.

Transient agent retry policy is part of the immutable run contract. Retry authorization
uses typed error events or stderr—not assistant text—and is bounded by the original wall
deadline. Each deterministic dispatch owns a hash-chained, cross-process-leased ledger
in supervisor-only control state; `raw/agent_retries/<dispatch-key>/state.json` is an
observability mirror with no authority. Dispatch identity includes the provider/model,
task and prompt, workspace, target, MCP/config, isolation, backend, and provider command.
A corrupt/unavailable ledger disables retry, while an interrupted nonterminal ledger
resumes without resetting its attempt budget or persisted absolute wall deadline.
Structured retry-delay hints retain their own units and resolve to the longest bounded
delay. Normal and recovery launches share one supervisor-only workspace lock. Recovery
uses a synced no-follow journal to quarantine recursive instruction symlinks without
hiding their targets or provider auth/MCP state, repairs interrupted restores before the
next launch, and rejects noncanonical or tampered journal state before mutation.

Whole-audit provider calls, elapsed wall time, optional tokens, and optional cost are
controlled by a provider-neutral admission ledger at `raw/audit_budget/state.json`.
Reservations occur under a cross-process lock before dispatch, retries count as calls,
and unmeasured token/cost usage is charged conservatively. The policy digest is pinned
in the immutable run contract and checkpoint. Resume keeps the original absolute
deadline, charges abandoned reservations, and refuses a missing/corrupt ledger. Normal
work cannot consume the protected final-consolidation reserve. Exhaustion is a
terminal `budget_exhausted` state with an explicitly incomplete report.

`src.observability` is the authoritative debug timeline. Its SQLite/WAL ledger lives
outside the model-writable workspace and commits each event synchronously with a
contiguous sequence and predecessor hash. The workspace JSONL is rebuildable and has
no authority. Trace/span/parent IDs correlate orchestrator model dispatch, provider
runtime, host subprocesses, MCP JSON-RPC, the network broker, retry/budget/checkpoint
state, confined artifact writes, database mutations, lifecycle changes, and exact
filesystem deltas. Protocol and prose payloads are represented by bounded descriptors;
secret-like keys/values are redacted. Child MCP telemetry is imported only after its
local chain validates and stays marked `untrusted_child`. The web endpoint is
`GET /api/runs/<id>/trace?since=<sequence>&limit=<n>&verify=0|1`.

All orchestrated engines consume `raw/immutable_target/<sha256>.bin`, captured through a
stable descriptor before run-contract construction. The snapshot is content-addressed,
synced, read-only, and shared by engine/export/readiness identity, so mutable source-path
replacement cannot rebind evidence. Capture failure produces a terminal incomplete
checkpoint before any supervisor/worker dispatch.

`code/` is promoted as a locked, crash-recoverable directory transaction only after all
staged files/directories are synced and `code/AUDIT_READINESS.json` validates. Readiness
requires exact manifest/ledger inventory equality, strict count/size/digest types,
artifact hashes, a successful injection scan, target identity, and manifest status that
matches decompilation coverage. Zero/partial decompilation remains explicitly
`ready_with_limitations`; corrupt or inconsistent evidence blocks every model call.
Exact resume hashes required artifacts through workspace-relative `O_NOFOLLOW` traversal
and rejects known size mismatches before reading file bodies.

`run` and `full-re` accept `--anchor-idl`; `audit-resume` accepts the same option for
an IDL relocated since checkpoint creation. `ANGERONA_ANCHOR_IDL` is the environment
equivalent. Without an explicit path, only an IDL whose decoded program public key is
present in a positively identified Solana ELF is associated. Exports always write
`code/anchor_instructions.json` and `code/anchor_instructions.md`; the former records
handler, dispatcher-only, unresolved, reachable-helper, shared-helper, and truncation
provenance. IDL labels are enclosed as untrusted external data before supervisor use.
The full function export remains authoritative. The path-independent IDL byte hash,
size, program id, instruction-set digest, and target-binary identity are part of the
immutable run contract and revalidated immediately before export.
Anchor-enabled orchestration resolves the IDL against the universal read-only target
snapshot; engine, MCP, and agent stages never return to the mutable source path.

`run` and `full-re` also accept repeatable `--similarity-corpus` export directories;
`audit-resume` accepts relocated byte-identical corpora. The environment equivalent is
`ANGERONA_SIMILARITY_CORPUS` (platform path-separated). Inputs are bounded, hashed,
read-only snapshotted, architecture-checked, and pinned in run-contract schema 13.
`code/similarity_corpus.json`, `code/re_analysis.json`, and the safe-load
`code/similarity_index.{json,npz}` preserve provenance, results, and fitted index state.
The audit policy is deterministic mnemonic TF-IDF plus exact NumPy cosine—not a learned
CFG embedding. External names are bounded candidate labels inside an untrusted-data
boundary; tie, low-information, generated-name, resource, and architecture gates fail
closed. Immutable corpus snapshots are shared rather than copied into every worker.

## MCP Surfaces

### Native Ghidra server

`GhidraMCPServer` registers these tools:

| Tool | Purpose |
|---|---|
| `status` | Engine readiness/status. |
| `security_properties` | ELF mitigation/security properties. |
| `detonate` | Explicit bounded no-network detonation. |
| `analyze` | Headless analysis summary. |
| `list_functions` | Paginated/filterable function inventory. |
| `decompile_function` | Focused decompilation. |
| `disassemble_function` | Focused disassembly. |
| `list_strings` | Filtered strings. |
| `list_imports` | Imports. |
| `list_exports` | Exports. |
| `list_symbols` | Filtered symbols. |
| `get_xrefs` | Function callers/callees/xrefs. |
| `search` | Cross-function/string/symbol text search. |
| `bindiff_match` | Compare against a BinDiff corpus. |
| `verify_understanding` | Verify reconstructed understanding with BinDiff evidence. |
| `verify_reconstruction` | Compile/check C reconstruction and structural similarity. |
| `verify_claims` | Check cited strings/imports/symbols against exported binary facts. |
| `verify_capabilities` | Check behavioral/capability claims against supporting imports. |

The server supports MCP initialize, ping, tools list/call, and empty resources/prompts
lists over line-delimited JSON-RPC on stdio. Tool exceptions are returned as MCP
content with `isError=true` and the same untrusted-data wrapper used for successes.

### IDA proxy

`IdaMcpProxy` forwards the upstream IDA MCP tool set and injects the local safety
tools `security_properties`, `detonate`, `bindiff_match`, `verify_understanding`,
`verify_reconstruction`, `verify_claims`, and `verify_capabilities`. It also:

- pins calls to the configured/current target database;
- rejects broad IDA sweeps unless explicitly enabled;
- serializes sensitive IDA operations with a lock;
- wraps forwarded result text as untrusted data;
- forwards initialize/tool-list/tool-call traffic and preserves MCP errors.

### MCP client installation

`src/mcp/config.py` writes Claude Code JSON and Codex TOML registrations, preserves
unrelated existing configuration, exposes engine-specific allowlists, and generates
launch commands/environment for IDA or Ghidra.

## Web HTTP API

The server is implemented with Python's stdlib HTTP stack. There is no built-in
authentication. Loopback binding is the default and remote binding requires
`--allow-remote`.

| Method | Path | Behavior |
|---|---|---|
| `GET` | `/` or `/index.html` | Control-panel HTML. |
| `GET` | `/static/*` | Traversal-checked JS/CSS assets. |
| `GET` | `/api/runs` | List persisted and live runs. |
| `GET` | `/api/engines` | IDA/Ghidra readiness. |
| `GET` | `/api/samples` | List files under repository `samples/`. |
| `GET` | `/api/files?path=...` | Server-side file picker with path checks. |
| `GET` | `/api/runs/{id}` | Run detail, metadata, workers, and artifacts. |
| `GET` | `/api/runs/{id}/file?path=...` | Bounded, traversal-checked artifact read. |
| `GET` | `/api/runs/{id}/live?since=N` | Monotonic live-event polling. |
| `GET` | `/api/runs/{id}/trace?since=N&limit=M&verify=0|1` | Read the authoritative observability timeline, verifying it by default. |
| `POST` | `/api/runs/start` | Validate configuration and start a run. |
| `POST` | `/api/runs/{id}/pause` | Request a cooperative pause at the next committed safe point. |
| `POST` | `/api/runs/{id}/resume` | Resume verified state, with optional relocated binary/IDL/corpus paths. |
| `POST` | `/api/runs/{id}/edit` | Edit a stopped run's configuration. |
| `POST` | `/api/runs/{id}/rerun` | Start a new run from prior configuration plus overrides. |
| `DELETE` | `/api/runs/{id}` | Delete a stopped run; rejects running runs. |

## Configuration Sources

`load_config` combines explicit engine arguments, environment variables, discovery,
and defaults. The checked-in default engine is IDA; automatic selection/fallback is
available in the full deterministic workflow.

The table below lists operator-facing configuration families. Internal inherited
process markers, trace/span IDs, and sandbox handoff variables are intentionally not
presented as public configuration.

| Group | Keys |
|---|---|
| Core | `ANGERONA_HOME`, `ANGERONA_ENGINE`, `ANGERONA_SANDBOX`, `ANGERONA_ANALYSIS_TIMEOUT`, `ANGERONA_TARGET_BINARY`, `ANGERONA_SOURCE_DB`, `ANGERONA_REQUIRE_TARGET_BINARY`, `ANGERONA_ANCHOR_IDL` |
| Agent/local model | `ANGERONA_CLAUDE_CMD`, `ANGERONA_CODEX_CMD`, `ANGERONA_CLAUDE_MODEL`, `ANGERONA_CODEX_MODEL`, `ANGERONA_LOCAL_API_KEY`, `ANGERONA_LOCAL_BASE_URL`, `ANGERONA_LOCAL_MODEL`, `ANGERONA_LOCAL_MODEL_NAME`, `CODEX_HOME` |
| Context/tool output | `ANGERONA_CONTEXT_WINDOW_TOKENS`, `ANGERONA_CONTEXT_COMPACT_PERCENT`, `ANGERONA_CONTEXT_MAX_RECOVERIES`, `ANGERONA_CONTEXT_INLINE_PAYLOAD_TOKENS`, `ANGERONA_CONTEXT_RECENT_CAPSULE_CHARS`, `ANGERONA_CONTEXT_PROFILE_DIR`, `ANGERONA_CONTEXT_COMPACT_PROMPT`, `ANGERONA_CONTEXT_COMPACT_PROMPT_FILE`, `ANGERONA_TOOL_OUTPUT_MAX_TOKENS`, `ANGERONA_TOOL_OUTPUT_SESSION_BUDGET_TOKENS`, `ANGERONA_TOOL_OUTPUT_PREVIEW_CHARS`, `ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_BYTES`, `ANGERONA_TOOL_OUTPUT_MAX_PERSISTED_FILES` |
| Agent transient retry | `ANGERONA_TRANSIENT_MAX_ATTEMPTS`, `ANGERONA_TRANSIENT_BASE_DELAY_SECONDS`, `ANGERONA_TRANSIENT_MAX_DELAY_SECONDS`, `ANGERONA_TRANSIENT_JITTER_RATIO`, `ANGERONA_TRANSIENT_MIN_REMAINING_SECONDS` |
| Audit-wide budget | `ANGERONA_AUDIT_MAX_AGENT_CALLS`, `ANGERONA_AUDIT_CRITICAL_RESERVE_CALLS`, `ANGERONA_AUDIT_MAX_WALL_SECONDS`, `ANGERONA_AUDIT_MAX_AGENT_TOKENS`, `ANGERONA_AUDIT_MAX_COST_USD`, `ANGERONA_AUDIT_TOKEN_RESERVATION_PER_CALL`, `ANGERONA_AUDIT_COST_RESERVATION_PER_CALL_USD`, `ANGERONA_AUDIT_DISPATCH_CALL_RESERVATION` |
| Agent isolation/network | `ANGERONA_AGENT_FS_SANDBOX`, `ANGERONA_AGENT_NETWORK_ALLOWLIST`, `ANGERONA_AGENT_NETWORK_ALLOW_PRIVATE`, `ANGERONA_ALLOW_CLAUDE_COMPAT_GATEWAY`, `ANGERONA_MCP_ALLOW_WRITE`, `MCP_TIMEOUT`, `MCP_TOOL_TIMEOUT` |
| Control state/observability | `ANGERONA_AGENT_CONTROL_STATE_DIR`, `ANGERONA_OBSERVABILITY_REQUIRED`, `XDG_STATE_HOME` |
| IDA discovery/MCP | `IDA_INSTALL_DIR` is documented but source discovery also uses `IDADIR`; indexed keys are `IDADIR`, `ANGERONA_IDA_MCP_PYTHON`, `ANGERONA_IDA_MCP_PACKAGE`, `ANGERONA_IDA_MCP_COMMIT`, `ANGERONA_IDA_MCP_PYTHON_VERSION`, `ANGERONA_IDA_MCP_CHILD_CMD`, `ANGERONA_IDA_MAX_WORKERS`, `IDA_MCP_MAX_WORKERS`, `ANGERONA_IDA_LOCK_FILE`, `ANGERONA_ALLOW_FULL_IDA_SWEEP` |
| IDA extraction limits | `ANGERONA_IDA_MAX_DECOMPILED_CHARS`, `ANGERONA_IDA_MAX_DISASM`, `ANGERONA_IDA_MAX_REFS`, `ANGERONA_IDA_MAX_STRINGS`, `ANGERONA_IDA_MAX_SYMBOLS` |
| IDA batch handoff | `ANGERONA_IDA_IDAT_MODE`, `ANGERONA_IDA_IDAT_OUT`, `ANGERONA_IDA_IDAT_FUNCTION`, `ANGERONA_IDA_IDAT_MAX_FUNCTIONS`, `ANGERONA_IDA_IDAT_PROCESSOR`, `ANGERONA_IDA_IDAT_QEXIT` |
| Ghidra/BinDiff | `GHIDRA_HOME`, `GHIDRA_INSTALL_DIR`, `JAVA_HOME`, `BINDIFF_PATH`, `BINEXPORT_GHIDRA_ZIP` |
| Host discovery | `HOME`, `APPDATA` |

`README.md` also documents `IDA_INSTALL_DIR`; configuration code and tests should be
consulted when changing discovery aliases because graph extraction reports only
literal environment reads it recognizes.

## Artifacts And Schemas

Common engine export artifacts include analysis JSON, decompiled functions, strings,
imports, exports, symbols, security properties, and a manifest with source identity
and status. The batch pipeline adds `triage.json`, graph/signature/type/xref/sink/C++
artifacts as enabled, a checkpoint database, Solana fusion/utility outputs when
applicable, and `raw/batch_report.json`.

Agent workflows add supervisor plans, worker sub-workspaces, raw model transcripts,
hash-chained retry ledgers, review rounds, living findings/progress, evidence-ledger
content, and consolidated reports. Consumers must inspect manifest/stage status instead
of inferring success from file existence.

Every promoted model output also has an output-boundary record containing the policy
version, role, exact byte SHA-256, size, status, and reasons. Current-policy worker and
supervisor checkpoints require these records for reports, reviews, plans, outcomes, and
terminal reports. Peer output is forwarded to another model only in a canonical
`<untrusted_agent_output>` JSON envelope with `authority: none`; a missing/mismatched
record, ambiguous reviewer verdict, decoded plan control, or semantic instruction
directive fails closed and cannot preserve convergence.
