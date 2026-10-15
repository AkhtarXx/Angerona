# Feature And Module Map

This file provides a module navigation map. Consult the current source for exact
signatures and behavior, and `docs/VERIFICATION.md` for executed qualification.
Implementation presence does not establish real-target coverage.

## Package Root

| Path | Responsibility |
|---|---|
| `src/__init__.py` | Package metadata/export surface. |
| `src/__main__.py` | Delegates `python -m src` to the CLI. |
| `src/cli.py` | All argument parsing and command handlers: agent runs, deterministic batch/full RE, engine operations, graph/checkpoint tools, execution probes, recovery passes, summaries, MCP, web, install, and update. |
| `src/boot_problems.py` | Fail-fast boot checklist (QM pattern): engine/agent/sandbox presence verified before any analysis begins so misconfigurations surface as explicit errors, not silent degradation. |
| `src/config.py` | Configuration dataclass, environment discovery, IDA/Ghidra/JDK/BinDiff paths, readiness checks, state locations, agent commands, and safety/runtime settings. |
| `src/secure_artifacts.py` | Bounded no-follow artifact reads, identity checks, atomic writes, and secure filesystem helpers shared by audit pipelines. |
| `src/observability.py` | External-authority hash-chained event ledger, trace/span correlation, secret-safe descriptors, child-spool validation, filesystem deltas, verification, and readable-mirror rebuild. |
| `src/subprocess_observability.py` | Drop-in host subprocess tracing with command/result descriptors and exact workspace change events. |
| `src/updater.py` | Ghidra release lookup/download/install/update workflow with progress reporting and pruning. |
| `src/workspace.py` | Run directory creation, metadata, traces, progress/findings writes, lifecycle completion, and workspace paths. |

## Agent System

| Path | Responsibility |
|---|---|
| `src/agents/__init__.py` | Agent package marker/exports. |
| `src/agents/audit_state.py` | Immutable checkpoint generations, content-addressed blobs, workspace manifests, leases, pause/resume requests, identity validation, and durable context policy. |
| `src/agents/budget_harness.py` | Audit-wide call/token/cost/wall budgets, reservations, protected finalization capacity, and durable usage ledgers. |
| `src/agents/context_harness.py` | Provider/model-aware context sizing, proactive compaction, sealed-FD initial/recovery payloads, attempt/snapshot/execution-contract-bound checkpoint chains, observed-limit learning, and tamper-evident continuation prompts. |
| `src/agents/network_guard.py` | Private-namespace K-candidate egress broker, bounded inherited channels, exact/scoped endpoint and canonical HTTP path policy, DNS/address/SNI validation, trusted local-gateway aliasing, resume-contract identity, and per-request allow/deny telemetry. |
| `src/agents/loop.py` | Bounded analyst-reviewer convergence, eligibility-first K-candidate selection, target-bound scoring, bounded no-follow materialization, attested Bubblewrap-enforced K>1 dispatch, isolated artifact promotion, exact file/directory resume authority, Reflexion memory, verification gates, and round persistence. |
| `src/agents/output_boundary.py` | Provider-agnostic model-output policy, strict reviewer control parsing, semantic control quarantine, canonical zero-authority peer envelopes, and content-addressed resume records. |
| `src/agents/respawn_policy.py` | Trusted-channel worker failure taxonomy, strict checkpoint-safe control records, and provider-neutral split/retry/reroute/stop decisions. |
| `src/agents/retry_harness.py` | Bounded transient retry classification, backoff/Retry-After policy, immutable deadline/attempt enforcement, execution-contract dispatch identity, supervisor-only hash-chained authority, and non-authoritative workspace mirrors. |
| `src/agents/run_contract.py` | Immutable execution-contract construction, hashing, persistence, and exact-resume compatibility validation. |
| `src/agents/scratch_quota.py` | Exact-manifest seed transfer, aggregate tmpfs plus FD/mmap inode enforcement, storage/namespace/retention seccomp, protected quota-runner lifecycle, inherited-FD sanitized candidate-local CLI auth/settings, cumulative exact-type recovery deltas with immutable-input exclusion, bounded reconstruction framing/import, and descriptor-anchored atomic host installation. |
| `src/agents/orchestrator.py` | End-to-end agent run setup, engine routing and pre-analysis, deterministic RE prepasses, MCP registration, worker dispatch, reviewer selection inputs, event printing, and final lifecycle handling. |
| `src/agents/prompts.py` | System prompts and task templates for analysts, reviewers, supervisors, and engine-specific first actions. |
| `src/agents/runtime.py` | Claude Code and Codex adapters, subprocess streaming, JSON event normalization, bounded stdout/stderr capture, process groups, idle/wall timeouts, model-agnostic context/retry recovery, universally serialized crash-safe instruction quarantine, OAuth/MCP-safe provider state, Bubblewrap/cgroup candidate isolation, provider-agnostic executable pinning, trusted artifact channels, filesystem/environment policy, and agent availability. |
| `src/agents/spawn_plan.py` | Worker-task representation, search strategies, model/tool routing, hard-capped candidate-budget allocation, DAG scheduling, plan evaluation, and adaptive spawn decisions. |
| `src/agents/supervisor.py` | Supervisor planning, coverage validation, worker creation, infrastructure-aware role-specific fallback/respawn, scope-authenticated immutable attempt lineage and active-leaf projection, concurrent scheduling, adaptive topology, evidence-ledger integration, and consolidated reports/run logs. |
| `src/agents/worker_lease.py` | Worker lease fencing with durable supervisor-only heartbeat, monotonic fencing token, and SIGTERM→SIGKILL watchdog reaping of zombie workers. |

## Analysis Modules

| Path | Responsibility |
|---|---|
| `src/analysis/__init__.py` | Analysis package marker. |
| `src/analysis/anchor_idl.py` | Bounded Anchor IDL discovery/parsing, target binding, instruction grouping, immutable snapshots, and exact-resume identity. |
| `src/analysis/anchor_retrieval.py` | Evidence-anchor extraction, indexing, ranking, and query retrieval. |
| `src/analysis/benchmark_matrix.py` | Reproducible multi-compiler corpus builds, precision/recall metrics, aggregation, and regression thresholds. |
| `src/analysis/auto_reexec.py` | C-block extraction, compile checking, and forced re-execution validation of reconstructed code. |
| `src/analysis/audit_readiness.py` | Fail-closed export/manifest/ledger/injection/coverage readiness transaction and deterministic limitation reporting. |
| `src/analysis/archive_router.py` | Recursive archive unzipper/router with depth/byte budget, Janus signing-ambiguity note, and cycle-safe hash dedup. |
| `src/analysis/asan_proxy.py` | Reconstruction→ASan-proxy oracle: builds/executes `-fsanitize=address,undefined` harnesses over reconstructed C units and emits sanitizer verdicts for binary-only targets. |
| `src/analysis/blob_fingerprint.py` | Headerless-blob forensics: iHEX/SREC detect, endianness/word-size vote, vector anchors (Cortex-M / x86 reset), rbasefind-style base inference, and BlobFacts with confidence+unresolved. |
| `src/analysis/format_detector.py` | Universal format detector producing FormatProfile (family/variant/confidence/container/engine-hint); combines magic signatures, polyglot scan, structural probes, statistical sniff fallback. |
| `src/analysis/signatures.yaml` | Signature DB for L0 format detector: 30+ native/managed/container/blob formats with corrected PRONOM PUIDs and polyglot preference ranks. |
| `src/analysis/formats/__init__.py` | Format-detection subpackage marker. |
| `src/analysis/formats/safe_reader.py` | Bounds-checked byte Reader used by every parser at L0/L1; rejects out-of-buffer reads and honours byte budgets. |
| `src/analysis/formats/loader.py` | YAML signature DB loader shaping Signature records for detect/polyglot. |
| `src/analysis/formats/detect.py` | Magic-offset identification engine: forward magic, structural heuristics (pyc), polyrank ordering. |
| `src/analysis/formats/polyglot.py` | Forward + backward EOCD + interior stride multi-offset polyglot scan with ≤3 candidate cap and 256 MiB byte budget. |
| `src/analysis/formats/sniff.py` | Statistical family sniffing (entropy / byte histogram / null-ratio) as fallback when no magic matches; reports numbers, never labels. |
| `src/analysis/lifters/__init__.py` | Universal lifting lane marker exposing LiftRequest/LiftOutcome registry. |
| `src/analysis/lifters/base.py` | LiftRequest/LiftOutcome dataclasses plus LifUnavailable contract shared by all lifters. |
| `src/analysis/lifters/pcode_lifter.py` | Primary lifter via pypcode (SLEIGH semantics, ~180 language variants); produces IR rows + confidence + provenance. |
| `src/analysis/lifters/vex_lifter.py` | Fast-path lifter via pyvex for angr guests (x86/AMD64/ARM/PPC/MIPS/S390X). |
| `src/analysis/lifters/fallback_lifter.py` | irnorm-capstone fallback for architectures with neither pypcode language nor pyvex guest; lower confidence and explicit unresolved. |
| `src/analysis/lifters/registry.py` | Lifter chain registry with preference ordering, dual-lift agreement helper, and graceful fallback. |
| `src/analysis/packing_detect.py` | Multi-signal packing classifier (per-section entropy, packer-marker sections, overlay anomaly, TLS callbacks, raw-vs-virtual expansion) producing PackingReport. |
| `src/analysis/refusal.py` | Refusal policy: emits UnprotectableReport when packing/vm-region/IAT/decoy/बudget thresholds cross; never fabricates analysis. |
| `src/processors/beam.py` | Erlang BEAM bytecode processor (calls/bs-ops subset) with call/jump edge emission. |
| `src/processors/cil.py` | .NET CIL bytecode processor (subset of single-byte CIL ops + 2-byte prefix 0xFE placeholders). |
| `src/processors/dex.py` | Dalvik DEX processor (invoke/goto/if/const family) with invoke-edge and control-flow edges. |
| `src/processors/jvm.py` | JVM class-file bytecode processor (80+ opcodes including tableswitch/lookupswitch variable-length forms). |
| `src/processors/lua_bc.py` | Lua 5.1/5.3/5.4 bytecode processors with version-specific opcode tables. |
| `src/processors/pyc.py` | CPython .pyc bytecode processor with per-version magic pinning and cache-skip support for 3.11+. |
| `src/processors/v8_ignition.py` | V8 Ignition bytecode processor (BytecodeArray-only experimental extraction). |
| `src/processors/wasm.py` | WebAssembly MVP+ processor (LEB128 immediates, block/if/loop nesting, memory/i32/i64/f32/f64 const forms). |
| `src/analysis/bcrl.py` | Binary-code representation learning features and similarity scoring. |
| `src/analysis/bequiv.py` | Behavioral equivalence test-case execution and result comparison. |
| `src/analysis/binary_bpe.py` | Byte-pair tokenizer training/encoding and context-window chunking for binary data. |
| `src/analysis/bindiff.py` | BinExport/BinDiff discovery, caching, command execution, SQLite result parsing, corpus matching, structural strength, and reconstruction/understanding verification. |
| `src/analysis/binprops.py` | ELF parsing and exploit-mitigation/security-property reporting. |
| `src/analysis/cfg_cache.py` | Bounded LRU cache for function-level CFG builds; memoises recursive-descent disassembly over stable instruction sets. |
| `src/analysis/cfg_spine.py` | Function CFG/basic-block recovery, dominators/loops/control-dependence, serialization, and graph-wide CFG construction. |
| `src/analysis/canonical_ir.py` | Canonical p-code records, SSA/PHI construction, def-use indexes, taint propagation, and program slicing. |
| `src/analysis/compiler_personality.py` | Compiler, linker, packer/protector, ABI, and language/personality evidence detection. |
| `src/analysis/composite.py` | Weighted aggregation of verification pillars into composite confidence/verdicts. |
| `src/analysis/corpus_caveat.py` | Corpus-match interpretation and explicit limitations for family/classification evidence. |
| `src/analysis/cost.py` | Token/cost event recording, budgets, summaries, and pricing-aware accounting. |
| `src/analysis/coverage_tier.py` | Coverage ratio calculation and evidence-tier classification. |
| `src/analysis/deobfuscate.py` | Constant folding, opaque-predicate simplification, and deobfuscation pass orchestration. |
| `src/analysis/debug_symbols.py` | DWARF, PDB, dSYM, debuginfod, signature normalization, target binding, and priority-aware merge. |
| `src/analysis/detonate.py` | Explicit no-network Docker detonation with limits and captured results. |
| `src/analysis/resources/detonate.Dockerfile` | Packaged disposable, unprivileged strace container recipe used by installed wheels. |
| `src/analysis/resources/ApkSigVerifier.java` | Packaged Java helper for extracting APK signing-scheme certificate evidence when platform tooling is unavailable. |
| `src/analysis/dex_security_rules.py` | QARK-style static security rule pass over DEX/smali: hardcoded credentials, weak crypto, cleartext HTTP, TLS TrustAll, reflection loaders, root/tamper indicators, with line+file provenance per finding. |
| `src/analysis/dex_semantic.py` | Strict DEX header/table/class/method/code inventory and exact semantic reconciliation used by static and recovered-runtime coverage gates. |
| `src/analysis/jadx_bridge.py` | Isolated JADX CLI subprocess bridge (bounded memory+timeout, pre-extract manifest fallback, security finding envelope, `untrusted_child` trust marker). |
| `src/analysis/allow_backup_check.py` | APK `allowBackup`/backup-rules manifest audit: default-true, missing full-backup-content, and data-extraction-rules findings. |
| `src/analysis/android_artifact.py` | Fail-closed single-APK container validation, traversal/zip-bomb budgets, DEX inventory, and valid native-only APK recognition. |
| `src/analysis/android_binary_inventory.py` | Magic-first APK member accounting, polyglot/custom-payload detection, licensed IDA native evidence, and executable/non-executable semantic coverage ledgers. |
| `src/analysis/android_root_scanner.py` | Root/tamper indicator scan over APK strings/smali/native libs: su binaries, Magisk, root-management apps, RW-path probes, per-category evidence. |
| `src/analysis/assets_blob_detector.py` | Encrypted/packed payload detection in APK assets: DEX-in-assets, ELF blobs, high-entropy containers, zip-signature anomalies. |
| `src/analysis/cleartext_tls_rule.py` | Cleartext-Traffic/TLS policy audit: manifest `usesCleartextTraffic`, network-security-config holes, raw-HTTP URLs in source, trust-anchor misuse, merged verdicts. |
| `src/analysis/contentprovider_traversal.py` | Exported content-provider attack-surface scan: path-traversal-prone `openFile`, SQL-injection-prone projection/selection usage, grant-uri-permission exposure. |
| `src/analysis/deeplink_injection.py` | Deeplink/intent-surface audit: exported activities with BROWSABLE schemes, missing `autoVerify`, intent extras flowing to loadUrl/execSQL sinks. |
| `src/analysis/dex_reflection_tracker.py` | Reflection/DexClassLoader load-site tracker over smali and JADX source: dynamic-load sinks, reflection invoke chains, per-site evidence. |
| `src/analysis/janus_signature.py` | Janus CVE-2017-13156 signature check: v1/v2 scheme presence, DEX-at-offset-0 vs first-zip-entry divergence, suspicious-payload verdict. |
| `src/analysis/logcat_sensitive.py` | Sensitive Log.* call audit over source: passwords/tokens/PII arguments reaching logcat sinks with severity-rated findings. |
| `src/analysis/multidex_coverage.py` | Multi-DEX coverage inventory: dex-file enumeration, `classesN.dex` chain, analysis-coverage gap reporting. |
| `src/analysis/native_secrets_hunter.py` | Native `.so` secrets hunter: hardcoded API keys, AES keys, base64 blobs, JNI-export names out of APK lib dirs. |
| `src/analysis/webview_bridge_finder.py` | WebView JavascriptInterface bridge inventory from DEX strings/JADX source: exposed bridge classes/methods reachable from JS. |
| `src/analysis/native_elf.py` | Bounds-checked minimal ELF64/32 parser (sections, PT_LOAD/PT_DYNAMIC, dynsym/symtab) powering native analysis modules. |
| `src/analysis/jni_registration_resolver.py` | Static JNINativeMethod[] table recovery from .so `.data.rel.ro` — resolves dynamic RegisterNatives entries to name/signature/fn-addr triples. |
| `src/analysis/native_anti_tamper_scanner.py` | Native anti-tamper evidence locator (ptrace/TracerPid/frida-scan/crc/timing patterns) → patch hit-list for dynamic runs. |
| `src/analysis/constructor_pre_emulator.py` | Unicorn pre-emulation of DT_INIT/.init_array constructors → recovered post-decryption memory strings → secrets scan. |
| `src/analysis/key_derivation_carver.py` | Static ARM64 carve of runtime-built secrets: mov-immediate/strb stack-fill pairs, movz/movk chains, XOR-decode loops (partial-flagged). |
| `src/analysis/crypto_const_fingerprints.py` | Algorithm fingerprinting: AES Te0, SHA-256 K, ChaCha σ, MD5 K, TEA delta, standard versus custom base64 alphabets. |
| `src/analysis/jni_boundary_taint.py` | Java↔native edge taint: loadLibrary sites, literal args into native/declared-native calls, GetFieldID+`token`-style reads, NewStringUTF escapes. |
| `src/analysis/apktool_bridge.py` | Apktool headless decode bridge (binary AXML → text XML, smali dirs, exported components, isolated subprocess, untrusted_child). |
| `src/analysis/apksigner_bridge.py` | APK signing cert-chain extraction (v1+v2/v3 schemes) + canonical-key registry verification — origin verification before any analysis. |
| `src/analysis/tls_stack_identifier.py` | TLS stack discrimination: conscrypt_java / boringssl / openssl / rustls / cronet identification + pinning + OkHttp detection. |
| `src/analysis/android_packer_db.py` | Android packer family fingerprints: Bangcle/SecNeo/Legu/Jiagu/Ijiami/DexGuard/Appdome/Promon/Alijiagu with weighted scoring. |
| `src/analysis/mtls_tier_classifier.py` | Mutual-TLS posture detection: server_tls vs mtls_soft vs mtls_hard (hardware keystore) + recommended MITM/testing approach. |
| `src/analysis/finding.py` | Canonical Finding schema with verdict tiers (CONFIRMED/LIKELY/INCONCLUSIVE/NOT_APPLICABLE/REFUSAL) + legacy-dict coercion. |
| `src/analysis/legacy_finding_adapter.py` | Migration bridge: promotes legacy dict-result findings into canonical Finding at module boundary (deletes when migration done). |
| `src/analysis/findings_compat.py` | Per-module naming variance adapter for Finding conversion: kind/marker/rule/category polymorphism, custom verdict vocab preservation, offset→line_no mapping. |
| `src/analysis/finding_evidence.py` | Courtroom-grade replay bundle per finding: APK-sha + module-version + rule-traces → deterministic replay hash; tamper-detection verified. |
| `src/execution/static_runtime_bridge.py` | Static-file-offset → runtime-hook plan generator + Frida script emitter (native anti-tamper → runtime Interceptor wiring). |
| `src/analysis/baseline_registry.py` | Disk-backed known-good APK baseline registry: `<root>/<pkg>/<version>.json` + `latest.json` pointer, atomic saves. |
| `src/analysis/wss_cleartext_rule.py` | WebSocket cleartext detection (ws:// vs wss://), OkHttp/javax.websocket sinks, native .so scan. |
| `src/analysis/browsable_implicits.py` | Android 12+ implicit-reachability: BROWSABLE+scheme without exported=false/autoVerify, deep-link hijacking surfaces. |
| `src/analysis/attack_chain_scorer.py` | Composite attack-chain detection: 20 curated kill-chain templates (webview-bridge, backup-exfil, cleartext-credential, root-injection, provider-traversal, secret-harvest, deeplink-xss, intent-redirection, logcat-credential, rooted-payload, trust-user-CA, MTLS-bypass, shared-preferences, insecure-deeplink, smali-evasion, janus-bypass, reflection-pwn, http-cache-sniff, keystore-attestation, contentprovider-any) + multi-link composition. |
| `src/analysis/upstream_source_differ.py` | APK-vs-baseline structural diff: dex/manifest/native/asset hashes CHANGED/ADDED/REMOVED (repack detection). |
| `src/analysis/jni_runtime_fusion.py` | Static JNI hypotheses × runtime jnitrace events fusion engine — corroborates or marks "not_observed_in_window". |
| `src/execution/adb_probe.py` | Runtime exported-surface verification: `dumpsys package`, `resolve-activity`, AppOps via adb shell (devices optional). |
| `src/execution/android_runtime_manager.py` | Disposable official-AVD lifecycle, APK-bound host-containment receipt validation, pinned tool/image/Frida setup, private ADB transport, authenticated loopback Frida, and verified teardown. |
| `src/execution/runtime_dex_extractor.py` | Dynamic DEX extraction orchestrator: Frida InMemoryDexClassLoader+DexFile+BaseDexClassLoader hooks, memory→disk dumps, sha256, static pipeline loop closure (actually dumps bytes — not just observations). |
| `src/execution/stalker_correlator.py` | Frida Stalker trace ingest + static CFG correlator: ELF-aware VADDR translation via PT_LOAD (not naive base+offset) — upgrades uncorroborated anti-tamper hits with runtime execution truth. |
| `src/pipeline/__init__.py` | Package init: exports run_android_audit, AuditReport, AuditFinding for callers. |
| `src/pipeline/android_ai_audit.py` | Android evidence materialization and AI swarm adapter: cost-balanced authoritative slices, controller-validated file/finding receipts, active-lineage coverage, observability verification, and atomic terminal completion gates. |
| `src/pipeline/android_audit.py` | Professional-ordered pipeline orchestrator: provenance → packer → runtime-extract → TLS-stack → gated rules → verdict tiers (CONFIRMED/LIKELY/INCONCLUSIVE/NOT_APPLICABLE/REFUSAL). Never emits "SAFE"; packed+uncorroborated downgrades to INCONCLUSIVE. |
| `src/analysis/differential.py` | Differential execution/input generation, comparison, divergence evidence, and graph application. |
| `src/analysis/differential_runtime.py` | Per-function runtime differential: compile-reconstructed vs reference C over a deterministic input corpus with 3-level (parse/compile/behavior) verdicts. |
| `src/analysis/embedding_recall.py` | NL-supervised recall layer for corpus matching: deterministic simindex-based candidate recall + BinDiff precision. |
| `src/analysis/ensemble_fuzz.py` | Ensemble fuzzing corpus-sync/merge with sha256 dedup, per-campaign provenance, and reseed allocation. |
| `src/analysis/evidence_ledger.py` | Structured claims, evidence/provenance records, claim status, conflict handling, merge, validation, persistence, and report rendering. |
| `src/analysis/export.py` | Deterministic engine analysis export, manifest state, hashes, decompiled files, facts, and crash-safe status reporting. |
| `src/analysis/firmware_extract.py` | Firmware container identification, extraction strategy, nested artifacts, and manifests. |
| `src/analysis/fuzzing.py` | AFL++ target contracts, seed corpora, campaign/minimization plans, manifests, and durable outcome parsing. |
| `src/analysis/gadget_finder.py` | Exact byte-pattern and return-oriented gadget discovery with architecture-aware representations. |
| `src/analysis/indirect_flow.py` | Switch-table, jump-table, function-pointer-table, virtual-call, and indirect target recovery. |
| `src/analysis/interproc_taint.py` | Inter-procedural taint tracking over the canonical SSA IR via call-graph propagation. |
| `src/analysis/irnorm.py` | Instruction/intermediate-representation normalization for cross-compiler comparisons. |
| `src/analysis/library_signatures.py` | Signature database storage/import/export, hashing/fuzzy matching, library classification, and graph labeling. |
| `src/analysis/lift_confidence.py` | Lift-quality/confidence assessment and fallback recommendations. |
| `src/analysis/malware_triage.py` | Static malware-family/capability/indicator triage with evidence and confidence. |
| `src/analysis/obfuscation.py` | Report/fact-aware obfuscation prepass and verification implications. |
| `src/analysis/obfuscation_detect.py` | Entropy and structural heuristics for packing/obfuscation detection. |
| `src/analysis/pcode_struct.py` | P-code/low-level operation structuring into higher-level expressions and blocks. |
| `src/analysis/pov_oracle.py` | Proof-of-vulnerability claim detection and optional oracle execution/assessment. |
| `src/analysis/provenance.py` | Source-binary hashing, manifest provenance, artifact binding, and trust checks. |
| `src/analysis/unicorn_oracle.py` | Public interface for bounded Unicorn behavioral-oracle runs. |
| `src/analysis/qemu_oracle.py` | Legacy compatibility import; the implementation uses Unicorn and does not invoke QEMU. |
| `src/analysis/re_analysis.py` | Ordered deterministic RE passes, per-pass status/error reporting, artifacts, and summary output. |
| `src/analysis/rebench_eval.py` | RE benchmark scoring and result comparison. |
| `src/analysis/redteam.py` | Adversarial review/red-team checks over claims and reports. |
| `src/analysis/rule_scanners.py` | capa and YARA planning/scanning with normalized rule provenance and target identities. |
| `src/analysis/sandbox.py` | Bubblewrap command construction and fail-closed parser isolation. |
| `src/analysis/scan_injection.py` | Prompt-injection scanning for extracted strings and generated content. |
| `src/analysis/security_slices.py` | Security-relevant function ranking, entry/sink reachability slices, evidence paths, and serializable slice reports. |
| `src/analysis/per_region_equiv.py` | codealign-style per-region equivalence feedback for reconstruction verdicts (localized spans + structural repair hints). |
| `src/analysis/resym_solver.py` | ReSym-style constraint solver: multi-query LLM type claims aggregated under deterministic pcode_struct field facts with TypeAgnosticArg guards. |
| `src/analysis/semantics.py` | Semantic evidence tiers and consistency verification. |
| `src/analysis/simindex.py` | Function fingerprints, similarity index persistence/search, locality-sensitive candidate generation, and match scoring. |
| `src/analysis/smali_string_decrypt.py` | TinySmaliEmulator-style smali constant-propagation decoder for hidden strings. |
| `src/analysis/similarity_corpus.py` | Trusted corpus resolution, bounded immutable materialization, architecture gates, provenance contracts, and resume-safe summaries. |
| `src/analysis/sink_hunter.py` | Sink taxonomy, candidate discovery/ranking, call-path context, and vulnerability-oriented sink reports. |
| `src/analysis/sleigh_draft.py` | Draft SLEIGH specification generation for custom architectures. |
| `src/analysis/stack_frame_recovery.py` | Stack-slot/frame analysis from instruction evidence and graph annotations. |
| `src/analysis/target_snapshot.py` | Universal content-addressed target snapshot creation and source-byte revalidation for audit identity. |
| `src/analysis/structrecovery.py` | Structure-field/layout inference and recovered-structure output. |
| `src/analysis/symbolrecovery.py` | Symbol/name candidate recovery and evidence-aware renaming proposals. |
| `src/analysis/topology.py` | Agent topology candidates, graph metrics, evaluation, and topology selection. |
| `src/analysis/typefidelity.py` | Recovered-type claims checked against exported type/symbol facts. |
| `src/analysis/unpacking.py` | Verified memory dumps, PE/OEP/IAT reconstruction metadata, CAPE ingestion, and recursive child analysis. |
| `src/analysis/variant_analysis.py` | Variant/family comparison and delta identification. |
| `src/analysis/vector_recovery.py` | SIMD/vector idiom and vector-type recovery. |
| `src/analysis/verify.py` | Binary fact loading, cited-token extraction, claim verification, capability-to-import checks, and verification reports. |
| `src/analysis/writeback.py` | Target-bound transactional rename/comment/type plans, receipts, rollback, and engine bundle export. |
| `src/analysis/xref_graph.py` | Function/data/string cross-reference graph construction, traversal, reachability, ownership resolution, and persistence. |

## Engines And Extractors

| Path | Responsibility |
|---|---|
| `src/engines/__init__.py` | Engine factory and public engine imports. |
| `src/engines/selector.py` | Readiness-aware IDA/Ghidra selection, explicit override, and fallback order/reasons. |
| `src/engines/ida.py` | IDA analysis/decompile adapter, IDB/cache lifecycle, subprocess specifications, metadata reads, and error normalization. |
| `src/engines/ghidra.py` | Ghidra headless project/cache management, extraction runs, eBPF recognition, metadata reads, and decompilation. |
| `src/scripts/REDump.java` | Ghidra-side program metadata, functions, decompilation, symbols, strings, xrefs, and instruction extraction. |
| `src/scripts/ida_dump.py` | IDA/idalib-side comprehensive extraction, analysis-quality recovery, normalized JSON output, and pure helper functions. |
| `src/scripts/ida_idat_dump.py` | IDA batch/idat extraction fallback entry point. |
| `src/scripts/ida_writeback.py` | IDA-side target verification, mutation application, old-value capture, database save, and receipt output. |
| `src/scripts/GhidraWriteback.java` | Ghidra-side dependency-free plan ingestion and all-or-nothing database transaction/receipt. |

## Analysis Models

| Path | Responsibility |
|---|---|
| `src/models/analysis_graph.py` | Canonical nodes/edges/evidence/confidence graph, indexes, mutation API, address ownership, validation, and JSON persistence. |
| `src/models/checkpoint_db.py` | SQLite mutation journal, checkpoints, audit log, revert, tags, and context-manager support. |
| `src/models/cpp_recovery.py` | RTTI/vtable/inheritance/object-layout/member-function recovery and graph updates. |
| `src/models/triage_profile.py` | Triage profile schema plus file/ELF/PE/Mach-O/entropy/string-based evidence collectors and fusion. |
| `src/models/type_library.py` | Type-library schema, lookup, persistence, C declarations, platform packs, and graph application. |
| `src/models/type_recovery.py` | Constraints, candidates, propagation, callsite/string/access inference, conflict resolution, and graph mutations. |

## Deterministic Orchestration

| Path | Responsibility |
|---|---|
| `src/orchestration/batch_spine.py` | Batch specification/result models and auditable `triage -> analyze -> graph -> signatures -> types -> xref -> sinks -> cpp` pipeline. |

## Execution And Runtime Feedback

| Path | Responsibility |
|---|---|
| `src/execution/models.py` | Emulator probe, memory snapshot, and backend-result data contracts. |
| `src/execution/backend_selector.py` | Backend capability descriptions, target/profile requirements, ranking, and selection. |
| `src/execution/probe_runner.py` | Runner registration, availability, lookup, and safe probe dispatch. |
| `src/execution/enrichment_loop.py` | Function/workspace probing loop and snapshot/constraint application to graphs. |
| `src/execution/loaders.py` | Bounded ELF/PE/Mach-O/raw executable mapping with base/entry/permission normalization. |
| `src/execution/snapshot_applier.py` | Snapshot segments, register/memory observations, symbolic constraints, and graph evidence updates. |
| `src/execution/providers.py` | GDB, LLDB, DbgEng, Frida, rr, real QEMU user-mode, and bpftrace capability discovery plus shell-free plans. |
| `src/execution/jnitrace_provider.py` | Bundled JNI-runtime tracing agent template (49 most-audited hooks) for FridaProvider with JSONL parser and untrusted-child trust boundary. |
| `src/execution/runtime_trace.py` | Content-addressed trace ingestion, bpftrace NDJSON/QEMU-strace normalization, atomic JSONL storage, and deterministic replay. |
| `src/execution/unicorn_harness.py` | ABI-aware loader-backed Unicorn execution, hooks, bounds, registers, memory capture, and evidence emission. |
| `src/execution/runners/__init__.py` | Runner exports. |
| `src/execution/runners/base.py` | Abstract runner contract and normalized runner result. |
| `src/execution/runners/native_runner.py` | Native symbol invocation/probe execution with bounded subprocess behavior. |
| `src/execution/runners/unicorn_runner.py` | Loader-backed Unicorn emulation, hooks, memory capture, and result normalization. |
| `src/execution/runners/qemu_runner.py` | Backward-compatible alias for the formerly misnamed Unicorn runner. |
| `src/mcp/radare2_provider.py` | Read-only, sandbox-locked launch planning for the official radareorg MCP server. |
| `src/execution/runners/symbolic_runner.py` | angr-backed symbolic exploration, targets, constraints, and snapshots. |
| `src/execution/symbolic/__init__.py` | Symbolic public exports. |
| `src/execution/symbolic/models.py` | Symbolic request, path, constraint, and result schemas/validation. |
| `src/execution/symbolic/fallback.py` | Symbolic backend availability and deterministic fallback selection. |

## Custom Processors

| Path | Responsibility |
|---|---|
| `src/processors/__init__.py` | Processor public API. |
| `src/processors/_register_defaults.py` | Registers built-in Solana BPF and EVM processors. |
| `src/processors/base.py` | Processor/decoder/instruction/program contracts. |
| `src/processors/registry.py` | Named processor registration, lookup, and enumeration. |
| `src/processors/loader.py` | Loads raw/custom binaries through a selected processor into program models. |
| `src/processors/analyzer.py` | Builds an `AnalysisGraph` from decoded custom-ISA programs. |
| `src/processors/solana_bpf.py` | Solana/eBPF instruction decoding, branch/call targets, helper imports, and processor metadata. |
| `src/processors/evm.py` | EVM opcode decoding, PUSH/JUMP behavior, stack effects, and processor metadata. |

## Plugin SDK

| Path | Responsibility |
|---|---|
| `src/plugins/__init__.py` | Versioned plugin API exports. |
| `src/plugins/sdk.py` | Manifest/API compatibility, capability scoping, entry-point discovery, duplicate protection, and lifecycle. |

## Solana Support

| Path | Responsibility |
|---|---|
| `src/solana/__init__.py` | Solana public exports. |
| `src/solana/adapters.py` | Solana ELF detection, IDA/Ghidra adapter installation/status, runtime probes, loader diagnostics, and analysis normalization. |
| `src/solana/fusion.py` | Multi-engine run coordination, function/evidence reconciliation, primary-source policy, conflict tracking, and fused summaries. |
| `src/solana/utilities.py` | External Solana tool discovery/execution, bounded evidence capture, and utility manifests. |

## Summaries

| Path | Responsibility |
|---|---|
| `src/summary/__init__.py` | Summary public exports. |
| `src/summary/models.py` | Function and report summary data models plus serialization. |
| `src/summary/function_summarizer.py` | Graph-backed call/string/risk/behavior summaries. |
| `src/summary/pseudocode_generator.py` | Deterministic pseudocode generation for one or all graph functions. |
| `src/summary/structured_pseudocode.py` | Phoenix/DREAM-style goto-free structured pseudocode over FunctionCFG via region analysis. |

## MCP

| Path | Responsibility |
|---|---|
| `src/mcp/__init__.py` | MCP package marker. |
| `src/mcp/config.py` | Claude/Codex MCP configuration generation/installation, tool allowlists, and server launch specifications. |
| `src/mcp/server.py` | JSON-RPC stdio server, analysis/introspection tools, BinDiff and claim/capability verification tools, authorization, and untrusted-data envelopes. |
| `src/mcp/ida_proxy.py` | IDA MCP child-process proxy, request/response transformation, database scope enforcement, broad-sweep blocking, shared safety tools, and stdio serving. |
| `src/mcp/tool_output_governor.py` | Per-call and session-wide MCP output budgets, bounded previews, content-addressed spill artifacts, and truncation metadata. |

## Web Control Plane

| Path | Responsibility |
|---|---|
| `src/web/__init__.py` | Web package marker. |
| `src/web/server.py` | Local HTTP server, run registry/process control, pause/resume and run CRUD/rerun/edit, live and verified observability timelines, bounded artifact reads, file picker, static delivery, and loopback bind policy. |
| `src/web/index.html` | Single-page control-panel structure. |
| `src/web/static/app.js` | Client state, API calls, run list/detail rendering, pause/resume, live-event and observability polling, trace filters, artifact browser, file picker, forms, and actions. |
| `src/web/static/app.css` | Control-panel layout, responsive styles, state colors, tables, logs, forms, and dialogs. |

## Service Contracts

| Path | Responsibility |
|---|---|
| `src/services/__init__.py` | Exposes transport-neutral service contracts. |
| `src/services/contracts.py` | Request context, immutable artifact references, analysis/execution/verification commands and results, run transitions, statuses, and JSON serialization contracts. |

## Packaging, Benchmarks, And Operational Assets

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata, Python requirement, console script, package data, pytest defaults, and optional `angr` marker. |
| `src/__main__.py` | Module launcher; the installed console command is declared in `pyproject.toml`. |
| `src/analysis/resources/detonate.Dockerfile` | Disposable detonation container definition. |
| `.githooks/pre-commit` | Relevant-input detection, partial-staging guard, generated documentation refresh/auto-stage, fixed-point verification, and staged whitespace checks. |
| `scripts/update_codebase_docs.py` | Fast graph reindex, graph/AST symbol generation, source fingerprint/state blocks, semantic catalog validation, and check mode. |
| `scripts/install-git-hooks.sh` | Per-clone `core.hooksPath=.githooks` installation and executable-bit setup. |
| `benchmarks/complex_fixture/fixture.cpp` | Feature-rich compiled target for recovery benchmarking. |
| `benchmarks/complex_fixture/oracle.json` | Expected benchmark structures, functions, classes, sinks, and relationships. |
| `benchmarks/complex_fixture/run_benchmark.py` | Build/analyze/evaluate pipeline, oracle scoring, diagnostics, and report output. |
| `benchmarks/corpus_matrix/` | Multi-compiler C/C++ source corpus, ground-truth oracles, matrix dimensions, and thresholds. |
| `scripts/prepare_review.py` | Source-only review export, credential-pattern scan and hash manifest. |
| `tests/fixtures/anchor_idl.json` | Synthetic Anchor IDL parser fixture; no deployed program identity claim. |
| `samples/` | Reproducible C and synthetic ELF-builder source; see the fixture README. |

## Additional analysis modules

The following modules extend the navigation map. Internal research, planning and
execution records are excluded from the review archive; claims should be assessed
against current source and recorded qualification.
| `src/analysis/cross_package_chain_analyzer.py` | Cross-APK collusion detection: sharedUserId groups, same-cert groups, custom signature-permission chains, exported cross-package surfaces. |
| `src/analysis/runtime_attestation.py` | Double-attest model for runtime corroboration: 2+ independent witness streams required to upgrade static findings (anti-evasion). |
| `src/analysis/shared_prefs_secrets_finder.py` | SharedPreferences plaintext secrets finder (cleartext-preference kind). |
| `src/analysis/http_cache_rule.py` | HTTP response cache + credential/PII sniff rule (http-cache-enabled kind). |
| `src/analysis/webview_settings_rule.py` | WebView unsafe settings passive detector (webview-unsafe-settings kind). |
| `src/analysis/hardware_keystore_detector.py` | Hardware keystore attestation claim finder (hardware-keystore-claim kind). |
| `src/analysis/file_provider_xml_check.py` | FileProvider paths.xml overly-permissive path verifier (file-provider-xml kind). |
| `src/analysis/implicit_intent_finder.py` | Implicit intent with unspecified component (implicit-intent kind). |
