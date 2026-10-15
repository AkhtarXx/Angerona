# Professional reverse-engineering harnesses

This document describes Angerona's evidence-grade reverse-engineering harnesses.
Every optional integration fails closed: absence of a tool is `unavailable`, never
successful evidence.

## Dynamic evidence and emulation

`src/execution/models.py` defines canonical, versioned `DynamicEvent`,
`MemoryRegion`, `ModuleMapping`, and `MemoryImage` records. Captured bytes and events
are SHA-256 bound; a memory image is bound to the exact target SHA-256 and has a
deterministic capture identity.

`src/execution/loaders.py` creates bounded load plans for ELF, PE, thin Mach-O, and
explicitly described raw code. The loader maps file-backed and zero-fill ranges and
tracks preferred/runtime bases. PE rebasing is refused until relocations are applied;
fat Mach-O requires explicit slice selection.

`src/execution/unicorn_harness.py` maps those plans into Unicorn, initializes the
supported ABI, installs a guarded stack and return sentinel, records block/error/
return events, and reads requested bytes from final emulator memory. Install it with
`pip install -e ".[emulation]"`. The target must be supplied by runtime address;
unresolved names return `missing_symbol` instead of silently executing the program
entry point.

Debugger and instrumentation providers in `src/execution/providers.py` cover GDB,
LLDB, DbgEng, Frida, and rr. They produce shell-free argument plans. Provider output
is normalized through `src/execution/runtime_trace.py`, atomically stored as JSONL,
hash checked, and replayed through a deterministic side-effect-free cursor.
Batch LLDB plans ignore user init files and disable automatic external-symbol lookup
before loading the target, so a headless run cannot stall on debuginfod networking.
Frida spawn plans use the current CLI's `-q -t inf` interface; the removed
`--no-pause` and unsupported `--quiet` long options are never emitted.

Linux execution also includes two deliberately separate QEMU providers:

- `qemu-user` selects an emulator from the ELF architecture and can emit QEMU's
  syscall trace. Guest syscalls are forwarded to the host, so this is not a sandbox.
- `qemu-tcg-plugin` verifies the full-system binary's plugin API with
  `-plugin help`, forces TCG software translation, and loads an explicit out-of-tree
  plugin. Use `angerona qemu-plugin-plan /path/to/plugin.so`; pass guest boot options
  with repeatable `--qemu-arg` values.

On a non-root host, `bpftrace-plan` automatically uses `sudo -n` only after that
gate succeeds, and keeps bpftrace output as NDJSON. Passing `--sudo` remains an
explicit equivalent. A bpftrace executable without root or verified non-interactive
sudo is excluded from the active audit registry. The rr status is stronger than an executable-presence check: a
temporary `/bin/true` recording must succeed. A VM that installs rr but does not
expose hardware performance counters reports `binary_installed=true` and
`recording_ready=false` with rr's diagnostic in the explicit complete inventory.
The default `ProviderRegistry()` used by real audits contains only providers whose
availability gate passed, so broken rr installs and Linux-inapplicable DbgEng are
absent instead of becoming audit options. Use
`ProviderRegistry(include_unavailable=True)` only for operator diagnostics.

Check local availability with:

```bash
angerona execution-status /path/to/binary --json
```

Unknown targets must still be run in a disposable, network-denied environment. A
provider plan is not a sandbox.

## Unpacking and recursive analysis

`src/analysis/unpacking.py` verifies memory images before writing dumps. It supports:

- sparse-to-flat memory reconstruction;
- patching captured bytes back into PE file-backed sections;
- OEP validation and `AddressOfEntryPoint` reconstruction;
- named PE import-directory synthesis (`.angimp`) with descriptors, ILT/IAT,
  DLL/name/ordinal thunks, plus resolved-address provenance;
- hash-validated, path-contained CAPE artifact ingestion; and
- bounded, breadth-first, content-deduplicated child-artifact analysis.

Import synthesis requires an explicit DLL plus symbol or ordinal mapping. Resolved
runtime addresses alone are retained as provenance and are never guessed into names.

## Canonical IR and data flow

`src/analysis/canonical_ir.py` turns engine p-code records into canonical SSA. It
computes reaching definitions across loops, inserts PHI operations at joins, enforces
one definition per SSA value, builds def-use indexes, and provides forward/backward
slices. `TaintEngine` reports explicit SSA flows into configured sink opcodes and
supports explicit sanitizer opcodes. It does not claim implicit/control-dependence
taint.

## Debug and signature metadata

`src/analysis/debug_symbols.py` normalizes DWARF, PDB-export text, dSYM payloads,
debuginfod artifacts, and signature metadata. Merge priority prevents heuristic
names from overwriting PDB/DWARF names and records conflicts. Debuginfod artifacts
are size-bounded and must contain the requested GNU build ID before entering cache.
Install DWARF support with `pip install -e ".[symbols]"`.

## Fuzzing and rule engines

`src/analysis/fuzzing.py` models a full AFL++ lifecycle: file/stdin contracts,
content-addressed seed corpora, resource limits, instrumented/QEMU/Frida/Unicorn
plans, durable status/crash/hang collection, and `afl-tmin` plans. Campaign manifests
bind commands and seeds to the target hash.

`src/analysis/rule_scanners.py` normalizes capa JSON and YARA matches with target
hashes, rule namespaces, tags, locations, and metadata. Install YARA support with
`pip install -e ".[rules]"`.

The PyPI `flare-capa` package is a library install and does not bundle the default
rules or extractor signatures. Provision matching releases of the official
`capa-rules` repository and capa `sigs/`, then pass both explicit paths through
`CapaAdapter.plan(..., rules=..., signatures=...)`. Angerona never treats a
resource-less capa invocation as equivalent evidence.

## Reversible engine write-back

`src/analysis/writeback.py` validates rename/comment/type plans, binds them to an
exact target SHA-256, rejects duplicate mutation targets, captures old values, and
generates reverse-order rollback plans. Partial logical failures are rolled back.

- `src/scripts/ida_writeback.py` applies JSON plans inside IDA and writes receipts.
- `src/scripts/GhidraWriteback.java` uses one Ghidra database transaction and a
  dependency-free TSV plan. Failed transactions are not committed.

The IDA runner reads every value back after mutation, rolls back already-applied
operations in reverse order after a partial failure, explicitly saves the current
database, and exits non-zero if persistence or rollback verification fails.

Always preview the plan and retain its receipt. Database write-back is never part of
read-only analysis unless explicitly requested.

## Plugins and benchmarks

`src/plugins/sdk.py` exposes API-version compatibility, declared capability lookup,
duplicate protection, entry-point discovery (`angerona.plugins`), and explicit
activation/deactivation. Python plugins execute with host-process authority; only
install trusted packages.

`benchmarks/corpus_matrix/manifest.json` defines compiler, optimization, stripping,
PIE, CFG, indirect-call, C++ RTTI/vtable, and exception dimensions. The evaluator in
`src/analysis/benchmark_matrix.py` computes precision/recall and enforces ratcheted
thresholds. Compiler-backed cases require the compiler named in the manifest.
