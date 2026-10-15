# Engineering review guide

Angerona is a research-beta local binary-analysis application. The current runtime
is a modular monolith. This guide describes how to review the delivered source;
planned features and implemented code should not be treated as equivalent.

## Suggested reading order

1. Read [README](README.md) for purpose, setup and the deterministic workflow.
2. Read [verification](docs/VERIFICATION.md) for recorded results and unresolved limits.
   Review [publication readiness](docs/PUBLICATION.md) before making a private repository public.
3. Read [architecture](docs/codebase/ARCHITECTURE.md) for data flow and trust boundaries.
4. Inspect `src/orchestration/batch_spine.py`, `src/models/analysis_graph.py` and
   `src/workspace.py` for deterministic execution, graph state and persisted artifacts.
5. Inspect `src/analysis/bequiv.py`, `src/analysis/verify.py`,
   `src/analysis/detonate.py` and `src/execution/runners/native_runner.py` for
   verification semantics, isolation and failure handling.
6. Inspect `src/agents/runtime.py`, `src/agents/loop.py`,
   `src/agents/run_contract.py` and `src/observability.py` for optional provider
   supervision, candidate admission, resume authority and audit records.
7. Inspect `src/web/server.py` and `src/mcp/` for external interfaces.

The [feature map](docs/codebase/FEATURES.md) and
[interface reference](docs/codebase/INTERFACES.md) provide deeper navigation.
Module presence means implementation exists; it does not imply that every
integration has been tested on real targets.

## Reproduce a small working path

On a Linux host with Python, GCC, JDK 21 and Ghidra configured:

```bash
python -m pip install -e '.[dev]'
gcc -O0 -g -fno-builtin -fno-stack-protector -no-pie samples/crackme.c -o /tmp/angerona-crackme
angerona full-re /tmp/angerona-crackme --engine ghidra --no-ai --json
python -m pytest tests/test_real_behavior_edges.py tests/test_archive_edge_inputs.py
```

The C fixture deliberately contains unsafe `strcpy` to support known-source
analysis. Do not feed it oversized input. Behavioral and native-call tests
require bubblewrap and GDB; Docker cases require explicit opt-in. Missing tools
can cause skips; inspect the summary rather than treating skips as passes.

## Review priorities

- Can a failed stage, missing dependency or incomplete audit become a success?
- Are cached and resumed artifacts bound to the target and current policy?
- Can untrusted engine/model output influence paths, commands or evidence authority?
- Do subprocess limits and cleanup hold across crashes, hangs and rapid exits?
- Are platform/ABI assumptions and unsupported execution paths explicit?
- Are reports clear about observed behavior versus inferred security findings?

The web control panel has no application authentication and defaults to loopback.
Dynamic execution is explicit; target binaries and model output remain untrusted.
Strict cross-engine parity, live provider quality and Android device workflows
remain review areas, not completed qualification claims.

## Contents of this Git repository

Git tracks application source, normal pytest tests, source fixtures, build
configuration, reviewer docs and the public website assets with their font license.
Use `git ls-files` to inspect the exact tracked set and `git log --all` for history.

Local workspaces, raw audit/provider logs, proprietary tools, generated
executables, dependency folders, host-specific acceptance scripts, internal notes
and historical research material are ignored. Portable verification records retain
counts and evidence hashes without publishing raw private execution state.

The repository was initialized from the reviewed working directory. The personal-account remote was later located, audited and privacy-filtered;
see [history cleanup](docs/HISTORY_CLEANUP.md). Before sharing changes, run the index and history
checks in [the Git sharing policy](docs/SHARING.md). No remote publication is
performed by these checks.
