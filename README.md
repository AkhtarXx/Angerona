# Angerona

Angerona is a local reverse-engineering and binary-analysis workspace. It turns
IDA Pro or Ghidra output into a shared analysis graph, runs deterministic analysis
passes, and saves reports and checkpoints for inspection. A Python CLI, MCP
interfaces, and a local web control panel expose the same core functionality.

**Version 0.1.0 — research beta.** The deterministic pipeline has been tested on
real executables. Optional AI investigation and device workflows have separate
requirements and are not all qualified.

## Start here

- [Review guide](REVIEW_GUIDE.md): suggested reading order and important boundaries.
- [Architecture](docs/codebase/ARCHITECTURE.md): components, data flow and trust model.
- [Verification](docs/VERIFICATION.md): actual results, environment and limitations.
- [Sharing guide](docs/SHARING.md): produce a source-only archive without local data.
- [Contributing](CONTRIBUTING.md): setup and development checks.

## What the system does

The deterministic `full-re --no-ai` workflow runs eight stages:

```text
Executable -> triage -> IDA/Ghidra extraction -> analysis graph
           -> signatures -> types -> cross-references -> sinks -> C++ recovery
           -> saved report, evidence artifacts and checkpoint
```

Analysis results are evidence to inspect, not automatically confirmed
vulnerabilities. Optional execution and behavioral checks can corroborate bounded
claims. AI orchestration is available separately and requires a configured
provider; the deterministic workflow makes no model calls.

| Directory | Responsibility |
| --- | --- |
| `src/orchestration/` | Deterministic stage execution and run reports |
| `src/engines/` | Analysis engine integrations |
| `src/models/`, `src/workspace.py` | Shared graph and persisted run state |
| `src/analysis/`, `src/execution/` | Analysis passes, verification and runtime adapters |
| `src/agents/` | Optional provider processes, investigation and evidence gates |
| `src/web/`, `src/mcp/` | Local control panel and MCP interfaces |
| `tests/`, `samples/`, `benchmarks/` | Regression tests and reproducible source fixtures |
| `frontend/` | Public informational website; separate from the local control panel |

## Install

Python **3.11+** is required. Linux provides the sandbox/runtime environment used
for qualification. Windows IDA extraction was tested separately.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
angerona --help
```

Install Ghidra and JDK 21 separately, then point the CLI to them:

```bash
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
export JAVA_HOME=/absolute/path/to/jdk-21
angerona full-re /path/to/binary --engine ghidra --no-ai --json
```

IDA needs a licensed installation and compatible idalib/`idapro` tooling. Engines,
licenses, target binaries and credentials are not bundled. The full optional
integration set below requires Python 3.12 or newer because pypcode 4 does.
Python 3.11 supports the base install and the emulation/symbols integrations.

```bash
python -m pip install -e '.[emulation,symbols,lifting,signing,symbolic]'
```

GCC, bubblewrap, GDB, Docker, QEMU, JADX and Android tools are separate requirements
for the features that use them. The symbolic adapter currently requires angr
below version 10. See [interfaces](docs/codebase/INTERFACES.md) for configuration.

## Common workflows

```bash
# Identify a target and inspect decompiled code.
angerona analyze-any /path/to/binary --json
angerona decompile /path/to/binary main --engine ghidra --json

# Run the deterministic pipeline or resume its saved workspace.
angerona full-re /path/to/binary --engine ghidra --no-ai --json
angerona full-re /path/to/binary --engine ghidra --no-ai \
  --resume-workspace /path/to/workspace --json

# Start local interfaces.
python -m src.web.server --host 127.0.0.1 --port 8765
python -m src.mcp.server
```

Inspect the JSON report's stage status and artifact paths. A successful run means
its requested stages completed; it does not mean every recovered function is
correct. Android audit exit `3` explicitly denotes incomplete coverage.

The local web server has no application authentication. Keep it bound to
loopback. Use only targets you own or are authorized to analyze; runtime execution
belongs in an appropriately contained lab.

## Tested behavior and limits

The 2026-10-15 source-review qualification recorded **1,848 passed, zero failed,
38 skipped**. Forty new real behavior/archive edge cases ran, including Docker
timeout cleanup. Actual Ghidra-recovered `add` code matched known source on
**267 input pairs**, with **11 original machine-code calls** checked through GDB.
A fresh installed wheel completed **8/8 deterministic stages** outside the checkout.
After compatible dependency updates, the public website passed lint/build and
**22 browser tests**; npm audit reported zero known vulnerabilities.

These are recorded source-snapshot results, not a guarantee for every machine or
future edit. Strict cross-engine function/vtable parity still fails. The public
APK audit is partial. Live AI/provider execution, Android device/emulator runs and
deployed Solana targets remain unqualified. Behavioral comparison needs a runnable
C driver and reference and checks supplied inputs, not universal program equivalence.

See [verification details](docs/VERIFICATION.md) for reproduction commands and
scope. No production-readiness or complete vulnerability-coverage claim is made.

## Git hygiene and review

The repository tracks application source, tests, source fixtures and reviewer
documentation. Local credentials, workspaces, raw logs, target binaries and
internal notes remain ignored. Public author/license attribution is preserved.

```bash
git status --short
python scripts/check_git_hygiene.py --staged
python scripts/check_git_hygiene.py --history
```

The checker scans actual Git blobs, rejects tracked private/ignored paths, and
prints finding locations without credential values. Install the pre-commit guard
with `bash scripts/install-git-hooks.sh`. Exact hash-bound exceptions document
synthetic scanner test fixtures. Pattern checks cannot recognize every secret
format; review changes before publishing. See [Git sharing policy](docs/SHARING.md).

Project license: [MIT](LICENSE). Bundled website fonts retain their
[SIL Open Font License](frontend/public/fonts/OFL.txt).
