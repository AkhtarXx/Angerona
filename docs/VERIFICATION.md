# Verification record

These results describe the source snapshot exercised on **2026-10-15**. They are
inclusive of source-export privacy checks; earlier target checks retain their
recorded scope. The portable
[result record](verification-results.json) includes counts, all skip reasons and
SHA-256 hashes identifying the original local evidence files. Raw logs and
workspaces are intentionally excluded from the review archive.

## Recorded execution

| Check | Result and scope |
| --- | --- |
| Fresh public clone after publication fixes | **1,851 passed, 0 failed, 38 skipped**, 1,889 cases; 211.80 seconds; source `1b645fc` |
| Latest public CLI real targets | **23/23 passed**: system ELF/source fixtures, Ghidra, full-re/resume, CFG/stack frames, sandboxed static analysis, MCP, HTTP and Docker; source `1b645fc` |
| Public hosted CI | Python 3.11 compatibility, Python 3.12 full integrations, frontend and wheel/package jobs [all passed](https://github.com/AkhtarXx/Angerona/actions/runs/38766903639) |
| Provisioned backend | **1,848 passed, 0 failed, 38 skipped**, 1,886 cases; 207.49 seconds |
| Real edge cases | **40 passed**: compiled behavior, GDB, Docker, ZIP failure boundaries |
| Runtime/edge subset | **116 passed, 2 skipped**; includes fast-exit count/byte regressions |
| Real recovered function | Ghidra `add` output compared with known source on **267 input pairs**; **11 GDB calls** into original machine code agree |
| Fresh installed wheel | Outside checkout: **8/8 deterministic stages**; stderr divergence, arbitrary output bytes and empty-input handling verified |
| Earlier real-target driver | **26/26 checks**, including ELF/PE extraction, deterministic analysis/resume, HTTP/MCP and an explicitly partial APK result |
| Earlier Windows IDA extraction | Source-built C fixture: 22 functions; expected `strcpy` reference observed |
| Public website after dependency refresh | Lint/build and **22 desktop/mobile browser tests passed**; npm audit reports zero known vulnerabilities |

The edge expansion found and fixed matching-crash false positives, ignored stderr,
empty-input verification, non-UTF-8 diagnostic failures and an event-limit race
when a provider exited before its stdout reader drained. Earlier failure logs are
retained locally; they were not rewritten to look successful.

## Environment and reproduction

Qualified backend: Ubuntu 24.04 under WSL2, Python 3.12.3, GCC 13.3, Clang/LLD 18,
JDK 21, Ghidra 12.1.3, bubblewrap, GDB, QEMU 8.2.2 and angr/claripy 9.3.4.
Windows extraction: licensed IDA Pro 9.1 with Python 3.11.9. Frontend: Node 24.19.
The Linux runner used root; unprivileged/platform coverage is still separate work.

```bash
python -m pip install -e '.[dev,emulation,symbols,lifting,symbolic]'
export GHIDRA_INSTALL_DIR=/absolute/path/to/ghidra
export JAVA_HOME=/absolute/path/to/jdk-21
gcc -O0 -g -fno-builtin -fno-stack-protector -no-pie samples/crackme.c -o samples/crackme

python -m pytest tests -n 4 --dist=loadfile --timeout=180 \
  --timeout-method=signal --disable-warnings --tb=short -ra \
  --junitxml=backend-results.xml

python scripts/verify_end_to_end.py --output /tmp/angerona-verification
```

The end-to-end driver uses local system executables and compiles a source fixture;
it downloads nothing and makes no model calls. Its APK/PE/Docker checks require
explicit flags and externally supplied targets. Use a fresh output directory.
For real Docker edge tests, set `ANGERONA_RUN_DOCKER_E2E=1` after provisioning the
daemon and `gra-detonate:latest` image. The image recipe is
`src/analysis/resources/detonate.Dockerfile`; the qualification host used a locally
recorded offline package build because Docker package-server access failed.
Use a virtual environment created inside the checkout for sandbox tests. An
interpreter in an unrelated home directory is intentionally hidden by the sandbox.

The review preparation also verified 20 privacy/export cases. The first clean
checkout attempt exposed missing fixture/interpreter setup prerequisites; these
are now explicit in setup instructions and CI configuration. Host-specific raw
logs remain local. Remote CI has not been executed.

## What remains unqualified

- Universal recovered-code equivalence, coverage-guided fuzzing and long soak runs.
- Live model-provider quality and full AI investigation on real targets.
- Real Android device/emulator execution and complete APK security coverage.
- Deployed Solana program execution and broad unprivileged/platform parity.
- Strict cross-engine parity: function totals and stripped vtable offsets differ.

Behavioral comparison needs runnable C drivers and a reference. It compares exit
status and exact stdout/stderr bytes for supplied inputs, not all memory, file or
concurrency effects. Bubblewrap signal-like exit statuses are conservatively
rejected when ambiguous with intentional program exits. Docker trace logs use
UTF-8 replacement decoding; timeout 124 records a timed-out sample, not normal
completion. Static candidates and symbolic reachability are not certified exploits.

The public APK audit was partial with exit `3`; no APK vulnerabilities are
certified. Missing optional tools are recorded as skips, not passes. See the
portable record for the exact reasons.
