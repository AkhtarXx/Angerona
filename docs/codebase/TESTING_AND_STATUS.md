# Testing and current status

The latest engine qualification is documented in [verification](../VERIFICATION.md).
On 2026-10-15, the full provisioned Linux backend run recorded **1,848 passed,
zero failed and 38 skipped** across 1,886 cases. This is an executed snapshot;
collection alone is not a pass. This run includes 20 source-export privacy
cases and three actual Git index/history cases. Windows separately passed 25 privacy/documentation checks, with one
symlink-capability skip.

## Main checks

```bash
python -m pytest tests -n 4 --dist=loadfile --timeout=180 \
  --timeout-method=signal --disable-warnings --tb=short -ra
python scripts/prepare_review.py --check
```

The qualified run enabled `ANGERONA_RUN_DOCKER_E2E=1`. This opt-in requires a
working Docker daemon and `gra-detonate:latest`; without it those tests skip.
Ghidra, GCC, bubblewrap, GDB, Java, optional Python integrations and other
external tools must be provisioned for their respective tests.

| Test area | Entry points |
| --- | --- |
| Real compiled behavior and debugger calls | `tests/test_real_behavior_edges.py` |
| Real archive failure cases | `tests/test_archive_edge_inputs.py` |
| Provider supervision and isolation | `tests/test_runtime_buffering.py` |
| Deterministic pipeline and verification contracts | `tests/test_verification_regressions.py`, `tests/test_a3_a4_b3_b4.py` |
| Full target workflow | `scripts/verify_end_to_end.py` |
| Source-review privacy policy | `tests/test_prepare_review.py` |
| Public website | `frontend/e2e/`; `npm run check`, `npm run test:e2e` |

Forty new real edge cases cover compiler failures, signal exits, hangs, byte
output, stderr mismatch, sandbox restrictions, native calls, Docker cleanup and
ZIP containment/size/depth limits. Two controlled scheduling tests exercise event
boundaries detected after a real provider process exits.

## Interpretation

The recorded deterministic workflow is operational in the qualified environment.
Behavioral checks require runnable C drivers and compare supplied input sets;
they are not a universal correctness proof. Static sink findings and symbolic
reachability are not confirmed exploits. Cross-engine function/vtable parity is
unresolved. APK results can be partial; live providers, real Android device runs
and deployed Solana execution remain unqualified.

Review the portable [result record](../verification-results.json) for all 38
skip reasons. Host-specific `real_*.py` acceptance scripts and private execution
artifacts are intentionally omitted from the shareable archive. Default pytest
collection did not include those scripts.
