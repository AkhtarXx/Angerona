#!/usr/bin/env python3
"""Batch-corpus audit driver — runs `run_android_audit` over a directory of APKs.

Usage:
    python3 scripts/android_corpus_audit.py --dir /path/to/apks \
        --out /path/to/report.jsonl [--timeout-per-step 120] [--rules]

Outputs one JSON line per APK with verdict-tier summary; aggregates attack-chain
hits at the end for false-positive triage.

This exists because the 20-year professional demanded chain-scorer ground-truth
corpus testing: "run 50 real fintech apps, measure false-positive attack-chain rate."
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.pipeline.android_audit import run_android_audit  # noqa: E402


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="directory of APKs")
    ap.add_argument("--out", required=True, help="output JSONL path")
    ap.add_argument("--timeout-per-step", type=int, default=60)
    ap.add_argument("--no-rules", action="store_true")
    ap.add_argument(
        "--runtime",
        action="store_true",
        help="opt in to ADB/Frida runtime extraction; static APK audit is the default",
    )
    ap.add_argument("--no-runtime-extract", action="store_true", help=argparse.SUPPRESS)
    args = ap.parse_args()

    src_dir = Path(args.dir)
    if not src_dir.is_dir():
        print(f"not a directory: {src_dir}", file=sys.stderr)
        return 1

    out_path = Path(args.out)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    apks = sorted(src_dir.glob("*.apk")) + sorted(src_dir.glob("**/*.apk"))
    # de-dup preserving order
    seen = set()
    apks = [p for p in apks if not (str(p) in seen or seen.add(str(p)))]

    if not apks:
        print(f"no .apk files under {src_dir}", file=sys.stderr)
        return 1

    stats: Counter = Counter()
    chains = Counter()
    failed: list[str] = []
    start = time.time()

    with open(out_path, "w") as fh:
        for i, apk in enumerate(apks, 1):
            t0 = time.time()
            try:
                r = run_android_audit(
                    apk,
                    try_runtime_extract=args.runtime and not args.no_runtime_extract,
                    timeout_per_step=args.timeout_per_step,
                    run_rules=not args.no_rules,
                )
                row = {
                    "apk": str(apk),
                    "status": r.status,
                    "provenance_verdict": r.provenance_verdict,
                    "packer_verdict": r.packer_verdict,
                    "tls_stack": r.tls_stack,
                    "duration_s": round(time.time() - t0, 1),
                    "steps_executed": len(r.steps_executed),
                    "steps_skipped": len(r.steps_skipped),
                    "verdicts": dict(Counter(f.verdict for f in r.findings)),
                    "severities": dict(Counter(f.severity for f in r.findings)),
                    "chains": [
                        {
                            "chain_id": f.metadata.get("chain_id"),
                            "severity": f.severity,
                            "verdict": f.verdict,
                            "links": f.metadata.get("links"),
                            "detail": f.detail[:200],
                        }
                        for f in r.findings if f.module == "attack_chain_scorer"
                    ],
                }
                fh.write(json.dumps(row) + "\n")
                fh.flush()
                stats[r.status] += 1
                for f in r.findings:
                    if f.module == "attack_chain_scorer":
                        cid = f.metadata.get("chain_id", "unknown")
                        chains[cid] += 1
                print(f"[{i:3d}/{len(apks)}] {apk.name:55s} "
                      f"{r.status:10s} prov={r.provenance_verdict:10s} "
                      f"dur={row['duration_s']}s")
            except Exception as exc:  # noqa: BLE001
                failed.append(f"{apk}: {exc}")
                stats["error"] += 1
                fh.write(json.dumps({"apk": str(apk), "status": "error",
                                     "error": str(exc)[:200]}) + "\n")
                fh.flush()

    # Aggregation summary
    summary = {
        "total_apks": len(apks),
        "wall_seconds": round(time.time() - start, 1),
        "status_breakdown": dict(stats),
        "attack_chain_hits": dict(chains),
        "failed": failed,
    }
    agg_path = out_path.with_suffix(".summary.json")
    agg_path.write_text(json.dumps(summary, indent=2))
    print(f"\n=== corpus summary: {agg_path} ===")
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
