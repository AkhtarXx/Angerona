"""Continuously resolve and reanalyze DEX semantic evidence requests."""

from __future__ import annotations

import argparse
import fcntl
import json
from pathlib import Path
import signal
import threading

from ..analysis.dex_evidence_resolver import resolve_dex_evidence_requests
from ..analysis.semantic_ai_controller import run_semantic_ai_queue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary-queue", required=True)
    parser.add_argument("--primary-ai-output", required=True)
    parser.add_argument("--evidence-ai-output", required=True)
    parser.add_argument("--resolution-output-dir", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-evidence-bytes", type=int, default=262144)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--max-tokens", type=int, default=12000)
    parser.add_argument("--poll-seconds", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    resolution = Path(args.resolution_output_dir).resolve()
    ai_output = Path(args.evidence_ai_output).resolve()
    resolution.mkdir(parents=True, exist_ok=True)
    ai_output.mkdir(parents=True, exist_ok=True)
    lock = (resolution / ".pipeline.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("DEX evidence pipeline is already running") from exc

    stopping = threading.Event()

    def stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    cycle = 0
    while not stopping.is_set():
        cycle += 1
        manifest = resolve_dex_evidence_requests(
            args.primary_queue,
            args.primary_ai_output,
            args.evidence_ai_output,
            resolution,
            max_evidence_bytes=args.max_evidence_bytes,
        )
        print(json.dumps({
            "event": "dex-evidence-resolution-cycle",
            "cycle": cycle,
            "requests": manifest["requests"],
            "resolved_requests": manifest["resolved_requests"],
            "pending_requests": manifest["pending_requests"],
            "evidence_work_units": manifest["evidence_work_units"],
            "manifest_sha256": manifest["manifest_sha256"],
        }, sort_keys=True), flush=True)
        if manifest["evidence_work_units"]:
            summary = run_semantic_ai_queue(
                resolution / "DEX_EVIDENCE_WORK_UNITS.jsonl",
                ai_output,
                workers=args.workers,
                max_attempts=args.max_attempts,
                timeout=args.timeout,
                max_tokens=args.max_tokens,
                stop_event=stopping,
            )
            print(json.dumps({
                "event": "dex-evidence-ai-cycle",
                "cycle": cycle,
                "scheduled": summary["scheduled"],
                "state_counts": summary["state_counts"],
                "cache_hits": summary["cache_hits"],
            }, sort_keys=True), flush=True)
        if args.once:
            return 0
        stopping.wait(max(30, args.poll_seconds))
    print(json.dumps({"event": "dex-evidence-stopped", "cycle": cycle}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
