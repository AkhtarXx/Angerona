from __future__ import annotations

import argparse
import fcntl
import json
import signal
import threading
from pathlib import Path

from src.analysis.class_consolidation import build_class_consolidation
from src.analysis.semantic_ai_controller import run_semantic_ai_queue


def main() -> int:
    parser = argparse.ArgumentParser(description="Build and run fail-closed whole-class consolidation")
    parser.add_argument("--class-queue", required=True)
    parser.add_argument("--primary-ai-output", required=True)
    parser.add_argument("--evidence-work-queue", required=True)
    parser.add_argument("--evidence-ai-output", required=True)
    parser.add_argument("--evidence-resolution", required=True)
    parser.add_argument("--consolidation-ai-output", required=True)
    parser.add_argument("--dex-method-queue", required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--audit-epoch", required=True)
    parser.add_argument("--parent-checkpoint-set", action="append", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--poll-seconds", type=int, default=900)
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    lock = (output / ".class-consolidation-pipeline.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("class consolidation pipeline is already running") from exc
    stopping = threading.Event()
    signal.signal(signal.SIGINT, lambda _s, _f: stopping.set())
    signal.signal(signal.SIGTERM, lambda _s, _f: stopping.set())
    cycle = 0
    while not stopping.is_set():
        cycle += 1
        manifest = build_class_consolidation(
            args.class_queue, args.primary_ai_output, args.evidence_work_queue,
            args.evidence_ai_output, args.evidence_resolution,
            args.consolidation_ai_output, args.dex_method_queue, args.apk,
            args.output_dir,
            audit_epoch=args.audit_epoch,
            parent_checkpoint_sets=args.parent_checkpoint_set,
        )
        semantic = None
        if manifest["work_units"]:
            semantic = run_semantic_ai_queue(
                output / "CLASS_CONSOLIDATION_WORK_UNITS.jsonl",
                args.consolidation_ai_output,
                workers=args.workers,
                max_attempts=3,
                timeout=1800,
                max_tokens=12000,
                max_token_ceiling=32000,
                endpoint_wait_timeout=0,
                stop_event=stopping,
                audit_epoch=args.audit_epoch,
            )
        print(json.dumps({
            "event": "class-consolidation-cycle",
            "cycle": cycle,
            "classes_seen": manifest["classes_seen"],
            "class_state_counts": manifest["class_state_counts"],
            "work_units": manifest["work_units"],
            "receipts": len(manifest["receipts"]),
            "coverage_terminal": manifest["coverage_terminal"],
            "semantic_complete": manifest["semantic_complete"],
            "manifest_sha256": manifest["manifest_sha256"],
            "semantic": semantic,
        }, sort_keys=True), flush=True)
        stopping.wait(max(30, args.poll_seconds))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
