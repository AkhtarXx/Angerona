from __future__ import annotations

import argparse
import fcntl
import json
import signal
import threading
from pathlib import Path
from typing import Any

from src.analysis.audit_lineage import seal_checkpoint_set
from src.analysis.class_evidence_resolver import resolve_class_evidence_requests
from src.analysis.semantic_ai_controller import run_semantic_ai_queue


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve class evidence requests and run real semantic reanalysis")
    parser.add_argument("--class-queue", required=True)
    parser.add_argument("--primary-checkpoint-set", required=True)
    parser.add_argument("--evidence-checkpoint-set", action="append", default=[])
    parser.add_argument("--evidence-ai-output", required=True)
    parser.add_argument("--dex-method-queue", required=True)
    parser.add_argument("--dex-code-method-accounting", required=True)
    parser.add_argument("--audit-epoch", required=True)
    parser.add_argument("--resolution-output", required=True)
    parser.add_argument("--workers", type=int, default=1)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--max-tokens", type=int, default=12000)
    parser.add_argument("--max-token-ceiling", type=int, default=32000)
    parser.add_argument("--max-evidence-depth", type=int, default=3)
    parser.add_argument("--poll-seconds", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    resolution = Path(args.resolution_output).resolve()
    resolution.mkdir(parents=True, exist_ok=True)
    lock = (resolution / ".class-evidence-pipeline.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("class evidence pipeline is already running") from exc
    stopping = threading.Event()

    def stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    cycle = 0
    sealed_sets = [str(Path(value).resolve()) for value in args.evidence_checkpoint_set]
    while not stopping.is_set():
        cycle += 1
        manifest = resolve_class_evidence_requests(
            args.class_queue,
            args.primary_checkpoint_set,
            sealed_sets,
            args.dex_method_queue,
            args.dex_code_method_accounting,
            args.audit_epoch,
            args.resolution_output,
            max_evidence_depth=args.max_evidence_depth,
        )
        summary: dict[str, Any] = {
            "event": "class-evidence-resolution-cycle",
            "cycle": cycle,
            "requests": manifest["requests"],
            "resolved_requests": manifest["resolved_requests"],
            "pending_requests": manifest["pending_requests"],
            "evidence_work_units": manifest["evidence_work_units"],
            "new_or_updated_subjects": manifest["new_or_updated_subjects"],
            "manifest_sha256": manifest["manifest_sha256"],
        }
        generation = manifest.get("generation")
        if generation and manifest["evidence_work_units"]:
            queue_path = Path(generation["queue_path"])
            generation_output = (
                Path(args.evidence_ai_output).resolve() / "generations" / generation["queue_sha256"]
            )
            summary["semantic"] = run_semantic_ai_queue(
                queue_path,
                generation_output,
                workers=args.workers,
                max_attempts=args.max_attempts,
                timeout=args.timeout,
                max_tokens=args.max_tokens,
                max_token_ceiling=args.max_token_ceiling,
                endpoint_wait_timeout=0,
                stop_event=stopping,
                audit_epoch=args.audit_epoch,
            )
            checkpoint_set = generation_output / "SEMANTIC_CHECKPOINT_SET.json"
            try:
                sealed = seal_checkpoint_set(
                    queue_path, generation_output, args.audit_epoch, checkpoint_set,
                )
                summary["sealed_generation"] = {
                    "path": str(checkpoint_set),
                    "manifest_sha256": sealed["manifest_sha256"],
                    "expected_units": sealed["expected_units"],
                }
                if str(checkpoint_set) not in sealed_sets:
                    sealed_sets.append(str(checkpoint_set))
            except ValueError as exc:
                summary["generation_not_sealed"] = str(exc)
        if not generation or not manifest["evidence_work_units"]:
            reasons = {
                str(row.get("reason") or "")
                for row in manifest.get("subjects") or []
            }
            if "evidence-budget-exceeded-partition-required" in reasons:
                summary["state"] = "blocked-evidence-budget"
            elif "maximum-evidence-depth-reached" in reasons:
                summary["state"] = "terminal-max-evidence-depth"
            elif manifest.get("pending_requests"):
                summary["state"] = "inconclusive-unresolved-evidence"
            else:
                summary["state"] = "complete-static-fixpoint"
        print(json.dumps(summary, sort_keys=True), flush=True)
        if "generation_not_sealed" in summary:
            return 2
        if args.once:
            if summary.get("sealed_generation"):
                return 0
            return 0 if summary.get("state") == "complete-static-fixpoint" else 2
        if summary.get("state") == "complete-static-fixpoint":
            return 0
        if summary.get("state") in {
            "blocked-evidence-budget",
            "terminal-max-evidence-depth",
            "inconclusive-unresolved-evidence",
        }:
            return 2
        stopping.wait(max(30, args.poll_seconds))
    print(json.dumps({"event": "class-evidence-pipeline-stopped", "cycle": cycle}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
