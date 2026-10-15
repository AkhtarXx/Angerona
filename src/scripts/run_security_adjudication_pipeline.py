from __future__ import annotations

import argparse
import fcntl
import json
import signal
import threading
from pathlib import Path

from src.analysis.security_adjudication import build_security_candidate_ledger


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ai-output-dir", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--class-consolidation-dir")
    parser.add_argument("--audit-epoch", required=True)
    parser.add_argument("--checkpoint-set", action="append", required=True,
                        help="JSON checkpoint-set input descriptor")
    parser.add_argument("--clean-plan", required=True)
    parser.add_argument("--clean-cross-merge-receipt", required=True)
    parser.add_argument("--clean-native-acceptance-receipt", required=True)
    parser.add_argument("--poll-seconds", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()
    checkpoint_sets = [json.loads(value) for value in args.checkpoint_set]
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    lock = (output / ".adjudication-pipeline.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("security adjudication pipeline is already running") from exc

    stopping = threading.Event()

    def stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    cycle = 0
    while not stopping.is_set():
        cycle += 1
        ledger = build_security_candidate_ledger(
            args.ai_output_dir, output, args.class_consolidation_dir,
            audit_epoch=args.audit_epoch, checkpoint_sets=checkpoint_sets,
            clean_plan=args.clean_plan,
            clean_cross_merge_receipt=args.clean_cross_merge_receipt,
            clean_native_acceptance_receipt=args.clean_native_acceptance_receipt,
        )
        print(json.dumps({
            "event": "security-adjudication-cycle",
            "cycle": cycle,
            "checkpoint_files": ledger["checkpoint_files"],
            "checkpoints_with_candidates": ledger["checkpoints_with_candidates"],
            "candidate_state_counts": ledger["candidate_state_counts"],
            "proof_work_units": ledger["proof_work_units"],
            "confirmed_findings": ledger["confirmed_findings"],
            "checkpoint_issues": len(ledger["checkpoint_issues"]),
            "validation_issues": len(ledger["validation_issues"]),
            "class_consolidation_issues": len(ledger["class_consolidation_issues"]),
            "class_consolidation_receipts": ledger["class_consolidation_receipts"],
            "current_candidates_validated": ledger["current_candidates_validated"],
            "ledger_sha256": ledger["ledger_sha256"],
        }, sort_keys=True), flush=True)
        if ledger["checkpoint_issues"] or ledger["validation_issues"] or ledger["class_consolidation_issues"]:
            return 2
        if args.once:
            return 0
        stopping.wait(max(30, args.poll_seconds))
    print(json.dumps({"event": "security-adjudication-stopped", "cycle": cycle}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
