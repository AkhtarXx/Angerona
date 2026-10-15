from __future__ import annotations

import argparse
import fcntl
import json
import signal
import threading
import time
from pathlib import Path

from src.analysis.native_semantic_queue import build_native_semantic_queue
from src.analysis.native_ownership_manifest import bind_native_output_directory, native_routing_context
from src.analysis.semantic_ai_controller import run_semantic_ai_queue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-root", required=True)
    parser.add_argument("--queue-output-dir", required=True)
    parser.add_argument("--ai-output-dir", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--max-chunk-bytes", type=int, default=32768)
    parser.add_argument("--max-units", type=int, default=0)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--max-tokens", type=int, default=12000)
    parser.add_argument("--poll-seconds", type=int, default=900)
    parser.add_argument("--once", action="store_true")
    args = parser.parse_args()

    queue_output = Path(args.queue_output_dir).expanduser().absolute()
    ai_output = Path(args.ai_output_dir).expanduser().absolute()
    _routing, _selected, _events, routing_binding = native_routing_context(
        args.ownership_manifest, args.native_universe,
    )
    ai_output = bind_native_output_directory(
        ai_output, lane="native-semantic-ai", lane_epoch_id=args.lane_epoch_id,
        routing_binding=routing_binding,
    )
    lock = (ai_output / ".pipeline.lock").open("a+b")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("native semantic pipeline is already running") from exc

    stopping = threading.Event()

    def stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    cycle = 0
    while not stopping.is_set():
        cycle += 1
        manifest = build_native_semantic_queue(
            args.production_root,
            queue_output,
            ownership_manifest=args.ownership_manifest,
            native_universe=args.native_universe,
            lane_epoch_id=args.lane_epoch_id,
            max_chunk_bytes=args.max_chunk_bytes,
        )
        print(json.dumps({
            "event": "native-semantic-queue",
            "cycle": cycle,
            "functions_ready": manifest["functions_ready"],
            "work_units": manifest["work_units"],
            "rejected": len(manifest["rejected"]),
            "manifest_sha256": manifest["manifest_sha256"],
        }, sort_keys=True), flush=True)
        if manifest["rejected"]:
            return 2
        if manifest["hold_targets"]:
            print(json.dumps({
                "event": "native-semantic-routing-hold",
                "targets": manifest["hold_targets"],
            }, sort_keys=True), flush=True)
            return 2
        summary = None
        if manifest["work_units"]:
            summary = run_semantic_ai_queue(
                queue_output / "NATIVE_SEMANTIC_WORK_UNITS.jsonl",
                ai_output,
                workers=args.workers,
                max_units=args.max_units,
                max_attempts=args.max_attempts,
                timeout=args.timeout,
                max_tokens=args.max_tokens,
                stop_event=stopping,
                native_ownership_manifest=args.ownership_manifest,
                native_universe=args.native_universe,
                native_lane_epoch_id=args.lane_epoch_id,
                native_queue_manifest=queue_output / "NATIVE_SEMANTIC_INPUT.json",
            )
            print(json.dumps({
                "event": "native-semantic-cycle",
                "cycle": cycle,
                "scheduled": summary["scheduled"],
                "state_counts": summary["state_counts"],
                "cache_hits": summary["cache_hits"],
            }, sort_keys=True), flush=True)
        if args.once:
            if summary and summary["state_counts"].get("error"):
                return 2
            return 0
        stopping.wait(max(30, args.poll_seconds))
    print(json.dumps({"event": "native-semantic-stopped", "cycle": cycle}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
