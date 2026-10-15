"""Run the durable DeepSeek semantic reconstruction queue."""

from __future__ import annotations

import argparse
import json
import signal
import threading

from ..analysis.semantic_ai_controller import run_semantic_ai_queue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--endpoint", default="http://127.0.0.1:3457/v1/messages")
    parser.add_argument("--model", default="claude-deepseek-v4-pro")
    parser.add_argument("--audit-epoch")
    parser.add_argument("--native-ownership-manifest")
    parser.add_argument("--native-universe")
    parser.add_argument("--native-lane-epoch-id")
    parser.add_argument("--native-queue-manifest")
    parser.add_argument("--workers", type=int, default=3)
    parser.add_argument("--max-units", type=int, default=0)
    parser.add_argument("--unit-id")
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=1800)
    parser.add_argument("--max-tokens", type=int, default=5000)
    parser.add_argument("--max-token-ceiling", type=int, default=32000)
    parser.add_argument(
        "--endpoint-wait-timeout",
        type=int,
        default=0,
        help="seconds to wait for the model endpoint; 0 waits indefinitely without consuming a unit attempt",
    )
    parser.add_argument(
        "--poll-seconds",
        type=int,
        default=0,
        help="rerun the durable queue at this interval; 0 performs one cycle",
    )
    args = parser.parse_args()

    stopping = threading.Event()

    def stop(_signum, _frame) -> None:
        stopping.set()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    cycle = 0
    while not stopping.is_set():
        cycle += 1
        result = run_semantic_ai_queue(
            args.queue, args.output_dir,
            endpoint=args.endpoint, model=args.model, workers=args.workers,
            max_units=args.max_units, unit_id=args.unit_id,
            max_attempts=args.max_attempts, timeout=args.timeout,
            max_tokens=args.max_tokens,
            max_token_ceiling=args.max_token_ceiling,
            endpoint_wait_timeout=args.endpoint_wait_timeout,
            stop_event=stopping,
            audit_epoch=args.audit_epoch,
            native_ownership_manifest=args.native_ownership_manifest,
            native_universe=args.native_universe,
            native_lane_epoch_id=args.native_lane_epoch_id,
            native_queue_manifest=args.native_queue_manifest,
        )
        print(json.dumps({
            "event": "semantic-controller-cycle",
            "cycle": cycle,
            **result,
        }, sort_keys=True), flush=True)
        if args.poll_seconds <= 0:
            break
        stopping.wait(max(30, args.poll_seconds))
    print(json.dumps({
        "event": "semantic-controller-terminal",
        "cycles": cycle,
        "stopped": stopping.is_set(),
    }, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
