from __future__ import annotations

import argparse
import json

from src.analysis.native_evidence_resolver import resolve_native_evidence_requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-queue", required=True)
    parser.add_argument("--native-input-dir", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    parser.add_argument("--max-evidence-bytes", type=int, default=262144)
    args = parser.parse_args()
    result = resolve_native_evidence_requests(
        args.request_queue, args.native_input_dir, args.output_dir,
        ownership_manifest=args.ownership_manifest,
        native_universe=args.native_universe,
        lane_epoch_id=args.lane_epoch_id,
        max_evidence_bytes=args.max_evidence_bytes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
