from __future__ import annotations

import argparse
import json

from src.analysis.native_consolidation import build_native_consolidation_queue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--native-queue", required=True)
    parser.add_argument("--fragment-ai-output", required=True)
    parser.add_argument("--consolidation-ai-output", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    parser.add_argument("--max-input-bytes", type=int, default=262144)
    args = parser.parse_args()
    result = build_native_consolidation_queue(
        args.native_queue,
        args.fragment_ai_output,
        args.consolidation_ai_output,
        args.output_dir,
        ownership_manifest=args.ownership_manifest,
        native_universe=args.native_universe,
        lane_epoch_id=args.lane_epoch_id,
        max_input_bytes=args.max_input_bytes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
