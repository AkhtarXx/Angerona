from __future__ import annotations

import argparse
import json

from src.analysis.native_semantic_queue import build_native_semantic_queue


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-root", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    parser.add_argument("--max-chunk-bytes", type=int, default=32768)
    args = parser.parse_args()
    result = build_native_semantic_queue(
        args.production_root,
        args.output_dir,
        ownership_manifest=args.ownership_manifest,
        native_universe=args.native_universe,
        lane_epoch_id=args.lane_epoch_id,
        max_chunk_bytes=args.max_chunk_bytes,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["rejected"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
