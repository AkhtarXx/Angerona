from __future__ import annotations

import argparse
import json

from src.analysis.jadx_class_queue import build_jadx_class_queue


def main() -> int:
    parser = argparse.ArgumentParser(description="Build sealed lossless JADX class reconstruction work units")
    parser.add_argument("method_evidence")
    parser.add_argument("output_dir")
    parser.add_argument("--chunk-bytes", type=int, default=32768)
    args = parser.parse_args()
    summary = build_jadx_class_queue(args.method_evidence, args.output_dir, chunk_bytes=args.chunk_bytes)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
