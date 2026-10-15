from __future__ import annotations

import argparse
import json

from src.analysis.jadx_class_queue import verify_jadx_class_queue


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify sealed lossless JADX class reconstruction work units")
    parser.add_argument("output_dir")
    args = parser.parse_args()
    result = verify_jadx_class_queue(args.output_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
