from __future__ import annotations

import argparse
import json

from src.analysis.class_consolidation import verify_class_consolidation


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("output_dir")
    args = parser.parse_args()
    result = verify_class_consolidation(args.output_dir)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["valid"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
