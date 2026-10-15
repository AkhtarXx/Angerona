from __future__ import annotations

import argparse
import json

from src.analysis.clean_audit_routing import seal_ownership_policy


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal a fail-closed audit ownership policy")
    parser.add_argument("--spec", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = seal_ownership_policy(args.spec, args.output)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
