from __future__ import annotations

import argparse
import json

from src.analysis.audit_lineage import seal_checkpoint_set, verify_checkpoint_set


def main() -> int:
    parser = argparse.ArgumentParser(description="Seal or verify an exact semantic checkpoint set")
    parser.add_argument("--queue", required=True)
    parser.add_argument("--checkpoint-root", required=True)
    parser.add_argument("--audit-epoch", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    if args.verify:
        result = verify_checkpoint_set(args.output, args.queue, args.audit_epoch)
    else:
        result = seal_checkpoint_set(
            args.queue, args.checkpoint_root, args.audit_epoch, args.output,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
