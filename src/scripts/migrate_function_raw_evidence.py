"""CLI for fail-closed migration of signed snapshot raw function evidence."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..analysis.raw_evidence_migration import migrate_signed_snapshot


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--snapshot", required=True)
    parser.add_argument("--output-root", required=True)
    parser.add_argument("--target-sha256", required=True)
    parser.add_argument("--epoch-id", required=True)
    parser.add_argument("--pinned-key-path", required=True)
    args = parser.parse_args()
    receipt = migrate_signed_snapshot(
        snapshot=Path(args.snapshot),
        output_root=Path(args.output_root),
        target_sha256=args.target_sha256.lower(),
        epoch_id=args.epoch_id,
        pinned_key_path=Path(args.pinned_key_path),
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
