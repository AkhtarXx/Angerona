from __future__ import annotations

import argparse
import json

from src.analysis.dex_inventory_accounting import build_dex_code_method_accounting


def main() -> int:
    parser = argparse.ArgumentParser(description="Build an exhaustive DEX code-method accounting receipt")
    parser.add_argument("--apk", required=True)
    parser.add_argument("--apk-content-manifest", required=True)
    parser.add_argument("--queue", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--validation", required=True)
    parser.add_argument("--dex-root", required=True)
    parser.add_argument("--raw-rebuild-root", required=True)
    parser.add_argument("--allowed-root", action="append", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    receipt = build_dex_code_method_accounting(
        args.apk, args.apk_content_manifest,
        args.queue, args.summary, args.validation, args.dex_root, args.raw_rebuild_root,
        args.allowed_root, args.output,
    )
    print(json.dumps(receipt, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
