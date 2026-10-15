"""Build per-method receipts for every packaged DEX."""

from __future__ import annotations

import argparse
import json

from ..analysis.dex_reconstruction_receipt import build_apk_dex_receipts


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = build_apk_dex_receipts(args.apk, args.output_dir)
    print(json.dumps({
        key: result[key] for key in (
            "apk_sha256", "dex_target_count", "method_ids", "defined_methods",
            "code_methods", "pending_work_units", "exhaustive_method_accounting",
            "semantic_complete", "manifest_sha256",
        )
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
