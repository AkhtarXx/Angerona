"""CLI for publishing an engine-neutral reconstruction receipt."""

from __future__ import annotations

import argparse
import json

from ..analysis.reconstruction_receipt import build_reconstruction_receipt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--export-dir", required=True)
    parser.add_argument("--toolchain-json", default="{}")
    args = parser.parse_args()
    toolchain = json.loads(args.toolchain_json)
    receipt = build_reconstruction_receipt(
        args.binary,
        args.analysis,
        args.export_dir,
        toolchain_identity=toolchain,
    )
    print(json.dumps({
        "target_id": receipt["target_id"],
        "functions_discovered": receipt["functions_discovered"],
        "functions_terminal": receipt["functions_terminal"],
        "pending_work_units": receipt["pending_work_units"],
        "exhaustive_accounting": receipt["exhaustive_accounting"],
        "semantic_complete": receipt["semantic_complete"],
        "receipt_sha256": receipt["receipt_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
