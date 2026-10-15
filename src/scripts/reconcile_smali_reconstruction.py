"""Reconcile real apktool smali against sealed DEX method receipts."""

from __future__ import annotations

import argparse
import json

from ..analysis.smali_reconstruction import reconcile_smali_tree


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smali-root", required=True)
    parser.add_argument("--dex-receipt-root", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = reconcile_smali_tree(args.smali_root, args.dex_receipt_root, args.output_dir)
    print(json.dumps({
        key: result[key] for key in (
            "smali_files", "smali_methods", "defined_methods_expected",
            "code_methods_expected", "methods_matched", "code_methods_matched",
            "exact_defined_method_reconciliation", "bytecode_fallback_complete",
            "high_level_semantic_complete", "manifest_sha256",
        )
    }, sort_keys=True))
    return 0 if result["bytecode_fallback_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
