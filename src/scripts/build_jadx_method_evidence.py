"""Bind all DEX code-method units to smali and JADX source evidence."""

from __future__ import annotations

import argparse
import json

from ..analysis.jadx_method_evidence import build_jadx_method_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--jadx-output", required=True)
    parser.add_argument("--dex-receipt-root", required=True)
    parser.add_argument("--smali-reconciliation", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()
    result = build_jadx_method_evidence(
        args.jadx_output, args.dex_receipt_root,
        args.smali_reconciliation, args.output_dir,
    )
    print(json.dumps({
        key: result[key] for key in (
            "dex_method_count", "defined_class_count", "source_artifact_count",
            "bound_source_artifact_count", "classes_with_exact_or_outer_source",
            "code_method_work_units", "all_code_methods_have_smali",
            "all_classes_dispositioned", "semantic_complete", "manifest_sha256",
        )
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
