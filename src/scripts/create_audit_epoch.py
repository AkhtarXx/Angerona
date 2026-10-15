from __future__ import annotations

import argparse
import json

from src.analysis.audit_lineage import create_audit_epoch


def main() -> int:
    parser = argparse.ArgumentParser(description="Create one immutable production audit epoch")
    parser.add_argument("--output", required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--inventory-manifest", required=True)
    parser.add_argument("--class-queue", required=True)
    parser.add_argument("--dex-method-queue", required=True)
    parser.add_argument("--native-queue", action="append", default=[])
    parser.add_argument("--operator-verify-key", required=True)
    parser.add_argument("--max-derived-depth", type=int, default=3)
    parser.add_argument("--epoch-output-root", required=True)
    parser.add_argument("--trusted-read-root", action="append", required=True)
    parser.add_argument("--model-alias", default="claude-deepseek-v4-pro")
    parser.add_argument("--resolved-model", action="append", required=True)
    parser.add_argument("--dex-code-method-accounting")
    args = parser.parse_args()
    epoch = create_audit_epoch(
        args.output,
        apk=args.apk,
        inventory_manifest=args.inventory_manifest,
        class_queue=args.class_queue,
        dex_method_queue=args.dex_method_queue,
        epoch_output_root=args.epoch_output_root,
        trusted_read_roots=args.trusted_read_root,
        model_alias=args.model_alias,
        allowed_resolved_models=args.resolved_model,
        dex_code_method_accounting=args.dex_code_method_accounting,
        native_queues=args.native_queue,
        operator_verify_key=args.operator_verify_key,
        max_derived_depth=args.max_derived_depth,
    )
    print(json.dumps(epoch, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
