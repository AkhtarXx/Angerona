from __future__ import annotations

import argparse
import json

from src.analysis.clean_audit_adapters import (
    ai_review_adapter, app_reconstruction_adapter, application_surface_adapter,
    cross_layer_merge_adapter,
    dynamic_security_plan_adapter,
    deterministic_parse_adapter, dex_index_adapter, hermes_index_adapter,
    native_acceptance_adapter, ownership_filter_adapter, seal_clean_execution_spec,
    surface_semantic_adapter,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one signed clean-audit adapter stage")
    sub = parser.add_subparsers(dest="command", required=True)

    seal = sub.add_parser("seal-execution")
    seal.add_argument("--plan", required=True)
    seal.add_argument("--source-spec", required=True)
    seal.add_argument("--output", required=True)
    seal.add_argument("--audit-epoch")

    for name in ("deterministic-parse", "dex-index"):
        lane = sub.add_parser(name)
        lane.add_argument("--plan", required=True)
        lane.add_argument("--output-dir", required=True)
        lane.add_argument("--completion-receipt", required=True)

    hermes = sub.add_parser("hermes-index")
    hermes.add_argument("--plan", required=True)
    hermes.add_argument("--output-dir", required=True)
    hermes.add_argument("--completion-receipt", required=True)
    hermes.add_argument("--indexer-descriptor", required=True)

    ownership = sub.add_parser("ownership-filter")
    ownership.add_argument("--plan", required=True)
    ownership.add_argument("--extracted-manifest", action="append", required=True)
    ownership.add_argument("--output-dir", required=True)
    ownership.add_argument("--completion-receipt", required=True)
    ownership.add_argument("--component-definition-receipt", required=True)

    surface = sub.add_parser("application-surface")
    surface.add_argument("--plan", required=True)
    surface.add_argument("--extracted-manifest", action="append", required=True)
    surface.add_argument("--output-dir", required=True)
    surface.add_argument("--completion-receipt", required=True)

    surface_ai = sub.add_parser("surface-semantic")
    surface_ai.add_argument("--plan", required=True)
    surface_ai.add_argument("--queue", required=True)
    surface_ai.add_argument("--queue-manifest", required=True)
    surface_ai.add_argument("--checkpoint-root", required=True)
    surface_ai.add_argument("--output-dir", required=True)
    surface_ai.add_argument("--completion-receipt", required=True)
    surface_ai.add_argument("--endpoint", default="http://127.0.0.1:3457/v1/messages")
    surface_ai.add_argument("--model", default="claude-deepseek-v4-pro")
    surface_ai.add_argument("--workers", type=int, default=3)

    reconstruction = sub.add_parser("app-reconstruction")
    reconstruction.add_argument("--plan", required=True)
    reconstruction.add_argument("--app-owned-manifest", required=True)
    reconstruction.add_argument("--output-dir", required=True)
    reconstruction.add_argument("--completion-receipt", required=True)
    reconstruction.add_argument("--context-budget-bytes", type=int, default=65536)
    reconstruction.add_argument("--baksmali-descriptor")
    reconstruction.add_argument("--hermes-decompiler-descriptor")

    ai = sub.add_parser("ai-review")
    ai.add_argument("--plan", required=True)
    ai.add_argument("--queue-triplet", action="append", nargs=3, metavar=("QUEUE", "MANIFEST", "CHECKPOINT_ROOT"), required=True)
    ai.add_argument("--output-dir", required=True)
    ai.add_argument("--completion-receipt", required=True)
    ai.add_argument("--endpoint", default="http://127.0.0.1:3457/v1/messages")
    ai.add_argument("--model", default="claude-deepseek-v4-pro")
    ai.add_argument("--workers", type=int, default=3)

    merge = sub.add_parser("cross-layer-merge")
    merge.add_argument("--plan", required=True)
    merge.add_argument("--ownership-receipt", required=True)
    merge.add_argument("--smali-root", required=True)
    merge.add_argument("--dex-receipt-root", required=True)
    merge.add_argument("--audit-root", required=True)
    merge.add_argument("--output-dir", required=True)
    merge.add_argument("--completion-receipt", required=True)
    merge.add_argument("--application-surface-receipt", required=True)
    merge.add_argument("--surface-semantic-receipt", required=True)
    merge.add_argument("--native-acceptance-receipt")

    native = sub.add_parser("native-acceptance")
    native.add_argument("--plan", required=True)
    native.add_argument("--lane-receipt", action="append", required=True, metavar="ROLE=PATH")
    native.add_argument("--root-conservation-receipt", required=True)
    native.add_argument("--completion-receipt", required=True)

    dynamic = sub.add_parser("dynamic-security-plan")
    dynamic.add_argument("--plan", required=True)
    dynamic.add_argument("--cross-layer-receipt", required=True)
    dynamic.add_argument("--occurrence-index", action="append", default=[])
    dynamic.add_argument("--output-dir", required=True)
    dynamic.add_argument("--completion-receipt", required=True)

    args = parser.parse_args()
    if args.command == "seal-execution":
        result = seal_clean_execution_spec(
            args.plan, args.source_spec, args.output, audit_epoch=args.audit_epoch,
        )
    elif args.command == "deterministic-parse":
        result = deterministic_parse_adapter(args.plan, args.output_dir, args.completion_receipt)
    elif args.command == "dex-index":
        result = dex_index_adapter(args.plan, args.output_dir, args.completion_receipt)
    elif args.command == "hermes-index":
        result = hermes_index_adapter(args.plan, args.output_dir, args.completion_receipt, args.indexer_descriptor)
    elif args.command == "application-surface":
        result = application_surface_adapter(
            args.plan, args.extracted_manifest, args.output_dir, args.completion_receipt,
        )
    elif args.command == "ownership-filter":
        result = ownership_filter_adapter(
            args.plan, args.extracted_manifest, args.output_dir, args.completion_receipt,
            args.component_definition_receipt,
        )
    elif args.command == "surface-semantic":
        result = surface_semantic_adapter(
            args.plan, args.queue, args.queue_manifest, args.checkpoint_root,
            args.output_dir, args.completion_receipt, endpoint=args.endpoint,
            model=args.model, workers=args.workers,
        )
    elif args.command == "app-reconstruction":
        result = app_reconstruction_adapter(
            args.plan, args.app_owned_manifest, args.output_dir, args.completion_receipt,
            context_budget_bytes=args.context_budget_bytes,
            baksmali_descriptor=args.baksmali_descriptor,
            hermes_decompiler_descriptor=args.hermes_decompiler_descriptor,
        )
    elif args.command == "ai-review":
        result = ai_review_adapter(
            args.plan, args.queue_triplet, args.output_dir, args.completion_receipt,
            endpoint=args.endpoint, model=args.model, workers=args.workers,
        )
    elif args.command == "native-acceptance":
        lane_receipts = {}
        for value in args.lane_receipt:
            role, separator, path = value.partition("=")
            if not separator or not role or not path or role in lane_receipts:
                raise ValueError("--lane-receipt must be a unique ROLE=PATH binding")
            lane_receipts[role] = path
        result = native_acceptance_adapter(
            args.plan, lane_receipts, args.root_conservation_receipt, args.completion_receipt,
        )
    elif args.command == "dynamic-security-plan":
        result = dynamic_security_plan_adapter(
            args.plan, args.cross_layer_receipt, args.output_dir,
            args.completion_receipt, occurrence_indexes=args.occurrence_index,
        )
    else:
        result = cross_layer_merge_adapter(
            args.plan, args.ownership_receipt, args.smali_root, args.dex_receipt_root,
            args.audit_root, args.output_dir, args.completion_receipt,
            application_surface_receipt=args.application_surface_receipt,
            surface_semantic_receipt=args.surface_semantic_receipt,
            native_acceptance_receipt=args.native_acceptance_receipt,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
