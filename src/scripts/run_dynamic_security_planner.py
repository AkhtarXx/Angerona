from __future__ import annotations

import argparse
import json

from src.analysis.dynamic_security_planner import (
    build_dynamic_followup_plan, build_dynamic_security_plan,
    verify_dynamic_security_queue,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build or verify graph-derived security work without static specialist categories",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    plan = sub.add_parser("plan")
    plan.add_argument("--clean-plan", required=True)
    plan.add_argument("--audit-epoch", required=True)
    plan.add_argument("--cross-layer-receipt", required=True)
    plan.add_argument("--occurrence-index", action="append", default=[])
    plan.add_argument("--knowledge-pack", required=True)
    plan.add_argument("--output-dir", required=True)
    plan.add_argument("--max-nodes-per-unit", type=int, default=64)
    plan.add_argument("--max-edges-per-unit", type=int, default=128)
    plan.add_argument("--max-anchors-per-unit", type=int, default=256)

    followup = sub.add_parser("followup")
    followup.add_argument("--base-queue", required=True)
    followup.add_argument("--checkpoint-set", required=True)
    followup.add_argument("--audit-epoch", required=True)
    followup.add_argument("--output-dir", required=True)
    followup.add_argument("--max-depth", type=int, default=3)

    verify = sub.add_parser("verify")
    verify.add_argument("--queue", required=True)
    verify.add_argument("--audit-epoch", required=True)
    args = parser.parse_args()
    if args.command == "plan":
        result = build_dynamic_security_plan(
            plan_path=args.clean_plan, audit_epoch=args.audit_epoch,
            cross_layer_receipt=args.cross_layer_receipt,
            occurrence_indexes=args.occurrence_index, output_dir=args.output_dir,
            knowledge_pack=args.knowledge_pack,
            max_nodes_per_unit=args.max_nodes_per_unit,
            max_edges_per_unit=args.max_edges_per_unit,
            max_anchors_per_unit=args.max_anchors_per_unit,
        )
    elif args.command == "followup":
        result = build_dynamic_followup_plan(
            base_queue=args.base_queue, parent_checkpoint_set=args.checkpoint_set,
            audit_epoch=args.audit_epoch, output_dir=args.output_dir,
            max_depth=args.max_depth,
        )
    else:
        result = {"queue_sha256": verify_dynamic_security_queue(args.queue, args.audit_epoch)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
