from __future__ import annotations

import argparse
import json

from src.analysis.security_adjudication import build_security_candidate_ledger


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ai-output-dir", action="append", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--class-consolidation-dir")
    parser.add_argument("--audit-epoch", required=True)
    parser.add_argument("--checkpoint-set", action="append", required=True,
                        help="JSON checkpoint-set input descriptor")
    parser.add_argument("--clean-plan", required=True)
    parser.add_argument("--clean-cross-merge-receipt", required=True)
    parser.add_argument("--clean-native-acceptance-receipt", required=True)
    args = parser.parse_args()
    checkpoint_sets = [json.loads(value) for value in args.checkpoint_set]
    result = build_security_candidate_ledger(
        args.ai_output_dir, args.output_dir, args.class_consolidation_dir,
        audit_epoch=args.audit_epoch, checkpoint_sets=checkpoint_sets,
        clean_plan=args.clean_plan,
        clean_cross_merge_receipt=args.clean_cross_merge_receipt,
        clean_native_acceptance_receipt=args.clean_native_acceptance_receipt,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if not result["checkpoint_issues"] and not result["validation_issues"] and not result["class_consolidation_issues"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
