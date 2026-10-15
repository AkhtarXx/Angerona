from __future__ import annotations

import argparse
import json

from src.analysis.clean_audit_orchestrator import lane_status, run_clean_audit_lane
from src.analysis.clean_audit_routing import verify_clean_apk_routing_plan


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify or execute one signed clean-audit lane")
    parser.add_argument("command", choices=("verify", "status", "start"))
    parser.add_argument("--plan", required=True)
    parser.add_argument("--lane")
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--execution-spec")
    args = parser.parse_args()
    if args.command == "verify":
        plan = verify_clean_apk_routing_plan(args.plan)
        result = {"plan_id": plan["plan_id"], "conservation_complete": True}
    elif args.command == "status":
        result = lane_status(args.plan)
    else:
        if not args.lane:
            parser.error("start requires --lane")
        result = run_clean_audit_lane(
            args.plan, args.lane, resume=args.resume, execution_spec=args.execution_spec,
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
