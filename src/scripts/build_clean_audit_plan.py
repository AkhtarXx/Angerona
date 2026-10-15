from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.analysis.clean_audit_routing import build_clean_apk_routing_plan


def _descriptor(path: str | None) -> dict[str, str] | None:
    if not path:
        return None
    resolved = Path(path).resolve(strict=True)
    import hashlib
    return {"path": str(resolved), "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()}


def main() -> int:
    parser = argparse.ArgumentParser(description="Build a signed conservative APK routing plan")
    parser.add_argument("--apk", required=True)
    parser.add_argument("--inventory-manifest", required=True)
    parser.add_argument("--ownership-policy", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--trusted-root", action="append", required=True)
    parser.add_argument("--native-routing")
    parser.add_argument("--native-universe")
    parser.add_argument("--execution-spec")
    parser.add_argument("--audit-epoch")
    args = parser.parse_args()
    result = build_clean_apk_routing_plan(
        apk=args.apk, inventory_manifest=args.inventory_manifest,
        ownership_policy=args.ownership_policy, output_dir=args.output_dir,
        trusted_roots=args.trusted_root,
        native_routing=_descriptor(args.native_routing),
        native_universe=_descriptor(args.native_universe),
        execution_spec=_descriptor(args.execution_spec),
        audit_epoch=_descriptor(args.audit_epoch),
    )
    print(json.dumps({
        "plan_id": result["plan_id"], "routing_set_id": result["routing_set_id"],
        "conservation_complete": result["conservation_complete"],
        "descriptor": result["descriptor"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
