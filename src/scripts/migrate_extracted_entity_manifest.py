from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from src.analysis.clean_audit_routing import verify_clean_apk_routing_plan
from src.analysis.signed_artifact_io import migrate_legacy_extracted_entity_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description="Explicitly migrate and re-sign one legacy extracted manifest")
    parser.add_argument("--plan", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    plan = verify_clean_apk_routing_plan(args.plan)
    source = Path(args.source).expanduser().resolve(strict=True)
    payload = source.read_bytes()
    descriptor = migrate_legacy_extracted_entity_manifest(
        {"path": str(source), "sha256": hashlib.sha256(payload).hexdigest()},
        plan["trusted_roots"], plan, args.output,
    )
    print(json.dumps(descriptor, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
