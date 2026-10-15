"""Build the signed immutable native ELF target universe."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..analysis.native_target_universe import build_native_target_universe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apk-manifest", required=True)
    parser.add_argument("--apk", required=True)
    parser.add_argument("--targets-root", required=True)
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = build_native_target_universe(
        apk_manifest_path=Path(args.apk_manifest), apk_path=Path(args.apk),
        targets_root=Path(args.targets_root), audit_root=Path(args.audit_root),
        output_path=Path(args.output),
    )
    print(json.dumps({
        "native_entry_count": result["native_entry_count"],
        "target_count": result["target_count"],
        "target_universe_sha256": result["target_universe_sha256"],
        "payload_sha256": result["payload_sha256"],
        "signature_key_id": result["signature_key_id"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
