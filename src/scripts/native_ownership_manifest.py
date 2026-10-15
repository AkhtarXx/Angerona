"""Build or verify the signed native ownership scheduling manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..analysis.native_ownership_manifest import (
    build_native_ownership_manifest,
    verify_native_ownership_manifest,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build = subparsers.add_parser("build")
    build.add_argument("--universe", required=True)
    build.add_argument("--output", required=True)
    build.add_argument("--pre-re-classification", required=True)
    build.add_argument("--app-provenance")
    build.add_argument("--third-party-reference")
    build.add_argument("--overrides")
    build.add_argument("--reconstruction-root")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--universe", required=True)
    verify.add_argument("--manifest", required=True)
    args = parser.parse_args()
    if args.command == "build":
        document = build_native_ownership_manifest(
            universe_path=Path(args.universe), output_path=Path(args.output),
            pre_re_classification_path=Path(args.pre_re_classification),
            app_provenance_path=Path(args.app_provenance) if args.app_provenance else None,
            third_party_reference_path=Path(args.third_party_reference) if args.third_party_reference else None,
            override_path=Path(args.overrides) if args.overrides else None,
            reconstruction_root=Path(args.reconstruction_root) if args.reconstruction_root else None,
        )
        result = {
            "payload_sha256": document["payload_sha256"],
            "signature_key_id": document["signature_key_id"],
            "target_count": document["target_count"],
            "app_owned_queue_count": document["app_owned_queue_count"],
            "disposition_counts": document["disposition_counts"],
        }
    else:
        result = verify_native_ownership_manifest(
            Path(args.manifest), universe_path=Path(args.universe),
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
