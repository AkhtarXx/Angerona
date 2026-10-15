"""Build catalogs and classify native binaries before any RE process exists."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from ..analysis.native_pre_re_classifier import (
    build_pre_re_classification, build_reference_catalog,
    verify_pre_re_classification,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    catalog = sub.add_parser("catalog-build")
    catalog.add_argument("--input", action="append", required=True)
    catalog.add_argument("--provenance", required=True)
    catalog.add_argument("--output", required=True)
    classify = sub.add_parser("classify")
    classify.add_argument("--universe", required=True)
    classify.add_argument("--output", required=True)
    classify.add_argument("--cache-root", required=True)
    classify.add_argument("--catalog", action="append", default=[])
    classify.add_argument("--ai-advisory")
    classify.add_argument("--app-namespace", action="append", default=[])
    verify = sub.add_parser("verify")
    verify.add_argument("--universe", required=True)
    verify.add_argument("--manifest", required=True)
    args = parser.parse_args()
    if args.command == "catalog-build":
        document = build_reference_catalog(
            inputs=[Path(value) for value in args.input],
            provenance_path=Path(args.provenance), output_path=Path(args.output),
        )
        result = {
            "payload_sha256": document["payload_sha256"],
            "signature_key_id": document["signature_key_id"],
            "record_count": document["record_count"],
            "records_sha256": document["records_sha256"],
        }
    elif args.command == "classify":
        document = build_pre_re_classification(
            universe_path=Path(args.universe), output_path=Path(args.output),
            cache_root=Path(args.cache_root),
            catalog_paths=[Path(value) for value in args.catalog],
            ai_advisory_path=Path(args.ai_advisory) if args.ai_advisory else None,
            app_namespaces=args.app_namespace,
        )
        result = {
            "payload_sha256": document["payload_sha256"],
            "signature_key_id": document["signature_key_id"],
            "classifier_identity_sha256": document["classifier_identity_sha256"],
            "catalog_identity_sha256": document["catalog_identity_sha256"],
            "target_count": document["target_count"],
            "decision_counts": document["decision_counts"],
        }
    else:
        result = verify_pre_re_classification(
            Path(args.manifest), universe_path=Path(args.universe),
        )
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
