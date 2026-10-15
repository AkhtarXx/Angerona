"""Verify every DEX semantic work unit and referenced artifact."""

from __future__ import annotations

import argparse
import json

from ..analysis.semantic_method_evidence_verifier import validate_semantic_method_evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", required=True)
    parser.add_argument("--summary", required=True)
    parser.add_argument("--allowed-root", required=True)
    parser.add_argument("--output")
    args = parser.parse_args()
    result = validate_semantic_method_evidence(
        args.queue,
        args.summary,
        allowed_root=args.allowed_root,
    )
    if args.output:
        with open(args.output, "w", encoding="utf-8") as handle:
            json.dump(result, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print(json.dumps({
        "event": "semantic-method-evidence-validation",
        "valid": result["valid"],
        "units": result["units"],
        "unique_methods": result["unique_methods"],
        "unique_artifacts_rehashed": result["unique_artifacts_rehashed"],
        "issues": len(result["issues"]),
        "queue_sha256": result["queue_sha256"],
    }, sort_keys=True), flush=True)
    return 0 if result["valid"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
