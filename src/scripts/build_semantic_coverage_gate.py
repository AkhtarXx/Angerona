"""Build a fail-closed semantic reconstruction coverage receipt."""

from __future__ import annotations

import argparse
import json

from ..analysis.semantic_coverage_gate import build_semantic_coverage_gate


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--queue", required=True)
    parser.add_argument("--ai-output-dir", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--expected-model-alias")
    args = parser.parse_args()
    gate = build_semantic_coverage_gate(
        args.queue,
        args.ai_output_dir,
        output_path=args.output,
        expected_model_alias=args.expected_model_alias,
    )
    print(json.dumps({
        "event": "semantic-coverage-gate",
        "coverage_complete": gate["coverage_complete"],
        "units_expected": gate["units_expected"],
        "status_counts": gate["status_counts"],
        "issues": len(gate["issues"]),
        "manifest_sha256": gate["manifest_sha256"],
    }, sort_keys=True), flush=True)
    return 0 if gate["coverage_complete"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
