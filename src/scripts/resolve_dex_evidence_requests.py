"""Resolve current DEX AI evidence requests from sealed artifacts."""

from __future__ import annotations

import argparse
import json

from ..analysis.dex_evidence_resolver import resolve_dex_evidence_requests


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--primary-queue", required=True)
    parser.add_argument("--primary-ai-output", required=True)
    parser.add_argument("--evidence-ai-output", required=True)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--max-evidence-bytes", type=int, default=262144)
    args = parser.parse_args()
    result = resolve_dex_evidence_requests(
        args.primary_queue,
        args.primary_ai_output,
        args.evidence_ai_output,
        args.output_dir,
        max_evidence_bytes=args.max_evidence_bytes,
    )
    print(json.dumps({"event": "dex-evidence-resolution", **{
        key: result[key] for key in (
            "primary_units", "latest_methods", "requests", "resolved_requests",
            "pending_requests", "evidence_work_units", "new_or_updated_subjects",
            "manifest_sha256",
        )
    }}, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
