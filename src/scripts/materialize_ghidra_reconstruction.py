"""Resumably export full Ghidra evidence for every discovered function."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from ..analysis.native_ownership_manifest import (
    bind_native_output_directory,
    native_routing_context,
    native_routing_targets,
    publish_native_lane_receipt,
)
from ..analysis.reconstruction_receipt import (
    FUNCTION_EXPORT_SCHEMA,
    materialize_ghidra_functions,
)
from ..mcp.server import GhidraEngine


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True)
    parser.add_argument("--analysis", required=True)
    parser.add_argument("--export-dir", required=True)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--entry", action="append", default=[])
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--lane-epoch-id", required=True)
    args = parser.parse_args()
    _routing, selected, policy_events, routing_binding = native_routing_context(
        args.ownership_manifest, args.native_universe,
    )
    app_targets, _excluded, hold_targets = native_routing_targets(selected, policy_events)
    if hold_targets:
        raise SystemExit(f"native ownership HOLD prevents Ghidra launch: {sorted(hold_targets)}")
    binary_path = Path(args.binary).expanduser().absolute()
    if binary_path.is_symlink() or not binary_path.is_file():
        raise SystemExit("Ghidra target must be a non-symlink regular file")
    binary_sha = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    if binary_sha not in app_targets:
        raise SystemExit("Ghidra target is not in exact signed app-owned queue")
    selected_row = next(row for row in selected if row["target_sha256"] == binary_sha)
    analysis_scope = str(selected_row.get("analysis_scope") or "")
    allowed_ranges = selected_row.get("allowed_executable_ranges") or []
    signed_entries = {
        format(int(row["address"]), "x") for row in allowed_ranges
    } if analysis_scope == "selective_ranges" else set()
    requested_entries = {str(value).lower().replace("0x", "") for value in args.entry}
    if analysis_scope == "selective_ranges":
        if requested_entries and not requested_entries.issubset(signed_entries):
            raise SystemExit("requested Ghidra entry is outside signed selective range queue")
        requested_entries = requested_entries or signed_entries
    analysis_path = Path(args.analysis).expanduser().absolute()
    if analysis_path.is_symlink() or not analysis_path.is_file():
        raise SystemExit("Ghidra analysis must be a non-symlink regular file")
    analysis_sha = hashlib.sha256(analysis_path.read_bytes()).hexdigest()
    export_dir = bind_native_output_directory(
        args.export_dir, lane="native-ghidra-materialization",
        lane_epoch_id=args.lane_epoch_id, routing_binding=routing_binding,
    )
    engine = GhidraEngine()
    launch_token = selected_row.get("native_launch_authority_token")
    engine.configure_native_authority(selected_row, launch_token)
    identity = {
        "engine": "ghidra",
        "status": engine.status(),
        "checkpoint_schema": FUNCTION_EXPORT_SCHEMA,
        "exporter_schema": "angerona/1",
        "exporter_sha256": hashlib.sha256(
            Path(__file__).with_name("REDump.java").read_bytes()
        ).hexdigest(),
        "native_routing": routing_binding,
        "native_analysis_scope": analysis_scope,
        "native_range_authority_sha256": selected_row.get("range_authority_sha256"),
        "native_launch_authority_token": launch_token,
        "native_partition_sha256": selected_row.get("partition_sha256"),
    }

    def progress(row):
        print(json.dumps({"event": "function-progress", **row}, sort_keys=True), flush=True)

    result = materialize_ghidra_functions(
        engine,
        binary_path,
        analysis_path,
        export_dir,
        toolchain_identity=identity,
        timeout=args.timeout,
        max_attempts=args.max_attempts,
        entries=requested_entries or None,
        analysis_scope=analysis_scope,
        allowed_exec_ranges=allowed_ranges,
        native_launch_authority_token=launch_token,
        progress_callback=progress,
    )
    publish_native_lane_receipt(
        export_dir / "NATIVE_GHIDRA_LANE_COMPLETION_RECEIPT.json",
        lane="native-ghidra-materialization", lane_epoch_id=args.lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={binary_sha}, excluded_targets=_excluded,
        hold_targets=hold_targets,
        semantic_complete=bool(result.get("target_semantic_complete")),
        input_bindings=[
            {"path": str(binary_path), "sha256": binary_sha},
            {"path": str(analysis_path.resolve()), "sha256": analysis_sha},
        ],
        counts={"failed": result.get("failed"), "terminal": result.get("terminal")},
    )
    print(json.dumps({"event": "complete", **result}, sort_keys=True))
    return 0 if result["failed"] == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
