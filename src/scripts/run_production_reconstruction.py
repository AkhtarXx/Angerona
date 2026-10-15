"""Long-running, resumable production reconstruction controller.

The controller discovers sealed Ghidra exports by target SHA, runs different
Ghidra projects in bounded parallel lanes, and delegates per-function durability
to reconstruction_receipt.function_exports checkpoints.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any

from ..analysis.reconstruction_receipt import (
    FUNCTION_EXPORT_SCHEMA,
    invalid_function_classifier_identity,
    materialize_ghidra_functions,
)
from ..analysis.evidence_signing import verify_document
from ..analysis.native_ownership_manifest import native_routing_context, native_routing_targets
from ..analysis.native_target_universe import (
    load_native_target_universe,
    preflight_operator_signing,
    write_ownership_root_conservation_receipt,
    write_ownership_scoped_operation_receipt,
)
from ..mcp.server import GhidraEngine


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _append_event(path: Path, event: dict[str, Any], lock: threading.Lock) -> None:
    payload = (json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n").encode()
    with lock:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)


def _canonical_utc_timestamp(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        raise ValueError("audit timestamp is empty")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("audit timestamp must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(None):
        raise ValueError("audit timestamp must be timezone-aware UTC")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _target_index(root: Path) -> dict[str, list[Path]]:
    result: dict[str, list[Path]] = {}
    targets = root / "targets"
    for path in sorted(targets.rglob("*")):
        if path.is_file():
            result.setdefault(_sha256_path(path), []).append(path.resolve())
    return result


def _discover(root: Path) -> list[dict[str, Any]]:
    targets = _target_index(root)
    records: dict[str, dict[str, Any]] = {
        target_sha: {
            "target_sha256": target_sha,
            "target": paths[0],
            "aliases": paths,
            "analysis": None,
            "analysis_sha256": "",
            "function_count": 0,
        }
        for target_sha, paths in targets.items()
    }
    pattern = "ghidra-results/*/*/code/analysis.json"
    for analysis_path in sorted(root.glob(pattern)):
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        target_sha = str((analysis.get("metadata") or {}).get("sha256") or "").lower()
        target_paths = targets.get(target_sha)
        if not target_sha or target_paths is None:
            continue
        candidate = {
            "target_sha256": target_sha,
            "target": target_paths[0],
            "aliases": target_paths,
            "analysis": analysis_path.resolve(),
            "analysis_sha256": _sha256_path(analysis_path),
            "function_count": len(analysis.get("functions") or []),
        }
        current = records.get(target_sha)
        if current is None or current["analysis"] is None or analysis_path.stat().st_mtime_ns > current["analysis"].stat().st_mtime_ns:
            records[target_sha] = candidate
    return sorted(records.values(), key=lambda row: row["target_sha256"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit-root", required=True)
    parser.add_argument("--workers", type=int, default=2)
    parser.add_argument("--timeout", type=int, default=300)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--max-targets", type=int, default=0)
    parser.add_argument("--target-sha")
    parser.add_argument("--entry", action="append", default=[])
    parser.add_argument("--entry-file")
    parser.add_argument("--repair-errors", action="store_true")
    parser.add_argument("--repair-epoch-id", default="")
    parser.add_argument("--require-signed-ledger", action="store_true")
    parser.add_argument("--audit-epoch-id", default="")
    parser.add_argument("--audit-timestamp-utc", default="")
    parser.add_argument("--native-universe", required=True)
    parser.add_argument("--ownership-manifest", required=True)
    parser.add_argument("--controller-root", required=True)
    args = parser.parse_args()
    if (args.entry or args.entry_file) and not args.target_sha:
        parser.error("--entry/--entry-file requires --target-sha")
    if args.repair_errors and (not args.target_sha or not args.repair_epoch_id):
        parser.error("--repair-errors requires --target-sha and --repair-epoch-id")
    if args.repair_epoch_id and not args.repair_errors:
        parser.error("--repair-epoch-id requires --repair-errors")

    root = Path(args.audit_root).resolve()
    audit_epoch_id = args.audit_epoch_id or root.name
    try:
        audit_timestamp_utc = _canonical_utc_timestamp(
            args.audit_timestamp_utc or datetime.now(timezone.utc).isoformat()
        )
    except ValueError as exc:
        parser.error(str(exc))
    controller_root = Path(args.controller_root).expanduser().absolute().resolve()
    signing_key_id = preflight_operator_signing()
    universe_path = Path(args.native_universe).resolve()
    universe, _universe_records = load_native_target_universe(universe_path)
    ownership_path = Path(args.ownership_manifest).expanduser().absolute()
    ownership, records, ownership_policy_events, routing_binding = native_routing_context(
        ownership_path, universe_path,
    )
    _app_targets, _excluded_targets, routing_hold_targets = native_routing_targets(
        records, ownership_policy_events,
    )
    for ownership_row in ownership.get("rows") or []:
        prior = (ownership_row.get("prior_checkpoint_evidence") or {})
        prior_path = prior.get("path")
        if prior.get("present") and prior_path:
            prior_resolved = Path(prior_path).resolve()
            if prior_resolved == controller_root or controller_root in prior_resolved.parents:
                raise SystemExit(
                    "controller root overlaps ownership-manifest superseded checkpoints; "
                    "use a fresh explicit audit epoch root"
                )
    controller_root.mkdir(parents=True, exist_ok=True)
    lock_file = (controller_root / ".controller.lock").open("a+b")
    try:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError as exc:
        raise SystemExit("production reconstruction controller is already running") from exc
    scoped_operation = bool(args.target_sha or args.max_targets > 0)
    selected_target_sha256: list[str]
    if args.target_sha:
        requested_target = args.target_sha.lower()
        universe_targets = {str(row["target_sha256"]) for row in universe.get("targets") or []}
        if requested_target not in universe_targets:
            raise SystemExit("--target-sha is not a signed native-universe member")
        records = [row for row in records if row["target_sha256"] == requested_target]
        ownership_policy_events = [
            event for event in ownership_policy_events
            if event["target_sha256"] == requested_target
        ]
        selected_target_sha256 = [requested_target]
    elif args.max_targets > 0:
        records = records[:args.max_targets]
        ownership_policy_events = []
        selected_target_sha256 = [row["target_sha256"] for row in records]
        if not records:
            raise SystemExit("signed app-owned queue has no target in the requested scope")
    else:
        selected_target_sha256 = [str(row["target_sha256"]) for row in universe.get("targets") or []]
    if routing_hold_targets:
        records = []

    identity: dict[str, Any] = {}
    if records:
        probe = GhidraEngine()
        identity = {
            "engine": "ghidra",
            "status": probe.status(),
            "checkpoint_schema": FUNCTION_EXPORT_SCHEMA,
            "exporter_schema": "angerona/1",
            "exporter_sha256": _sha256_path(Path(__file__).with_name("REDump.java")),
            "native_ownership_manifest_sha256": _sha256_path(ownership_path),
            "native_ownership_payload_sha256": ownership.get("payload_sha256"),
            "native_routing": routing_binding,
        }
    classifier_identity = invalid_function_classifier_identity()
    event_path = controller_root / "TARGET_EVENTS.jsonl"
    event_lock = threading.Lock()
    requested_entries = {str(entry).lower().replace("0x", "") for entry in args.entry if str(entry).strip()}
    if args.entry_file:
        entry_path = Path(args.entry_file)
        raw = entry_path.read_text(encoding="utf-8")
        try:
            document = json.loads(raw)
        except ValueError:
            document = None
        if isinstance(document, dict):
            if document.get("target_sha256") != args.target_sha.lower():
                parser.error("repair manifest target SHA does not match --target-sha")
            if not verify_document(document, require_signature=args.require_signed_ledger):
                parser.error("repair manifest signature/hash validation failed")
            requested_entries.update(
                str(row.get("entry") or "").lower().replace("0x", "")
                for row in document.get("rows") or []
                if isinstance(row, dict) and row.get("disposition") == "repair_pending"
            )
        else:
            if args.require_signed_ledger:
                parser.error("--require-signed-ledger requires a signed JSON --entry-file manifest")
            requested_entries.update(line.strip().lower().replace("0x", "") for line in raw.splitlines() if line.strip())
    requested_entries.discard("")
    requested_entries = requested_entries or None
    if args.repair_errors and requested_entries is None:
        parser.error("--repair-errors requires a nonempty --entry or --entry-file selection")
    if args.require_signed_ledger and args.repair_errors and not args.entry_file:
        parser.error("signed repair requires --entry-file with a signed JSON manifest")

    def run_target(record: dict[str, Any]) -> dict[str, Any]:
        target_sha = record["target_sha256"]
        analysis_scope = str(record.get("analysis_scope") or "")
        allowed_ranges = record.get("allowed_executable_ranges") or []
        authorized_entries = {
            format(int(row["address"]), "x") for row in allowed_ranges
        } if analysis_scope == "selective_ranges" else None
        target_entries = requested_entries
        if authorized_entries is not None:
            if requested_entries is not None and not requested_entries.issubset(authorized_entries):
                raise ValueError("repair selection escapes signed mixed-target range queue")
            target_entries = requested_entries or authorized_entries
        target_identity = {
            **identity,
            "native_analysis_scope": analysis_scope,
            "native_range_authority_sha256": record.get("range_authority_sha256"),
            "native_launch_authority_token": record.get("native_launch_authority_token"),
            "native_partition_sha256": record.get("partition_sha256"),
        }
        output = controller_root / "targets" / target_sha
        if record["target"] is None or record["analysis"] is None:
            event = {
                "schema": "angerona/target-event/v2",
                "state": "missing-semantic-analysis",
                "target_sha256": target_sha,
                "aliases": [str(path) for path in record["aliases"]],
                "ownership_disposition": record["ownership_disposition"],
                "ownership_row_sha256": record["ownership_row_sha256"],
                "native_routing": routing_binding,
                "error": "signed universe lacks one exact extracted target or Ghidra analysis",
            }
            _append_event(event_path, event, event_lock)
            print(json.dumps({"event": "target-terminal", **event}, sort_keys=True), flush=True)
            return event
        _append_event(event_path, {
            "schema": "angerona/target-event/v2",
            "state": "running",
            "target_sha256": target_sha,
            "analysis_sha256": record["analysis_sha256"],
            "aliases": [str(path) for path in record["aliases"]],
            "ownership_disposition": record["ownership_disposition"],
            "ownership_row_sha256": record["ownership_row_sha256"],
            "native_routing": routing_binding,
        }, event_lock)

        def progress(row: dict[str, Any]) -> None:
            print(json.dumps({"event": "function-progress", "target_sha256": target_sha, **row}, sort_keys=True), flush=True)

        try:
            engine = GhidraEngine()
            launch_token = record.get("native_launch_authority_token")
            engine.configure_native_authority(record, launch_token)
            result = materialize_ghidra_functions(
                engine,
                record["target"],
                record["analysis"],
                output,
                toolchain_identity=target_identity,
                classifier_identity=classifier_identity,
                timeout=args.timeout,
                max_attempts=args.max_attempts,
                entries=target_entries,
                analysis_scope=analysis_scope,
                allowed_exec_ranges=allowed_ranges,
                native_launch_authority_token=launch_token,
                allow_error_retry=args.repair_errors,
                repair_epoch_id=args.repair_epoch_id,
                audit_epoch_id=audit_epoch_id,
                audit_timestamp_utc=audit_timestamp_utc,
                progress_callback=progress,
            )
            signed_ok = not args.require_signed_ledger or result["quality_ledger_trust"] == "operator_signed"
            pages_conserved = bool(
                result["failed"] == 0
                and result["repair_pending"] == 0
                and result["queue_conservation_complete"]
                and signed_ok
            )
            target_complete = bool(
                pages_conserved
                and result["target_semantic_complete"]
                and result["executable_range_conservation_complete"]
                and result["target_pending_work_units"] == 0
                and result["partial_function_count"] == 0
                and result["quality_ledger_trust"] == "operator_signed"
            )
            state = (
                "target-semantic-complete" if target_complete
                else "function-pages-conserved" if pages_conserved
                else "partial"
            )
            event = {
                "schema": "angerona/target-event/v2",
                "state": state,
                "target_sha256": target_sha,
                "analysis_sha256": record["analysis_sha256"],
                "aliases": [str(path) for path in record["aliases"]],
                "ownership_disposition": record["ownership_disposition"],
                "ownership_row_sha256": record["ownership_row_sha256"],
                "native_routing": routing_binding,
                "result": result,
            }
        except Exception as exc:
            event = {
                "schema": "angerona/target-event/v2",
                "state": "interrupted-or-failed",
                "target_sha256": target_sha,
                "analysis_sha256": record["analysis_sha256"],
                "aliases": [str(path) for path in record["aliases"]],
                "ownership_disposition": record["ownership_disposition"],
                "ownership_row_sha256": record["ownership_row_sha256"],
                "native_routing": routing_binding,
                "error_type": type(exc).__name__,
                "error": str(exc)[-4000:],
            }
        _append_event(event_path, event, event_lock)
        print(json.dumps({"event": "target-terminal", **event}, sort_keys=True), flush=True)
        return event

    terminal_events: list[dict[str, Any]] = [
        {**event, "native_routing": routing_binding}
        for event in ownership_policy_events
    ]
    failures = sum(event["state"] == "ownership-hold" for event in terminal_events)
    for policy_event in terminal_events:
        _append_event(event_path, policy_event, event_lock)
    worker_count = max(1, min(args.workers, len(records))) if records else 0
    if records:
        with ThreadPoolExecutor(max_workers=worker_count) as pool:
            futures = [pool.submit(run_target, record) for record in records]
            for future in as_completed(futures):
                terminal_event = future.result()
                terminal_events.append(terminal_event)
                if terminal_event["state"] != "target-semantic-complete":
                    failures += 1
    if scoped_operation:
        operation_receipt_path = controller_root / "NATIVE_SCOPED_OPERATION_RECEIPT.json"
        operation_receipt = write_ownership_scoped_operation_receipt(
            output_path=operation_receipt_path, universe_path=universe_path,
            universe=universe,
            selected_target_sha256=selected_target_sha256,
            terminal_events=terminal_events, audit_epoch_id=audit_epoch_id,
            target_selector=args.target_sha, max_targets=args.max_targets,
            ownership_path=ownership_path, ownership=ownership,
        )
        controller_complete = False
        universe_conserved = False
        operation_succeeded = operation_receipt["operation_succeeded"]
    else:
        operation_receipt_path = controller_root / "NATIVE_ROOT_CONSERVATION_RECEIPT.json"
        operation_receipt = write_ownership_root_conservation_receipt(
            output_path=operation_receipt_path, universe_path=universe_path,
            universe=universe, terminal_events=terminal_events,
            audit_epoch_id=audit_epoch_id,
            ownership_path=ownership_path, ownership=ownership,
        )
        controller_complete = operation_receipt["controller_complete"]
        universe_conserved = operation_receipt["universe_conserved"]
        operation_succeeded = controller_complete
    summary = {
        "event": "controller-terminal",
        "targets": len(selected_target_sha256),
        "app_owned_scheduled_targets": len(records),
        "ownership_policy_terminal_targets": len(ownership_policy_events),
        "failures": failures,
        "workers": worker_count,
        "universe_target_count": universe["target_count"],
        "universe_conserved": universe_conserved,
        "controller_complete": controller_complete,
        "scoped_operation": scoped_operation,
        "operation_succeeded": operation_succeeded,
        "operator_signing_key_id": signing_key_id,
        "operation_receipt_sha256": _sha256_path(operation_receipt_path),
    }
    print(json.dumps(summary, sort_keys=True), flush=True)
    return 0 if operation_succeeded else 2


if __name__ == "__main__":
    raise SystemExit(main())
