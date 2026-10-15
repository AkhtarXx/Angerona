"""Android artifact adapter for Angerona's supervisor/worker convergence swarm."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import shlex
import shutil
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from src.agents.audit_state import AuditStateStore
from src.agents.loop import attest_isolation_capable_dispatch
from src.agents.runtime import ClaudeCodeAgent, CodexAgent
from src.agents.supervisor import (
    SupervisorLoop,
    SwarmResult,
    project_active_worker_outcomes,
)
from src.config import default_engine, load_config
from src.observability import content_descriptor, sanitize_attributes
from src.pipeline.android_audit import AuditReport
from src.workspace import RunWorkspace

_SOURCE_SUFFIXES = {
    ".java", ".kt", ".kts", ".smali", ".xml", ".json", ".properties",
    ".cfg", ".conf",
    ".js", ".c", ".cc", ".cpp", ".h", ".hpp", ".aidl", ".txt",
    ".yaml", ".yml",
}
_MAX_INVENTORY_FILES = 50_000
_MAX_SOURCE_SHARDS = 63  # supervisor plan bound leaves one finding-corroboration slice
_TARGET_SHARD_BYTES = 256 * 1024
_FILE_READ_MARKER = "ANGERONA_FILE_READ_V1 "
_EVIDENCE_READER_NAME = "ANGERONA_EVIDENCE_READ.py"
_FINDING_ADJUDICATION_MARKER = "ANGERONA_FINDING_ADJUDICATION_V1 "
_FINDING_ADJUDICATOR_NAME = "ANGERONA_FINDING_ADJUDICATE.py"

_EVIDENCE_READER_SOURCE = r'''#!/usr/bin/env python3
"""Read an inventoried Android artifact and emit a machine-parseable access record."""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

MARKER = "ANGERONA_FILE_READ_V1 "


def fail(message: str) -> None:
    print(f"ANGERONA_FILE_READ_ERROR: {message}", file=sys.stderr)
    raise SystemExit(2)


parser = argparse.ArgumentParser()
parser.add_argument("--path", required=True)
parser.add_argument("--start", type=int, default=1)
parser.add_argument("--end", type=int)
parser.add_argument("--native", action="store_true")
parser.add_argument("--binary", action="store_true")
args = parser.parse_args()

root = Path.cwd().resolve()
inventory_path = root / "ANDROID_SOURCE_INVENTORY.json"
try:
    inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
except (OSError, ValueError) as exc:
    fail(f"inventory unavailable: {exc}")
records = {
    str(item.get("path")): item
    for item in inventory.get("files", [])
    if isinstance(item, dict) and item.get("path")
}
record = records.get(args.path)
if record is None:
    fail("path is not in ANDROID_SOURCE_INVENTORY.json")
artifact_root = (root / str(inventory.get("artifact_root", "android_artifacts"))).resolve()
target = (root / args.path).resolve()
try:
    target.relative_to(artifact_root)
except ValueError:
    fail("path escapes the Android artifact root")
if not target.is_file() or target.is_symlink():
    fail("path is not a regular, non-symlink artifact")
raw = target.read_bytes()
digest = hashlib.sha256(raw).hexdigest()
if digest != record.get("sha256") or len(raw) != record.get("bytes"):
    fail("artifact bytes do not match the machine inventory")

review_mode = str(record.get("review_mode") or "")
if not review_mode:
    review_mode = "native_artifact" if str(record.get("suffix", "")).lower() == ".so" else "text_lines"
if review_mode in {"native_artifact", "binary_artifact"}:
    expected_flag = args.native if review_mode == "native_artifact" else args.binary
    if not expected_flag or (args.native and args.binary):
        flag = "--native" if review_mode == "native_artifact" else "--binary"
        fail(f"{review_mode} requires exactly {flag}")
    meta = {
        "schema_version": 1,
        "path": args.path,
        "sha256": digest,
        "bytes": len(raw),
        "lines": None,
        "mode": review_mode,
        "start_line": None,
        "end_line": None,
        "full_file": True,
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    print(f"Binary artifact attested: {args.path} sha256={digest} bytes={len(raw)}")
    evidence = record.get("required_evidence") or []
    if evidence:
        print("Required derived evidence (must also be fully read):")
        for item in evidence:
            print(f"- {item}")
    if not record.get("analysis_complete", True):
        print(f"UNRESOLVED ANALYSIS LIMITATION: {record.get('limitation', 'unknown')}")
    print(MARKER + encoded)
    raise SystemExit(0)

if args.native or args.binary:
    fail("--native/--binary are valid only for matching binary inventory entries")
try:
    text = raw.decode("utf-8", errors="replace")
except Exception as exc:
    fail(f"text decoding failed: {exc}")
lines = text.split("\n")
total = len(lines)
start = args.start
end = args.end if args.end is not None else min(total, start + 399)
if start < 1 or end < start or end > total:
    fail(f"invalid line range {start}-{end}; total={total}")
if end - start + 1 > 400:
    fail("a single evidence read may cover at most 400 lines")
rendered_lines = [f"{number:08d}: {lines[number - 1]}" for number in range(start, end + 1)]
rendered = "\n".join(rendered_lines)
if len(rendered.encode("utf-8", "replace")) > 256 * 1024:
    fail("rendered evidence chunk exceeds 256 KiB; request a smaller line range")
meta = {
    "schema_version": 1,
    "path": args.path,
    "sha256": digest,
    "bytes": len(raw),
    "lines": total,
    "mode": "text_lines",
    "start_line": start,
    "end_line": end,
    "full_file": start == 1 and end == total,
    "chunk_sha256": hashlib.sha256(rendered.encode("utf-8", "replace")).hexdigest(),
}
encoded = base64.urlsafe_b64encode(
    json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
).decode("ascii")
print(rendered)
# Receipt is deliberately emitted after the bounded content so provider-output
# truncation cannot leave a success marker without the evidence it represents.
print(MARKER + encoded)
'''

_FINDING_ADJUDICATOR_SOURCE = r'''#!/usr/bin/env python3
"""Emit a structured adjudication receipt for one deterministic finding."""
import argparse
import base64
import hashlib
import json
from pathlib import Path

MARKER = "ANGERONA_FINDING_ADJUDICATION_V1 "


def fail(message: str) -> None:
    print(f"ANGERONA_FINDING_ADJUDICATION_ERROR: {message}", file=__import__("sys").stderr)
    raise SystemExit(2)


parser = argparse.ArgumentParser()
parser.add_argument("--finding-id", required=True)
parser.add_argument(
    "--verdict", required=True, choices=("confirmed", "rejected", "inconclusive")
)
parser.add_argument("--evidence-path", required=True)
args = parser.parse_args()
root = Path.cwd().resolve()
try:
    findings = json.loads((root / "ANDROID_FINDING_INVENTORY.json").read_text())
    sources = json.loads((root / "ANDROID_SOURCE_INVENTORY.json").read_text())
except (OSError, ValueError) as exc:
    fail(f"authoritative inventory unavailable: {exc}")
rows = {
    str(item.get("finding_id")): item
    for item in findings.get("findings", [])
    if isinstance(item, dict) and item.get("finding_id")
}
finding = rows.get(args.finding_id)
if finding is None:
    fail("finding id is not in ANDROID_FINDING_INVENTORY.json")
allowed = {
    str(item.get("path")): str(item.get("sha256"))
    for item in sources.get("files", [])
    if isinstance(item, dict) and item.get("path") and item.get("sha256")
}
allowed["ANDROID_AUDIT.json"] = str(findings.get("audit_sha256") or "")
expected_sha = allowed.get(args.evidence_path)
if not expected_sha:
    fail("evidence path is not in an authoritative Android inventory")
target = (root / args.evidence_path).resolve()
try:
    target.relative_to(root)
except ValueError:
    fail("evidence path escapes the worker code root")
if not target.is_file() or target.is_symlink():
    fail("evidence path is not a regular, non-symlink file")
observed_sha = hashlib.sha256(target.read_bytes()).hexdigest()
if observed_sha != expected_sha:
    fail("evidence bytes do not match the authoritative inventory")
receipt = {
    "schema_version": 1,
    "finding_id": args.finding_id,
    "finding_fingerprint": finding.get("fingerprint"),
    "verdict": args.verdict,
    "evidence_path": args.evidence_path,
    "evidence_sha256": observed_sha,
}
encoded = base64.urlsafe_b64encode(
    json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()
).decode()
print(
    f"Finding adjudicated: {args.finding_id} verdict={args.verdict} "
    f"evidence={args.evidence_path} sha256={observed_sha}"
)
print(MARKER + encoded)
'''


@dataclass(frozen=True)
class AndroidAISwarmOutcome:
    swarm: SwarmResult
    workspace: Path
    coverage: dict[str, Any]


def _evaluate_android_completion(
    report: AuditReport,
    coverage: dict[str, Any],
    *,
    model_swarm_converged: bool,
) -> dict[str, bool]:
    gate = report.metadata.get("coverage_gate", {})
    runtime_required = bool(
        report.metadata.get("runtime_escalation", {}).get("required")
        or gate.get("runtime_required")
        or report.metadata.get("runtime_requested")
    )
    runtime_complete = bool(
        not runtime_required
        or (
            report.runtime_extract_status == "ok"
            and gate.get("runtime_complete") is True
        )
    )
    static_complete = bool(
        report.status == "completed"
        and gate.get("manifest_decoded")
        and gate.get("static_code_covered")
        and gate.get("origin_anchored")
        and not report.refusal_reasons
    )
    deterministic_complete = bool(static_complete and runtime_complete)
    overall_complete = bool(
        model_swarm_converged
        and coverage.get("coverage_complete")
        and deterministic_complete
    )
    return {
        "runtime_required": runtime_required,
        "runtime_complete": runtime_complete,
        "static_complete": static_complete,
        "deterministic_complete": deterministic_complete,
        "overall_complete": overall_complete,
    }


def _dispatch_requires_isolation(
    control_code_dir: Path, effective_cwd: Path, requested: bool
) -> bool:
    """Keep every worker/reviewer isolated, including the K=1 fast path."""
    return requested or effective_cwd.resolve() != control_code_dir.resolve()


def create_android_ai_workspace(apk_path: str | Path, output_parent: str | Path) -> RunWorkspace:
    """Create a normal Angerona run workspace beside the requested report."""
    runs_dir = Path(output_parent).expanduser().resolve() / "android-ai-runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    ws = RunWorkspace.create(runs_dir, str(Path(apk_path).expanduser().resolve()))
    ws.meta["target_kind"] = "android-apk"
    ws.meta["ai_orchestration"] = "supervisor-worker-convergence"
    ws._save_meta()
    return ws


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _deterministic_finding_rows(report: AuditReport) -> list[dict[str, Any]]:
    """Assign stable, content-derived identities to deterministic report rows."""

    occurrences: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for report_index, finding in enumerate(report.findings):
        payload = finding.as_dict()
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
        ).encode("utf-8")
        fingerprint = hashlib.sha256(encoded).hexdigest()
        occurrence = occurrences.get(fingerprint, 0) + 1
        occurrences[fingerprint] = occurrence
        rows.append({
            "finding_id": f"android-finding-{fingerprint[:16]}-{occurrence:03d}",
            "fingerprint": fingerprint,
            "occurrence": occurrence,
            "report_index": report_index,
            "module": finding.module,
            "kind": finding.kind,
            "deterministic_verdict": finding.verdict,
        })
    return rows


def _validate_finding_inventory(
    report: AuditReport, code_dir: Path, inventory: dict[str, Any]
) -> dict[str, Any]:
    """Rebind finding closure to controller-authored report bytes."""

    audit_path = code_dir / "ANDROID_AUDIT.json"
    expected_rows = _deterministic_finding_rows(report)
    expected_payload = report.as_dict()
    for row, finding_payload in zip(
        expected_rows, expected_payload.get("findings", []), strict=True
    ):
        finding_payload["finding_id"] = row["finding_id"]
        finding_payload["fingerprint"] = row["fingerprint"]
    expected_bytes = (
        json.dumps(expected_payload, indent=2, default=str) + "\n"
    ).encode("utf-8")
    try:
        observed_bytes = audit_path.read_bytes()
        audit = json.loads(observed_bytes)
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return {"valid": False, "reason": "android_audit_unreadable"}
    actual_rows = inventory.get("findings")
    if not isinstance(actual_rows, list):
        return {"valid": False, "reason": "finding_rows_invalid"}
    audit_findings = audit.get("findings")
    if not isinstance(audit_findings, list):
        return {"valid": False, "reason": "audit_findings_invalid"}
    embedded_rows = [
        {
            "finding_id": item.get("finding_id"),
            "fingerprint": item.get("fingerprint"),
        }
        for item in audit_findings
        if isinstance(item, dict)
    ]
    expected_embedded = [
        {"finding_id": row["finding_id"], "fingerprint": row["fingerprint"]}
        for row in expected_rows
    ]
    valid = bool(
        inventory.get("schema_version") == 1
        and inventory.get("finding_count") == len(expected_rows)
        and actual_rows == expected_rows
        and embedded_rows == expected_embedded
        and observed_bytes == expected_bytes
        and inventory.get("audit_sha256") == _sha256(audit_path)
    )
    return {
        "valid": valid,
        "reason": "" if valid else "finding_inventory_report_binding_mismatch",
        "finding_count": len(expected_rows),
        "audit_sha256": _sha256(audit_path),
    }


def _atomic_replace_json(path: Path, payload: dict[str, Any]) -> None:
    """Durably replace one controller-owned JSON artifact without ledger recursion."""
    temporary = path.parent / f".{path.name}.{uuid.uuid4().hex}.tmp"
    encoded = (json.dumps(payload, indent=2, default=str) + "\n").encode("utf-8")
    try:
        with temporary.open("xb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        descriptor = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def _revalidate_apk_identity(report: AuditReport, apk_path: str | Path) -> dict[str, Any]:
    """Bind the final terminal commit to the same immutable APK audited initially."""
    apk = Path(apk_path).expanduser().resolve()
    expected = str(report.metadata.get("artifact_validation", {}).get("sha256", ""))
    observed = _sha256(apk) if apk.is_file() else ""
    valid = bool(expected and observed == expected)
    gate = {
        "status": "verified" if valid else "mismatch",
        "expected_sha256": expected,
        "observed_sha256": observed,
    }
    report.metadata["apk_identity_final_gate"] = gate
    if not valid:
        if report.status != "error":
            report.status = "partial"
        reason = "APK identity changed or disappeared before final AI commit"
        if reason not in report.refusal_reasons:
            report.refusal_reasons.append(reason)
    return {"valid": valid, "sha256": observed, **gate}


def _line_count(path: Path) -> int | None:
    if path.suffix.lower() == ".so":
        return None
    try:
        return path.read_bytes().count(b"\n") + 1
    except OSError:
        return None


def _source_inventory(
    code_dir: Path,
    binary_inventory: dict[str, Any] | None = None,
) -> dict[str, Any]:
    artifact_root = code_dir / "android_artifacts"
    files: list[dict[str, Any]] = []
    truncated = False
    binary_by_path = {
        str(item.get("path")): item
        for item in (binary_inventory or {}).get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    required_binary_paths: set[str] = set()
    for item in binary_by_path.values():
        if item.get("review_required"):
            required_binary_paths.add(str(item["path"]))
            required_binary_paths.update(
                str(path) for path in item.get("required_evidence", []) if path
            )
    if artifact_root.is_dir():
        for path in sorted(item for item in artifact_root.rglob("*") if item.is_file()):
            relative_artifact = path.relative_to(artifact_root).as_posix()
            binary = binary_by_path.get(relative_artifact)
            is_review_binary = relative_artifact in required_binary_paths
            is_source_text = bool(
                (path.suffix.lower() in _SOURCE_SUFFIXES and not binary)
                or (
                    binary
                    and binary.get("format") == "text"
                    and (
                        binary.get("review_required")
                        or path.suffix.lower() in _SOURCE_SUFFIXES
                    )
                )
            )
            if not is_source_text and not is_review_binary:
                continue
            if len(files) >= _MAX_INVENTORY_FILES:
                truncated = True
                break
            stat = path.stat()
            review_mode = (
                str(binary.get("review_mode"))
                if binary and binary.get("review_required") and binary.get("format") != "text"
                else "text_lines"
            )
            item: dict[str, Any] = {
                "path": path.relative_to(code_dir).as_posix(),
                "suffix": path.suffix.lower(),
                "bytes": stat.st_size,
                "lines": None if review_mode != "text_lines" else _line_count(path),
                "sha256": _sha256(path),
                "review_mode": review_mode,
                "format": str(binary.get("format", "text")) if binary else "text",
                "analysis_complete": bool(binary.get("analysis_complete", True)) if binary else True,
                "limitation": str(binary.get("limitation", "")) if binary else "",
                "required_evidence": [
                    f"android_artifacts/{value}"
                    for value in (binary.get("required_evidence", []) if binary else [])
                ],
            }
            files.append(item)
    return {
        "schema_version": 1,
        "artifact_root": "android_artifacts",
        "file_count": len(files),
        "truncated": truncated,
        "artifact_inventory_count": int((binary_inventory or {}).get("file_count", 0)),
        "binary_review_required": int(
            (binary_inventory or {}).get("review_required_count", 0)
        ),
        "binary_analysis_incomplete": list(
            (binary_inventory or {}).get("incomplete_required", [])
        ),
        "apk_member_closure": dict(
            (binary_inventory or {}).get("apk_member_closure", {})
        ),
        "files": files,
    }


def _security_slices(inventory: dict[str, Any], report: AuditReport) -> dict[str, Any]:
    records = [
        item for item in inventory.get("files", [])
        if isinstance(item, dict) and item.get("path")
    ]
    files = [str(item["path"]) for item in records]
    total_weight = sum(
        max(int(item.get("bytes") or 0), int(item.get("lines") or 0) * 80, 1)
        for item in records
    )
    shard_count = min(
        _MAX_SOURCE_SHARDS,
        len(records),
        max(1, math.ceil(total_weight / _TARGET_SHARD_BYTES)),
    ) if records else 0
    shards: list[list[str]] = [[] for _ in range(shard_count)]
    shard_weights = [0] * shard_count
    # Deterministic LPT balancing prevents one huge decompiler artifact from
    # dominating a worker while bounding the total worker count for 200–300MB
    # APKs. Paths break weight ties reproducibly.
    weighted = sorted(
        (
            (
                max(
                    int(item.get("bytes") or 0),
                    int(item.get("lines") or 0) * 80,
                    1,
                ),
                str(item["path"]),
            )
            for item in records
        ),
        key=lambda value: (-value[0], value[1]),
    )
    for weight, path in weighted:
        index = min(range(shard_count), key=lambda value: (shard_weights[value], value))
        shards[index].append(path)
        shard_weights[index] += weight
    slices: list[dict[str, Any]] = []
    for index, shard in enumerate(shards):
        shard.sort()
        slice_id = f"android-files-{index + 1:02d}"
        slices.append({
            "slice_id": slice_id,
            "status": "candidate",
            "risk": {"severity": "HIGH", "category": "android-source-review"},
            "source": {"name": f"APK source shard {index + 1}"},
            "sink": {"name": "security-sensitive Android behavior"},
            "reconstruction_targets": [],
            "ai_scope": {
                "allowed_inputs": shard,
                "estimated_review_bytes": shard_weights[index],
                "required_action": (
                    "Inspect every listed file; verify existing findings and hunt for "
                    "missed source-to-sink vulnerabilities with exact citations."
                ),
            },
        })
    finding_rows = _deterministic_finding_rows(report)
    finding_modules = sorted({finding.module for finding in report.findings})
    slices.append({
        "slice_id": "android-findings-corroboration",
        "status": "candidate",
        "risk": {"severity": "CRITICAL", "category": "finding-corroboration"},
        "source": {"name": "deterministic Android findings"},
        "sink": {"name": "verified vulnerability report"},
        "reconstruction_targets": [],
        "ai_scope": {
            "allowed_inputs": [
                "ANDROID_AUDIT.json",
                "ANDROID_FINDING_INVENTORY.json",
                "ANDROID_SOURCE_INVENTORY.json",
            ],
            "finding_modules": finding_modules,
            "finding_ids": [row["finding_id"] for row in finding_rows],
            "required_action": (
                "Reproduce or reject every deterministic finding; preserve uncertainty "
                "and identify false positives and missing exploit preconditions. Analyst "
                "and reviewer must independently emit one structured "
                "ANGERONA_FINDING_ADJUDICATE.py receipt per finding id."
            ),
        },
    })
    return {
        "schema_version": 1,
        "target_kind": "android-apk",
        "summary": {
            "candidate_slices": len(slices),
            "source_files_scheduled": len(files),
            "inventory_truncated": bool(inventory.get("truncated")),
        },
        "slices": slices,
    }


def materialize_android_ai_evidence(ws: RunWorkspace, report: AuditReport) -> dict[str, Any]:
    """Write machine-authored inputs consumed by every isolated AI worker."""
    snapshot = report.metadata.get("audit_input_snapshot", {})
    snapshot_path = str(snapshot.get("path") or "")
    apk = Path(snapshot_path or report.apk_path).expanduser().resolve()
    expected_apk_sha = str(
        snapshot.get("sha256")
        or report.metadata.get("artifact_validation", {}).get("sha256", "")
    )
    expected_apk_size = int(snapshot.get("size") or 0)
    observed_apk_sha = _sha256(apk) if apk.is_file() else ""
    observed_apk_size = apk.stat().st_size if apk.is_file() else 0
    if (
        not expected_apk_sha
        or observed_apk_sha != expected_apk_sha
        or (expected_apk_size and observed_apk_size != expected_apk_size)
    ):
        report.status = "partial" if report.status != "error" else report.status
        reason = "APK identity changed or is unavailable between deterministic and AI phases"
        if reason not in report.refusal_reasons:
            report.refusal_reasons.append(reason)
        report.metadata["apk_identity_gate"] = {
            "status": "mismatch", "expected_sha256": expected_apk_sha,
            "observed_sha256": observed_apk_sha,
            "expected_size": expected_apk_size,
            "observed_size": observed_apk_size,
            "source": "audit_input_snapshot" if snapshot_path else "report_apk_path",
        }
    else:
        report.metadata["apk_identity_gate"] = {
            "status": "verified", "sha256": observed_apk_sha,
            "size": observed_apk_size,
            "source": "audit_input_snapshot" if snapshot_path else "report_apk_path",
        }
    finding_rows = _deterministic_finding_rows(report)
    report_payload = report.as_dict()
    for row, finding_payload in zip(finding_rows, report_payload["findings"], strict=True):
        finding_payload["finding_id"] = row["finding_id"]
        finding_payload["fingerprint"] = row["fingerprint"]
    report_path = ws.code_dir / "ANDROID_AUDIT.json"
    report_path.write_text(
        json.dumps(report_payload, indent=2, default=str) + "\n",
        encoding="utf-8",
    )
    finding_inventory = {
        "schema_version": 1,
        "audit_sha256": _sha256(report_path),
        "finding_count": len(finding_rows),
        "findings": finding_rows,
    }
    (ws.code_dir / "ANDROID_FINDING_INVENTORY.json").write_text(
        json.dumps(finding_inventory, indent=2) + "\n", encoding="utf-8"
    )
    from src.analysis.android_binary_inventory import materialize_binary_evidence

    progress_started = time.monotonic()
    last_progress_publish = 0.0

    def publish_pre_ai_progress(event: dict[str, Any]) -> None:
        nonlocal last_progress_publish
        now = time.monotonic()
        completed = int(event.get("completed", 0))
        expected = int(event.get("expected", 0))
        if completed != expected and now - last_progress_publish < 5.0:
            return
        elapsed = max(0.001, now - progress_started)
        payload = {
            **event,
            "elapsed_seconds": round(elapsed, 3),
            "items_per_second": round(completed / elapsed, 3),
            "updated_time_ns": time.time_ns(),
            "binary_evidence_complete": bool(expected and completed >= expected),
            "materialization_complete": bool(event.get("final_materialization")),
        }
        _atomic_replace_json(
            ws.raw_dir / "ANDROID_PRE_AI_PROGRESS.json", payload
        )
        ws.update_progress("android_pre_ai_progress", payload)
        if payload["materialization_complete"]:
            # Keep the last-known-good seal separate from the live cursor. A
            # later interrupted retry may update progress, but it must never
            # erase authority to resume from the completed materialization.
            _atomic_replace_json(
                ws.raw_dir / "ANDROID_PRE_AI_CHECKPOINT.json", payload
            )
            ws.update_progress("android_pre_ai_checkpoint", payload)
        ws.observability.emit(
            component="android_ai_adapter",
            category="progress",
            action="pre_ai_materialization",
            attributes={
                "completed": completed,
                "expected": expected,
                "format": str(event.get("format", "")),
                "cache_hit": bool(event.get("cache_hit")),
                "elapsed_seconds": payload["elapsed_seconds"],
                "items_per_second": payload["items_per_second"],
            },
        )
        print(
            f"android-ai-prep {completed}/{expected} "
            f"format={event.get('format', 'unknown')} "
            f"cache={'hit' if event.get('cache_hit') else 'miss'} "
            f"elapsed={payload['elapsed_seconds']}s",
            file=sys.stderr,
            flush=True,
        )
        last_progress_publish = now

    binary_inventory = materialize_binary_evidence(
        ws.code_dir / "android_artifacts",
        observation_workspace=ws.root,
        precomputed_native_records=list(
            report.metadata.get("native_static_evidence", {}).get("records", [])
        ),
        ownership_manifest=report.metadata.get("native_static_evidence", {}).get(
            "ownership_manifest_path", ""
        ),
        native_universe=report.metadata.get("native_static_evidence", {}).get(
            "native_universe_path", ""
        ),
        native_lane_epoch_id=report.metadata.get("native_static_evidence", {}).get(
            "native_lane_epoch_id", ""
        ),
        progress_callback=publish_pre_ai_progress,
        deadline_monotonic=float(
            report.metadata.get("pre_ai_budget", {}).get("deadline_monotonic", 0.0)
        ) or None,
    )
    binary_inventory["native_cache_hits"] = sum(
        bool(item.get("native_cache_hit"))
        for item in binary_inventory.get("files", [])
        if isinstance(item, dict)
    )
    # A raw DEX becomes complete only when its class-data table reconciles
    # exactly with its independently generated Smali tree. JADX is a readable
    # corroborating view, never the semantic coverage oracle.
    from src.analysis.dex_semantic import validate_dex_semantic_receipt

    successful_dex_targets: dict[str, str] = {}
    for semantic_result in report.metadata.get("dex_semantic_coverage", {}).get(
        "target_results", []
    ):
        if (
            isinstance(semantic_result, dict)
            and validate_dex_semantic_receipt(semantic_result)
        ):
            successful_dex_targets[
                str(Path(semantic_result.get("path", "")).resolve())
            ] = str(semantic_result.get("sha256", ""))
    artifact_root = (ws.code_dir / "android_artifacts").resolve()
    for item in binary_inventory.get("files", []):
        if item.get("format") != "dex":
            continue
        candidate = str((artifact_root / str(item.get("path", ""))).resolve())
        if (
            candidate in successful_dex_targets
            and str(item.get("sha256", "")) == successful_dex_targets[candidate]
        ):
            item["analysis_complete"] = True
            item["limitation"] = ""
            item["semantic_witness"] = "exact-dex-class-method-to-smali-reconciliation"

    direct_apk_inventory = report.metadata.get("binary_inventory", {})
    binary_by_relative = {
        str(item.get("path")): item
        for item in binary_inventory.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    closure_rows: list[dict[str, Any]] = []
    for member in direct_apk_inventory.get("members", []):
        if not isinstance(member, dict) or not member.get("review_required"):
            continue
        exported = str(member.get("exported_path") or "")
        mapped = ""
        if exported:
            try:
                mapped = Path(exported).resolve().relative_to(artifact_root).as_posix()
            except (OSError, ValueError):
                mapped = ""
        produced = binary_by_relative.get(mapped)
        hash_matches = bool(
            produced is not None
            and str(produced.get("sha256", ""))
            == str(member.get("sha256", ""))
        )
        routed_excluded = bool(
            produced is not None
            and produced.get("review_mode") == "fully_excluded_third_party"
        )
        if produced is not None and hash_matches and not routed_excluded:
            produced["review_required"] = True
            produced["review_reason"] = str(member.get("review_reason") or "apk-member")
            produced["apk_member"] = str(member.get("member") or "")
        closure_rows.append({
            "member": str(member.get("member") or ""),
            "sha256": str(member.get("sha256") or ""),
            "format": str(member.get("format") or ""),
            "artifact": mapped,
            "mapped": produced is not None and hash_matches,
            "hash_matches": hash_matches,
            "fully_excluded_third_party": routed_excluded,
            "artifact_sha256": str(produced.get("sha256", ""))
            if produced is not None else "",
        })
    closure_missing = [row["member"] for row in closure_rows if not row["mapped"]]
    binary_inventory["apk_member_closure"] = {
        "expected": len(closure_rows),
        "mapped": len(closure_rows) - len(closure_missing),
        "missing": closure_missing,
        "complete": bool(closure_rows and not closure_missing),
        "rows": closure_rows,
    }
    binary_inventory["incomplete_required"] = [
        item["path"] for item in binary_inventory.get("files", [])
        if item.get("review_required") and not item.get("analysis_complete")
    ]
    binary_inventory["apk_member_accounting"] = {
        "status": direct_apk_inventory.get("status", "missing"),
        "member_count": direct_apk_inventory.get("member_count", 0),
        "review_required_count": direct_apk_inventory.get("review_required_count", 0),
        "unresolved_opaque_members": list(
            direct_apk_inventory.get("unresolved_opaque_members", [])
        ),
        "skipped": list(direct_apk_inventory.get("skipped", [])),
        "members": list(direct_apk_inventory.get("members", [])),
    }
    (ws.code_dir / "ANDROID_BINARY_INVENTORY.json").write_text(
        json.dumps(binary_inventory, indent=2) + "\n", encoding="utf-8"
    )
    inventory = _source_inventory(ws.code_dir, binary_inventory)
    (ws.code_dir / "ANDROID_SOURCE_INVENTORY.json").write_text(
        json.dumps(inventory, indent=2) + "\n",
        encoding="utf-8",
    )
    reader_path = ws.code_dir / _EVIDENCE_READER_NAME
    # A prior materialization seals these scripts chmod 0o555 (read+execute).
    # Re-running materialize on resume then hits PermissionError on write_text.
    # Re-open the write bit before writing, then re-seal, so resume is idempotent.
    if reader_path.exists():
        reader_path.chmod(0o755)
    reader_path.write_text(_EVIDENCE_READER_SOURCE, encoding="utf-8")
    reader_path.chmod(0o555)
    adjudicator_path = ws.code_dir / _FINDING_ADJUDICATOR_NAME
    if adjudicator_path.exists():
        adjudicator_path.chmod(0o755)
    adjudicator_path.write_text(_FINDING_ADJUDICATOR_SOURCE, encoding="utf-8")
    adjudicator_path.chmod(0o555)
    slices = _security_slices(inventory, report)
    (ws.raw_dir / "security_slices.json").write_text(
        json.dumps(slices, indent=2) + "\n",
        encoding="utf-8",
    )
    overview = {
        "target_kind": "android-apk",
        "apk": report.apk_path,
        "status": report.status,
        "package_name": report.metadata.get("package_name", ""),
        "provenance_verdict": report.provenance_verdict,
        "packer_verdict": report.packer_verdict,
        "finding_count": len(report.findings),
        "source_file_count": inventory["file_count"],
        "source_inventory_truncated": inventory["truncated"],
        "artifact_inventory_count": inventory["artifact_inventory_count"],
        "binary_review_required": inventory["binary_review_required"],
        "binary_analysis_incomplete": inventory["binary_analysis_incomplete"],
        "security_slice_count": len(slices["slices"]),
        "coverage_gate": report.metadata.get("coverage_gate", {}),
        "rule_steps_executed": report.steps_executed,
        "rule_steps_skipped": report.steps_skipped,
    }
    (ws.code_dir / "ANDROID_TARGET_OVERVIEW.json").write_text(
        json.dumps(overview, indent=2) + "\n",
        encoding="utf-8",
    )
    ws.meta["android_overview"] = overview
    ws._save_meta()
    publish_pre_ai_progress({
        "stage": "android-ai-materialization",
        "completed": int(binary_inventory.get("file_count", 0)),
        "expected": int(binary_inventory.get("file_count", 0)),
        "format": "sealed-inventories-and-slices",
        "cache_hit": False,
        "final_materialization": True,
        "artifact_sha256": {
            "source_inventory": _sha256(ws.code_dir / "ANDROID_SOURCE_INVENTORY.json"),
            "binary_inventory": _sha256(ws.code_dir / "ANDROID_BINARY_INVENTORY.json"),
            "finding_inventory": _sha256(ws.code_dir / "ANDROID_FINDING_INVENTORY.json"),
            "security_slices": _sha256(ws.raw_dir / "security_slices.json"),
            "overview": _sha256(ws.code_dir / "ANDROID_TARGET_OVERVIEW.json"),
        },
    })
    return overview


def _event_role(path: Path) -> str | None:
    if "_analyst" in path.name:
        return "analyst"
    if "_review" in path.name or "_adversarial" in path.name:
        return "reviewer"
    return None


def _canonical_event_files(raw_dir: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(raw_dir.glob("round_*events.json")):
        if re.search(r"_analyst_k\d+\.events\.json$", path.name):
            canonical = path.with_name(re.sub(r"_k\d+(?=\.events\.json$)", "", path.name))
            if canonical.is_file():
                continue
        if _event_role(path):
            files.append(path)
    return files


def _decode_file_read_marker(output: str) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.startswith(_FILE_READ_MARKER):
            continue
        encoded = line[len(_FILE_READ_MARKER):].strip()
        try:
            item = json.loads(base64.urlsafe_b64decode(encoded).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(item, dict):
            decoded.append(item)
    return decoded


def _evidence_reader_invocations(command: str) -> list[dict[str, Any]]:
    """Extract exact helper arguments from a direct or shell-wrapped command."""
    try:
        outer = shlex.split(command)
    except ValueError:
        return []
    shell_exec = any(
        token.startswith("-") and "c" in token[1:]
        for token in outer[1:-1]
    )
    trusted_shells = {
        Path(value).resolve()
        for value in (shutil.which("bash"), shutil.which("sh"), "/bin/bash", "/bin/sh")
        if value and Path(value).exists()
    }
    outer_executable = (
        Path(outer[0]).resolve()
        if outer and "/" in outer[0]
        else Path(shutil.which(outer[0]) or "/nonexistent").resolve()
        if outer else Path("/nonexistent")
    )
    if (
        len(outer) >= 3
        and Path(outer[0]).name in {"bash", "sh"}
        and shell_exec
        and outer_executable in trusted_shells
    ):
        scripts = [outer[-1]]
    elif len(outer) >= 3 and shell_exec:
        return []
    else:
        scripts = [command]
    invocations: list[dict[str, Any]] = []
    for script in scripts:
        try:
            tokens = shlex.split(script)
        except ValueError:
            continue
        # Only a direct helper execution is credited.  Marker text printed by
        # echo, dead shell branches, pipelines, comments, or compound commands
        # is not an invocation and receives no coverage.
        if len(tokens) < 2 or any(token in {";", "&&", "||", "|"} for token in tokens):
            continue
        trusted_interpreters = {
            Path(value).resolve()
            for value in (sys.executable, shutil.which("python3"))
            if value and Path(value).exists()
        }
        interpreter = (
            Path(tokens[0]).resolve()
            if "/" in tokens[0]
            else Path(shutil.which(tokens[0]) or "/nonexistent").resolve()
        )
        if interpreter not in trusted_interpreters:
            continue
        if "/" not in tokens[0] and not re.fullmatch(r"python3(?:\.\d+)?", tokens[0]):
            continue
        if tokens[1] != _EVIDENCE_READER_NAME:
            continue
        args: dict[str, Any] = {"native": False}
        cursor = 2
        while cursor < len(tokens):
            token = tokens[cursor]
            if token == "--native":
                args["native"] = True
                cursor += 1
                continue
            if token == "--binary":
                args["binary"] = True
                cursor += 1
                continue
            if token in {"--path", "--start", "--end"} and cursor + 1 < len(tokens):
                key = token[2:]
                value: Any = tokens[cursor + 1]
                if key in {"start", "end"}:
                    try:
                        value = int(value)
                    except ValueError:
                        value = None
                args[key] = value
                cursor += 2
                continue
            # Unknown flags/positional arguments make the receipt ambiguous.
            args = {}
            break
        if args:
            invocations.append(args)
    unique: list[dict[str, Any]] = []
    for item in invocations:
        if item not in unique:
            unique.append(item)
    return unique


def _finding_adjudicator_invocations(command: str) -> list[dict[str, str]]:
    """Parse only a direct, exact structured-adjudication helper invocation."""

    try:
        outer = shlex.split(command)
    except ValueError:
        return []
    shell_exec = any(
        token.startswith("-") and not token.startswith("--") and "c" in token[1:]
        for token in outer[1:-1]
    )
    trusted_shells = {
        Path(value).resolve()
        for value in (shutil.which("bash"), shutil.which("sh"), "/bin/bash", "/bin/sh")
        if value and Path(value).exists()
    }
    outer_executable = (
        Path(outer[0]).resolve()
        if outer and "/" in outer[0]
        else Path(shutil.which(outer[0]) or "/nonexistent").resolve()
        if outer else Path("/nonexistent")
    )
    if (
        len(outer) >= 3
        and Path(outer[0]).name in {"bash", "sh"}
        and shell_exec
        and outer_executable in trusted_shells
    ):
        script = outer[-1]
    elif len(outer) >= 3 and shell_exec:
        return []
    else:
        script = command
    try:
        tokens = shlex.split(script)
    except ValueError:
        return []
    if len(tokens) != 8 or any(token in {";", "&&", "||", "|"} for token in tokens):
        return []
    trusted_interpreters = {
        Path(value).resolve()
        for value in (sys.executable, shutil.which("python3"))
        if value and Path(value).exists()
    }
    interpreter = (
        Path(tokens[0]).resolve()
        if "/" in tokens[0]
        else Path(shutil.which(tokens[0]) or "/nonexistent").resolve()
    )
    if (
        interpreter not in trusted_interpreters
        or ("/" not in tokens[0] and not re.fullmatch(r"python3(?:\.\d+)?", tokens[0]))
        or tokens[1] != _FINDING_ADJUDICATOR_NAME
    ):
        return []
    values: dict[str, str] = {}
    for offset in range(2, 8, 2):
        flag = tokens[offset]
        if flag not in {"--finding-id", "--verdict", "--evidence-path"} or flag in values:
            return []
        values[flag] = tokens[offset + 1]
    if set(values) != {"--finding-id", "--verdict", "--evidence-path"}:
        return []
    return [{
        "finding_id": values["--finding-id"],
        "verdict": values["--verdict"],
        "evidence_path": values["--evidence-path"],
    }]


def _decode_finding_adjudication(output: str) -> list[dict[str, Any]]:
    decoded: list[dict[str, Any]] = []
    for line in output.splitlines():
        if not line.startswith(_FINDING_ADJUDICATION_MARKER):
            continue
        try:
            item = json.loads(
                base64.urlsafe_b64decode(
                    line[len(_FINDING_ADJUDICATION_MARKER):].strip()
                ).decode("utf-8")
            )
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(item, dict):
            decoded.append(item)
    return decoded


def _provider_command_records(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Normalize Codex command events and Claude Code Bash tool turns."""

    records: list[dict[str, Any]] = []
    pending_claude: dict[str, dict[str, Any]] = {}
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("type") == "item.completed":
            item = event.get("item")
            if isinstance(item, dict) and item.get("type") == "command_execution":
                records.append({
                    "command": str(item.get("command") or ""),
                    "output": str(item.get("aggregated_output") or ""),
                    "exit_code": item.get("exit_code"),
                    "provider_status": item.get("status"),
                    "succeeded": (
                        item.get("status") == "completed"
                        and item.get("exit_code") == 0
                    ),
                    "call_id": item.get("id"),
                    "started_time_ns": event.get("_angerona_started_time_ns"),
                    "completed_time_ns": event.get("_angerona_received_time_ns"),
                    "duration_ms": event.get("_angerona_duration_ms"),
                })
            continue
        message = event.get("message")
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if not isinstance(content, list):
            continue
        if event.get("type") == "assistant":
            for block in content:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                if block.get("name") != "Bash" or not block.get("id"):
                    continue
                tool_input = block.get("input")
                if not isinstance(tool_input, dict):
                    continue
                pending_claude[str(block["id"])] = {
                    "command": str(tool_input.get("command") or ""),
                    "call_id": str(block["id"]),
                    "started_time_ns": event.get("_angerona_received_time_ns"),
                }
            continue
        if event.get("type") != "user":
            continue
        tool_metadata = event.get("tool_use_result")
        for block in content:
            if not isinstance(block, dict) or block.get("type") != "tool_result":
                continue
            call_id = str(block.get("tool_use_id") or "")
            pending = pending_claude.pop(call_id, None)
            if pending is None:
                continue
            raw_content = block.get("content")
            if isinstance(raw_content, str):
                output = raw_content
            elif isinstance(raw_content, list):
                output = "\n".join(
                    str(part.get("text") or "")
                    for part in raw_content
                    if isinstance(part, dict) and part.get("type") == "text"
                )
            else:
                output = str(raw_content or "")
            interrupted = bool(
                isinstance(tool_metadata, dict)
                and tool_metadata.get("interrupted")
            )
            succeeded = not bool(block.get("is_error")) and not interrupted
            records.append({
                **pending,
                "output": output,
                "exit_code": 0 if succeeded else 1,
                "provider_status": "completed" if succeeded else "failed",
                "succeeded": succeeded,
                "completed_time_ns": event.get("_angerona_received_time_ns"),
                "duration_ms": None,
            })
    for pending in pending_claude.values():
        records.append({
            **pending,
            "output": "",
            "exit_code": None,
            "provider_status": "missing_tool_result",
            "succeeded": False,
            "completed_time_ns": None,
            "duration_ms": None,
        })
    return records


def _collect_worker_ledgers(
    inventory: dict[str, Any], swarm: SwarmResult
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Normalize provider command events and extract fail-closed file-read evidence."""
    inventory_by_path = {
        str(item.get("path")): item
        for item in inventory.get("files", [])
        if isinstance(item, dict) and item.get("path")
    }
    tool_calls: list[dict[str, Any]] = []
    file_reads: list[dict[str, Any]] = []
    for outcome in swarm.workers:
        root_value = getattr(outcome, "workspace_root", "")
        if not root_value:
            continue
        worker_root = Path(root_value)
        reader_path = worker_root / "code" / _EVIDENCE_READER_NAME
        try:
            reader_integrity = (
                reader_path.is_file()
                and not reader_path.is_symlink()
                and _sha256(reader_path)
                == hashlib.sha256(_EVIDENCE_READER_SOURCE.encode("utf-8")).hexdigest()
            )
        except OSError:
            reader_integrity = False
        for event_path in _canonical_event_files(worker_root / "raw"):
            try:
                events = json.loads(event_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(events, list):
                continue
            role = _event_role(event_path)
            for record in _provider_command_records(events):
                command = str(record.get("command") or "")
                output = str(record.get("output") or "")
                exit_code = record.get("exit_code")
                succeeded = bool(record.get("succeeded"))
                call = {
                    "schema_version": 1,
                    "worker_id": outcome.spec.id,
                    "slice_id": outcome.spec.slice_id,
                    "role": role,
                    "source_event_file": event_path.relative_to(worker_root).as_posix(),
                    "call_id": record.get("call_id"),
                    "tool": "shell",
                    "command": sanitize_attributes(command, key="command", string_chars=4096),
                    "status": "succeeded" if succeeded else "failed",
                    "provider_status": record.get("provider_status"),
                    "exit_code": exit_code,
                    "started_time_ns": record.get("started_time_ns"),
                    "completed_time_ns": record.get("completed_time_ns"),
                    "duration_ms": record.get("duration_ms"),
                    "output": content_descriptor(output),
                    "evidence_reader_integrity": reader_integrity,
                }
                tool_calls.append(call)
                invocations = _evidence_reader_invocations(command)
                if not succeeded or not reader_integrity or not invocations:
                    continue
                for marker in _decode_file_read_marker(output):
                    path = str(marker.get("path") or "")
                    expected = inventory_by_path.get(path)
                    expected_lines = expected.get("lines") if expected else None
                    if expected_lines is None:
                        expected_mode = str(
                            (expected or {}).get("review_mode") or "native_artifact"
                        )
                        mode_valid = (
                            marker.get("mode") == expected_mode
                            and expected_mode in {"native_artifact", "binary_artifact"}
                            and marker.get("start_line") is None
                            and marker.get("end_line") is None
                        )
                    else:
                        start_line = marker.get("start_line")
                        end_line = marker.get("end_line")
                        mode_valid = (
                            marker.get("mode") == "text_lines"
                            and isinstance(start_line, int)
                            and not isinstance(start_line, bool)
                            and isinstance(end_line, int)
                            and not isinstance(end_line, bool)
                            and 1 <= start_line <= end_line <= expected_lines
                        )
                    invocation_valid = any(
                        invocation.get("path") == path
                        and (
                            invocation.get("native") is True
                            if marker.get("mode") == "native_artifact"
                            else invocation.get("binary") is True
                            if marker.get("mode") == "binary_artifact"
                            else (
                                invocation.get("native") is False
                                and invocation.get("binary") is not True
                                and invocation.get("start") == marker.get("start_line")
                                and invocation.get("end") == marker.get("end_line")
                            )
                        )
                        for invocation in invocations
                    )
                    transcript_valid = False
                    nonempty_output_lines = [
                        line for line in output.splitlines() if line.strip()
                    ]
                    marker_is_last = bool(
                        nonempty_output_lines
                        and nonempty_output_lines[-1].startswith(_FILE_READ_MARKER)
                    )
                    if marker.get("mode") == "text_lines" and expected:
                        try:
                            source = worker_root / "code" / path
                            source_text = source.read_bytes().decode(
                                "utf-8", errors="replace"
                            )
                            source_lines = source_text.split("\n")
                            start = int(marker["start_line"])
                            end = int(marker["end_line"])
                            rendered = "\n".join(
                                f"{number:08d}: {source_lines[number - 1]}"
                                for number in range(start, end + 1)
                            )
                            receipt = nonempty_output_lines[-1]
                            expected_output = rendered + "\n" + receipt
                            transcript_valid = bool(
                                marker_is_last
                                and output.strip() == expected_output
                                and marker.get("chunk_sha256")
                                == hashlib.sha256(
                                    rendered.encode("utf-8", "replace")
                                ).hexdigest()
                            )
                        except (OSError, ValueError, IndexError, KeyError):
                            transcript_valid = False
                    elif (
                        marker.get("mode") in {"native_artifact", "binary_artifact"}
                        and expected
                    ):
                        expected_body = [(
                            "Binary artifact attested: "
                            f"{path} sha256={expected.get('sha256')} "
                            f"bytes={expected.get('bytes')}"
                        )]
                        evidence = [
                            str(value)
                            for value in expected.get("required_evidence", [])
                            if value
                        ]
                        if evidence:
                            expected_body.append(
                                "Required derived evidence (must also be fully read):"
                            )
                            expected_body.extend(f"- {value}" for value in evidence)
                        if not expected.get("analysis_complete", True):
                            expected_body.append(
                                "UNRESOLVED ANALYSIS LIMITATION: "
                                + str(expected.get("limitation", "unknown"))
                            )
                        expected_body.append(nonempty_output_lines[-1])
                        transcript_valid = bool(
                            marker_is_last
                            and output.strip() == "\n".join(expected_body)
                        )
                    valid = bool(
                        expected
                        and marker.get("schema_version") == 1
                        and marker.get("sha256") == expected.get("sha256")
                        and marker.get("bytes") == expected.get("bytes")
                        and marker.get("lines") == expected.get("lines")
                        and mode_valid
                        and invocation_valid
                        and transcript_valid
                    )
                    file_reads.append({
                        "schema_version": 1,
                        "worker_id": outcome.spec.id,
                        "slice_id": outcome.spec.slice_id,
                        "role": role,
                        "source_event_file": call["source_event_file"],
                        "tool_call_id": call["call_id"],
                        "path": path,
                        "inventory_sha256": expected.get("sha256") if expected else None,
                        "observed_sha256": marker.get("sha256"),
                        "bytes": marker.get("bytes"),
                        "lines": marker.get("lines"),
                        "mode": marker.get("mode"),
                        "start_line": marker.get("start_line"),
                        "end_line": marker.get("end_line"),
                        "status": "verified" if valid else "rejected",
                    })
    return tool_calls, file_reads


def _collect_finding_adjudications(
    inventory: dict[str, Any],
    finding_inventory: dict[str, Any],
    swarm: SwarmResult,
) -> list[dict[str, Any]]:
    """Build controller-validated, structured per-finding analyst/reviewer receipts."""

    expected_findings = {
        str(item.get("finding_id")): item
        for item in finding_inventory.get("findings", [])
        if isinstance(item, dict) and item.get("finding_id")
    }
    evidence_hashes = {
        str(item.get("path")): str(item.get("sha256"))
        for item in inventory.get("files", [])
        if isinstance(item, dict) and item.get("path") and item.get("sha256")
    }
    evidence_hashes["ANDROID_AUDIT.json"] = str(
        finding_inventory.get("audit_sha256") or ""
    )
    rows: list[dict[str, Any]] = []
    helper_sha = hashlib.sha256(
        _FINDING_ADJUDICATOR_SOURCE.encode("utf-8")
    ).hexdigest()
    for outcome in swarm.workers:
        root_value = getattr(outcome, "workspace_root", "")
        if not root_value:
            continue
        worker_root = Path(root_value)
        helper = worker_root / "code" / _FINDING_ADJUDICATOR_NAME
        try:
            helper_valid = helper.is_file() and not helper.is_symlink() and _sha256(helper) == helper_sha
        except OSError:
            helper_valid = False
        for event_path in _canonical_event_files(worker_root / "raw"):
            try:
                events = json.loads(event_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(events, list):
                continue
            role = _event_role(event_path)
            for record in _provider_command_records(events):
                command = str(record.get("command") or "")
                output = str(record.get("output") or "")
                invocations = _finding_adjudicator_invocations(command)
                if not invocations:
                    continue
                receipts = _decode_finding_adjudication(output)
                for receipt in receipts:
                    finding_id = str(receipt.get("finding_id") or "")
                    expected = expected_findings.get(finding_id)
                    evidence_path = str(receipt.get("evidence_path") or "")
                    expected_evidence_sha = evidence_hashes.get(evidence_path, "")
                    invocation_valid = any(
                        invocation["finding_id"] == finding_id
                        and invocation["verdict"] == receipt.get("verdict")
                        and invocation["evidence_path"] == evidence_path
                        for invocation in invocations
                    )
                    receipt_line = next(
                        (
                            line for line in output.splitlines()
                            if line.startswith(_FINDING_ADJUDICATION_MARKER)
                        ),
                        "",
                    )
                    expected_output = (
                        f"Finding adjudicated: {finding_id} "
                        f"verdict={receipt.get('verdict')} evidence={evidence_path} "
                        f"sha256={receipt.get('evidence_sha256')}\n{receipt_line}"
                    )
                    valid = bool(
                        record.get("succeeded")
                        and helper_valid
                        and expected
                        and receipt.get("schema_version") == 1
                        and receipt.get("finding_fingerprint") == expected.get("fingerprint")
                        and receipt.get("verdict") in {"confirmed", "rejected", "inconclusive"}
                        and expected_evidence_sha
                        and receipt.get("evidence_sha256") == expected_evidence_sha
                        and invocation_valid
                        and output.strip() == expected_output
                    )
                    rows.append({
                        "schema_version": 1,
                        "worker_id": outcome.spec.id,
                        "slice_id": outcome.spec.slice_id,
                        "role": role,
                        "source_event_file": event_path.relative_to(worker_root).as_posix(),
                        "tool_call_id": record.get("call_id"),
                        "finding_id": finding_id,
                        "finding_fingerprint": receipt.get("finding_fingerprint"),
                        "verdict": receipt.get("verdict"),
                        "evidence_path": evidence_path,
                        "evidence_sha256": receipt.get("evidence_sha256"),
                        "status": "verified" if valid else "rejected",
                    })
    return rows


def _ranges_cover_file(
    records: list[dict[str, Any]],
    lines: int | None,
    review_mode: str = "text_lines",
) -> bool:
    if lines is None:
        return any(item.get("mode") == review_mode for item in records)
    ranges = sorted(
        (int(item["start_line"]), int(item["end_line"]))
        for item in records
        if item.get("mode") == "text_lines"
        and isinstance(item.get("start_line"), int)
        and isinstance(item.get("end_line"), int)
    )
    next_line = 1
    for start, end in ranges:
        if start > next_line:
            return False
        next_line = max(next_line, end + 1)
        if next_line > lines:
            return True
    return next_line > lines


def _coverage_after_swarm(
    inventory: dict[str, Any],
    slices: dict[str, Any],
    swarm: SwarmResult,
    file_reads: list[dict[str, Any]] | None = None,
    finding_inventory: dict[str, Any] | None = None,
    finding_adjudications: list[dict[str, Any]] | None = None,
    finding_inventory_binding_valid: bool = True,
) -> dict[str, Any]:
    lineage_error = ""
    try:
        active_outcomes = project_active_worker_outcomes(list(swarm.workers))
    except AttributeError:
        # Lightweight unit-test doubles do not carry attempt-lineage fields.
        active_outcomes = list(swarm.workers)
    except RuntimeError as exc:
        # Invalid/ambiguous replacement lineage is a coverage failure. Historical
        # attempts must never be revived as evidence after projection fails.
        active_outcomes = []
        lineage_error = f"{type(exc).__name__}: {exc}"
    converged_workers = {
        (outcome.spec.id, outcome.spec.slice_id)
        for outcome in active_outcomes
        if outcome.converged and outcome.spec.slice_id
    }
    converged_slice_ids = {slice_id for _worker_id, slice_id in converged_workers}
    assigned_by_slice: dict[str, set[str]] = {}
    for item in slices.get("slices", []):
        slice_id = str(item.get("slice_id", ""))
        if slice_id.startswith("android-files-"):
            assigned_by_slice[slice_id] = {
                str(path) for path in item.get("ai_scope", {}).get("allowed_inputs", [])
            }
    inventory_by_path = {
        str(item["path"]): item for item in inventory.get("files", [])
    }
    accepted_reads = [
        item for item in (file_reads or [])
        if item.get("status") == "verified"
        and (item.get("worker_id"), item.get("slice_id")) in converged_workers
        and item.get("path") in assigned_by_slice.get(str(item.get("slice_id")), set())
    ]
    verified_files: set[str] = set()
    file_reviews: list[dict[str, Any]] = []

    def role_covers(path: str, role: str, worker_id: str | None = None) -> bool:
        item = inventory_by_path.get(path)
        if item is None:
            return False
        records = [
            read for read in accepted_reads
            if read.get("path") == path and read.get("role") == role
            and (worker_id is None or read.get("worker_id") == worker_id)
        ]
        return _ranges_cover_file(
            records,
            item.get("lines"),
            str(item.get("review_mode") or (
                "native_artifact" if item.get("lines") is None else "text_lines"
            )),
        )

    def workers_covering_bundle(
        path: str, evidence: list[str], role: str
    ) -> set[str]:
        return {
            worker_id
            for worker_id, _slice_id in converged_workers
            if role_covers(path, role, worker_id)
            and all(role_covers(item, role, worker_id) for item in evidence)
        }

    for path, inventory_item in sorted(inventory_by_path.items()):
        required_evidence = [
            str(item) for item in inventory_item.get("required_evidence", []) if item
        ]
        reviewer_reopened = any(
            read.get("path") == path and read.get("role") == "reviewer"
            for read in accepted_reads
        )
        analyst_workers = workers_covering_bundle(
            path, required_evidence, "analyst"
        )
        reviewer_workers = workers_covering_bundle(
            path, required_evidence, "reviewer"
        )
        same_worker_complete = sorted(analyst_workers & reviewer_workers)
        analyst_complete = bool(analyst_workers)
        reviewer_complete = bool(reviewer_workers)
        analysis_complete = bool(inventory_item.get("analysis_complete", True))
        verified = bool(same_worker_complete and analysis_complete)
        if verified:
            verified_files.add(path)
        file_reviews.append({
            "path": path,
            "sha256": inventory_item.get("sha256"),
            "review_mode": inventory_item.get("review_mode", "text_lines"),
            "required_evidence": required_evidence,
            "semantic_analysis_complete": analysis_complete,
            "limitation": inventory_item.get("limitation", ""),
            "analyst_read_complete": analyst_complete,
            "reviewer_reopened": reviewer_reopened,
            "reviewer_read_complete": reviewer_complete,
            "same_worker_ids": same_worker_complete,
            "verified": verified,
        })
    all_files = set(inventory_by_path)
    missing = sorted(all_files - verified_files)
    inventory_empty = not all_files
    member_closure_present = "apk_member_closure" in inventory
    member_closure = dict(inventory.get("apk_member_closure", {}))
    member_closure_complete = (
        bool(member_closure.get("complete")) if member_closure_present else True
    )
    finding_rows = list((finding_inventory or {}).get("findings", []))
    expected_finding_count = (finding_inventory or {}).get(
        "finding_count", len(finding_rows)
    )
    finding_ids = [
        str(item.get("finding_id"))
        for item in finding_rows
        if isinstance(item, dict) and item.get("finding_id") and item.get("fingerprint")
    ]
    finding_inventory_valid = bool(
        finding_inventory_binding_valid
        and (
        finding_inventory is None
        or (
            (finding_inventory or {}).get("schema_version") == 1
            and type(expected_finding_count) is int
            and expected_finding_count == len(finding_rows) == len(finding_ids)
            and len(set(finding_ids)) == len(finding_ids)
        )
        )
    )
    accepted_adjudications = [
        item for item in (finding_adjudications or [])
        if item.get("status") == "verified"
        and item.get("slice_id") == "android-findings-corroboration"
        and (item.get("worker_id"), item.get("slice_id")) in converged_workers
    ]
    finding_reviews: list[dict[str, Any]] = []
    missing_finding_ids: list[str] = []
    for finding_id in finding_ids:
        complete_worker = ""
        verdict = ""
        evidence_paths: list[str] = []
        for worker_id, slice_id in sorted(converged_workers):
            if slice_id != "android-findings-corroboration":
                continue
            analyst = [
                item for item in accepted_adjudications
                if item.get("worker_id") == worker_id
                and item.get("finding_id") == finding_id
                and item.get("role") == "analyst"
            ]
            reviewer = [
                item for item in accepted_adjudications
                if item.get("worker_id") == worker_id
                and item.get("finding_id") == finding_id
                and item.get("role") == "reviewer"
            ]
            analyst_verdicts = {str(item.get("verdict")) for item in analyst}
            reviewer_verdicts = {str(item.get("verdict")) for item in reviewer}
            if (
                len(analyst_verdicts) == 1
                and analyst_verdicts == reviewer_verdicts
                and all(item.get("evidence_path") for item in analyst + reviewer)
            ):
                complete_worker = worker_id
                verdict = next(iter(analyst_verdicts))
                evidence_paths = sorted({
                    str(item.get("evidence_path")) for item in analyst + reviewer
                })
                break
        complete = bool(complete_worker)
        if not complete:
            missing_finding_ids.append(finding_id)
        finding_reviews.append({
            "finding_id": finding_id,
            "worker_id": complete_worker,
            "verdict": verdict,
            "evidence_paths": evidence_paths,
            "analyst_reviewer_agreed": complete,
            "verified": complete,
        })
    finding_closure_complete = bool(
        finding_inventory_valid and not missing_finding_ids
    )
    return {
        "schema_version": 3,
        "method": (
            "file counted only after a converged assigned slice has hash-matched evidence-reader "
            "events covering the full analyst and reviewer text ranges; binary artifacts also "
            "require immutable derived evidence and a complete semantic-analysis producer"
        ),
        "inventory_files": len(all_files),
        "worker_slice_verified_files": len(verified_files),
        "coverage_complete": (
            not inventory_empty
            and not missing
            and not inventory.get("truncated", False)
            and member_closure_complete
            and finding_closure_complete
        ),
        "inventory_empty": inventory_empty,
        "inventory_truncated": bool(inventory.get("truncated", False)),
        "active_lineage_valid": not lineage_error,
        "active_lineage_error": lineage_error,
        "apk_member_closure_complete": member_closure_complete,
        "apk_member_closure": member_closure,
        "deterministic_finding_inventory_valid": finding_inventory_valid,
        "deterministic_findings_expected": len(finding_ids),
        "deterministic_findings_verified": len(finding_ids) - len(missing_finding_ids),
        "deterministic_finding_closure_complete": finding_closure_complete,
        "missing_finding_ids": missing_finding_ids,
        "finding_reviews": finding_reviews,
        "converged_slice_ids": sorted(converged_slice_ids),
        "missing_files": missing,
        "file_reviews": file_reviews,
    }


def _swarm_resume_payload(state_store: AuditStateStore) -> dict[str, Any]:
    """Resume the supervisor from its own committed swarm checkpoint (R7).

    ``run_android_ai_swarm`` previously always passed ``resume_payload=None``, so
    the on-disk snapshots were never read and every resume fresh-started the
    supervisor. Load the latest snapshot only when it is a swarm checkpoint; an
    absent store or an unrelated checkpoint kind yields an empty payload (fresh
    start) — a non-swarm checkpoint must never be misread as supervisor state.
    A corrupt chain surfaces loudly rather than silently discarding progress.
    """
    snapshot = state_store.load_latest()  # raises AuditStateError on corrupt chain
    if snapshot is None:
        return {}
    payload = snapshot.payload if isinstance(snapshot.payload, dict) else {}
    if payload.get("kind") != "swarm":
        return {}
    return payload


def _completed_materialization_progress(ws: RunWorkspace) -> dict[str, Any] | None:
    """Load the newest completed pre-AI checkpoint from durable state.

    Progress is written to ``raw/ANDROID_PRE_AI_PROGRESS.json`` before
    ``run.json`` is updated. A crash in that small window must not discard a
    completed materialization and restart thousands of artifacts.
    """
    candidates: list[dict[str, Any]] = []
    for key in ("android_pre_ai_checkpoint", "android_pre_ai_progress"):
        meta_progress = ws.meta.get(key) or {}
        if isinstance(meta_progress, dict):
            candidates.append(meta_progress)
    for filename in (
        "ANDROID_PRE_AI_CHECKPOINT.json",
        "ANDROID_PRE_AI_PROGRESS.json",
    ):
        progress_path = ws.raw_dir / filename
        if progress_path.is_file() and not progress_path.is_symlink():
            try:
                raw_progress = json.loads(progress_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, json.JSONDecodeError):
                raw_progress = None
            if isinstance(raw_progress, dict):
                candidates.append(raw_progress)
    completed = [
        candidate for candidate in candidates
        if candidate.get("materialization_complete") is True
        and candidate.get("final_materialization") is True
    ]
    if not completed:
        return None
    return max(completed, key=lambda value: int(value.get("updated_time_ns") or 0))


def _repair_evidence_scripts(ws: RunWorkspace) -> None:
    """Atomically restore cheap canonical helpers without rebuilding evidence."""
    for name, canonical_source in (
        (_EVIDENCE_READER_NAME, _EVIDENCE_READER_SOURCE),
        (_FINDING_ADJUDICATOR_NAME, _FINDING_ADJUDICATOR_SOURCE),
    ):
        script = ws.code_dir / name
        expected = hashlib.sha256(canonical_source.encode("utf-8")).hexdigest()
        if (
            script.is_file()
            and not script.is_symlink()
            and _sha256(script) == expected
        ):
            script.chmod(0o555)
            continue
        temporary = script.with_name(f".{script.name}.{time.time_ns()}.tmp")
        try:
            temporary.write_text(canonical_source, encoding="utf-8")
            temporary.chmod(0o555)
            temporary.replace(script)
        finally:
            if temporary.exists():
                temporary.unlink()


def _resume_materialized_overview(ws: RunWorkspace) -> dict[str, Any] | None:
    """Return the sealed pre-AI overview when materialization already completed.

    R8: ``run_android_ai_swarm`` re-materialized every resume (hours of IDA)
    because it never consulted ``ANDROID_PRE_AI_PROGRESS.json``. When the prior
    materialization sealed every inventory (``materialization_complete=True``)
    and each sealed artifact still matches its live sha256, return the saved
    overview so the swarm proceeds without re-disassembly. Return ``None`` when
    any gate fails, forcing the caller to materialize.
    """
    progress = _completed_materialization_progress(ws)
    if progress is None:
        return None
    sealed = progress.get("artifact_sha256")
    if not isinstance(sealed, dict):
        return None
    sealed_paths = {
        "source_inventory": ws.code_dir / "ANDROID_SOURCE_INVENTORY.json",
        "binary_inventory": ws.code_dir / "ANDROID_BINARY_INVENTORY.json",
        "finding_inventory": ws.code_dir / "ANDROID_FINDING_INVENTORY.json",
        "overview": ws.code_dir / "ANDROID_TARGET_OVERVIEW.json",
    }
    for key, path in sealed_paths.items():
        expected = sealed.get(key)
        if not isinstance(expected, str) or not path.is_file():
            return None
        if _sha256(path) != expected:
            return None
    # The supervisor updates slice statuses after every committed worker, so
    # security_slices.json is durable mutable execution state rather than an
    # immutable materialization artifact. Validate its structure, but never
    # compare it with the pre-dispatch seed hash or completed work would force
    # a full materialization on every resume.
    slices_path = ws.raw_dir / "security_slices.json"
    if not slices_path.is_file() or slices_path.is_symlink():
        return None
    try:
        slices_payload = json.loads(slices_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(slices_payload, dict) or not isinstance(
        slices_payload.get("slices"), list
    ):
        return None
    # Helper scripts are cheap derived files, not authority for the expensive
    # inventories. Repair source-version drift in place instead of turning one
    # missing helper into a full 33k-artifact materialization.
    _repair_evidence_scripts(ws)
    try:
        return json.loads(
            (ws.code_dir / "ANDROID_TARGET_OVERVIEW.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, json.JSONDecodeError):
        return None


def run_android_ai_swarm(
    *,
    apk_path: str | Path,
    report: AuditReport,
    workspace: RunWorkspace,
    agent: str = "claude",
    model: str | None = None,
    reviewer_agent: str = "auto",
    reviewer_model: str | None = None,
    reviewer_reasoning_effort: str = "high",
    dangerous_skip_permissions: bool = False,
    rounds: int = 2,
    parallel: int = 3,
) -> AndroidAISwarmOutcome:
    """Run the existing supervisor/worker/reviewer system over Android evidence."""
    from src.analysis.native_ownership_manifest import (
        bind_native_output_directory,
        native_routing_context,
        native_routing_targets,
    )

    native_static = report.metadata.get("native_static_evidence", {})
    if not isinstance(native_static, dict) or native_static.get("launch_blocked"):
        raise RuntimeError("native ownership routing prevents Android AI launch")
    routed = bool(native_static.get("ownership_manifest_path") or native_static.get("native_universe_path") or native_static.get("native_lane_epoch_id"))
    if routed:
        _routing, selected, policy_events, routing_binding = native_routing_context(
            native_static.get("ownership_manifest_path", ""),
            native_static.get("native_universe_path", ""),
        )
        _app_targets, _excluded_targets, hold_targets = native_routing_targets(
            selected, policy_events,
        )
        if hold_targets or native_static.get("native_routing") != routing_binding:
            raise RuntimeError("Android AI launch routing binding/HOLD check failed")
    else:
        from src.analysis.android_binary_inventory import require_non_native_artifacts
        require_non_native_artifacts(workspace.code_dir / "android_artifacts")
        if native_static.get("records") or any(
            item.get("format") == "elf"
            for item in report.metadata.get("binary_inventory", {}).get("members", [])
        ):
            raise RuntimeError("native artifacts require signed ownership routing")
    routed_evidence_output = (
        workspace.code_dir / "android_artifacts" / "_angerona_binary_evidence"
    )
    overview = _resume_materialized_overview(workspace)
    if routed and overview is not None and not (routed_evidence_output / "NATIVE_ROUTED_OUTPUT.json").is_file():
        raise RuntimeError("legacy Android AI materialization is superseded-read-only")
    if routed:
        bind_native_output_directory(
            routed_evidence_output,
            lane="native-ai-evidence",
            lane_epoch_id=str(native_static.get("native_lane_epoch_id") or ""),
            routing_binding=routing_binding,
        )
    if overview is None:
        overview = materialize_android_ai_evidence(workspace, report)
    inventory = json.loads(
        (workspace.code_dir / "ANDROID_SOURCE_INVENTORY.json").read_text(encoding="utf-8")
    )
    finding_inventory = json.loads(
        (workspace.code_dir / "ANDROID_FINDING_INVENTORY.json").read_text(
            encoding="utf-8"
        )
    )
    finding_inventory_binding = _validate_finding_inventory(
        report, workspace.code_dir, finding_inventory
    )
    slices = json.loads(
        (workspace.raw_dir / "security_slices.json").read_text(encoding="utf-8")
    )
    if agent not in {"claude", "codex"}:
        raise ValueError(f"unsupported Android AI agent: {agent!r}")
    if reviewer_agent not in {"auto", "claude", "codex"}:
        raise ValueError(f"unsupported Android reviewer agent: {reviewer_agent!r}")
    runtimes = {
        "claude": ClaudeCodeAgent(),
        "codex": CodexAgent(),
    }
    if not runtimes[agent].available():
        raise RuntimeError(f"{agent} CLI is required for the Android AI swarm")
    selected_reviewer = reviewer_agent
    if selected_reviewer == "auto":
        selected_reviewer = "codex" if runtimes["codex"].available() else agent
    elif not runtimes[selected_reviewer].available():
        # Review availability is an optimization, not a reason to lose the
        # authorized audit. Fail over to the proven primary provider.
        selected_reviewer = agent
    # Keep the empty Claude MCP config in the controller workspace, not inside
    # a candidate worker. Required candidate isolation replaces the worker root
    # with a scratch symlink before mounting config files; an in-worker config
    # path would therefore be impossible for bubblewrap to create safely.
    claude_mcp_path = workspace.raw_dir / "android-claude-mcp.json"
    claude_mcp_path.write_text('{"mcpServers":{}}\n', encoding="utf-8")

    def dispatch(
        agent: str,
        task: str,
        system_prompt: str,
        on_event,
        cwd_override: str | None = None,
        allowed_tools: list[str] | None = None,
        skip_permissions: bool = True,
        budget_priority: str = "normal",
        budget_phase: str = "android-ai",
        isolation_required: bool = False,
    ):
        del skip_permissions, budget_priority, budget_phase
        if agent not in available_agents:
            raise ValueError(
                f"Android AI swarm cannot dispatch {agent!r}; available={sorted(available_agents)!r}"
            )
        read_only = allowed_tools == ["Read"]
        effective_cwd = Path(cwd_override or workspace.code_dir).resolve()
        required_isolation = _dispatch_requires_isolation(
            workspace.code_dir, effective_cwd, isolation_required
        )
        if agent == "claude":
            return runtimes["claude"].run(
                task,
                system_prompt=system_prompt,
                mcp_config_path=str(claude_mcp_path),
                allowed_tools=allowed_tools or ["Read", "Bash"],
                cwd=str(effective_cwd),
                target_binary=None,
                model=model,
                # The Android swarm only needs local evidence reads.  Keep
                # Claude Code in its explicit allowlist mode so Web/Search,
                # edits, and nested agents cannot be selected by a worker.
                skip_permissions=dangerous_skip_permissions,
                idle_timeout=300.0,
                wall_timeout=1800.0,
                on_event=on_event,
                isolation_required=required_isolation,
            )
        result = runtimes["codex"].run(
            task,
            system_prompt=system_prompt,
            mcp_command="",
            mcp_args=[],
            mcp_env={},
            cwd=str(effective_cwd),
            server_name="disabled",
            target_binary=None,
            model=reviewer_model or model,
            reasoning_effort=reviewer_reasoning_effort,
            sandbox="read-only" if read_only else "workspace-write",
            full_access=bool(dangerous_skip_permissions or required_isolation),
            idle_timeout=300.0,
            wall_timeout=1800.0,
            on_event=on_event,
            enable_mcp=False,
            isolation_required=required_isolation,
        )
        if result.ok or selected_agent != "claude":
            return result
        # Codex may be installed while its selected model/quota is unavailable.
        # Preserve the independent-review role by replaying the exact immutable
        # task through the primary Claude/GLM runtime.
        return runtimes["claude"].run(
            task,
            system_prompt=system_prompt,
            mcp_config_path=str(claude_mcp_path),
            allowed_tools=allowed_tools or ["Read", "Bash"],
            cwd=str(effective_cwd),
            target_binary=None,
            model=model,
            skip_permissions=dangerous_skip_permissions,
            idle_timeout=300.0,
            wall_timeout=1800.0,
            on_event=on_event,
            isolation_required=required_isolation,
        )

    selected_agent = agent
    available_agents = {selected_agent, selected_reviewer}
    attest_isolation_capable_dispatch(dispatch)
    config = load_config(default_engine())
    state_store = AuditStateStore(workspace.root)
    resume_payload = _swarm_resume_payload(state_store)
    try:
        state_store.acquire_lease()
        loop = SupervisorLoop(
            binary=str(Path(apk_path).expanduser().resolve()),
            objective=(
                "Perform an authorized, exhaustive Android APK reverse-engineering security "
                "audit. Divide the machine-authored file inventory across workers, require "
                "exact file/line/function evidence, corroborate deterministic findings, hunt "
                "for missed vulnerabilities, and consolidate only reviewer-verified claims."
            ),
            overview=json.dumps(overview, indent=2),
            workspace=workspace,
            dispatch=dispatch,
            supervisor_agent=selected_agent,
            worker_analyst=selected_agent,
            worker_reviewer=selected_reviewer,
            max_supervisor_rounds=rounds,
            max_worker_rounds=rounds,
            max_parallel=parallel,
            engine="android",
            cfg=config,
            k_candidates=1,
            adversarial_review=True,
            topo_strategy="fixed",
            # The Android adapter already built bounded, cost-balanced authoritative
            # file/finding slices.  Do not ask the model to invent duplicate work
            # units before analysis; supervisors still consolidate worker verdicts.
            spawn_strategy="slices",
            # Every authoritative slice needs at least one analyst candidate.
            # max_parallel still bounds concurrent processes; spawn_budget is
            # the global candidate allocation and cannot be lower than the
            # number of pending slice work units.
            spawn_budget=max(1, len(slices.get("slices", []))),
            strict_verify=False,
            cheap_agent=selected_agent,
            available_agents=available_agents,
            defer_workspace_finish=True,
            state_store=state_store,
            resume_payload=resume_payload,
        )
        swarm = loop.run()
    finally:
        state_store.release_lease()
        state_store.close()
    tool_calls, file_reads = _collect_worker_ledgers(inventory, swarm)
    finding_adjudications = _collect_finding_adjudications(
        inventory, finding_inventory, swarm
    )
    coverage = _coverage_after_swarm(
        inventory,
        slices,
        swarm,
        file_reads,
        finding_inventory,
        finding_adjudications,
        finding_inventory_binding_valid=bool(finding_inventory_binding["valid"]),
    )
    coverage["deterministic_finding_inventory_binding"] = finding_inventory_binding
    (workspace.raw_dir / "ANDROID_TOOL_CALL_LEDGER.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in tool_calls),
        encoding="utf-8",
    )
    (workspace.raw_dir / "ANDROID_FILE_REVIEW_LEDGER.jsonl").write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in file_reads),
        encoding="utf-8",
    )
    (workspace.raw_dir / "ANDROID_FINDING_ADJUDICATION_LEDGER.jsonl").write_text(
        "".join(
            json.dumps(item, sort_keys=True) + "\n"
            for item in finding_adjudications
        ),
        encoding="utf-8",
    )
    coverage_path = workspace.code_dir / "ANDROID_AI_COVERAGE.json"
    coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    model_swarm_converged = bool(swarm.converged)
    try:
        final_finding_inventory = json.loads(
            (workspace.code_dir / "ANDROID_FINDING_INVENTORY.json").read_text(
                encoding="utf-8"
            )
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        final_finding_inventory = {}
    final_finding_binding = _validate_finding_inventory(
        report, workspace.code_dir, final_finding_inventory
    )
    coverage["deterministic_finding_inventory_binding"] = final_finding_binding
    if not final_finding_binding["valid"]:
        coverage["deterministic_finding_inventory_valid"] = False
        coverage["deterministic_finding_closure_complete"] = False
        coverage["coverage_complete"] = False
        coverage_path.write_text(json.dumps(coverage, indent=2) + "\n", encoding="utf-8")
    # Validate the immutable report bytes before appending the final APK identity
    # gate to the in-memory report; that terminal gate was not part of the
    # deterministic evidence shown to workers.
    final_identity = _revalidate_apk_identity(report, apk_path)
    final_identity_valid = bool(final_identity["valid"])
    final_apk_sha = str(final_identity["sha256"])
    completion_gates = _evaluate_android_completion(
        report, coverage, model_swarm_converged=model_swarm_converged
    )
    deterministic_gate = report.metadata.get("coverage_gate", {})
    runtime_required = completion_gates["runtime_required"]
    runtime_complete = completion_gates["runtime_complete"]
    static_complete = completion_gates["static_complete"]
    deterministic_complete = completion_gates["deterministic_complete"]
    overall_complete = completion_gates["overall_complete"]
    if not overall_complete:
        swarm.converged = False
        if not coverage["coverage_complete"]:
            gate_reason = (
                "artifact_inventory_empty" if coverage.get("inventory_empty")
                else "android_file_coverage_incomplete"
            )
        elif not deterministic_complete:
            gate_reason = "android_deterministic_or_runtime_gate_incomplete"
        else:
            gate_reason = "android_swarm_not_converged"
        swarm.incomplete_reason = swarm.incomplete_reason or gate_reason
        limitation = (
            "# ANDROID RUN STATUS: INCOMPLETE\n\n"
            "## Canonical Android completion limitation\n\n"
            f"Reviewer-converged file slices covered {coverage['worker_slice_verified_files']}/"
            f"{coverage['inventory_files']} inventoried files. Deterministic status is "
            f"`{report.status}` and runtime required/complete is "
            f"`{runtime_required}/{runtime_complete}`. Uncovered evidence is listed in "
            "`code/ANDROID_AI_COVERAGE.json`; this run does not make a total-audit claim.\n"
        )
        if not swarm.final_report.startswith("# ANDROID RUN STATUS: INCOMPLETE"):
            swarm.final_report = limitation + "\n" + swarm.final_report
            (workspace.docs_dir / "consolidated_report.md").write_text(
                swarm.final_report, encoding="utf-8"
            )
    tool_failures = sum(item["status"] == "failed" for item in tool_calls)
    completion = {
        "schema_version": 2,
        "status": "complete" if overall_complete else "incomplete",
        "completion_class": (
            "total_complete" if overall_complete else
            "static_complete_dynamic_unresolved"
            if (coverage["coverage_complete"] and static_complete
                and runtime_required and not runtime_complete) else
            "incomplete"
        ),
        "swarm_converged": bool(swarm.converged),
        "model_swarm_converged_before_android_gates": model_swarm_converged,
        "overall_complete": overall_complete,
        "apk_identity": {
            "valid": final_identity_valid,
            "sha256": final_apk_sha,
        },
        "incomplete_reason": swarm.incomplete_reason,
        "deterministic": {
            "report_status": report.status,
            "complete": deterministic_complete,
            "static_complete": static_complete,
            "refusal_reasons": list(report.refusal_reasons),
            "coverage_gate": deterministic_gate,
            "runtime_required": runtime_required,
            "runtime_complete": runtime_complete,
        },
        "files": {
            "inventoried": coverage["inventory_files"],
            "verified": coverage["worker_slice_verified_files"],
            "missing": len(coverage["missing_files"]),
            "inventory_truncated": coverage["inventory_truncated"],
        },
        "findings": {
            "expected": coverage["deterministic_findings_expected"],
            "verified": coverage["deterministic_findings_verified"],
            "missing": len(coverage["missing_finding_ids"]),
            "closure_complete": coverage[
                "deterministic_finding_closure_complete"
            ],
        },
        "tools": {
            "completed_calls": len(tool_calls),
            "failed_calls": tool_failures,
            "successful_calls": len(tool_calls) - tool_failures,
        },
        "workers": {
            "total": len(swarm.workers),
            "converged": sum(bool(item.converged) for item in swarm.workers),
        },
        "artifacts": {
            "coverage": "code/ANDROID_AI_COVERAGE.json",
            "file_review_ledger": "raw/ANDROID_FILE_REVIEW_LEDGER.jsonl",
            "tool_call_ledger": "raw/ANDROID_TOOL_CALL_LEDGER.jsonl",
            "finding_adjudication_ledger": (
                "raw/ANDROID_FINDING_ADJUDICATION_LEDGER.jsonl"
            ),
            "observability": "raw/observability/events.jsonl",
        },
        "observability_verification": None,
    }
    workspace.mark_finalizing(note="committing canonical Android completion artifacts")
    workspace.meta["android_ai_coverage"] = coverage
    # Capture the terminal ledger head before publishing any completed state.  A
    # verification failure is itself a completion-gate failure, not an exception
    # path that may leave the previously persisted run.json saying completed.
    try:
        observability_verification = workspace.observability.verify()
        if observability_verification.get("valid") is not True:
            raise RuntimeError("observability verification returned an invalid result")
        completion["observability_verification"] = observability_verification
    except Exception as exc:  # noqa: BLE001 - any ledger failure must fail closed
        swarm.converged = False
        swarm.incomplete_reason = "android_observability_verification_failed"
        completion.update({
            "status": "incomplete",
            "completion_class": "incomplete",
            "swarm_converged": False,
            "overall_complete": False,
            "incomplete_reason": swarm.incomplete_reason,
            "observability_verification": {
                "valid": False,
                "error": f"{type(exc).__name__}: {exc}",
            },
        })
        workspace.meta.update({
            "status": "incomplete",
            "converged": False,
            "note": swarm.incomplete_reason,
        })
        limitation = (
            "# ANDROID RUN STATUS: INCOMPLETE\n\n"
            "## Observability verification failed\n\n"
            "The controller could not verify the authoritative hash-chained event ledger; "
            "this run does not make a total-audit claim.\n\n"
        )
        if not swarm.final_report.startswith("# ANDROID RUN STATUS: INCOMPLETE"):
            swarm.final_report = limitation + swarm.final_report
            (workspace.docs_dir / "consolidated_report.md").write_text(
                swarm.final_report, encoding="utf-8"
            )
    commit_id = uuid.uuid4().hex
    completion["terminal_commit_id"] = commit_id
    terminal_meta = dict(workspace.meta)
    terminal_meta.update({
        "status": "completed" if completion["overall_complete"] else "incomplete",
        "converged": bool(completion["overall_complete"]),
        "total_rounds": int(getattr(swarm, "supervisor_rounds", 0)),
        "finished": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "note": (
            "Android total audit complete"
            if completion["overall_complete"] else swarm.incomplete_reason
        ),
        "terminal_commit_id": commit_id,
        "android_ai_coverage": coverage,
        "android_ai_completion": completion,
    })
    try:
        _atomic_replace_json(
            workspace.raw_dir / "ANDROID_RUN_COMPLETION.json", completion
        )
        # run.json is the public terminal pointer and is deliberately committed
        # last. Before this replacement the run remains visibly finalizing.
        _atomic_replace_json(workspace.root / "run.json", terminal_meta)
        workspace.meta = terminal_meta
    except OSError as exc:
        swarm.converged = False
        swarm.incomplete_reason = "android_terminal_commit_failed"
        completion.update({
            "status": "incomplete",
            "completion_class": "incomplete",
            "swarm_converged": False,
            "overall_complete": False,
            "incomplete_reason": swarm.incomplete_reason,
            "terminal_commit_error": f"{type(exc).__name__}: {exc}",
        })
        recovery_meta = dict(workspace.meta)
        recovery_meta.update({
            "status": "incomplete", "converged": False,
            "note": swarm.incomplete_reason,
            "terminal_commit_id": commit_id,
            "android_ai_completion": completion,
        })
        # Best-effort fail-closed recovery. If either write remains impossible,
        # propagate so the CLI cannot advertise a successfully committed run.
        _atomic_replace_json(
            workspace.raw_dir / "ANDROID_RUN_COMPLETION.json", completion
        )
        _atomic_replace_json(workspace.root / "run.json", recovery_meta)
        workspace.meta = recovery_meta
    return AndroidAISwarmOutcome(swarm=swarm, workspace=workspace.root, coverage=coverage)
