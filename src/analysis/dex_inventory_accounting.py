"""Independent, exhaustive DEX-to-semantic-queue accounting."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterable

from src.analysis.audit_lineage import (
    atomic_write,
    canonical,
    open_verified_artifact,
    sha256_bytes,
    sha256_path,
)
from src.analysis.semantic_method_evidence_verifier import validate_semantic_method_evidence
from src.analysis.dex_reconstruction_receipt import build_apk_dex_receipts


SCHEMA = "angerona/dex-code-method-accounting/v1"


def _allowed_paths(allowed_roots: str | Path | Iterable[str | Path]) -> list[Path]:
    values = [allowed_roots] if isinstance(allowed_roots, (str, Path)) else list(allowed_roots)
    roots = [Path(value).resolve(strict=True) for value in values]
    if not roots:
        raise ValueError("at least one accounting trust root is required")
    return roots


def _strict_path(
    path: str | Path, allowed_roots: str | Path | Iterable[str | Path],
) -> Path:
    raw = Path(path)
    if not raw.is_absolute():
        raise ValueError(f"accounting path is not absolute: {raw}")
    lexical = Path(os.path.abspath(raw))
    resolved = raw.resolve(strict=True)
    if lexical != resolved:
        raise ValueError(f"symlinked accounting path is forbidden: {raw}")
    for allowed in _allowed_paths(allowed_roots):
        try:
            resolved.relative_to(allowed)
            return resolved
        except ValueError:
            continue
    raise ValueError(f"accounting path escapes allowed roots: {resolved}")


def _artifact(
    path: Path, allowed_roots: str | Path | Iterable[str | Path],
) -> dict[str, str]:
    resolved = _strict_path(path, allowed_roots)
    return {"path": str(resolved), "sha256": sha256_path(resolved)}


def build_dex_code_method_accounting(
    apk: str | Path,
    apk_content_manifest: str | Path,
    queue: str | Path,
    summary: str | Path,
    validation: str | Path,
    dex_root: str | Path,
    raw_rebuild_root: str | Path,
    allowed_roots: Iterable[str | Path],
    output_path: str | Path,
) -> dict[str, Any]:
    allowed = _allowed_paths(allowed_roots)
    apk_path = _strict_path(apk, allowed)
    apk_manifest_path = _strict_path(apk_content_manifest, allowed)
    queue_path = _strict_path(queue, allowed)
    summary_path = _strict_path(summary, allowed)
    validation_path = _strict_path(validation, allowed)
    dex_path = _strict_path(dex_root, allowed)
    raw_root = Path(raw_rebuild_root)
    raw_root.mkdir(parents=True, exist_ok=True)
    raw_root = _strict_path(raw_root, allowed)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    _strict_path(output.parent, allowed)

    apk_descriptor = _artifact(apk_path, allowed)
    apk_manifest = json.loads(apk_manifest_path.read_bytes())
    if apk_manifest.get("schema") != "angerona/apk-content-manifest/v2":
        raise ValueError("unknown APK content manifest schema")
    unsigned_apk_manifest = {
        key: value for key, value in apk_manifest.items() if key != "manifest_sha256"
    }
    if apk_manifest.get("manifest_sha256") != sha256_bytes(canonical(unsigned_apk_manifest)):
        raise ValueError("APK content manifest self-hash mismatch")
    if (
        apk_manifest.get("apk_sha256") != apk_descriptor["sha256"]
        or str(Path(str(apk_manifest.get("apk_path") or "")).resolve(strict=True)) != str(apk_path)
        or not apk_manifest.get("archive_byte_partition_complete")
    ):
        raise ValueError("APK content manifest does not bind the exact APK")

    raw_aggregate = build_apk_dex_receipts(apk_path, raw_root)
    raw_manifest_path = raw_root / "DEX_TARGETS.json"
    raw_targets: dict[str, dict[str, Any]] = {}
    raw_receipts: dict[str, tuple[dict[str, Any], dict[str, str]]] = {}
    for target in raw_aggregate.get("targets") or []:
        dex_sha = str(target.get("content_sha256") or "")
        target_path = raw_root / "dex" / dex_sha / "DEX_TARGET_RECEIPT.json"
        target_row = json.loads(target_path.read_bytes())
        unsigned_target = {key: value for key, value in target_row.items() if key != "receipt_sha256"}
        if target_row.get("receipt_sha256") != sha256_bytes(canonical(unsigned_target)):
            raise ValueError(f"raw DEX target self-hash mismatch: {target_path}")
        raw_targets[dex_sha] = target_row
        for receipt_path in sorted((target_path.parent / "methods").glob("*.json")):
            descriptor = _artifact(receipt_path, allowed)
            receipt = json.loads(receipt_path.read_bytes())
            method_id = str(receipt.get("method_id") or "")
            if not method_id or method_id in raw_receipts:
                raise ValueError(f"duplicate raw DEX method identity: {method_id}")
            raw_receipts[method_id] = (receipt, descriptor)

    packaged_dex = sorted(
        (str(row.get("name") or ""), str(row.get("content_sha256") or ""), int(row.get("content_bytes") or 0))
        for row in apk_manifest.get("entries") or [] if row.get("classification") == "dex"
    )
    rebuilt_dex = sorted(
        (str(row.get("member_name") or ""), str(row.get("content_sha256") or ""), int(row.get("content_bytes") or 0))
        for row in raw_targets.values()
    )
    if packaged_dex != rebuilt_dex:
        raise ValueError("raw rebuilt DEX entry set differs from APK content manifest")

    summary_row = json.loads(summary_path.read_bytes())
    if summary_row.get("schema") != "angerona/jadx-method-evidence/v4":
        raise ValueError("DEX accounting requires JADX method evidence v4")
    unsigned_summary = {key: value for key, value in summary_row.items() if key != "manifest_sha256"}
    if summary_row.get("manifest_sha256") != sha256_bytes(canonical(unsigned_summary)):
        raise ValueError("JADX method evidence manifest self-hash mismatch")

    validation_row = json.loads(validation_path.read_bytes())
    live_validation = validate_semantic_method_evidence(
        queue_path, summary_path, allowed_root=next(
            root for root in allowed if queue_path.is_relative_to(root)
        ),
    )
    if not live_validation.get("valid") or live_validation.get("issues"):
        raise ValueError(f"live semantic method validation failed: {live_validation.get('issues')}")
    for key in ("schema", "queue_sha256", "summary_sha256", "units", "unique_methods", "valid"):
        if validation_row.get(key) != live_validation.get(key):
            raise ValueError(f"stored semantic validation differs from live validation: {key}")
    if validation_row.get("issues"):
        raise ValueError("stored semantic validation contains issues")

    queue_rows: dict[str, dict[str, Any]] = {}
    with queue_path.open(encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            row = json.loads(line)
            method_id = str(row.get("method_id") or "")
            if row.get("schema") != "angerona/semantic-method-work-unit/v4":
                raise ValueError(f"unexpected queue schema at line {line_number}")
            if not method_id or method_id in queue_rows:
                raise ValueError(f"missing or duplicate queue method at line {line_number}")
            queue_rows[method_id] = row

    inventory: dict[str, dict[str, Any]] = {}
    per_dex: dict[str, dict[str, int]] = {}
    receipt_paths = sorted(dex_path.glob("*/methods/*.json"))
    if not receipt_paths:
        raise ValueError("DEX receipt inventory is empty")
    for receipt_path in receipt_paths:
        descriptor = _artifact(receipt_path, allowed)
        verified_path, payload = open_verified_artifact(descriptor, allowed)
        receipt = json.loads(payload)
        if receipt.get("schema") != "angerona/dex-method-receipt/v2":
            raise ValueError(f"unexpected DEX method receipt schema: {verified_path}")
        method_id = str(receipt.get("method_id") or "")
        if not method_id or method_id in inventory:
            raise ValueError(f"missing or duplicate DEX method ID: {method_id}")
        dex_sha = str(receipt.get("dex_sha256") or "")
        if not dex_sha:
            raise ValueError(f"DEX receipt omits DEX identity: {verified_path}")
        code_bearing = bool(receipt.get("code_offset"))
        if code_bearing and not receipt.get("defined"):
            raise ValueError(f"code-bearing method is not defined: {method_id}")
        raw_pair = raw_receipts.get(method_id)
        if raw_pair is None:
            raise ValueError(f"materialized receipt has no raw APK-derived method: {method_id}")
        raw_receipt, raw_descriptor = raw_pair
        if payload != canonical(raw_receipt):
            raise ValueError(f"materialized receipt differs from raw APK-derived receipt: {method_id}")
        inventory[method_id] = {
            "method_id": method_id,
            "dex_sha256": dex_sha,
            "qualified_name": str(receipt.get("qualified_name") or ""),
            "defined": bool(receipt.get("defined")),
            "code_bearing": code_bearing,
            "receipt_path": str(verified_path),
            "receipt_sha256": descriptor["sha256"],
            "raw_receipt_path": raw_descriptor["path"],
            "raw_receipt_sha256": raw_descriptor["sha256"],
            "method_index": int(receipt.get("method_index") or 0),
            "access_flags": receipt.get("access_flags"),
            "code_offset": receipt.get("code_offset"),
            "status": str(receipt.get("status") or ""),
        }
        counts = per_dex.setdefault(dex_sha, {"methods": 0, "defined_methods": 0, "code_methods": 0})
        counts["methods"] += 1
        counts["defined_methods"] += int(bool(receipt.get("defined")))
        counts["code_methods"] += int(code_bearing)

    if set(inventory) != set(raw_receipts):
        raise ValueError("materialized receipt method set differs from raw APK-derived method set")

    code_inventory = {method_id: row for method_id, row in inventory.items() if row["code_bearing"]}
    queue_ids = set(queue_rows)
    code_ids = set(code_inventory)
    if queue_ids != code_ids:
        missing = sorted(code_ids - queue_ids)
        extra = sorted(queue_ids - code_ids)
        raise ValueError(
            f"semantic queue is not exhaustive for code methods: missing={missing[:3]} extra={extra[:3]}"
        )
    for method_id, unit in queue_rows.items():
        receipts = [item for item in unit.get("inputs") or [] if item.get("kind") == "dex-method-receipt"]
        if len(receipts) != 1:
            raise ValueError(f"queue method lacks exactly one DEX receipt: {method_id}")
        expected = code_inventory[method_id]
        item = receipts[0]
        if (
            str(Path(str(item.get("path"))).resolve(strict=True)) != expected["receipt_path"]
            or item.get("sha256") != expected["receipt_sha256"]
            or str(unit.get("qualified_name") or "") != expected["qualified_name"]
        ):
            raise ValueError(f"queue-to-DEX receipt binding mismatch: {method_id}")

    if int(summary_row.get("dex_method_count") or -1) != len(inventory):
        raise ValueError("JADX summary total method count differs from independent inventory")
    if int(summary_row.get("code_method_work_units") or -1) != len(code_inventory):
        raise ValueError("JADX summary code method count differs from independent inventory")
    ordered = [inventory[method_id] for method_id in sorted(inventory)]
    code_method_ids = sorted(code_inventory)
    code_id_stream_sha = sha256_bytes(b"".join((value + "\n").encode() for value in code_method_ids))
    unqueued_methods = []
    for method_id, row in sorted(inventory.items()):
        if row["code_bearing"]:
            disposition = "queued_code_method"
            reason = "defined method has nonzero code_off"
        elif not row["defined"]:
            disposition = "terminal_external_reference"
            reason = "method table entry is not defined by class_data"
        else:
            flags = int(row.get("access_flags") or 0)
            if not flags & (0x100 | 0x400):
                raise ValueError(f"defined no-code method is neither native nor abstract: {method_id}")
            disposition = "terminal_native_or_abstract"
            reason = "defined method has zero code_off and native/abstract access flag"
        row["disposition"] = disposition
        row["disposition_reason"] = reason
        if not row["code_bearing"]:
            unqueued_methods.append(row)
    inventory_stream_sha = sha256_bytes(b"".join(canonical(row) for row in ordered))

    body: dict[str, Any] = {
        "schema": SCHEMA,
        "apk": apk_descriptor,
        "apk_content_manifest": _artifact(apk_manifest_path, allowed),
        "queue": _artifact(queue_path, allowed),
        "jadx_method_evidence": _artifact(summary_path, allowed),
        "stored_validation": _artifact(validation_path, allowed),
        "raw_dex_rebuild_manifest": _artifact(raw_manifest_path, allowed),
        "raw_dex_rebuild_manifest_sha256": raw_aggregate["manifest_sha256"],
        "raw_dex_targets": [
            {
                "member_name": row["member_name"],
                "content_sha256": dex_sha,
                "content_bytes": row["content_bytes"],
                "method_ids": row["method_ids"],
                "defined_methods": row["defined_methods"],
                "code_methods": row["code_methods"],
                "receipt": _artifact(
                    raw_root / "dex" / dex_sha / "DEX_TARGET_RECEIPT.json", allowed,
                ),
            }
            for dex_sha, row in sorted(raw_targets.items())
        ],
        "dex_receipt_root": str(dex_path),
        "dex_receipt_inventory_sha256": inventory_stream_sha,
        "dex_receipt_inventory_projection": "complete emitted method_accounting_rows in method_id order",
        "method_receipts": len(inventory),
        "defined_methods": sum(row["defined"] for row in inventory.values()),
        "code_methods": len(code_inventory),
        "queue_methods": len(queue_rows),
        "code_method_ids": code_method_ids,
        "method_accounting_rows": ordered,
        "unqueued_methods": unqueued_methods,
        "code_method_id_stream_sha256": code_id_stream_sha,
        "per_dex": dict(sorted(per_dex.items())),
        "live_validation": live_validation,
        "exact_code_method_set_match": True,
        "exhaustive_code_method_accounting": True,
        "negative_lookup_authority": "only within this exact code_method_ids set",
    }
    receipt = {**body, "receipt_sha256": sha256_bytes(canonical(body))}
    atomic_write(output, canonical(receipt), immutable=True)
    return receipt


def verify_dex_code_method_accounting(
    receipt_path: str | Path,
    *,
    allowed_roots: Iterable[str | Path],
    verification_root: str | Path,
) -> dict[str, Any]:
    allowed = _allowed_paths(allowed_roots)
    path = _strict_path(receipt_path, allowed)
    receipt = json.loads(path.read_bytes())
    if receipt.get("schema") != SCHEMA:
        raise ValueError("unknown DEX code-method accounting schema")
    unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    if receipt.get("receipt_sha256") != sha256_bytes(canonical(unsigned)):
        raise ValueError("DEX code-method accounting self-hash mismatch")
    for key in (
        "apk", "apk_content_manifest", "queue", "jadx_method_evidence",
        "stored_validation", "raw_dex_rebuild_manifest",
    ):
        open_verified_artifact(receipt[key], allowed)
    for target in receipt.get("raw_dex_targets") or []:
        open_verified_artifact(target["receipt"], allowed)
    for row in receipt.get("method_accounting_rows") or []:
        open_verified_artifact(
            {"path": row["receipt_path"], "sha256": row["receipt_sha256"]}, allowed,
        )
        open_verified_artifact(
            {"path": row["raw_receipt_path"], "sha256": row["raw_receipt_sha256"]}, allowed,
        )
    code_ids = list(receipt.get("code_method_ids") or [])
    if len(code_ids) != len(set(code_ids)) or len(code_ids) != int(receipt.get("code_methods") or -1):
        raise ValueError("DEX accounting code-method identity set is malformed")
    observed_stream = sha256_bytes(b"".join((value + "\n").encode() for value in code_ids))
    if observed_stream != receipt.get("code_method_id_stream_sha256"):
        raise ValueError("DEX accounting code-method identity stream mismatch")
    verification = Path(verification_root)
    verification.mkdir(parents=True, exist_ok=True)
    verification = _strict_path(verification, allowed)
    rebuilt = build_apk_dex_receipts(receipt["apk"]["path"], verification)
    if rebuilt.get("manifest_sha256") != receipt.get("raw_dex_rebuild_manifest_sha256"):
        raise ValueError("fresh raw APK DEX rebuild differs from accounting receipt")
    fresh_rows: dict[str, tuple[dict[str, Any], bytes, str]] = {}
    for target in rebuilt.get("targets") or []:
        dex_sha = str(target["content_sha256"])
        for candidate in sorted((verification / "dex" / dex_sha / "methods").glob("*.json")):
            payload = candidate.read_bytes()
            row = json.loads(payload)
            method_id = str(row["method_id"])
            if method_id in fresh_rows:
                raise ValueError(f"fresh raw APK rebuild has duplicate method: {method_id}")
            fresh_rows[method_id] = (row, payload, sha256_bytes(payload))
    recorded_list = list(receipt.get("method_accounting_rows") or [])
    recorded_rows: dict[str, dict[str, Any]] = {}
    expected_rows: list[dict[str, Any]] = []
    expected_per_dex: dict[str, dict[str, int]] = {}
    for recorded in recorded_list:
        method_id = str(recorded.get("method_id") or "")
        if not method_id or method_id in recorded_rows:
            raise ValueError(f"accounting rows contain duplicate or missing method: {method_id}")
        recorded_rows[method_id] = recorded
        if method_id not in fresh_rows:
            raise ValueError(f"accounting row is absent from fresh raw APK rebuild: {method_id}")
        raw_row, raw_payload, raw_sha = fresh_rows[method_id]
        materialized_path, materialized_payload = open_verified_artifact(
            {"path": recorded["receipt_path"], "sha256": recorded["receipt_sha256"]}, allowed,
        )
        if materialized_payload != raw_payload or recorded.get("raw_receipt_sha256") != raw_sha:
            raise ValueError(f"materialized/raw receipt mismatch: {method_id}")
        code_bearing = bool(raw_row.get("code_offset"))
        if code_bearing:
            disposition = "queued_code_method"
            reason = "defined method has nonzero code_off"
        elif not raw_row.get("defined"):
            disposition = "terminal_external_reference"
            reason = "method table entry is not defined by class_data"
        else:
            flags = int(raw_row.get("access_flags") or 0)
            if not flags & (0x100 | 0x400):
                raise ValueError(f"fresh defined no-code method is not native/abstract: {method_id}")
            disposition = "terminal_native_or_abstract"
            reason = "defined method has zero code_off and native/abstract access flag"
        expected = {
            "method_id": method_id,
            "dex_sha256": str(raw_row["dex_sha256"]),
            "qualified_name": str(raw_row["qualified_name"]),
            "defined": bool(raw_row["defined"]),
            "code_bearing": code_bearing,
            "receipt_path": str(materialized_path),
            "receipt_sha256": sha256_bytes(materialized_payload),
            "raw_receipt_path": str(recorded["raw_receipt_path"]),
            "raw_receipt_sha256": raw_sha,
            "method_index": int(raw_row["method_index"]),
            "access_flags": raw_row.get("access_flags"),
            "code_offset": raw_row.get("code_offset"),
            "status": str(raw_row.get("status") or ""),
            "disposition": disposition,
            "disposition_reason": reason,
        }
        if canonical(expected) != canonical(recorded):
            raise ValueError(f"derived accounting row mismatch: {method_id}")
        expected_rows.append(expected)
        counts = expected_per_dex.setdefault(
            str(raw_row["dex_sha256"]), {"methods": 0, "defined_methods": 0, "code_methods": 0},
        )
        counts["methods"] += 1
        counts["defined_methods"] += int(bool(raw_row["defined"]))
        counts["code_methods"] += int(code_bearing)
    if set(fresh_rows) != set(recorded_rows):
        raise ValueError("fresh raw APK method set differs from accounting rows")
    expected_rows.sort(key=lambda row: row["method_id"])
    expected_stream = sha256_bytes(b"".join(canonical(row) for row in expected_rows))
    if expected_stream != receipt.get("dex_receipt_inventory_sha256"):
        raise ValueError("complete accounting-row stream hash mismatch")
    expected_code_ids = [row["method_id"] for row in expected_rows if row["code_bearing"]]
    expected_unqueued = [row for row in expected_rows if not row["code_bearing"]]
    if expected_code_ids != code_ids or canonical(expected_unqueued) != canonical(receipt.get("unqueued_methods")):
        raise ValueError("DEX accounting queued/unqueued partition mismatch")
    expected_top = {
        "method_receipts": len(expected_rows),
        "defined_methods": sum(row["defined"] for row in expected_rows),
        "code_methods": len(expected_code_ids),
        "queue_methods": len(expected_code_ids),
        "per_dex": dict(sorted(expected_per_dex.items())),
    }
    for key, value in expected_top.items():
        if receipt.get(key) != value:
            raise ValueError(f"DEX accounting derived top-level mismatch: {key}")
    queue_ids: set[str] = set()
    with Path(receipt["queue"]["path"]).open(encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                queue_ids.add(str(json.loads(line).get("method_id") or ""))
    if queue_ids != set(code_ids):
        raise ValueError("current semantic queue differs from APK-derived code-method set")
    return {
        "schema": "angerona/dex-code-method-accounting-validation/v1",
        "receipt_sha256": receipt["receipt_sha256"],
        "apk_sha256": receipt["apk"]["sha256"],
        "method_receipts": len(fresh_rows),
        "code_methods": len(code_ids),
        "valid": True,
    }
