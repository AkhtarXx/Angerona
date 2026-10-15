"""Bind every DEX code method to exact smali and JADX class evidence."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


SCHEMA = "angerona/jadx-method-evidence/v4"
WORK_SCHEMA = "angerona/semantic-method-work-unit/v4"


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _methods(dex_root: Path) -> list[dict[str, Any]]:
    result = []
    for path in sorted(dex_root.glob("dex/*/methods/*.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(row, dict) and row.get("schema") == "angerona/dex-method-receipt/v2":
            row["receipt_path"] = str(path)
            row["receipt_sha256"] = _sha(path)
            result.append(row)
    return result


def _smali_overlays(smali_manifest: Path) -> dict[str, dict[str, Any]]:
    data = json.loads(smali_manifest.read_text(encoding="utf-8"))
    return {str(row["method_id"]): row for row in data.get("overlays") or []}


def build_jadx_method_evidence(
    jadx_output: str | Path,
    dex_receipt_root: str | Path,
    smali_reconciliation: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    jadx = Path(jadx_output).resolve()
    dex_root = Path(dex_receipt_root).resolve()
    smali_manifest = Path(smali_reconciliation).resolve()
    output = Path(output_dir).resolve()
    sources_root = jadx / "sources" if (jadx / "sources").is_dir() else jadx
    source_index: dict[str, list[dict[str, Any]]] = {}
    source_rows: list[dict[str, Any]] = []
    for path in sorted(jadx.rglob("*.java")):
        try:
            source_relative = path.relative_to(sources_root).as_posix()
            descriptor = "L" + source_relative[:-5] + ";"
        except ValueError:
            descriptor = ""
        relative = path.relative_to(jadx).as_posix()
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        blob = output / "blobs" / f"{digest}.java"
        if not blob.is_file():
            _atomic(blob, data)
        row = {
            "descriptor": descriptor,
            "path": str(path),
            "relative_path": relative,
            "bytes": len(data),
            "sha256": digest,
            "blob": f"blobs/{digest}.java",
        }
        if descriptor:
            source_index.setdefault(descriptor, []).append(row)
        source_rows.append(row)

    methods = _methods(dex_root)
    overlays = _smali_overlays(smali_manifest)
    classes: dict[str, list[dict[str, Any]]] = {}
    for method in methods:
        if method.get("defined"):
            classes.setdefault(str(method["class_descriptor"]), []).append(method)

    class_receipts: list[dict[str, Any]] = []
    bound_source_paths: set[str] = set()
    class_evidence: dict[str, dict[str, Any]] = {}
    for descriptor, class_methods in sorted(classes.items()):
        direct = source_index.get(descriptor, [])
        candidates = direct
        disposition = "exact-source-file"
        if not candidates and "$" in descriptor:
            outer = descriptor.split("$", 1)[0] + ";"
            candidates = source_index.get(outer, [])
            disposition = "outer-class-source" if candidates else "missing-source"
        elif not candidates:
            disposition = "missing-source"
        if len(candidates) > 1:
            disposition = "ambiguous-source"
        for row in candidates:
            bound_source_paths.add(row["path"])
        receipt = {
            "class_descriptor": descriptor,
            "method_ids": [row["method_id"] for row in class_methods],
            "code_method_ids": [row["method_id"] for row in class_methods if row.get("code_offset")],
            "disposition": disposition,
            "source_candidates": candidates,
        }
        class_receipts.append(receipt)
        class_evidence[descriptor] = receipt

    work_units: list[dict[str, Any]] = []
    for method in methods:
        if not method.get("code_offset"):
            continue
        method_id = str(method["method_id"])
        class_receipt = class_evidence[str(method["class_descriptor"])]
        smali = overlays.get(method_id)
        inputs = [{
            "kind": "dex-method-receipt",
            "path": method["receipt_path"],
            "sha256": method["receipt_sha256"],
        }]
        if smali:
            overlay_path = (Path(smali_manifest).parent / smali["overlay"]).resolve()
            overlay_bytes = overlay_path.read_bytes()
            if hashlib.sha256(overlay_bytes).hexdigest() != smali["overlay_sha256"]:
                raise ValueError(f"smali overlay hash mismatch for {method_id}")
            inputs.append({
                "kind": "smali-overlay",
                "path": str(overlay_path),
                "sha256": smali["overlay_sha256"],
            })
            overlay_receipt = json.loads(overlay_bytes)
            if overlay_receipt.get("method_id") != method_id:
                raise ValueError(f"smali overlay method mismatch for {method_id}")
            smali_root = Path(smali_manifest).parent.resolve()
            smali_blob = (smali_root / str(overlay_receipt["smali_blob"])).resolve()
            try:
                smali_blob.relative_to(smali_root)
            except ValueError as exc:
                raise ValueError(f"smali blob escapes evidence root for {method_id}") from exc
            smali_bytes = smali_blob.read_bytes()
            smali_sha = hashlib.sha256(smali_bytes).hexdigest()
            if smali_sha != overlay_receipt.get("smali_sha256"):
                raise ValueError(f"smali body hash mismatch for {method_id}")
            inputs.append({
                "kind": "smali-method-body",
                "path": str(smali_blob),
                "sha256": smali_sha,
            })
        for source in class_receipt["source_candidates"]:
            source_reference = {
                "schema": "angerona/jadx-class-source-reference/v1",
                "class_descriptor": method["class_descriptor"],
                "disposition": class_receipt["disposition"],
                "source_path": source["path"],
                "source_relative_path": source["relative_path"],
                "source_bytes": source["bytes"],
                "source_sha256": source["sha256"],
                "source_blob": str(output / source["blob"]),
            }
            reference_bytes = _canonical(source_reference)
            reference_sha = hashlib.sha256(reference_bytes).hexdigest()
            reference_path = output / "source-references" / f"{reference_sha}.json"
            if not reference_path.is_file():
                _atomic(reference_path, reference_bytes)
            inputs.append({
                "kind": "jadx-class-source-reference",
                "path": str(reference_path),
                "sha256": reference_sha,
            })
        input_manifest = {
            "schema": "angerona/semantic-method-input-manifest/v2",
            "dex_sha256": method["dex_sha256"],
            "method_id": method_id,
            "qualified_name": method["qualified_name"],
            "inputs": inputs,
        }
        input_manifest_sha = hashlib.sha256(_canonical(input_manifest)).hexdigest()
        unit_id = hashlib.sha256(
            f"{method['dex_sha256']}\0{method_id}\0{input_manifest_sha}\0semantic-reconstruction-v4".encode()
        ).hexdigest()
        work_units.append({
            "schema": WORK_SCHEMA,
            "unit_id": unit_id,
            "unit_kind": "dex_method_semantic_reconstruction",
            "state": "pending",
            "method_id": method_id,
            "qualified_name": method["qualified_name"],
            "class_descriptor": method["class_descriptor"],
            "class_evidence_disposition": class_receipt["disposition"],
            "inputs": inputs,
            "input_manifest_sha256": input_manifest_sha,
            "evidence_requests": [],
            "unresolved_reasons": ["high-level-semantic-reconstruction-pending"],
        })

    unbound_sources = [row for row in source_rows if row["path"] not in bound_source_paths]
    summary = {
        "schema": SCHEMA,
        "jadx_output": str(jadx),
        "dex_method_count": len(methods),
        "defined_class_count": len(classes),
        "source_artifact_count": len(source_rows),
        "bound_source_artifact_count": len(source_rows) - len(unbound_sources),
        "unbound_source_artifacts": unbound_sources,
        "class_receipts": class_receipts,
        "code_method_work_units": len(work_units),
        "all_code_methods_have_smali": all(
            any(item["kind"] == "smali-overlay" for item in unit["inputs"])
            for unit in work_units
        ),
        "all_code_methods_have_smali_body": all(
            any(item["kind"] == "smali-method-body" for item in unit["inputs"])
            for unit in work_units
        ),
        "all_classes_dispositioned": all(row["disposition"] for row in class_receipts),
        "classes_with_exact_or_outer_source": sum(
            row["disposition"] in {"exact-source-file", "outer-class-source"}
            for row in class_receipts
        ),
        "semantic_complete": False,
    }
    work_units_bytes = b"".join(_canonical(row) for row in sorted(work_units, key=lambda row: row["unit_id"]))
    summary["work_units_sha256"] = hashlib.sha256(work_units_bytes).hexdigest()
    summary_bytes = _canonical(summary)
    manifest_sha = hashlib.sha256(summary_bytes).hexdigest()
    summary["manifest_sha256"] = manifest_sha
    _atomic(output / "SEMANTIC_METHOD_WORK_UNITS.jsonl", work_units_bytes)
    _atomic(output / "JADX_METHOD_EVIDENCE.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    return summary
