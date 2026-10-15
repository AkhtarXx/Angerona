"""Exact DEX-method to smali fallback reconciliation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any


SCHEMA = "angerona/smali-reconciliation/v2"
OVERLAY_SCHEMA = "angerona/dex-method-semantic-overlay/v2"
_CLASS_RE = re.compile(r"^\.class\b.*\s(L[^;]+;)\s*$")
_METHOD_RE = re.compile(r"^\.method\b.*\s([^\s(]+)(\([^\s]+)\s*$")


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


def _parse_smali(path: Path) -> tuple[str | None, list[dict[str, Any]]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines(keepends=True)
    class_descriptor = None
    methods: list[dict[str, Any]] = []
    index = 0
    while index < len(lines):
        stripped = lines[index].strip()
        if class_descriptor is None:
            match = _CLASS_RE.match(stripped)
            if match:
                class_descriptor = match.group(1)
        method = _METHOD_RE.match(stripped)
        if not method:
            index += 1
            continue
        start = index
        index += 1
        while index < len(lines) and lines[index].strip() != ".end method":
            index += 1
        if index < len(lines):
            index += 1
        body = "".join(lines[start:index])
        instruction_count = sum(
            1 for line in lines[start + 1:max(start + 1, index - 1)]
            if (token := line.strip()) and not token.startswith((".", "#", ":"))
        )
        methods.append({
            "name": method.group(1),
            "prototype": method.group(2),
            "body": body,
            "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
            "instruction_lines": instruction_count,
            "start_line": start + 1,
            "end_line": index,
        })
    return class_descriptor, methods


def _method_receipts(dex_root: Path) -> list[tuple[Path, dict[str, Any]]]:
    result = []
    for path in sorted(dex_root.glob("dex/*/methods/*.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if isinstance(row, dict) and row.get("schema") == "angerona/dex-method-receipt/v2":
            result.append((path, row))
    return result


def reconcile_smali_tree(
    smali_root: str | Path,
    dex_receipt_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    smali = Path(smali_root).resolve()
    dex_root = Path(dex_receipt_root).resolve()
    output = Path(output_dir).resolve()
    blobs = output / "blobs"
    index: dict[str, list[dict[str, Any]]] = {}
    parsed_files = 0
    parsed_methods = 0
    for path in sorted(smali.rglob("*.smali")):
        class_descriptor, methods = _parse_smali(path)
        if not class_descriptor:
            continue
        parsed_files += 1
        for method in methods:
            qualified = f"{class_descriptor}->{method['name']}{method['prototype']}"
            method["qualified_name"] = qualified
            method["source_path"] = str(path)
            index.setdefault(qualified, []).append(method)
            parsed_methods += 1

    overlays: list[dict[str, Any]] = []
    missing: list[dict[str, Any]] = []
    ambiguous: list[dict[str, Any]] = []
    matched_code = 0
    code_expected = 0
    defined_expected = 0
    for receipt_path, receipt in _method_receipts(dex_root):
        if not receipt.get("defined"):
            continue
        defined_expected += 1
        code_bearing = bool(receipt.get("code_offset"))
        if code_bearing:
            code_expected += 1
        qualified = str(receipt["qualified_name"])
        candidates = index.get(qualified, [])
        if len(candidates) != 1:
            row = {
                "method_id": receipt["method_id"],
                "qualified_name": qualified,
                "candidate_count": len(candidates),
                "receipt": str(receipt_path),
            }
            (missing if not candidates else ambiguous).append(row)
            continue
        candidate = candidates[0]
        body = candidate["body"].encode()
        blob_sha = hashlib.sha256(body).hexdigest()
        blob_path = blobs / f"{blob_sha}.smali"
        if not blob_path.is_file():
            _atomic(blob_path, body)
        overlay = {
            "schema": OVERLAY_SCHEMA,
            "method_id": receipt["method_id"],
            "dex_sha256": receipt["dex_sha256"],
            "qualified_name": qualified,
            "source_receipt_sha256": hashlib.sha256(_canonical(receipt)).hexdigest(),
            "smali_blob": f"blobs/{blob_sha}.smali",
            "smali_sha256": blob_sha,
            "source_path": candidate["source_path"],
            "source_lines": [candidate["start_line"], candidate["end_line"]],
            "instruction_lines": candidate["instruction_lines"],
            "status": "bytecode_assembly_fallback",
            "terminal_accounting": True,
            "high_level_semantic_complete": False,
        }
        overlay_bytes = _canonical(overlay)
        overlay_name = hashlib.sha256(str(receipt["method_id"]).encode()).hexdigest() + ".json"
        _atomic(output / "methods" / overlay_name, overlay_bytes)
        overlays.append({
            "method_id": receipt["method_id"],
            "qualified_name": qualified,
            "overlay": f"methods/{overlay_name}",
            "overlay_sha256": hashlib.sha256(overlay_bytes).hexdigest(),
            "code_bearing": code_bearing,
        })
        if code_bearing:
            matched_code += 1

    summary = {
        "schema": SCHEMA,
        "smali_root": str(smali),
        "dex_receipt_root": str(dex_root),
        "smali_files": parsed_files,
        "smali_methods": parsed_methods,
        "defined_methods_expected": defined_expected,
        "code_methods_expected": code_expected,
        "methods_matched": len(overlays),
        "code_methods_matched": matched_code,
        "missing_methods": missing,
        "ambiguous_methods": ambiguous,
        "overlays": overlays,
        "exact_defined_method_reconciliation": len(overlays) == defined_expected and not missing and not ambiguous,
        "bytecode_fallback_complete": matched_code == code_expected and not any(
            row for row in missing + ambiguous
            if json.loads(Path(row["receipt"]).read_text()).get("code_offset")
        ),
        "high_level_semantic_complete": False,
    }
    summary_bytes = _canonical(summary)
    summary["manifest_sha256"] = hashlib.sha256(summary_bytes).hexdigest()
    _atomic(output / "SMALI_RECONCILIATION.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    return summary
