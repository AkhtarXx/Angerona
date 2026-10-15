from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


QUEUE_SCHEMA = "angerona/jadx-class-chunk-queue/v1"
WORK_SCHEMA = "angerona/jadx-class-chunk-work-unit/v1"
SOURCE_SCHEMA = "angerona/jadx-class-source-receipt/v1"
INPUT_SCHEMA = "angerona/jadx-class-chunk-input-manifest/v1"


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8") + b"\n"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(data)
    os.replace(temporary, path)


def _lossless_chunks(data: bytes, maximum: int) -> list[tuple[int, int, bytes]]:
    if maximum < 1024:
        raise ValueError("chunk_bytes must be at least 1024")
    data.decode("utf-8", errors="strict")
    if not data:
        return [(0, 0, b"")]
    result: list[tuple[int, int, bytes]] = []
    start = 0
    while start < len(data):
        end = min(start + maximum, len(data))
        if end < len(data):
            newline = data.rfind(b"\n", start, end)
            if newline >= start:
                end = newline + 1
            else:
                while end > start and data[end] & 0xC0 == 0x80:
                    end -= 1
        if end <= start:
            raise ValueError("unable to form a lossless UTF-8 chunk")
        chunk = data[start:end]
        chunk.decode("utf-8", errors="strict")
        result.append((start, end, chunk))
        start = end
    return result


def build_jadx_class_queue(
    method_evidence: str | Path,
    output_dir: str | Path,
    *,
    chunk_bytes: int = 32768,
) -> dict[str, Any]:
    evidence_path = Path(method_evidence).resolve()
    output = Path(output_dir).resolve()
    evidence_bytes = evidence_path.read_bytes()
    evidence = json.loads(evidence_bytes)
    if evidence.get("schema") != "angerona/jadx-method-evidence/v4":
        raise ValueError("JADX method evidence v4 is required")

    sources: dict[tuple[str, str], dict[str, Any]] = {}
    for receipt in evidence.get("class_receipts") or []:
        descriptor = str(receipt["class_descriptor"])
        disposition = str(receipt["disposition"])
        for candidate in receipt.get("source_candidates") or []:
            relative = str(candidate["relative_path"])
            digest = str(candidate["sha256"])
            key = (relative, digest)
            row = sources.setdefault(key, {
                "candidate": candidate,
                "class_descriptors": set(),
                "dispositions": set(),
            })
            row["class_descriptors"].add(descriptor)
            row["dispositions"].add(disposition)

    for candidate in evidence.get("unbound_source_artifacts") or []:
        relative = str(candidate["relative_path"])
        digest = str(candidate["sha256"])
        key = (relative, digest)
        row = sources.setdefault(key, {
            "candidate": candidate,
            "class_descriptors": set(),
            "dispositions": set(),
        })
        row["dispositions"].add("unbound-source")

    units: list[dict[str, Any]] = []
    source_summaries: list[dict[str, Any]] = []
    total_source_bytes = 0
    multi_chunk_sources = 0
    for (relative, expected_sha), row in sorted(sources.items()):
        candidate = row["candidate"]
        blob = (evidence_path.parent / str(candidate["blob"])).resolve()
        try:
            blob.relative_to(evidence_path.parent)
        except ValueError as exc:
            raise ValueError(f"source blob escapes evidence root: {blob}") from exc
        data = blob.read_bytes()
        if _sha(data) != expected_sha or len(data) != int(candidate["bytes"]):
            raise ValueError(f"sealed JADX source mismatch: {relative}")
        class_id = _sha(f"{relative}\0{expected_sha}".encode("utf-8"))
        descriptors = sorted(row["class_descriptors"])
        dispositions = sorted(row["dispositions"])
        source_receipt = {
            "schema": SOURCE_SCHEMA,
            "class_id": class_id,
            "class_descriptors": descriptors,
            "dispositions": dispositions,
            "source_relative_path": relative,
            "source_bytes": len(data),
            "source_sha256": expected_sha,
            "sealed_source_blob": str(blob),
            "method_evidence_sha256": _sha(evidence_bytes),
        }
        source_receipt_bytes = _canonical(source_receipt)
        source_receipt_sha = _sha(source_receipt_bytes)
        source_receipt_path = output / "source-receipts" / f"{source_receipt_sha}.json"
        _atomic(source_receipt_path, source_receipt_bytes)

        chunks = _lossless_chunks(data, chunk_bytes)
        multi_chunk_sources += int(len(chunks) > 1)
        total_source_bytes += len(data)
        source_summaries.append({
            "class_id": class_id,
            "source_relative_path": relative,
            "source_sha256": expected_sha,
            "source_bytes": len(data),
            "chunk_count": len(chunks),
            "class_descriptors": descriptors,
        })
        for index, (start, end, chunk) in enumerate(chunks):
            chunk_sha = _sha(chunk)
            chunk_path = output / "chunks" / expected_sha / f"{index:05d}-{chunk_sha}.java"
            _atomic(chunk_path, chunk)
            inputs = [
                {"kind": "jadx-class-source-receipt", "path": str(source_receipt_path), "sha256": source_receipt_sha},
                {"kind": "jadx-class-source-chunk", "path": str(chunk_path), "sha256": chunk_sha},
            ]
            input_manifest = {
                "schema": INPUT_SCHEMA,
                "class_id": class_id,
                "source_sha256": expected_sha,
                "chunk_index": index,
                "chunk_count": len(chunks),
                "byte_start": start,
                "byte_end": end,
                "inputs": inputs,
            }
            input_bytes = _canonical(input_manifest)
            input_sha = _sha(input_bytes)
            input_path = output / "input-manifests" / f"{input_sha}.json"
            _atomic(input_path, input_bytes)
            unit_id = _sha(
                f"{class_id}\0{index}\0{len(chunks)}\0{input_sha}\0jadx-class-chunk-v1".encode("utf-8")
            )
            units.append({
                "schema": WORK_SCHEMA,
                "unit_id": unit_id,
                "unit_kind": "jadx_class_source_chunk",
                "state": "pending",
                "class_id": class_id,
                "class_descriptors": descriptors,
                "source_relative_path": relative,
                "source_sha256": expected_sha,
                "source_bytes": len(data),
                "chunk_index": index,
                "chunk_count": len(chunks),
                "byte_start": start,
                "byte_end": end,
                "inputs": inputs,
                "input_manifest_path": str(input_path),
                "input_manifest_sha256": input_sha,
                "evidence_requests": [],
                "unresolved_reasons": ["class-source-semantic-reconstruction-pending"],
            })

    work_bytes = b"".join(_canonical(row) for row in sorted(units, key=lambda item: item["unit_id"]))
    manifest = {
        "schema": QUEUE_SCHEMA,
        "method_evidence": str(evidence_path),
        "method_evidence_sha256": _sha(evidence_bytes),
        "chunk_bytes": chunk_bytes,
        "source_count": len(source_summaries),
        "source_bytes": total_source_bytes,
        "work_unit_count": len(units),
        "multi_chunk_source_count": multi_chunk_sources,
        "sources": source_summaries,
        "work_units_sha256": _sha(work_bytes),
        "semantic_complete": False,
    }
    _atomic(output / "JADX_CLASS_WORK_UNITS.jsonl", work_bytes)
    _atomic(output / "JADX_CLASS_QUEUE.json", json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n")
    return manifest


def verify_jadx_class_queue(output_dir: str | Path) -> dict[str, Any]:
    output = Path(output_dir).resolve()
    manifest_path = output / "JADX_CLASS_QUEUE.json"
    queue_path = output / "JADX_CLASS_WORK_UNITS.jsonl"
    manifest = json.loads(manifest_path.read_bytes())
    issues: list[str] = []
    if manifest.get("schema") != QUEUE_SCHEMA:
        issues.append("queue schema mismatch")
    queue_bytes = queue_path.read_bytes()
    if _sha(queue_bytes) != manifest.get("work_units_sha256"):
        issues.append("work-unit stream hash mismatch")
    units: list[dict[str, Any]] = []
    for line_number, line in enumerate(queue_bytes.splitlines(), 1):
        try:
            unit = json.loads(line)
        except ValueError:
            issues.append(f"invalid JSON at work-unit line {line_number}")
            continue
        units.append(unit)
    if len(units) != manifest.get("work_unit_count"):
        issues.append("work-unit count mismatch")
    if len({row.get("unit_id") for row in units}) != len(units):
        issues.append("duplicate work-unit identity")

    grouped: dict[str, list[dict[str, Any]]] = {}
    for unit in units:
        class_id = str(unit.get("class_id") or "")
        grouped.setdefault(class_id, []).append(unit)
        if unit.get("schema") != WORK_SCHEMA or unit.get("unit_kind") != "jadx_class_source_chunk":
            issues.append(f"work-unit schema/kind mismatch: {unit.get('unit_id')}")
        input_path = Path(str(unit.get("input_manifest_path"))).resolve()
        try:
            input_bytes = input_path.read_bytes()
        except OSError as exc:
            issues.append(f"missing input manifest for {unit.get('unit_id')}: {exc}")
            continue
        if _sha(input_bytes) != unit.get("input_manifest_sha256"):
            issues.append(f"input manifest hash mismatch: {unit.get('unit_id')}")
        else:
            expected_input = {
                "schema": INPUT_SCHEMA,
                "class_id": unit.get("class_id"),
                "source_sha256": unit.get("source_sha256"),
                "chunk_index": unit.get("chunk_index"),
                "chunk_count": unit.get("chunk_count"),
                "byte_start": unit.get("byte_start"),
                "byte_end": unit.get("byte_end"),
                "inputs": unit.get("inputs"),
            }
            if input_bytes != _canonical(expected_input):
                issues.append(f"input manifest content mismatch: {unit.get('unit_id')}")
        for item in unit.get("inputs") or []:
            path = Path(str(item.get("path"))).resolve()
            try:
                actual = _sha(path.read_bytes())
            except OSError as exc:
                issues.append(f"missing input {path}: {exc}")
                continue
            if actual != item.get("sha256"):
                issues.append(f"input hash mismatch: {path}")

    reconstructed_sources = 0
    reconstructed_bytes = 0
    for class_id, rows in grouped.items():
        ordered = sorted(rows, key=lambda item: int(item.get("chunk_index", -1)))
        if not ordered or [row.get("chunk_index") for row in ordered] != list(range(len(ordered))):
            issues.append(f"non-contiguous chunk indexes: {class_id}")
            continue
        expected_count = int(ordered[0].get("chunk_count", -1))
        if expected_count != len(ordered) or any(int(row.get("chunk_count", -1)) != expected_count for row in ordered):
            issues.append(f"chunk count mismatch: {class_id}")
            continue
        cursor = 0
        pieces: list[bytes] = []
        for row in ordered:
            if int(row.get("byte_start", -1)) != cursor:
                issues.append(f"byte offset gap/overlap: {class_id}")
            chunk_items = [item for item in row.get("inputs") or [] if item.get("kind") == "jadx-class-source-chunk"]
            if len(chunk_items) != 1:
                issues.append(f"missing or duplicate source chunk: {row.get('unit_id')}")
                continue
            chunk = Path(chunk_items[0]["path"]).read_bytes()
            cursor += len(chunk)
            if cursor != int(row.get("byte_end", -1)):
                issues.append(f"byte end mismatch: {row.get('unit_id')}")
            pieces.append(chunk)
        source = b"".join(pieces)
        if _sha(source) != ordered[0].get("source_sha256") or len(source) != int(ordered[0].get("source_bytes", -1)):
            issues.append(f"lossless source reconstruction mismatch: {class_id}")
        else:
            reconstructed_sources += 1
            reconstructed_bytes += len(source)

    if len(grouped) != manifest.get("source_count"):
        issues.append("source count mismatch")
    if reconstructed_bytes != manifest.get("source_bytes"):
        issues.append("source byte coverage mismatch")
    return {
        "schema": "angerona/jadx-class-chunk-queue-verification/v1",
        "queue": str(output),
        "source_count": len(grouped),
        "reconstructed_source_count": reconstructed_sources,
        "reconstructed_source_bytes": reconstructed_bytes,
        "work_unit_count": len(units),
        "issue_count": len(issues),
        "issues": issues,
        "valid": not issues,
    }
