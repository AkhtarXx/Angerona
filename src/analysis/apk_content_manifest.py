"""Authoritative, lossless APK member and archive-byte accounting."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Any
import zipfile

from .android_binary_inventory import detect_android_binary_format
from .evidence_signing import canonical_payload


SCHEMA = "angerona/apk-content-manifest/v2"
WORK_SCHEMA = "angerona/apk-content-work-unit/v2"
MANIFEST_SELF_FIELDS = frozenset({"manifest_sha256"})
MANIFEST_SIGNATURE_FIELDS = frozenset({
    "payload_sha256", "signature", "signature_key_id", "signing_key_id", "trust",
})
_LOCAL_SIG = b"PK\x03\x04"
_EOCD_SIG = b"PK\x05\x06"
_APK_SIG_MAGIC = b"APK Sig Block 42"


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def canonical_apk_content_manifest_payload(manifest: dict[str, Any]) -> bytes:
    """Return the sole v2 manifest identity payload.

    V2 manifests are unsigned identity documents. Signed/legacy representations
    must be converted by an explicit signed migration; accepting either encoding
    here would make the authoritative identity ambiguous.
    """
    if not isinstance(manifest, dict) or manifest.get("schema") != SCHEMA:
        raise ValueError("unsupported APK content manifest schema")
    attached_signature_fields = sorted(MANIFEST_SIGNATURE_FIELDS.intersection(manifest))
    if attached_signature_fields:
        raise ValueError(
            "signed APK content manifests require explicit migration: "
            + ",".join(attached_signature_fields)
        )
    body = {key: value for key, value in manifest.items() if key not in MANIFEST_SELF_FIELDS}
    return canonical_payload(body)


def apk_content_manifest_sha256(manifest: dict[str, Any]) -> str:
    return hashlib.sha256(canonical_apk_content_manifest_payload(manifest)).hexdigest()


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


def _hash_file_range(path: Path, start: int, size: int) -> str:
    digest = hashlib.sha256()
    remaining = size
    with path.open("rb") as handle:
        handle.seek(start)
        while remaining:
            chunk = handle.read(min(1024 * 1024, remaining))
            if not chunk:
                raise ValueError("compressed member range extends beyond APK")
            digest.update(chunk)
            remaining -= len(chunk)
    return digest.hexdigest()


def _local_ranges(apk: Path, info: zipfile.ZipInfo) -> tuple[tuple[int, int], tuple[int, int]]:
    with apk.open("rb") as handle:
        handle.seek(info.header_offset)
        header = handle.read(30)
    if len(header) != 30 or header[:4] != _LOCAL_SIG:
        raise ValueError("invalid local file header")
    filename_bytes, extra_bytes = struct.unpack_from("<HH", header, 26)
    data_start = info.header_offset + 30 + filename_bytes + extra_bytes
    data_end = data_start + info.compress_size
    return (info.header_offset, data_start), (data_start, data_end)


def _archive_end(data: bytes) -> int:
    position = data.rfind(_EOCD_SIG)
    if position < 0 or position + 22 > len(data):
        return len(data)
    comment_size = struct.unpack_from("<H", data, position + 20)[0]
    return min(len(data), position + 22 + comment_size)


def _signing_block(data: bytes, central_start: int) -> tuple[int, int] | None:
    if central_start < 24 or data[central_start - 16:central_start] != _APK_SIG_MAGIC:
        return None
    footer_size = struct.unpack_from("<Q", data, central_start - 24)[0]
    total_size = footer_size + 8
    start = central_start - total_size
    if start < 0 or start + 8 > len(data):
        return None
    if struct.unpack_from("<Q", data, start)[0] != footer_size:
        return None
    return start, central_start


def _partition(size: int, ranges: list[tuple[int, int, str, str]]) -> list[dict[str, Any]]:
    changes: dict[int, dict[str, list[tuple[str, str]]]] = {
        0: {"add": [], "remove": []},
        size: {"add": [], "remove": []},
    }
    for start, end, state, owner in ranges:
        if start < 0 or end > size or end <= start:
            continue
        changes.setdefault(start, {"add": [], "remove": []})["add"].append((state, owner))
        changes.setdefault(end, {"add": [], "remove": []})["remove"].append((state, owner))
    active: set[tuple[str, str]] = set()
    cursor = 0
    result: list[dict[str, Any]] = []
    for point in sorted(changes):
        if point > cursor:
            if not active:
                state = "unclassified_archive_bytes"
            elif len(active) > 1:
                state = "overlapping_or_ambiguous"
            else:
                state = next(iter(active))[0]
            owners = sorted(owner for _kind, owner in active)
            result.append({
                "start": cursor,
                "end": point,
                "size": point - cursor,
                "state": state,
                "owners": owners[:64],
                "owners_truncated": len(owners) > 64,
            })
        active.difference_update(changes[point]["remove"])
        active.update(changes[point]["add"])
        cursor = point
    return result


def _unit_id(apk_sha: str, kind: str, subject: str) -> str:
    return hashlib.sha256(f"{apk_sha}\0{kind}\0{subject}".encode()).hexdigest()


def build_apk_content_manifest(apk: str | Path, output_dir: str | Path) -> dict[str, Any]:
    apk_path = Path(apk).resolve()
    output = Path(output_dir).resolve()
    apk_sha = _sha256_path(apk_path)
    apk_size = apk_path.stat().st_size
    raw = apk_path.read_bytes()
    entries: list[dict[str, Any]] = []
    archive_ranges: list[tuple[int, int, str, str]] = []
    work_units: list[dict[str, Any]] = []

    with zipfile.ZipFile(apk_path) as archive:
        infos = archive.infolist()
        central_start = int(archive.start_dir)
        archive_end = _archive_end(raw)
        archive_ranges.append((central_start, archive_end, "central_directory_and_eocd", "zip-structure"))
        signing = _signing_block(raw, central_start)
        if signing is not None:
            archive_ranges.append((signing[0], signing[1], "apk_signing_block", "apk-signing-block"))
        name_counts: dict[str, int] = {}
        for info in infos:
            name_counts[info.filename] = name_counts.get(info.filename, 0) + 1
        name_seen: dict[str, int] = {}

        for index, info in enumerate(infos):
            duplicate_index = name_seen.get(info.filename, 0)
            name_seen[info.filename] = duplicate_index + 1
            encrypted = bool(info.flag_bits & 0x1)
            errors: list[str] = []
            content_sha = None
            prefix = b""
            content_bytes = 0
            crc_verified = False
            try:
                local_header, compressed = _local_ranges(apk_path, info)
                archive_ranges.append((*local_header, "local_file_header", f"entry:{index}"))
                archive_ranges.append((*compressed, "compressed_member_data", f"entry:{index}"))
                compressed_sha = _hash_file_range(apk_path, compressed[0], compressed[1] - compressed[0])
            except (OSError, ValueError, struct.error) as exc:
                local_header = (info.header_offset, info.header_offset)
                compressed = local_header
                compressed_sha = None
                errors.append(f"local-range:{type(exc).__name__}")
            if not info.is_dir() and not encrypted:
                digest = hashlib.sha256()
                try:
                    with archive.open(info) as handle:
                        while True:
                            chunk = handle.read(1024 * 1024)
                            if not chunk:
                                break
                            if len(prefix) < 65536:
                                prefix += chunk[:65536 - len(prefix)]
                            digest.update(chunk)
                            content_bytes += len(chunk)
                    content_sha = digest.hexdigest()
                    crc_verified = content_bytes == info.file_size
                except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
                    errors.append(f"content-read:{type(exc).__name__}")
            elif encrypted:
                errors.append("encrypted-member-no-password")
            else:
                content_sha = hashlib.sha256(b"").hexdigest()
                crc_verified = True

            kind = "directory" if info.is_dir() else detect_android_binary_format(info.filename, prefix)
            child_sha = content_sha or compressed_sha or "unavailable"
            child_prefix = {
                "elf": "elf", "dex": "dex", "compact_dex": "dex",
                "java_class": "jvm", "zip": "archive", "wasm": "wasm",
            }.get(kind, "artifact")
            routing_status = (
                "pending-semantic-analysis"
                if kind in {"elf", "dex", "compact_dex", "java_class", "zip", "wasm"}
                else "terminal-classified-artifact"
            )
            if errors:
                routing_status = "unresolved"
            entry_id = hashlib.sha256(
                f"{apk_sha}\0{index}\0{info.header_offset}\0{info.filename}\0{child_sha}".encode()
            ).hexdigest()
            record = {
                "entry_id": entry_id,
                "central_directory_index": index,
                "name": info.filename,
                "duplicate_name_count": name_counts[info.filename],
                "duplicate_name_index": duplicate_index,
                "local_header_offset": info.header_offset,
                "local_header_end": local_header[1],
                "compressed_data_offset": compressed[0],
                "compressed_bytes": info.compress_size,
                "content_bytes": info.file_size,
                "observed_content_bytes": content_bytes,
                "compressed_sha256": compressed_sha,
                "content_sha256": content_sha,
                "crc32": f"{info.CRC:08x}",
                "crc_and_size_verified": crc_verified,
                "compression_method": info.compress_type,
                "flags": info.flag_bits,
                "encrypted": encrypted,
                "is_directory": info.is_dir(),
                "classification": kind,
                "routing_status": routing_status,
                "child_target_ids": [f"{child_prefix}:{child_sha}"],
                "limitations": errors,
            }
            entries.append(record)
            if routing_status not in {"terminal-classified-artifact"}:
                kind_name = "semantic_route" if not errors else "member_recovery"
                work_units.append({
                    "schema": WORK_SCHEMA,
                    "unit_id": _unit_id(apk_sha, kind_name, entry_id),
                    "unit_kind": kind_name,
                    "entry_id": entry_id,
                    "state": "pending",
                    "child_target_ids": record["child_target_ids"],
                    "unresolved_reasons": errors or [routing_status],
                })

    partition = _partition(apk_size, archive_ranges)
    for row in partition:
        if row["state"] not in {"unclassified_archive_bytes", "overlapping_or_ambiguous"}:
            continue
        subject = f"{row['start']}:{row['end']}:{row['state']}"
        work_units.append({
            "schema": WORK_SCHEMA,
            "unit_id": _unit_id(apk_sha, "archive_range_classification", subject),
            "unit_kind": "archive_range_classification",
            "state": "pending",
            "subject": subject,
            "unresolved_reasons": [row["state"]],
        })

    partition_bytes = sum(row["size"] for row in partition)
    manifest = {
        "schema": SCHEMA,
        "apk_path": str(apk_path),
        "apk_sha256": apk_sha,
        "apk_bytes": apk_size,
        "zip_structure_sha256": hashlib.sha256(raw[min((r[0] for r in archive_ranges if r[2] == "central_directory_and_eocd"), default=apk_size):]).hexdigest(),
        "entry_count": len(entries),
        "duplicate_name_entries": sum(1 for row in entries if row["duplicate_name_count"] > 1),
        "entries": entries,
        "archive_byte_coverage": partition,
        "archive_partition_bytes": partition_bytes,
        "archive_byte_partition_complete": partition_bytes == apk_size,
        "pending_work_units": len(work_units),
        "exhaustive_accounting": not work_units and partition_bytes == apk_size,
        "unaccounted_entries": [row["entry_id"] for row in entries if row["routing_status"] == "unresolved"],
    }
    manifest_sha = apk_content_manifest_sha256(manifest)
    manifest["manifest_sha256"] = manifest_sha
    for unit in work_units:
        unit["input_manifest_sha256"] = manifest_sha
    _atomic(output / "APK_CONTENT_WORK_UNITS.jsonl", b"".join(_canonical(row) for row in sorted(work_units, key=lambda row: row["unit_id"])))
    _atomic(output / "APK_CONTENT_MANIFEST.json", json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n")
    return manifest
