"""Evidence-preserving unpack, dump reconstruction, and recursive re-analysis."""

from __future__ import annotations

import hashlib
import json
import os
import struct
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from src.execution.loaders import BinaryLoadError, load_binary_bytes
from src.execution.models import MemoryImage, MemoryRegion


UNPACK_SCHEMA_VERSION = "angerona.unpack/v1"
MAX_REBUILT_BYTES = 1024 * 1024 * 1024
MAX_CHILD_ARTIFACTS = 256


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _align(value: int, alignment: int) -> int:
    if alignment <= 0 or alignment & (alignment - 1):
        raise BinaryLoadError("PE alignment must be a positive power of two")
    return (value + alignment - 1) & ~(alignment - 1)


def _synthesize_pe_imports(
    original: bytearray,
    imports: list[ResolvedImport],
    pointer_size: int,
) -> tuple[bytearray, dict[str, Any]]:
    """Append a valid named import section and update PE directories."""
    if not imports:
        return original, {"synthesized": False, "section": None}
    groups: dict[str, list[ResolvedImport]] = {}
    for row in imports:
        module = row.module.strip()
        if not module or (not row.symbol and row.ordinal is None):
            raise ValueError("each reconstructed import requires a module and symbol or ordinal")
        if row.ordinal is not None and not 0 <= row.ordinal <= 0xFFFF:
            raise ValueError("PE import ordinal is outside 16-bit range")
        groups.setdefault(module, []).append(row)

    pe_offset = struct.unpack_from("<I", original, 0x3C)[0]
    section_count = struct.unpack_from("<H", original, pe_offset + 6)[0]
    optional_size = struct.unpack_from("<H", original, pe_offset + 20)[0]
    optional_offset = pe_offset + 24
    magic = struct.unpack_from("<H", original, optional_offset)[0]
    if (magic == 0x20B) != (pointer_size == 8) or magic not in {0x10B, 0x20B}:
        raise BinaryLoadError("PE pointer width does not match optional header")
    section_alignment = struct.unpack_from("<I", original, optional_offset + 32)[0] or 0x1000
    file_alignment = struct.unpack_from("<I", original, optional_offset + 36)[0] or 0x200
    section_table = optional_offset + optional_size
    sections: list[dict[str, int]] = []
    for index in range(section_count):
        offset = section_table + index * 40
        virtual_size, virtual_address, raw_size, raw_pointer = struct.unpack_from(
            "<IIII", original, offset + 8
        )
        sections.append({
            "header": offset, "virtual_size": virtual_size,
            "virtual_address": virtual_address, "raw_size": raw_size,
            "raw_pointer": raw_pointer,
        })
    if not sections:
        raise BinaryLoadError("PE import synthesis requires an existing section table")
    first_raw = min(row["raw_pointer"] for row in sections if row["raw_pointer"])
    required_header_end = section_table + (section_count + 1) * 40
    if required_header_end > first_raw:
        # Shifting raw data also requires rewriting file-offset-bearing debug,
        # certificate, and vendor directories. Refuse instead of producing a
        # subtly corrupt image when no section-header slot is available.
        raise BinaryLoadError("PE headers have no safe room for reconstructed import section")

    section_rva = _align(max(
        row["virtual_address"] + max(row["virtual_size"], row["raw_size"])
        for row in sections
    ), section_alignment)
    descriptors_size = (len(groups) + 1) * 20
    blob = bytearray(descriptors_size)
    first_iat_offset: int | None = None
    last_iat_end = 0
    for descriptor_index, (module, rows) in enumerate(sorted(groups.items())):
        while len(blob) % pointer_size:
            blob.append(0)
        ilt_offset = len(blob)
        blob.extend(b"\0" * ((len(rows) + 1) * pointer_size))
        iat_offset = len(blob)
        blob.extend(b"\0" * ((len(rows) + 1) * pointer_size))
        first_iat_offset = iat_offset if first_iat_offset is None else min(first_iat_offset, iat_offset)
        last_iat_end = max(last_iat_end, iat_offset + (len(rows) + 1) * pointer_size)
        module_offset = len(blob)
        blob.extend(module.encode("ascii", errors="strict") + b"\0")
        thunk_values: list[int] = []
        ordinal_flag = 1 << (pointer_size * 8 - 1)
        for row in rows:
            if row.ordinal is not None and not row.symbol:
                thunk_values.append(ordinal_flag | row.ordinal)
            else:
                if len(blob) & 1:
                    blob.append(0)
                hint_name_offset = len(blob)
                blob.extend(struct.pack("<H", row.ordinal or 0))
                blob.extend(row.symbol.encode("ascii", errors="strict") + b"\0")
                thunk_values.append(section_rva + hint_name_offset)
        thunk_format = "<Q" if pointer_size == 8 else "<I"
        for index, value in enumerate(thunk_values):
            struct.pack_into(thunk_format, blob, ilt_offset + index * pointer_size, value)
            struct.pack_into(thunk_format, blob, iat_offset + index * pointer_size, value)
        struct.pack_into(
            "<IIIII", blob, descriptor_index * 20,
            section_rva + ilt_offset, 0, 0,
            section_rva + module_offset, section_rva + iat_offset,
        )

    raw_pointer = _align(len(original), file_alignment)
    if raw_pointer > len(original):
        original.extend(b"\0" * (raw_pointer - len(original)))
    raw_size = _align(len(blob), file_alignment)
    original.extend(blob)
    original.extend(b"\0" * (raw_size - len(blob)))
    new_header = section_table + section_count * 40
    original[new_header:new_header + 8] = b".angimp\0"
    struct.pack_into(
        "<IIIIIIHHI", original, new_header + 8,
        len(blob), section_rva, raw_size, raw_pointer,
        0, 0, 0, 0, 0xC0000040,
    )
    struct.pack_into("<H", original, pe_offset + 6, section_count + 1)
    struct.pack_into("<I", original, optional_offset + 56, _align(section_rva + len(blob), section_alignment))
    struct.pack_into("<I", original, optional_offset + 64, 0)  # checksum invalidated

    directory_offset = optional_offset + (112 if pointer_size == 8 else 96)
    count_offset = optional_offset + (108 if pointer_size == 8 else 92)
    directory_count = struct.unpack_from("<I", original, count_offset)[0]
    if optional_size < (directory_offset - optional_offset) + 13 * 8:
        raise BinaryLoadError("PE optional header has no room for import directories")
    if directory_count < 13:
        struct.pack_into("<I", original, count_offset, 13)
    struct.pack_into("<II", original, directory_offset + 8, section_rva, descriptors_size)
    struct.pack_into("<II", original, directory_offset + 4 * 8, 0, 0)  # Authenticode is invalid now.
    assert first_iat_offset is not None
    struct.pack_into(
        "<II", original, directory_offset + 12 * 8,
        section_rva + first_iat_offset, last_iat_end - first_iat_offset,
    )
    return original, {
        "synthesized": True,
        "section": ".angimp",
        "section_rva": f"0x{section_rva:x}",
        "descriptor_count": len(groups),
        "iat_rva": f"0x{section_rva + first_iat_offset:x}",
    }


def _atomic_write(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


@dataclass(frozen=True)
class ResolvedImport:
    module: str
    symbol: str
    iat_address: int
    resolved_address: int
    ordinal: int | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "symbol": self.symbol,
            "iat_address": f"0x{self.iat_address:x}",
            "resolved_address": f"0x{self.resolved_address:x}",
            "ordinal": self.ordinal,
        }


@dataclass(frozen=True)
class DumpArtifact:
    path: str
    sha256: str
    size: int
    parent_sha256: str
    kind: str
    provider: str
    oep: str | None = None
    metadata_path: str | None = None
    schema_version: str = UNPACK_SCHEMA_VERSION

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class UnpackResult:
    status: str
    artifacts: list[DumpArtifact] = field(default_factory=list)
    imports: list[ResolvedImport] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": UNPACK_SCHEMA_VERSION,
            "status": self.status,
            "artifacts": [artifact.as_dict() for artifact in self.artifacts],
            "imports": [row.as_dict() for row in self.imports],
            "notes": list(self.notes),
        }


class MemoryDumpReconstructor:
    """Reconstruct flat or PE artifacts from verified captured memory bytes."""

    @staticmethod
    def _verified_regions(image: MemoryImage) -> list[MemoryRegion]:
        valid, errors = image.verify_integrity()
        if not valid:
            raise ValueError("invalid memory image: " + "; ".join(errors))
        return sorted(
            (region for region in image.regions if region.bytes_b64 is not None),
            key=lambda region: int(region.address, 0),
        )

    def dump_flat(self, image: MemoryImage, destination: str | Path) -> DumpArtifact:
        regions = self._verified_regions(image)
        if not regions:
            raise ValueError("memory image has no captured bytes")
        start = min(int(region.address, 0) for region in regions)
        end = max(int(region.address, 0) + region.size for region in regions)
        size = end - start
        if size <= 0 or size > MAX_REBUILT_BYTES:
            raise ValueError("flat dump span exceeds safety limit")
        output = bytearray(size)
        for region in regions:
            offset = int(region.address, 0) - start
            output[offset:offset + region.size] = region.to_bytes() or b""
        path = Path(destination)
        payload = bytes(output)
        _atomic_write(path, payload)
        return DumpArtifact(
            path=str(path),
            sha256=_sha256(payload),
            size=len(payload),
            parent_sha256=image.target_sha256,
            kind="flat_memory",
            provider=image.provider,
            oep=image.entry_point,
        )

    def rebuild_pe(
        self,
        original: bytes,
        image: MemoryImage,
        destination: str | Path,
        *,
        oep: int | None = None,
        imports: Iterable[ResolvedImport] = (),
    ) -> DumpArtifact:
        loaded = load_binary_bytes(original)
        if loaded.format != "pe":
            raise BinaryLoadError("PE reconstruction requires a PE parent image")
        if _sha256(original) != image.target_sha256:
            raise ValueError("memory image target hash does not match PE parent")
        regions = self._verified_regions(image)
        output = bytearray(original)
        for region in regions:
            region_start = int(region.address, 0)
            region_end = region_start + region.size
            payload = region.to_bytes() or b""
            for segment in loaded.segments:
                if segment.name == "headers" or segment.file_size == 0:
                    continue
                overlap_start = max(region_start, segment.runtime_address)
                overlap_end = min(region_end, segment.runtime_address + segment.file_size)
                if overlap_start >= overlap_end:
                    continue
                source_offset = overlap_start - region_start
                file_offset = segment.file_offset + overlap_start - segment.runtime_address
                length = overlap_end - overlap_start
                output[file_offset:file_offset + length] = payload[source_offset:source_offset + length]

        actual_oep = oep if oep is not None else (
            int(image.entry_point, 0) if image.entry_point is not None else loaded.entry_point
        )
        if not loaded.load_base <= actual_oep < loaded.image_end:
            raise ValueError("OEP is outside the mapped PE image")
        pe_offset = struct.unpack_from("<I", output, 0x3C)[0]
        optional_offset = pe_offset + 24
        struct.pack_into("<I", output, optional_offset + 16, actual_oep - loaded.load_base)

        normalized_imports = list(imports)
        output, import_reconstruction = _synthesize_pe_imports(
            output, normalized_imports, loaded.pointer_size
        )

        path = Path(destination)
        payload = bytes(output)
        _atomic_write(path, payload)
        metadata_path = path.with_suffix(path.suffix + ".imports.json")
        metadata = {
            "schema_version": UNPACK_SCHEMA_VERSION,
            "parent_sha256": image.target_sha256,
            "rebuilt_sha256": _sha256(payload),
            "oep": f"0x{actual_oep:x}",
            "load_base": f"0x{loaded.load_base:x}",
            "imports": [row.as_dict() for row in normalized_imports],
            "import_reconstruction": import_reconstruction,
        }
        _atomic_write(metadata_path, json.dumps(metadata, indent=2, sort_keys=True).encode())
        return DumpArtifact(
            path=str(path),
            sha256=metadata["rebuilt_sha256"],
            size=len(payload),
            parent_sha256=image.target_sha256,
            kind="rebuilt_pe",
            provider=image.provider,
            oep=metadata["oep"],
            metadata_path=str(metadata_path),
        )


class CapeReportAdapter:
    """Ingest CAPE/Cuckoo-compatible extracted-file reports with hash validation."""

    def ingest(self, report: dict[str, Any], report_dir: str | Path) -> UnpackResult:
        base = Path(report_dir).resolve(strict=True)
        candidates = report.get("CAPE") or report.get("cape") or report.get("dropped") or []
        if isinstance(candidates, dict):
            candidates = candidates.get("payloads") or candidates.get("files") or []
        artifacts: list[DumpArtifact] = []
        notes: list[str] = []
        for row in candidates[:MAX_CHILD_ARTIFACTS]:
            relative = row.get("path") or row.get("file") or row.get("name")
            if not relative:
                continue
            path = (base / relative).resolve()
            if base not in path.parents and path != base:
                notes.append(f"rejected path outside report directory: {relative}")
                continue
            if not path.is_file():
                notes.append(f"missing extracted file: {relative}")
                continue
            if path.stat().st_size > MAX_REBUILT_BYTES:
                notes.append(f"extracted file exceeds size limit: {relative}")
                continue
            payload = path.read_bytes()
            digest = _sha256(payload)
            declared = str(row.get("sha256") or "").lower()
            if declared and declared != digest:
                notes.append(f"hash mismatch: {relative}")
                continue
            artifacts.append(DumpArtifact(
                path=str(path),
                sha256=digest,
                size=len(payload),
                parent_sha256=str(report.get("target", {}).get("sha256") or "unknown"),
                kind=str(row.get("type") or "cape_extracted"),
                provider="cape",
            ))
        return UnpackResult("success" if artifacts else "no_artifacts", artifacts, notes=notes)


class RecursiveArtifactAnalyzer:
    """Bounded, cycle-safe breadth-first re-analysis of unpacked child artifacts."""

    def __init__(self, analyzer: Callable[[Path, str | None], Iterable[DumpArtifact]]) -> None:
        self.analyzer = analyzer

    def run(
        self,
        roots: Iterable[str | Path],
        *,
        max_depth: int = 3,
        max_artifacts: int = MAX_CHILD_ARTIFACTS,
    ) -> list[dict[str, Any]]:
        if not 0 <= max_depth <= 16 or not 1 <= max_artifacts <= MAX_CHILD_ARTIFACTS:
            raise ValueError("recursive analysis bounds are invalid")
        queue: list[tuple[Path, int, str | None]] = [(Path(path), 0, None) for path in roots]
        seen: set[str] = set()
        records: list[dict[str, Any]] = []
        while queue and len(records) < max_artifacts:
            path, depth, parent_sha = queue.pop(0)
            if path.stat().st_size > MAX_REBUILT_BYTES:
                raise ValueError(f"child artifact exceeds size limit: {path}")
            payload = path.read_bytes()
            digest = _sha256(payload)
            if digest in seen:
                continue
            seen.add(digest)
            children = list(self.analyzer(path, parent_sha)) if depth < max_depth else []
            records.append({
                "path": str(path),
                "sha256": digest,
                "parent_sha256": parent_sha,
                "depth": depth,
                "children": [child.sha256 for child in children],
            })
            queue.extend((Path(child.path), depth + 1, digest) for child in children)
        return records
