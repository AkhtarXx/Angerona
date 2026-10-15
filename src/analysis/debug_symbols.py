"""Provenance-aware DWARF, PDB, dSYM, debuginfod, and signature ingestion."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


DEBUG_SCHEMA_VERSION = "angerona.debug-metadata/v1"
MAX_DEBUG_FILE_BYTES = 1024 * 1024 * 1024
MAX_SYMBOLS = 5_000_000


def elf_build_id(payload: bytes) -> str | None:
    """Extract a GNU build-id from bounded ELF PT_NOTE records."""
    # 64 covers the full Elf64_Ehdr; smaller 32-bit headers also fit within it.
    if len(payload) < 64 or not payload.startswith(b"\x7fELF"):
        return None
    elf_class, encoding = payload[4], payload[5]
    if elf_class not in (1, 2) or encoding not in (1, 2):
        return None
    endian = "<" if encoding == 1 else ">"
    if elf_class == 2:
        phoff = struct.unpack_from(endian + "Q", payload, 32)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", payload, 54)
        minimum, program_format = 56, endian + "IIQQQQQQ"
    else:
        phoff = struct.unpack_from(endian + "I", payload, 28)[0]
        phentsize, phnum = struct.unpack_from(endian + "HH", payload, 42)
        minimum, program_format = 32, endian + "IIIIIIII"
    if phentsize < minimum or phnum > 65_535 or phoff > len(payload):
        return None
    for index in range(phnum):
        offset = phoff + index * phentsize
        if offset > len(payload) - minimum:
            return None
        fields = struct.unpack_from(program_format, payload, offset)
        if fields[0] != 4:  # PT_NOTE
            continue
        if elf_class == 2:
            note_offset, note_size = fields[2], fields[5]
        else:
            note_offset, note_size = fields[1], fields[4]
        if note_offset > len(payload) or note_size > len(payload) - note_offset:
            return None
        cursor, end = note_offset, note_offset + note_size
        while cursor <= end - 12:
            name_size, descriptor_size, note_type = struct.unpack_from(endian + "III", payload, cursor)
            cursor += 12
            name_end = cursor + name_size
            descriptor_start = (name_end + 3) & ~3
            descriptor_end = descriptor_start + descriptor_size
            if name_end > end or descriptor_end > end:
                return None
            name = payload[cursor:name_end].rstrip(b"\0")
            descriptor = payload[descriptor_start:descriptor_end]
            if name == b"GNU" and note_type == 3 and descriptor:
                return descriptor.hex()
            cursor = (descriptor_end + 3) & ~3
    return None


@dataclass(frozen=True)
class DebugSymbol:
    name: str
    address: int | None
    size: int = 0
    kind: str = "unknown"
    source: str = "unknown"
    confidence: float = 1.0
    linkage_name: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    properties: dict[str, Any] = field(default_factory=dict, compare=False)

    def __post_init__(self) -> None:
        if not self.name:
            raise ValueError("debug symbol name must be non-empty")
        if self.address is not None and self.address < 0:
            raise ValueError("debug symbol address must be non-negative")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("debug symbol confidence must be between zero and one")

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": f"0x{self.address:x}" if self.address is not None else None,
            "size": self.size,
            "kind": self.kind,
            "source": self.source,
            "confidence": self.confidence,
            "linkage_name": self.linkage_name,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "properties": dict(self.properties),
        }


@dataclass(frozen=True)
class DebugType:
    name: str
    kind: str
    size: int | None
    source: str
    declaration: str | None = None
    properties: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


@dataclass
class DebugMetadata:
    target_sha256: str
    provider: str
    symbols: list[DebugSymbol] = field(default_factory=list)
    types: list[DebugType] = field(default_factory=list)
    build_id: str | None = None
    source_artifact: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    schema_version: str = DEBUG_SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.target_sha256 = self.target_sha256.lower()
        if len(self.target_sha256) != 64 or any(c not in "0123456789abcdef" for c in self.target_sha256):
            raise ValueError("target_sha256 must be a SHA-256 digest")
        if len(self.symbols) > MAX_SYMBOLS:
            raise ValueError("symbol count exceeds safety limit")

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "target_sha256": self.target_sha256,
            "provider": self.provider,
            "build_id": self.build_id,
            "source_artifact": self.source_artifact,
            "symbols": [symbol.as_dict() for symbol in self.symbols],
            "types": [row.as_dict() for row in self.types],
            "properties": dict(self.properties),
        }


class DebugMetadataMerger:
    """Merge sources deterministically without allowing weak names to overwrite strong ones."""

    PRIORITY = {"pdb": 100, "dwarf": 100, "dsym": 100, "debuginfod": 95, "signature": 70, "heuristic": 20}

    def merge(self, inputs: Iterable[DebugMetadata]) -> DebugMetadata:
        rows = list(inputs)
        if not rows:
            raise ValueError("at least one metadata source is required")
        target = rows[0].target_sha256
        if any(row.target_sha256 != target for row in rows):
            raise ValueError("cannot merge debug metadata for different targets")
        symbols: dict[tuple[int | None, str], DebugSymbol] = {}
        conflicts: list[dict[str, Any]] = []
        for metadata in rows:
            for symbol in metadata.symbols:
                # Address is the primary identity across providers; providers
                # frequently disagree on whether the same row is "public" or
                # "function". Address-less type-like names remain separated.
                key = (
                    symbol.address,
                    f"{symbol.kind}:{symbol.name}" if symbol.address is None else "",
                )
                existing = symbols.get(key)
                if existing is None:
                    symbols[key] = symbol
                    continue
                old_rank = (self.PRIORITY.get(existing.source, 0), existing.confidence, existing.name)
                new_rank = (self.PRIORITY.get(symbol.source, 0), symbol.confidence, symbol.name)
                if symbol.name != existing.name:
                    conflicts.append({
                        "address": f"0x{symbol.address:x}" if symbol.address is not None else None,
                        "kept": max((existing, symbol), key=lambda row: (
                            self.PRIORITY.get(row.source, 0), row.confidence, row.name
                        )).name,
                        "candidates": sorted({existing.name, symbol.name}),
                    })
                if new_rank > old_rank:
                    symbols[key] = symbol
        types: dict[tuple[str, str], DebugType] = {}
        for metadata in rows:
            for row in metadata.types:
                types.setdefault((row.name, row.kind), row)
        return DebugMetadata(
            target,
            "merged",
            sorted(symbols.values(), key=lambda row: (row.address is None, row.address or 0, row.name)),
            sorted(types.values(), key=lambda row: (row.kind, row.name)),
            properties={"providers": sorted({row.provider for row in rows}), "conflicts": conflicts},
        )


class DwarfProvider:
    """Read subprogram and type DIEs via the optional pyelftools package."""

    def ingest(self, binary_path: str | Path, *, target_sha256: str | None = None) -> DebugMetadata:
        path = Path(binary_path)
        if path.stat().st_size > MAX_DEBUG_FILE_BYTES:
            raise ValueError("debug artifact exceeds safety limit")
        try:
            from elftools.elf.elffile import ELFFile
        except ImportError as exc:
            raise RuntimeError("DWARF ingestion requires pyelftools") from exc
        payload_hash = target_sha256 or hashlib.sha256(path.read_bytes()).hexdigest()
        symbols: list[DebugSymbol] = []
        types: list[DebugType] = []
        with path.open("rb") as handle:
            elf = ELFFile(handle)
            if not elf.has_dwarf_info():
                return DebugMetadata(payload_hash, "dwarf", source_artifact=str(path))
            dwarf = elf.get_dwarf_info()
            for compilation_unit in dwarf.iter_CUs():
                for die in compilation_unit.iter_DIEs():
                    attrs = die.attributes
                    name_attr = attrs.get("DW_AT_name")
                    if name_attr is None:
                        continue
                    raw_name = name_attr.value
                    name = raw_name.decode(errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
                    if die.tag == "DW_TAG_subprogram":
                        address_attr = attrs.get("DW_AT_low_pc")
                        size_attr = attrs.get("DW_AT_high_pc")
                        address = int(address_attr.value) if address_attr is not None else None
                        size = int(size_attr.value) if size_attr is not None and address is not None else 0
                        if (
                            address is not None
                            and size_attr is not None
                            and str(getattr(size_attr, "form", "")).startswith("DW_FORM_addr")
                        ):
                            size -= address
                        symbols.append(DebugSymbol(name, address, size, "function", "dwarf"))
                    elif die.tag in {"DW_TAG_structure_type", "DW_TAG_union_type", "DW_TAG_enumeration_type", "DW_TAG_typedef"}:
                        byte_size = attrs.get("DW_AT_byte_size")
                        types.append(DebugType(
                            name, die.tag.removeprefix("DW_TAG_").removesuffix("_type"),
                            int(byte_size.value) if byte_size is not None else None, "dwarf",
                        ))
                    if len(symbols) > MAX_SYMBOLS:
                        raise ValueError("DWARF symbol count exceeds safety limit")
        return DebugMetadata(payload_hash, "dwarf", symbols, types, source_artifact=str(path))


class PdbTextAdapter:
    """Parse stable address/name rows exported by llvm-pdbutil or DIA wrappers."""

    _PUBLIC = re.compile(r"(?:addr(?:ess)?\s*[=:]\s*)?(0x[0-9a-fA-F]+|[0-9A-Fa-f]{8,16})\s+(.+)$")
    _LLVM_PUBLIC = re.compile(r"S_PUB32\b.*`([^`]+)`")
    _LLVM_ADDRESS = re.compile(r"\baddr\s*=\s*([0-9A-Fa-f]+):([0-9A-Fa-f]+)\b")
    _LLVM_SECTION = re.compile(r"\brva\s*=\s*(0x[0-9A-Fa-f]+|\d+),\s*section\s*#\s*=\s*(\d+)\b")

    def ingest(
        self,
        text: str,
        *,
        target_sha256: str,
        image_base: int = 0,
        source_artifact: str | None = None,
    ) -> DebugMetadata:
        symbols: list[DebugSymbol] = []
        lines = text.splitlines()
        section_rvas: dict[int, int] = {}
        for line in lines:
            section_match = self._LLVM_SECTION.search(line)
            if section_match:
                rva, section = section_match.groups()
                section_rvas[int(section)] = int(rva, 0)

        pending_public: str | None = None
        for line in lines:
            llvm_public = self._LLVM_PUBLIC.search(line)
            if llvm_public:
                pending_public = llvm_public.group(1).strip()
                continue
            llvm_address = self._LLVM_ADDRESS.search(line) if pending_public else None
            if llvm_address:
                section_token, offset_token = llvm_address.groups()
                section = int(section_token, 16)
                offset = int(offset_token, 16)
                if section in section_rvas:
                    symbols.append(DebugSymbol(
                        pending_public,
                        image_base + section_rvas[section] + offset,
                        kind="public",
                        source="pdb",
                    ))
                    if len(symbols) > MAX_SYMBOLS:
                        raise ValueError("PDB symbol count exceeds safety limit")
                pending_public = None
                continue
            match = self._PUBLIC.search(line.strip())
            if not match:
                continue
            token, name = match.groups()
            address = int(token, 0 if token.startswith("0x") else 16) + image_base
            symbols.append(DebugSymbol(name.strip(), address, kind="public", source="pdb"))
            if len(symbols) > MAX_SYMBOLS:
                raise ValueError("PDB symbol count exceeds safety limit")
        return DebugMetadata(target_sha256, "pdb", symbols, source_artifact=source_artifact)


class DsymProvider:
    """Locate the Mach-O DWARF payload inside a .dSYM bundle."""

    def locate(self, bundle: str | Path, binary_name: str | None = None) -> Path:
        root = Path(bundle).resolve(strict=True)
        dwarf_dir = root / "Contents" / "Resources" / "DWARF"
        if not dwarf_dir.is_dir():
            raise ValueError("invalid dSYM bundle")
        if binary_name:
            candidate = dwarf_dir / binary_name
            if candidate.is_file():
                return candidate
            raise ValueError("named dSYM payload is missing")
        candidates = sorted(path for path in dwarf_dir.iterdir() if path.is_file())
        if len(candidates) != 1:
            raise ValueError("dSYM bundle must contain exactly one payload unless binary_name is supplied")
        return candidates[0]


class DebuginfodClient:
    """Bounded build-id fetcher with atomic cache writes (network opt-in by caller)."""

    def fetch(self, base_url: str, build_id: str, cache_dir: str | Path) -> Path:
        normalized = build_id.lower().replace("-", "")
        if not normalized or any(c not in "0123456789abcdef" for c in normalized):
            raise ValueError("invalid build id")
        destination = Path(cache_dir) / normalized / "debuginfo"
        if destination.is_file():
            cached = destination.read_bytes()
            if elf_build_id(cached) != normalized:
                raise ValueError("cached debuginfo build id does not match request")
            return destination
        url = base_url.rstrip("/") + f"/buildid/{normalized}/debuginfo"
        request = urllib.request.Request(url, headers={"User-Agent": "angerona/0.1"})
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = response.read(MAX_DEBUG_FILE_BYTES + 1)
        if len(payload) > MAX_DEBUG_FILE_BYTES:
            raise ValueError("debuginfod response exceeds safety limit")
        if elf_build_id(payload) != normalized:
            raise ValueError("debuginfod artifact build id does not match request")
        destination.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary = tempfile.mkstemp(prefix=".debuginfo.", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
        return destination


class SignatureMetadataAdapter:
    """Ingest explicit address/name/type metadata from signature pipelines."""

    def ingest(self, payload: dict[str, Any], *, target_sha256: str) -> DebugMetadata:
        symbols = [DebugSymbol(
            str(row["name"]),
            int(str(row["address"]), 0) if row.get("address") is not None else None,
            int(row.get("size") or 0),
            str(row.get("kind") or "function"),
            "signature",
            float(row.get("confidence", 0.8)),
            properties={"signature_id": row.get("signature_id")},
        ) for row in payload.get("symbols") or []]
        types = [DebugType(
            str(row["name"]), str(row.get("kind") or "typedef"),
            int(row["size"]) if row.get("size") is not None else None,
            "signature", row.get("declaration"),
        ) for row in payload.get("types") or []]
        return DebugMetadata(target_sha256, "signature", symbols, types)
