"""Deterministic multi-engine evidence fusion for Solana SBF binaries."""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
import struct
from typing import Any, Mapping

from ..config import Config, load_config
from ..engines import make_engine
from .adapters import collect_solana_adapter_status


ENGINE_ORDER = ("ida", "ghidra")
_GENERIC_NAME_PREFIXES = (
    "FUN_",
    "SUB_",
    "sub_",
    "func_",
    "thunk_FUN_",
    "LAB_",
)


@dataclass(frozen=True)
class SolanaFusionResult:
    fused: dict
    analyses: dict[str, dict]
    errors: dict[str, str]
    primary: str

    def summary(self) -> dict:
        return {
            "primary": self.primary,
            "successful_engines": list(self.analyses),
            "errors": dict(self.errors),
            "counts": {
                "functions": len(self.fused.get("functions", [])),
                "strings": len(self.fused.get("strings", [])),
                "imports": len(self.fused.get("imports", [])),
                "exports": len(self.fused.get("exports", [])),
                "symbols": len(self.fused.get("symbols", [])),
                "decompiled_functions": sum(
                    1
                    for function in self.fused.get("functions", [])
                    if function.get("decompiled")
                ),
            },
        }


def build_solana_engine_map(
    config: Config,
    *,
    primary_name: str,
    primary_engine: Any,
) -> dict[str, Any]:
    """Return runnable IDA/Ghidra engines, preserving the active engine object."""

    engines = {primary_name: primary_engine}
    available = {
        status.engine
        for status in collect_solana_adapter_status(config)
        if status.available and status.engine in ENGINE_ORDER
    }
    for engine_name in ENGINE_ORDER:
        if engine_name in engines or engine_name not in available:
            continue
        engines[engine_name] = make_engine(load_config(engine_name))
    return engines


def analyze_solana_with_engines(
    binary: str | Path,
    *,
    engines: Mapping[str, Any],
    primary: str,
    max_functions: int = 0,
    force: bool = False,
) -> SolanaFusionResult:
    """Run available engines sequentially and fuse all successful evidence.

    Sequential execution is deliberate: IDA and Ghidra can each consume
    substantial memory during auto-analysis. A failure in one engine is isolated
    and recorded; the successful engine remains usable.
    """

    ordered = [primary] + [
        name for name in ENGINE_ORDER if name != primary and name in engines
    ]
    ordered.extend(name for name in engines if name not in ordered)

    analyses: dict[str, dict] = {}
    errors: dict[str, str] = {}
    for engine_name in ordered:
        engine = engines.get(engine_name)
        if engine is None:
            continue
        try:
            analyses[engine_name] = engine.analyze(
                binary,
                decompile=engine_name == "ghidra",
                max_functions=max_functions,
                force=force,
            )
        except Exception as exc:  # noqa: BLE001 - evidence source isolation boundary
            errors[engine_name] = f"{type(exc).__name__}: {exc}"

    if not analyses:
        details = "; ".join(f"{name}={error}" for name, error in errors.items())
        raise RuntimeError(f"all Solana analysis engines failed: {details or 'no engines'}")

    successful_primary = primary if primary in analyses else next(iter(analyses))
    fused = merge_solana_analyses(
        analyses,
        primary=successful_primary,
        binary=binary,
    )
    fusion = fused.setdefault("metadata", {}).setdefault("fusion", {})
    fusion["errors"] = dict(errors)
    return SolanaFusionResult(
        fused=fused,
        analyses=analyses,
        errors=errors,
        primary=successful_primary,
    )


def merge_solana_analyses(
    analyses: Mapping[str, dict],
    *,
    primary: str,
    binary: str | Path | None = None,
) -> dict:
    """Merge engine JSON without inventing facts or hiding provenance."""

    if not analyses:
        raise ValueError("at least one analysis is required")
    if primary not in analyses:
        raise ValueError(f"primary engine {primary!r} has no analysis")

    source_order = [primary] + [name for name in analyses if name != primary]
    fused = deepcopy(analyses[primary])
    fused["functions"] = _merge_functions(analyses, source_order)
    fused["strings"] = _merge_records(
        analyses,
        source_order,
        "strings",
        lambda record: (
            _address_key(record.get("address")),
            str(record.get("value", "")),
        ),
    )
    fused["imports"] = _merge_records(
        analyses,
        source_order,
        "imports",
        lambda record: _import_key(record.get("name")),
    )
    fused["exports"] = _merge_records(
        analyses,
        source_order,
        "exports",
        lambda record: (
            _address_key(record.get("address")),
            str(record.get("name", "")),
        ),
    )
    fused["symbols"] = _merge_records(
        analyses,
        source_order,
        "symbols",
        lambda record: (
            _address_key(record.get("address")),
            str(record.get("name", "")),
            str(record.get("type", "")),
        ),
    )

    metadata = _merge_metadata(
        analyses,
        source_order=source_order,
        primary=primary,
        binary=binary,
    )
    fused["metadata"] = metadata
    fused["_fusion"] = {
        "primary": primary,
        "sources": source_order,
    }
    return fused


def _merge_metadata(
    analyses: Mapping[str, dict],
    *,
    source_order: list[str],
    primary: str,
    binary: str | Path | None,
) -> dict:
    """Merge metadata while keeping binary facts separate from engine claims."""

    source_metadata = {
        name: deepcopy(analyses[name].get("metadata") or {})
        for name in source_order
    }
    metadata = deepcopy(source_metadata[primary])

    # Prefer the most specific processor/language actually observed. IDA's
    # legacy eBPF processor can report a 32-bit database even when the custom
    # SBF loader created a 64-bit program. The Solana Ghidra language is a
    # stronger processor identity, while the ELF header below remains the
    # authority for bitness, byte order, machine and entry point.
    for name in source_order:
        candidate = source_metadata[name]
        language_id = str(candidate.get("language_id") or "")
        processor = str(candidate.get("processor") or "")
        if language_id.startswith("eBPFSol:"):
            metadata["language_id"] = language_id
        if processor.lower() == "ebpfsol":
            metadata["processor"] = processor

    pointer_sizes = [
        value
        for source in source_metadata.values()
        if isinstance((value := source.get("pointer_size")), int)
    ]
    bitness = [
        value
        for source in source_metadata.values()
        if isinstance((value := source.get("bits")), int)
    ]
    if pointer_sizes:
        metadata["pointer_size"] = max(pointer_sizes)
    if bitness:
        metadata["bits"] = max(bitness)

    elf_facts = _read_elf_header(binary) if binary is not None else {}
    metadata.update(elf_facts)
    metadata.update(
        {
            "engine": "solana-fused",
            "architecture": "Solana SBF/eBPF",
            "primary_engine": primary,
            "source_engines": source_order,
            "source_metadata": source_metadata,
            "fusion": {
                "policy": (
                    "IDA is the primary symbol/relocation source; missing "
                    "decompilation and records are filled from Ghidra. "
                    "Every merged function retains source provenance. ELF "
                    "header facts are authoritative for architecture metadata."
                ),
                "sbf_decompiler_policy": (
                    "Do not label SBF pseudocode as Hex-Rays evidence unless "
                    "the source engine explicitly produced it. The normal "
                    "Solana decompiler source is Ghidra SLEIGH/eBPF."
                ),
                "function_key": "entry address",
                "metadata_authority": "ELF header, then observed engine metadata",
            },
        }
    )
    return metadata


def _read_elf_header(binary: str | Path) -> dict:
    """Return architecture facts directly encoded in an ELF header."""

    try:
        with Path(binary).expanduser().open("rb") as handle:
            header = handle.read(64)
    except (OSError, TypeError, ValueError):
        return {}
    if len(header) < 32 or header[:4] != b"\x7fELF":
        return {}

    elf_class = header[4]
    data_encoding = header[5]
    if elf_class not in (1, 2) or data_encoding not in (1, 2):
        return {}

    byte_order = "<" if data_encoding == 1 else ">"
    bits = 32 if elf_class == 1 else 64
    entry_format = "I" if bits == 32 else "Q"
    try:
        machine = struct.unpack_from(f"{byte_order}H", header, 18)[0]
        entry = struct.unpack_from(f"{byte_order}{entry_format}", header, 24)[0]
    except struct.error:
        return {}

    return {
        "bits": bits,
        "pointer_size": bits // 8,
        "endianness": "little" if data_encoding == 1 else "big",
        "elf_class": f"ELF{bits}",
        "elf_machine": machine,
        "entry_point": hex(entry),
    }


def _merge_functions(
    analyses: Mapping[str, dict],
    source_order: list[str],
) -> list[dict]:
    merged: dict[Any, dict] = {}
    insertion_order: list[Any] = []

    for source in source_order:
        for index, function in enumerate(analyses[source].get("functions", [])):
            key = _address_key(function.get("entry"))
            if key is None:
                key = ("name", str(function.get("name", "")), source, index)
            if key not in merged:
                item = deepcopy(function)
                item["_sources"] = [source]
                if item.get("decompiled"):
                    item["_decompiled_source"] = source
                    item["_decompiler_kind"] = _decompiler_kind(source)
                merged[key] = item
                insertion_order.append(key)
                continue

            current = merged[key]
            current.setdefault("_sources", []).append(source)
            _merge_function_fields(current, function, source=source)

    return [merged[key] for key in insertion_order]


def _merge_function_fields(current: dict, candidate: dict, *, source: str) -> None:
    if _name_score(candidate.get("name")) > _name_score(current.get("name")):
        current["name"] = candidate.get("name")

    if not current.get("decompiled") and candidate.get("decompiled"):
        current["decompiled"] = candidate["decompiled"]
        current["_decompiled_source"] = source
        current["_decompiler_kind"] = _decompiler_kind(source)

    if not current.get("signature") and candidate.get("signature"):
        current["signature"] = candidate["signature"]

    if not current.get("size") and candidate.get("size"):
        current["size"] = candidate["size"]

    for field in ("callers", "callees"):
        current[field] = _stable_union(current.get(field), candidate.get(field))

    for field, value in candidate.items():
        if field.startswith("_") or field in current:
            continue
        current[field] = deepcopy(value)


def _decompiler_kind(source: str) -> str:
    if source == "ghidra":
        return "ghidra_sleigh"
    if source == "ida":
        return "ida_hexrays_or_loader"
    return source


def _merge_records(
    analyses: Mapping[str, dict],
    source_order: list[str],
    field: str,
    key_fn,
) -> list[dict]:
    merged: dict[Any, dict] = {}
    insertion_order: list[Any] = []
    for source in source_order:
        for index, record in enumerate(analyses[source].get(field, [])):
            key = key_fn(record)
            if key in (None, "", (None, "")):
                key = ("unkeyed", source, index)
            if key not in merged:
                merged[key] = deepcopy(record)
                insertion_order.append(key)
                continue
            current = merged[key]
            for name, value in record.items():
                if not current.get(name) and value not in (None, "", [], {}):
                    current[name] = deepcopy(value)
    return [merged[key] for key in insertion_order]


def _stable_union(first: Any, second: Any) -> list:
    output = []
    seen = set()
    for value in list(first or []) + list(second or []):
        address = _address_key(value)
        identity = ("address", address) if isinstance(address, int) else ("value", str(value))
        if identity in seen:
            continue
        seen.add(identity)
        output.append(value)
    return output


def _address_key(value: Any) -> Any:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text, 0)
        except ValueError:
            # Ghidra serializes addresses as address-space-qualified values such
            # as ``ram:00000120``. The suffix is the ELF virtual address and must
            # compare equal to IDA's ``0x120``.
            if ":" in text:
                suffix = text.rsplit(":", 1)[1]
                try:
                    return int(suffix, 16)
                except ValueError:
                    pass
            return text.lower() or None
    return None


def _name_score(value: Any) -> tuple[int, int]:
    name = str(value or "")
    if not name:
        return (0, 0)
    generic = name.startswith(_GENERIC_NAME_PREFIXES)
    return (1, 0) if generic else (2, len(name))


def _import_key(value: Any) -> str:
    name = str(value or "")
    return name[6:] if name.startswith("__imp_") else name
