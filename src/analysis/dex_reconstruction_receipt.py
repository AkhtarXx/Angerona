"""Per-method, content-addressed reconstruction accounting for every DEX."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import struct
from typing import Any
import zipfile


SCHEMA = "angerona/dex-target/v2"
METHOD_SCHEMA = "angerona/dex-method-receipt/v2"
WORK_SCHEMA = "angerona/dex-work-unit/v2"


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


def _u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        raise ValueError(f"u32-out-of-bounds:{offset}")
    return struct.unpack_from("<I", blob, offset)[0]


def _uleb(blob: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(blob):
            raise ValueError("uleb-out-of-bounds")
        byte = blob[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ValueError("uleb-too-large")


def _string(blob: bytes, string_ids_off: int, index: int, count: int) -> str:
    if index < 0 or index >= count:
        raise ValueError(f"string-index-out-of-bounds:{index}")
    offset = _u32(blob, string_ids_off + index * 4)
    _utf16_size, cursor = _uleb(blob, offset)
    end = blob.find(b"\x00", cursor)
    if end < 0:
        raise ValueError(f"unterminated-string:{index}")
    return blob[cursor:end].decode("utf-8", errors="replace")


def _type_descriptor(
    blob: bytes, type_ids_off: int, type_count: int,
    string_ids_off: int, string_count: int, index: int,
) -> str:
    if index < 0 or index >= type_count:
        raise ValueError(f"type-index-out-of-bounds:{index}")
    return _string(blob, string_ids_off, _u32(blob, type_ids_off + index * 4), string_count)


def _prototype(
    blob: bytes, proto_ids_off: int, proto_count: int, index: int,
    type_ids_off: int, type_count: int, string_ids_off: int, string_count: int,
) -> str:
    if index < 0 or index >= proto_count:
        raise ValueError(f"proto-index-out-of-bounds:{index}")
    row = proto_ids_off + index * 12
    return_type = _u32(blob, row + 4)
    params_off = _u32(blob, row + 8)
    params: list[str] = []
    if params_off:
        count = _u32(blob, params_off)
        if params_off + 4 + count * 2 > len(blob):
            raise ValueError(f"proto-params-out-of-bounds:{index}")
        for item in range(count):
            type_index = struct.unpack_from("<H", blob, params_off + 4 + item * 2)[0]
            params.append(_type_descriptor(
                blob, type_ids_off, type_count, string_ids_off, string_count, type_index,
            ))
    return "(" + "".join(params) + ")" + _type_descriptor(
        blob, type_ids_off, type_count, string_ids_off, string_count, return_type,
    )


def _defined_methods(
    blob: bytes, class_defs_size: int, class_defs_off: int, method_ids_size: int,
) -> dict[int, dict[str, int]]:
    result: dict[int, dict[str, int]] = {}
    for class_index in range(class_defs_size):
        row = class_defs_off + class_index * 32
        class_data_off = _u32(blob, row + 24)
        if not class_data_off:
            continue
        cursor = class_data_off
        static_fields, cursor = _uleb(blob, cursor)
        instance_fields, cursor = _uleb(blob, cursor)
        direct_methods, cursor = _uleb(blob, cursor)
        virtual_methods, cursor = _uleb(blob, cursor)
        for _ in range(static_fields + instance_fields):
            _diff, cursor = _uleb(blob, cursor)
            _access, cursor = _uleb(blob, cursor)
        for method_count in (direct_methods, virtual_methods):
            method_index = 0
            for _ in range(method_count):
                diff, cursor = _uleb(blob, cursor)
                access, cursor = _uleb(blob, cursor)
                code_off, cursor = _uleb(blob, cursor)
                method_index += diff
                if method_index >= method_ids_size:
                    raise ValueError(f"defined-method-index-out-of-bounds:{method_index}")
                if method_index in result:
                    raise ValueError(f"duplicate-defined-method:{method_index}")
                result[method_index] = {
                    "class_def_index": class_index,
                    "access_flags": access,
                    "code_offset": code_off,
                }
    return result


def _method_id(apk_sha: str, dex_sha: str, index: int, qualified: str) -> str:
    stable = hashlib.sha256(f"{apk_sha}\0{dex_sha}\0{index}\0{qualified}".encode()).hexdigest()
    return f"dex-method:{stable}"


def _work_id(dex_sha: str, method_id: str) -> str:
    return hashlib.sha256(f"{dex_sha}\0semantic-reconstruction\0{method_id}".encode()).hexdigest()


def build_dex_target_receipt(
    blob: bytes,
    *,
    apk_sha256: str,
    member_name: str,
    output_dir: str | Path,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    if len(blob) < 112 or blob[:4] != b"dex\n" or blob[7:8] != b"\x00":
        raise ValueError(f"invalid DEX: {member_name}")
    if _u32(blob, 32) != len(blob):
        raise ValueError(f"DEX size mismatch: {member_name}")
    if _u32(blob, 36) != 112 or _u32(blob, 40) != 0x12345678:
        raise ValueError(f"unsupported DEX header or endian tag: {member_name}")
    dex_sha = hashlib.sha256(blob).hexdigest()
    root = Path(output_dir).resolve() / "dex" / dex_sha
    methods_root = root / "methods"
    string_count, string_off = _u32(blob, 56), _u32(blob, 60)
    type_count, type_off = _u32(blob, 64), _u32(blob, 68)
    proto_count, proto_off = _u32(blob, 72), _u32(blob, 76)
    method_count, method_off = _u32(blob, 88), _u32(blob, 92)
    class_count, class_off = _u32(blob, 96), _u32(blob, 100)
    for count, offset, width, label in (
        (string_count, string_off, 4, "strings"),
        (type_count, type_off, 4, "types"),
        (proto_count, proto_off, 12, "protos"),
        (method_count, method_off, 8, "methods"),
        (class_count, class_off, 32, "classes"),
    ):
        if count and (offset < 112 or offset + count * width > len(blob)):
            raise ValueError(f"DEX {label} table out of bounds")
    defined = _defined_methods(blob, class_count, class_off, method_count)
    summaries: list[dict[str, Any]] = []
    work_units: list[dict[str, Any]] = []
    code_methods = 0
    no_code_methods = 0
    external_methods = 0

    for index in range(method_count):
        row = method_off + index * 8
        class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", blob, row)
        class_desc = _type_descriptor(blob, type_off, type_count, string_off, string_count, class_idx)
        name = _string(blob, string_off, name_idx, string_count)
        proto = _prototype(
            blob, proto_off, proto_count, proto_idx,
            type_off, type_count, string_off, string_count,
        )
        qualified = f"{class_desc}->{name}{proto}"
        method_id = _method_id(apk_sha256, dex_sha, index, qualified)
        definition = defined.get(index)
        code_offset = int(definition["code_offset"]) if definition else 0
        instruction_sha = None
        insns_size = 0
        registers_size = 0
        ins_size = 0
        outs_size = 0
        tries_size = 0
        if definition is None:
            status, terminal = "external_reference", True
            external_methods += 1
        elif not code_offset:
            status, terminal = "no_code_declared", True
            no_code_methods += 1
        else:
            if code_offset < 112 or code_offset + 16 > len(blob):
                raise ValueError(f"method code header out of bounds:{index}")
            registers_size, ins_size, outs_size, tries_size = struct.unpack_from("<4H", blob, code_offset)
            insns_size = _u32(blob, code_offset + 12)
            insns_start = code_offset + 16
            insns_end = insns_start + insns_size * 2
            if not insns_size or insns_end > len(blob):
                raise ValueError(f"method instructions out of bounds:{index}")
            instruction_sha = hashlib.sha256(blob[insns_start:insns_end]).hexdigest()
            status, terminal = "bytecode_accounted", False
            code_methods += 1

        receipt = {
            "schema": METHOD_SCHEMA,
            "method_id": method_id,
            "dex_sha256": dex_sha,
            "method_index": index,
            "qualified_name": qualified,
            "class_descriptor": class_desc,
            "name": name,
            "prototype": proto,
            "defined": definition is not None,
            "class_def_index": definition["class_def_index"] if definition else None,
            "access_flags": definition["access_flags"] if definition else None,
            "code_offset": code_offset or None,
            "registers_size": registers_size,
            "ins_size": ins_size,
            "outs_size": outs_size,
            "tries_size": tries_size,
            "instruction_code_units": insns_size,
            "instruction_bytes_sha256": instruction_sha,
            "status": status,
            "terminal": terminal,
            "semantic_artifacts": [],
            "losses": [] if terminal else ["semantic-reconstruction-pending"],
        }
        receipt_bytes = _canonical(receipt)
        filename = f"{index:05d}-{hashlib.sha256(qualified.encode()).hexdigest()[:12]}.json"
        _atomic(methods_root / filename, receipt_bytes)
        summaries.append({
            "method_id": method_id,
            "method_index": index,
            "qualified_name": qualified,
            "status": status,
            "terminal": terminal,
            "receipt": f"methods/{filename}",
            "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        })
        if not terminal:
            work_units.append({
                "schema": WORK_SCHEMA,
                "unit_id": _work_id(dex_sha, method_id),
                "unit_kind": "dex_method_semantic_reconstruction",
                "state": "pending",
                "dex_sha256": dex_sha,
                "method_id": method_id,
                "required_evidence": [f"dex/{dex_sha}/methods/{filename}"],
                "unresolved_reasons": ["semantic-reconstruction-pending"],
            })

    target = {
        "schema": SCHEMA,
        "target_id": f"dex:{dex_sha}",
        "apk_sha256": apk_sha256,
        "member_name": member_name,
        "content_sha256": dex_sha,
        "content_bytes": len(blob),
        "class_defs": class_count,
        "method_ids": method_count,
        "defined_methods": len(defined),
        "code_methods": code_methods,
        "no_code_defined_methods": no_code_methods,
        "external_method_references": external_methods,
        "methods_terminal": sum(bool(row["terminal"]) for row in summaries),
        "methods": summaries,
        "pending_work_units": len(work_units),
        "exhaustive_method_accounting": len(summaries) == method_count,
        "semantic_complete": not work_units,
    }
    target_bytes = _canonical(target)
    target_sha = hashlib.sha256(target_bytes).hexdigest()
    target["receipt_sha256"] = target_sha
    for unit in work_units:
        unit["input_manifest_sha256"] = target_sha
    _atomic(root / "DEX_TARGET_RECEIPT.json", json.dumps(target, indent=2, sort_keys=True).encode() + b"\n")
    return target, work_units


def build_apk_dex_receipts(apk: str | Path, output_dir: str | Path) -> dict[str, Any]:
    apk_path = Path(apk).resolve()
    output = Path(output_dir).resolve()
    apk_sha = hashlib.sha256(apk_path.read_bytes()).hexdigest()
    targets: list[dict[str, Any]] = []
    work_units: list[dict[str, Any]] = []
    with zipfile.ZipFile(apk_path) as archive:
        dex_infos = [
            info for info in archive.infolist()
            if not info.is_dir() and Path(info.filename).name.startswith("classes")
            and Path(info.filename).suffix == ".dex"
        ]
        for info in dex_infos:
            blob = archive.read(info)
            target, units = build_dex_target_receipt(
                blob,
                apk_sha256=apk_sha,
                member_name=info.filename,
                output_dir=output,
            )
            targets.append(target)
            work_units.extend(units)
    aggregate = {
        "schema": "angerona/apk-dex-targets/v2",
        "apk_sha256": apk_sha,
        "dex_target_count": len(targets),
        "method_ids": sum(row["method_ids"] for row in targets),
        "defined_methods": sum(row["defined_methods"] for row in targets),
        "code_methods": sum(row["code_methods"] for row in targets),
        "pending_work_units": len(work_units),
        "exhaustive_method_accounting": all(row["exhaustive_method_accounting"] for row in targets),
        "semantic_complete": all(row["semantic_complete"] for row in targets),
        "targets": [{
            key: row[key] for key in (
                "target_id", "member_name", "content_sha256", "class_defs", "method_ids",
                "defined_methods", "code_methods", "pending_work_units", "receipt_sha256",
            )
        } for row in targets],
    }
    aggregate_bytes = _canonical(aggregate)
    aggregate_sha = hashlib.sha256(aggregate_bytes).hexdigest()
    aggregate["manifest_sha256"] = aggregate_sha
    _atomic(output / "DEX_WORK_UNITS.jsonl", b"".join(_canonical(row) for row in sorted(work_units, key=lambda row: row["unit_id"])))
    _atomic(output / "DEX_TARGETS.json", json.dumps(aggregate, indent=2, sort_keys=True).encode() + b"\n")
    return aggregate
