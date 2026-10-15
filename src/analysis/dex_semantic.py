"""Strict DEX-to-Smali semantic coverage accounting.

The Android audit may use JADX for readable Java, but JADX output counts are not
an authoritative coverage witness.  This module parses each DEX class-data
table, disassembles that *individual* DEX through the vendored apktool/baksmali
stack, and requires exact class and declared-method counts before the target is
considered covered.
"""

from __future__ import annotations

import hashlib
import json
import mmap
import os
import re
import shutil
import struct
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_HEADER_SIZE = 0x70
_MAX_TABLE_ITEMS = 10_000_000


@dataclass
class DexSemanticInventory:
    status: str
    sha256: str
    bytes: int
    class_defs: int = 0
    method_ids: int = 0
    defined_methods: int = 0
    code_methods: int = 0
    code_units: int = 0
    code_shape_sha256: str = ""
    code_semantic_sha256: str = ""
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "sha256": self.sha256,
            "bytes": self.bytes,
            "class_defs": self.class_defs,
            "method_ids": self.method_ids,
            "defined_methods": self.defined_methods,
            "code_methods": self.code_methods,
            "code_units": self.code_units,
            "code_shape_sha256": self.code_shape_sha256,
            "code_semantic_sha256": self.code_semantic_sha256,
            "errors": list(self.errors),
        }


def _u32(blob: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(blob):
        raise ValueError(f"u32-out-of-bounds@0x{offset:x}")
    return struct.unpack_from("<I", blob, offset)[0]


def _uleb128(blob: bytes, offset: int) -> tuple[int, int]:
    value = 0
    for shift in range(0, 35, 7):
        if offset >= len(blob):
            raise ValueError("truncated-uleb128")
        byte = blob[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            return value, offset
    raise ValueError("oversized-uleb128")


def _sleb128(blob: bytes, offset: int) -> tuple[int, int]:
    value = 0
    byte = 0
    for shift in range(0, 35, 7):
        if offset >= len(blob):
            raise ValueError("truncated-sleb128")
        byte = blob[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte < 0x80:
            if shift < 32 and byte & 0x40:
                value |= -(1 << (shift + 7))
            return value, offset
    raise ValueError("oversized-sleb128")


def _bounded_table(blob: bytes, size: int, offset: int, width: int, name: str) -> None:
    if size < 0 or size > _MAX_TABLE_ITEMS:
        raise ValueError(f"{name}-count-out-of-policy")
    if size == 0:
        if offset not in (0,) and offset > len(blob):
            raise ValueError(f"{name}-offset-out-of-bounds")
        return
    if offset < _HEADER_SIZE or offset + size * width > len(blob):
        raise ValueError(f"{name}-table-out-of-bounds")


def inventory_dex_bytes(blob: bytes) -> DexSemanticInventory:
    """Parse enough of a standard DEX to account for every declared method."""
    digest = hashlib.sha256(blob).hexdigest()
    result = DexSemanticInventory(status="invalid", sha256=digest, bytes=len(blob))
    try:
        if len(blob) < _HEADER_SIZE:
            raise ValueError("truncated-header")
        if blob[:4] != b"dex\n" or blob[7:8] != b"\x00":
            raise ValueError("bad-dex-magic")
        if _u32(blob, 32) != len(blob):
            raise ValueError("declared-file-size-mismatch")
        if _u32(blob, 36) != _HEADER_SIZE:
            raise ValueError("unexpected-header-size")
        if _u32(blob, 40) != 0x12345678:
            raise ValueError("unsupported-endian-tag")

        string_ids_size, string_ids_off = _u32(blob, 56), _u32(blob, 60)
        type_ids_size, type_ids_off = _u32(blob, 64), _u32(blob, 68)
        proto_ids_size, proto_ids_off = _u32(blob, 72), _u32(blob, 76)
        field_ids_size, field_ids_off = _u32(blob, 80), _u32(blob, 84)
        method_ids_size, method_ids_off = _u32(blob, 88), _u32(blob, 92)
        class_defs_size, class_defs_off = _u32(blob, 96), _u32(blob, 100)
        _bounded_table(blob, string_ids_size, string_ids_off, 4, "string-ids")
        _bounded_table(blob, type_ids_size, type_ids_off, 4, "type-ids")
        _bounded_table(blob, proto_ids_size, proto_ids_off, 12, "proto-ids")
        _bounded_table(blob, field_ids_size, field_ids_off, 8, "field-ids")
        _bounded_table(blob, method_ids_size, method_ids_off, 8, "method-ids")
        _bounded_table(blob, class_defs_size, class_defs_off, 32, "class-defs")

        defined_methods = 0
        code_methods = 0
        code_units = 0
        code_shape = hashlib.sha256()
        code_semantics = hashlib.sha256()
        seen_method_ids: set[int] = set()
        for class_index in range(class_defs_size):
            entry = class_defs_off + class_index * 32
            class_idx = _u32(blob, entry)
            class_data_off = _u32(blob, entry + 24)
            if class_idx >= type_ids_size:
                raise ValueError(f"class-{class_index}-type-index-out-of-bounds")
            if class_data_off == 0:
                continue
            if class_data_off < _HEADER_SIZE or class_data_off >= len(blob):
                raise ValueError(f"class-{class_index}-data-offset-out-of-bounds")
            cursor = class_data_off
            static_fields, cursor = _uleb128(blob, cursor)
            instance_fields, cursor = _uleb128(blob, cursor)
            direct_methods, cursor = _uleb128(blob, cursor)
            virtual_methods, cursor = _uleb128(blob, cursor)
            for count, label in (
                (static_fields, "static-fields"),
                (instance_fields, "instance-fields"),
                (direct_methods, "direct-methods"),
                (virtual_methods, "virtual-methods"),
            ):
                if count > _MAX_TABLE_ITEMS:
                    raise ValueError(f"class-{class_index}-{label}-count-out-of-policy")
            for _ in range(static_fields + instance_fields):
                _field_diff, cursor = _uleb128(blob, cursor)
                _access, cursor = _uleb128(blob, cursor)
            for method_count in (direct_methods, virtual_methods):
                method_index = 0
                for _ in range(method_count):
                    method_diff, cursor = _uleb128(blob, cursor)
                    _access, cursor = _uleb128(blob, cursor)
                    code_off, cursor = _uleb128(blob, cursor)
                    method_index += method_diff
                    if method_index >= method_ids_size:
                        raise ValueError(f"class-{class_index}-method-index-out-of-bounds")
                    if method_index in seen_method_ids:
                        raise ValueError(f"duplicate-defined-method-{method_index}")
                    seen_method_ids.add(method_index)
                    defined_methods += 1
                    code_shape.update(struct.pack("<II", method_index, code_off != 0))
                    code_semantics.update(struct.pack("<II", method_index, code_off != 0))
                    if code_off:
                        if code_off < _HEADER_SIZE or code_off + 16 > len(blob):
                            raise ValueError(f"method-{method_index}-code-offset-out-of-bounds")
                        registers_size, ins_size, outs_size, tries_size = struct.unpack_from(
                            "<4H", blob, code_off
                        )
                        insns_size = _u32(blob, code_off + 12)
                        if insns_size == 0:
                            raise ValueError(f"method-{method_index}-empty-code-item")
                        insns_end = code_off + 16 + insns_size * 2
                        if insns_end > len(blob):
                            raise ValueError(
                                f"method-{method_index}-instructions-out-of-bounds"
                            )
                        code_methods += 1
                        code_units += insns_size
                        code_shape.update(struct.pack("<II", insns_size, tries_size))
                        code_semantics.update(struct.pack(
                            "<II5I", method_index, code_off != 0, registers_size,
                            ins_size, outs_size, tries_size, insns_size,
                        ))
                        code_semantics.update(blob[code_off + 16:insns_end])
                        if tries_size:
                            tries_off = insns_end + (2 if insns_size & 1 else 0)
                            tries_end = tries_off + tries_size * 8
                            if tries_end > len(blob):
                                raise ValueError(f"method-{method_index}-tries-out-of-bounds")
                            handlers_start = tries_end
                            handlers_count, handlers_end = _uleb128(blob, handlers_start)
                            if handlers_count > _MAX_TABLE_ITEMS:
                                raise ValueError(f"method-{method_index}-handlers-count-out-of-policy")
                            for _ in range(handlers_count):
                                handler_size, handlers_end = _sleb128(blob, handlers_end)
                                for _ in range(abs(handler_size)):
                                    _type_idx, handlers_end = _uleb128(blob, handlers_end)
                                    _address, handlers_end = _uleb128(blob, handlers_end)
                                if handler_size <= 0:
                                    _catch_all, handlers_end = _uleb128(blob, handlers_end)
                            code_semantics.update(blob[tries_off:tries_end])
                            code_semantics.update(blob[handlers_start:handlers_end])

        result.status = "parsed"
        result.class_defs = class_defs_size
        result.method_ids = method_ids_size
        result.defined_methods = defined_methods
        result.code_methods = code_methods
        result.code_units = code_units
        result.code_shape_sha256 = code_shape.hexdigest()
        result.code_semantic_sha256 = code_semantics.hexdigest()
    except (ValueError, struct.error) as exc:
        result.errors.append(str(exc))
    return result


def inventory_dex(path: str | Path) -> DexSemanticInventory:
    target = Path(path)
    try:
        with target.open("rb") as stream:
            with mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as blob:
                return inventory_dex_bytes(blob)
    except (OSError, ValueError) as exc:
        return DexSemanticInventory(
            status="unreadable", sha256="", bytes=0,
            errors=[f"{type(exc).__name__}: {exc}"],
        )


def inventory_smali_tree(root: str | Path) -> dict[str, Any]:
    """Count lossless Smali class/method declarations in one DEX output tree."""
    base = Path(root)
    files = sorted(base.rglob("*.smali")) if base.is_dir() else []
    classes = 0
    methods = 0
    code_methods = 0
    instructions = 0
    in_method = False
    current_has_code = False
    unreadable: list[str] = []
    tree_digest = hashlib.sha256()
    semantic_digest = hashlib.sha256()
    for path in files:
        try:
            relative = path.relative_to(base).as_posix().encode("utf-8", "surrogateescape")
            tree_digest.update(len(relative).to_bytes(8, "big"))
            tree_digest.update(relative)
            semantic_digest.update(len(relative).to_bytes(8, "big"))
            semantic_digest.update(relative)
            with path.open("rb") as raw_stream:
                for raw_line in raw_stream:
                    tree_digest.update(len(raw_line).to_bytes(8, "big"))
                    tree_digest.update(raw_line)
                    line = raw_line.decode("utf-8", errors="replace")
                    semantic_line = re.sub(
                        r"(\.field\b.*)\s+=\s+(?:false|null|0x0(?:L|s|t)?|0\.0f?)$",
                        r"\1",
                        line.rstrip("\r\n"),
                    ).rstrip()
                    normalized = (semantic_line + "\n").encode("utf-8", "surrogateescape")
                    semantic_digest.update(len(normalized).to_bytes(8, "big"))
                    semantic_digest.update(normalized)
                    if re.match(r"^\.class\s+", line):
                        classes += 1
                    if re.match(r"^\.method(?:\s|$)", line):
                        methods += 1
                        in_method = True
                        current_has_code = False
                    elif in_method and re.match(r"^\s*\.end\s+method(?:\s|$)", line):
                        if current_has_code:
                            code_methods += 1
                        in_method = False
                    elif in_method:
                        stripped = line.strip()
                        if (
                            stripped
                            and not stripped.startswith((".", ":", "#"))
                        ):
                            instructions += 1
                            current_has_code = True
        except OSError:
            unreadable.append(str(path))
            continue
    return {
        "status": "success" if files and not unreadable else "partial",
        "files": len(files),
        "classes": classes,
        "methods": methods,
        "code_methods": code_methods,
        "instructions": instructions,
        "unreadable": unreadable,
        "tree_sha256": tree_digest.hexdigest(),
        "semantic_tree_sha256": semantic_digest.hexdigest(),
    }


def _reassemble_smali_tree(
    root: Path,
    *,
    timeout: int,
    deadline_monotonic: float | None,
) -> dict[str, Any]:
    """Reassemble the complete Smali tree and inventory the produced DEX.

    This closes the gap between textual declaration counting and actual
    bytecode coverage: baksmali output is credited only when smali can rebuild
    and the per-method code shape is identical to the source DEX.
    """

    from src.analysis.apktool_bridge import find_apktool
    from src.subprocess_observability import (
        ProgressTimeoutExpired,
        bounded_env_int,
        observed_progress_run,
    )

    cli = find_apktool()
    if cli is None:
        return {"status": "unavailable", "errors": ["apktool unavailable for Smali reassembly"]}
    build_dir = root / "build"
    shutil.rmtree(build_dir, ignore_errors=True)
    if cli.suffix == ".jar":
        command = [
            shutil.which("java") or "java", "-Xmx4096m", "-jar", str(cli),
        ]
    else:
        command = [str(cli)]
    command.extend([
        "b", "--no-apk", "--force", "--jobs",
        str(max(1, min(8, os.cpu_count() or 1))), str(root),
    ])
    wall_timeout = max(60.0, float(timeout))
    if deadline_monotonic is not None:
        wall_timeout = min(wall_timeout, max(0.001, deadline_monotonic - time.monotonic()))
    log_handle = tempfile.NamedTemporaryFile(
        prefix="angerona-smali-reassembly-", suffix=".log", delete=False,
        dir=root.parent,
    )
    log_path = Path(log_handle.name)
    log_handle.close()
    try:
        with log_path.open("ab") as log:
            result = observed_progress_run(
                command,
                progress_path=log_path,
                idle_timeout=min(600.0, wall_timeout),
                wall_timeout=wall_timeout,
                poll_interval=1.0,
                stdout=log,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                cwd=str(root),
                resource_paths=[build_dir, log_path],
                max_rss_bytes=bounded_env_int(
                    "ANGERONA_APKTOOL_MAX_RSS_MB", 6144,
                    minimum=1024, maximum=32768,
                ) * 1024 * 1024,
                max_processes=bounded_env_int(
                    "ANGERONA_APKTOOL_MAX_PROCESSES", 128,
                    minimum=8, maximum=1024,
                ),
                max_output_bytes=bounded_env_int(
                    "ANGERONA_APKTOOL_MAX_OUTPUT_GIB", 24,
                    minimum=1, maximum=256,
                ) * 1024**3,
                max_output_items=bounded_env_int(
                    "ANGERONA_ANDROID_MAX_OUTPUT_ITEMS", 2_000_000,
                    minimum=10_000, maximum=20_000_000,
                ),
                min_free_bytes=bounded_env_int(
                    "ANGERONA_ANDROID_MIN_FREE_GIB", 8,
                    minimum=1, maximum=128,
                ) * 1024**3,
            )
        rebuilt_path = build_dir / "apk" / "classes.dex"
        rebuilt = inventory_dex(rebuilt_path)
        errors: list[str] = []
        if result.returncode != 0:
            errors.append(f"apktool Smali reassembly exited rc={result.returncode}")
        if rebuilt.status != "parsed":
            errors.extend(rebuilt.errors or ["rebuilt classes.dex was not produced"])
        second_observed: dict[str, Any] = {}
        if not errors:
            with tempfile.TemporaryDirectory(
                prefix="angerona-smali-second-pass-", dir=root.parent,
            ) as second_temp:
                second_root = Path(second_temp) / "decoded"
                wrapper = Path(second_temp) / "rebuilt.apk"
                with zipfile.ZipFile(wrapper, "w", compression=zipfile.ZIP_STORED) as archive:
                    archive.write(rebuilt_path, arcname="classes.dex")
                from src.analysis.apktool_bridge import decode_apk

                second_decode = decode_apk(
                    wrapper,
                    timeout=max(60, timeout),
                    skip_sources=False,
                    keep_output=second_root,
                    deadline_monotonic=deadline_monotonic,
                )
                second_observed = inventory_smali_tree(second_root)
                if second_decode.status not in {"success", "partial"}:
                    errors.append("rebuilt DEX second-pass decode failed")
                if second_observed.get("status") != "success":
                    errors.append("rebuilt DEX second-pass Smali inventory incomplete")
        first_observed = inventory_smali_tree(root)
        semantic_roundtrip_complete = bool(
            not errors
            and first_observed.get("semantic_tree_sha256")
            == second_observed.get("semantic_tree_sha256")
        )
        if not semantic_roundtrip_complete:
            errors.append("canonical Smali semantic round-trip mismatch")
        return {
            "status": "success" if not errors else "partial",
            "inventory": rebuilt.as_dict(),
            "semantic_roundtrip_complete": semantic_roundtrip_complete,
            "source_semantic_tree_sha256": first_observed.get("semantic_tree_sha256", ""),
            "rebuilt_semantic_tree_sha256": second_observed.get("semantic_tree_sha256", ""),
            "errors": errors,
        }
    except (OSError, ProgressTimeoutExpired) as exc:
        return {
            "status": "partial",
            "errors": [f"Smali reassembly failed: {type(exc).__name__}: {exc}"],
        }
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)
        log_path.unlink(missing_ok=True)


def disassemble_dex(
    dex_path: str | Path,
    output_dir: str | Path,
    *,
    timeout: int,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Disassemble one raw DEX by wrapping it as a one-member APK for apktool."""
    source = Path(dex_path).expanduser().resolve()
    destination = Path(output_dir).expanduser().resolve()
    if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
        return {
            "status": "deadline-exhausted", "complete": False,
            "expected": {}, "observed": {},
        }
    expected = inventory_dex(source)
    if expected.status != "parsed":
        return {
            "status": "invalid-dex", "complete": False,
            "expected": expected.as_dict(), "observed": {},
        }
    destination.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="angerona-dex-wrapper-") as temp:
            wrapper = Path(temp) / "single-dex.apk"
            with zipfile.ZipFile(wrapper, "w", compression=zipfile.ZIP_STORED) as archive:
                archive.write(source, arcname="classes.dex")
            from src.analysis.apktool_bridge import decode_apk

            decoded = decode_apk(
                wrapper,
                timeout=timeout,
                skip_sources=False,
                keep_output=destination,
                deadline_monotonic=deadline_monotonic,
            )
    except (OSError, zipfile.BadZipFile) as exc:
        return {
            "status": "failed", "complete": False,
            "expected": expected.as_dict(), "observed": {},
            "errors": [f"{type(exc).__name__}: {exc}"],
        }
    observed = inventory_smali_tree(destination)
    dex_only_manifest_limitation = bool(
        decoded.status == "partial"
        and decoded.errors
        and all(
            error == "AndroidManifest.xml not produced by apktool"
            or error.startswith("apktool recovered on attempt ")
            for error in decoded.errors
        )
    )
    decoder_semantically_complete = bool(
        decoded.status == "success" or dex_only_manifest_limitation
    )
    reassembly = _reassemble_smali_tree(
        destination,
        timeout=timeout,
        deadline_monotonic=deadline_monotonic,
    )
    rebuilt = reassembly.get("inventory", {})
    bytecode_shape_complete = bool(
        reassembly.get("status") == "success"
        and rebuilt.get("status") == "parsed"
        and rebuilt.get("class_defs") == expected.class_defs
        and rebuilt.get("method_ids") == expected.method_ids
        and rebuilt.get("defined_methods") == expected.defined_methods
        and rebuilt.get("code_methods") == expected.code_methods
        and rebuilt.get("code_units") == expected.code_units
        and rebuilt.get("code_shape_sha256") == expected.code_shape_sha256
        and reassembly.get("semantic_roundtrip_complete") is True
    )
    complete = bool(
        decoder_semantically_complete
        and observed["status"] == "success"
        and observed["classes"] == expected.class_defs
        and observed["methods"] == expected.defined_methods
        and bytecode_shape_complete
    )
    receipt_path = destination / "ANGERONA_DEX_SEMANTIC_RECEIPT.json"
    receipt = {
        "schema_version": 2,
        "status": "complete" if complete else "partial",
        "input_sha256": expected.sha256,
        "input_bytes": expected.bytes,
        "expected": expected.as_dict(),
        "observed": observed,
        "apktool_status": decoded.status,
        "dex_only_manifest_limitation": dex_only_manifest_limitation,
        "reassembly": reassembly,
        "bytecode_shape_complete": bytecode_shape_complete,
    }
    with receipt_path.open("w", encoding="utf-8") as receipt_stream:
        json.dump(receipt, receipt_stream, sort_keys=True, separators=(",", ":"))
        receipt_stream.write("\n")
        receipt_stream.flush()
        os.fsync(receipt_stream.fileno())
    with receipt_path.open("rb") as receipt_stream:
        receipt_sha256 = hashlib.file_digest(receipt_stream, "sha256").hexdigest()
    return {
        "status": "success" if complete else "partial",
        "complete": complete,
        "expected": expected.as_dict(),
        "observed": observed,
        "apktool_status": decoded.status,
        "apktool_errors": list(decoded.errors),
        "reassembly": reassembly,
        "bytecode_shape_complete": bytecode_shape_complete,
        "dex_only_manifest_limitation": dex_only_manifest_limitation,
        "output": str(destination),
        "input_sha256": expected.sha256,
        "smali_tree_sha256": observed["tree_sha256"],
        "receipt": str(receipt_path),
        "receipt_sha256": receipt_sha256,
    }


def validate_dex_semantic_receipt(result: dict[str, Any]) -> bool:
    """Revalidate DEX identity and the complete published Smali tree."""

    try:
        if result.get("complete") is not True or not result.get("sha256"):
            return False
        receipt_path = Path(str(result.get("receipt", ""))).resolve()
        output = Path(str(result.get("output", ""))).resolve()
        if not receipt_path.is_file() or receipt_path.is_symlink() or not output.is_dir():
            return False
        with receipt_path.open("rb") as stream:
            receipt_sha = hashlib.file_digest(stream, "sha256").hexdigest()
        if receipt_sha != result.get("receipt_sha256"):
            return False
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        observed = inventory_smali_tree(output)
        return bool(
            receipt.get("schema_version") == 2
            and receipt.get("status") == "complete"
            and receipt.get("input_sha256") == result.get("sha256")
            and receipt.get("input_sha256") == result.get("input_sha256")
            and observed.get("status") == "success"
            and observed.get("tree_sha256") == receipt.get("observed", {}).get("tree_sha256")
            and observed.get("tree_sha256") == result.get("smali_tree_sha256")
            and observed.get("classes") == receipt.get("expected", {}).get("class_defs")
            and observed.get("methods") == receipt.get("expected", {}).get("defined_methods")
            and receipt.get("bytecode_shape_complete") is True
            and receipt.get("reassembly", {}).get("status") == "success"
            and receipt.get("reassembly", {}).get("inventory", {}).get("code_shape_sha256")
            == receipt.get("expected", {}).get("code_shape_sha256")
            and receipt.get("reassembly", {}).get("semantic_roundtrip_complete") is True
            and receipt.get("reassembly", {}).get("source_semantic_tree_sha256")
            == observed.get("semantic_tree_sha256")
            and receipt.get("reassembly", {}).get("source_semantic_tree_sha256")
            == receipt.get("reassembly", {}).get("rebuilt_semantic_tree_sha256")
            and receipt.get("reassembly", {}).get("inventory", {}).get("code_units")
            == receipt.get("expected", {}).get("code_units")
        )
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return False
