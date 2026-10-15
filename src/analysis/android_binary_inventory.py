"""Fail-closed binary inventory and evidence generation for Android APK audits.

An APK is a ZIP container, not a source archive.  Professional coverage therefore
starts by classifying every member by bytes (not its extension), exporting embedded
code payloads, and producing reviewable evidence for opaque/native artifacts.

All inputs are untrusted.  Archive reads are bounded and external disassemblers are
invoked with an argv list; target bytes are never executed.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import shutil
import struct
import subprocess
import time
import zipfile
import zlib
from pathlib import Path
from collections.abc import Callable
from typing import Any

from src.analysis.jni_registration_resolver import resolve_jni_registration
from src.analysis.native_elf import parse_elf
from src.analysis.native_range_authority import (
    canonicalize_cross_range_references,
    sanitize_restricted_text,
    validate_restricted_evidence,
)
from src.subprocess_observability import (
    ProgressTimeoutExpired,
    bounded_env_int,
    observed_progress_run,
)


def _mib_budget(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(16, min(value, maximum)) * 1024 * 1024


def _seconds_budget(name: str, default: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError:
        value = default
    return max(1, min(value, maximum))


MEMBER_LIMIT = _mib_budget("ANGERONA_ANDROID_MEMBER_LIMIT_MIB", 256, 1024)
DISASSEMBLY_LIMIT = _mib_budget("ANGERONA_ANDROID_DISASSEMBLY_LIMIT_MIB", 128, 512)
IDA_EVIDENCE_LIMIT = _mib_budget("ANGERONA_ANDROID_IDA_EVIDENCE_LIMIT_MIB", 256, 1024)
_NATIVE_RECEIPT_SCHEMA = 2
STRINGS_LIMIT = 50_000
_OPAQUE_SUFFIXES = {"", ".bin", ".blob", ".dat", ".enc", ".pack", ".pak", ".payload"}
_TEXT_SUFFIXES = {
    ".aidl", ".c", ".cc", ".cfg", ".conf", ".cpp", ".h", ".hpp",
    ".java", ".js", ".json", ".kt", ".kts", ".properties", ".smali",
    ".txt", ".xml", ".yaml", ".yml",
}
_EXECUTABLE_MAGICS = {
    "dex": b"dex\n",
    "elf": b"\x7fELF",
    "zip": b"PK\x03\x04",
    "wasm": b"\x00asm",
}
_MEDIA_KINDS = {"png", "jpeg", "webp", "ogg"}
_PNG_STANDARD_CHUNKS = {
    b"IHDR", b"PLTE", b"IDAT", b"IEND", b"tRNS", b"cHRM", b"gAMA", b"iCCP",
    b"sBIT", b"sRGB", b"cICP", b"mDCV", b"cLLI", b"tEXt", b"zTXt", b"iTXt",
    b"bKGD", b"hIST", b"pHYs", b"sPLT", b"eXIf", b"tIME", b"acTL", b"fcTL",
    b"fdAT",
}
_PNG_AUXILIARY_DATA_CHUNKS = {
    b"iCCP", b"tEXt", b"zTXt", b"iTXt", b"eXIf", b"sPLT",
}
_PNG_CORE_VALIDATED_CHUNKS = {b"IHDR", b"PLTE", b"IDAT", b"IEND"}
_ANDROID_NINEPATCH_CHUNKS = {b"npTc", b"npLb", b"npOl"}
_WEBP_STANDARD_CHUNKS = {
    b"VP8 ", b"VP8L", b"VP8X", b"ALPH", b"ICCP", b"ANIM", b"ANMF", b"EXIF",
    b"XMP ",
}
_ELF_METADATA_PREFIXES = (
    ".dyn", ".gnu", ".hash", ".rel", ".note", ".eh_frame", ".gcc_except_table",
    ".got", ".plt", ".init", ".fini", ".interp", ".android", ".comment",
    ".symtab", ".strtab", ".shstrtab", ".arm", ".llvm", ".debug", ".zdebug",
    ".attributes",
)
_ELF_DATA_SECTION_PREFIXES = (".rodata", ".data")
_VM_SECTION_TOKENS = ("vm", "bytecode", "payload", "opcode", "dispatch", "packed")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _entropy(data: bytes) -> float:
    sample = data[: 1024 * 1024]
    if not sample:
        return 0.0
    counts = [0] * 256
    for value in sample:
        counts[value] += 1
    size = len(sample)
    return -sum(
        (count / size) * math.log2(count / size)
        for count in counts
        if count
    )


def _entropy_all(data: bytes) -> float:
    """Entropy over one already-bounded blob, without prefix-only blind spots."""
    if not data:
        return 0.0
    counts = [0] * 256
    for value in data:
        counts[value] += 1
    size = len(data)
    return -sum(
        (count / size) * math.log2(count / size)
        for count in counts
        if count
    )


def _chunk_entropy_profile(data: bytes, *, chunk_size: int = 64 * 1024) -> dict[str, Any]:
    """Account for every byte while bounding retained per-chunk evidence."""
    high_entropy: list[dict[str, Any]] = []
    maximum = 0.0
    chunks = 0
    high_count = 0
    for offset in range(0, len(data), chunk_size):
        chunk = data[offset:offset + chunk_size]
        entropy = _entropy_all(chunk)
        maximum = max(maximum, entropy)
        chunks += 1
        if entropy >= 7.2:
            high_count += 1
            if len(high_entropy) < 256:
                high_entropy.append({
                    "offset": offset, "bytes": len(chunk), "entropy": round(entropy, 4),
                })
    return {
        "bytes_accounted": len(data),
        "chunk_size": chunk_size,
        "chunk_count": chunks,
        "maximum_entropy": round(maximum, 4),
        "high_entropy_chunk_count": high_count,
        "high_entropy_chunks": high_entropy,
        "evidence_truncated": high_count > len(high_entropy),
    }


def _media_payload_profile(kind: str, data: bytes) -> dict[str, Any]:
    """Boundedly account standard media containers and expose hidden payload space."""
    reasons: list[str] = []
    custom_chunks: list[dict[str, Any]] = []
    accounted_end = 0
    structurally_complete = False

    if kind == "png" and data.startswith(b"\x89PNG\r\n\x1a\n"):
        png_width = png_height = 0
        png_bit_depth = png_color_type = png_interlace = -1
        idat_payloads: list[bytes] = []
        idat_closed = False
        png_chunks: dict[bytes, int] = {}
        cursor = 8
        for _ in range(100_000):
            if cursor + 12 > len(data):
                reasons.append("truncated-png-chunk-header")
                break
            size = struct.unpack(">I", data[cursor:cursor + 4])[0]
            chunk_type = data[cursor + 4:cursor + 8]
            end = cursor + 12 + size
            if end > len(data):
                reasons.append("truncated-png-chunk")
                break
            payload = data[cursor + 8:cursor + 8 + size]
            png_chunks[chunk_type] = png_chunks.get(chunk_type, 0) + 1
            if not re.fullmatch(rb"[A-Za-z]{4}", chunk_type):
                reasons.append("invalid-png-chunk-type")
            elif not 65 <= chunk_type[2] <= 90:
                reasons.append("png-chunk-reserved-bit-set")
            expected_crc = struct.unpack(">I", data[cursor + 8 + size:end])[0]
            if zlib.crc32(chunk_type + payload) & 0xFFFFFFFF != expected_crc:
                reasons.append("png-chunk-crc-mismatch")
            if chunk_type == b"IHDR" and size == 13:
                if cursor != 8 or png_chunks[chunk_type] != 1:
                    reasons.append("png-ihdr-order-or-cardinality")
                png_width, png_height = struct.unpack(">II", payload[:8])
                png_bit_depth, png_color_type = payload[8], payload[9]
                png_interlace = payload[12]
                if payload[10:12] != b"\x00\x00":
                    reasons.append("png-unsupported-compression-or-filter-method")
            elif chunk_type == b"IHDR":
                reasons.append("png-ihdr-size")
            if chunk_type == b"IDAT":
                if png_chunks.get(b"IHDR", 0) != 1 or png_chunks.get(b"IEND", 0):
                    reasons.append("png-idat-order")
                if idat_closed:
                    reasons.append("noncontiguous-png-idat")
                idat_payloads.append(payload)
            elif idat_payloads and chunk_type != b"IEND":
                idat_closed = True
            if chunk_type == b"PLTE":
                if png_chunks[chunk_type] != 1 or idat_payloads or size == 0 or size % 3:
                    reasons.append("png-plte-order-size-or-cardinality")
                if size > 768 or png_color_type in {0, 4}:
                    reasons.append("png-plte-invalid-for-color-type")
            if chunk_type == b"IEND":
                if size != 0 or png_chunks[chunk_type] != 1 or not idat_payloads:
                    reasons.append("png-iend-size-order-or-cardinality")
            if (
                chunk_type not in _PNG_STANDARD_CHUNKS
                and chunk_type not in _ANDROID_NINEPATCH_CHUNKS
                and 65 <= chunk_type[0] <= 90
            ):
                reasons.append("unknown-critical-png-chunk")
            if chunk_type in _ANDROID_NINEPATCH_CHUNKS:
                valid, detail = _validate_android_ninepatch_chunk(
                    chunk_type, payload, width=png_width, height=png_height,
                )
                if not valid:
                    custom_chunks.append({
                        "type": chunk_type.decode("ascii"), "offset": cursor,
                        "bytes": size, "validation": detail,
                    })
                    reasons.append("invalid-android-ninepatch-chunk")
            elif chunk_type not in _PNG_STANDARD_CHUNKS:
                entropy = _entropy_all(payload)
                custom_chunks.append({
                    "type": chunk_type.decode("ascii", "replace"),
                    "offset": cursor, "bytes": size, "entropy": round(entropy, 4),
                })
                # Unknown ancillary chunks are executable-payload hiding space
                # even when split into many sub-threshold fragments. Preserve
                # them for review unconditionally under the strict audit gate.
                reasons.append("custom-png-chunk")
            elif (
                chunk_type in _PNG_STANDARD_CHUNKS
                and chunk_type not in _PNG_CORE_VALIDATED_CHUNKS
            ):
                # Known ancillary/APNG/profile chunks are still arbitrary
                # data-bearing surfaces. Until each format has a bounded
                # semantic parser, route every occurrence to review; never
                # let attackers split data below a per-chunk threshold.
                entropy = _entropy_all(payload)
                custom_chunks.append({
                    "type": chunk_type.decode("ascii", "replace"),
                    "offset": cursor, "bytes": size,
                    "entropy": round(entropy, 4), "known_ancillary": True,
                })
                reasons.append("png-ancillary-semantics-not-validated")
            cursor = end
            accounted_end = cursor
            if chunk_type == b"IEND":
                structurally_complete = True
                break
        if structurally_complete and accounted_end != len(data):
            reasons.append("png-trailing-payload")
        if png_chunks.get(b"IHDR", 0) != 1:
            reasons.append("png-ihdr-cardinality")
        if png_chunks.get(b"IEND", 0) != 1:
            reasons.append("png-iend-cardinality")
        if png_color_type == 3 and png_chunks.get(b"PLTE", 0) != 1:
            reasons.append("png-indexed-color-plte-missing")
        expected_pixels = _png_expected_inflated_bytes(
            png_width, png_height, png_bit_depth, png_color_type, png_interlace,
        )
        if expected_pixels <= 0 or expected_pixels > 512 * 1024 * 1024:
            reasons.append("png-pixel-layout-unsupported-or-out-of-policy")
        elif not idat_payloads:
            reasons.append("png-idat-missing")
        else:
            inflater = zlib.decompressobj()
            inflated = bytearray()
            try:
                for payload in idat_payloads:
                    inflated.extend(inflater.decompress(
                        payload, max(0, expected_pixels + 1 - len(inflated))
                    ))
                    if len(inflated) > expected_pixels or inflater.unconsumed_tail:
                        reasons.append("png-idat-output-exceeds-layout")
                        break
                inflated.extend(inflater.flush(max(1, expected_pixels + 1 - len(inflated))))
                if not inflater.eof:
                    reasons.append("png-idat-zlib-stream-incomplete")
                if inflater.unused_data or inflater.unconsumed_tail:
                    reasons.append("png-idat-hidden-or-unconsumed-payload")
                if len(inflated) != expected_pixels:
                    reasons.append("png-inflated-pixel-size-mismatch")
                elif not _png_filter_bytes_valid(
                    inflated, png_width, png_height, png_bit_depth,
                    png_color_type, png_interlace,
                ):
                    reasons.append("png-invalid-scanline-filter")
            except zlib.error:
                reasons.append("png-idat-zlib-invalid")
    elif kind == "webp" and data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        reasons.append("webp-codec-payload-not-semantically-validated")
        declared_end = 8 + int.from_bytes(data[4:8], "little")
        if declared_end != len(data):
            reasons.append("webp-size-or-trailing-payload")
        cursor = 12
        limit = min(declared_end, len(data))
        while cursor + 8 <= limit:
            chunk_type = data[cursor:cursor + 4]
            size = int.from_bytes(data[cursor + 4:cursor + 8], "little")
            end = cursor + 8 + size
            padded_end = end + (size & 1)
            if end > limit or padded_end > limit:
                reasons.append("truncated-webp-chunk")
                break
            payload = data[cursor + 8:end]
            if chunk_type not in _WEBP_STANDARD_CHUNKS:
                entropy = _entropy_all(payload)
                custom_chunks.append({
                    "type": chunk_type.decode("ascii", "replace"),
                    "offset": cursor, "bytes": size, "entropy": round(entropy, 4),
                })
                if size >= 64 or entropy >= 7.2:
                    reasons.append("custom-webp-chunk")
            cursor = padded_end
            accounted_end = cursor
        structurally_complete = cursor == limit == len(data)
        if not structurally_complete and not reasons:
            reasons.append("webp-container-unaccounted")
    elif kind == "jpeg" and data.startswith(b"\xff\xd8\xff"):
        reasons.append("jpeg-codec-payload-not-semantically-validated")
        # Entropy-coded JPEG bytes escape marker values with FF00, so the first
        # EOI is the container boundary. Using rfind would let appended payload
        # bytes hide simply by ending in another FF D9 pair.
        eoi = data.find(b"\xff\xd9", 2)
        structurally_complete = eoi >= 2
        accounted_end = eoi + 2 if structurally_complete else 0
        if not structurally_complete:
            reasons.append("jpeg-eoi-missing")
        elif accounted_end != len(data):
            reasons.append("jpeg-trailing-payload")
    elif kind == "ogg" and data.startswith(b"OggS"):
        reasons.append("ogg-codec-payload-not-semantically-validated")
        cursor = 0
        pages = 0
        while cursor + 27 <= len(data) and data[cursor:cursor + 4] == b"OggS":
            segments = data[cursor + 26]
            header_end = cursor + 27 + segments
            if header_end > len(data):
                break
            body_size = sum(data[cursor + 27:header_end])
            end = header_end + body_size
            if end > len(data):
                break
            cursor = end
            pages += 1
        accounted_end = cursor
        structurally_complete = pages > 0 and cursor == len(data)
        if not structurally_complete:
            reasons.append("ogg-pages-unaccounted-or-trailing-payload")
    else:
        reasons.append("unsupported-media-accounting")

    entropy_profile = _chunk_entropy_profile(data)
    return {
        "kind": kind,
        "structurally_complete": structurally_complete,
        "bytes_accounted": accounted_end,
        "total_bytes": len(data),
        "custom_chunks": custom_chunks,
        "entropy": entropy_profile,
        "suspicious": bool(reasons),
        "reasons": sorted(set(reasons)),
    }


def _validate_android_ninepatch_chunk(
    chunk_type: bytes,
    payload: bytes,
    *,
    width: int,
    height: int,
) -> tuple[bool, str]:
    """Validate AOSP's bounded npTc/npLb/npOl compiled resource layouts."""

    if chunk_type == b"npLb":
        if len(payload) != 16:
            return False, "npLb-size"
        values = struct.unpack("<4i", payload)
        return (all(value >= 0 for value in values), "npLb-insets")
    if chunk_type == b"npOl":
        if len(payload) != 24:
            return False, "npOl-size"
        insets = struct.unpack("<4i", payload[:16])
        radius = struct.unpack("<f", payload[16:20])[0]
        alpha = struct.unpack("<I", payload[20:24])[0]
        valid = all(value >= 0 for value in insets) and math.isfinite(radius)
        valid = valid and radius >= 0 and alpha <= 0xFF
        return valid, "npOl-outline"
    if chunk_type != b"npTc" or len(payload) < 32:
        return False, "npTc-header"
    _deserialized, x_count, y_count, color_count = payload[:4]
    expected_size = 32 + 4 * (x_count + y_count + color_count)
    if len(payload) != expected_size:
        return False, "npTc-serialized-size"
    x_offset, y_offset = struct.unpack("<II", payload[4:12])
    colors_offset = struct.unpack("<I", payload[28:32])[0]
    if (x_offset, y_offset, colors_offset) != (
        32, 32 + 4 * x_count, 32 + 4 * (x_count + y_count),
    ):
        return False, "npTc-array-offsets"
    padding_left, padding_right, padding_top, padding_bottom = struct.unpack(
        ">4i", payload[12:28]
    )
    if any(value < 0 for value in (
        padding_left, padding_right, padding_top, padding_bottom,
    )):
        return False, "npTc-padding-negative"
    if width and padding_left + padding_right > width:
        return False, "npTc-horizontal-padding-bounds"
    if height and padding_top + padding_bottom > height:
        return False, "npTc-vertical-padding-bounds"
    if x_count == 0 or y_count == 0 or x_count % 2 or y_count % 2:
        return False, "npTc-division-counts"
    # Res_png_9patch keeps its serialized offsets in host order, while
    # deviceToFile() converts coordinate/color words to PNG (big-endian)
    # representation before aapt writes npTc.
    x_divs = struct.unpack(f">{x_count}i", payload[x_offset:y_offset])
    y_divs = struct.unpack(f">{y_count}i", payload[y_offset:colors_offset])
    if any(left < 0 or left >= right for left, right in zip(x_divs, x_divs[1:])):
        return False, "npTc-x-divisions"
    if any(top < 0 or top >= bottom for top, bottom in zip(y_divs, y_divs[1:])):
        return False, "npTc-y-divisions"
    if width and x_divs and x_divs[-1] > width:
        return False, "npTc-x-bounds"
    if height and y_divs and y_divs[-1] > height:
        return False, "npTc-y-bounds"
    expected_columns = x_count + 1 - int(x_divs[0] == 0) - int(x_divs[-1] == width)
    expected_rows = y_count + 1 - int(y_divs[0] == 0) - int(y_divs[-1] == height)
    expected_colors = expected_columns * expected_rows
    if color_count != expected_colors:
        return False, "npTc-color-count"
    return True, "valid"


def _png_expected_inflated_bytes(
    width: int, height: int, bit_depth: int, color_type: int, interlace: int,
) -> int:
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 0)
    allowed_depths = {
        0: {1, 2, 4, 8, 16}, 2: {8, 16}, 3: {1, 2, 4, 8},
        4: {8, 16}, 6: {8, 16},
    }
    if (
        width <= 0 or height <= 0 or channels == 0
        or bit_depth not in allowed_depths.get(color_type, set())
        or interlace not in {0, 1}
    ):
        return 0

    def pass_bytes(pass_width: int, pass_height: int) -> int:
        return pass_height * (1 + (pass_width * channels * bit_depth + 7) // 8)

    if interlace == 0:
        return pass_bytes(width, height)
    total = 0
    for x_start, y_start, x_step, y_step in (
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2),
    ):
        pass_width = max(0, (width - x_start + x_step - 1) // x_step)
        pass_height = max(0, (height - y_start + y_step - 1) // y_step)
        if pass_width and pass_height:
            total += pass_bytes(pass_width, pass_height)
    return total


def _png_filter_bytes_valid(
    inflated: bytes,
    width: int,
    height: int,
    bit_depth: int,
    color_type: int,
    interlace: int,
) -> bool:
    channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(color_type, 0)
    if channels == 0:
        return False
    passes = [(0, 0, 1, 1)] if interlace == 0 else [
        (0, 0, 8, 8), (4, 0, 8, 8), (0, 4, 4, 8), (2, 0, 4, 4),
        (0, 2, 2, 4), (1, 0, 2, 2), (0, 1, 1, 2),
    ]
    cursor = 0
    for x_start, y_start, x_step, y_step in passes:
        pass_width = max(0, (width - x_start + x_step - 1) // x_step)
        pass_height = max(0, (height - y_start + y_step - 1) // y_step)
        if not pass_width or not pass_height:
            continue
        row_bytes = (pass_width * channels * bit_depth + 7) // 8
        for _ in range(pass_height):
            if cursor >= len(inflated) or inflated[cursor] > 4:
                return False
            cursor += 1 + row_bytes
    return cursor == len(inflated)


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 1.0
    printable = sum(value in b"\r\n\t" or 0x20 <= value <= 0x7E for value in data)
    return printable / len(data)


def _elf_nonexec_data_profile(data: bytes) -> dict[str, Any]:
    """Account ELF non-code bytes and fail closed on plausible embedded VM payloads."""
    elf = parse_elf(data)
    if elf is None:
        return {
            "complete": False, "status": "unparseable-elf", "sections": [],
            "suspicious_sections": ["<unparseable>"],
        }
    rows: list[dict[str, Any]] = []
    suspicious: list[str] = []
    candidates = [section for section in elf.sections if not section.executable and section.size]
    for index, section in enumerate(candidates):
        if section.sh_type == 8:  # SHT_NOBITS: no file bytes to conceal a packaged payload.
            continue
        start, end = int(section.offset), int(section.offset + section.size)
        if start < 0 or end > len(data) or end < start:
            suspicious.append(section.name or f"section-{index}")
            rows.append({
                "name": section.name, "offset": start, "bytes": section.size,
                "status": "out-of-bounds", "suspicious": True,
            })
            continue
        payload = data[start:end]
        entropy = _entropy_all(payload)
        printable = _printable_ratio(payload)
        name = section.name or f"section-{index}"
        lower = name.lower()
        metadata = lower.startswith(_ELF_METADATA_PREFIXES)
        explicit_vm = any(token in lower for token in _VM_SECTION_TOKENS)
        data_candidate = lower.startswith(_ELF_DATA_SECTION_PREFIXES)
        custom = bool(lower and not lower.startswith(".") or (
            lower.startswith(".") and not metadata and not data_candidate
        ))
        suspect = bool(
            explicit_vm
            or (custom and len(payload) >= 256)
            or (
                metadata and len(payload) >= 64 * 1024
                and printable < 0.60 and entropy >= 7.2
            )
            or (
                data_candidate and len(payload) >= 4096
                and printable < 0.60 and entropy >= 5.5
            )
        )
        if suspect:
            suspicious.append(name)
        rows.append({
            "name": name, "offset": start, "bytes": len(payload),
            "sha256": _sha256(payload), "entropy": round(entropy, 4),
            "printable_ratio": round(printable, 4), "metadata": metadata,
            "suspicious": suspect,
        })
    if elf.sections:
        section_ranges = sorted(
            (int(section.offset), int(section.offset + section.size))
            for section in elf.sections
            if section.sh_type != 8 and section.size
            and 0 <= section.offset <= section.offset + section.size <= len(data)
        )
        for index, segment in enumerate(elf.segments):
            if segment.executable or not segment.filesz:
                continue
            seg_start = max(0, int(segment.offset))
            seg_end = min(len(data), int(segment.offset + segment.filesz))
            cursor = seg_start
            for left, right in section_ranges:
                if right <= cursor or left >= seg_end:
                    continue
                gap_end = min(left, seg_end)
                if gap_end > cursor:
                    payload = data[cursor:gap_end]
                    entropy = _entropy_all(payload)
                    printable = _printable_ratio(payload)
                    suspect = (
                        len(payload) >= 4096 and printable < 0.60 and entropy >= 5.5
                    )
                    name = f"PT_LOAD-{index}-gap-{cursor:x}"
                    if suspect:
                        suspicious.append(name)
                    rows.append({
                        "name": name, "offset": cursor, "bytes": len(payload),
                        "sha256": _sha256(payload), "entropy": round(entropy, 4),
                        "printable_ratio": round(printable, 4), "metadata": True,
                        "suspicious": suspect, "kind": "unsectioned-segment-bytes",
                    })
                cursor = max(cursor, min(right, seg_end))
                if cursor >= seg_end:
                    break
            if cursor < seg_end:
                payload = data[cursor:seg_end]
                entropy = _entropy_all(payload)
                printable = _printable_ratio(payload)
                suspect = len(payload) >= 4096 and printable < 0.60 and entropy >= 5.5
                name = f"PT_LOAD-{index}-gap-{cursor:x}"
                if suspect:
                    suspicious.append(name)
                rows.append({
                    "name": name, "offset": cursor, "bytes": len(payload),
                    "sha256": _sha256(payload), "entropy": round(entropy, 4),
                    "printable_ratio": round(printable, 4), "metadata": True,
                    "suspicious": suspect, "kind": "unsectioned-segment-bytes",
                })
    if not elf.sections:
        for index, segment in enumerate(elf.segments):
            if segment.executable or not segment.filesz:
                continue
            start, end = int(segment.offset), int(segment.offset + segment.filesz)
            if start < 0 or end > len(data) or end < start:
                suspicious.append(f"segment-{index}")
                continue
            payload = data[start:end]
            entropy = _entropy_all(payload)
            printable = _printable_ratio(payload)
            suspect = len(payload) >= 4096 and printable < 0.60 and entropy >= 5.5
            if suspect:
                suspicious.append(f"segment-{index}")
            rows.append({
                "name": f"PT_LOAD-{index}", "offset": start, "bytes": len(payload),
                "sha256": _sha256(payload), "entropy": round(entropy, 4),
                "printable_ratio": round(printable, 4), "metadata": False,
                "suspicious": suspect,
            })
    return {
        "status": "complete" if not suspicious else "suspicious-data",
        "complete": not suspicious,
        "policy": (
            "all file-backed non-executable sections are hash/entropy-accounted; "
            "custom sections, explicit VM sections, and large opaque rodata/data block completion"
        ),
        "sections": rows,
        "suspicious_sections": sorted(set(suspicious)),
    }


def _looks_text(data: bytes) -> bool:
    sample = data[: 128 * 1024]
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        return False
    printable = sum(char.isprintable() or char in "\r\n\t" for char in decoded)
    return printable / max(1, len(decoded)) >= 0.90


def detect_android_binary_format(name: str, data: bytes) -> str:
    """Classify a member from magic bytes with extension only as a fallback."""
    lower = name.lower()
    suffix = Path(lower).suffix
    if data.startswith(b"\x7fELF"):
        return "elf"
    if data.startswith(b"dex\n"):
        return "dex"
    if data.startswith(b"cdex"):
        return "compact_dex"
    if data.startswith(b"\xca\xfe\xba\xbe"):
        return "java_class"
    if data.startswith(b"\x00asm"):
        return "wasm"
    if data.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if data.startswith((b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08")):
        return "zip"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"OggS"):
        return "ogg"
    if data.startswith(b"\x00\x01\x00\x00") and suffix in {".ttf", ".otf"}:
        return "font"
    if suffix == ".arsc":
        return "android_resource_table"
    if suffix == ".xml" and not _looks_text(data):
        return "android_binary_xml"
    if _looks_text(data):
        return "text"
    return "opaque_binary"


def _security_relevant(name: str, kind: str, entropy: float) -> tuple[bool, str]:
    lower = name.lower()
    suffix = Path(lower).suffix
    # Executable content identity always wins over conventional paths. Expected
    # signature/profile metadata may remain non-reviewable only when it does not
    # identify as code or a nested executable container.
    if kind in {"elf", "dex", "compact_dex", "java_class", "wasm", "sqlite", "zip"}:
        return True, f"embedded-{kind}"
    if (
        lower.startswith("meta-inf/")
        and suffix in {".rsa", ".dsa", ".ec", ".sf", ".mf"}
    ):
        return False, "signature-container-covered-by-provenance"
    if lower.startswith("assets/dexopt/baseline.prof"):
        return False, "android-runtime-optimization-profile"
    if lower.startswith("kotlin/") and suffix == ".kotlin_builtins":
        return False, "kotlin-standard-library-metadata"
    if lower.endswith("okhttp3/internal/publicsuffix/publicsuffixes.gz"):
        return False, "okhttp-public-suffix-data"
    if kind == "opaque_binary":
        return True, "opaque-payload" if entropy < 7.2 else "high-entropy-opaque-payload"
    if kind == "text" and (
        suffix in _TEXT_SUFFIXES or lower.startswith(("assets/", "res/raw/"))
    ):
        return True, "reviewable-text"
    return False, f"known-{kind}-resource"


def _embedded_executable_magics(data: bytes) -> list[dict[str, Any]]:
    """Locate executable/container magic at non-zero offsets (polyglot signal)."""
    hits: list[dict[str, Any]] = []
    for kind, magic in _EXECUTABLE_MAGICS.items():
        start = 1
        while len(hits) < 64:
            offset = data.find(magic, start)
            if offset < 0:
                break
            hits.append({"format": kind, "offset": offset})
            start = offset + 1
    return sorted(hits, key=lambda item: int(item["offset"]))


def _safe_export_name(member: str, digest: str) -> str:
    leaf = re.sub(r"[^A-Za-z0-9._-]+", "_", member).strip("._") or "member"
    return f"{digest[:16]}_{leaf[-160:]}"


def scan_apk_binary_members(
    apk_path: str | Path,
    *,
    export_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Inventory every APK member and export security-relevant binary payloads."""
    apk = Path(apk_path)
    destination = Path(export_dir) if export_dir is not None else None
    if destination is not None:
        destination.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, Any]] = []
    exported_code: list[str] = []
    exported_code_targets: list[dict[str, Any]] = []
    unresolved_opaque: list[str] = []
    skipped: list[dict[str, Any]] = []
    try:
        archive = zipfile.ZipFile(apk)
    except (OSError, zipfile.BadZipFile) as exc:
        return {"status": "error", "note": str(exc), "members": []}
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            if info.file_size > MEMBER_LIMIT:
                skipped.append({
                    "member": info.filename,
                    "bytes": info.file_size,
                    "reason": f"exceeds-{MEMBER_LIMIT // (1024 * 1024)}MiB-member-budget",
                })
                continue
            try:
                with archive.open(info) as handle:
                    data = handle.read(MEMBER_LIMIT + 1)
            except (KeyError, OSError, RuntimeError, zipfile.BadZipFile) as exc:
                skipped.append({"member": info.filename, "reason": type(exc).__name__})
                continue
            if len(data) > MEMBER_LIMIT:
                skipped.append({"member": info.filename, "reason": "read-budget-exceeded"})
                continue
            digest = _sha256(data)
            entropy = _entropy(data)
            kind = detect_android_binary_format(info.filename, data)
            relevant, reason = _security_relevant(info.filename, kind, entropy)
            payload_profile: dict[str, Any] = {}
            if kind in _MEDIA_KINDS:
                payload_profile = _media_payload_profile(kind, data)
                if payload_profile.get("suspicious"):
                    relevant, reason = True, "suspicious-media-or-custom-payload"
            native_data_profile: dict[str, Any] = {}
            if kind == "elf":
                native_data_profile = _elf_nonexec_data_profile(data)
                if not native_data_profile.get("complete"):
                    relevant, reason = True, "native-nonexec-payload-unresolved"
            embedded_payloads = _embedded_executable_magics(data)
            if embedded_payloads:
                relevant, reason = True, "polyglot-or-embedded-executable-payload"
            record: dict[str, Any] = {
                "member": info.filename,
                "bytes": len(data),
                "compressed_bytes": info.compress_size,
                "sha256": digest,
                "format": kind,
                "entropy": round(entropy, 4),
                "review_required": relevant,
                "review_reason": reason,
                "embedded_payloads": embedded_payloads,
                "payload_profile": payload_profile,
                "native_data_profile": native_data_profile,
                "exported_path": "",
            }
            # Export every DEX independently.  APK-level aggregate decompilation
            # cannot prove that classes2.dex/classesN.dex were covered.
            # Export every review-required member, including extensionless text.
            # This creates an authoritative APK-member -> AI-artifact mapping;
            # relying on apktool paths or suffixes can silently lose assets/config.
            should_export = relevant and destination is not None
            if should_export:
                output = destination / _safe_export_name(info.filename, digest)
                output.write_bytes(data)
                record["exported_path"] = str(output.resolve())
                if kind in {"dex", "compact_dex", "java_class"}:
                    exported_code.append(str(output.resolve()))
                    exported_code_targets.append({
                        "path": str(output.resolve()),
                        "format": kind,
                        "member": info.filename,
                        "sha256": digest,
                    })
            if (
                (kind == "opaque_binary" and relevant)
                or embedded_payloads
                or bool(payload_profile.get("suspicious"))
                or (kind == "elf" and not native_data_profile.get("complete"))
            ):
                unresolved_opaque.append(info.filename)
            records.append(record)
    formats: dict[str, int] = {}
    for item in records:
        formats[item["format"]] = formats.get(item["format"], 0) + 1
    return {
        "schema_version": 1,
        "status": "partial" if skipped else "success",
        "apk": str(apk.resolve()),
        "member_count": len(records),
        "formats": formats,
        "review_required_count": sum(bool(item["review_required"]) for item in records),
        "exported_code_files": exported_code,
        "exported_code_targets": exported_code_targets,
        "unresolved_opaque_members": unresolved_opaque,
        "native_members": [
            item["member"] for item in records if item.get("format") == "elf"
        ],
        "native_structural_gate_complete": all(
            item.get("native_data_profile", {}).get("complete") is True
            for item in records if item.get("format") == "elf"
        ),
        "skipped": skipped,
        "members": records,
        "classification_policy": "magic-first; extension is fallback only",
        "budgets": {
            "member_bytes": MEMBER_LIMIT,
            "disassembly_bytes": DISASSEMBLY_LIMIT,
            "ida_evidence_bytes": IDA_EVIDENCE_LIMIT,
        },
    }


def _extract_strings(data: bytes) -> tuple[list[dict[str, Any]], bool]:
    found: list[dict[str, Any]] = []
    truncated = False
    for match in re.finditer(rb"[\x20-\x7e]{4,}", data):
        if len(found) >= STRINGS_LIMIT:
            truncated = True
            break
        found.append({
            "offset": match.start(),
            "value": match.group()[:4096].decode("ascii", "replace"),
        })
    return found, truncated


def _elf_manifest(data: bytes) -> dict[str, Any]:
    elf = parse_elf(data)
    if elf is None:
        return {"status": "not-elf", "sections": [], "symbols": [], "executable_ranges": []}
    registration = resolve_jni_registration(data)
    return {
        "status": "parsed" if not elf.errors else "partial",
        "bits": 64 if elf.is64 else 32,
        "endian": "little" if elf.endian == "<" else "big",
        "machine": elf.machine,
        "errors": elf.errors,
        "sections": [
            {
                "name": section.name,
                "address": section.addr,
                "offset": section.offset,
                "size": section.size,
                "executable": section.executable,
                "writable": section.writable,
            }
            for section in elf.sections
        ],
        "executable_ranges": [
            {"address": address, "size": size}
            for address, size in elf.exec_ranges()
        ],
        "symbols": [
            {"name": symbol.name, "address": symbol.addr, "size": symbol.size,
             "imported": symbol.imported}
            for symbol in elf.symbols
        ],
        "jni": {
            "status": registration.status,
            "statically_named": registration.statically_named,
            "dynamically_registered": [
                {"name": item.java_name, "signature": item.signature, "address": item.fn_addr}
                for item in registration.dynamically_registered
            ],
            "jni_onload_present": registration.jni_onload_present,
            "registernatives_imported": registration.registernatives_imported,
        },
    }


def _write_disassembly(
    target: Path,
    output: Path,
    *,
    timeout: int,
    observation_workspace: str | Path | None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    tool = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not tool:
        return {"status": "tool-unavailable", "complete": False, "tool": ""}
    args = [tool, "--disassemble", "--no-show-raw-insn", str(target)]
    partial = output.with_suffix(output.suffix + ".partial")
    stderr_partial = output.with_suffix(output.suffix + ".stderr.partial")
    idle_timeout = _seconds_budget(
        "ANGERONA_ANDROID_OBJDUMP_IDLE_TIMEOUT_SECONDS", max(timeout, 600), 7_200
    )
    wall_timeout = max(
        idle_timeout,
        _seconds_budget(
            "ANGERONA_ANDROID_OBJDUMP_WALL_TIMEOUT_SECONDS", 86_400, 172_800
        ),
    )
    if deadline_monotonic is not None:
        remaining = max(0.001, deadline_monotonic - time.monotonic())
        wall_timeout = min(wall_timeout, remaining)
        idle_timeout = min(idle_timeout, wall_timeout)
    try:
        # Full native disassembly can be hundreds of MiB. Stream it to disk so
        # subprocess pipes cannot retain the whole rendering in controller RAM.
        # Output growth resets the idle watchdog, so a large healthy target is
        # not killed by a fixed wall-clock timeout. The bounded final evidence
        # is published only after a clean exit; timeout partials remain invalid.
        with partial.open("wb") as stdout, stderr_partial.open("wb") as stderr:
            result = observed_progress_run(
                args,
                progress_path=partial,
                idle_timeout=idle_timeout,
                wall_timeout=wall_timeout,
                stdout=stdout,
                stderr=stderr,
                stdin=subprocess.DEVNULL,
                observation_workspace=observation_workspace,
                max_rss_bytes=bounded_env_int(
                    "ANGERONA_OBJDUMP_MAX_RSS_MB", 2048,
                    minimum=256, maximum=16384,
                ) * 1024 * 1024,
                max_processes=bounded_env_int(
                    "ANGERONA_OBJDUMP_MAX_PROCESSES", 32,
                    minimum=2, maximum=256,
                ),
                resource_paths=[partial, stderr_partial],
                max_output_bytes=DISASSEMBLY_LIMIT + 16 * 1024 * 1024,
                min_free_bytes=bounded_env_int(
                    "ANGERONA_ANDROID_MIN_FREE_GIB", 8,
                    minimum=1, maximum=128,
                ) * 1024**3,
            )
    except (OSError, ProgressTimeoutExpired) as exc:
        try:
            stderr_text = stderr_partial.read_bytes()[:2000].decode("utf-8", "replace")
        except OSError:
            stderr_text = ""
        partial.unlink(missing_ok=True)
        stderr_partial.unlink(missing_ok=True)
        return {
            "status": type(exc).__name__, "complete": False, "tool": tool,
            "bytes": 0, "published": False,
            "timeout_reason": getattr(exc, "reason", ""),
            "progress_bytes": int(getattr(exc, "progress_bytes", 0)),
            "progress_items": int(getattr(exc, "progress_items", 0)),
            "progress_events": int(getattr(exc, "progress_events", 0)),
            "cpu_ticks": int(getattr(exc, "cpu_ticks", 0)),
            "elapsed_seconds": round(float(getattr(exc, "elapsed_seconds", 0.0)), 3),
            "idle_timeout_seconds": idle_timeout,
            "wall_timeout_seconds": wall_timeout,
            "stderr": stderr_text,
        }
    with partial.open("rb") as stream:
        encoded = stream.read(DISASSEMBLY_LIMIT + 1)
    partial.unlink(missing_ok=True)
    truncated = len(encoded) > DISASSEMBLY_LIMIT
    encoded = encoded[:DISASSEMBLY_LIMIT]
    if encoded:
        output.write_bytes(encoded)
    else:
        output.unlink(missing_ok=True)
    try:
        stderr_text = stderr_partial.read_bytes()[:2000].decode("utf-8", "replace")
    except OSError:
        stderr_text = ""
    stderr_partial.unlink(missing_ok=True)
    complete = result.returncode == 0 and not truncated and bool(encoded.strip())
    return {
        "status": "success" if result.returncode == 0 else "failed",
        "complete": complete,
        "tool": tool,
        "returncode": result.returncode,
        "truncated": truncated,
        "bytes": len(encoded),
        "published": bool(encoded),
        "progress_bytes": result.progress_bytes,
        "progress_items": result.progress_items,
        "progress_events": result.progress_events,
        "cpu_ticks": result.cpu_ticks,
        "elapsed_seconds": result.elapsed_seconds,
        "idle_timeout_seconds": idle_timeout,
        "wall_timeout_seconds": wall_timeout,
        "stderr": stderr_text,
    }


def _write_ida_evidence(
    target: Path, output: Path, *, timeout: int,
    deadline_monotonic: float | None = None,
    allowed_ranges: list[dict[str, Any]] | None = None,
    range_authority_sha256: str | None = None,
    native_authority: dict[str, Any] | None = None,
    native_authority_token: str | None = None,
) -> dict[str, Any]:
    """Run the licensed IDA/idalib backend and persist its immutable full export."""
    try:
        from src.engines.ida import IdaEngine

        engine = IdaEngine()
        if native_authority is not None:
            engine.configure_native_authority(native_authority, native_authority_token)
        status = engine.status()
        if not status.get("ready"):
            return {
                "status": "unavailable", "complete": False,
                "message": status.get("message", "IDA is not ready"),
            }
        analysis = engine.analyze(
            target, decompile=True, max_functions=0, force=False, timeout=timeout,
            deadline_monotonic=deadline_monotonic,
            allowed_ranges=allowed_ranges,
            range_authority_sha256=range_authority_sha256,
            native_authority_token=native_authority_token,
        )
    except Exception as exc:  # noqa: BLE001 - producer failure is evidence
        return {
            "status": "failed", "complete": False,
            "error": f"{type(exc).__name__}: {exc}"[:4000],
        }
    functions = [item for item in analysis.get("functions", []) if isinstance(item, dict)]
    producer_validation = None
    projection_validation = None
    restricted_text_receipts: list[dict[str, Any]] = []
    if allowed_ranges is not None:
        address_bias = int(str((analysis.get("metadata") or {}).get("image_base") or "0"), 16)
        allowed_intervals = [
            (int(row["address"]) + address_bias,
             int(row["address"]) + address_bias + int(row["size"]))
            for row in allowed_ranges
        ]
        producer_validation = validate_restricted_evidence(
            analysis, allowed_ranges, bias=address_bias,
        )
        if not producer_validation["valid"]:
            return {
                "status": "failed", "complete": False,
                "error": "IDA restricted producer contains out-of-authority address evidence",
                "producer_restricted_validation": producer_validation,
            }
        producer_coverage = analysis.get("restricted_allowed_coverage") or {}
        expected_allowed_bytes = sum(end - start for start, end in allowed_intervals)
        if (
            producer_coverage.get("complete") is not True
            or int(producer_coverage.get("allowed_bytes") or -1) != expected_allowed_bytes
            or int(producer_coverage.get("covered_bytes") or -1) != expected_allowed_bytes
        ):
            return {
                "status": "failed", "complete": False,
                "error": "IDA restricted producer coverage is incomplete",
                "producer_restricted_validation": producer_validation,
                "producer_restricted_coverage": producer_coverage,
            }
    disassembled = sum(bool(item.get("disassembly")) for item in functions)
    decompiled = sum(bool(item.get("decompiled")) for item in functions)
    internal = [item for item in functions if not item.get("is_external")]
    internal_recovered = sum(bool(item.get("decompiled")) for item in internal)
    truncated_functions = sum(
        bool(item.get("decompiled_truncated")) for item in internal
    )
    parsed_elf = parse_elf(target.read_bytes())
    executable_ranges = (
        [(int(row["address"]) + address_bias, int(row["size"])) for row in allowed_ranges]
        if allowed_ranges is not None else
        list(parsed_elf.exec_ranges()) if parsed_elf is not None else []
    )
    function_ranges: list[tuple[int, int]] = []
    for function in functions:
        for item in function.get("body_ranges", []) or []:
            try:
                start = int(str(item.get("start")), 0)
                size = int(item.get("size", 0))
            except (TypeError, ValueError):
                continue
            if size > 0:
                function_ranges.append((start, start + size))

    merged_function_ranges: list[list[int]] = []
    for start, end in sorted(function_ranges):
        if merged_function_ranges and start <= merged_function_ranges[-1][1]:
            merged_function_ranges[-1][1] = max(merged_function_ranges[-1][1], end)
        else:
            merged_function_ranges.append([start, end])
    expected_merged_ranges: list[list[int]] = []
    for start, size in sorted(executable_ranges):
        end = start + size
        if expected_merged_ranges and start <= expected_merged_ranges[-1][1]:
            expected_merged_ranges[-1][1] = max(expected_merged_ranges[-1][1], end)
        else:
            expected_merged_ranges.append([start, end])
    exact_body_union_complete = bool(
        allowed_ranges is None or merged_function_ranges == expected_merged_ranges
    )
    if allowed_ranges is not None and not exact_body_union_complete:
        return {
            "status": "failed", "complete": False,
            "error": "IDA restricted body union has a gap or extra byte",
            "producer_restricted_validation": producer_validation,
            "expected_allowed_intervals": expected_merged_ranges,
            "merged_function_body_intervals": merged_function_ranges,
        }

    def covered_bytes(start: int, size: int) -> int:
        end = start + size
        clipped = sorted(
            (max(start, fn_start), min(end, fn_end))
            for fn_start, fn_end in function_ranges
            if fn_end > start and fn_start < end
        )
        total = 0
        cursor = start
        for left, right in clipped:
            if right <= cursor:
                continue
            left = max(left, cursor)
            total += max(0, right - left)
            cursor = max(cursor, right)
        return total

    executable_bytes = sum(size for _start, size in executable_ranges)
    assigned_executable_bytes = sum(
        covered_bytes(start, size) for start, size in executable_ranges
    )
    executable_coverage = (
        assigned_executable_bytes / executable_bytes if executable_bytes else 0.0
    )
    projection = {
        "schema": "angerona/ida-selective-publication/v1",
        "metadata": {
            key: (analysis.get("metadata") or {}).get(key)
            for key in (
                "filename", "executable_format", "processor", "bits", "pointer_size",
                "endian", "language_id", "image_base", "sha256", "function_count",
            )
        },
        "imports": analysis.get("imports", []),
        "exports": analysis.get("exports", []),
        "functions": [],
        "analysis_scope": analysis.get("analysis_scope"),
        "range_authority_sha256": analysis.get("range_authority_sha256"),
        "native_launch_authority_token": analysis.get("native_launch_authority_token"),
        "restricted_allowed_coverage": analysis.get("restricted_allowed_coverage"),
    }
    for function in functions:
        decompiled = str(function.get("decompiled") or "")
        if allowed_ranges is not None:
            decompiled, text_receipt = sanitize_restricted_text(
                decompiled, allowed_ranges, bias=address_bias,
            )
            restricted_text_receipts.append(text_receipt)
        projection["functions"].append({
            "name": function.get("name"),
            "entry": function.get("entry"),
            "size": function.get("size"),
            "body_ranges": function.get("body_ranges", []),
            "signature": function.get("signature"),
            "callers": function.get("callers", []),
            "callees": function.get("callees", []),
            "xrefs_to": function.get("xrefs_to", []),
            "disassembly": function.get("disassembly", []),
            "pcode": function.get("pcode", []),
            "decompiled": decompiled,
        })
    if allowed_ranges is not None:
        projection = canonicalize_cross_range_references(
            projection, allowed_ranges, bias=address_bias,
        )
        projection_validation = validate_restricted_evidence(
            projection, allowed_ranges, bias=address_bias,
        )
        if not projection_validation["valid"]:
            return {
                "status": "failed", "complete": False,
                "error": "IDA emitted projection contains out-of-authority address evidence",
                "producer_restricted_validation": producer_validation,
                "projection_restricted_validation": projection_validation,
            }

    # Stream function-oriented evidence directly to its bounded artifact.  The
    # former list+join path could temporarily allocate several copies of a very
    # large IDA export before discovering it exceeded the publication limit.
    written = 0
    truncated = False

    def emit(line: str) -> None:
        nonlocal written, truncated
        if truncated:
            return
        payload = (line + "\n").encode("utf-8", "replace")
        remaining = IDA_EVIDENCE_LIMIT - written
        if len(payload) > remaining:
            if remaining > 0:
                stream.write(payload[:remaining])
                written += remaining
            truncated = True
            return
        stream.write(payload)
        written += len(payload)

    with output.open("wb") as stream:
        emit("IDA_PRO_ANALYSIS_V1")
        emit("METADATA " + json.dumps(projection["metadata"], sort_keys=True, default=str))
        emit("IMPORTS " + json.dumps(projection["imports"], sort_keys=True, default=str))
        emit("EXPORTS " + json.dumps(projection["exports"], sort_keys=True, default=str))
        for function in projection["functions"]:
            emit(
                "FUNCTION " + json.dumps({
                "name": function.get("name"),
                "entry": function.get("entry"),
                "size": function.get("size"),
                "body_ranges": function.get("body_ranges", []),
                "signature": function.get("signature"),
                "callers": function.get("callers", []),
                "callees": function.get("callees", []),
                "xrefs_to": function.get("xrefs_to", []),
                }, sort_keys=True, default=str)
            )
            emit("DISASSEMBLY_BEGIN")
            for instruction in (function.get("disassembly") or []):
                emit(json.dumps(instruction, sort_keys=True, default=str))
            emit("DISASSEMBLY_END")
            emit("PCODE_BEGIN")
            for operation in (function.get("pcode") or []):
                emit(json.dumps(operation, sort_keys=True, default=str))
            emit("PCODE_END")
            emit("PSEUDOCODE_BEGIN")
            for line in str(function.get("decompiled") or "").splitlines():
                emit(line)
            emit("PSEUDOCODE_END")
        stream.flush()
        os.fsync(stream.fileno())
    metadata = analysis.get("metadata", {})
    ida_executable = metadata.get("executable_coverage", {})
    enumerated_complete = int(metadata.get("function_count", len(functions))) == len(functions)
    complete = bool(
        internal
        and internal_recovered == len(internal)
        and truncated_functions == 0
        and enumerated_complete
        and executable_bytes > 0
        and exact_body_union_complete
        and (allowed_ranges is None or (
            producer_validation is not None and producer_validation["valid"]
            and projection_validation is not None and projection_validation["valid"]
            and (analysis.get("restricted_allowed_coverage") or {}).get("complete") is True
        ))
        and (allowed_ranges is not None or ida_executable.get("complete") is True)
        and not ida_executable.get("evidence_truncated")
        and not truncated
    )
    return {
        "status": "success",
        "complete": complete,
        "backend": "ida-pro-idalib",
        "functions": len(functions),
        "functions_disassembled": disassembled,
        "functions_decompiled": decompiled,
        "internal_functions": len(internal),
        "internal_functions_semantically_recovered": internal_recovered,
        "unresolved_internal_functions": len(internal) - internal_recovered,
        "truncated_internal_functions": truncated_functions,
        "enumerated_function_count_matches": enumerated_complete,
        "executable_bytes": executable_bytes,
        "function_assigned_executable_bytes": assigned_executable_bytes,
        "function_assigned_executable_ratio": round(executable_coverage, 6),
        "minimum_executable_ratio": 1.0,
        "ida_executable_coverage": ida_executable,
        "producer_restricted_validation": producer_validation,
        "projection_restricted_validation": projection_validation,
        "restricted_text_receipts": restricted_text_receipts,
        "exact_body_union_complete": exact_body_union_complete,
        "expected_allowed_intervals": expected_merged_ranges,
        "merged_function_body_intervals": merged_function_ranges,
        "evidence_truncated": truncated,
        "bytes": written,
        "target_sha256": str(metadata.get("sha256") or "").lower(),
        "target_bytes": target.stat().st_size,
        "analysis_scope": "selective_ranges" if allowed_ranges is not None else "whole_target",
        "range_authority_sha256": range_authority_sha256,
        "source_cache": str(analysis.get("_cache", "")),
        "source_cache_receipt": str(analysis.get("_cache_receipt", "")),
        "producer_contract_sha256": str(
            analysis.get("_producer_contract_sha256", "")
        ),
    }


def _resume_native_static(
    item_root: Path, target_sha256: str, target_bytes: int,
    range_authority_sha256: str | None,
    native_launch_authority_token: str | None,
    partition_sha256: str | None,
) -> dict[str, Any] | None:
    """Reconstruct a completed native-static record from on-disk evidence (R11).

    ``analyze_native_static_evidence`` re-ran IDA (hours) on every deterministic
    re-run despite the prior run having written a hash-attested receipt +
    ``ida_analysis.txt`` under ``<sha>/``. When that receipt is internally
    consistent (schema, target identity, status==complete, and every referenced
    evidence file still hash-matches), return the record fields to reuse — the
    disk artifact's embedded contract is authoritative, exactly like the
    precomputed-IDA path in F3.
    """
    receipt_path = item_root / "native_static_receipt.json"
    ida_path = item_root / "ida_analysis.txt"
    data_path = item_root / "native_nonexec_data.json"
    if receipt_path.is_symlink() or not receipt_path.is_file():
        return None
    try:
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(receipt, dict):
        return None
    from src.analysis.evidence_signing import verify_document
    if not verify_document(receipt, require_signature=True):
        return None
    try:
        consistent = bool(
            receipt.get("schema_version") == _NATIVE_RECEIPT_SCHEMA
            and receipt.get("target_sha256") == target_sha256
            and int(receipt.get("target_bytes", -1)) == target_bytes
            and receipt.get("status") == "complete"
            and receipt.get("ida_semantic_complete") is True
            and receipt.get("native_data_complete") is True
            and receipt.get("range_authority_sha256") == range_authority_sha256
            and receipt.get("native_launch_authority_token") == native_launch_authority_token
            and receipt.get("partition_sha256") == partition_sha256
        )
    except (TypeError, ValueError):
        consistent = False
    if not consistent:
        return None
    evidence_hashes = receipt.get("evidence_sha256")
    if not isinstance(evidence_hashes, dict):
        return None
    for evidence_path in (ida_path, data_path):
        expected = str(evidence_hashes.get(str(evidence_path), ""))
        if not expected or not evidence_path.is_file() or evidence_path.is_symlink():
            return None
        try:
            if _sha256_path(evidence_path) != expected:
                return None
        except OSError:
            return None
    try:
        native_data = json.loads(data_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ida = {
        "status": "success",
        "complete": True,
        "target_sha256": target_sha256,
        "target_bytes": target_bytes,
        "producer_contract_sha256": str(
            receipt.get("ida_producer_contract_sha256", "")
        ),
        "cache_hit": True,
        "cache_source": str(ida_path),
        "range_authority_sha256": range_authority_sha256,
    }
    record_evidence_sha256 = {
        str(ida_path): evidence_hashes[str(ida_path)],
        str(data_path): evidence_hashes[str(data_path)],
    }
    if receipt_path.is_file():
        record_evidence_sha256[str(receipt_path)] = _sha256_path(receipt_path)
    return {
        "ida": ida,
        "native_data": native_data,
        "required_evidence": [str(data_path), str(ida_path), str(receipt_path)],
        "evidence_sha256": record_evidence_sha256,
        "receipt": str(receipt_path),
        "complete": True,
    }


def analyze_native_static_evidence(
    paths: list[str | Path],
    *,
    evidence_root: str | Path,
    ownership_manifest: str | Path,
    native_universe: str | Path,
    lane_epoch_id: str,
    timeout: int = 120,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Run the authoritative native static gate without requiring a dynamic lane.

    Clean libraries remain statically closable only when licensed IDA recovers
    every internal function/executable byte and the independent non-executable
    data ledger finds no unresolved VM-like payload. Callers must escalate any
    incomplete result; runtime support alone is not native execution evidence.
    """
    from src.analysis.evidence_signing import sign_document
    from src.analysis.native_ownership_manifest import (
        bind_native_output_directory,
        native_routing_context,
        native_routing_targets,
        publish_native_lane_receipt,
        publish_native_lane_receipt,
    )

    _routing, selected, policy_events, routing_binding = native_routing_context(
        ownership_manifest, native_universe,
    )
    app_targets, excluded_targets, hold_targets = native_routing_targets(selected, policy_events)
    root = bind_native_output_directory(
        evidence_root, lane="native-ida-static", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding,
    )
    supplied_targets: dict[str, Path] = {}
    for raw_path in paths:
        candidate = Path(raw_path).expanduser().absolute()
        if candidate.is_symlink() or not candidate.is_file():
            raise ValueError(f"native inventory target must be a non-symlink regular file: {candidate}")
        supplied_targets[_sha256_path(candidate)] = candidate.resolve(strict=True)
    routed_universe = app_targets | excluded_targets | hold_targets
    if set(supplied_targets) != routed_universe:
        raise ValueError("Android native inventory does not exactly conserve signed ownership targets")
    paths = [str(row["target"]) for row in selected]
    selected_by_sha = {str(row["target_sha256"]): row for row in selected}
    records: list[dict[str, Any]] = []
    completed_by_hash: dict[str, dict[str, Any]] = {}
    total = len(paths)

    if hold_targets:
        publish_native_lane_receipt(
            root / "NATIVE_IDA_LANE_COMPLETION_RECEIPT.json",
            lane="native-ida-static", lane_epoch_id=lane_epoch_id,
            routing_binding=routing_binding, expected_app_targets=app_targets,
            processed_targets=set(), excluded_targets=excluded_targets,
            hold_targets=hold_targets, semantic_complete=False,
            input_bindings=[{
                "kind": "native-ownership-routing",
                "sha256": routing_binding["ownership_manifest_file_sha256"],
            }],
            counts={"scheduled": 0, "hold": len(hold_targets)},
        )
        return {
            "schema_version": 2,
            "native_routing": routing_binding,
            "native_count": 0,
            "complete": False,
            "launch_blocked": True,
            "hold_targets": sorted(hold_targets),
            "excluded_targets": sorted(excluded_targets),
            "records": [],
        }

    def notify(index: int, target: Path, record: dict[str, Any], *, cache_hit: bool) -> None:
        if progress_callback is not None:
            progress_callback({
                "stage": "native-static-evidence", "completed": index,
                "expected": total, "target": str(target), "cache_hit": cache_hit,
                "complete": bool(record.get("complete")),
                "limitation": str(record.get("limitation", "")),
            })

    for index, raw_path in enumerate(paths, 1):
        target = Path(raw_path).expanduser().resolve()
        record: dict[str, Any] = {
            "path": str(target), "complete": False, "ida": {},
            "native_data": {}, "required_evidence": [], "limitation": "",
            "native_routing": routing_binding,
        }
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            record["limitation"] = "aggregate-pre-ai-deadline-exhausted"
            records.append(record)
            notify(index, target, record, cache_hit=False)
            continue
        try:
            size = target.stat().st_size
            if size > MEMBER_LIMIT:
                record["limitation"] = (
                    f"exceeds-{MEMBER_LIMIT // (1024 * 1024)}MiB-analysis-budget"
                )
                records.append(record)
                notify(index, target, record, cache_hit=False)
                continue
            data = target.read_bytes()
        except OSError as exc:
            record["limitation"] = type(exc).__name__
            records.append(record)
            notify(index, target, record, cache_hit=False)
            continue
        digest = _sha256(data)
        record.update({"sha256": digest, "bytes": len(data)})
        if detect_android_binary_format(target.name, data) != "elf":
            record["limitation"] = "native-target-is-not-elf"
            records.append(record)
            notify(index, target, record, cache_hit=False)
            continue
        cached = completed_by_hash.get(digest)
        if cached is not None:
            record.update({
                "complete": cached["complete"],
                "ida": dict(cached["ida"]),
                "native_data": dict(cached["native_data"]),
                "required_evidence": list(cached["required_evidence"]),
                "evidence_sha256": dict(cached["evidence_sha256"]),
                "receipt": cached.get("receipt", ""),
                "limitation": cached["limitation"],
                "duplicate_of": cached["path"],
            })
            records.append(record)
            notify(index, target, record, cache_hit=True)
            continue
        item_root = root / digest
        item_root.mkdir(parents=True, exist_ok=True)
        route_row = selected_by_sha[digest]
        range_authority_sha256 = route_row.get("range_authority_sha256")
        allowed_ranges = (
            route_row.get("allowed_executable_ranges") or []
            if route_row.get("analysis_scope") == "selective_ranges" else None
        )
        resumed = _resume_native_static(
            item_root, digest, len(data), range_authority_sha256,
            route_row.get("native_launch_authority_token"),
            route_row.get("partition_sha256"),
        )
        if resumed is not None:
            record.update(resumed)
            completed_by_hash[digest] = record
            records.append(record)
            notify(index, target, record, cache_hit=True)
            continue
        ida_path = item_root / "ida_analysis.txt"
        data_path = item_root / "native_nonexec_data.json"
        ida = _write_ida_evidence(
            target, ida_path, timeout=timeout,
            deadline_monotonic=deadline_monotonic,
            allowed_ranges=allowed_ranges,
            range_authority_sha256=range_authority_sha256,
            native_authority=route_row,
            native_authority_token=route_row.get("native_launch_authority_token"),
        )
        native_data = _elf_nonexec_data_profile(data)
        data_path.write_text(json.dumps(native_data, indent=2) + "\n", encoding="utf-8")
        record["ida"] = ida
        record["native_data"] = native_data
        record["required_evidence"] = [str(data_path)]
        if ida_path.is_file():
            record["required_evidence"].append(str(ida_path))
        evidence_sha256 = {
            str(evidence): _sha256_path(Path(evidence))
            for evidence in record["required_evidence"]
            if Path(evidence).is_file()
        }
        record["complete"] = bool(
            ida.get("complete") is True and native_data.get("complete") is True
        )
        if not record["complete"]:
            record["limitation"] = (
                f"native-static-evidence-incomplete:ida={ida.get('status')};"
                f"nonexec-data={native_data.get('status')}"
            )
        receipt_path = item_root / "native_static_receipt.json"
        receipt = {
            "schema_version": _NATIVE_RECEIPT_SCHEMA,
            "status": "complete" if record["complete"] else "partial",
            "target_sha256": digest,
            "target_bytes": len(data),
            "ida_semantic_complete": ida.get("complete") is True,
            "ida_producer_contract_sha256": str(
                ida.get("producer_contract_sha256", "")
            ),
            "native_data_complete": native_data.get("complete") is True,
            "evidence_sha256": evidence_sha256,
            "native_routing": routing_binding,
            "range_authority_sha256": range_authority_sha256,
            "native_launch_authority_token": route_row.get("native_launch_authority_token"),
            "partition_sha256": route_row.get("partition_sha256"),
        }
        receipt = sign_document(receipt)
        if receipt.get("trust") != "operator_signed":
            raise ValueError("native IDA evidence receipt requires operator signing")
        with receipt_path.open("w", encoding="utf-8") as receipt_stream:
            json.dump(receipt, receipt_stream, sort_keys=True, separators=(",", ":"))
            receipt_stream.write("\n")
            receipt_stream.flush()
            os.fsync(receipt_stream.fileno())
        record["required_evidence"].append(str(receipt_path))
        evidence_sha256[str(receipt_path)] = _sha256_path(receipt_path)
        record["evidence_sha256"] = evidence_sha256
        record["receipt"] = str(receipt_path)
        completed_by_hash[digest] = record
        records.append(record)
        notify(index, target, record, cache_hit=False)
    result = {
        "schema_version": 2,
        "native_routing": routing_binding,
        "policy": (
            "only signed app-owned native libraries enter IDA; signed third-party targets "
            "are fully excluded and ownership HOLD prevents lane launch"
        ),
        "native_count": len(records),
        "complete": bool(
            not hold_targets
            and len(records) == len(app_targets)
            and all(item["complete"] for item in records)
        ),
        "records": records,
    }
    publish_native_lane_receipt(
        root / "NATIVE_IDA_LANE_COMPLETION_RECEIPT.json",
        lane="native-ida-static", lane_epoch_id=lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={str(row.get("sha256") or "") for row in records},
        excluded_targets=excluded_targets, hold_targets=hold_targets,
        semantic_complete=bool(result["complete"]),
        input_bindings=[{
            "kind": "native-ownership-routing",
            "sha256": routing_binding["ownership_manifest_file_sha256"],
        }] + [{
            "kind": "native-static-receipt",
            "path": str(row.get("receipt") or ""),
            "sha256": str((row.get("evidence_sha256") or {}).get(str(row.get("receipt") or ""), "")),
        } for row in records if row.get("receipt")],
        counts={"scheduled": len(paths), "records": len(records)},
    )
    return result


def _validated_precomputed_ida(
    item: dict[str, Any], *, target_sha256: str, target_bytes: int
) -> tuple[Path, dict[str, Any]] | None:
    """Validate a controller-produced native receipt before reusing IDA bytes."""
    from src.analysis.evidence_signing import verify_document

    ida = item.get("ida") if isinstance(item.get("ida"), dict) else {}
    native_routing = item.get("native_routing")
    native_data = (
        item.get("native_data") if isinstance(item.get("native_data"), dict) else {}
    )
    try:
        identity_valid = bool(
            item.get("complete") is True
            and str(item.get("sha256", "")) == target_sha256
            and int(item.get("bytes", -1)) == target_bytes
            and ida.get("status") == "success"
            and ida.get("complete") is True
            and ida.get("target_sha256") == target_sha256
            and int(ida.get("target_bytes", -1)) == target_bytes
            and bool(ida.get("producer_contract_sha256"))
            and native_data.get("complete") is True
        )
    except (TypeError, ValueError):
        identity_valid = False
    if not identity_valid:
        return None
    evidence_hashes = item.get("evidence_sha256")
    if not isinstance(evidence_hashes, dict):
        return None
    receipt_path = Path(str(item.get("receipt", "")))
    expected_receipt_hash = str(evidence_hashes.get(str(receipt_path), ""))
    if (
        not receipt_path.is_file()
        or receipt_path.is_symlink()
        or not expected_receipt_hash
    ):
        return None
    try:
        if _sha256_path(receipt_path) != expected_receipt_hash:
            return None
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return None
    try:
        receipt_valid = bool(
            isinstance(native_routing, dict)
            and verify_document(receipt, require_signature=True)
            and receipt.get("native_routing") == native_routing
            and
            receipt.get("schema_version") == _NATIVE_RECEIPT_SCHEMA
            and receipt.get("status") == "complete"
            and receipt.get("target_sha256") == target_sha256
            and int(receipt.get("target_bytes", -1)) == target_bytes
            and receipt.get("ida_semantic_complete") is True
            and receipt.get("native_data_complete") is True
            and receipt.get("ida_producer_contract_sha256")
            == ida.get("producer_contract_sha256")
        )
    except (TypeError, ValueError):
        receipt_valid = False
    if not receipt_valid:
        return None
    # R4: do NOT gate reuse on the *live* producer contract. The receipt above
    # already attests that the on-disk ``ida_analysis.txt`` was produced by the
    # contract the record embeds (receipt.ida_producer_contract_sha256 ==
    # ida.producer_contract_sha256), and the bytes are hash-verified below. A
    # later edit to ida_dump.py drifts the live contract but leaves this
    # self-attested evidence valid — requiring a multi-hour IDA re-run here
    # would defeat resume. The disk artifact's embedded contract is authoritative.
    receipt_evidence = receipt.get("evidence_sha256")
    if not isinstance(receipt_evidence, dict):
        return None
    for raw_path, raw_hash in receipt_evidence.items():
        evidence_path = Path(str(raw_path))
        expected_hash = str(raw_hash)
        if not (
            evidence_path.is_file()
            and not evidence_path.is_symlink()
            and evidence_path.parent.resolve() == receipt_path.parent.resolve()
            and expected_hash
            and evidence_hashes.get(str(evidence_path)) == expected_hash
        ):
            return None
        try:
            if _sha256_path(evidence_path) != expected_hash:
                return None
        except OSError:
            return None
    ida_sources = [
        Path(str(raw)) for raw in item.get("required_evidence", [])
        if Path(str(raw)).name == "ida_analysis.txt"
    ]
    if len(ida_sources) != 1:
        return None
    source = ida_sources[0]
    expected = str(evidence_hashes.get(str(source), ""))
    if not (
        source.is_file()
        and not source.is_symlink()
        and source.parent.resolve() == receipt_path.parent.resolve()
        and expected
        and receipt_evidence.get(str(source)) == expected
    ):
        return None
    try:
        if _sha256_path(source) != expected:
            return None
    except OSError:
        return None
    return source, dict(ida)


def _resume_evidence_record(
    item_root: Path, record: dict[str, Any], root: Path
) -> dict[str, Any] | None:
    """Reconstruct a record from on-disk evidence when already materialized.

    Disk idempotency (R3): a resume must reuse ``<sha>/manifest.json`` instead
    of re-invoking IDA/objdump on every artifact. The manifest is considered
    authoritative when it is internally consistent (sha256 + bytes match the
    current file) and was written by this code path (carries the derived
    ``analysis_complete`` field). Returns the fields to merge into the record,
    or ``None`` when the manifest is absent, stale, or an older schema that
    cannot prove materialization completed.
    """
    manifest_path = item_root / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return None
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(manifest, dict):
        return None
    from src.analysis.evidence_signing import verify_document
    if (record.get("format") == "elf" or manifest.get("analysis_complete")) and not verify_document(manifest, require_signature=True):
        return None
    if record.get("format") == "elf" and manifest.get("native_routing") != record.get("native_routing"):
        return None
    if manifest.get("sha256") != record["sha256"]:
        return None
    if manifest.get("bytes") != record["bytes"]:
        return None
    # Older v1 manifests never carried the derived completion fields; they
    # cannot prove a completed materialization and must be re-materialized.
    if "analysis_complete" not in manifest:
        return None
    required_evidence = [
        rel for rel in manifest.get("required_evidence") or []
        if isinstance(rel, str)
    ]
    # Every evidence file the manifest claims must still exist on disk, else
    # the materialization is partial and must be redone.
    hashes = manifest.get("evidence_sha256")
    if not isinstance(hashes, dict):
        return None
    for rel in required_evidence:
        candidate = root / rel
        if candidate.is_symlink() or not candidate.is_file() or not candidate.resolve().is_relative_to(item_root.resolve()):
            return None
        if candidate != manifest_path and hashes.get(rel) != _sha256_path(candidate):
            return None
    resumed: dict[str, Any] = {
        "analysis_complete": bool(manifest.get("analysis_complete")),
        "limitation": str(manifest.get("limitation", "")),
        "native_backend": str(manifest.get("native_backend", "")),
        "required_evidence": required_evidence,
        "evidence_checkpoint_hit": True,
    }
    ida = manifest.get("ida")
    if isinstance(ida, dict) and ida.get("cache_hit"):
        resumed["native_cache_hit"] = True
    return resumed


def require_non_native_artifacts(root: Path) -> None:
    """Reject ELF inputs before allowing a route without native authority."""
    evidence_root = root / "_angerona_binary_evidence"
    for candidate in root.rglob("*"):
        if candidate.is_file() and evidence_root not in candidate.parents:
            with candidate.open("rb") as handle:
                if handle.read(4) == b"\x7fELF":
                    raise ValueError("ELF evidence requires signed native ownership routing")


def materialize_binary_evidence(
    artifact_root: str | Path,
    *,
    observation_workspace: str | Path | None = None,
    timeout: int = 120,
    precomputed_native_records: list[dict[str, Any]] | None = None,
    ownership_manifest: str | Path | None = None,
    native_universe: str | Path | None = None,
    native_lane_epoch_id: str | None = None,
    progress_callback: Callable[[dict[str, Any]], None] | None = None,
    deadline_monotonic: float | None = None,
) -> dict[str, Any]:
    """Build deterministic text evidence for every security-relevant binary artifact."""
    root = Path(artifact_root).resolve()
    from src.analysis.native_ownership_manifest import (
        bind_native_output_directory,
        native_routing_context,
        native_routing_targets,
        publish_native_lane_receipt,
    )

    routed = bool(ownership_manifest or native_universe or native_lane_epoch_id)
    if routed:
        if not all((ownership_manifest, native_universe, native_lane_epoch_id)):
            raise ValueError("native evidence requires ownership manifest, universe and lane epoch")
        _routing, selected, policy_events, routing_binding = native_routing_context(
            ownership_manifest, native_universe,
        )
        app_targets, excluded_targets, hold_targets = native_routing_targets(selected, policy_events)
        if hold_targets:
            raise ValueError(f"native ownership HOLD prevents AI evidence launch: {sorted(hold_targets)}")
        evidence_root = bind_native_output_directory(
            root / "_angerona_binary_evidence", lane="native-ai-evidence",
            lane_epoch_id=native_lane_epoch_id, routing_binding=routing_binding,
        )
    else:
        # Non-native artifacts need no native launch authority. Never turn that
        # convenience into implicit permission to analyze ELF bytes.
        evidence_root = root / "_angerona_binary_evidence"
        require_non_native_artifacts(root)
        if precomputed_native_records:
            raise ValueError("native records require signed native ownership routing")
        app_targets, excluded_targets, hold_targets = set(), set(), set()
        routing_binding = {"status": "not-applicable"}
    records: list[dict[str, Any]] = []
    evidence_cache: dict[str, dict[str, Any]] = {}
    precomputed_by_hash: dict[str, dict[str, Any]] = {}
    for precomputed_item in precomputed_native_records or []:
        if not isinstance(precomputed_item, dict) or not precomputed_item.get("sha256"):
            continue
        digest = str(precomputed_item["sha256"])
        current = precomputed_by_hash.get(digest)
        # Prefer the canonical controller record carrying the receipt; never let
        # a later duplicate alias silently replace stronger reuse authority.
        if current is None or (
            precomputed_item.get("receipt") and not current.get("receipt")
        ):
            precomputed_by_hash[digest] = precomputed_item
    paths = sorted(
        path for path in root.rglob("*")
        if path.is_file() and evidence_root not in path.parents
    )
    total_paths = len(paths)

    def publish_progress(index: int, target: str, record: dict[str, Any]) -> None:
        if progress_callback is not None:
            progress_callback({
                "stage": "android-ai-binary-evidence",
                "completed": index,
                "expected": total_paths,
                "target": target,
                "format": str(record.get("format", "unknown")),
                "analysis_complete": bool(record.get("analysis_complete", False)),
                "cache_hit": bool(
                    record.get("evidence_duplicate_of")
                    or record.get("native_cache_hit")
                    or record.get("evidence_checkpoint_hit")
                ),
            })

    for path_index, path in enumerate(paths, 1):
        if deadline_monotonic is not None and time.monotonic() >= deadline_monotonic:
            relative = path.relative_to(root).as_posix()
            expired = {
                "path": relative,
                "review_required": True,
                "analysis_complete": False,
                "limitation": "aggregate-pre-ai-deadline-exhausted",
                "required_evidence": [],
            }
            records.append(expired)
            publish_progress(path_index, relative, expired)
            continue
        try:
            size = path.stat().st_size
            if size > MEMBER_LIMIT:
                oversized = {
                    "path": path.relative_to(root).as_posix(),
                    "bytes": size,
                    "review_required": True,
                    "analysis_complete": False,
                    "limitation": f"exceeds-{MEMBER_LIMIT // (1024 * 1024)}MiB-analysis-budget",
                    "required_evidence": [],
                }
                records.append(oversized)
                publish_progress(path_index, oversized["path"], oversized)
                continue
            data = path.read_bytes()
        except OSError as exc:
            unreadable = {
                "path": path.relative_to(root).as_posix(),
                "review_required": True,
                "analysis_complete": False,
                "limitation": type(exc).__name__,
                "required_evidence": [],
            }
            records.append(unreadable)
            publish_progress(path_index, unreadable["path"], unreadable)
            continue
        relative = path.relative_to(root).as_posix()
        kind = detect_android_binary_format(relative, data)
        entropy = _entropy(data)
        relevant, reason = _security_relevant(relative, kind, entropy)
        payload_profile: dict[str, Any] = {}
        if kind in _MEDIA_KINDS:
            payload_profile = _media_payload_profile(kind, data)
            if payload_profile.get("suspicious"):
                relevant, reason = True, "suspicious-media-or-custom-payload"
        native_data_profile: dict[str, Any] = {}
        if kind == "elf":
            native_data_profile = _elf_nonexec_data_profile(data)
            if not native_data_profile.get("complete"):
                relevant, reason = True, "native-nonexec-payload-unresolved"
        embedded_payloads = _embedded_executable_magics(data)
        if embedded_payloads:
            relevant, reason = True, "polyglot-or-embedded-executable-payload"
        record: dict[str, Any] = {
            "path": relative,
            "sha256": _sha256(data),
            "bytes": len(data),
            "suffix": path.suffix.lower(),
            "format": kind,
            "entropy": round(entropy, 4),
            "review_required": relevant,
            "review_reason": reason,
            "embedded_payloads": embedded_payloads,
            "payload_profile": payload_profile,
            "native_data_profile": native_data_profile,
            "review_mode": "native_artifact" if kind == "elf" else "binary_artifact",
            "analysis_complete": True,
            "required_evidence": [],
            "limitation": "",
            **({"native_routing": routing_binding} if kind == "elf" else {}),
        }
        if kind == "elf" and record["sha256"] in excluded_targets:
            path.unlink()
            record.update({
                "review_required": False,
                "review_reason": "fully-excluded-third-party-by-signed-routing",
                "review_mode": "fully_excluded_third_party",
                "analysis_complete": True,
                "native_backend": "fully-excluded-third-party",
                "artifact_removed_from_ai_workspace": True,
                "authoritative_target_sha256": record["sha256"],
            })
            records.append(record)
            publish_progress(path_index, relative, record)
            continue
        if kind == "elf" and record["sha256"] not in app_targets:
            raise ValueError("ELF artifact is not an exact signed app-owned routing member")
        if not relevant or kind == "text":
            records.append(record)
            publish_progress(path_index, relative, record)
            continue
        cached = evidence_cache.get(record["sha256"])
        if cached is not None:
            record.update({
                "analysis_complete": cached["analysis_complete"],
                "required_evidence": list(cached["required_evidence"]),
                "limitation": cached["limitation"],
                "native_backend": cached.get("native_backend", ""),
                "evidence_duplicate_of": cached["source_path"],
            })
            records.append(record)
            publish_progress(path_index, relative, record)
            continue
        item_root = evidence_root / record["sha256"]
        resumed = _resume_evidence_record(item_root, record, root)
        if resumed is not None:
            record.update(resumed)
            evidence_cache[record["sha256"]] = {
                "analysis_complete": record["analysis_complete"],
                "required_evidence": list(record["required_evidence"]),
                "limitation": record["limitation"],
                "native_backend": record.get("native_backend", ""),
                "source_path": relative,
            }
            records.append(record)
            publish_progress(path_index, relative, record)
            continue
        item_root.mkdir(parents=True, exist_ok=True)
        strings, strings_truncated = _extract_strings(data)
        strings_path = item_root / "strings.json"
        strings_path.write_text(
            json.dumps(
                {"source": relative, "strings": strings, "truncated": strings_truncated},
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "source": relative,
            "sha256": record["sha256"],
            "bytes": len(data),
            "format": kind,
            "entropy": record["entropy"],
            "strings_truncated": strings_truncated,
        }
        if kind == "elf":
            manifest["native_routing"] = routing_binding
            manifest["elf"] = _elf_manifest(data)
            native_data_path = item_root / "native_nonexec_data.json"
            native_data_path.write_text(
                json.dumps(native_data_profile, indent=2) + "\n", encoding="utf-8"
            )
            manifest["native_nonexec_data"] = native_data_profile
            ida_path = item_root / "ida_analysis.txt"
            ida: dict[str, Any] | None = None
            precomputed = precomputed_by_hash.get(str(record["sha256"]))
            if precomputed is not None and precomputed.get("native_routing") == routing_binding:
                validated = _validated_precomputed_ida(
                    precomputed,
                    target_sha256=str(record["sha256"]),
                    target_bytes=int(record["bytes"]),
                )
                if validated is not None:
                    source, ida = validated
                    shutil.copy2(source, ida_path)
                    ida.update({
                        "cache_hit": True,
                        "cache_source": str(source),
                        "cache_evidence_sha256": _sha256_path(source),
                    })
            if ida is None:
                ida = {
                    "status": "missing-routed-precomputed-ida",
                    "complete": False,
                    "target_sha256": record["sha256"],
                    "message": "native AI preparation cannot launch IDA; routed IDA receipt is required",
                }
            record["native_cache_hit"] = bool(ida.get("cache_hit"))
            manifest["ida"] = ida
            disassembly_path = item_root / "disassembly.txt"
            if ida.get("complete"):
                # IDA evidence already contains function/range disassembly and
                # semantic decompilation. A second full-file objdump is neither
                # a completeness oracle nor worth serially blocking AI dispatch.
                disassembly = {
                    "status": "skipped-complete-ida-evidence",
                    "complete": False,
                    "tool": "",
                    "bytes": 0,
                    "published": False,
                }
            else:
                disassembly = _write_disassembly(
                    path,
                    disassembly_path,
                    timeout=timeout,
                    observation_workspace=observation_workspace,
                    deadline_monotonic=deadline_monotonic,
                )
            manifest["disassembly"] = disassembly
            record["native_backend"] = (
                "ida-pro-idalib" if ida.get("complete") else
                "llvm-objdump-assembly-only" if disassembly.get("complete") else
                "unresolved"
            )
            # Raw objdump is valuable corroboration, but it cannot prove that
            # functions/custom-VM dispatchers were semantically recovered.
            record["analysis_complete"] = bool(
                ida.get("complete") and native_data_profile.get("complete")
            )
            if not record["analysis_complete"]:
                record["limitation"] = (
                    f"native-analysis-incomplete:ida={ida.get('status')};"
                    f"nonexec-data={native_data_profile.get('status')};"
                    f"objdump={disassembly.get('status')};assembly-only-is-not-semantic-completion"
                )
            if ida.get("status") == "success":
                record["required_evidence"].append(
                    ida_path.relative_to(root).as_posix()
                )
            if disassembly_path.is_file() and disassembly.get("published"):
                record["required_evidence"].append(
                    disassembly_path.relative_to(root).as_posix()
                )
            record["required_evidence"].append(
                native_data_path.relative_to(root).as_posix()
            )
        elif kind in {"dex", "compact_dex", "java_class"}:
            record["analysis_complete"] = False
            record["limitation"] = "raw-bytecode-requires-correlated-jadx-export"
        elif kind == "zip":
            record["analysis_complete"] = False
            record["limitation"] = "nested-archive-requires-bounded-recursive-routing"
        elif kind == "wasm":
            record["analysis_complete"] = False
            record["limitation"] = "wasm-requires-function-level-disassembly"
        elif kind == "sqlite":
            record["analysis_complete"] = False
            record["limitation"] = "sqlite-requires-schema-and-record-level-inspection"
        elif kind == "opaque_binary":
            record["analysis_complete"] = False
            record["limitation"] = (
                "high-entropy-payload-requires-unpacking-or-runtime-witness"
                if entropy >= 7.2 else
                "opaque-payload-requires-format-recovery-or-data-only-proof"
            )
        elif kind in _MEDIA_KINDS and payload_profile.get("suspicious"):
            record["analysis_complete"] = False
            record["limitation"] = (
                "media-container-has-unaccounted-custom-or-trailing-payload:"
                + ",".join(payload_profile.get("reasons", []))
            )
        if embedded_payloads:
            record["analysis_complete"] = False
            suffix = "embedded-executable-payload-requires-carving-and-child-analysis"
            record["limitation"] = (
                f"{record['limitation']};{suffix}" if record["limitation"] else suffix
            )
        if strings_truncated:
            record["analysis_complete"] = False
            suffix = "strings-evidence-truncated"
            record["limitation"] = (
                f"{record['limitation']};{suffix}" if record["limitation"] else suffix
            )
        manifest_path = item_root / "manifest.json"
        record["required_evidence"].extend([
            manifest_path.relative_to(root).as_posix(),
            strings_path.relative_to(root).as_posix(),
        ])
        # Persist the derived completion fields into the manifest so a resume
        # can reconstruct this record without re-invoking IDA/objdump (R3).
        manifest["analysis_complete"] = record["analysis_complete"]
        manifest["limitation"] = record["limitation"]
        manifest["native_backend"] = record.get("native_backend", "")
        manifest["required_evidence"] = list(record["required_evidence"])
        manifest["evidence_sha256"] = {
            relative: _sha256_path(root / relative)
            for relative in record["required_evidence"]
            if root / relative != manifest_path
        }
        from src.analysis.evidence_signing import sign_document
        manifest = sign_document(manifest)
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        evidence_cache[record["sha256"]] = {
            "analysis_complete": record["analysis_complete"],
            "required_evidence": list(record["required_evidence"]),
            "limitation": record["limitation"],
            "native_backend": record.get("native_backend", ""),
            "source_path": relative,
        }
        records.append(record)
        publish_progress(path_index, relative, record)
    discovered_elf_targets = {
        str(item.get("sha256") or "") for item in records
        if item.get("format") == "elf"
    }
    if discovered_elf_targets != app_targets | excluded_targets:
        raise ValueError("Android AI artifact set does not conserve exact native routing universe")
    result = {
        "schema_version": 1,
        "native_routing": routing_binding,
        "artifact_root": str(root),
        "file_count": len(records),
        "review_required_count": sum(bool(item["review_required"]) for item in records),
        "checkpoint_hits": sum(
            bool(item.get("evidence_checkpoint_hit")) for item in records
        ),
        "incomplete_required": [
            item["path"] for item in records
            if item["review_required"] and not item["analysis_complete"]
        ],
        "files": records,
    }
    app_records = [
        item for item in records
        if item.get("format") == "elf" and item.get("sha256") in app_targets
    ]
    if not routed:
        return result
    publish_native_lane_receipt(
        evidence_root / "NATIVE_AI_EVIDENCE_LANE_COMPLETION_RECEIPT.json",
        lane="native-ai-evidence", lane_epoch_id=native_lane_epoch_id,
        routing_binding=routing_binding, expected_app_targets=app_targets,
        processed_targets={str(item["sha256"]) for item in app_records},
        excluded_targets=excluded_targets, hold_targets=hold_targets,
        semantic_complete=bool(
            len(app_records) == len(app_targets)
            and all(item.get("analysis_complete") for item in app_records)
        ),
        input_bindings=[{
            "kind": "native-ownership-routing",
            "sha256": routing_binding["ownership_manifest_file_sha256"],
        }] + [{
            "kind": "routed-precomputed-native-receipt",
            "path": str(item.get("receipt") or ""),
            "sha256": str((item.get("evidence_sha256") or {}).get(str(item.get("receipt") or ""), "")),
        } for item in precomputed_native_records or [] if item.get("receipt")],
        counts={"files": len(records), "app_owned_elf": len(app_records)},
    )
    return result
