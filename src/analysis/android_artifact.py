"""Fail-closed validation for Android audit input archives.

This module deliberately validates the container before any external decoder is
invoked.  It is not a malware verdict; it is a resource and format boundary for
the audit harness itself.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath


@dataclass
class AndroidArtifactValidation:
    status: str  # valid | invalid | unsupported | unsafe
    path: str
    format: str = "apk"
    dex_entries: list[str] = field(default_factory=list)
    native_entries: list[str] = field(default_factory=list)
    member_count: int = 0
    uncompressed_bytes: int = 0
    note: str = ""

    @property
    def valid(self) -> bool:
        return self.status == "valid"


def validate_apk(
    apk_path: str | Path,
    *,
    max_members: int = 100_000,
    max_uncompressed_bytes: int = 4 * 1024 * 1024 * 1024,
    max_member_bytes: int = 1024 * 1024 * 1024,
    max_compression_ratio: int = 2_000,
) -> AndroidArtifactValidation:
    """Validate an APK container and reject traversal/resource-abuse archives."""
    path = Path(apk_path)
    result = AndroidArtifactValidation(status="invalid", path=str(path))
    if not path.is_file():
        result.note = f"missing artifact: {path}"
        return result
    if path.suffix.lower() != ".apk":
        result.status = "unsupported"
        result.format = path.suffix.lower().lstrip(".") or "unknown"
        result.note = "this audit entry point accepts a single APK; normalize split/APKS/XAPK/AAB first"
        return result

    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            result.member_count = len(infos)
            if len(infos) > max_members:
                result.status = "unsafe"
                result.note = f"archive has {len(infos)} members; limit is {max_members}"
                return result

            seen: set[str] = set()
            total = 0
            for info in infos:
                name = info.filename.replace("\\", "/")
                pure = PurePosixPath(name)
                if pure.is_absolute() or ".." in pure.parts:
                    result.status = "unsafe"
                    result.note = f"unsafe archive member path: {name}"
                    return result
                if name in seen:
                    result.status = "unsafe"
                    result.note = f"duplicate archive member: {name}"
                    return result
                seen.add(name)
                total += info.file_size
                if info.file_size > max_member_bytes:
                    result.status = "unsafe"
                    result.note = f"archive member exceeds size limit: {name}"
                    return result
                if info.file_size and info.compress_size == 0:
                    result.status = "unsafe"
                    result.note = f"invalid compressed size for archive member: {name}"
                    return result
                if info.compress_size and info.file_size / info.compress_size > max_compression_ratio:
                    result.status = "unsafe"
                    result.note = f"excessive compression ratio for archive member: {name}"
                    return result
            result.uncompressed_bytes = total
            if total > max_uncompressed_bytes:
                result.status = "unsafe"
                result.note = f"archive expands to {total} bytes; limit is {max_uncompressed_bytes}"
                return result
            if "AndroidManifest.xml" not in seen:
                result.note = "APK is missing AndroidManifest.xml"
                return result
            result.dex_entries = sorted(
                n for n in seen if n.startswith("classes") and n.endswith(".dex")
            )
            abi_machines = {
                "armeabi-v7a": 40,
                "arm64-v8a": 183,
                "x86": 3,
                "x86_64": 62,
                "riscv64": 243,
            }
            native_candidates = [
                info for info in infos
                if re.fullmatch(r"lib/([^/]+)/[^/]+\.so", info.filename)
            ]
            for info in native_candidates:
                match = re.fullmatch(r"lib/([^/]+)/[^/]+\.so", info.filename)
                abi = match.group(1) if match else ""
                expected_machine = abi_machines.get(abi)
                if expected_machine is None:
                    continue
                try:
                    with zf.open(info) as handle:
                        header = handle.read(64)
                except (KeyError, OSError, RuntimeError, zipfile.BadZipFile):
                    continue
                if (
                    len(header) < 52
                    or header[:4] != b"\x7fELF"
                    or header[4] not in {1, 2}
                    or header[5] not in {1, 2}
                ):
                    continue
                if len(header) < (64 if header[4] == 2 else 52):
                    continue
                endian = "little" if header[5] == 1 else "big"
                elf_type = int.from_bytes(header[16:18], endian)
                machine = int.from_bytes(header[18:20], endian)
                if elf_type == 3 and machine == expected_machine:  # ET_DYN shared object
                    result.native_entries.append(info.filename)
            result.native_entries.sort()
            if not result.dex_entries and not result.native_entries:
                result.note = (
                    "APK contains neither classes*.dex nor a valid ABI-matching "
                    "lib/<abi>/*.so ELF shared object"
                )
                return result
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as exc:
        result.note = f"invalid APK ZIP container: {exc}"
        return result

    result.status = "valid"
    result.note = (
        f"validated APK container: {result.member_count} members, "
        f"{len(result.dex_entries)} DEX files, {len(result.native_entries)} native libraries"
    )
    return result
