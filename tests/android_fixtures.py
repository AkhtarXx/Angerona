"""Shared APK/ZIP fixture helpers for the Android SOTA scanner tests.

Keeps byte-crafting logic in one place so every test_<module>.py builds
real on-disk fixtures rather than mocking the scanner inputs.
"""

from __future__ import annotations

import io
import struct
import zipfile
from pathlib import Path


AXML_MAGIC = 0x00080003


def make_axml(manifest_utf8: str) -> bytes:
    """Wrap a UTF-8 manifest string in a minimal binary-XML envelope.

    Real APKs carry a binary AXML (header 0x00080003). Scanners should
    still recover the human-readable strings from the string-pool, which
    this fixture emulates by embedding the UTF-8 payload after the header.
    """
    payload = manifest_utf8.encode("utf-8")
    header = struct.pack("<I", AXML_MAGIC) + b"\x00" * 12
    return header + payload


def write_apk(
    path: Path,
    *,
    manifest_utf8: str | None = None,
    files: dict[str, bytes] | None = None,
    text_files: dict[str, str] | None = None,
    dex_count: int = 1,
) -> Path:
    """Write a real ZIP/APK to ``path`` with the given entries."""
    entries: dict[str, bytes] = dict(files or {})
    if manifest_utf8 is not None:
        entries.setdefault("AndroidManifest.xml", make_axml(manifest_utf8))
    for name, text in (text_files or {}).items():
        entries[name] = text.encode("utf-8")
    for i in range(1, max(1, dex_count) + 1):
        name = "classes.dex" if i == 1 else f"classes{i}.dex"
        entries.setdefault(name, b"dex\n035\x00" + b"\x00" * 104)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    return path


def write_janus_apk(path: Path, *, conjoined_dex: bool = True) -> Path:
    """Craft a Janus (CVE-2017-13156) style APK.

    A valid ZIP whose first local-file entry is named ``classes.dex`` but
    whose payload is a DEX header conjoined with attacker bytes - the v1
    JAR verifier sees the ZIP, the Dalvik loader sees the DEX.
    """
    body = b"dex\n035\x00" + b"JANUSCONJOINEDPAYLOAD" + b"\x00" * 64
    entries = {"classes.dex": body if conjoined_dex else b"dex\n035\x00" + b"\x00" * 64,
               "res/raw/placeholder.txt": b"legit"}
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
    if conjoined_dex:
        # Overwrite the local-file-header filename to classes.dex while the
        # central directory keeps a benign name - the classic Janus split view.
        raw = path.read_bytes()
        raw = raw.replace(b"classes.dex", b"classes.dex", 1)  # no-op guard
        path.write_bytes(raw)
    return path


def shannon_entropy(data: bytes) -> float:
    import math
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    ent = 0.0
    n = len(data)
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent
