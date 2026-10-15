"""Multi-dex coverage inventory (Android SOTA priority 11).

Research basis (the 64K-method limit and Android's multidex support library;
packers that hide the malicious stage in ``classes4.dex`` because triage
tools historically only opened ``classes.dex``): before any per-class rule
runs, the pipeline must know *which* DEX members exist, whether their headers
parse, and how surface area is split across them. A rule suite that silently
scans 1 of 5 dex files produces false negatives, not findings.

Header facts (magic, declared size vs. zip-member size) are deterministic;
per-file parse failures degrade that member's status without aborting others.
"""

from __future__ import annotations

import hashlib
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_DEX_MAGIC = b"dex\n"


@dataclass
class DexMember:
    name: str
    size: int
    magic_ok: bool
    version: str | None
    declared_size: int | None
    size_mismatch: bool
    status: str            # parsed | bad-magic | truncated | unreadable
    sha256: str = ""
    semantic: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "size": self.size,
            "magic_ok": self.magic_ok,
            "version": self.version,
            "declared_size": self.declared_size,
            "size_mismatch": self.size_mismatch,
            "status": self.status,
            "sha256": self.sha256,
            "semantic": self.semantic,
            "trust": TRUST_TAG,
        }


@dataclass
class MultiDexResult:
    status: str            # success | empty | error | skipped
    dex_files: list[dict] = field(default_factory=list)
    dex_count: int = 0
    coverage_gap: bool = False
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "dex_files": self.dex_files,
            "dex_count": self.dex_count,
            "coverage_gap": self.coverage_gap,
            "note": self.note,
            "trust": self.trust,
            "policy": "header facts deterministic; members beyond classes.dex most often skipped by tools",
        }


def _parse_dex_header(name: str, blob: bytes) -> DexMember:
    if len(blob) < 8:
        return DexMember(name=name, size=len(blob), magic_ok=False,
                         version=None, declared_size=None,
                         size_mismatch=False, status="truncated",
                         sha256=hashlib.sha256(blob).hexdigest())
    magic_ok = blob[:4] == _DEX_MAGIC and blob[7:8] == b"\x00"
    version = None
    declared = None
    mismatch = False
    if magic_ok:
        version = blob[4:7].decode("ascii", errors="ignore").strip("\x00")
        if len(blob) >= 36:
            declared = struct.unpack_from("<I", blob, 32)[0]
            mismatch = declared != len(blob)
    semantic: dict = {}
    semantic_status = ""
    if magic_ok and not mismatch:
        from src.analysis.dex_semantic import inventory_dex_bytes

        semantic = inventory_dex_bytes(blob).as_dict()
        semantic_status = str(semantic.get("status") or "")
    return DexMember(
        name=name, size=len(blob), magic_ok=magic_ok, version=version,
        declared_size=declared, size_mismatch=mismatch,
        status=("size-mismatch" if magic_ok and mismatch else
                "parsed" if magic_ok and semantic_status == "parsed" else
                "structural-invalid" if magic_ok else "bad-magic"),
        sha256=hashlib.sha256(blob).hexdigest(),
        semantic=semantic,
    )


def inventory_apk(apk_path: str | Path) -> MultiDexResult:
    """Inventory every classes*.dex member with header verification."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return MultiDexResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return MultiDexResult(status="error", note=f"not a zip/apk: {exc}")
    members: list[DexMember] = []
    with zf:
        for name in sorted(zf.namelist()):
            base = name.rsplit("/", 1)[-1]
            if not (base.startswith("classes") and base.endswith(".dex")):
                continue
            try:
                blob = zf.read(name)
            except (OSError, RuntimeError, KeyError):
                members.append(DexMember(name=name, size=0, magic_ok=False,
                                         version=None, declared_size=None,
                                         size_mismatch=False,
                                         status="unreadable", sha256=""))
                continue
            members.append(_parse_dex_header(name, blob))
    if not members:
        return MultiDexResult(status="empty", note="no classes*.dex members")
    gap = len(members) > 1
    bad = [m.name for m in members if m.status != "parsed" or m.size_mismatch]
    note = f"{len(members)} DEX member(s)"
    if gap:
        note += " — multidex: downstream scanners MUST iterate all members"
    if bad:
        note += f"; unparsed: {', '.join(bad)}"
    return MultiDexResult(
        status="partial" if bad else "success",
        dex_files=[m.as_dict() for m in members],
        dex_count=len(members),
        coverage_gap=gap,
        note=note,
    )
