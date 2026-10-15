"""Locate native anti-tamper / anti-analysis sites in Android .so files.

Professional sequencing: BEFORE any dynamic (Frida/JNI-trace) run, you must
know where the library defends itself — ptrace self-attach, TracerPid reads,
/proc/self/maps tool scans, CRC self-checks, timing probes.  Naive tracing
against a tamper-checked app just gets you detected and killed.

This module scans lifted .so bytes (string/byte patterns + imported symbol
names) and reports a **patch hit-list**: evidence addresses the dynamic side
should neutralise before stepping in.  All evidence is static; uncorroborated
sites are tagged uncorroborated=True.

Trust: parsed-from-untrusted-binary — TRUST_TAG "untrusted_child".
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass
from pathlib import Path

TRUST_TAG = "untrusted_child"


@dataclass(frozen=True)
class TamperSite:
    category: str        # ptrace | tracer_pid | frida_scan | crc_check | timing | syscall
    pattern: str         # the exact string/byte pattern that matched
    offset: int          # absolute byte offset in the .so file
    severity: str        # critical | high | medium | low
    snippet: str         # short printable context around the hit
    uncorroborated: bool


@dataclass(frozen=True)
class AntiTamperResult:
    status: str                     # defended | clear | unsupported
    sites: list[TamperSite]
    categories: list[str]
    imports_of_interest: list[str]  # dangerous imported symbol names seen
    bytes_scanned: int
    note: str
    trust: str = TRUST_TAG

    @property
    def max_severity(self) -> str:
        order = {"critical": 3, "high": 2, "medium": 1, "low": 0}
        best = "low"
        for s in self.sites:
            if order[s.severity] > order[best]:
                best = s.severity
        return best


# byte/string patterns (as bytes where possible for direct .find)
# Severity:
#   * CRITICAL = hard evidence (import corroboration or explicit debug calls)
#   * HIGH = string/name markers usually enough alone
#   * MEDIUM = weaker but consistent signals
# Severity ladder is consumption-based: ptrace string is MEDIUM for
# generic evidence, CRITICAL when PTRACE_TRACEME or import-list is present.
_BYTE_PATTERNS: list[tuple[bytes, str, str, str]] = [
    (b"ptrace", "ptrace", "medium", "ptrace symbol/string"),
    (b"PTRACE_TRACEME", "ptrace", "critical", "self-attach constant"),
    (b"TracerPid", "tracer_pid", "high", "TracerPid proc probe"),
    (b"/proc/self/status", "tracer_pid", "high", "/proc/self/status path"),
    (b"/proc/self/maps", "frida_scan", "high", "/proc/self/maps path"),
    (b"frida", "frida_scan", "high", "frida marker"),
    (b"gum-js-loop", "frida_scan", "high", "frida gum loop thread name"),
    (b"gmain", "frida_scan", "medium", "frida glib thread pool"),
    (b"linjector", "frida_scan", "high", "frida injector name"),
    (b"substrate", "frida_scan", "medium", "cydia substrate marker"),
    (b"xposed", "frida_scan", "medium", "xposed marker"),
    (b"/proc/self/stat", "tracer_pid", "medium", "/proc/self/stat path"),
    (b"check_crc", "crc_check", "medium", "crc check label"),
    (b"crc32", "crc_check", "medium", "crc32 symbol/string"),
    (b"gettimeofday", "timing", "low", "timing probe symbol"),
    (b"clock_gettime", "timing", "low", "timing probe symbol"),
    (b"int3", "syscall", "medium", "breakpoint string"),
]

_IMPORTS_OF_INTEREST = {
    "ptrace": ("ptrace", "medium"),  # string presence alone = medium; needs import to corroborate critical
    "prctl": ("syscall", "medium"),
    "gettimeofday": ("timing", "low"),
    "clock_gettime": ("timing", "low"),
    "syscall": ("syscall", "medium"),
    "inotify_add_watch": ("syscall", "low"),
    "kill": ("syscall", "medium"),
    "tgkill": ("syscall", "medium"),
    "fork": ("syscall", "low"),
}

# ptrace is only CRITICAL when the import is actually present (not just byte scan)


def _context(data: bytes, offset: int, width: int = 24) -> str:
    start = max(0, offset - 8)
    end = min(len(data), offset + width)
    chunk = data[start:end]
    out = []
    for b in chunk:
        out.append(chr(b) if 32 <= b < 127 else ".")
    return re.sub(r"\.{3,}", "...", "".join(out)).strip()


def _scan_patterns(data: bytes) -> list[TamperSite]:
    sites: list[TamperSite] = []
    for needle, category, severity, label in _BYTE_PATTERNS:
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                break
            sites.append(
                TamperSite(
                    category=category,
                    pattern=label,
                    offset=idx,
                    severity=severity,
                    snippet=_context(data, idx),
                    uncorroborated=True,
                )
            )
            start = idx + len(needle)
            if len(sites) >= 512:  # hostile-input bound
                return sites
    return sites


def _scan_imports(data: bytes, elf=None) -> list[str]:
    """Look for dangerous import names anywhere in the byte stream (cheap).

    When `elf` is provided (NativeElf), only report imports actually in the
    dynamic symbol table (imported=True).  Byte-scan fallback retained for
    situations without an ELF parse.
    """
    hits: list[str] = []
    if elf is not None:
        for sym in elf.symbols:
            if sym.imported and sym.name in _IMPORTS_OF_INTEREST:
                hits.append(sym.name)
        return sorted(set(hits))

    for name in _IMPORTS_OF_INTEREST:
        needle = name.encode()
        if data.find(needle) >= 0:
            hits.append(name)
    return sorted(hits)


def _scan_imports_from_elf(elf) -> list[str]:
    """Direct ELF dynamic import extraction (proper corroboration, not byte-scan)."""
    hits = []
    for sym in elf.symbols:
        if sym.imported and sym.name in _IMPORTS_OF_INTEREST:
            hits.append(sym.name)
    return sorted(set(hits))


def scan_so_bytes(data: bytes) -> AntiTamperResult:
    sites = _scan_patterns(data)
    # parse ELF to obtain real dynamic imports when available (not byte-scan).
    from src.analysis.native_elf import parse_elf
    elf = parse_elf(data)
    if elf is not None:
        imports = _scan_imports_from_elf(elf)  # real ELF import evidence
    else:
        imports = _scan_imports(data)  # fallback byte-scan when ELF parse fails
    # merge: imported handle presence upgrades matching category corroboration
    merged_sites = []
    category_to_import = {"ptrace": "ptrace", "timing": "gettimeofday"}
    for s in sites:
        corr = s.uncorroborated
        if s.category in category_to_import and category_to_import[s.category] in imports:
            corr = False
        # ptrace is CRITICAL when the import evidence exists (not just byte presence).
        # (ELITE-2 fix-2: only corroborated ptrace classifies CRITICAL.)
        sev = s.severity
        if s.category == "ptrace" and s.severity == "medium" and "ptrace" in imports:
            sev = "critical"
        merged_sites.append(
            TamperSite(s.category, s.pattern, s.offset, sev, s.snippet, corr)
        )
    cats = sorted({s.category for s in merged_sites})
    if not merged_sites and not imports:
        status, note = "clear", "no native anti-tamper evidence."
    else:
        status = "defended"
        note = f"{len(merged_sites)} anti-tamper evidence site(s) across {len(cats)} categor(ies); patch hit-list ready."
    return AntiTamperResult(
        status=status,
        sites=merged_sites,
        categories=cats,
        imports_of_interest=imports,
        bytes_scanned=len(data),
        note=note,
    )


# zip-bomb guard: refuse to decompress lib members whose declared uncompressed
# size exceeds this cap (zf.read does not apply the extract-only _MAX_EXTRACT_SIZE).
_MAX_LIB_BYTES = 256 * 1024 * 1024


def scan_apk_native_libs(apk_path: str) -> dict[str, AntiTamperResult]:
    """Scan every ``lib/**.so`` member of an APK (bounded, non-raising)."""
    out: dict[str, AntiTamperResult] = {}
    if not Path(apk_path).is_file():
        return out  # missing path: nothing scanned, no exception
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError):
        return out  # not a zip/apk: nothing scanned
    with zf:
        for name in zf.namelist():
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            info = zf.getinfo(name)
            if info.file_size > _MAX_LIB_BYTES:
                continue  # zip-bomb guard
            try:
                blob = zf.read(name)
            except (OSError, RuntimeError, KeyError):
                continue
            out[name] = scan_so_bytes(blob)
    return out
