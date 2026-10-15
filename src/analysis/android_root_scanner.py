"""Android root/tamper fingerprint static scanner (Android SOTA priority 1).

Research basis (rootbeer [scottyab/rootbeer], MagiskHide technical notes, and the
OWASP MASVS-RESILIENCE control family): production tamper checks leave a stable
vocabulary in DEX strings — su-path probes, Magisk package names, BusyBox applets,
SELinux state reads, ``SystemProperties.get`` and ``TracerPid`` self-inspection.
Finding that vocabulary is deterministic evidence that the sample *contains* an
anti-analysis surface the rest of the pipeline must not mistake for app logic.

Every finding carries the ``untrusted_child`` trust marker: a string match is a
claim by an untrusted artifact, not a verified fact, until a downstream gate
corroborates it against call-site evidence.
"""

from __future__ import annotations

from .finding import CONFIRMED, LIKELY, Finding
from .findings_compat import as_canonical_findings

import io
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

# RootBeer /Magisk / BusyBox vocabulary; each tuple is (token, category).
# Tokens are matched case-insensitively inside extracted printable strings.
_ROOT_VOCAB: tuple[tuple[str, str], ...] = (
    ("/sbin/su", "su_path"),
    ("/system/bin/su", "su_path"),
    ("/system/xbin/su", "su_path"),
    ("/system/app/supersu", "su_package"),
    ("eu.chainfire.supersu", "su_package"),
    ("com.topjohnwu.magisk", "magisk"),
    ("magisk", "magisk"),
    ("magiskhide", "magisk"),
    ("busybox", "busybox"),
    ("toybox", "busybox"),
    ("/proc/self/status", "tracerpid"),
    ("tracerpid", "tracerpid"),
    ("getenforce", "selinux"),
    ("/sys/fs/selinux", "selinux"),
    ("selinux", "selinux"),
    ("systemproperties", "system_property"),
    ("ro.debuggable", "system_property"),
    ("ro.secure", "system_property"),
    ("service.adb.root", "system_property"),
    ("test-keys", "build_tags"),
    ("xposed", "hooking_framework"),
    ("substrate", "hooking_framework"),
    ("frida", "hooking_framework"),
)

_SEVERITY_BY_CATEGORY = {
    "magisk": "high",
    "hooking_framework": "high",
    "su_package": "high",
    "tracerpid": "medium",
    "su_path": "medium",
    "selinux": "medium",
    "busybox": "low",
    "system_property": "low",
    "build_tags": "low",
}

_STRING_RE = re.compile(rb"[ -~]{4,}")


@dataclass
class RootIndicator:
    category: str
    token: str
    severity: str
    offset: int
    source: str            # e.g. "classes.dex" or "smali:line"
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "token": self.token,
            "severity": self.severity,
            "offset": self.offset,
            "source": self.source,
            "trust": self.trust,
        }


@dataclass
class RootScanResult:
    status: str            # success | empty | error | skipped
    indicators: list[Finding] = field(default_factory=list)
    categories: dict[str, int] = field(default_factory=dict)
    bytes_scanned: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "indicators": self.indicators,
            "categories": self.categories,
            "bytes_scanned": self.bytes_scanned,
            "note": self.note,
            "trust": self.trust,
            "policy": "string-vocabulary match is a claim by an untrusted artifact",
        }


def scan_bytes(data: bytes, *, source: str = "buffer") -> RootScanResult:
    """Scan raw bytes (DEX, .so, config) for the root/tamper vocabulary."""
    if not data:
        return RootScanResult(status="empty", note="zero-byte input")
    indicators: list[RootIndicator] = []
    for m in _STRING_RE.finditer(data):
        s = m.group().decode("ascii", errors="ignore").lower()
        for token, category in _ROOT_VOCAB:
            if token in s:
                indicators.append(RootIndicator(
                    category=category, token=token,
                    severity=_SEVERITY_BY_CATEGORY.get(category, "info"),
                    offset=m.start(), source=source,
                ))
    categories: dict[str, int] = {}
    for ind in indicators:
        categories[ind.category] = categories.get(ind.category, 0) + 1
    return RootScanResult(
        status="success",
        indicators=as_canonical_findings("android_root_scanner", indicators),
        categories=categories,
        bytes_scanned=len(data),
        note=f"{len(indicators)} root/tamper indicator(s)",
    )


def scan_smali_text(text: str, *, source: str = "smali") -> RootScanResult:
    """Scan smali/java source text line by line (richer offsets)."""
    if not text:
        return RootScanResult(status="empty", note="empty text")
    indicators: list[RootIndicator] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for token, category in _ROOT_VOCAB:
            if token in low:
                indicators.append(RootIndicator(
                    category=category, token=token,
                    severity=_SEVERITY_BY_CATEGORY.get(category, "info"),
                    offset=line_no, source=source,
                ))
    categories: dict[str, int] = {}
    for ind in indicators:
        categories[ind.category] = categories.get(ind.category, 0) + 1
    return RootScanResult(
        status="success",
        indicators=as_canonical_findings("android_root_scanner", indicators),
        categories=categories,
        bytes_scanned=len(text.encode("utf-8", errors="ignore")),
        note=f"{len(indicators)} root/tamper indicator(s)",
    )


def scan_apk(apk_path: str | Path) -> RootScanResult:
    """Scan every DEX member of an APK. Degrades on any malformed input."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return RootScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return RootScanResult(status="error", note=f"not a zip/apk: {exc}")
    indicators: list[Finding] = []
    categories: dict[str, int] = {}
    total = 0
    with zf:
        for name in zf.namelist():
            if not (name.endswith(".dex") or name.endswith(".so")):
                continue
            try:
                blob = zf.read(name)
            except (OSError, RuntimeError, KeyError):
                continue
            sub = scan_bytes(blob, source=name)
            total += sub.bytes_scanned
            indicators.extend(sub.indicators)
            for cat, n in sub.categories.items():
                categories[cat] = categories.get(cat, 0) + n
    return RootScanResult(
        status="success",
        indicators=indicators,
        categories=categories,
        bytes_scanned=total,
        note=f"{len(indicators)} root/tamper indicator(s) across APK",
    )
