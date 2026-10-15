"""Exported ContentProvider path-traversal detector (Android SOTA priority 5).

Research basis (OWASP MASVS-PLATFORM IPC controls; CWE-22 "Path Traversal";
the well-known ``openFile``/``openAssetFile`` traversal class documented by
MWR/NowSecure): an exported ``<provider>`` whose ``openFile`` hands a
caller-controlled ``Uri`` straight to ``ParcelFileDescriptor.open`` lets any
app read outside the provider's directory via ``content://auth/../..``.

The manifest half (exported provider, grantUriPermissions) is deterministic;
code-level sinks are static claims tagged ``untrusted_child`` until a
sanitizer-usage gate (canonicalize + startsWith check) is verified absent.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_PROVIDER_RE = re.compile(
    r"<provider[^>]*android:name=\"([^\"]+)\"[^>]*>", re.DOTALL)
_AUTHORITY_RE = re.compile(r'android:authorities="([^"]+)"')
_EXPORTED_TRUE_RE = re.compile(r'android:exported="true"')
_EXPORTED_FALSE_RE = re.compile(r'android:exported="false"')
_GRANT_URI_RE = re.compile(r'android:grantUriPermissions="true"')

_SINK_TOKENS = ("openfile(", "openassetfile(", "parcelfiledescriptor.open",
                "new file(uri", "getpath()")
_SANITIZER_TOKENS = ("getcanonicalpath", "canonicalize", "startswith(")


from .finding import CONFIRMED, LIKELY, Finding


@dataclass
class ProviderScanResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    providers: list[str] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": self.findings,
            "providers": self.providers,
            "note": self.note,
            "trust": self.trust,
            "policy": "sink rows are static claims; sanitizer-absence needs verification",
        }


def scan_manifest_text(manifest_text: str, *, source: str = "AndroidManifest.xml") -> ProviderScanResult:
    if not manifest_text:
        return ProviderScanResult(status="empty", note="no manifest text")
    findings: list[Finding] = []
    providers: list[str] = []
    for m in _PROVIDER_RE.finditer(manifest_text):
        tag = m.group(0)
        name = m.group(1)
        providers.append(name)
        if _EXPORTED_FALSE_RE.search(tag):
            continue
        exported = bool(_EXPORTED_TRUE_RE.search(tag))
        auth_m = _AUTHORITY_RE.search(tag)
        authority = auth_m.group(1) if auth_m else "<unspecified>"
        if exported:
            findings.append(Finding(
                module="contentprovider_traversal",
                kind="exported-provider", severity="high", verdict=LIKELY,
                detail=f"exported provider {name} (authority={authority})",
                rule_layer="manifest", evidence=source,
            ))
        if _GRANT_URI_RE.search(tag):
            findings.append(Finding(
                module="contentprovider_traversal",
                kind="grant-uri-permissions", severity="medium", verdict=LIKELY,
                detail=f"provider {name} grants URI permissions (widens traversal blast radius)",
                rule_layer="manifest", evidence=source,
            ))
    return ProviderScanResult(
        status="success" if providers else "empty",
        findings=findings, providers=providers,
        note=f"{len(providers)} provider(s), {len(findings)} finding(s)",
    )


_CONTROL_KWS = ("if", "for", "while", "switch", "catch", "else", "try", "do", "finally")
_TYPE_DECL_KWS = ("class", "interface", "enum", "record", "annotation")


def _is_method_header(stripped: str) -> bool:
    """True if a stripped Java/Kotlin line opens a method body (K&R ``{``)."""
    if "(" not in stripped or "{" not in stripped:
        return False
    head = stripped.split("(", 1)[0].strip().lower()
    words = [w for w in re.split(r"[^a-z0-9_$]+", head) if w]
    if not words:
        return False
    return not any(w in _CONTROL_KWS or w in _TYPE_DECL_KWS for w in words)


def _starts_method_signature(stripped: str) -> bool:
    """True if a stripped line starts a method signature whose ``{`` lands on a
    later line (Allman style or a wrapped signature), e.g. ``openFile(Uri u,
    String m)``. Excludes statement/assignment lines that merely contain ``(``."""
    if "(" not in stripped or "{" in stripped:
        return False
    if stripped.endswith((";", "=")):
        return False
    head = stripped.split("(", 1)[0].strip().lower()
    words = [w for w in re.split(r"[^a-z0-9_$]+", head) if w]
    if not words:
        return False
    return not any(w in _CONTROL_KWS or w in _TYPE_DECL_KWS for w in words)


def _method_scopes(lines: list[str]) -> list[int | None]:
    """Assign each line the id of the enclosing method (brace-delimited Java/Kotlin,
    or a smali ``.method`` block). Lines outside any method get None."""
    scopes: list[int | None] = [None] * len(lines)
    if any(l.lstrip().lower().startswith(".method ") for l in lines):
        current: int | None = None
        next_id = 0
        for i, line in enumerate(lines):
            s = line.strip().lower()
            if s.startswith(".method "):
                current = next_id
                next_id += 1
            elif s.startswith(".end method"):
                current = None
            scopes[i] = current
        return scopes
    depth_scopes: list[int | None] = [None]
    next_id = 0
    pending_signature = False
    for i, line in enumerate(lines):
        stripped = line.strip()
        if pending_signature and "{" in line:
            # Allman / multi-line signature: '{' arrives on its own line (or at
            # the end of a wrapped signature); open the method body now.
            current = next_id
            next_id += 1
            pending_signature = False
        else:
            is_header = _is_method_header(stripped)
            current = next_id if is_header else (depth_scopes[-1] if depth_scopes else None)
            if is_header:
                next_id += 1
            elif _starts_method_signature(stripped):
                pending_signature = True
        scopes[i] = current
        for _ in range(line.count("{")):
            depth_scopes.append(current)
        for _ in range(line.count("}")):
            if len(depth_scopes) > 1:
                depth_scopes.pop()
    return scopes


def scan_provider_code(source_text: str, *, source: str = "source") -> ProviderScanResult:
    """Scan provider implementation for Uri -> file-open traversal sinks."""
    if not source_text:
        return ProviderScanResult(status="empty", note="empty text")
    findings: list[Finding] = []
    lines = source_text.splitlines()
    scopes = _method_scopes(lines)
    # A sink is downgraded only when a sanitizer token appears in the same
    # method, so one canonicalizing openFile() cannot hide a sibling openFile()
    # that passes Uri.getPath() straight to new File().
    sanitized_scopes = {
        scopes[i]
        for i, line in enumerate(lines)
        if scopes[i] is not None and any(tok in line.lower() for tok in _SANITIZER_TOKENS)
    }
    for i, line in enumerate(lines, 1):
        low = line.lower()
        sink = next((t for t in _SINK_TOKENS if t in low), None)
        if sink:
            sanitized = scopes[i - 1] in sanitized_scopes
            findings.append(Finding(
                module="contentprovider_traversal",
                kind="traversal-sink",
                severity="medium" if sanitized else "high",
                verdict=LIKELY,
                detail=f"provider file-open sink '{sink}' at line {i}"
                       + (" (canonicalization tokens present — verify scope)" if sanitized
                          else " with NO canonicalization token in method"),
                line_no=i, rule_layer="java" if source.endswith((".java", ".kt")) else "smali",
                evidence=source,
            ))
    return ProviderScanResult(
        status="success", findings=findings,
        note=f"{len(findings)} traversal-sink claim(s)",
    )


def scan_apk(apk_path: str | Path) -> ProviderScanResult:
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return ProviderScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return ProviderScanResult(status="error", note=f"not a zip/apk: {exc}")
    with zf:
        if "AndroidManifest.xml" not in zf.namelist():
            return ProviderScanResult(status="empty", note="no manifest member")
        try:
            raw = zf.read("AndroidManifest.xml")
        except (OSError, RuntimeError, KeyError):
            return ProviderScanResult(status="error", note="manifest unreadable")
    text = raw.decode("utf-8", errors="ignore")
    if "<provider" not in text:
        # binary AXML fallback: printable-string extraction keeps the
        # attributes legible enough for the regexes above.
        text = "\n".join(m.decode("ascii", errors="ignore")
                         for m in re.findall(rb"[ -~]{4,}", raw))
    return scan_manifest_text(text)
