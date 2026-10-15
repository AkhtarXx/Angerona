"""Deep-link scheme injection detector (Android SOTA priority 4).

Research basis (OWASP MASVS-PLATFORM deep-link controls; CWE-939 "Improper
Authorization in Handler for Custom URL Scheme"; Trend Micro's 2020 deep-link
abuse survey): an ``<intent-filter>`` with a custom ``android:scheme`` on an
exported Activity hands every installed app the ability to deliver attacker-
controlled URIs into the handler. The dangerous half is the *usage*: URI
parameters flowing unvalidated into ``Intent`` extras, ``loadUrl``, or SQL.

The manifest surface (scheme registration) is deterministic; the usage rows
are static claims tagged ``untrusted_child`` until a data-flow gate confirms
the parameter actually reaches a sink.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_SCHEME_RE = re.compile(r'android:scheme="([^"]+)"')
_HOST_RE = re.compile(r'android:host="([^"]+)"')
_EXPORTED_RE = re.compile(r'android:exported="true"')
# Scheme-carrying components: an exported deep-link handler can be an activity,
# an activity-alias, a receiver, or a service. ``(?![-\w])`` keeps ``<activity>``
# from also matching the ``<activity-alias`` prefix.
_COMPONENT_OPEN_RE = re.compile(
    r"<(activity|activity-alias|receiver|service)(?![-\w])[^>]*>", re.S
)
_DANGEROUS_SINKS = ("loadurl", "execsql", "rawquery", "runtime.exec",
                    "processbuilder", "openfileoutput", "getlastpathsegment")
_URI_GETTERS = ("getdata()", "getdatastring()", "getqueryparameter(", "getpathsegments(")


def _extract_invoked_method(low_line: str) -> str | None:
    """Best-effort semantic sink extraction from a Java/smali invoke line.

    Handles both Kotlin/Java source and smali bytecode, surviving basic
    R8-style renames by also matching against known WebView/File getters.
    """
    m = re.search(r"\b((?:loadurl|openfile|execsql|execsql|evaljavascript|setweb|addjsinterface|par)|(?:addjavascriptinterface))\s*\(", low_line)
    if m:
        return m.group(1)
    # smali invoke-* pattern: invoke-* {v...}, L<cls>;-><method>(...)
    m2 = re.search(r"L([A-Za-z0-9_/$]+);->([A-Za-z0-9_$]+)\(", low_line)
    if m2:
        return m2.group(1) + ";->" + m2.group(2)
    return None


from .finding import CONFIRMED, INCONCLUSIVE, LIKELY, Finding


@dataclass
class DeepLinkScanResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    schemes: list[str] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": self.findings,
            "schemes": self.schemes,
            "note": self.note,
            "trust": self.trust,
            "policy": "data-flow claims are static; require taint-gate corroboration",
        }


def _read_manifest_text(apk: zipfile.ZipFile) -> str:
    """Return whatever decodable text the manifest carries (binary AXML keeps
    the string pool readable enough for scheme/activity attributes)."""
    if "AndroidManifest.xml" not in apk.namelist():
        return ""
    try:
        raw = apk.read("AndroidManifest.xml")
    except (OSError, RuntimeError, KeyError):
        return ""
    text = raw.decode("utf-8", errors="ignore")
    if "android:scheme" in text:
        return text
    # binary AXML: fall back to printable-string extraction
    return "\n".join(
        m.decode("ascii", errors="ignore")
        for m in re.findall(rb"[ -~]{4,}", raw)
    )


def _component_blocks(manifest_text: str) -> list[str]:
    """Full text of each scheme-capable component element (self-closing or body).

    ``android:exported`` must be scoped to the exact component carrying a scheme;
    a whole-manifest search lets any unrelated exported component inflate every
    scheme into a high-severity exported handler, while matching only
    ``<activity>`` would drop exported ``<activity-alias>``/``<receiver>``/
    ``<service>`` deep-link handlers into false negatives.
    """
    blocks: list[str] = []
    for m in _COMPONENT_OPEN_RE.finditer(manifest_text):
        tag = m.group(1)
        open_tag = m.group(0)
        if open_tag.rstrip().endswith("/>"):
            blocks.append(open_tag)
            continue
        close = f"</{tag}>"
        end = manifest_text.find(close, m.end())
        if end < 0:
            blocks.append(open_tag)  # malformed unterminated tag
            continue
        blocks.append(manifest_text[m.start():end + len(close)])
    return blocks


def _scheme_export_flags(manifest_text: str) -> dict[str, bool]:
    """Map each scheme to whether its registering component is exported.

    ``android:exported`` must be scoped to the component carrying the scheme;
    a whole-manifest search lets any unrelated exported component inflate
    every scheme into a high-severity exported handler.
    """
    flags: dict[str, bool] = {}
    for block in _component_blocks(manifest_text):
        exported = bool(_EXPORTED_RE.search(block))
        for scheme in _SCHEME_RE.findall(block):
            flags[scheme] = flags.get(scheme, False) or exported
    return flags


def scan_manifest_text(manifest_text: str, *, source: str = "AndroidManifest.xml") -> DeepLinkScanResult:
    """Scan manifest text (binary-AXML-decoded or plain XML) for schemes."""
    if not manifest_text:
        return DeepLinkScanResult(status="empty", note="no manifest text")
    findings: list[DeepLinkFinding] = []
    schemes = sorted(set(_SCHEME_RE.findall(manifest_text)))
    exported_by_scheme = _scheme_export_flags(manifest_text)
    # A scheme attribute on its own line (binary AXML fallback) still counts.
    if not schemes:
        for line in manifest_text.splitlines():
            if line.strip().startswith(("http", "https")) or "://" in line:
                continue
    for scheme in schemes:
        exported = exported_by_scheme.get(scheme, False)
        sev = "high" if exported and scheme not in ("http", "https") else "medium"
        findings.append(Finding(
            module="deeplink_injection",
            kind="scheme-registration", severity=sev, verdict=LIKELY,
            detail=f"custom URL scheme registered: {scheme}://"
                   + (" (exported handler)" if exported else ""),
            rule_layer="manifest", evidence=source,
        ))
    if any(exported_by_scheme.get(scheme, False) for scheme in schemes):
        findings.append(Finding(
            module="deeplink_injection",
            kind="exported-handler", severity="high", verdict=LIKELY,
            detail="scheme-carrying activity is exported; any installed app can deliver URIs",
            rule_layer="manifest", evidence=source,
        ))
    return DeepLinkScanResult(
        status="success",
        findings=findings,
        schemes=schemes,
        note=f"{len(schemes)} scheme(s), {len(findings)} finding(s)",
    )


def scan_usage_text(source_text: str, *, source: str = "source") -> DeepLinkScanResult:
    """Scan handler code for URI parameter -> dangerous-sink flows."""
    if not source_text:
        return DeepLinkScanResult(status="empty", note="empty text")
    findings: list[Finding] = []
    lines = source_text.splitlines()
    for i, line in enumerate(lines, 1):
        low = line.lower()
        getter = next((g for g in _URI_GETTERS if g in low), None)
        if getter:
            window = "\n".join(lines[i - 1: i + 6]).lower()
            sink = next((s for s in _DANGEROUS_SINKS if s in window), None)
            invoked = _extract_invoked_method(window)
            sink_detail = sink or invoked
            findings.append(Finding(
                module="deeplink_injection",
                kind="unvalidated-uri-flow",
                severity="high" if sink or invoked else "medium",
                verdict=LIKELY if sink else LIKELY,
                detail=f"URI getter {getter} at line {i}"
                       + (f" reaches sink {sink_detail} within 6 lines" if sink_detail
                          else " (no sink in window)"),
                line_no=i, rule_layer="java" if source.endswith((".java", ".kt")) else "smali",
                evidence=source,
                metadata={"literal_sink": sink, "invoked_method": invoked},
            ))
    return DeepLinkScanResult(
        status="success", findings=findings,
        note=f"{len(findings)} URI-flow claim(s)",
    )


def scan_apk(apk_path: str | Path) -> DeepLinkScanResult:
    """Manifest-side scan over a real APK file. Degrades on malformed input."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return DeepLinkScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return DeepLinkScanResult(status="error", note=f"not a zip/apk: {exc}")
    with zf:
        text = _read_manifest_text(zf)
    result = scan_manifest_text(text)
    if result.status == "empty":
        return DeepLinkScanResult(status="empty", note="no readable manifest")
    return result
