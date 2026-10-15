"""WebView JavaScript-bridge implicit-export finder (Android SOTA priority 3).

Research basis (OWASP MASVS-PLATFORM WebView controls; the CVE-2012-6636 /
CVE-2014-1939 "addJavascriptInterface" class; and CWE-749 "Exposed Dangerous
Method"): any object handed to ``WebView.addJavascriptInterface`` exposes its
``@JavascriptInterface``-annotated methods to *any* JS the page loads. On API <
17 even un-annotated public methods are callable (the implicit-export bug this
module is named for). ``setJavaScriptEnabled(true)`` + ``loadUrl(http://...)``
turns that surface into a remote-execution path.

Static claims only: matches are ``untrusted_child`` until a call-graph gate
confirms reachability from an exported Activity.
"""

from __future__ import annotations

from .finding import CONFIRMED, LIKELY, Finding
from .findings_compat import as_canonical_findings

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_MARKERS: tuple[tuple[str, str, str], ...] = (
    ("addjavascriptinterface", "js-bridge-registration", "high"),
    ("@javascriptinterface", "js-bridge-annotation", "medium"),
    ("setjavascriptenabled(true)", "js-enabled", "medium"),
    ("setallowfileaccess(true)", "file-access-enabled", "medium"),
    ("setallowuniversalaccessfromfileurls(true)", "universal-file-access", "high"),
    ("setallowfileaccessfromfileurls(true)", "file-url-access", "high"),
    ("loadurl(\"http://", "cleartext-js-load", "high"),
    ("shouldinterceptrequest", "request-interceptor", "low"),
    ("webviewclient", "webview-client", "info"),
)

_ANNOTATION_PAIR = re.compile(
    r"@JavascriptInterface[\s\S]{0,400}?(public\s+[\w<>\[\]]+\s+(\w+)\s*\()",
    re.MULTILINE,
)


@dataclass
class BridgeFinding:
    marker: str
    severity: str
    evidence: str
    source: str
    line_no: int
    exposed_methods: list[str] = field(default_factory=list)
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "marker": self.marker,
            "severity": self.severity,
            "evidence": self.evidence,
            "source": self.source,
            "line_no": self.line_no,
            "exposed_methods": list(self.exposed_methods),
            "trust": self.trust,
        }


@dataclass
class BridgeScanResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    bridges_registered: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": self.findings,
            "bridges_registered": self.bridges_registered,
            "note": self.note,
            "trust": self.trust,
            "policy": "static marker match; reachability requires call-graph gate",
        }


def scan_source_text(text: str, *, source: str = "source") -> BridgeScanResult:
    """Scan Java/smali text for WebView bridge markers."""
    if not text:
        return BridgeScanResult(status="empty", note="empty text")
    findings: list[BridgeFinding] = []
    exposed = [m.group(2) for m in _ANNOTATION_PAIR.finditer(text)]
    for line_no, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for token, marker, severity in _MARKERS:
            if token in low:
                findings.append(BridgeFinding(
                    marker=marker, severity=severity,
                    evidence=line.strip(), source=source, line_no=line_no,
                    exposed_methods=exposed if marker == "js-bridge-annotation" else [],
                ))
    return BridgeScanResult(
        status="success",
        findings=as_canonical_findings("webview_bridge_finder", findings),
        bridges_registered=sum(1 for f in findings if f.marker == "js-bridge-registration"),
        note=f"{len(findings)} WebView marker(s), {len(exposed)} annotated method(s)",
    )


def scan_apk_dex_strings(apk_path: str | Path) -> BridgeScanResult:
    """Fallback scan over DEX raw strings when no source is available."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return BridgeScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return BridgeScanResult(status="error", note=f"not a zip/apk: {exc}")
    findings: list[Finding] = []
    str_re = re.compile(rb"[ -~]{6,}")
    with zf:
        for name in zf.namelist():
            if not name.endswith(".dex"):
                continue
            try:
                blob = zf.read(name)
            except (OSError, RuntimeError, KeyError):
                continue
            for m in str_re.finditer(blob):
                s = m.group().decode("ascii", errors="ignore").lower()
                for token, marker, severity in _MARKERS:
                    if token.replace("(", "").replace("\"", "") in s:
                        findings.append(BridgeFinding(
                            marker=marker, severity=severity,
                            evidence=m.group().decode("ascii", errors="ignore"),
                            source=name, line_no=m.start(),
                        ))
                        break
    findings = as_canonical_findings("webview_bridge_finder", findings)
    return BridgeScanResult(
        status="success",
        findings=findings,
        bridges_registered=sum(1 for f in findings if f.kind == "js-bridge-registration"),
        note=f"{len(findings)} WebView marker(s) in DEX strings",
    )
