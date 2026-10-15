"""WebView unsafe settings passive detector (webview-unsafe-settings).

Detects setJavaScriptEnabled(True) combined with addJavascriptInterface,
setAllowFileAccess(True), setAllowUniversalAccessFromFileURLs(True), or
clear-text loadUrl — classic WebView takeover primitives.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, CONFIRMED, Finding

TRUST_TAG = "untrusted_child"

_UNSAFE_PATTERNS: tuple[tuple[str, str, float], ...] = (
    (r"setjavascriptenabled\(true\)", "javascript-enabled", 0.8),
    ("addjavascriptinterface", "js-bridge", 0.9),
    (r"setallowfileaccess\(true\)", "file-access", 0.7),
    ("setAllowUniversalAccessFromFileURLs", "universal-file-access", 0.95),
    (r"loadurl\(\"http://", "cleartext-load", 0.8),
)


@dataclass
class WebviewSettingsResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}


def scan_source_text(text: str, *, source: str = "web") -> WebviewSettingsResult:
    if not text.strip():
        return WebviewSettingsResult(status="empty", note="no source")
    findings: list[Finding] = []
    for pattern, name, conf in _UNSAFE_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            findings.append(Finding(
                module="webview_settings_rule",
                kind="webview-unsafe-settings",
                severity="high" if conf > 0.85 else "medium",
                verdict=LIKELY,
                detail=f"unsafe WebView setting: {name}",
                evidence=m.group(0),
            ))
    return WebviewSettingsResult(status="success", findings=findings,
                                 note=f"{len(findings)} unsafe WebView setting(s)")
