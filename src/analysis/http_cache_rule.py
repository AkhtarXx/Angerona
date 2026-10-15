"""HTTP response cache credential/PII sniff rule (http-cache-enabled).

When OkHttp/Retrofit caching is enabled for responses containing auth
tokens or PII, subsequent users of the device can read cached blobs.  This
rule scans for OkHttpCache/Cache-Control misuse.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"

_CACHE_ENABLE_RE = re.compile(
    r"(okhttp3\.Cache|\.cache\s*\(|CacheControl|setCacheEnabled|responseCache)",
    re.IGNORECASE,
)
_SENSITIVE = re.compile(
    r"(token|secret|password|session|auth|cookie|bearer|api[_-]?key)",
    re.IGNORECASE,
)


@dataclass
class HttpCacheResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}


def scan_source_text(text: str, *, source: str = "http") -> HttpCacheResult:
    if not text.strip():
        return HttpCacheResult(status="empty", note="no source")
    findings: list[Finding] = []
    if _CACHE_ENABLE_RE.search(text):
        sensitive = _SENSITIVE.search(text)
        if sensitive:
            findings.append(Finding(
                module="http_cache_rule",
                kind="http-cache-enabled",
                severity="medium",
                verdict=LIKELY,
                detail="HTTP cache enabled in presence of sensitive vocab (token/auth)",
                evidence=sensitive.group(0),
            ))
    return HttpCacheResult(status="success", findings=findings,
                           note=f"{len(findings)} cache-sensitive finding(s)")
