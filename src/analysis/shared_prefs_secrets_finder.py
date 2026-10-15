"""SharedPreferences plaintext secrets detector (cleartext-preference).

Real fintech writeups (MWR/BishopFox): fintech apps store session tokens,
PINs, partial card numbers in `getSharedPreferences()` XML, which an adb
backup or root user can trivially read unless android:allowBackup=false.
This pairs with EncryptedSharedPreferences as mitigation but requires us to
first find the *plaintext* writes.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"

_PREFS_WRITE_RE = re.compile(
    r"(getSharedPreferences|PreferenceManager\.getDefaultSharedPreferences)"
    r"[\s\S]{0,200}?\.edit\(\)[\s\S]{0,200}?putString\s*\(\s*\"([^\"]+)\""
)
_SENSITIVE = re.compile(
    r"(token|secret|password|pin|auth|credential|session|apikey|api_key|card|cvv|pan|ssn)",
    re.IGNORECASE,
)


@dataclass
class PrefsResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}


def scan_source_text(text: str, *, source: str = "prefs") -> PrefsResult:
    if not text.strip():
        return PrefsResult(status="empty", note="no source")
    findings: list[Finding] = []
    for m in _PREFS_WRITE_RE.finditer(text):
        key = m.group(2)
        vocab = _SENSITIVE.findall(key)
        if not vocab:
            continue
        findings.append(Finding(
            module="shared_prefs_secrets_finder",
            kind="cleartext-preference",
            severity="high" if vocab else "medium",
            verdict=LIKELY,
            detail=f"SharedPreferences plaintext write of sensitive key '{key}'",
            evidence=m.group(0)[:200],
            metadata={"key": key, "vocab": vocab},
        ))
    return PrefsResult(status="success", findings=findings,
                       note=f"{len(findings)} plaintext-sensitive write(s)")
