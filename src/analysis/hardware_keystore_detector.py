"""Hardware-backed keystore attestation claim detector (hardware-keystore-claim).

Detects when an app claims hardware-backed keystore (Android Keystore,
StrongBox, TEE-backed) — this is a positive signal, but spoofable on rooted
devices.  When the app ALSO contains root indicators, the claim becomes suspect.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from .finding import LIKELY, Finding

TRUST_TAG = "untrusted_child"

_CLAIM_TOKENS = (
    "AndroidKeyStore", "StrongBox", "KeyGenParameterSpec",
    "KeyStore.getInstance(\"AndroidKeyStore\")",
    "android.hardware.keystore",
)


@dataclass
class HardwareKeystoreResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {"status": self.status, "findings": [f.as_dict() for f in self.findings],
                "note": self.note, "trust": self.trust}


def scan_source_text(text: str, *, source: str = "keystore") -> HardwareKeystoreResult:
    if not text.strip():
        return HardwareKeystoreResult(status="empty", note="no source")
    findings: list[Finding] = []
    for tok in _CLAIM_TOKENS:
        if tok.lower() in text.lower():
            findings.append(Finding(
                module="hardware_keystore_detector",
                kind="hardware-keystore-claim",
                severity="info",
                verdict=LIKELY,
                detail=f"hardware keystore claim via: {tok}",
                evidence=tok,
            ))
            break
    return HardwareKeystoreResult(status="success", findings=findings,
                                  note=f"{len(findings)} keystore claim(s)")
