"""Cleartext-HTTP + TrustAll-TLS combined rule (Android SOTA priority 6).

Research basis (OWASP MASVS-NETWORK; CWE-295 "Improper Certificate
Validation"; CWE-319 "Cleartext Transmission"): the two failure modes
compound — an app that both speaks cleartext HTTP *and* installs an
accept-all ``X509TrustManager`` / ``HostnameVerifier`` has no transport
integrity at all. The combined score is what matters for triage, so this
module emits both per-line findings and a joint verdict.

``usesCleartextTraffic="true"`` and ``networkSecurityConfig`` absence are
manifest-deterministic; code tokens are static claims tagged
``untrusted_child`` until an interprocedural gate confirms the trust manager
is actually installed on a live connection.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TRUST_TAG = "untrusted_child"

_CLEARTEXT_URL = re.compile(r'http://[^\s"\'<>]+')
_TRUSTALL_TOKENS = (
    ("x509trustmanager", "custom-trustmanager"),
    ("checkservertrusted", "trustmanager-override"),
    ("allow_all_hostname_verifier", "allow-all-hostname"),
    ("noophostnameverifier", "noop-hostname-verifier"),
    ("setdefaulthostnameverifier", "hostname-verifier-install"),
    ("sslsocketfactory", "custom-sslsocketfactory"),
    ("trustallcerts", "trustall-certs"),
)
_CLEARTEXT_MANIFEST_RE = re.compile(r'android:usesCleartextTraffic="(true|false)"')
_NSC_MANIFEST_RE = re.compile(r'android:networkSecurityConfig="([^"]+)"')


from .finding import CONFIRMED, LIKELY, Finding


@dataclass
class TlsScanResult:
    status: str
    findings: list[Finding] = field(default_factory=list)
    cleartext_count: int = 0
    trustall_count: int = 0
    combined_risk: str = "none"      # none | low | medium | high
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "findings": self.findings,
            "cleartext_count": self.cleartext_count,
            "trustall_count": self.trustall_count,
            "combined_risk": self.combined_risk,
            "note": self.note,
            "trust": self.trust,
            "policy": "combined verdict = cleartext AND trust-all; each half is a claim",
        }


def _combined(cleartext: int, trustall: int) -> str:
    if cleartext and trustall:
        return "high"
    if trustall:
        return "medium"
    if cleartext:
        return "low"
    return "none"


def scan_source_text(text: str, *, source: str = "source") -> TlsScanResult:
    """Scan Java/smali text for cleartext + trust-all markers."""
    if not text:
        return TlsScanResult(status="empty", note="empty text")
    findings: list[TlsFinding] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        low = line.lower()
        for m in _CLEARTEXT_URL.finditer(low):
            url = m.group()
            if "localhost" in url or "127.0.0.1" in url:
                continue
            # Skip schema namespace references (http://schemas.android.com, etc.) — not actual clear text endpoints
            if "schemas.android.com" in url or "w3.org" in url or "adobe.com" in url:
                continue
            findings.append(Finding(
                module="cleartext_tls_rule",
                kind="cleartext-http", severity="medium", verdict=LIKELY,
                detail=f"cleartext HTTP reference",
                evidence=line.strip()[:200],
                line_no=line_no, rule_layer="java" if source.endswith((".java", ".kt")) else "smali",
            ))
        for token, kind in _TRUSTALL_TOKENS:
            if token in low:
                findings.append(Finding(
                    module="cleartext_tls_rule",
                    kind=kind, severity="high", verdict=LIKELY if "trustall" in kind else LIKELY,
                    detail=f"trust manager bypass pattern: {token}",
                    evidence=line.strip()[:200],
                    line_no=line_no,
                ))
                break
    cleartext = sum(1 for f in findings if f.kind == "cleartext-http")
    trustall = sum(1 for f in findings
                   if f.kind in ("trustall-certs", "noop-hostname-verifier", "trustmanager-override",
                                  "custom-trustmanager", "custom-sslsocketfactory",
                                  "allow-all-hostname", "hostname-verifier-install"))
    return TlsScanResult(
        status="success",
        findings=findings,
        cleartext_count=cleartext, trustall_count=trustall,
        combined_risk=_combined(cleartext, trustall),
        note=f"cleartext={cleartext} trustall={trustall} combined={_combined(cleartext, trustall)}",
    )


def scan_manifest_text(manifest_text: str, *, source: str = "AndroidManifest.xml") -> TlsScanResult:
    if not manifest_text:
        return TlsScanResult(status="empty", note="no manifest text")
    findings: list[Finding] = []
    m = _CLEARTEXT_MANIFEST_RE.search(manifest_text)
    cleartext = 0
    if m and m.group(1) == "true":
        cleartext = 1
        findings.append(Finding(
            module="cleartext_tls_rule",
            kind="manifest-cleartext", severity="high", verdict=LIKELY,
            detail='usesCleartextTraffic="true"', rule_layer="manifest", evidence=source,
        ))
    elif m is None and not _NSC_MANIFEST_RE.search(manifest_text):
        findings.append(Finding(
            module="cleartext_tls_rule",
            kind="manifest-cleartext", severity="low", verdict=LIKELY,
            detail="no usesCleartextTraffic attr and no networkSecurityConfig",
            rule_layer="manifest", evidence=source,
        ))
    return TlsScanResult(
        status="success",
        findings=findings,
        cleartext_count=cleartext, trustall_count=0,
        combined_risk="none",
        note=f"{len(findings)} manifest transport finding(s)",
    )


def merge_results(*results: TlsScanResult) -> TlsScanResult:
    """Combine manifest + code scans into one layered verdict."""
    merged = TlsScanResult(status="success")
    for r in results:
        merged.findings.extend(r.findings)
        merged.cleartext_count += r.cleartext_count
        merged.trustall_count += r.trustall_count
    merged.combined_risk = _combined(merged.cleartext_count, merged.trustall_count)
    merged.note = f"merged: cleartext={merged.cleartext_count} trustall={merged.trustall_count}"
    return merged
