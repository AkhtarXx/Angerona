"""Mutual-TLS (MTLS) tier classifier for Android network security.

Fintech / enterprise apps increasingly require *client* certs — meaning the
APK holds a KeyManager that presents a hardware-backed private key during the
TLS handshake.  This breaks classic MITM testing even before pinning is in
play.  Security verdicts need to distinguish:

  * no-tls      — HTTP/cleartext (bad)
  * server-tls  — server auth only (typical)
  * mtls-soft   — client cert from software keystore (intercept-able with root)
  * mtls-hard   — client cert from hardware keystore (TEE/StrongBox — MITM blocked)

Existing `cleartext_tls_rule` only distinguishes the first two.  This module
scans manifest, source, and native-lib strings for the **KeyManagerFactory /
KeyStore usage chain** to refine the tier.

Trust: ``untrusted_child``.
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_KEYMGR_TOKENS = (
    "keymanagerfactory", "javax.net.ssl.keymanagerfactory",
    "x509keymanager", "privatekeyentry",
    "keystore.getkey", "keystore.getprivatekey",
    "setalias", "chooseclientalias", "keychain.chooseprivatekeyalias",
)
_HW_KEYSTORE_TOKENS = (
    "androidkeystore", "android_hardware_keystore",
    "android.security.keystore", "keymastersignature",
    "strongbox", "hardwarekeygate", "androidhardwarekeymint",
)
_INSTALLED_CERT_MARKERS = (
    "clientalias", "client_alias", "client_cert",
    "ssl_client_auth", "clientauthentication",
)


@dataclass
class MtlsResult:
    status: str                      # identified | mtls_not_detected | partial | error
    tier: str                        # none | server_tls | mtls_soft | mtls_hard
    signals: list[str] = field(default_factory=list)
    hardware_keystore_evidence: bool = False
    client_cert_chain_detected: bool = False
    recommended_testing: str = ""     # "mitm_with_ca" / "repinning_only" / "runtime_hook_only" / "tee_required"
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "tier": self.tier,
            "signals": self.signals,
            "hardware_keystore_evidence": self.hardware_keystore_evidence,
            "client_cert_chain_detected": self.client_cert_chain_detected,
            "recommended_testing": self.recommended_testing,
            "note": self.note,
            "trust": self.trust,
        }


def _scan_text(text: str, tokens: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    low = text.lower()
    for t in tokens:
        if t.lower() in low:
            hits.append(t)
    return hits


def classify_mtls_tier(
    *,
    manifest_text: str = "",
    source_text: str = "",
    apk_path: str | Path | None = None,
) -> MtlsResult:
    """Classify the MTLS posture of an APK.

    Inputs: decoded manifest text (from ``apktool_bridge``), decompiled
    source / smali corpus, and optionally the APK itself for native .so
    string signals.
    """
    signals: list[str] = []

    if manifest_text:
        for m in _scan_text(manifest_text, _INSTALLED_CERT_MARKERS):
            signals.append(f"manifest:{m}")

    if source_text:
        for m in _scan_text(source_text, _KEYMGR_TOKENS):
            signals.append(f"source:{m}")
        for m in _scan_text(source_text, _HW_KEYSTORE_TOKENS):
            signals.append(f"source-hw:{m}")
        for m in _scan_text(source_text, _INSTALLED_CERT_MARKERS):
            signals.append(f"source-cert:{m}")

    if apk_path is not None and Path(apk_path).is_file():
        try:
            with zipfile.ZipFile(apk_path) as zf:
                for n in zf.namelist():
                    if n.endswith(".so"):
                        try:
                            blob = zf.read(n)[: 8 * 1024 * 1024]
                        except (OSError, RuntimeError, KeyError):
                            continue
                        for t in _HW_KEYSTORE_TOKENS:
                            if t.encode() in blob:
                                signals.append(f"native-hw:{t}")
                                break
                        for t in (b"SSL_CTX_use_certificate", b"SSL_CTX_set_cert_verify_callback",
                                   b"SSL_set_tlsext_host_name", b"SSL_use_PrivateKey"):
                            if t in blob:
                                signals.append(f"native-tls:{t.decode()}")
                                break
        except (zipfile.BadZipFile, OSError):
            pass

    hw_evidence = any(s.startswith("source-hw:") or s.startswith("native-hw:") for s in signals)
    cert_chain = any(
        s.startswith("source:") or s.startswith("source-cert:") or s.startswith("manifest:")
        for s in signals
    )

    if cert_chain and hw_evidence:
        tier = "mtls_hard"
        recommended = "runtime_hook_only (no MITM without TEE bypass)"
    elif cert_chain:
        tier = "mtls_soft"
        recommended = "repinning_only (software keystore — root can extract)"
    elif signals:
        tier = "server_tls"
        recommended = "mitm_with_ca (and cert-pin-) bypass needed if pinning observed"
    else:
        tier = "none"
        recommended = "mitm_with_ca"

    status = "identified" if tier in ("mtls_soft", "mtls_hard") else (
        "mtls_not_detected" if tier == "none" else "partial"
    )
    return MtlsResult(
        status=status,
        tier=tier,
        signals=signals,
        hardware_keystore_evidence=hw_evidence,
        client_cert_chain_detected=cert_chain,
        recommended_testing=recommended,
        note=f"tier={tier}; cert-chain={cert_chain}; hw-keystore={hw_evidence}; signals={len(signals)}",
    )
