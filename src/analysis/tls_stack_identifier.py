"""Identify WHICH TLS stack an Android app actually uses.

A professional never runs TLS rules blind.  Applying Java-side TrustAll checks
to an app whose TLS lives in Rust/rustls (Signal) is a layer error; skipping
Java checks on one that uses OkHttp/Conscrypt is the opposite error.  This
module discriminates the TLS layer(s) in play so downstream rules target the
right surface.

Detection strategy (multi-signal, confidence-tagged):
  * **Conscrypt / Java** — `Conscrypt` classes in DEX/strings, `conscrypt_jni.so`
    presence, `com.android.org.conscrypt` references
  * **BoringSSL** — `BoringSSL`/`bssl` strings in .so, `SSL_CTX_`/`BIO_` symbols
  * **OpenSSL** — `libssl.so`/`libcrypto.so` bundling, `SSL_library_init` etc.
  * **rustls** — `rustls`/`rustls::` symbol substrings in Rust .so binaries
  * **OkHttp pinning** — `CertificatePinner`/`okhttp3` classes
  * **NetCron / Chromium net** — `libcronet.so` presence
  * **Native TLS via JNI** — presence of native TLS-related JNI exports
"""

from __future__ import annotations

import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"


@dataclass
class TlsStackResult:
    status: str                    # identified | partial | unknown
    primary_stack: str             # conscrypt_java | boringssl | openssl | rustls | cronet | unknown
    stacks_detected: list[str]
    evidence: dict[str, list[str]]  # stack -> evidence strings
    okhttp_present: bool
    cert_pinning_likely: bool
    native_tls_libs: list[str]     # .so files with TLS evidence
    recommended_rule_layer: str    # java | native | hybrid | unknown
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "primary_stack": self.primary_stack,
            "stacks_detected": self.stacks_detected,
            "evidence": self.evidence,
            "okhttp_present": self.okhttp_present,
            "cert_pinning_likely": self.cert_pinning_likely,
            "native_tls_libs": self.native_tls_libs,
            "recommended_rule_layer": self.recommended_rule_layer,
            "note": self.note,
            "trust": self.trust,
        }


_TLS_LIB_PATTERNS = (
    ("conscrypt_java", ("conscrypt",)),
    ("boringssl", ("boringssl", "bssl")),
    ("openssl", ("libssl", "libcrypto", "openssl")),
    ("rustls", ("rustls",)),
    ("cronet", ("libcronet", "cronet")),
)

_TLS_SYM_PATTERNS: dict[str, tuple[str, ...]] = {
    "conscrypt_java": ("com.android.org.conscrypt", "Conscrypt", "conscrypt_jni"),
    "boringssl": ("BoringSSL", "bssl::", "BORINGSSL", "_bssl"),
    "openssl": ("SSL_library_init", "OpenSSL_", "libssl.so", "SSL_CTX_new"),
    "rustls": ("rustls::", "_rustls", "rustls_version", "webpki::"),
    "cronet": ("Cronet", "org.chromium.net"),
    "okhttp3": ("okhttp3.", "CertificatePinner", "okhttp3.OkHttpClient"),
}


def _scan_bytes_for(data: bytes, patterns: tuple[str, ...]) -> list[str]:
    hits: list[str] = []
    for p in patterns:
        if p.encode() in data:
            hits.append(p)
    return hits


def identify_tls_stack(apk_path: str | Path) -> TlsStackResult:
    """Identify the TLS stack(s) in use.

    Scans lib names, .so content markers, and DEX-byte references.  Never
    raises: on any structural error returns status="unknown".
    """
    apk = Path(apk_path)
    if not apk.is_file():
        return TlsStackResult(
            status="unknown", primary_stack="unknown", stacks_detected=[],
            evidence={}, okhttp_present=False, cert_pinning_likely=False,
            native_tls_libs=[], recommended_rule_layer="unknown",
            note=f"missing: {apk}",
        )

    evidence: dict[str, list[str]] = {}
    native_tls: set[str] = set()
    okhttp = False
    pinning = False

    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            # 1) .so name evidence
            for n in names:
                if not n.endswith(".so"):
                    continue
                low = n.lower()
                for stack, pats in _TLS_LIB_PATTERNS:
                    for p in pats:
                        if p in low:
                            evidence.setdefault(stack, []).append(f"lib-name:{n}")
                            native_tls.add(n)
            # 2) .so content evidence (limit per-lib scan to 32MB)
            for n in names:
                if not n.endswith(".so"):
                    continue
                info = zf.getinfo(n)
                if info.file_size > 32 * 1024 * 1024:
                    continue
                try:
                    blob = zf.read(n)
                except (OSError, RuntimeError, KeyError):
                    continue
                for stack, pats in _TLS_SYM_PATTERNS.items():
                    for p in pats:
                        if p.encode() in blob:
                            evidence.setdefault(stack, []).append(f"sym:{n}:{p}")
                            native_tls.add(n)
            # 3) DEX content evidence (cheap: scan first 2MB of each)
            for n in names:
                if not n.endswith(".dex"):
                    continue
                try:
                    head = zf.read(n)[: 2 * 1024 * 1024]
                except (OSError, RuntimeError, KeyError):
                    continue
                for stack, pats in _TLS_SYM_PATTERNS.items():
                    for p in pats:
                        if p.encode() in head:
                            evidence.setdefault(stack, []).append(f"dex:{n}:{p}")
                            if stack == "okhttp3":
                                okhttp = True
                                if "CertificatePinner" in p:
                                    pinning = True
    except (zipfile.BadZipFile, OSError) as exc:
        return TlsStackResult(
            status="unknown", primary_stack="unknown", stacks_detected=[],
            evidence={}, okhttp_present=False, cert_pinning_likely=False,
            native_tls_libs=[], recommended_rule_layer="unknown",
            note=f"apk unreadable: {exc}",
        )

    stacks = sorted(evidence)
    # Priority: rustls > boringssl > openssl > cronet > conscrypt_java
    for cand in ("rustls", "boringssl", "openssl", "cronet", "conscrypt_java"):
        if cand in evidence:
            primary = cand
            break
    else:
        primary = "unknown"

    if primary == "rustls":
        layer = "native"
    elif primary in ("boringssl", "openssl"):
        layer = "hybrid"
    elif primary == "conscrypt_java":
        layer = "java"
    else:
        layer = "unknown"

    status = "identified" if primary != "unknown" else ("partial" if stacks else "unknown")
    note = (
        f"primary={primary}; detected={stacks}; okhttp={okhttp}; "
        f"pinning_likely={pinning}; recommend_layer={layer}"
    )
    return TlsStackResult(
        status=status,
        primary_stack=primary,
        stacks_detected=stacks,
        evidence=evidence,
        okhttp_present=okhttp,
        cert_pinning_likely=pinning,
        native_tls_libs=sorted(native_tls),
        recommended_rule_layer=layer,
        note=note,
    )
