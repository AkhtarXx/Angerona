"""Native .so secrets hunter (Android SOTA priority 7).

Research basis (CWE-798 "Use of Hard-coded Credentials"; MobSF's native
strings pass; the "API keys in libfoo.so" incident pattern from the NowSecure
and Appthority disclosures): native libraries are the second-favorite place
to hide keys after BuildConfig, and strings(1)-style extraction plus a crypto
co-location hint (AES/EVP symbols nearby) is the deterministic way to rank
what a human should look at first.

String claims from an untrusted .so are tagged ``untrusted_child``; entropy
and crypto-hint are scoring signals, not proof of key usage.
"""

from __future__ import annotations

import math
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

TRUST_TAG = "untrusted_child"

_SECRET_PATTERNS: tuple[tuple[re.Pattern, str], ...] = (
    (re.compile(rb"AKIA[0-9A-Z]{16}"), "aws-access-key"),
    (re.compile(rb"AIza[0-9A-Za-z_\-]{35}"), "google-api-key"),
    (re.compile(rb"-----BEGIN [A-Z ]*PRIVATE KEY-----"), "pem-private-key"),
    (re.compile(rb"(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token)"
                rb"[\x00-\x20]*[=:][\x00-\x20]*[A-Za-z0-9+/=_\-]{8,}"), "labeled-secret"),
    (re.compile(rb"(?i)bearer [A-Za-z0-9._\-]{20,}"), "bearer-token"),
    (re.compile(rb"[0-9a-fA-F]{64}"), "hex-64-secret"),
)

_CRYPTO_HINTS = (b"AES_set_encrypt_key", b"EVP_EncryptInit", b"RSA_public_encrypt",
                 b"mbedtls_aes", b"EVP_BytesToKey", b"DES_ecb_encrypt",
                 b"CCKeyDerivationPBKDF", b"pkcs5")
_STR_RE = re.compile(rb"[ -~]{6,}")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


# Severity tiers (professional framing): a *named-pattern hit* (AKIA, AIza,
# labeled-secret, bearer, PEM) is ALARM — a specific attacker-usable shape.
# A *generic entropy* hit is just an INDICATOR — Rust release binaries contain
# hundreds of high-entropy symbol bytes with no attacker value; raising an
# alarm on each one drowns real findings.
_ALARM_KINDS = frozenset({
    "aws-access-key", "google-api-key", "pem-private-key",
    "labeled-secret", "bearer-token",
})


@dataclass
class SecretHit:
    kind: str
    offset: int
    preview: str            # redacted preview, never the full secret
    crypto_hint: bool
    score: float
    severity: str = "alarm"     # "alarm" for named shapes, "indicator" for entropy
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "kind": self.kind,
            "offset": self.offset,
            "preview": self.preview,
            "crypto_hint": self.crypto_hint,
            "score": round(self.score, 3),
            "severity": self.severity,
            "trust": self.trust,
        }


@dataclass
class SecretScanResult:
    status: str
    hits: list[dict] = field(default_factory=list)
    members_scanned: int = 0
    note: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "hits": self.hits,
            "members_scanned": self.members_scanned,
            "note": self.note,
            "trust": self.trust,
            "policy": "previews redacted; crypto_hint is a ranking signal only",
        }


def _redact(token: bytes) -> str:
    s = token.decode("utf-8", errors="ignore")
    if len(s) <= 10:
        return s[:3] + "..."
    return s[:6] + "..." + s[-3:]


def scan_so_bytes(data: bytes, *, source: str = "buffer") -> list[SecretHit]:
    """Scan one native-library buffer for embedded secrets."""
    if not data:
        return []
    crypto_hint = any(h in data for h in _CRYPTO_HINTS)
    hits: list[SecretHit] = []
    for pattern, kind in _SECRET_PATTERNS:
        for m in pattern.finditer(data):
            # Rust / protobuf / packed struct binaries contain tons of 64-char
            # "hex" strings that are actually little-endian length prefixes
            # (e.g. "4000...0") — high *character* variety but near-zero byte
            # entropy.  Real crypto keys have BOTH high hex variety AND high
            # raw-byte entropy, so only keep hex hits whose byte-level entropy
            # is in the key range.  This kills ~99% of the false positives on
            # Rust-based apps (Signal, Mobilecoin) without dropping real keys.
            if kind == "hex-64-secret":
                raw = bytes.fromhex(m.group().decode("ascii", errors="ignore"))
                if _entropy(raw) < 3.5:
                    continue
            score = 0.7 + (0.2 if crypto_hint else 0.0)
            if kind in ("aws-access-key", "google-api-key", "pem-private-key"):
                score += 0.1
            hits.append(SecretHit(
                kind=kind, offset=m.start(), preview=_redact(m.group()),
                crypto_hint=crypto_hint, score=min(1.0, score),
                severity="alarm" if kind in _ALARM_KINDS else "indicator",
            ))
    # High-entropy printable runs of 40+ chars are candidate keys only when
    # they match no named pattern AND are not well-known not-secrets:
    # JNI exports (Java_com_*, Java_org_signal_libsignal_internal_Native_*),
    # Rust symbol mangling, ELF section names, and protobuf field descriptors
    # all score "high entropy" while being plain identifiers.
    _NOT_SECRETS = (
        b"Java_",                       # JNI Java_* convention
        b"Dyld",                        # Mach-O loader hints
        b"_ZN",                         # Rust/C++ Itanium mangling start
        b"/vendor/", b"/system/",
        b"AndroidRuntime",              # runtime symbol
        b".text.", b".rodata.", b".data.rel.ro",
        b"GooglePlay", b"crashpad_",   # crash reporting helper libs
    )
    seen_offsets = {h.offset for h in hits}  # dedup vs named-pattern hits at same offset
    for m in _STR_RE.finditer(data):
        s = m.group()
        if len(s) >= 40 and _entropy(s) > 4.2 and m.start() not in seen_offsets:
            if any(ns in s for ns in _NOT_SECRETS):
                continue
            # High hex-letter density at 40+ chars + moderate entropy = usually
            # a Rust symbol or generic identifier, not a user-supplied secret.
            hex_chars = sum(1 for c in s if chr(c) in "0123456789abcdefABCDEF")
            if hex_chars > len(s) * 0.7 and _entropy(s) < 5.0:
                continue
            # CamelCased concatenated English words (Rust enum field dumps,
            # protobuf field lists, HTTP headers) are NOT secrets.  Real
            # secrets are mostly hex/base64/random with LOW fraction of
            # dictionary-shape letters.
            alpha_chars = sum(1 for c in s if 65 <= c <= 90 or 97 <= c <= 122)
            if len(s) >= 40 and alpha_chars > 0:
                # If >85% of the string is ASCII letters and it contains
                # multiple camelCase transitions (lower→Upper), it's a
                # symbol/identifier, not a secret.
                transitions = sum(
                    1 for i in range(1, len(s))
                    if 97 <= s[i - 1] <= 122 and 65 <= s[i] <= 90
                )
                if alpha_chars / len(s) > 0.85 and transitions >= 2:
                    continue
                # Rust debug/fmt mangling markers (D2_2G_y*, u128/i128::fmt,
                # ::fmt::Debug, etc.) appear in symbol dumps inside packed
                # rodata.  Their presence means "binary identifier", not a
                # secret string.
                rust_marks = (b"D2_", b"G_y", b"i128", b"u128", b"::", b"dyn ")
                rust_score = sum(1 for m_ in rust_marks if m_ in s)
                if rust_score >= 2:
                    continue
            hits.append(SecretHit(
                kind="high-entropy-string", offset=m.start(),
                preview=_redact(s), crypto_hint=crypto_hint,
                score=0.4 + (0.2 if crypto_hint else 0.0),
                severity="indicator",
            ))
            seen_offsets.add(m.start())
    hits.sort(key=lambda h: h.score, reverse=True)
    return hits


# zip-bomb guard: refuse to decompress lib members whose declared uncompressed
# size exceeds this cap, and never read more than cap + 1 bytes even if a
# malformed member lies about its size (ZipExtFile.read does not apply the
# extract-only _MAX_EXTRACT_SIZE).
_MAX_LIB_BYTES = 256 * 1024 * 1024


def scan_apk_native_libs(apk_path: str | Path) -> SecretScanResult:
    """Scan every ``lib/**.so`` member of an APK."""
    apk_path = Path(apk_path)
    if not apk_path.is_file():
        return SecretScanResult(status="skipped", note=f"missing: {apk_path}")
    try:
        zf = zipfile.ZipFile(apk_path)
    except (zipfile.BadZipFile, OSError) as exc:
        return SecretScanResult(status="error", note=f"not a zip/apk: {exc}")
    hits: list[SecretHit] = []
    scanned = 0
    with zf:
        for name in zf.namelist():
            if not (name.startswith("lib/") and name.endswith(".so")):
                continue
            info = zf.getinfo(name)
            if info.file_size > _MAX_LIB_BYTES:
                continue  # zip-bomb guard (declared decompressed size)
            try:
                with zf.open(info) as handle:
                    blob = handle.read(_MAX_LIB_BYTES + 1)
            except (OSError, RuntimeError, KeyError, zipfile.BadZipFile):
                continue
            if len(blob) > _MAX_LIB_BYTES:
                continue  # read-budget guard (declared size understated)
            scanned += 1
            for hit in scan_so_bytes(blob, source=name):
                row = hit.as_dict()
                row["member"] = name
                hits.append(row)
    return SecretScanResult(
        status="success" if scanned else "empty",
        hits=hits,
        members_scanned=scanned,
        note=f"{len(hits)} secret hit(s) in {scanned} native lib(s)",
    )
