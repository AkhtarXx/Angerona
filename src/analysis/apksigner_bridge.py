"""APK signing-cert chain extraction + canonical-key registry verification.

Professional RE's absolute first move on any APK: verify the signing cert.
Repackaged/fake apps (modified Signal clones, fake banking trojans, Pegasus-style
implants) ALL share one weakness — they cannot forge the original developer's
signing key.  Everything downstream (manifest permissions, native libs, runtime
behavior) is meaningless if the APK itself is a repack with a different key.

Design:
  * Pure-Python APK v2 signing-block parse for cert extraction where feasible;
    falls back to ``apksigner verify --print-certs`` when the binary exists.
  * Canonical registry is a JSON file mapping known-package names to
    expected SHA-256 cert fingerprints (shipped as data, user-extensible).
  * Trust: ``untrusted_child`` — an attacker repacks the APK *including* the
    registry claim, so registry data must come from local operator, not the APK.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from ..config import Config
from ..subprocess_observability import observed_run

TRUST_TAG = "untrusted_child"


@dataclass
class CertInfo:
    sha256: str        # hex fingerprint (colons stripped, lowercase)
    subject: str = ""
    issuer: str = ""
    serial: str = ""


@dataclass
class ApkSignerResult:
    status: str                    # verified | mismatch | unknown_app | unsigned | tool_unavailable | skipped
    apk_path: str
    package_name: str = ""
    certs: list[CertInfo] = field(default_factory=list)
    scheme_v1: bool = False
    scheme_v2: bool = False
    scheme_v3: bool = False
    matched_canonical: str = ""    # canonical entry name that matched
    note: str = ""
    errors: list[str] = field(default_factory=list)
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "apk_path": self.apk_path,
            "package_name": self.package_name,
            "certs": [vars(c) for c in self.certs],
            "scheme_v1": self.scheme_v1,
            "scheme_v2": self.scheme_v2,
            "scheme_v3": self.scheme_v3,
            "matched_canonical": self.matched_canonical,
            "note": self.note,
            "errors": self.errors,
            "trust": self.trust,
        }


# ------------------------------------------------------- canonical registry

_BUILTIN_REGISTRY: dict[str, list[str]] = {
    # importable override point — real deployments ship YAML/JSON under
    # ``share/angerona/known_certs.json``;  hardcoded subset for tests
    "org.thoughtcrime.securesms": [
        # Signal website-prod 4096-bit signing cert (published)
        "29f34e5f27f211b424bc5bf9d67162c0eafa45da35af35c16416fc446276ba26",
        # older 1024-bit transition cert (also published)
        "45984dc207a5b47d1d4840b703f5bda02df25f02e11d5b37fcfaa19eae70b35a",
    ],
}

_REGISTRY_ENV = "ANGERONA_KNOWN_CERTS_JSON"


def _load_registry() -> dict[str, list[str]]:
    path = os.environ.get(_REGISTRY_ENV)
    if path and Path(path).is_file():
        try:
            data = json.loads(Path(path).read_text())
            if isinstance(data, dict):
                return {k: [c.lower().replace(":", "") for c in v] for k, v in data.items()}
        except (OSError, json.JSONDecodeError):
            pass
    return dict(_BUILTIN_REGISTRY)


# ------------------------------------------------------- cert extraction

def _cert_fingerprint_sha256(cert_bytes: bytes) -> str:
    return hashlib.sha256(cert_bytes).hexdigest()


def find_apk_verifier() -> tuple[str, list[str]] | None:
    """Locate Android's apksigner CLI or the vendored Google apksig library."""
    apksigner = shutil.which("apksigner")
    if apksigner:
        return apksigner, ["verify", "--print-certs", "--verbose"]
    root = Path(__file__).resolve().parents[2]
    java = shutil.which("java")
    jars = sorted((root / "vendor" / "android-tools").glob("apksig-*.jar"))
    source = Path(__file__).with_name("resources") / "ApkSigVerifier.java"
    if java and jars and source.is_file():
        return java, ["--class-path", str(jars[-1]), str(source)]
    return None


def _extract_certs_via_apksigner(apk: Path, timeout: int) -> tuple[list[CertInfo], list[str]]:
    """Use ``apksigner verify --print-certs`` when available (build-tools)."""
    verifier = find_apk_verifier()
    if not verifier:
        return [], []
    binary, args = verifier
    errors: list[str] = []
    try:
        r = observed_run(
            [binary, *args, str(apk)],
            capture_output=True, text=True, timeout=timeout, check=False,
        )
    except (subprocess.TimeoutExpired, OSError) as exc:
        return [], [f"apksigner spawn failed: {exc}"]
    if r.returncode != 0:
        return [], [f"apksigner rc={r.returncode}: {(r.stderr or '')[-200:]}"]
    certs: list[CertInfo] = []
    for line in (r.stdout or "").splitlines():
        line = line.strip()
        if "certificate SHA-256 digest:" in line.lower():
            fp = line.split(":", 1)[-1].strip().lower().replace(":", "")
            if fp and fp not in {c.sha256 for c in certs}:
                certs.append(CertInfo(sha256=fp))
    return certs, errors


def _extract_certs_from_v2_block(apk: Path) -> list[CertInfo]:
    """Best-effort v2 signing-block cert extraction (pure Python).

    Scans for the APK Signing Block in the zip tail; extracts X.509 cert
    DER blobs from the first signer entry.
    """
    try:
        with open(apk, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            read_back = min(size, 1 << 20)  # signing block lives near the end
            fh.seek(size - read_back)
            tail = fh.read(read_back)
    except OSError:
        return []

    marker = b"APK Sig Block 42"
    idx = tail.find(marker)
    if idx < 0:
        return []
    # Block layout: [8B size][pairs ...][8B size][16B magic]
    # pairs: [8B len][4B id][value]
    # We scan AOSP's v2 block ID 0x7109871a and extract first-level
    # length-prefixed cert DER blobs.
    scan = tail[max(0, idx - 4096): idx + 4096]
    certs: list[CertInfo] = []
    i = 0
    while i < len(scan) - 24:
        if scan[i:i+4] == (0x7109871A).to_bytes(4, "little"):
            length = int.from_bytes(scan[i-8:i-4], "little") if i >= 8 else 0
            blob = scan[i+4:i+4+min(length, 4096)]
            # hunt for X.509 DER certs (start 0x30 0x82)
            j = 0
            while j < len(blob) - 8:
                if blob[j] == 0x30 and blob[j+1] == 0x82:
                    der_len = int.from_bytes(blob[j+2:j+4], "big") + 4
                    if 4 < der_len < 4096 and j + der_len <= len(blob):
                        der = blob[j:j+der_len]
                        fp = _cert_fingerprint_sha256(der)
                        if fp not in {c.sha256 for c in certs}:
                            certs.append(CertInfo(sha256=fp))
                        j += der_len
                        continue
                j += 1
            break
        i += 1
    return certs


def _scheme_flags(apk: Path) -> tuple[bool, bool, bool]:
    """Detect v1 (META-INF/*.RSA) and v2/v3 scheme presence."""
    v1 = v2 = v3 = False
    try:
        with zipfile.ZipFile(apk) as zf:
            names = zf.namelist()
            v1 = any(n.startswith("META-INF/") and n.endswith((".RSA", ".DSA", ".EC"))
                     for n in names)
    except (zipfile.BadZipFile, OSError):
        return False, False, False
    # Scheme IDs from AOSP's apksig implementation.  Presence is not the same
    # as verification; apksigner remains the cryptographic authority.
    try:
        with open(apk, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            rb = min(size, 1 << 20)
            fh.seek(size - rb)
            tail = fh.read(rb)
        has_signing_block = b"APK Sig Block 42" in tail
        v2 = has_signing_block and (0x7109871A).to_bytes(4, "little") in tail
        v3 = has_signing_block and any(
            scheme_id.to_bytes(4, "little") in tail
            for scheme_id in (0xF05368C0, 0x1B93AD61)
        )
    except OSError:
        pass
    return v1, v2, v3


def _package_name(apk: Path) -> str:
    """Extract the application id from binary AXML, failing closed on noise."""
    try:
        from pyaxmlparser import APK

        package = str(APK(str(apk)).get_package() or "").strip()
        if re.fullmatch(
            r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+",
            package,
        ):
            return package
    except Exception:
        # Keep a conservative fallback for minimal/static installations. It is
        # evidence discovery only; malformed fragments must never become an app id.
        pass
    try:
        import zipfile as _zf
        with _zf.ZipFile(apk) as z:
            raw = z.read("AndroidManifest.xml")
    except (zipfile.BadZipFile, OSError, KeyError):
        return ""
    # binary AXML: package name is in the string pool — heuristic scan
    out = []
    i = 0
    while i < len(raw) - 1:
        if 0x20 <= raw[i] < 0x7f:
            j = i
            while j < len(raw) and 0x20 <= raw[j] < 0x7f:
                j += 1
            token = raw[i:j].decode("ascii", "replace")
            if "." in token and token.replace(".", "").replace("_", "").isalnum():
                out.append(token)
            i = j
        else:
            i += 1
    package_pattern = re.compile(
        r"[A-Za-z][A-Za-z0-9_]{1,}(?:\.[A-Za-z][A-Za-z0-9_]{1,}){1,}"
    )
    candidates = [token for token in out if package_pattern.fullmatch(token)]
    for token in candidates:
        if token.startswith(("com.", "org.", "net.", "io.")):
            return token
    return ""


# ------------------------------------------------------- driver

def verify_apk_signature(
    apk_path: str | Path,
    *,
    cfg: Config | None = None,
    timeout: int = 60,
    expected_package: str | None = None,
) -> ApkSignerResult:
    """Verify an APK's signing cert against the canonical registry."""
    apk = Path(apk_path)
    if not apk.is_file():
        return ApkSignerResult(status="skipped", apk_path=str(apk),
                               note=f"missing: {apk}")

    package = expected_package or _package_name(apk)
    v1, v2, v3 = _scheme_flags(apk)

    certs, errors = _extract_certs_via_apksigner(apk, timeout)
    # apksigner only emits certs on rc==0, i.e. after cryptographically
    # verifying the signer chain.  The pure-Python v2 block parse below is a
    # byte heuristic with NO signature check, so its fingerprints are evidence
    # only and must never anchor a "verified" origin — an attacker can simply
    # copy the victim's public cert DER next to a forged marker.
    cryptographically_verified = bool(certs)
    if not certs:
        certs = _extract_certs_from_v2_block(apk)
        if not certs:
            errors.append("no certs recovered (no apksigner, no v2 block parse)")

    if not certs:
        status = "tool_unavailable" if (v1 or v2 or v3) else "unsigned"
        return ApkSignerResult(
            status=status, apk_path=str(apk), package_name=package,
            scheme_v1=v1, scheme_v2=v2, scheme_v3=v3,
            note=(
                "cert chain unavailable — cannot verify origin"
                if status == "tool_unavailable"
                else "no APK v1/v2/v3 signing scheme detected"
            ),
            errors=errors,
        )

    registry = _load_registry()
    known = registry.get(package, [])
    have = {c.sha256 for c in certs}
    if known:
        hit = have & set(known)
        if hit:
            if not cryptographically_verified:
                # Heuristic fingerprint matches the registry, but the signer
                # was never cryptographically verified (no apksigner).  A
                # repacker can copy the victim's public cert DER, so this must
                # not be reported as "verified".
                return ApkSignerResult(
                    status="tool_unavailable", apk_path=str(apk), package_name=package,
                    certs=certs, scheme_v1=v1, scheme_v2=v2, scheme_v3=v3,
                    note=(
                        f"cert fingerprint matches canonical registry for {package} "
                        f"but signer NOT cryptographically verified (no apksigner) — "
                        f"origin not anchored"
                    ),
                    errors=errors,
                )
            return ApkSignerResult(
                status="verified", apk_path=str(apk), package_name=package,
                certs=certs, scheme_v1=v1, scheme_v2=v2, scheme_v3=v3,
                matched_canonical=package,
                note=f"signing cert matches canonical registry entry for {package}",
                errors=errors,
            )
        return ApkSignerResult(
            status="mismatch", apk_path=str(apk), package_name=package,
            certs=certs, scheme_v1=v1, scheme_v2=v2, scheme_v3=v3,
            note=(
                f"⚠️ SIGNING MISMATCH: {package} signed with cert(s) "
                f"{sorted(have)}, expected {sorted(set(known))} — "
                f"possible repack/fake-app"
            ),
            errors=errors,
        )

    return ApkSignerResult(
        status="unknown_app", apk_path=str(apk), package_name=package,
        certs=certs, scheme_v1=v1, scheme_v2=v2, scheme_v3=v3,
        note=f"package {package} not in canonical registry — cannot anchor origin",
        errors=errors,
    )
