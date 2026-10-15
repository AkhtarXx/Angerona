"""Courtroom-grade evidence bundle per finding — operator-signed (Ed25519).

A bank-grade M&A audit must be defensible in litigation.  That requires:
  * any finding can be **replay-verified** without re-fetching the APK
  * the tool's verdict is bound to the **exact APK bytes, module version,
    rule-set version, and runtime trace** that produced it
  * every bundle is **signed by an operator key** so opposing counsel cannot
    claim self-attestation

Signing model:
  * **Emission**: if ``ANGERONA_SIGNING_KEY_PATH`` is set and the key exists,
    we derive the Ed25519 public key and sign the canonical bundle payload
    (sha256 of the canonical JSON).  Signature + key id are embedded.
  * **Verification**: anyone with the matching public key can verify against
    the canonical payload — no private key ever leaves the operator's control.
  * **Degradation**: if no signing key is available, the bundle is still
    emitted but `trust=untrusted_child` and `signature=""` — clearly
    marked as non-courtroom.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from .finding import Finding
from .evidence_signing import load_ed25519_private as _load_ed25519_private
from .evidence_signing import sign_payload as _sign_payload

TRUST_TAG = "untrusted_child"
SIGNED_TRUST = "operator_signed"


@dataclass(frozen=True)
class RuleTrace:
    rule_id: str
    rule_version: str
    severity: str
    triggered_on: str       # short evidence string (line + file)


@dataclass(frozen=True)
class ReplayBundle:
    apk_sha256: str
    module_name: str
    module_version: str
    rule_traces: tuple[RuleTrace, ...]
    apk_size: int
    emitted_at_utc: str     # ISO 8601
    finding: Finding
    signature: str = ""       # base64 (deterministic Ed25519 signature)
    signature_key_id: str = ""
    trust: str = TRUST_TAG

    def as_dict(self) -> dict:
        out = self._base_dict()
        out["signature"] = self.signature
        out["signature_key_id"] = self.signature_key_id
        out["replay_instructions_hash"] = hashlib.sha256(self.canonical_payload()).hexdigest()
        return out

    def _base_dict(self) -> dict:
        """Normal field dict, EXCLUDING signature/key_id/replay_instructions_hash."""
        return {
            "apk_sha256": self.apk_sha256,
            "module_name": self.module_name,
            "module_version": self.module_version,
            "apk_size": self.apk_size,
            "emitted_at_utc": self.emitted_at_utc,
            "rule_traces": [
                {"rule_id": r.rule_id, "rule_version": r.rule_version,
                 "severity": r.severity, "triggered_on": r.triggered_on}
                for r in self.rule_traces
            ],
            "finding": self.finding.as_dict(),
            "trust": self.trust,
        }

    def canonical_payload(self) -> bytes:
        """Bytes that get signed (deterministic order, no volatile fields)."""
        return json.dumps(self._base_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    def replay_hash(self) -> str:
        """Deterministic fingerprint — identical for identical inputs."""
        return hashlib.sha256(self.canonical_payload()).hexdigest()

    # ------------------------------------------------------------- Ed25519

def _file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def build_replay_bundle(
    *,
    apk_path: str | Path,
    finding: Finding,
    module_version: str = "0.0.0",
    rule_traces: tuple[RuleTrace, ...] = (),
    emitted_at_utc: str = "",
    apk_bytes: bytes | None = None,
    signed: bool = True,
    apk_sha256: str = "",
    apk_size: int = -1,
) -> ReplayBundle:
    """Produce a courtroom-grade replay bundle for one finding.

    When ``signed=True`` and a signing key is configured, the bundle gets an
    Ed25519 signature; trust level upgrades to ``operator_signed``.

    APK identity (hash + size) is resolved with the cheapest available source:
      1. ``apk_sha256``/``apk_size`` passed by the caller (precomputed once for a
         whole batch — avoids re-hashing a large APK per finding; this is the only
         path that does not touch the file at all).
      2. ``apk_bytes`` (already in memory) → ``hashlib.sha256``.
      3. Fall back to streaming ``_file_sha256(path)`` for single-call callers.

    ``apk_sha256`` is a field of the signed canonical payload, so caller-supplied
    and file-computed values are interchangeable with no integrity loss.
    """
    path = Path(apk_path)
    if apk_sha256 and apk_size >= 0:
        apk_hash = apk_sha256
    elif apk_bytes is not None:
        apk_hash = hashlib.sha256(apk_bytes).hexdigest()
        apk_size = len(apk_bytes)
    elif path.is_file():
        apk_hash = _file_sha256(path)
        apk_size = path.stat().st_size
    else:
        apk_hash = ""
        apk_size = 0

    candidate = ReplayBundle(
        apk_sha256=apk_hash,
        module_name=finding.module,
        module_version=module_version,
        rule_traces=rule_traces,
        apk_size=apk_size,
        emitted_at_utc=emitted_at_utc,
        finding=finding,
    )

    if signed:
        # Court-repudiation guard: timestamp is REQUIRED for any signed bundle.
        # （ELITE-2 N-2 — unsigned/empty timestamp lets two byte-identical findings
        # collide on replay_hash, trivially repudiating courtroom use.）
        if not emitted_at_utc:
            return candidate

        # Build the final signed-bundle FIRST so its trust field is set
        # BEFORE canonical_payload() is called (the payload includes trust).
        candidate_with_trust = ReplayBundle(
            apk_sha256=candidate.apk_sha256,
            module_name=candidate.module_name,
            module_version=candidate.module_version,
            rule_traces=candidate.rule_traces,
            apk_size=candidate.apk_size,
            emitted_at_utc=candidate.emitted_at_utc,
            finding=candidate.finding,
            trust=SIGNED_TRUST,
        )
        sig, kid = _sign_payload(candidate_with_trust.canonical_payload())
        if sig:
            return ReplayBundle(
                apk_sha256=candidate_with_trust.apk_sha256,
                module_name=candidate_with_trust.module_name,
                module_version=candidate_with_trust.module_version,
                rule_traces=candidate_with_trust.rule_traces,
                apk_size=candidate_with_trust.apk_size,
                emitted_at_utc=candidate_with_trust.emitted_at_utc,
                finding=candidate_with_trust.finding,
                signature=sig,
                signature_key_id=kid,
                trust=SIGNED_TRUST,
            )

    return candidate


def verify_bundle_signature(bundle: ReplayBundle, *, pubkey_hex: str) -> bool:
    """Verify a bundle's signature against an operator public key.

    ``pubkey_hex`` — hex-encoded 32-byte Ed25519 public key.
    Returns True only when signature is present, parseable, and valid.
    """
    if not bundle.signature or not pubkey_hex:
        return False
    try:
        from nacl.signing import VerifyKey  # type: ignore
    except ImportError:
        return False
    try:
        vk = VerifyKey(bytes.fromhex(pubkey_hex))
        sig_bytes = bytes.fromhex(bundle.signature)
        # Rebuild canonical payload from the bundle itself — Dict-form strips
        # the derived fields the way canonical_payload does.
        vk.verify(bundle.canonical_payload(), sig_bytes)
        return True
    except Exception:  # noqa: BLE001
        return False


def bundle_report_json(bundles: list[ReplayBundle]) -> str:
    """Serialize bundles into a pretty, court-submissable JSON report."""
    out = {
        "report_format": "angerona.replay.v1",
        "bundle_count": len(bundles),
        "signed": any(b.trust == SIGNED_TRUST for b in bundles),
        "bundles": [b.as_dict() for b in bundles],
    }
    return json.dumps(out, indent=2, sort_keys=True)


def verify_replay_hash(bundle_dict: dict) -> bool:
    """Check that a previously-emitted bundle's replay hash is still valid."""
    expected = bundle_dict.get("replay_instructions_hash")
    if not expected:
        return False
    # Rebuild exactly the same canonical payload as build did, ignoring
    # signature/signature_key_id/replay_instructions_hash from the dict.
    # Trust field is part of canonical payload when present in input dict.
    cleaned = {
        k: v for k, v in bundle_dict.items()
        if k not in ("replay_instructions_hash", "signature", "signature_key_id")
    }
    # strip only top-level trust mismatch — canonical payload has trust included
    actual = hashlib.sha256(
        json.dumps(cleaned, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return actual == expected
