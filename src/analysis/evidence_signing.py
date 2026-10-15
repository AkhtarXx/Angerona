"""Canonical Ed25519 signing shared by durable audit evidence artifacts."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any


UNTRUSTED = "untrusted_child"
OPERATOR_SIGNED = "operator_signed"
SIGNATURE_ENVELOPE_FIELDS = frozenset({
    "payload_sha256", "signature", "signature_key_id",
})
GENERATED_DOCUMENT_FIELDS = SIGNATURE_ENVELOPE_FIELDS | {"trust"}
DOCUMENT_IDENTITY_FIELDS = {
    "angerona/audit-ownership-policy/v1": "policy_id",
    "angerona/clean-apk-routing-plan/v1": "plan_id",
    "angerona/application-surface-derived-queue/v1": "receipt_sha256",
    "angerona/derived-semantic-queue/v2": "receipt_sha256",
    "angerona/semantic-checkpoint-set/v1": "manifest_sha256",
    "angerona/class-evidence-resolution/v1": "manifest_sha256",
    "angerona/class-consolidation-manifest/v1": "manifest_sha256",
    "angerona/reverse-knowledge-pack/v1": "pack_id",
    "angerona/reverse-knowledge-retrieval/v1": "retrieval_id",
}


def canonical_payload(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def signed_document_body(document: dict[str, Any]) -> dict[str, Any]:
    """Return the exact body covered by an evidence signature."""
    if not isinstance(document, dict):
        raise TypeError("signed document must be an object")
    return {
        key: value for key, value in document.items()
        if key not in SIGNATURE_ENVELOPE_FIELDS
    }


def semantic_document_body(
    document: dict[str, Any], *, identity_field: str,
) -> dict[str, Any]:
    """Return stable semantic fields for a pre/post-signing document ID.

    Trust is generated and signature-bound by ``sign_document``. It is excluded
    from the semantic ID so the ID computed before signing remains identical
    after signing, while ``verify_document`` still authenticates its exact value.
    """
    body = signed_document_body(document)
    trust = body.get("trust")
    if trust is not None and trust not in {UNTRUSTED, OPERATOR_SIGNED}:
        raise ValueError("document contains an unknown trust semantic")
    return {
        key: value for key, value in body.items()
        if key not in {"trust", identity_field}
    }


def document_identity_sha256(
    document: dict[str, Any], *, identity_field: str,
) -> str:
    return hashlib.sha256(canonical_payload(
        semantic_document_body(document, identity_field=identity_field)
    )).hexdigest()


def identity_field_for_schema(document_or_schema: dict[str, Any] | str) -> str:
    schema = (
        str(document_or_schema.get("schema") or "")
        if isinstance(document_or_schema, dict)
        else str(document_or_schema or "")
    )
    try:
        return DOCUMENT_IDENTITY_FIELDS[schema]
    except KeyError as exc:
        raise ValueError(f"schema has no registered document identity: {schema!r}") from exc


def document_identity_sha256_for_schema(document: dict[str, Any]) -> str:
    identity_field = identity_field_for_schema(document)
    return document_identity_sha256(document, identity_field=identity_field)


def with_document_identity(document: dict[str, Any]) -> dict[str, Any]:
    identity_field = identity_field_for_schema(document)
    identity = document_identity_sha256(
        document, identity_field=identity_field,
    )
    existing = document.get(identity_field)
    if existing is not None and existing != identity:
        raise ValueError(
            f"{document.get('schema')!r} contains a conflicting {identity_field}"
        )
    return {**document, identity_field: identity}


def verify_document_identity(document: dict[str, Any]) -> bool:
    identity_field = identity_field_for_schema(document)
    return document.get(identity_field) == document_identity_sha256(
        document, identity_field=identity_field,
    )


def load_ed25519_private() -> tuple[object | None, str]:
    path = os.environ.get("ANGERONA_SIGNING_KEY_PATH")
    if not path or not Path(path).is_file():
        return None, ""
    try:
        from nacl.signing import SigningKey  # type: ignore

        raw = Path(path).read_bytes()[:64]
        key = SigningKey(raw[:32])
        key_id = hashlib.sha256(bytes(key.verify_key)).hexdigest()[:16]
        return key, key_id
    except Exception:  # noqa: BLE001
        return None, ""


def sign_payload(payload: bytes) -> tuple[str, str]:
    key, key_id = load_ed25519_private()
    if key is None:
        return "", ""
    return key.sign(payload).signature.hex(), key_id


def load_ed25519_verify() -> tuple[object | None, str]:
    path = os.environ.get("ANGERONA_VERIFY_KEY_PATH")
    if path and Path(path).is_file():
        try:
            from nacl.signing import VerifyKey  # type: ignore

            raw = Path(path).read_bytes()
            if len(raw) != 32:
                try:
                    encoded = raw.decode("ascii").strip()
                except UnicodeDecodeError:
                    encoded = ""
                if len(encoded) != 64 or any(character not in "0123456789abcdefABCDEF" for character in encoded):
                    raise ValueError("Ed25519 verify key must be 32 raw bytes or 64 hexadecimal characters")
                raw = bytes.fromhex(encoded)
            key = VerifyKey(raw[:32])
            key_id = hashlib.sha256(bytes(key)).hexdigest()[:16]
            return key, key_id
        except Exception:  # noqa: BLE001
            return None, ""
    private, key_id = load_ed25519_private()
    return (private.verify_key, key_id) if private is not None else (None, "")


def load_ed25519_verify_key(key_id: str) -> object | None:
    """Resolve one explicitly pinned verify key without implicit trust discovery."""
    candidates = []
    primary = os.environ.get("ANGERONA_VERIFY_KEY_PATH")
    if primary:
        candidates.append(primary)
    candidates.extend(
        value for value in os.environ.get("ANGERONA_VERIFY_KEY_PATHS", "").split(os.pathsep)
        if value
    )
    seen_paths: set[str] = set()
    seen_ids: dict[str, object] = {}
    try:
        from nacl.signing import VerifyKey  # type: ignore

        for raw_path in candidates:
            supplied = Path(raw_path).expanduser().absolute()
            if str(supplied) in seen_paths:
                continue
            seen_paths.add(str(supplied))
            metadata = supplied.lstat()
            if supplied.is_symlink() or not supplied.is_file() or metadata.st_size > 4096:
                return None
            raw = supplied.read_bytes()
            if len(raw) != 32:
                encoded = raw.decode("ascii").strip()
                if len(encoded) != 64 or any(c not in "0123456789abcdefABCDEF" for c in encoded):
                    return None
                raw = bytes.fromhex(encoded)
            key = VerifyKey(raw)
            candidate_id = hashlib.sha256(bytes(key)).hexdigest()[:16]
            if candidate_id in seen_ids and bytes(seen_ids[candidate_id]) != bytes(key):
                return None
            seen_ids[candidate_id] = key
    except Exception:  # noqa: BLE001
        return None
    if key_id in seen_ids:
        return seen_ids[key_id]
    private, private_id = load_ed25519_private()
    if private is not None and private_id == key_id:
        return private.verify_key
    return None


def sign_document(body: dict[str, Any]) -> dict[str, Any]:
    key, key_id = load_ed25519_private()
    trust = OPERATOR_SIGNED if key is not None else UNTRUSTED
    signed_body = {**body, "trust": trust}
    payload = canonical_payload(signed_body)
    signature = key.sign(payload).signature.hex() if key is not None else ""
    return {
        **signed_body,
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature": signature,
        "signature_key_id": key_id,
    }


def verify_document(document: dict[str, Any], *, require_signature: bool = False) -> bool:
    derived = signed_document_body(document)
    payload = canonical_payload(derived)
    if document.get("payload_sha256") != hashlib.sha256(payload).hexdigest():
        return False
    signature = str(document.get("signature") or "")
    if not signature:
        return not require_signature and document.get("trust") == UNTRUSTED
    key_id = str(document.get("signature_key_id") or "")
    key = load_ed25519_verify_key(key_id)
    if key is None:
        return False
    try:
        key.verify(payload, bytes.fromhex(signature))
        return document.get("trust") == OPERATOR_SIGNED
    except Exception:  # noqa: BLE001
        return False
