"""Behavior tests for the native .so secrets hunter."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.native_secrets_hunter import (
    TRUST_TAG,
    scan_apk_native_libs,
    scan_so_bytes,
)


def _so_with(*blobs: bytes) -> bytes:
    # minimal ELF-ish native blob with embedded strings
    return (b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 120
            + b"".join(b + b"\x00" for b in blobs) + b"\x00" * 512)


def test_aws_key_detected_with_redacted_preview():
    so = _so_with(b"key=AKIAIOSFODNN7EXAMPLE region us-east-1")
    hits = scan_so_bytes(so, source="libcore.so")
    kinds = {h.kind for h in hits}
    assert "aws-access-key" in kinds
    for h in hits:
        assert "AKIAIOSFODNN7EXAMPLE" not in h.preview  # redacted
        assert h.preview


def test_crypto_hint_raises_score():
    plain = _so_with(b"AIzaSyB1234567890123456789012345678901234567")
    with_crypto = _so_with(b"AIzaSyB1234567890123456789012345678901234567",
                           b"EVP_EncryptInit", b"AES_set_encrypt_key")
    h_plain = {h.kind: h for h in scan_so_bytes(plain)}
    h_crypto = {h.kind: h for h in scan_so_bytes(with_crypto)}
    assert h_crypto["google-api-key"].crypto_hint is True
    assert h_crypto["google-api-key"].score > h_plain["google-api-key"].score


def test_clean_so_has_no_named_hits():
    so = _so_with(b"malloc", b"memcpy", b"__cxa_finalize")
    hits = [h for h in scan_so_bytes(so) if h.kind != "high-entropy-string"]
    assert hits == []


def test_empty_and_missing_degrade():
    assert scan_so_bytes(b"") == []


def test_scan_real_apk_native_libs_and_trust(tmp_path):
    so = _so_with(b"AKIAIOSFODNN7EXAMPLE", b"EVP_EncryptInit")
    apk = write_apk(tmp_path / "app.apk", files={
        "lib/arm64-v8a/libapp.so": so,
        "assets/skip.bin": b"not a lib",
    })
    out = scan_apk_native_libs(apk)
    assert out.status == "success"
    assert out.members_scanned == 1
    assert out.trust == TRUST_TAG == "untrusted_child"
    assert out.hits
    for h in out.hits:
        assert h["trust"] == "untrusted_child"
        assert h["member"] == "lib/arm64-v8a/libapp.so"
        assert "AKIAIOSFODNN7EXAMPLE" not in h["preview"]


def test_bad_apk_statuses(tmp_path):
    assert scan_apk_native_libs(tmp_path / "m.apk").status == "skipped"
    bad = tmp_path / "b.apk"
    bad.write_bytes(b"zzzz")
    assert scan_apk_native_libs(bad).status == "error"
    no_libs = write_apk(tmp_path / "nl.apk", files={"classes.dex": b"dex\n035\x00"})
    assert scan_apk_native_libs(no_libs).status == "empty"
