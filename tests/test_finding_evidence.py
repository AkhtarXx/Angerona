from __future__ import annotations

import hashlib
import os
import zipfile
from pathlib import Path

from src.analysis.finding import CONFIRMED, LIKELY, Finding
from src.analysis.finding_evidence import (
    ReplayBundle,
    RuleTrace,
    build_replay_bundle,
    bundle_report_json,
    verify_bundle_signature,
    verify_replay_hash,
)


def _apk(path, payload=b"\x00" * 100):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + payload)
        zf.writestr("classes.dex", b"dex\n035\x00" + payload)
    return path


def test_bundle_unsigned_when_no_key(monkeypatch, tmp_path):
    monkeypatch.delenv("ANGERONA_SIGNING_KEY_PATH", raising=False)
    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f)
    assert b.trust == "untrusted_child"
    assert b.signature == ""


def test_bundle_signed_when_key_present(monkeypatch, tmp_path):
    monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(tmp_path / "key"))
    from nacl.signing import SigningKey
    key = SigningKey.generate()
    (tmp_path / "key").write_bytes(key.encode())

    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f, signed=True, emitted_at_utc="2026-08-09T00:00:00Z")
    assert b.trust == "operator_signed"
    assert b.signature != ""
    assert b.signature_key_id != ""
    assert len(b.signature) == 128  # Ed25519 sig hex = 64 bytes = 128 hex chars


def test_bundle_signature_verification(monkeypatch, tmp_path):
    monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(tmp_path / "key"))
    from nacl.signing import SigningKey
    key = SigningKey.generate()
    (tmp_path / "key").write_bytes(key.encode())

    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f, signed=True, emitted_at_utc="2026-08-09T00:00:00Z")
    pubkey_hex = key.verify_key.encode().hex()
    assert verify_bundle_signature(b, pubkey_hex=pubkey_hex) is True


def test_bundle_signature_tampered_fails_verification(monkeypatch, tmp_path):
    monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(tmp_path / "key"))
    from nacl.signing import SigningKey
    key = SigningKey.generate()
    (tmp_path / "key").write_bytes(key.encode())

    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f, signed=True, emitted_at_utc="2026-08-09T00:00:00Z")
    # Corrupt the first byte of the signature — guaranteed to differ from the
    # original. (Overwriting the TRAILING byte with "00" is a no-op whenever
    # the signature already ends in 0x00, making the test flaky ~1/256 runs.)
    first_byte = b.signature[:2]
    bad_sig = ("00" if first_byte != "00" else "01") + b.signature[2:]
    assert bad_sig != b.signature
    tampered = ReplayBundle(
        apk_sha256=b.apk_sha256, module_name=b.module_name,
        module_version=b.module_version, rule_traces=b.rule_traces,
        apk_size=b.apk_size, emitted_at_utc=b.emitted_at_utc,
        finding=b.finding, signature=bad_sig, signature_key_id=b.signature_key_id,
        trust=b.trust,
    )
    assert verify_bundle_signature(tampered, pubkey_hex=key.verify_key.encode().hex()) is False


def test_replay_hash_changes_on_different_apk(tmp_path):
    apk1 = _apk(tmp_path / "a.apk", b"payload_A" * 20)
    apk2 = _apk(tmp_path / "b.apk", b"payload_B" * 20)
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b1 = build_replay_bundle(apk_path=apk1, finding=f)
    b2 = build_replay_bundle(apk_path=apk2, finding=f)
    assert b1.apk_sha256 != b2.apk_sha256
    assert b1.replay_hash() != b2.replay_hash()


def test_caller_supplied_apk_hash_is_used_verbatim(tmp_path):
    """Caller-precomputed apk_sha256 must flow into the bundle untouched, so a
    batch caller can hash the APK once instead of per-finding (the fix for the
    O(N×|APK|) replay-bundle stall)."""
    apk = _apk(tmp_path / "a.apk", b"payload_A" * 20)
    expected = hashlib.sha256(apk.read_bytes()).hexdigest()
    expected_size = apk.stat().st_size
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(
        apk_path=apk, finding=f, apk_sha256=expected, apk_size=expected_size,
    )
    assert b.apk_sha256 == expected
    assert b.apk_size == expected_size


def test_caller_supplied_apk_hash_matches_file_computed(tmp_path):
    """The caller-supplied hash path and the file-hash path must produce
    identical replay bundles (apk_sha256 is a canonical-payload field)."""
    apk = _apk(tmp_path / "a.apk", b"payload_A" * 20)
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b_file = build_replay_bundle(apk_path=apk, finding=f)
    b_passed = build_replay_bundle(
        apk_path=apk, finding=f,
        apk_sha256=b_file.apk_sha256, apk_size=b_file.apk_size,
    )
    assert b_file.replay_hash() == b_passed.replay_hash()


def test_report_json_schema(tmp_path):
    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f)
    txt = bundle_report_json([b])
    assert '"report_format": "angerona.replay.v1"' in txt
    assert '"bundle_count": 1' in txt
    assert '"signed": false' in txt


def test_report_json_with_signed_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("ANGERONA_SIGNING_KEY_PATH", str(tmp_path / "key"))
    from nacl.signing import SigningKey
    key = SigningKey.generate()
    (tmp_path / "key").write_bytes(key.encode())

    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f, signed=True, emitted_at_utc="2026-08-09T00:00:00Z")
    txt = bundle_report_json([b])
    assert '"signed": true' in txt


def test_rule_trace_preserved(tmp_path):
    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    traces = (RuleTrace(rule_id="R-1", rule_version="1.0",
                        severity="high", triggered_on="line 5"),)
    b = build_replay_bundle(apk_path=apk, finding=f, rule_traces=traces)
    assert len(b.rule_traces) == 1
    assert b.rule_traces[0].rule_id == "R-1"


def test_replay_hash_tamper_detection(tmp_path):
    apk = _apk(tmp_path / "a.apk")
    f = Finding(module="m", kind="k", severity="medium", verdict=LIKELY, detail="d")
    b = build_replay_bundle(apk_path=apk, finding=f)
    d = b.as_dict()
    assert verify_replay_hash(d) is True
    d["finding"]["detail"] = "tampered"
    assert verify_replay_hash(d) is False
