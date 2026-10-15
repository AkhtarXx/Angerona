"""Behavior tests for the APK assets encrypted-blob detector."""
from __future__ import annotations

import base64
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.assets_blob_detector import (
    TRUST_TAG,
    classify_blob,
    scan_apk_assets,
    shannon_entropy,
)


def test_high_entropy_blob_flagged():
    import random
    rnd = random.Random(1337)
    blob = bytes(rnd.getrandbits(8) for _ in range(8192))
    assert shannon_entropy(blob) > 6.0
    cand = classify_blob("assets/payload.bin", blob)
    assert cand.verdict == "encrypted-suspect"
    assert "size>2KB" in cand.signals
    assert any(s.startswith("entropy>") for s in cand.signals)


def test_base64_blob_flagged():
    inner = os.urandom(2048)
    b64 = base64.b64encode(inner)
    cand = classify_blob("assets/d.txt", b64)
    assert "base64-blob" in cand.signals
    assert cand.verdict == "encrypted-suspect"


def test_single_byte_xor_flagged():
    payload = bytes(b ^ 0x42 for b in (b"This is an XOR-hidden payload. " * 120))
    cand = classify_blob("assets/xor.bin", payload)
    assert any(s.startswith("single-byte-xor") for s in cand.signals)
    assert cand.verdict == "encrypted-suspect"


def test_small_text_asset_is_benign():
    cand = classify_blob("assets/readme.txt", b"hello world, plain text")
    assert cand.verdict == "benign"


def test_malformed_and_missing_apk_degrade(tmp_path):
    out = scan_apk_assets(tmp_path / "missing.apk")
    assert out.status == "skipped"
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"not a zip")
    assert scan_apk_assets(bad).status == "error"


def test_scan_real_apk_and_trust_tags(tmp_path):
    import random
    rnd = random.Random(7)
    blob = bytes(rnd.getrandbits(8) for _ in range(4096))
    apk = write_apk(tmp_path / "app.apk", files={
        "assets/payload.bin": blob,
        "assets/plain.txt": b"just a note",
        "classes.dex": b"dex\n035\x00" + b"\x00" * 128,
    })
    out = scan_apk_assets(apk)
    assert out.status == "success"
    assert out.members_scanned == 2
    assert out.trust == TRUST_TAG == "untrusted_child"
    suspects = [c for c in out.candidates if c.kind == "encrypted-suspect"]
    assert suspects and all(c.trust == "untrusted_child" for c in suspects)
    assert any(c.metadata.get("member") == "assets/payload.bin" for c in suspects)
