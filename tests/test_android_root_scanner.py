"""Behavior tests for the Android root/tamper fingerprint scanner."""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.android_root_scanner import (
    TRUST_TAG,
    scan_apk,
    scan_bytes,
    scan_smali_text,
)


def _dex_with_strings(*strings: bytes) -> bytes:
    body = b"".join(s + b"\x00" for s in strings)
    # pad to a plausible DEX blob
    return b"dex\n035\x00" + b"\x00" * 96 + body + b"\x00" * 512


def test_root_vocab_detected_in_dex_bytes():
    blob = _dex_with_strings(b"/system/xbin/su", b"com.topjohnwu.magisk",
                             b"TracerPid", b"getenforce")
    out = scan_bytes(blob, source="classes.dex")
    assert out.status == "success"
    cats = out.categories
    assert cats.get("su_path", 0) >= 1
    assert cats.get("magisk", 0) >= 1
    assert cats.get("tracerpid", 0) >= 1
    assert cats.get("selinux", 0) >= 1
    assert out.bytes_scanned == len(blob)


def test_clean_blob_is_clean():
    blob = _dex_with_strings(b"hello world", b"just some math constants")
    out = scan_bytes(blob)
    assert out.status == "success"
    assert out.indicators == []
    assert out.categories == {}


def test_empty_input_degrades_gracefully():
    out = scan_bytes(b"")
    assert out.status == "empty"
    assert out.indicators == []


def test_smali_text_scan_line_offsets():
    smali = """
    const-string v0, "/proc/self/status"
    const-string v1, "ro.debuggable"
    invoke-static {v1}, Landroid/os/SystemProperties;->get(Ljava/lang/String;)
    """
    out = scan_smali_text(smali)
    assert out.status == "success"
    assert any(i.metadata.get("token") == "/proc/self/status" for i in out.indicators)
    assert all(i.metadata.get("offset",0) >= 1 for i in out.indicators)


def test_every_finding_carries_untrusted_child_tag():
    blob = _dex_with_strings(b"magisk", b"busybox")
    out = scan_bytes(blob)
    assert out.trust == TRUST_TAG == "untrusted_child"
    for row in out.indicators:
        assert row.trust == "untrusted_child"
        assert row.kind and row.metadata.get("token") and row.evidence


def test_scan_apk_real_zip_and_missing_file(tmp_path):
    apk = write_apk(tmp_path / "app.apk",
                    files={"classes.dex": _dex_with_strings(b"busybox su")})
    out = scan_apk(apk)
    assert out.status == "success"
    assert out.categories.get("busybox", 0) >= 1
    missing = scan_apk(tmp_path / "nope.apk")
    assert missing.status == "skipped"
    bad = tmp_path / "notazip.apk"
    bad.write_bytes(b"this is not a zip at all" * 4)
    errored = scan_apk(bad)
    assert errored.status == "error"
