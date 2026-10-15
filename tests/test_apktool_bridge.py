from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from src.analysis.apktool_bridge import (
    _parse_manifest_xml,
    decode_apk,
    find_apktool,
    get_decoded_manifest_text,
)

APKTOOL = find_apktool()
apktool_missing = APKTOOL is None
skip_no_apktool = pytest.mark.skipif(apktool_missing, reason="apktool not installed")


def _make_apk(path: Path, manifest: bytes | None = None, dex: bytes | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest if manifest is not None else b"\x03\x00\x08\x00" + b"\x00" * 64)
        zf.writestr("classes.dex", dex if dex is not None else b"dex\n035\x00" + b"\x00" * 100)
    return path


def test_find_apktool_env(monkeypatch, tmp_path):
    fake = tmp_path / "apktool"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("APKTOOL_CLI", str(fake))
    assert find_apktool() == fake
    monkeypatch.delenv("APKTOOL_CLI")


@skip_no_apktool
def test_find_apktool_vendored(monkeypatch):
    monkeypatch.delenv("APKTOOL_CLI", raising=False)
    found = find_apktool()
    assert found is not None
    assert found.is_file()


def test_decode_missing_apk_skipped(tmp_path):
    res = decode_apk(tmp_path / "nope.apk")
    assert res.status == "skipped"
    assert res.trust == "untrusted_child"


def test_decode_unavailable_when_no_binary(tmp_path, monkeypatch):
    monkeypatch.setenv("APKTOOL_CLI", "/nonexistent/apktool")
    monkeypatch.setattr("src.analysis.apktool_bridge.Path", Path)  # no-op, just isolate
    from src.analysis import apktool_bridge as mod
    monkeypatch.setattr(mod, "find_apktool", lambda cfg=None: None)
    res = decode_apk(_make_apk(tmp_path / "a.apk"))
    assert res.status == "unavailable"


def test_parse_manifest_xml_permissions_and_exported():
    xml = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <uses-permission android:name="android.permission.INTERNET"/>
  <uses-permission android:name="android.permission.READ_SMS"/>
  <application>
    <activity android:exported="true" android:name=".MainActivity"/>
    <provider android:exported="true" android:name=".DataProvider"/>
    <activity android:exported="false" android:name=".Hidden"/>
  </application>
</manifest>
"""
    perms, exported = _parse_manifest_xml(xml)
    assert perms == ["android.permission.INTERNET", "android.permission.READ_SMS"]
    names = {c["name"] for c in exported}
    assert names == {".MainActivity", ".DataProvider"}
    assert all(c["type"] in ("activity", "provider") for c in exported)


def test_parse_manifest_xml_handles_garbage():
    perms, exported = _parse_manifest_xml("\x00\x01binary-axml-bytes-not-parseable")
    assert perms == [] and exported == []


@skip_no_apktool
def test_decode_apk_real_run(tmp_path):
    apk = _make_apk(tmp_path / "w.apk")
    res = decode_apk(apk, timeout=120)
    assert res.status in ("success", "partial"), res.errors
    assert res.apktool_version is None or res.apktool_version  # string when got it
    if res.status == "success":
        assert res.manifest_xml, "apktool-success should decode manifest"
        assert "<manifest" in res.manifest_xml


@skip_no_apktool
def test_decode_apk_get_text_helper(tmp_path):
    apk = _make_apk(tmp_path / "w2.apk")
    text = get_decoded_manifest_text(apk, timeout=120)
    assert isinstance(text, str)


@skip_no_apktool
def test_decode_apk_smali_dirs_without_skip_sources(tmp_path):
    apk = _make_apk(tmp_path / "w3.apk")
    res = decode_apk(apk, timeout=120, skip_sources=False)
    assert isinstance(res.smali_dirs, list)
    assert res.smali_files_count >= 0
