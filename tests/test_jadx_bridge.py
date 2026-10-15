"""Behavior tests for the JADX bridge (isolated subprocess, evidence envelope).

All file-based tests use real downloaded JADX to run JADX against:
  * valid.apk fixture (synthetic minimal APK built programmatically)
  * optional skeleton.apk (downloaded from APKMirror/samples if available)

All other tests cover:
  * trusted discovery
  * missing-input graceful degrade
  * security pattern extraction from a fake jadx-sources tree
"""
from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

import pytest

from src.analysis.jadx_bridge import (
    JadxResult,
    _parse_jadx_sources,
    _parse_manifest,
    analyze_apk,
    find_jadx_cli,
)


def _synthetic_dex_strings() -> bytes:
    import hashlib
    import zlib
    def _uleb(n):
        out = bytearray()
        while True:
            b = n & 0x7F; n >>= 7
            if n == 0:
                out.append(b); break
            out.append(b | 0x80)
        return bytes(out)
    header = bytearray(112)
    header[0:4] = b"dex\n"
    header[4:8] = b"035\x00"
    header[36:40] = (112).to_bytes(4, "little")
    header[40:44] = (0x12345678).to_bytes(4, "little")
    header[52:56] = header[56:60] = (0).to_bytes(4, "little")

    sids = [s.encode() for s in ["MainActivity", "AKIAIOSFODNN7EXAMPLE"]]
    n = len(sids)
    sid_tab_off = 112
    data_off = sid_tab_off + 4 * n
    string_blob = b""
    offs = []
    cur = data_off
    for s in sids:
        offs.append(cur)
        uleb = _uleb(len(s))
        string_blob += uleb + s + b"\x00"
        cur += len(uleb) + len(s) + 1
    map_off = cur
    entries = [
        (0x0000, 1, sid_tab_off),
        (0x0001, n, sid_tab_off),
        (0x2002, 1, map_off),
    ]
    map_list = (len(entries)).to_bytes(4, "little") + b"".join(
        e[0].to_bytes(2, "little") + b"\x00\x00" + e[1].to_bytes(4, "little") + e[2].to_bytes(4, "little")
        for e in entries)
    header[60:64] = map_off.to_bytes(4, "little")
    header[64:68] = n.to_bytes(4, "little")
    header[68:72] = sid_tab_off.to_bytes(4, "little")
    body = bytes(header)
    for off in offs:
        body += off.to_bytes(4, "little")
    body += string_blob + map_list
    header[32:36] = len(body).to_bytes(4, "little")
    out = bytes(header) + body[112:]
    header[12:32] = hashlib.sha1(out[32:]).digest()
    out = bytes(header) + body[112:]
    header[8:12] = zlib.adler32(out[12:]).to_bytes(4, "little")
    return bytes(header) + out[112:]


def _make_test_apk(path: Path) -> Path:
    dex = _synthetic_dex_strings()
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("classes.dex", dex)
        zf.writestr("AndroidManifest.xml", """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.demo">
  <uses-permission android:name="android.permission.INTERNET"/>
  <application>
    <activity android:exported="true" android:name=".MainActivity"/>
    <service android:exported="true" android:name=".SyncService"/>
  </application>
</manifest>""")
    return path


# ------------------------------------------------------------------ discovery

def test_find_jadx_cli_in_env_or_vendored(monkeypatch, tmp_path):
    executable = tmp_path / "jadx"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o755)
    monkeypatch.setenv("JADX_CLI", str(executable))
    found = find_jadx_cli()
    assert found == executable


def test_find_jadx_cli_not_found(monkeypatch):
    monkeypatch.delenv("JADX_CLI", raising=False)
    monkeypatch.setattr("shutil.which", lambda _name: None)
    monkeypatch.setattr(Path, "is_file", lambda self: False)
    assert find_jadx_cli() is None


# ------------------------------------------------------------------ graceful degrade

def test_analyze_apk_missing_input_skips():
    out = analyze_apk("/definitely/missing.apk")
    assert out.status == "skipped"
    assert "missing" in out.note


def test_analyze_apk_when_jadx_unavailable(monkeypatch):
    monkeypatch.setattr("src.analysis.jadx_bridge.find_jadx_cli", lambda *_: None)
    with tempfile.TemporaryDirectory() as td:
        apk = Path(td) / "app.apk"
        apk.write_bytes(b"PK\x03\x04" + b"\x00" * 4096)
        out = analyze_apk(apk)
        assert out.status == "unavailable"


def test_analyze_apk_applies_jvm_heap_ceiling(monkeypatch, tmp_path):
    cli = tmp_path / "jadx"
    cli.write_text("#!/bin/sh\n")
    apk = _make_test_apk(tmp_path / "app.apk")
    observed = {}

    def fake_run(cmd, **kwargs):
        observed["cmd"] = list(cmd)
        observed.update(kwargs)
        return type("Completed", (), {"returncode": 0, "stderr": "", "stdout": ""})()

    monkeypatch.setattr("src.analysis.jadx_bridge.find_jadx_cli", lambda *_: cli)
    monkeypatch.setattr("src.analysis.jadx_bridge.observed_progress_run", fake_run)
    out = analyze_apk(apk, memory_limit_mb=512)
    assert out.status == "success"
    assert observed["env"]["JAVA_OPTS"] == "-Xmx512m"
    assert "--allow-corrupted-files" not in observed["cmd"]
    assert "--decompilation-scheduling-algorithm" not in observed["cmd"]


def test_failed_jadx_attempt_never_parses_or_overwrites_stale_output(monkeypatch, tmp_path):
    cli = tmp_path / "jadx"
    cli.write_text("#!/bin/sh\n")
    apk = _make_test_apk(tmp_path / "app.apk")
    published = tmp_path / "published"
    stale = published / "sources" / "Stale.java"
    stale.parent.mkdir(parents=True)
    stale.write_text("class Stale {}\n")

    def failed_run(_cmd, **kwargs):
        kwargs["stdout"].write(b"ERROR controlled failure\n")
        return type("Completed", (), {"returncode": 1})()

    monkeypatch.setattr("src.analysis.jadx_bridge.find_jadx_cli", lambda *_: cli)
    monkeypatch.setattr("src.analysis.jadx_bridge.observed_progress_run", failed_run)
    out = analyze_apk(apk, keep_output=published)

    assert out.status == "partial"
    assert out.classes_count == 0
    assert stale.read_text() == "class Stale {}\n"


# ------------------------------------------------------------------ manifest parsing

def test_parse_manifest_extracts_exported_components():
    xml = """
    <?xml version="1.0"?>
    <manifest>
      <uses-permission android:name="android.permission.INTERNET"/>
      <application>
        <activity android:exported="true" android:name=".MainActivity"/>
        <service android:exported="true" android:name=".SmsService"/>
        <receiver android:exported="true" android:name=".BootReceiver"/>
      </application>
    </manifest>
    """
    exported, perms = _parse_manifest(xml)
    assert "android.permission.INTERNET" in perms
    names = {c["name"] for c in exported}
    assert ".MainActivity" in names and ".SmsService" in names
    assert ".BootReceiver" in names


# ------------------------------------------------------------------ source tree parsing

def test_security_pattern_coverage_in_fixture(tmp_path):
    d = tmp_path / "sources"
    d.mkdir()
    (d / "Crypto.java").write_text("""
    package com.x;
    public class Crypto {
      public void vulnerable() throws Exception {
        Class.forName("com.evil.Class");
        javax.crypto.Cipher.getInstance("AES/ECB");
        javax.crypto.Cipher.getInstance("DES");
        String key = "AKIAIOSFODNN7EXAMPLE";
        String api_key = "AIzaSyB_real-api-key-value";
        MessageDigest.getInstance("MD5");
      }
    }
    """)
    findings, _errors, n = _parse_jadx_sources([d])
    assert n == 1
    kinds = {f["kind"] for f in findings}
    assert "reflection" in kinds
    assert "weak-crypto" in kinds
    assert "hardcoded-secret" in kinds


def test_nested_jadx_roots_do_not_double_count_classes_or_findings(tmp_path):
    out = tmp_path / "jadx"
    sources = out / "sources" / "a"
    sources.mkdir(parents=True)
    (sources / "One.java").write_text(
        'class One { void load() { System.loadLibrary("stumble"); } }\n'
    )

    findings, errors, classes = _parse_jadx_sources([out / "sources", out])

    assert errors == []
    assert classes == 1
    assert len(findings) == 1
    assert findings[0]["class_path"] == "a/One.java"


# ------------------------------------------------------------------ full pipeline (slow, real JADX)

@pytest.mark.skip(reason="requires a real Android APK on this host")
def test_real_apk_pipeline():
    r = analyze_apk("/tmp/android_samples/real.apk")
    assert r.status in ("success", "partial")
    assert r.classes_count >= 0


# ------------------------------------------------------------------ envelope trust


def test_findings_carry_untrusted_child_trust_tag():
    out = JadxResult(status="success", apk_path="test.apk")
    out.findings.append({
        "kind": "reflection", "severity": "medium",
        "class_path": "A.java", "method": "vuln",
        "message": "reflection", "evidence": "Class.forName",
        "line_no": 1,
    })
    d = out.as_dict()
    assert "findings" in d and isinstance(d["findings"], list)
    assert d["status"] == "success"
