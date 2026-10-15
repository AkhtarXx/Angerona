from __future__ import annotations

import json
import zipfile
from pathlib import Path

from src.analysis.upstream_source_differ import (
    diff_against_baseline,
    diff_to_findings,
    index_apk,
    load_baseline,
    save_baseline,
)


def _mk_apk(path, manifest=b"\x03\x00\x08\x00" + b"\x00" * 64, dex_payload=b"dex\n035\x00" + b"\x00" * 100, libs=()):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", dex_payload)
        for name, blob in libs:
            zf.writestr(name, blob)
    return path


def test_index_apk_collects(tmp_path):
    p = _mk_apk(tmp_path / "a.apk", libs=[("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 32)])
    idx = index_apk(p)
    assert idx["dex"]["classes.dex"]
    assert idx["manifest"]["AndroidManifest.xml"]
    assert idx["native"]["lib/arm64-v8a/libfoo.so"]


def test_missing_baseline_error(tmp_path):
    p = _mk_apk(tmp_path / "a.apk")
    r = diff_against_baseline(p, tmp_path / "nope.json")
    assert r.status == "baseline_missing"
    assert r.trust == "untrusted_child"


def test_baseline_roundtrip(tmp_path):
    p = _mk_apk(tmp_path / "a.apk")
    idx = index_apk(p)
    bl_path = tmp_path / "bl.json"
    save_baseline(idx, bl_path, name="com.test", version="1.0")
    bl = load_baseline(bl_path)
    assert bl["name"] == "com.test"
    assert bl["version"] == "1.0"
    assert bl["index"]["dex"]["classes.dex"]


def test_identical_apks_no_diff(tmp_path):
    p = _mk_apk(tmp_path / "a.apk")
    idx = index_apk(p)
    bl_path = tmp_path / "bl.json"
    save_baseline(idx, bl_path, name="com.test", version="1.0")
    r = diff_against_baseline(p, bl_path)
    assert r.status == "ok"
    assert r.summary == {"added": 0, "removed": 0, "changed": 0}


def test_modified_manifest_flags_changed(tmp_path):
    pa = _mk_apk(tmp_path / "a.apk", manifest=b"\x03\x00\x08\x00" + b"A" * 64)
    pb = _mk_apk(tmp_path / "b.apk", manifest=b"\x03\x00\x08\x00" + b"B" * 64)
    idx_a = index_apk(pa)
    bl_path = tmp_path / "bl.json"
    save_baseline(idx_a, bl_path, name="com.test", version="1.0")
    r = diff_against_baseline(pb, bl_path)
    assert r.status == "ok"
    assert r.summary["changed"] >= 1
    assert any(d.category == "manifest" and d.status == "changed" for d in r.diffs)


def test_added_dex_flagged(tmp_path):
    pa = _mk_apk(tmp_path / "a.apk")
    pb_path = tmp_path / "b.apk"
    _mk_apk(pb_path)
    with zipfile.ZipFile(pb_path, "a") as zf:
        zf.writestr("classes2.dex", b"dex\n035\x00" + b"\x00" * 64)
    idx_a = index_apk(pa)
    bl_path = tmp_path / "bl.json"
    save_baseline(idx_a, bl_path, name="com.test", version="1.0")
    r = diff_against_baseline(pb_path, bl_path)
    assert r.summary["added"] >= 1
    dex_added = [d for d in r.diffs if d.category == "dex" and d.status == "added"]
    assert dex_added and dex_added[0].member == "classes2.dex"


def test_diff_to_findings_confirmed_on_manifest_change(tmp_path):
    pa = _mk_apk(tmp_path / "a.apk", manifest=b"\x03\x00\x08\x00" + b"A" * 64)
    pb = _mk_apk(tmp_path / "b.apk", manifest=b"\x03\x00\x08\x00" + b"B" * 64)
    idx_a = index_apk(pa)
    bl_path = tmp_path / "bl.json"
    save_baseline(idx_a, bl_path, name="com.test", version="1.0")
    r = diff_against_baseline(pb, bl_path)
    findings = diff_to_findings(r)
    manifest_findings = [f for f in findings if f.kind.startswith("upstream-changed-manifest")]
    assert manifest_findings
    assert manifest_findings[0].verdict == "CONFIRMED"
    assert manifest_findings[0].severity == "critical"
