from __future__ import annotations

import zipfile
from pathlib import Path

from src.analysis.cross_package_chain_analyzer import analyze_cross_package


def _mkapk(path, manifest: bytes):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)


def test_empty_input():
    r = analyze_cross_package([])
    assert r.status == "empty"
    assert r.groups == []


def test_shared_userid_group_detected(tmp_path):
    m1 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bank.a" android:sharedUserId="com.bank.shared"><application/></manifest>'
    m2 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bank.b" android:sharedUserId="com.bank.shared"><application/></manifest>'
    ap = tmp_path / "a.apk"
    ap2 = tmp_path / "b.apk"
    _mkapk(ap, m1)
    _mkapk(ap2, m2)
    r = analyze_cross_package([ap, ap2])
    assert r.status == "ok"
    uids = [g for g in r.groups if g.group_id.startswith("uid:")]
    assert uids
    assert uids[0].severity == "high"


def test_single_apk_singleton(tmp_path):
    m1 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.alone.app"><application/></manifest>'
    ap = tmp_path / "a.apk"
    _mkapk(ap, m1)
    r = analyze_cross_package([ap])
    assert r.status == "ok"
    assert r.groups == []
    assert "com.alone.app" in r.singletons


def test_same_cert_collusion(tmp_path):
    m1 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.corp.a"><application/></manifest>'
    m2 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.corp.b"><application/></manifest>'
    ap = tmp_path / "a.apk"
    ap2 = tmp_path / "b.apk"
    cert = b"\x30\x82\x02\x00" + b"\x00" * 512
    with zipfile.ZipFile(ap, "w") as zf:
        zf.writestr("AndroidManifest.xml", m1)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("META-INF/CERT.RSA", cert)
    with zipfile.ZipFile(ap2, "w") as zf:
        zf.writestr("AndroidManifest.xml", m2)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
        zf.writestr("META-INF/CERT.RSA", cert)
    r = analyze_cross_package([ap, ap2])
    assert r.status == "ok"
    cert_groups = [g for g in r.groups if g.sharing_mechanism == "same-cert"]
    assert cert_groups
    assert cert_groups[0].severity == "high"


def test_custom_signature_permission_group(tmp_path):
    m1 = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.sender.app">
  <permission android:name="com.sender.SECURE" android:protectionLevel="signature"/>
  <application/></manifest>'''
    m2 = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.receiver.app">
  <permission android:name="com.sender.SECURE" android:protectionLevel="signature"/>
  <application/></manifest>'''
    ap = tmp_path / "a.apk"
    ap2 = tmp_path / "b.apk"
    _mkapk(ap, m1)
    _mkapk(ap2, m2)
    r = analyze_cross_package([ap, ap2])
    assert r.status == "ok"
    perm_groups = [g for g in r.groups if g.sharing_mechanism == "custom-permission"]
    assert perm_groups
    assert perm_groups[0].severity == "medium"


def test_exported_component_in_group_noted(tmp_path):
    m1 = b'''<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bank.a" android:sharedUserId="com.bank.s">
  <application>
    <provider android:name="com.bank.a.DataProvider" android:exported="true"/>
    <activity android:name="com.bank.a.MainActivity" android:exported="true"/>
  </application>
</manifest>'''
    m2 = b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.bank.b" android:sharedUserId="com.bank.s"><application/></manifest>'
    ap = tmp_path / "a.apk"
    ap2 = tmp_path / "b.apk"
    _mkapk(ap, m1)
    _mkapk(ap2, m2)
    r = analyze_cross_package([ap, ap2])
    assert r.status == "ok"
    uids = [g for g in r.groups if g.group_id.startswith("uid:")]
    assert uids
    findings = uids[0].findings
    assert any(f.kind == "cross-package-exposed-provider" for f in findings)


def test_real_roman_apps(tmp_path):
    import os
    paths = []
    for f in ("/tmp/dummy_signed.apk", "/tmp/aegis.apk"):
        if os.path.exists(f):
            paths.append(f)
    if len(paths) < 2:
        import pytest
        pytest.skip("need 2+ real APKs")
    r = analyze_cross_package(paths[:2])
    assert r.status == "ok"
