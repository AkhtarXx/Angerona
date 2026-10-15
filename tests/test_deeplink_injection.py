"""Behavior tests for the deep-link scheme injection detector."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.deeplink_injection import (
    TRUST_TAG,
    scan_apk,
    scan_manifest_text,
    scan_usage_text,
)


MANIFEST_VULN = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
        <data android:scheme="myapp" android:host="open"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

MANIFEST_SAFE = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".SafeActivity" android:exported="false"/>
  </application>
</manifest>
"""

HANDLER_VULN = """
public void onCreate(Bundle b) {
    Uri uri = getIntent().getData();
    String target = uri.getQueryParameter("next");
    webView.loadUrl(target);
}
"""


def test_exported_custom_scheme_flagged():
    out = scan_manifest_text(MANIFEST_VULN)
    assert out.status == "success"
    assert "myapp" in out.schemes
    kinds = {f.kind for f in out.findings}
    assert "scheme-registration" in kinds
    assert "exported-handler" in kinds
    assert any(f.severity == "high" for f in out.findings)


def test_no_scheme_is_clean():
    out = scan_manifest_text(MANIFEST_SAFE)
    assert out.status == "success"
    assert out.schemes == []
    assert out.findings == []


def test_uri_to_sink_flow_flagged():
    out = scan_usage_text(HANDLER_VULN)
    flows = [f for f in out.findings if f.kind == "unvalidated-uri-flow"]
    assert flows
    assert any(f.severity == "high" for f in flows)


def test_malformed_and_missing_apk(tmp_path):
    assert scan_apk(tmp_path / "nope.apk").status == "skipped"
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"garbage not zip")
    assert scan_apk(bad).status == "error"
    no_manifest = tmp_path / "bare.apk"
    write_apk(no_manifest, files={"classes.dex": b"dex\n035\x00" + b"\x00" * 64})
    assert scan_apk(no_manifest).status == "empty"


def test_real_apk_manifest_and_trust(tmp_path):
    apk = write_apk(tmp_path / "app.apk", manifest_utf8=MANIFEST_VULN)
    out = scan_apk(apk)
    assert out.status == "success"
    assert "myapp" in out.schemes
    assert out.trust == TRUST_TAG == "untrusted_child"
    for f in out.findings:
        assert f.trust == "untrusted_child"
        assert f.detail and f.evidence
