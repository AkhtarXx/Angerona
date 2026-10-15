from __future__ import annotations

from src.analysis.finding import CONFIRMED, LIKELY, NOT_APPLICABLE
from src.analysis.browsable_implicits import scan_manifest_text


MANIFEST_CLEAN = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".MainActivity"/>
  </application>
</manifest>
"""

MANIFEST_DEEPLINK_NO_EXPORTED = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".DeepActivity">
      <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="myapp" android:host="open"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

MANIFEST_EXPORTED_FALSE = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".Locked" android:exported="false">
      <intent-filter>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="foo"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""

MANIFEST_AUTOVERIFY = """<?xml version="1.0"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <activity android:name=".VerifiedLink" android:exported="true">
      <intent-filter android:autoVerify="true">
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="https" android:host="example.com"/>
      </intent-filter>
    </activity>
  </application>
</manifest>
"""


def test_no_browsable_no_findings():
    r = scan_manifest_text(MANIFEST_CLEAN)
    assert r.status == "ok"
    assert r.findings == []


def test_browsable_no_exported_high_severity():
    r = scan_manifest_text(MANIFEST_DEEPLINK_NO_EXPORTED)
    assert r.status == "ok"
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.kind == "implicit-deep-link"
    assert f.verdict == LIKELY
    assert f.severity == "high"
    assert "no autoVerify" in f.detail


def test_exported_false_not_applicable():
    r = scan_manifest_text(MANIFEST_EXPORTED_FALSE)
    assert r.status == "ok"
    assert r.findings == []  # NOT_APPLICABLE findings are skipped


def test_auto_verify_downgrades_to_likely():
    r = scan_manifest_text(MANIFEST_AUTOVERIFY)
    assert r.status == "ok"
    assert len(r.findings) == 1
    f = r.findings[0]
    assert f.verdict == LIKELY
    assert f.severity == "medium"
    assert "autoVerify declared" in f.detail


def test_empty_manifest_graceful():
    r = scan_manifest_text("")
    assert r.status == "empty"


def test_real_signal_browsable():
    from pathlib import Path
    manifest = Path("/tmp/signal_decoded/AndroidManifest.xml")
    if not manifest.exists():
        import pytest
        pytest.skip("signal manifest unavailable")
    r = scan_manifest_text(manifest.read_text())
    print(f"signal implicit-routes: {r.implicit_routes}")
    print(f"signal findings: {len(r.findings)}")
    assert r.status == "ok"
