"""Behavior tests for the allowBackup unencrypted-backup check."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.allow_backup_check import (
    TRUST_TAG,
    scan_apk,
    scan_manifest_text,
)


MANIFEST_BACKUP_TRUE = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:allowBackup="true" android:label="x"/>
</manifest>
"""

MANIFEST_BACKUP_SAFE = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:allowBackup="false"
               android:fullBackupContent="@xml/backup_rules"/>
</manifest>
"""

MANIFEST_NO_ATTR = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:label="x"/>
</manifest>
"""

MANIFEST_DEBUGGABLE = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application android:allowBackup="true" android:debuggable="true"/>
</manifest>
"""


def test_allow_backup_true_flagged_high():
    out = scan_manifest_text(MANIFEST_BACKUP_TRUE)
    assert out.status == "success"
    assert out.allow_backup is True
    kinds = {f.kind for f in out.findings}
    assert "allow-backup-true" in kinds
    assert "no-backup-rules" in kinds
    assert any(f.severity == "high" for f in out.findings)


def test_explicit_false_with_rules_is_clean():
    out = scan_manifest_text(MANIFEST_BACKUP_SAFE)
    assert out.allow_backup is False
    assert out.has_backup_rules is True
    assert out.findings == []


def test_absent_attribute_defaults_to_warning():
    out = scan_manifest_text(MANIFEST_NO_ATTR)
    assert out.allow_backup is None
    assert any(f.kind == "allow-backup-true" and f.severity == "medium"
               for f in out.findings)


def test_debuggable_compounds():
    out = scan_manifest_text(MANIFEST_DEBUGGABLE)
    assert any(f.kind == "debuggable-build" for f in out.findings)


def test_malformed_apk_degrades(tmp_path):
    assert scan_apk(tmp_path / "none.apk").status == "skipped"
    bad = tmp_path / "bad.apk"
    bad.write_bytes(b"### not zip ###")
    assert scan_apk(bad).status == "error"
    bare = write_apk(tmp_path / "bare.apk", files={"classes.dex": b"dex\n035\x00"})
    assert scan_apk(bare).status == "empty"


def test_real_apk_manifest_and_trust(tmp_path):
    apk = write_apk(tmp_path / "app.apk", manifest_utf8=MANIFEST_BACKUP_TRUE)
    out = scan_apk(apk)
    assert out.status == "success"
    assert out.allow_backup is True
    assert out.trust == TRUST_TAG == "untrusted_child"
    assert all(f.trust == "untrusted_child" for f in out.findings)
