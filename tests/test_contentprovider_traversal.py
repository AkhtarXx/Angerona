"""Behavior tests for the exported ContentProvider traversal detector."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.contentprovider_traversal import (
    TRUST_TAG,
    scan_apk,
    scan_manifest_text,
    scan_provider_code,
)


MANIFEST_EXPORTED = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <provider android:name=".FileProvider"
              android:authorities="com.x.files"
              android:exported="true"
              android:grantUriPermissions="true"/>
  </application>
</manifest>
"""

MANIFEST_NOT_EXPORTED = """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <application>
    <provider android:name=".FileProvider"
              android:authorities="com.x.files"
              android:exported="false"/>
  </application>
</manifest>
"""

PROVIDER_CODE_VULN = """
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File f = new File(getContext().getFilesDir(), uri.getPath());
    return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
}
"""

PROVIDER_CODE_SAFE = """
public ParcelFileDescriptor openFile(Uri uri, String mode) {
    File base = getContext().getFilesDir().getCanonicalFile();
    File f = new File(base, uri.getLastPathSegment()).getCanonicalPath();
    if (!f.startsWith(base)) throw new SecurityException();
    return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
}
"""

# One canonicalizing openFile alongside a sibling that hands Uri.getPath()
# straight to new File(): a sanitizer in one method must not downgrade the other.
PROVIDER_CODE_MIXED = """
public class Provider {
    public ParcelFileDescriptor openFileSafe(Uri uri, String mode) {
        File base = getContext().getFilesDir().getCanonicalFile();
        File f = new File(base, uri.getLastPathSegment()).getCanonicalPath();
        if (!f.startsWith(base)) throw new SecurityException();
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }

    public ParcelFileDescriptor openFileVuln(Uri uri, String mode) {
        File f = new File(uri.getPath());
        return ParcelFileDescriptor.open(f, ParcelFileDescriptor.MODE_READ_ONLY);
    }
}
"""


def test_exported_provider_flagged():
    out = scan_manifest_text(MANIFEST_EXPORTED)
    assert out.status == "success"
    kinds = {f.kind for f in out.findings}
    assert "exported-provider" in kinds
    assert "grant-uri-permissions" in kinds
    assert ".FileProvider" in out.providers


def test_non_exported_provider_not_flagged_high():
    out = scan_manifest_text(MANIFEST_NOT_EXPORTED)
    assert out.status == "success"
    assert not any(f.severity == "high" for f in out.findings)


def test_traversal_sink_unsanitized_is_high():
    out = scan_provider_code(PROVIDER_CODE_VULN)
    sinks = [f for f in out.findings if f.kind == "traversal-sink"]
    assert sinks and any(f.severity == "high" for f in sinks)


def test_sanitized_sink_downgraded():
    out = scan_provider_code(PROVIDER_CODE_SAFE)
    sinks = [f for f in out.findings if f.kind == "traversal-sink"]
    assert sinks
    assert all(f.severity == "medium" for f in sinks)


def test_sanitizer_scope_is_per_method_not_per_file():
    out = scan_provider_code(PROVIDER_CODE_MIXED)
    sinks = [f for f in out.findings if f.kind == "traversal-sink"]
    assert any(f.severity == "medium" for f in sinks)  # canonicalizing openFileSafe
    assert any(f.severity == "high" and "new file(uri" in f.detail for f in sinks)
    assert any(f.severity == "high" and "parcelfiledescriptor.open" in f.detail for f in sinks)


def test_malformed_degrade_and_trust(tmp_path):
    assert scan_apk(tmp_path / "missing.apk").status == "skipped"
    bad = tmp_path / "x.apk"
    bad.write_bytes(b"junk bytes")
    assert scan_apk(bad).status == "error"
    apk = write_apk(tmp_path / "ok.apk", manifest_utf8=MANIFEST_EXPORTED)
    out = scan_apk(apk)
    assert out.status == "success"
    assert out.trust == TRUST_TAG == "untrusted_child"
    assert all(f.trust == "untrusted_child" for f in out.findings)
