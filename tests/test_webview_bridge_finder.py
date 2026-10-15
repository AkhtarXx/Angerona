"""Behavior tests for the WebView JS-bridge implicit-export finder."""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from android_fixtures import write_apk

from src.analysis.webview_bridge_finder import (
    TRUST_TAG,
    scan_apk_dex_strings,
    scan_source_text,
)


VULN_JAVA = """
public class MainActivity extends Activity {
    protected void onCreate(Bundle b) {
        WebView wv = findViewById(R.id.web);
        wv.getSettings().setJavaScriptEnabled(true);
        wv.addJavascriptInterface(new JsBridge(), "Android");
        wv.loadUrl("http://api.example.com/page");
    }
    class JsBridge {
        @JavascriptInterface
        public String readFile(String path) { return slurp(path); }
    }
}
"""

CLEAN_JAVA = """
public class MainActivity extends Activity {
    protected void onCreate(Bundle b) {
        WebView wv = findViewById(R.id.web);
        wv.getSettings().setJavaScriptEnabled(false);
        wv.loadUrl("https://api.example.com/page");
    }
}
"""


def test_vulnerable_bridge_detected():
    out = scan_source_text(VULN_JAVA)
    assert out.status == "success"
    markers = {f.kind for f in out.findings}
    assert "js-bridge-registration" in markers
    assert "js-enabled" in markers
    assert "cleartext-js-load" in markers
    assert out.bridges_registered == 1
    annotated = [f for f in out.findings if f.kind == "js-bridge-annotation"]
    assert annotated and "readFile" in annotated[0].metadata.get("exposed_methods",[])


def test_clean_source_only_benign_markers():
    out = scan_source_text(CLEAN_JAVA)
    assert out.bridges_registered == 0
    kinds = {f.kind for f in out.findings}
    assert "js-bridge-registration" not in kinds
    assert "cleartext-js-load" not in kinds


def test_empty_and_missing_inputs():
    assert scan_source_text("").status == "empty"
    out = scan_apk_dex_strings("/definitely/missing.apk")
    assert out.status == "skipped"


def test_dex_strings_fallback_on_real_apk(tmp_path):
    # DEX blob carrying a readable addJavascriptInterface symbol string.
    dex = (b"dex\n035\x00" + b"\x00" * 96 +
           b"addJavascriptInterface\x00setJavaScriptEnabled\x00" + b"\x00" * 256)
    apk = write_apk(tmp_path / "app.apk", files={"classes.dex": dex})
    out = scan_apk_dex_strings(apk)
    assert out.status == "success"
    assert out.bridges_registered >= 1
    assert all(f.trust == TRUST_TAG for f in out.findings)


def test_trust_envelope_and_as_dict():
    out = scan_source_text(VULN_JAVA)
    assert out.trust == "untrusted_child"
    for f in out.findings:
        assert f.trust == "untrusted_child"
        assert f.evidence and f.line_no >= 1 and f.evidence
    # round-trips through as_dict deterministically
    again = scan_source_text(VULN_JAVA).as_dict()
    assert again["bridges_registered"] == out.bridges_registered
