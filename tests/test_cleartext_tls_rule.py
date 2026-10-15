"""Behavior tests for the cleartext-HTTP + TrustAll-TLS combined rule."""
from __future__ import annotations

from src.analysis.cleartext_tls_rule import (
    TRUST_TAG,
    merge_results,
    scan_manifest_text,
    scan_source_text,
)


VULN_JAVA = """
import javax.net.ssl.X509TrustManager;
public class Net {
    static final String API = "http://api.example.com/v1";
    X509TrustManager trustAll = new X509TrustManager() {
        public void checkServerTrusted(X509Certificate[] c, String a) {}
    };
    void go() {
        HttpsURLConnection.setDefaultHostnameVerifier((h, s) -> true);
    }
}
"""

CLEAN_JAVA = """
public class Net {
    static final String API = "https://api.example.com/v1";
}
"""

MANIFEST_CLEARTEXT = """
<manifest><application android:usesCleartextTraffic="true"/></manifest>
"""
MANIFEST_NSC = """
<manifest><application android:usesCleartextTraffic="false"
    android:networkSecurityConfig="@xml/nsc"/></manifest>
"""


def test_combined_high_when_both_halves_present():
    out = scan_source_text(VULN_JAVA)
    assert out.status == "success"
    assert out.cleartext_count >= 1
    assert out.trustall_count >= 1
    assert out.combined_risk == "high"


def test_trustall_alone_is_medium():
    out = scan_source_text("class A { X509TrustManager tm; }")
    assert out.combined_risk == "medium"
    assert out.cleartext_count == 0


def test_noop_hostname_verifier_counts_as_trustall():
    out = scan_source_text("HostnameVerifier hv = new NoopHostnameVerifier();")
    assert any(f.kind == "noop-hostname-verifier" and f.severity == "high"
               for f in out.findings)
    assert out.trustall_count == 1
    assert out.cleartext_count == 0
    assert out.combined_risk == "medium"


def test_cleartext_alone_is_low_and_localhost_ignored():
    out = scan_source_text('String A = "http://api.example.com";\n'
                           'String B = "http://127.0.0.1:8080";\n')
    assert out.combined_risk == "low"
    assert all("127.0.0.1" not in f.evidence for f in out.findings)


def test_clean_source_no_findings():
    out = scan_source_text(CLEAN_JAVA)
    assert out.combined_risk == "none"
    assert out.findings == []


def test_manifest_flags():
    vuln = scan_manifest_text(MANIFEST_CLEARTEXT)
    assert any(f.kind == "manifest-cleartext" and f.severity == "high"
               for f in vuln.findings)
    ok = scan_manifest_text(MANIFEST_NSC)
    assert ok.findings == []


def test_empty_malformed_and_trust():
    assert scan_source_text("").status == "empty"
    assert scan_manifest_text("").status == "empty"
    merged = merge_results(scan_source_text(VULN_JAVA),
                           scan_manifest_text(MANIFEST_CLEARTEXT))
    assert merged.combined_risk == "high"
    assert merged.trust == TRUST_TAG == "untrusted_child"
    assert all(f.trust == "untrusted_child" for f in merged.findings)
    assert "policy" in merged.as_dict()
