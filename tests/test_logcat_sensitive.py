"""Behavior tests for the logcat sensitive-data detector."""
from __future__ import annotations

from src.analysis.logcat_sensitive import (
    TRUST_TAG,
    scan_source_text,
)


VULN_JAVA = """
public class Login {
    void onLogin(String user, String password, String token) {
        Log.d("AUTH", "user=" + user + " password=" + password);
        Log.v("AUTH", "session token=" + token);
        Log.e("AUTH", "login failed for " + user);
    }
}
"""

CLEAN_JAVA = """
public class Ui {
    void onDraw() {
        Log.i("UI", "frame drawn");
    }
}
"""

SMALI_LOG = """
.method public go()V
    .locals 2
    const-string v0, "TAG"
    const-string v1, "api_key=deadbeef"
    invoke-static {v0, v1}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I
.end method
"""


def test_sensitive_logging_upgraded():
    out = scan_source_text(VULN_JAVA)
    assert out.status == "success"
    assert out.total_log_calls == 3
    assert out.sensitive_calls >= 2
    vd = [f for f in out.findings if f.metadata.get("level") in ("v", "d")]
    assert vd and all(f.severity == "high" for f in vd)
    toks = {w for f in out.findings for w in f.metadata.get("sensitive_vocab",[])}
    assert {"password", "token", "session"} & toks


def test_info_log_not_reported_without_sensitive_vocab():
    out = scan_source_text(CLEAN_JAVA)
    assert out.total_log_calls == 1
    assert out.sensitive_calls == 0
    assert out.findings == []  # level=i with no sensitive vocab: not reported


def test_smali_log_alias_detected():
    out = scan_source_text(SMALI_LOG, source="smali")
    assert any(f.metadata.get("level") == "d" and "api_key" in f.metadata.get("sensitive_vocab",[])
               for f in out.findings)


def test_empty_and_trust_envelope():
    assert scan_source_text("").status == "empty"
    out = scan_source_text(VULN_JAVA)
    assert out.trust == TRUST_TAG == "untrusted_child"
    for f in out.findings:
        assert f.trust == "untrusted_child"
        assert f.evidence and f.line_no >= 1
    d = out.as_dict()
    assert {"total_log_calls", "sensitive_calls", "policy"} <= set(d)
