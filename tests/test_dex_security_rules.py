"""Behavior tests for QARK-style DEX security rules (roadmap Android #2)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.dex_security_rules import (
    run_security_rules_on_dir,
    run_security_rules_on_smali,
)


SAMPLE_SMALI = """
.class public final Lcom/x/Runner;
.method public static run()V
    .locals 3
    const-string v0, "http://api.evil.example.com/v1/submit"
    invoke-static {v0}, Lcom/example/net/HttpClient;->get(Ljava/lang/String;)V

    const-string v1, "AKIAIOSFODNN7EXAMPLE"
    const-string v2, "0123456789abcdef0123456789abcdef"
    const-string v3, "AIzaSyB1234567890123456789012345678901234567"
    invoke-static {v1, v2}, Lcom/aws/S3Client;->auth(Ljava/lang/String;Ljava/lang/String;)V

    const-string v4, "AES/ECB/PKCS5Padding"
    invoke-static {v4}, Ljavax/crypto/Cipher;->getInstance(Ljava/lang/String;)Ljavax/crypto/Cipher;

    const-string v5, "MD5"
    invoke-static {v5}, Ljava/security/MessageDigest;->getInstance(Ljava/lang/String;)Ljava/security/MessageDigest;

    invoke-static {}, Ldalvik/system/DexClassLoader;->getSystemClassLoader()Ldalvik/system/DexClassLoader;

    invoke-static {v4}, Ljava/lang/SSLContext;->getInstance(Ljava/lang/String;)Ljavax/net/ssl/SSLContext;

    const-string v6, "magisk"
    invoke-static {v6}, Landroid/os/SystemProperties;->get(Ljava/lang/String;)Ljava/lang/String;
.end method
"""

CLEAN_SMALI = """
.method public static safe()V
    .locals 1
    const-string v0, "https://api.example.com/v2/secure"
    invoke-static {v0}, Lcom/example/net/HttpsClient;->get(Ljava/lang/String;)V
.end method
"""


def test_rules_detect_full_suite():
    out = run_security_rules_on_smali(SAMPLE_SMALI)
    assert out["total"] >= 6
    by_sev = out["by_severity"]
    assert by_sev.get("high", 0) >= 2
    rules = {f["rule"] for f in out["findings"]}
    assert "hardcoded-aws-key" in rules
    assert "hardcoded-symmetric-key" in rules
    assert "hardcoded-google-api-key" in rules
    assert any("weak" in f["rule"] for f in out["findings"])
    assert "cleartext-http" in rules or any("http" in f["evidence"] for f in out["findings"])
    url_findings = [f for f in out["findings"] if "http://" in f.get("evidence", "")]
    assert url_findings


def test_rules_clean_input_is_clean():
    out = run_security_rules_on_smali(CLEAN_SMALI)
    assert out["total"] == 0 or (
        all(f["severity"] in {"info"} for f in out["findings"]))
    assert out["by_severity"].get("high", 0) == 0


def test_rules_dir_scan_marks_file_provenance():
    with tempfile.TemporaryDirectory() as td:
        d = Path(td)
        (d / "a.smali").write_text(SAMPLE_SMALI)
        (d / "b.smali").write_text(CLEAN_SMALI)
        out = run_security_rules_on_dir(d)
        assert out["files_scanned"] == 2
        assert out["total"] >= 6
        file_paths = {f.get("file") for f in out["findings"] if "file" in f}
        assert "a.smali" in file_paths


def test_evidence_never_empty_when_finding():
    out = run_security_rules_on_smali(SAMPLE_SMALI)
    for f in out["findings"]:
        assert f.get("evidence"), f"finding without evidence: {f}"
        assert f.get("line_no", 0) >= 1
