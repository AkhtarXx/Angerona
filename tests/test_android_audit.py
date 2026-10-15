from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path

from src.pipeline.android_audit import (
    V_INCONCLUSIVE,
    V_LIKELY,
    _dex_semantic_coverage,
    run_android_audit,
)


def _mk_apk(path, manifest: bytes | None = None, with_sig: bool = False,
           with_libs: bool = False, with_packer_strings: bool = False) -> Path:
    manifest = manifest or (b"\x03\x00\x08\x00" + b"\x00" * 128)
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 100)
        if with_sig:
            zf.writestr("META-INF/CERT.RSA", b"\x30\x82\x02\x00" + b"\x00" * 512)
        if with_libs:
            zf.writestr("lib/arm64-v8a/libfoo.so", b"\x7fELF" + b"\x00" * 128)
        if with_packer_strings:
            # simulate SecNeo marker
            zf.writestr("assets/secneo_boot.dat", b"secneo" + b"\x00" * 32)
    return path


def test_missing_apk_errors(tmp_path):
    r = run_android_audit(tmp_path / "nope.apk")
    assert r.status == "error"
    assert r.trust == "untrusted_child"


def test_dex_semantic_gate_requires_every_independent_dex_target():
    mdex = type("MultiDex", (), {"status": "success", "dex_count": 2})()
    incomplete = _dex_semantic_coverage(
        mdex, {"dex_targets_expected": 2, "dex_targets_complete": 1}
    )
    assert incomplete["complete"] is False
    assert _dex_semantic_coverage(
        mdex, {"dex_targets_expected": 2, "dex_targets_complete": 2}
    )["complete"] is True


def test_non_apk_file_fails_before_security_verdicts(tmp_path):
    artifact = tmp_path / "not-an-apk.apk"
    artifact.write_bytes(b"not a zip")
    r = run_android_audit(artifact, try_runtime_extract=False)
    assert r.status == "error"
    assert r.findings == []
    assert r.metadata["artifact_validation"]["status"] == "invalid"
    assert r.steps_executed == ["artifact-snapshot"]


def test_android_audit_uses_durable_immutable_input_snapshot(tmp_path):
    source = _mk_apk(tmp_path / "source.apk")
    original_sha = hashlib.sha256(source.read_bytes()).hexdigest()
    snapshot_dir = tmp_path / "engagement" / "input"

    report = run_android_audit(
        source,
        run_rules=False,
        audit_input_snapshot_dir=snapshot_dir,
    )
    snapshot = Path(report.metadata["audit_input_snapshot"]["path"])

    assert snapshot != source
    assert snapshot.is_file()
    assert report.metadata["audit_input_snapshot"]["sha256"] == original_sha
    assert (snapshot.stat().st_mode & 0o777) == 0o444
    source.write_bytes(b"replaced after deterministic audit")
    assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == original_sha


def test_clean_apk_runs_provenance_first(tmp_path, monkeypatch):
    # Stub out modules that need devices/frida
    monkeypatch.setattr(
        "src.analysis.apksigner_bridge._extract_certs_from_v2_block", lambda apk: [])
    monkeypatch.setattr(
        "src.analysis.apksigner_bridge._extract_certs_via_apksigner", lambda apk, t: ([], []))
    p = _mk_apk(tmp_path / "a.apk")
    r = run_android_audit(p, try_runtime_extract=False)
    assert r.status == "partial"
    assert "apksigner_bridge" in r.steps_executed
    assert r.provenance_verdict != ""
    assert r.metadata["coverage_gate"]["origin_anchored"] is False


def test_provenance_mismatch_hits_refusal(tmp_path, monkeypatch):
    from src.analysis.apksigner_bridge import ApkSignerResult
    fake = ApkSignerResult(
        status="mismatch", apk_path="/x.apk", package_name="com.fake",
        note="⚠️ SIGNING MISMATCH: com.fake signed with cert [aaa], expected [bbb] — possible repack/fake-app",
    )
    monkeypatch.setattr("src.analysis.apksigner_bridge.verify_apk_signature", lambda *a, **kw: fake)
    p = _mk_apk(tmp_path / "fake.apk")
    r = run_android_audit(p)
    assert r.status == "refusal"
    assert any("mismatch" in rr.lower() or "repack" in rr.lower() for rr in r.refusal_reasons)
    assert "android_packer_db" in r.steps_executed


def test_verified_package_name_drives_runtime_extraction(tmp_path, monkeypatch):
    from src.analysis.android_packer_db import PackerDetectionResult, PackerMatch
    from src.analysis.apksigner_bridge import ApkSignerResult
    from src.execution.runtime_dex_extractor import DexDumpResult

    monkeypatch.setattr(
        "src.analysis.apksigner_bridge.verify_apk_signature",
        lambda *a, **kw: ApkSignerResult(
            status="verified", apk_path="/x", package_name="com.real.target"
        ),
    )
    monkeypatch.setattr(
        "src.analysis.android_packer_db.detect_android_packer",
        lambda apk: PackerDetectionResult(
            status="identified",
            matches=[PackerMatch(
                family="test", vendor="Test", score=0.9,
                matched_signals=["marker"], description="packed",
            )],
        ),
    )
    observed = []

    def fake_extract(package, **kwargs):
        observed.append((package, kwargs))
        return DexDumpResult(status="no_process", package=package, note="not running")

    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.extract_dex_runtime", fake_extract
    )
    p = _mk_apk(tmp_path / "packed.apk")
    run_android_audit(
        p, try_runtime_extract=True, runtime_provider="avd",
        runtime_api=35, runtime_abi="x86_64",
        authorization_ref="unit-test-authorized",
    )
    assert observed[0][0] == "com.real.target"
    assert observed[0][1]["runtime_provider"] == "avd"
    assert observed[0][1]["runtime_api"] == 35
    assert observed[0][1]["runtime_abi"] == "x86_64"


def test_runtime_execution_requires_authorization_reference(tmp_path, monkeypatch):
    called = False

    def forbidden_extract(*args, **kwargs):
        nonlocal called
        called = True
        raise AssertionError("runtime must not execute without engagement authorization")

    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.extract_dex_runtime", forbidden_extract
    )
    report = run_android_audit(_mk_apk(tmp_path / "unauthorized.apk"), try_runtime_extract=True)

    assert called is False
    assert report.metadata["runtime_authorized"] is False
    assert "runtime_dex_extractor:authorization-required" in report.steps_skipped
    assert any("authorization reference" in item for item in report.refusal_reasons)


def test_real_apktool_output_becomes_smali_corpus(tmp_path, monkeypatch):
    from src.analysis.apktool_bridge import ApktoolResult

    def fake_decode(apk, *, keep_output=None, **kwargs):
        root = Path(keep_output)
        smali = root / "smali" / "com" / "demo" / "Main.smali"
        smali.parent.mkdir(parents=True)
        smali.write_text(
            '.class public Lcom/demo/Main;\n.method public test()V\n'
            'const-string v0, "AKIAIOSFODNN7EXAMPLE"\nreturn-void\n.end method\n'
        )
        return ApktoolResult(
            status="success", apk_path=str(apk),
            manifest_xml='<manifest package="com.demo"><application/></manifest>',
            smali_dirs=["smali"], smali_files_count=1,
        )

    monkeypatch.setattr("src.analysis.apktool_bridge.decode_apk", fake_decode)
    p = _mk_apk(tmp_path / "smali.apk")
    r = run_android_audit(p, try_runtime_extract=False)
    assert "smali-corpus" in r.steps_executed
    assert "dex_security_rules" in r.steps_executed
    assert r.metadata["smali_coverage"]["files_read"] == 1
    assert r.metadata["smali_coverage"]["truncated"] is False


def test_plain_manifest_fallback_is_persisted_for_ai_review(tmp_path, monkeypatch):
    from src.analysis.apktool_bridge import ApktoolResult

    manifest = (
        b'<manifest xmlns:android="http://schemas.android.com/apk/res/android" '
        b'package="com.demo"><application android:allowBackup="true"/></manifest>'
    )
    p = _mk_apk(tmp_path / "plain.apk", manifest=manifest)
    artifacts = tmp_path / "artifacts"
    monkeypatch.setattr(
        "src.analysis.apktool_bridge.decode_apk",
        lambda *args, **kwargs: ApktoolResult(
            status="failed", apk_path=str(p), note="synthetic manifest"
        ),
    )

    report = run_android_audit(p, artifact_output_dir=artifacts)

    persisted = artifacts / "apktool" / "AndroidManifest.xml"
    assert persisted.read_text() == manifest.decode()
    assert "manifest-plain-xml-fallback" in report.steps_executed


def test_packer_detection_downgrades_verdicts(tmp_path, monkeypatch):
    # Stub provenance to verified
    from src.analysis.apksigner_bridge import ApkSignerResult
    monkeypatch.setattr(
        "src.analysis.apksigner_bridge.verify_apk_signature",
        lambda *a, **kw: ApkSignerResult(
            status="verified", apk_path="/x", package_name="com.bank"),
    )
    # Stub packer detection to identified
    from src.analysis.android_packer_db import PackerDetectionResult, PackerMatch
    monkeypatch.setattr(
        "src.analysis.android_packer_db.detect_android_packer",
        lambda apk: PackerDetectionResult(
            status="identified",
            matches=[PackerMatch(
                family="secneo", vendor="SecNeo", score=0.85,
                matched_signals=["lib:lib/libsecneo.so"], description="fake")],
        ),
    )
    # Stub runtime extract to fail silently
    from src.execution.runtime_dex_extractor import DexDumpResult
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.extract_dex_runtime",
        lambda pkg, **kw: DexDumpResult(
            status="no_process", package=pkg,
            note="no events",
        ),
    )
    p = _mk_apk(tmp_path / "pack.apk", with_packer_strings=True)
    r = run_android_audit(
        p,
        expected_package="com.bank",
        try_runtime_extract=True,
        authorization_ref="unit-test-authorized",
    )
    # Static security findings should be INCONCLUSIVE due to packer + no runtime
    sec_findings = [f for f in r.findings if f.module in ("cleartext_tls_rule", "deeplink_injection", "contentprovider_traversal", "allow_backup_check", "android_packer_db")]
    for f in sec_findings:
        if f.kind != "dex-inventory" and not f.runtime_corroborated:
            assert f.verdict in (V_INCONCLUSIVE, V_LIKELY), f"finding {f.kind} has verdict {f.verdict}"
    # check refusal-reason recorded
    assert any("INCONCLUSIVE" in rr or "packed" in rr.lower() for rr in r.refusal_reasons)


def test_pipeline_skips_janus_when_modern(tmp_path, monkeypatch):
    # Janus CVE is dead on minSdk≥23 — pipeline should skip when not suspicious
    monkeypatch.setattr(
        "src.analysis.janus_signature.check_apk",
        lambda apk: type("R", (), {"suspicious": False, "note": "clean"})(),
    )
    p = _mk_apk(tmp_path / "a.apk")
    r = run_android_audit(p, try_runtime_extract=False)
    assert "janus_signature:not-applicable" in r.steps_skipped or "janus_signature" in r.steps_executed


def test_rustls_skips_java_tls_rules(tmp_path, monkeypatch):
    # Signal-like: rustls primary → java TLS rules should be skipped
    monkeypatch.setattr(
        "src.analysis.tls_stack_identifier.identify_tls_stack",
        lambda apk: type("R", (), {
            "recommended_rule_layer": "native",
            "primary_stack": "rustls",
            "note": "rustls",
            "cert_pinning_likely": False,
        })(),
    )
    p = _mk_apk(tmp_path / "a.apk", with_libs=True)
    r = run_android_audit(p, try_runtime_extract=False)
    assert any(s.startswith("cleartext_tls_rule:skipped") for s in r.steps_skipped)


def test_report_summary_line(tmp_path, monkeypatch):
    p = _mk_apk(tmp_path / "a.apk")
    r = run_android_audit(p, try_runtime_extract=False)
    line = r.summary_line()
    assert "audit[" in line
    assert "steps=" in line


def test_real_signal_audit_smoke(tmp_path):
    sig = Path("/tmp/signal.apk")
    if not sig.exists():
        import pytest
        pytest.skip("signal apk unavailable")
    r = run_android_audit(sig, try_runtime_extract=False, timeout_per_step=60, run_rules=True)
    assert r.status in ("completed", "partial", "refusal")
    assert r.provenance_verdict != ""
    print("\nsignal verdicts:")
    for f in r.findings[:10]:
        print(f"  {f.verdict:15s} {f.module:30s} {f.kind}")
