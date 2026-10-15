from __future__ import annotations

import json
from types import SimpleNamespace

from src import cli
from src.pipeline.android_audit import AuditReport


def test_android_audit_parser_exposes_engagement_inputs():
    ns = cli.build_parser().parse_args([
        "android-audit", "target.apk",
        "--expected-package", "com.example.app",
        "--related-apk", "helper.apk",
        "--baseline", "baseline.json",
        "--authorization-ref", "ENG-2026-0812",
        "--device-serial", "device-1",
    ])
    assert ns.apk == "target.apk"
    assert ns.expected_package == "com.example.app"
    assert ns.related_apk == ["helper.apk"]
    assert ns.baseline == "baseline.json"
    assert ns.device_serial == "device-1"
    assert ns.authorization_ref == "ENG-2026-0812"
    assert ns.runtime is False


def test_android_ai_parser_exposes_independent_reviewer_routing():
    ns = cli.build_parser().parse_args([
        "android-audit", "target.apk", "--ai-review",
        "--ai-agent", "claude", "--model", "claude-glm-5-2",
        "--ai-reviewer-agent", "codex",
        "--ai-reviewer-model", "gpt-5.6-sol",
        "--ai-reviewer-reasoning", "high",
        "--ai-dangerous-skip-permissions",
    ])
    assert ns.ai_agent == "claude"
    assert ns.model == "claude-glm-5-2"
    assert ns.ai_reviewer_agent == "codex"
    assert ns.ai_reviewer_model == "gpt-5.6-sol"
    assert ns.ai_reviewer_reasoning == "high"
    assert ns.ai_dangerous_skip_permissions is True


def test_android_runtime_is_explicit_opt_in():
    audit = cli.build_parser().parse_args([
        "android-audit", "target.apk", "--runtime",
        "--runtime-provider", "avd", "--runtime-api", "35",
        "--runtime-abi", "x86_64",
    ])
    doctor = cli.build_parser().parse_args(["android-doctor"])
    runtime_doctor = cli.build_parser().parse_args(["android-doctor", "--runtime"])

    assert audit.runtime is True
    assert audit.runtime_provider == "avd"
    assert audit.runtime_api == 35
    assert audit.runtime_abi == "x86_64"
    assert doctor.runtime is False
    assert runtime_doctor.runtime is True


def test_android_audit_command_writes_full_report(monkeypatch, tmp_path):
    report = AuditReport(apk_path="target.apk", status="completed")
    monkeypatch.setattr(
        "src.pipeline.android_audit.run_android_audit", lambda *a, **kw: report
    )
    output = tmp_path / "report.json"
    rc = cli.main(["android-audit", "target.apk", "--output", str(output)])
    assert rc == 0
    assert json.loads(output.read_text())["status"] == "completed"


def test_android_ai_review_runs_supervisor_swarm(monkeypatch, tmp_path):
    report = AuditReport(apk_path="target.apk", status="completed")
    monkeypatch.setattr(
        "src.pipeline.android_audit.run_android_audit", lambda *a, **kw: report
    )
    code_dir = tmp_path / "ai-workspace" / "code"
    code_dir.mkdir(parents=True)
    workspace = SimpleNamespace(code_dir=code_dir)
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.create_android_ai_workspace",
        lambda *a, **kw: workspace,
    )

    def fake_swarm(**kwargs):
        assert kwargs["workspace"] is workspace
        assert kwargs["report"] is report
        assert kwargs["rounds"] == 2
        assert kwargs["parallel"] == 3
        assert kwargs["reviewer_agent"] == "auto"
        assert kwargs["reviewer_reasoning_effort"] == "high"
        return SimpleNamespace(
            workspace=tmp_path / "ai-workspace",
            coverage={"coverage_complete": True},
            swarm=SimpleNamespace(
                final_report="# Verified Android report",
                converged=True,
                supervisor_rounds=2,
                workers=[],
                incomplete_reason="",
            ),
        )

    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.run_android_ai_swarm", fake_swarm
    )
    output = tmp_path / "report.json"
    rc = cli.main([
        "android-audit", "target.apk", "--output", str(output), "--ai-review"
    ])
    assert rc == 0
    review = output.with_suffix(".json.ai-review.md")
    assert review.read_text() == "# Verified Android report\n"
    payload = json.loads(output.read_text())
    assert payload["metadata"]["ai_swarm"]["converged"] is True
