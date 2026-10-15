import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

from src.agents import prompts
from src.agents.supervisor import SwarmResult
from src.pipeline.android_ai_audit import (
    _EVIDENCE_READER_SOURCE,
    _collect_finding_adjudications,
    _collect_worker_ledgers,
    _coverage_after_swarm,
    _deterministic_finding_rows,
    _dispatch_requires_isolation,
    _evaluate_android_completion,
    _evidence_reader_invocations,
    _provider_command_records,
    _revalidate_apk_identity,
    _security_slices,
    _validate_finding_inventory,
    materialize_android_ai_evidence,
    run_android_ai_swarm,
)
from src.pipeline.android_audit import AuditFinding, AuditReport
from src.workspace import RunWorkspace


def _workspace(tmp_path: Path) -> RunWorkspace:
    runs = tmp_path / "runs"
    runs.mkdir()
    return RunWorkspace.create(runs, str(tmp_path / "target.apk"))


def test_android_prompts_require_exact_artifact_citations():
    analyst = prompts.analyst_system_prompt("android")
    reviewer = prompts.reviewer_system_prompt("android")

    assert "ANDROID_SOURCE_INVENTORY.json" in analyst
    assert "exact relative file path" in analyst
    assert "Re-open the exact JADX/Smali/XML/native evidence" in reviewer
    assert prompts.engine_label("android") == "Android APK artifact workspace"


def test_android_worker_cwd_forces_isolation_in_single_candidate_mode(tmp_path):
    control = tmp_path / "root" / "code"
    worker = tmp_path / "root" / "workers" / "worker-1" / "code"

    assert _dispatch_requires_isolation(control, control, False) is False
    assert _dispatch_requires_isolation(control, worker, False) is True
    assert _dispatch_requires_isolation(control, control, True) is True


def test_android_security_slices_are_cost_balanced_not_fixed_six():
    inventory = {
        "files": [
            {"path": "small.java", "bytes": 10, "lines": 1},
            {"path": "large.java", "bytes": 400_000, "lines": 5_000},
        ],
        "truncated": False,
    }
    slices = _security_slices(
        inventory, AuditReport(apk_path="target.apk", status="completed")
    )["slices"]

    file_slices = [item for item in slices if item["slice_id"].startswith("android-files")]
    assert len(file_slices) == 2
    assert {path for item in file_slices for path in item["ai_scope"]["allowed_inputs"]} == {
        "small.java", "large.java",
    }
    assert slices[-1]["slice_id"] == "android-findings-corroboration"


def test_deterministic_finding_ids_are_content_stable_and_duplicate_safe():
    report = AuditReport(apk_path="target.apk", status="completed")
    finding = AuditFinding(
        module="tls", kind="cleartext", severity="high", verdict="LIKELY",
        detail="cleartext traffic is permitted",
    )
    report.findings.extend([finding, finding])

    first = _deterministic_finding_rows(report)
    second = _deterministic_finding_rows(report)

    assert first == second
    assert first[0]["fingerprint"] == first[1]["fingerprint"]
    assert first[0]["finding_id"] != first[1]["finding_id"]


def test_android_evidence_reader_parser_accepts_real_bash_lc_shape():
    command = (
        "/bin/bash -lc 'python3 ANGERONA_EVIDENCE_READ.py --path "
        "android_artifacts/apktool/AndroidManifest.xml --start 1 --end 1'"
    )

    assert _evidence_reader_invocations(command) == [{
        "native": False,
        "path": "android_artifacts/apktool/AndroidManifest.xml",
        "start": 1,
        "end": 1,
    }]


def test_android_evidence_reader_parser_rejects_forged_shell_shapes():
    from src.pipeline.android_ai_audit import _evidence_reader_invocations

    assert _evidence_reader_invocations(
        "echo python3 ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 2"
    ) == []
    assert _evidence_reader_invocations(
        "true || python3 ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 2"
    ) == []
    assert _evidence_reader_invocations(
        "python3 /tmp/ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 2"
    ) == []
    assert _evidence_reader_invocations(
        "./python3 ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 2"
    ) == []
    assert _evidence_reader_invocations(
        "/tmp/bash -lc 'python3 ANGERONA_EVIDENCE_READ.py "
        "--path a.java --start 1 --end 2'"
    ) == []


def test_claude_bash_tool_turn_is_normalized_for_evidence_ledgers():
    events = [
        {
            "type": "assistant",
            "message": {"content": [{
                "type": "tool_use",
                "id": "call-1",
                "name": "Bash",
                "input": {"command": "python3 ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 1"},
            }]},
        },
        {
            "type": "user",
            "message": {"content": [{
                "type": "tool_result",
                "tool_use_id": "call-1",
                "content": "00000001: evidence\nANGERONA_FILE_READ_V1 receipt",
                "is_error": False,
            }]},
            "tool_use_result": {"stdout": "evidence", "interrupted": False},
        },
    ]

    assert _provider_command_records(events) == [{
        "command": "python3 ANGERONA_EVIDENCE_READ.py --path a.java --start 1 --end 1",
        "call_id": "call-1",
        "started_time_ns": None,
        "output": "00000001: evidence\nANGERONA_FILE_READ_V1 receipt",
        "exit_code": 0,
        "provider_status": "completed",
        "succeeded": True,
        "completed_time_ns": None,
        "duration_ms": None,
    }]


def test_extensionless_apk_text_member_is_scheduled_and_mapped(tmp_path):
    import zipfile

    from src.analysis.android_binary_inventory import scan_apk_binary_members

    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/config", b"endpoint=https://example.invalid\n")
    ws = _workspace(tmp_path)
    artifact_root = ws.code_dir / "android_artifacts"
    direct = scan_apk_binary_members(
        apk, export_dir=artifact_root / "binary_payloads"
    )
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.metadata["binary_inventory"] = direct
    materialize_android_ai_evidence(ws, report)
    inventory = json.loads(
        (ws.code_dir / "ANDROID_SOURCE_INVENTORY.json").read_text()
    )
    paths = {item["path"] for item in inventory["files"]}
    assert any(path.endswith("_config") for path in paths)
    assert inventory["apk_member_closure"]["complete"] is True
    assert inventory["apk_member_closure"]["mapped"] == 1


def test_materialize_android_evidence_builds_file_slices(tmp_path):
    ws = _workspace(tmp_path)
    jadx = ws.code_dir / "android_artifacts" / "jadx_bridge" / "sources" / "com" / "acme"
    smali = ws.code_dir / "android_artifacts" / "apktool" / "smali" / "com" / "acme"
    jadx.mkdir(parents=True)
    smali.mkdir(parents=True)
    (jadx / "MainActivity.java").write_text(
        "package com.acme;\nclass MainActivity {}\n", encoding="utf-8"
    )
    (smali / "Secrets.smali").write_text(
        ".class public Lcom/acme/Secrets;\n", encoding="utf-8"
    )
    report = AuditReport(apk_path="target.apk", status="completed")
    report.findings.append(
        AuditFinding(
            module="cleartext_tls_rule",
            kind="cleartext",
            severity="high",
            verdict="LIKELY",
            detail="candidate",
        )
    )

    overview = materialize_android_ai_evidence(ws, report)

    assert overview["source_file_count"] == 2
    inventory = __import__("json").loads(
        (ws.code_dir / "ANDROID_SOURCE_INVENTORY.json").read_text()
    )
    assert {item["suffix"] for item in inventory["files"]} == {".java", ".smali"}
    slices = __import__("json").loads(
        (ws.raw_dir / "security_slices.json").read_text()
    )
    scheduled = {
        path
        for item in slices["slices"]
        if item["slice_id"].startswith("android-files-")
        for path in item["ai_scope"]["allowed_inputs"]
    }
    assert scheduled == {item["path"] for item in inventory["files"]}
    reader = ws.code_dir / "ANGERONA_EVIDENCE_READ.py"
    result = subprocess.run(
        [
            sys.executable,
            str(reader),
            "--path",
            inventory["files"][0]["path"],
            "--start",
            "1",
            "--end",
            str(inventory["files"][0]["lines"]),
        ],
        cwd=ws.code_dir,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "ANGERONA_FILE_READ_V1 " in result.stdout
    assert result.stdout.rstrip().splitlines()[-1].startswith("ANGERONA_FILE_READ_V1 ")


def test_android_coverage_requires_every_file_slice_to_converge():
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java"}, {"path": "b.smali"}],
    }
    slices = {
        "slices": [
            {
                "slice_id": "android-files-01",
                "ai_scope": {"allowed_inputs": ["a.java"]},
            },
            {
                "slice_id": "android-files-02",
                "ai_scope": {"allowed_inputs": ["b.smali"]},
            },
        ]
    }
    worker = lambda slice_id, converged: type(
        "Outcome", (), {
            "spec": type("Spec", (), {"id": slice_id, "slice_id": slice_id})(),
            "converged": converged,
        }
    )()
    swarm = type("Swarm", (), {
        "workers": [
            worker("android-files-01", True),
            worker("android-files-02", False),
        ]
    })()

    coverage = _coverage_after_swarm(inventory, slices, swarm)

    assert coverage["coverage_complete"] is False
    # Reviewer convergence alone is not proof that either model opened a file.
    assert coverage["worker_slice_verified_files"] == 0
    assert coverage["missing_files"] == ["a.java", "b.smali"]


def test_android_coverage_empty_inventory_is_incomplete():
    swarm = type("Swarm", (), {"workers": []})()
    coverage = _coverage_after_swarm(
        {"truncated": False, "files": []}, {"slices": []}, swarm
    )
    assert coverage["coverage_complete"] is False
    assert coverage["inventory_empty"] is True


def test_android_coverage_blocks_when_one_deterministic_finding_is_omitted():
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "lines": 1, "analysis_complete": True}],
    }
    slices = {"slices": [
        {"slice_id": "android-files-01", "ai_scope": {"allowed_inputs": ["a.java"]}},
        {
            "slice_id": "android-findings-corroboration",
            "ai_scope": {"finding_ids": ["finding-a", "finding-b"]},
        },
    ]}
    worker = lambda worker_id, slice_id: type("Outcome", (), {
        "spec": type("Spec", (), {"id": worker_id, "slice_id": slice_id})(),
        "converged": True,
    })()
    swarm = type("Swarm", (), {"workers": [
        worker("files", "android-files-01"),
        worker("findings", "android-findings-corroboration"),
    ]})()
    reads = [
        {
            "worker_id": "files", "slice_id": "android-files-01", "role": role,
            "path": "a.java", "mode": "text_lines", "start_line": 1,
            "end_line": 1, "status": "verified",
        }
        for role in ("analyst", "reviewer")
    ]
    finding_inventory = {
        "schema_version": 1,
        "finding_count": 2,
        "findings": [
            {"finding_id": "finding-a", "fingerprint": "a" * 64},
            {"finding_id": "finding-b", "fingerprint": "b" * 64},
        ],
    }
    adjudications = [
        {
            "worker_id": "findings", "slice_id": "android-findings-corroboration",
            "finding_id": "finding-a", "role": role, "verdict": "confirmed",
            "evidence_path": "a.java", "status": "verified",
        }
        for role in ("analyst", "reviewer")
    ]

    coverage = _coverage_after_swarm(
        inventory, slices, swarm, reads, finding_inventory, adjudications
    )

    assert coverage["worker_slice_verified_files"] == 1
    assert coverage["deterministic_findings_verified"] == 1
    assert coverage["missing_finding_ids"] == ["finding-b"]
    assert coverage["coverage_complete"] is False


def test_overall_completion_ands_static_runtime_and_ai_gates():
    report = AuditReport(apk_path="target.apk", status="completed")
    report.metadata["coverage_gate"] = {
        "manifest_decoded": True, "static_code_covered": True,
        "origin_anchored": True, "runtime_required": False,
        "runtime_complete": True,
    }
    complete = _evaluate_android_completion(
        report, {"coverage_complete": True}, model_swarm_converged=True
    )
    assert complete["overall_complete"] is True
    report.status = "partial"
    assert _evaluate_android_completion(
        report, {"coverage_complete": True}, model_swarm_converged=True
    )["overall_complete"] is False


def test_explicit_runtime_failure_blocks_total_even_without_static_escalation():
    report = AuditReport(apk_path="target.apk", status="completed")
    report.metadata["runtime_requested"] = True
    report.metadata["runtime_escalation"] = {"required": False}
    report.metadata["coverage_gate"] = {
        "manifest_decoded": True,
        "static_code_covered": True,
        "origin_anchored": True,
        "runtime_required": True,
        "runtime_complete": False,
    }
    report.runtime_extract_status = "target_prepare_failed"
    result = _evaluate_android_completion(
        report, {"coverage_complete": True}, model_swarm_converged=True
    )
    assert result["runtime_required"] is True
    assert result["overall_complete"] is False
    report.status = "completed"
    report.metadata["runtime_escalation"] = {"required": True}
    report.runtime_extract_status = "ok"
    report.metadata["coverage_gate"]["runtime_complete"] = False
    assert _evaluate_android_completion(
        report, {"coverage_complete": True}, model_swarm_converged=True
    )["overall_complete"] is False


def test_native_hash_attestation_without_derived_evidence_is_incomplete():
    inventory = {
        "truncated": False,
        "files": [
            {
                "path": "lib.so", "lines": None, "review_mode": "native_artifact",
                "sha256": "a" * 64, "analysis_complete": True,
                "required_evidence": ["ida.txt"],
            },
            {
                "path": "ida.txt", "lines": 2, "review_mode": "text_lines",
                "sha256": "b" * 64, "analysis_complete": True,
            },
        ],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["lib.so", "ida.txt"]},
    }]}
    worker = lambda: type("Outcome", (), {
        "spec": type("Spec", (), {"id": "w", "slice_id": "android-files-01"})(),
        "converged": True,
    })()
    reads = [
        {"worker_id": "w", "slice_id": "android-files-01", "role": role,
         "path": "lib.so", "mode": "native_artifact", "status": "verified"}
        for role in ("analyst", "reviewer")
    ]
    coverage = _coverage_after_swarm(
        inventory, slices, type("Swarm", (), {"workers": [worker()]})(), reads
    )
    assert coverage["coverage_complete"] is False
    assert coverage["file_reviews"][1]["analyst_read_complete"] is False


def test_evidence_reader_rejects_oversized_line_chunk(tmp_path):
    ws = _workspace(tmp_path)
    artifact = ws.code_dir / "android_artifacts" / "large.txt"
    artifact.parent.mkdir(parents=True)
    artifact.write_text("\n".join(f"line-{index}" for index in range(401)), encoding="utf-8")
    report = AuditReport(apk_path="target.apk", status="completed")
    materialize_android_ai_evidence(ws, report)
    result = subprocess.run(
        [sys.executable, str(ws.code_dir / "ANGERONA_EVIDENCE_READ.py"),
         "--path", "android_artifacts/large.txt", "--start", "1", "--end", "401"],
        cwd=ws.code_dir, text=True, capture_output=True, check=False,
    )
    assert result.returncode == 2
    assert "at most 400 lines" in result.stderr
    assert "ANGERONA_FILE_READ_V1" not in result.stdout


def _worker(tmp_path: Path, *, converged: bool = True):
    root = tmp_path / "worker"
    (root / "raw").mkdir(parents=True)
    (root / "code").mkdir()
    (root / "code" / "ANGERONA_EVIDENCE_READ.py").write_text(
        _EVIDENCE_READER_SOURCE, encoding="utf-8"
    )
    return type(
        "Outcome",
        (),
        {
            "spec": type(
                "Spec", (), {"id": "worker-1", "slice_id": "android-files-01"}
            )(),
            "converged": converged,
            "workspace_root": str(root),
        },
    )()


def _read_marker(path: str, payload: bytes, *, start: int, end: int) -> str:
    source_lines = payload.decode("utf-8", errors="replace").split("\n")
    rendered = "\n".join(
        f"{number:08d}: {source_lines[number - 1]}"
        for number in range(start, end + 1)
    )
    meta = {
        "schema_version": 1,
        "path": path,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "bytes": len(payload),
        "lines": payload.count(b"\n") + 1,
        "mode": "text_lines",
        "start_line": start,
        "end_line": end,
        "full_file": start == 1 and end == payload.count(b"\n") + 1,
        "chunk_sha256": hashlib.sha256(rendered.encode()).hexdigest(),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(meta, sort_keys=True, separators=(",", ":")).encode()
    ).decode()
    return f"{rendered}\nANGERONA_FILE_READ_V1 {encoded}\n"


def _command_event(
    output: str, *, exit_code: int = 0, start: int = 1, end: int = 2
) -> dict:
    return {
        "type": "item.completed",
        "_angerona_started_time_ns": 1_000_000_000,
        "_angerona_received_time_ns": 1_250_000_000,
        "_angerona_duration_ms": 250.0,
        "item": {
            "id": "call-1",
            "type": "command_execution",
            "command": (
                "python3 ANGERONA_EVIDENCE_READ.py --path a.java "
                f"--start {start} --end {end}"
            ),
            "aggregated_output": output,
            "exit_code": exit_code,
            "status": "completed",
        },
    }


def test_android_coverage_requires_hash_matched_full_read_and_reviewer_reopen(tmp_path):
    payload = b"first\nsecond"
    digest = hashlib.sha256(payload).hexdigest()
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "suffix": ".java", "bytes": len(payload),
                   "lines": 2, "sha256": digest}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    worker = _worker(tmp_path)
    (Path(worker.workspace_root) / "code" / "a.java").write_bytes(payload)
    marker = _read_marker("a.java", payload, start=1, end=2)
    for role in ("analyst", "review"):
        (Path(worker.workspace_root) / "raw" / f"round_1_{role}.events.json").write_text(
            json.dumps([_command_event(marker)]), encoding="utf-8"
        )
    swarm = type("Swarm", (), {"workers": [worker]})()

    tool_calls, file_reads = _collect_worker_ledgers(inventory, swarm)
    coverage = _coverage_after_swarm(inventory, slices, swarm, file_reads)

    assert len(tool_calls) == 2
    assert tool_calls[0]["duration_ms"] == 250.0
    assert tool_calls[0]["started_time_ns"] == 1_000_000_000
    assert tool_calls[0]["completed_time_ns"] == 1_250_000_000
    assert {item["role"] for item in file_reads} == {"analyst", "reviewer"}
    assert coverage["coverage_complete"] is True
    assert coverage["file_reviews"][0]["analyst_read_complete"] is True
    assert coverage["file_reviews"][0]["reviewer_reopened"] is True
    assert coverage["file_reviews"][0]["reviewer_read_complete"] is True


def test_android_coverage_rejects_hash_mismatch_and_records_failed_tool(tmp_path):
    payload = b"first\nsecond"
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "suffix": ".java", "bytes": len(payload),
                   "lines": 2, "sha256": hashlib.sha256(payload).hexdigest()}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    worker = _worker(tmp_path)
    (Path(worker.workspace_root) / "code" / "a.java").write_bytes(payload)
    raw = Path(worker.workspace_root) / "raw"
    (raw / "round_1_analyst.events.json").write_text(
        json.dumps([_command_event(_read_marker("a.java", b"tampered", start=1, end=1))]),
        encoding="utf-8",
    )
    (raw / "round_1_review.events.json").write_text(
        json.dumps([_command_event("permission denied", exit_code=13)]), encoding="utf-8"
    )
    swarm = type("Swarm", (), {"workers": [worker]})()

    tool_calls, file_reads = _collect_worker_ledgers(inventory, swarm)
    coverage = _coverage_after_swarm(inventory, slices, swarm, file_reads)

    assert [item["status"] for item in tool_calls] == ["succeeded", "failed"]
    assert file_reads[0]["status"] == "rejected"
    assert coverage["coverage_complete"] is False
    assert coverage["missing_files"] == ["a.java"]


def test_android_coverage_rejects_marker_only_transcript(tmp_path):
    payload = b"first\nsecond"
    inventory = {"truncated": False, "files": [{
        "path": "a.java", "suffix": ".java", "bytes": len(payload), "lines": 2,
        "sha256": hashlib.sha256(payload).hexdigest(),
    }]}
    slices = {"slices": [{
        "slice_id": "android-files-01", "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    worker = _worker(tmp_path)
    (Path(worker.workspace_root) / "code" / "a.java").write_bytes(payload)
    full = _read_marker("a.java", payload, start=1, end=2)
    receipt_only = full.strip().splitlines()[-1] + "\n"
    for role in ("analyst", "review"):
        (Path(worker.workspace_root) / "raw" / f"round_1_{role}.events.json").write_text(
            json.dumps([_command_event(receipt_only)]), encoding="utf-8"
        )
    swarm = type("Swarm", (), {"workers": [worker]})()
    _calls, reads = _collect_worker_ledgers(inventory, swarm)
    assert all(item["status"] == "rejected" for item in reads)
    assert _coverage_after_swarm(inventory, slices, swarm, reads)["coverage_complete"] is False


def test_materialization_detects_apk_identity_change(tmp_path):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"original")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(b"original").hexdigest()
    }
    apk.write_bytes(b"replaced")
    materialize_android_ai_evidence(ws, report)
    assert report.metadata["apk_identity_gate"]["status"] == "mismatch"
    assert any("APK identity changed" in item for item in report.refusal_reasons)


def test_final_commit_rechecks_apk_identity(tmp_path):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"initial")
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(b"initial").hexdigest()
    }
    apk.write_bytes(b"changed-during-swarm")
    gate = _revalidate_apk_identity(report, apk)
    assert gate["valid"] is False
    assert report.status == "partial"
    assert report.metadata["apk_identity_final_gate"]["status"] == "mismatch"


def test_structured_finding_receipts_require_both_active_roles(tmp_path):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"apk")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.findings.append(AuditFinding(
        module="tls", kind="cleartext", severity="high", verdict="LIKELY",
        detail="cleartext traffic candidate",
    ))
    materialize_android_ai_evidence(ws, report)
    finding_inventory = json.loads(
        (ws.code_dir / "ANDROID_FINDING_INVENTORY.json").read_text()
    )
    finding_id = finding_inventory["findings"][0]["finding_id"]
    command = (
        "python3 ANGERONA_FINDING_ADJUDICATE.py "
        f"--finding-id {finding_id} --verdict inconclusive "
        "--evidence-path ANDROID_AUDIT.json"
    )
    result = subprocess.run(
        command.split(), cwd=ws.code_dir, text=True, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr
    event = {
        "type": "item.completed",
        "item": {
            "id": "finding-call",
            "type": "command_execution",
            "command": command,
            "aggregated_output": result.stdout,
            "exit_code": 0,
            "status": "completed",
        },
    }
    for role in ("analyst", "review"):
        (ws.raw_dir / f"round_1_{role}.events.json").write_text(json.dumps([event]))
    outcome = type("Outcome", (), {
        "spec": type("Spec", (), {
            "id": "finding-worker", "slice_id": "android-findings-corroboration"
        })(),
        "workspace_root": str(ws.root),
        "converged": True,
    })()
    inventory = json.loads((ws.code_dir / "ANDROID_SOURCE_INVENTORY.json").read_text())

    rows = _collect_finding_adjudications(
        inventory, finding_inventory, type("Swarm", (), {"workers": [outcome]})()
    )

    assert len(rows) == 2
    assert {row["role"] for row in rows} == {"analyst", "reviewer"}
    assert all(row["status"] == "verified" for row in rows)


def test_finding_inventory_rejects_forged_subset_and_audit_mutation(tmp_path):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"apk")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.findings.append(AuditFinding(
        module="tls", kind="cleartext", severity="high", verdict="LIKELY",
        detail="controller finding that must remain in terminal closure",
    ))
    materialize_android_ai_evidence(ws, report)
    inventory_path = ws.code_dir / "ANDROID_FINDING_INVENTORY.json"
    inventory = json.loads(inventory_path.read_text())
    assert _validate_finding_inventory(report, ws.code_dir, inventory)["valid"] is True

    forged = dict(inventory)
    forged["finding_count"] = 0
    forged["findings"] = []
    assert _validate_finding_inventory(report, ws.code_dir, forged)["valid"] is False

    audit_path = ws.code_dir / "ANDROID_AUDIT.json"
    audit = json.loads(audit_path.read_text())
    audit["findings"][0]["severity"] = "low"
    audit_path.write_text(json.dumps(audit, indent=2, default=str) + "\n")
    forged_hash = dict(inventory)
    forged_hash["audit_sha256"] = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    assert _validate_finding_inventory(report, ws.code_dir, forged_hash)["valid"] is False


@pytest.mark.parametrize("verification_fails", [False, True])
def test_terminal_completion_is_bound_to_observability_verification(
    tmp_path, monkeypatch, verification_fails
):
    apk = tmp_path / "target.apk"
    apk.write_bytes(b"immutable-apk")
    ws = _workspace(tmp_path)
    report = AuditReport(apk_path=str(apk), status="completed")
    report.metadata["artifact_validation"] = {
        "sha256": hashlib.sha256(apk.read_bytes()).hexdigest()
    }
    report.metadata["coverage_gate"] = {
        "manifest_decoded": True,
        "static_code_covered": True,
        "origin_anchored": True,
        "runtime_required": False,
        "runtime_complete": True,
    }

    def fake_materialize(workspace, _report):
        audit_path = workspace.code_dir / "ANDROID_AUDIT.json"
        audit_path.write_text(
            json.dumps(_report.as_dict(), indent=2, default=str) + "\n"
        )
        (workspace.code_dir / "ANDROID_SOURCE_INVENTORY.json").write_text(
            json.dumps({"files": [{"path": "a.java"}], "truncated": False})
        )
        (workspace.code_dir / "ANDROID_FINDING_INVENTORY.json").write_text(
            json.dumps({
                "schema_version": 1,
                "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                "finding_count": 0,
                "findings": [],
            })
        )
        (workspace.raw_dir / "security_slices.json").write_text(
            json.dumps({"slices": []})
        )
        return {"source_file_count": 1}

    coverage = {
        "coverage_complete": True,
        "inventory_files": 1,
        "worker_slice_verified_files": 1,
        "missing_files": [],
        "inventory_truncated": False,
        "inventory_empty": False,
        "deterministic_findings_expected": 0,
        "deterministic_findings_verified": 0,
        "missing_finding_ids": [],
        "deterministic_finding_closure_complete": True,
    }
    swarm = SwarmResult(
        converged=True,
        supervisor_rounds=1,
        workers=[],
        workspace=ws,
        final_report="## Summary\nall gates initially green",
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.materialize_android_ai_evidence",
        fake_materialize,
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.ClaudeCodeAgent.available", lambda _self: True
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.SupervisorLoop.run", lambda _self: swarm
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._collect_worker_ledgers",
        lambda _inventory, _swarm: ([], []),
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._collect_finding_adjudications",
        lambda _inventory, _findings, _swarm: [],
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._coverage_after_swarm",
        lambda *_args, **_kwargs: dict(coverage),
    )
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit._validate_finding_inventory",
        lambda *_args, **_kwargs: {"valid": True, "reason": ""},
    )
    if verification_fails:
        monkeypatch.setattr(
            ws.observability,
            "verify",
            lambda: (_ for _ in ()).throw(RuntimeError("ledger-corrupt")),
        )

    outcome = run_android_ai_swarm(
        apk_path=apk, report=report, workspace=ws, rounds=1, parallel=1
    )

    run_meta = json.loads((ws.root / "run.json").read_text())
    completion = json.loads(
        (ws.raw_dir / "ANDROID_RUN_COMPLETION.json").read_text()
    )
    if verification_fails:
        assert outcome.swarm.converged is False
        assert run_meta["status"] == "incomplete"
        assert run_meta["converged"] is False
        assert completion["overall_complete"] is False
        assert completion["observability_verification"]["valid"] is False
        assert "Observability verification failed" in (
            ws.docs_dir / "consolidated_report.md"
        ).read_text()
    else:
        assert outcome.swarm.converged is True
        assert run_meta["status"] == "completed"
        assert run_meta["converged"] is True
        assert completion["overall_complete"] is True
        assert completion["observability_verification"]["valid"] is True
        assert run_meta["terminal_commit_id"] == completion["terminal_commit_id"]
        assert run_meta["android_ai_completion"] == completion


def test_android_coverage_rejects_partial_analyst_line_ranges(tmp_path):
    payload = b"first\nsecond\nthird"
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "suffix": ".java", "bytes": len(payload),
                   "lines": 3, "sha256": hashlib.sha256(payload).hexdigest()}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    worker = _worker(tmp_path)
    (Path(worker.workspace_root) / "code" / "a.java").write_bytes(payload)
    raw = Path(worker.workspace_root) / "raw"
    (raw / "round_1_analyst.events.json").write_text(
        json.dumps([_command_event(_read_marker("a.java", payload, start=1, end=2))]),
        encoding="utf-8",
    )
    (raw / "round_1_review.events.json").write_text(
        json.dumps([
            _command_event(
                _read_marker("a.java", payload, start=2, end=2), start=2, end=2
            )
        ]),
        encoding="utf-8",
    )
    swarm = type("Swarm", (), {"workers": [worker]})()

    _tool_calls, file_reads = _collect_worker_ledgers(inventory, swarm)
    coverage = _coverage_after_swarm(inventory, slices, swarm, file_reads)

    assert coverage["coverage_complete"] is False
    assert coverage["file_reviews"][0]["analyst_read_complete"] is False
    assert coverage["file_reviews"][0]["reviewer_reopened"] is True
    assert coverage["file_reviews"][0]["reviewer_read_complete"] is False


def test_android_coverage_does_not_lend_reads_between_worker_attempts():
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "suffix": ".java", "bytes": 1,
                   "lines": 1, "sha256": "a" * 64}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    outcome = lambda worker_id, converged: type(
        "Outcome", (), {
            "spec": type(
                "Spec", (), {"id": worker_id, "slice_id": "android-files-01"}
            )(),
            "converged": converged,
        }
    )()
    swarm = type("Swarm", (), {"workers": [
        outcome("read-but-failed", False), outcome("converged-without-reads", True)
    ]})()
    file_reads = [
        {
            "worker_id": "read-but-failed",
            "slice_id": "android-files-01",
            "role": role,
            "path": "a.java",
            "mode": "text_lines",
            "start_line": 1,
            "end_line": 1,
            "status": "verified",
        }
        for role in ("analyst", "reviewer")
    ]

    coverage = _coverage_after_swarm(inventory, slices, swarm, file_reads)

    assert coverage["coverage_complete"] is False
    assert coverage["missing_files"] == ["a.java"]


def test_android_coverage_does_not_lend_roles_between_active_siblings():
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "suffix": ".java", "bytes": 1,
                   "lines": 1, "sha256": "a" * 64}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    def outcome(worker_id):
        return type("Outcome", (), {
            "spec": type("Spec", (), {
                "id": worker_id, "slice_id": "android-files-01",
            })(),
            "converged": True,
        })()
    swarm = type("Swarm", (), {"workers": [outcome("a"), outcome("b")]})()
    file_reads = [
        {"worker_id": "a", "slice_id": "android-files-01", "role": "analyst",
         "path": "a.java", "mode": "text_lines", "start_line": 1,
         "end_line": 1, "status": "verified"},
        {"worker_id": "b", "slice_id": "android-files-01", "role": "reviewer",
         "path": "a.java", "mode": "text_lines", "start_line": 1,
         "end_line": 1, "status": "verified"},
    ]

    coverage = _coverage_after_swarm(inventory, slices, swarm, file_reads)

    assert coverage["coverage_complete"] is False
    assert coverage["file_reviews"][0]["same_worker_ids"] == []


def test_android_coverage_fails_closed_on_invalid_active_lineage(monkeypatch):
    inventory = {
        "truncated": False,
        "files": [{"path": "a.java", "lines": 1, "analysis_complete": True}],
    }
    slices = {"slices": [{
        "slice_id": "android-files-01",
        "ai_scope": {"allowed_inputs": ["a.java"]},
    }]}
    worker = type("Outcome", (), {
        "spec": type("Spec", (), {"id": "old", "slice_id": "android-files-01"})(),
        "converged": True,
    })()
    monkeypatch.setattr(
        "src.pipeline.android_ai_audit.project_active_worker_outcomes",
        lambda _workers: (_ for _ in ()).throw(RuntimeError("ambiguous-lineage")),
    )
    reads = [
        {
            "worker_id": "old", "slice_id": "android-files-01", "role": role,
            "path": "a.java", "mode": "text_lines", "start_line": 1,
            "end_line": 1, "status": "verified",
        }
        for role in ("analyst", "reviewer")
    ]
    coverage = _coverage_after_swarm(
        inventory, slices, type("Swarm", (), {"workers": [worker]})(), reads
    )
    assert coverage["coverage_complete"] is False
    assert coverage["active_lineage_valid"] is False
