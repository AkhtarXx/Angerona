from __future__ import annotations

import hashlib
import shutil
import struct
import zipfile
import zlib

from src.execution.runtime_dex_extractor import (
    _baseline_workload_ledger,
    _devices,
    _frida_command,
    _packaged_dex_baseline,
    _parse_events,
    _prepare_runtime_target,
    _runtime_coverage_is_complete,
    extract_dex_runtime,
    write_agent,
)


def _valid_dex() -> bytes:
    blob = bytearray(112)
    blob[:8] = b"dex\n035\x00"
    struct.pack_into("<I", blob, 32, len(blob))
    struct.pack_into("<I", blob, 36, 0x70)
    struct.pack_into("<I", blob, 40, 0x12345678)
    blob[12:32] = hashlib.sha1(blob[32:]).digest()
    struct.pack_into("<I", blob, 8, zlib.adler32(blob[12:]) & 0xFFFFFFFF)
    return bytes(blob)


def test_agent_written(tmp_path):
    agent = write_agent(
        tmp_path, device_drop_dir="/data/local/tmp/angerona-dex-test123"
    )
    assert agent.exists()
    text = agent.read_text()
    assert "BaseDexClassLoader" in text
    assert "ANGERONA_DEX_EVENT" in text
    assert "agent-ready" in text
    assert "/data/local/tmp/angerona-dex-test123" in text
    assert "__ANGERONA_DROP_DIR__" not in text
    assert "67108864" in text
    assert "findGlobalExportByName" in text
    assert "findExportByName" not in text


def test_frida_17_command_omits_removed_no_pause_flag(tmp_path):
    command = _frida_command(
        "/venv/bin/frida", "emulator-5554", "com.example.app",
        tmp_path / "agent.js", spawn=True,
    )
    assert command[:5] == [
        "/venv/bin/frida", "-D", "emulator-5554", "-f", "com.example.app",
    ]
    assert "--no-pause" not in command

    forwarded = _frida_command(
        "/venv/bin/frida", "emulator-5554", "com.example.app",
        tmp_path / "agent.js", spawn=True,
        host_endpoint="127.0.0.1:37123",
    )
    assert forwarded[:5] == [
        "/venv/bin/frida", "-H", "127.0.0.1:37123", "-f", "com.example.app",
    ]
    assert "-D" not in forwarded

    # Authentication is passed through FRIDA_TOKEN in the subprocess
    # environment, keeping the secret out of argv and observability logs.
    assert "--token" not in forwarded


def test_baseline_workload_complete_is_bounded_to_primary_launch_and_hooks():
    required = {
        "dexfile-hook-installed", "bdcl-hook-installed", "imcl-hook-installed",
    }
    events = [
        {"event": "agent-ready"},
        *({"event": event} for event in sorted(required)),
        {"event": "observation-window-complete"},
    ]
    samples = [
        {
            "event": "process-sample", "success": True, "terminal": False,
            "elapsed_ms": 0, "processes": [],
        },
        {
            "event": "process-sample", "success": True, "terminal": False,
            "elapsed_ms": 1000,
            "processes": [{"pid": 123, "name": "com.example.app"}],
        },
        {
            "event": "process-sample", "success": True, "terminal": True,
            "elapsed_ms": 2000,
            "processes": [{"pid": 123, "name": "com.example.app"}],
        },
    ]
    ledger = _baseline_workload_ledger(
        "com.example.app", spawn=True, wait_seconds=2,
        controller_window_complete=True, process_exited_early=False,
        events=events, process_samples=samples, required_hooks=required,
    )
    assert ledger["complete"] is True
    assert ledger["process_observation_complete"] is True
    assert ledger["hook_health_complete"] is True
    assert ledger["workload_id"] == "baseline-launch-idle-v1"
    assert ledger["claims_excluded"]


def test_baseline_workload_refuses_secondary_or_unsampled_processes():
    required = {
        "dexfile-hook-installed", "bdcl-hook-installed", "imcl-hook-installed",
    }
    events = [
        {"event": "agent-ready"},
        *({"event": event} for event in sorted(required)),
        {"event": "observation-window-complete"},
    ]
    samples = [
        {
            "event": "process-sample", "success": True, "terminal": False,
            "elapsed_ms": 1000,
            "processes": [
                {"pid": 123, "name": "com.example.app"},
                {"pid": 124, "name": "com.example.app:remote"},
            ],
        },
        {
            "event": "process-sample", "success": True, "terminal": True,
            "elapsed_ms": 2000,
            "processes": [{"pid": 123, "name": "com.example.app"}],
        },
    ]
    ledger = _baseline_workload_ledger(
        "com.example.app", spawn=True, wait_seconds=2,
        controller_window_complete=True, process_exited_early=False,
        events=events, process_samples=samples, required_hooks=required,
    )
    assert ledger["complete"] is False
    assert "secondary-package-process-observed-but-not-instrumented" in ledger["reasons"]


def test_runtime_coverage_rejects_frida_output_truncated_during_terminal_drain():
    otherwise_complete = {
        "dumped_files": ["/evidence/novel.dex"],
        "agent_ready": True,
        "failure_events": [],
        "packaged_baseline_errors": [],
        "native_lane_complete": True,
        "containment_complete": True,
        "frida_transport_complete": True,
        "workload_complete": True,
    }
    assert _runtime_coverage_is_complete(
        **otherwise_complete, stdout_truncated=False,
    ) is True
    assert _runtime_coverage_is_complete(
        **otherwise_complete, stdout_truncated=True,
    ) is False


def test_no_frida_missing(monkeypatch):
    monkeypatch.setattr("src.execution.runtime_dex_extractor.find_frida", lambda cfg=None: None)
    r = extract_dex_runtime("com.x")
    assert r.status == "frida_missing"
    assert r.trust == "untrusted_child"


def test_connected_provider_requires_explicit_authorized_serial(monkeypatch):
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.find_frida",
        lambda cfg=None: "/usr/bin/frida",
    )
    result = extract_dex_runtime(
        "com.example.target", runtime_provider="connected", wait_seconds=1,
    )
    assert result.status == "target_prepare_failed"
    assert "explicit authorized device serial" in result.note


def test_parse_events_filtering():
    lines = [
        'ANGERONA_DEX_EVENT {"event":"agent-ready"}',
        '{"type":"dex-extractor","payload":{"event":"agent-ready"}}',
        '{"type":"dex-extractor","payload":{"event":"dumped","tag":"loaded","path":"/data/local/tmp/x.dex","size":4096}}',
        'noise line',
        '   ',
        'garbage json {bad}',
        '{"type":"other","payload":{"event":"not-us"}}',
    ]
    events = _parse_events(lines)
    assert len(events) == 3
    assert events[0]["event"] == "agent-ready"
    assert events[2]["size"] == 4096


def test_parse_events_handles_junk():
    events = _parse_events([b"".decode() for b in []])
    assert events == []


def test_extraction_status_no_device(monkeypatch, tmp_path):
    # When no adb device is connected — extraction reports device_missing.
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.find_frida",
        lambda cfg=None: "/usr/bin/frida",
    )
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._devices",
        lambda serial_override="": [],
    )
    r = extract_dex_runtime("com.x", wait_seconds=1, out_dir=tmp_path)
    assert r.status == "device_missing"


def test_device_drop_dir_is_scoped(monkeypatch, tmp_path):
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor.find_frida", lambda cfg=None: "/usr/bin/frida"
    )
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._devices", lambda serial_override="": ["device-1"]
    )
    r = extract_dex_runtime(
        "com.x", serial="device-1", out_dir=tmp_path,
        device_drop_dir="/sdcard/shared-dumps"
    )
    assert r.status == "error"
    assert "scoped" in r.note


def test_packaged_dex_baseline_is_magic_first(tmp_path):
    apk = tmp_path / "target.apk"
    dex = _valid_dex()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/no_extension", dex)
    raw, normalized, errors = _packaged_dex_baseline(apk)
    assert errors == []
    assert hashlib.sha256(dex).hexdigest() in raw
    rewritten = bytearray(dex)
    rewritten[8:32] = b"\x00" * 24
    assert hashlib.sha256(rewritten).hexdigest() in normalized


def test_packaged_dex_baseline_ignores_textual_dex_substrings(tmp_path):
    apk = tmp_path / "metadata.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr(
            "kotlin/collections/collections.kotlin_builtins",
            b"metadata prefix dex\nnot-a-version suffix",
        )
    raw, normalized, errors = _packaged_dex_baseline(apk)
    assert raw == set()
    assert normalized == set()
    assert errors == []


def test_packaged_dex_baseline_streams_large_member_and_cross_chunk_header(
    monkeypatch, tmp_path,
):
    apk = tmp_path / "streamed.apk"
    dex = _valid_dex()
    chunk_bytes = 1024 * 1024
    with (
        zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_STORED) as archive,
        archive.open("assets/large-payload.bin", "w") as member,
    ):
        for _ in range(12):
            member.write(b"A" * chunk_bytes)
        # Split the eight-byte DEX signature across the scanner's chunk
        # boundary without constructing a 12+ MiB member in Python memory.
        member.write(b"B" * (chunk_bytes - 4))
        member.write(dex)

    def whole_member_read_forbidden(*args, **kwargs):
        raise AssertionError("baseline must stream ZipExtFile members")

    monkeypatch.setattr(zipfile.ZipFile, "read", whole_member_read_forbidden)
    raw, normalized, errors = _packaged_dex_baseline(apk)
    assert errors == []
    assert hashlib.sha256(dex).hexdigest() in raw
    rewritten = bytearray(dex)
    rewritten[8:32] = b"\x00" * 24
    assert hashlib.sha256(rewritten).hexdigest() in normalized


def test_packaged_dex_baseline_marks_candidate_cap_incomplete(tmp_path):
    apk = tmp_path / "too-many-candidates.apk"
    dex = _valid_dex()
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/dex-bundle.bin", dex * 65)
    raw, normalized, errors = _packaged_dex_baseline(apk)
    assert raw == set()
    assert normalized == set()
    assert any("dex-candidate-cap-exceeded:64" in error for error in errors)


def test_packaged_dex_baseline_marks_scan_budget_incomplete(monkeypatch, tmp_path):
    apk = tmp_path / "over-budget.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("assets/blob.bin", b"A" * 4096)
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._MAX_PACKAGED_MEMBER_SCAN_BYTES", 1024,
    )
    raw, normalized, errors = _packaged_dex_baseline(apk)
    assert raw == set()
    assert normalized == set()
    assert any("member-scan-budget-exceeded" in error for error in errors)


def test_runtime_cleanup_runs_after_unexpected_exception(monkeypatch):
    calls = []

    def boom(package, **kwargs):
        lifecycle = kwargs["_lifecycle"]
        lifecycle.update({
            "serial": "emulator-5554",
            "package": package,
            "device_drop_dir": "/data/local/tmp/angerona-dex-test",
            "runtime_target": {"installed_by_angerona": True},
        })
        raise RuntimeError("synthetic failure")

    def fake_adb(args, serial="", timeout=30):
        calls.append((list(args), serial))
        return (0, "Success")

    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._extract_dex_runtime_impl", boom
    )
    monkeypatch.setattr("src.execution.runtime_dex_extractor._adb", fake_adb)
    result = extract_dex_runtime("com.example.target")
    assert result.status == "error"
    assert result.runtime_target["cleanup"]["success"] is True
    assert (["uninstall", "com.example.target"], "emulator-5554") in calls


def test_explicit_offline_serial_is_not_trusted(monkeypatch):
    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._adb",
        lambda *args, **kwargs: (0, "List of devices attached\n"),
    )
    assert _devices("emulator-5554") == []


def test_exact_apk_install_pull_hash_abi_and_storage_binding(monkeypatch, tmp_path):
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
        archive.writestr("classes.dex", _valid_dex())
    package_queries = 0

    def fake_adb(args, serial="", timeout=30, **kwargs):
        nonlocal package_queries
        if args[:4] == ["shell", "pm", "path", "com.example.target"]:
            package_queries += 1
            if package_queries == 1:
                return (1, "")
            return (0, "package:/data/app/example/base.apk\n")
        if args[:2] == ["install", "-t"]:
            return (0, "Success\n")
        if args[0] == "pull":
            shutil.copyfile(apk, args[2])
            return (0, "1 file pulled\n")
        if args[-1] == "ro.product.cpu.abi":
            return (0, "x86_64\n")
        if args[-1] == "ro.build.version.sdk":
            return (0, "35\n")
        if args[-1] == "ro.product.cpu.abilist":
            return (0, "x86_64,x86\n")
        if args[-1] == "ro.dalvik.vm.native.bridge":
            return (0, "0\n")
        if args[:4] == ["shell", "df", "-Pk", "/data"]:
            return (0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/data 4000000 1 3999999 1% /data\n")
        raise AssertionError(args)

    monkeypatch.setattr("src.execution.runtime_dex_extractor._adb", fake_adb)
    target, error = _prepare_runtime_target(
        apk, "com.example.target", "emulator-5554"
    )
    assert error == ""
    assert target["installed_by_angerona"] is True
    assert target["verified_exact_apk"] is True
    assert target["installed_apk_sha256"] == target["apk_sha256"]
    assert target["abi_list"] == ["x86_64", "x86"]
    assert target["native_bridge"] == "0"
    assert target["guest_storage_preflight"]["complete"] is True


def test_managed_target_refuses_preexisting_package_even_if_hash_matches(
    monkeypatch, tmp_path,
):
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")

    def preexisting_adb(args, **kwargs):
        if args[:4] == ["shell", "df", "-Pk", "/data"]:
            return (0, "Filesystem 1024-blocks Used Available Capacity Mounted on\n/data 4000000 1 3999999 1% /data\n")
        return (0, "package:/data/app/example/base.apk\n")

    monkeypatch.setattr(
        "src.execution.runtime_dex_extractor._adb", preexisting_adb,
    )
    target, error = _prepare_runtime_target(
        apk, "com.example.target", "emulator-5554",
        target_metadata={"owned": True},
    )
    assert error == "managed-target-was-not-clean-package-already-present"
    assert target["verified_exact_apk"] is False


def test_managed_target_refuses_apk_changed_after_containment_lease(tmp_path):
    apk = tmp_path / "target.apk"
    with zipfile.ZipFile(apk, "w") as archive:
        archive.writestr("AndroidManifest.xml", "<manifest/>")
    target, error = _prepare_runtime_target(
        apk, "com.example.target", "emulator-5554",
        target_metadata={
            "owned": True,
            "managed_lease": {
                "apk_requirements": {"apk_sha256": "a" * 64},
                "host_containment": {"apk_sha256": "a" * 64},
            },
        },
    )
    assert error == "managed-apk-identity-changed-after-containment-lease"
    assert target["verified_exact_apk"] is False
