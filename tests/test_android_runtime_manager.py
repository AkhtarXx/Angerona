from __future__ import annotations

import hashlib
import json
import os
import socket
import subprocess
import time
import zipfile
from pathlib import Path

import pytest

from src.execution.android_runtime_manager import (
    AndroidRuntimeError,
    AndroidRuntimeManager,
    AndroidRuntimePolicy,
    ApkRuntimeRequirements,
    _choose_abi,
    _ports_unbound,
    _select_emulator_console_port,
    discover_android_toolchain,
    profile_apk,
    verify_host_containment_receipt,
)


def _apk(path: Path, *, abis: tuple[str, ...] = ()) -> Path:
    manifest = (
        '<manifest package="com.example.app" xmlns:android="http://schemas.android.com/apk/res/android">'
        '<uses-sdk android:minSdkVersion="24" android:targetSdkVersion="35"/>'
        "</manifest>"
    )
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("AndroidManifest.xml", manifest)
        archive.writestr("classes.dex", b"dex\n035\x00")
        for abi in abis:
            archive.writestr(f"lib/{abi}/libtarget.so", b"\x7fELF")
    return path


def _toolchain_tree(root: Path) -> None:
    for relative in (
        "platform-tools/adb",
        "emulator/emulator",
        "cmdline-tools/latest/bin/avdmanager",
        "cmdline-tools/latest/bin/sdkmanager",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n")
        path.chmod(0o700)


def _containment_receipt(path: Path, apk: Path) -> tuple[str, str]:
    now = int(time.time())
    payload = {
        "schema": "angerona.android.host-containment/v1",
        "controller": "angerona-worker-controller",
        "worker_id": "test-worker-1",
        "engagement_id": "test-engagement-1",
        "apk_sha256": hashlib.sha256(apk.read_bytes()).hexdigest(),
        "isolated_worker": True,
        "imds_denied": True,
        "egress_policy": {
            "enforced": True,
            "scope": "host+vpc",
            "mode": "deny",
        },
        "issued_at_unix": now - 5,
        "expires_at_unix": now + 3600,
    }
    path.write_text(json.dumps(payload, sort_keys=True))
    path.chmod(0o600)
    return str(path.resolve()), hashlib.sha256(path.read_bytes()).hexdigest()


def _attest_test_receipt_as_controller(monkeypatch) -> None:
    real_fstat = os.fstat

    def root_owned_fstat(fd):
        values = list(real_fstat(fd))
        values[4] = 0  # st_uid
        return os.stat_result(values)

    monkeypatch.setattr(
        "src.execution.android_runtime_manager.os.fstat", root_owned_fstat
    )


def test_profile_apk_records_api_hash_size_and_native_abis(tmp_path):
    apk = _apk(tmp_path / "target.apk", abis=("arm64-v8a", "x86_64"))
    profile = profile_apk(apk)

    assert profile.apk_bytes == apk.stat().st_size
    assert len(profile.apk_sha256) == 64
    assert profile.native_abis == ("arm64-v8a", "x86_64")
    assert profile.min_sdk == 24
    assert profile.target_sdk == 35


def test_discovery_requires_one_coherent_sdk_root(tmp_path):
    sdk = tmp_path / "sdk"
    _toolchain_tree(sdk)
    tools = discover_android_toolchain(str(sdk))
    assert tools.sdk_root == str(sdk.resolve())
    assert Path(tools.adb).is_relative_to(sdk)

    (sdk / "emulator" / "emulator").unlink()
    with pytest.raises(AndroidRuntimeError, match="toolchain-incomplete"):
        discover_android_toolchain(str(sdk))


def test_arm_only_apk_refuses_non_native_x86_host(monkeypatch):
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    requirements = ApkRuntimeRequirements(
        apk_sha256="a" * 64, apk_bytes=1, apk_uncompressed_bytes=1,
        native_abis=("arm64-v8a",)
    )
    with pytest.raises(AndroidRuntimeError, match="native-runner-required"):
        _choose_abi(requirements, AndroidRuntimePolicy())


def test_translation_must_be_an_explicit_exploratory_policy(monkeypatch):
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    requirements = ApkRuntimeRequirements(
        apk_sha256="a" * 64, apk_bytes=1, apk_uncompressed_bytes=1,
        native_abis=("arm64-v8a",)
    )
    chosen = _choose_abi(
        requirements, AndroidRuntimePolicy(allow_native_translation=True)
    )
    assert chosen == "arm64-v8a"


def test_owned_avd_lifecycle_boots_roots_smokes_frida_and_destroys(
    monkeypatch, tmp_path,
):
    _attest_test_receipt_as_controller(monkeypatch)
    apk = _apk(tmp_path / "target.apk")
    sdk = tmp_path / "sdk"
    _toolchain_tree(sdk)
    image = sdk / "system-images" / "android-35" / "default" / "x86_64"
    image.mkdir(parents=True)
    (image / "system.img").write_bytes(b"image")
    frida_server = tmp_path / "frida-server"
    frida_server.write_bytes(b"server")
    containment_path, containment_sha = _containment_receipt(
        tmp_path / "containment.json", apk,
    )
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._free_tcp_port",
        lambda: 5039,
    )
    lock_handle = (tmp_path / "fake-port.lock").open("a+")
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._select_emulator_console_port",
        lambda lock_path: (5554, lock_handle),
    )
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._ports_unbound", lambda ports: True
    )
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._frida_version",
        lambda: ("/venv/bin/frida", "17.16.4"),
    )
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._ensure_frida_server",
        lambda *args, **kwargs: (frida_server, "f" * 64),
    )
    monkeypatch.setattr(
        "src.execution.android_runtime_manager._frida_authenticated_smoke",
        lambda endpoint, token: (True, "enumerated-processes=2"),
    )
    real_read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *args, **kwargs: (
            "0::/user.slice/angerona-avd.scope\n"
            if str(self) == "/proc/4242/cgroup"
            else real_read_text(self, *args, **kwargs)
        ),
    )

    commands: list[list[str]] = []
    process_envs: list[dict[str, str]] = []
    run_envs: list[tuple[list[str], dict[str, str]]] = []
    scope_active = {"value": True}

    def fake_run(command, **kwargs):
        command = [str(item) for item in command]
        commands.append(command)
        run_envs.append((command, dict(kwargs.get("env") or {})))
        stdout = ""
        if command[-1] == "devices":
            stdout = "List of devices attached\nemulator-5554\tdevice\n"
        elif command[-1] in {"sys.boot_completed", "dev.bootcomplete"}:
            stdout = "1\n"
        elif command[-1] == "init.svc.bootanim":
            stdout = "stopped\n"
        elif command[-3:] == ["pm", "path", "android"]:
            stdout = "package:/system/framework/framework-res.apk\n"
        elif command[-2:] == ["id", "-u"]:
            stdout = "0\n"
        elif command[-1] == "--version":
            stdout = "17.16.4\n"
        elif command[-1] == "--help":
            stdout = "--listen=ADDRESS\n--token=TOKEN\n"
        elif command[-3] == "forward" and command[-2] == "tcp:0":
            stdout = "37123\n"
        elif (
            len(command) >= 3
            and command[-3] in {"iptables", "ip6tables"}
            and command[-2:] == ["-S", "OUTPUT"]
        ):
            stdout = "-P OUTPUT DROP\n-A OUTPUT -o lo -j ACCEPT\n"
        elif Path(command[0]).name == "frida-ps":
            stdout = "PID  Name\n1  init\n"
        elif Path(command[0]).name == "systemctl" and "stop" in command:
            scope_active["value"] = False
            stdout = ""
        elif Path(command[0]).name == "systemctl" and "show" in command:
            stdout = (
                f"ActiveState={'active' if scope_active['value'] else 'inactive'}\n"
                "ControlGroup=/user.slice/angerona-avd.scope\n"
                "IPAddressAllow=::1/128 127.0.0.0/8\n"
                "IPAddressDeny=0.0.0.0/0 ::/0\n"
                "MemoryMax=6442450944\nTasksMax=512\n"
            )
        else:
            stdout = "Success\n"
        return subprocess.CompletedProcess(command, 0, stdout, "")

    class FakeProcess:
        def __init__(self, command, **kwargs):
            commands.append([str(item) for item in command])
            process_envs.append(dict(kwargs.get("env") or {}))
            self.pid = 4242
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    monkeypatch.setattr("src.execution.android_runtime_manager._run", fake_run)
    monkeypatch.setattr(
        "src.execution.android_runtime_manager.subprocess.Popen", FakeProcess
    )

    policy = AndroidRuntimePolicy(
        sdk_root=str(sdk), state_root=str(tmp_path / "state"),
        allow_software_acceleration=True, data_partition_mb=256,
        containment_receipt_path=containment_path,
        containment_receipt_sha256=containment_sha,
    )
    with AndroidRuntimeManager(apk, policy) as target:
        receipt = target.receipt
        runtime_secret = target.frida_token
        assert target.serial == "emulator-5554"
        assert receipt["cold_clean_boot"] is True
        assert receipt["root_verified"] is True
        assert receipt["frida_ready"] is True
        assert receipt["native_coverage_complete"] is True
        assert receipt["host_emulator_scope"]["verified"] is True
        assert "--property=IPAddressDeny=any" in receipt["emulator_command"]
        assert "--property=IPAddressAllow=localhost" in receipt["emulator_command"]
        job_dir = Path(target.job_dir)
        assert job_dir.exists()

    assert receipt["cleanup"]["success"] is True
    assert not job_dir.exists()
    flattened = [" ".join(command) for command in commands]
    assert any("-no-window" in command and "-no-snapshot" in command for command in flattened)
    assert runtime_secret
    assert all(runtime_secret not in command for command in flattened)
    assert receipt["frida_handshake"] == "frida-python-api-enumerate-processes-success"
    assert receipt["frida_host_endpoint"] == "127.0.0.1:37123"
    assert receipt["frida_transport"]["authenticated"] is True
    assert receipt["frida_transport"]["guest_port"] != 27042
    assert receipt["host_containment"]["apk_sha256"] == profile_apk(apk).apk_sha256
    assert "frida_token" not in receipt
    assert any(
        "shell sh /data/local/tmp/.angerona-" in command
        and ".launch.sh" in command
        for command in flattened
    )
    assert any("forward --remove tcp:37123" in command for command in flattened)
    assert any("kill-server" in command for command in flattened)
    assert "ADB_SERVER_SOCKET" not in process_envs[0]
    assert "ANDROID_ADB_SERVER_ADDRESS" not in process_envs[0]
    assert process_envs[0]["ANDROID_ADB_SERVER_PORT"] == "5039"


def test_managed_runtime_refuses_before_sdk_without_pinned_containment_receipt(tmp_path):
    apk = _apk(tmp_path / "target.apk")
    with pytest.raises(AndroidRuntimeError, match="containment-receipt-and-sha256-required"):
        AndroidRuntimeManager(
            apk,
            AndroidRuntimePolicy(
                sdk_root=str(tmp_path / "missing-sdk"),
                allow_software_acceleration=True,
            ),
        ).__enter__()


def test_containment_receipt_is_hash_and_apk_bound(tmp_path, monkeypatch):
    _attest_test_receipt_as_controller(monkeypatch)
    apk = _apk(tmp_path / "target.apk")
    path, digest = _containment_receipt(tmp_path / "containment.json", apk)
    policy = AndroidRuntimePolicy(
        containment_receipt_path=path,
        containment_receipt_sha256=digest,
    )
    verified = verify_host_containment_receipt(
        policy, apk_sha256=profile_apk(apk).apk_sha256,
    )
    assert verified["verified"] is True
    assert verified["imds_denied"] is True
    with pytest.raises(AndroidRuntimeError, match="apk-mismatch"):
        verify_host_containment_receipt(policy, apk_sha256="0" * 64)
    with pytest.raises(AndroidRuntimeError, match="sha256-mismatch"):
        verify_host_containment_receipt(
            AndroidRuntimePolicy(
                containment_receipt_path=path,
                containment_receipt_sha256="f" * 64,
            )
        )


def test_containment_receipt_self_minted_by_worker_is_rejected(tmp_path):
    apk = _apk(tmp_path / "target.apk")
    path, digest = _containment_receipt(tmp_path / "worker.json", apk)
    if os.stat(path).st_uid == 0:
        pytest.skip("test runner is root; non-root ownership cannot be exercised")
    with pytest.raises(AndroidRuntimeError, match="owner-invalid"):
        verify_host_containment_receipt(AndroidRuntimePolicy(
            containment_receipt_path=path,
            containment_receipt_sha256=digest,
        ))


def test_multi_abi_receipt_never_claims_one_lane_is_complete(monkeypatch, tmp_path):
    requirements = ApkRuntimeRequirements(
        apk_sha256="a" * 64,
        apk_bytes=10,
        apk_uncompressed_bytes=10,
        native_abis=("arm64-v8a", "x86_64"),
    )
    monkeypatch.setattr("platform.machine", lambda: "x86_64")
    assert _choose_abi(requirements, AndroidRuntimePolicy()) == "x86_64"
    assert set(requirements.native_abis) - {"x86_64"} == {"arm64-v8a"}


def test_console_port_comes_from_official_even_range(tmp_path):
    port, handle = _select_emulator_console_port(tmp_path / "ports.lock")
    try:
        assert 5554 <= port <= 5682
        assert port % 2 == 0
    finally:
        handle.close()


def test_port_cleanup_checks_live_listeners_not_time_wait():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = int(listener.getsockname()[1])
        assert _ports_unbound([port]) is False
    assert _ports_unbound([port]) is True
