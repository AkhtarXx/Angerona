import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from src.execution.providers import (
    FridaProvider,
    GdbProvider,
    LldbProvider,
    BpftraceProvider,
    ProviderCapabilities,
    ProviderRegistry,
    QemuTcgPluginProvider,
    QemuUserProvider,
    RrProvider,
)
from src.execution.runtime_trace import (
    RuntimeTrace,
    TraceIngestor,
    TraceReplayer,
    normalize_provider_events,
    parse_bpftrace_ndjson,
    parse_qemu_strace,
)
from src.agents.runtime import _authorized_artifact_sender


def test_runtime_trace_round_trip_and_deterministic_replay(tmp_path: Path) -> None:
    events = normalize_provider_events("frida", [
        {"kind": "call", "runtime_address": "0x1010", "thread_id": 7, "symbol": "malloc"},
        {"kind": "return", "runtime_address": "0x1020", "thread_id": 7, "value": 3},
    ])
    trace = RuntimeTrace("frida", "b" * 64, events, metadata={"session": "test"})
    output = tmp_path / "trace.jsonl"

    TraceIngestor.write_jsonl(trace, output)
    restored = TraceIngestor.read(output)

    assert restored.trace_id == trace.trace_id
    replay = TraceReplayer(restored)
    assert [event.kind for event in replay.step(1)] == ["call"]
    assert replay.seek(1).properties["value"] == 3
    assert [event.kind for event in replay.iter_events(kinds={"call"}, thread_id=7)] == ["call"]


def test_runtime_trace_rejects_tampered_event() -> None:
    event = normalize_provider_events("gdb", [{"kind": "breakpoint"}])[0]
    row = event.as_dict()
    row["kind"] = "changed"
    with pytest.raises(ValueError, match="digest mismatch"):
        RuntimeTrace("gdb", "c" * 64, [type(event).from_dict(row)])


def test_jsonl_requires_header(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(json.dumps({"record_type": "event"}) + "\n")
    with pytest.raises(ValueError, match="trace_header"):
        TraceIngestor.read(path)


def test_gdb_plan_has_no_shell_and_disables_user_init(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    commands = tmp_path / "commands.gdb"
    commands.write_text("quit\n")
    monkeypatch.setattr("src.execution.providers.shutil.which", lambda name: "/usr/bin/gdb")

    plan = GdbProvider().launch_plan(target, commands)

    assert plan.argv[:5] == ("/usr/bin/gdb", "--nx", "--nh", "--batch", "--quiet")
    assert plan.capabilities == ProviderCapabilities(launch=True, attach=True, memory_capture=True)


def test_lldb_plan_disables_init_and_external_symbol_lookup(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    commands = tmp_path / "commands.lldb"
    commands.write_text("quit\n")
    monkeypatch.setattr("src.execution.providers.shutil.which", lambda name: "/usr/bin/lldb")

    plan = LldbProvider().launch_plan(target, commands)

    assert "--no-lldbinit" in plan.argv
    assert "--one-line-before-file" in plan.argv
    assert "settings set symbols.enable-external-lookup false" in plan.argv


def test_registry_excludes_unavailable_providers_from_real_audits() -> None:
    complete = ProviderRegistry(include_unavailable=True).status()
    assert set(complete) == {
        "gdb", "lldb", "dbgeng", "frida", "rr", "qemu-user",
        "qemu-tcg-plugin", "bpftrace",
    }
    active = ProviderRegistry().status()
    assert active
    assert all(row["available"] for row in active.values())
    assert set(active) == {
        name for name, row in complete.items() if row["available"]
    }


def test_rr_availability_matches_real_recording_probe() -> None:
    provider = RrProvider()
    details = provider.details()
    assert details["recording_ready"] is provider.available()
    assert details["recording_probe"]


def test_frida_plan_uses_current_cli_flags(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"sample")
    script = tmp_path / "agent.js"
    script.write_text("send(Process.id);\n")
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: "/usr/bin/frida" if name == "frida" else None,
    )

    plan = FridaProvider().launch_plan(target, script)

    assert "--no-pause" not in plan.argv
    assert "--quiet" not in plan.argv
    assert plan.argv[-3:] == ("-q", "-t", "inf")


def test_qemu_user_plan_selects_elf_arch_and_never_claims_sandbox(
    tmp_path: Path, monkeypatch
) -> None:
    target = tmp_path / "aarch64-sample"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setattr(
        "src.execution.loaders.load_binary",
        lambda _path: SimpleNamespace(format="elf", architecture="aarch64"),
    )
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "qemu-aarch64" else None,
    )

    plan = QemuUserProvider().launch_plan(target, argv=["hello world"], syscall_trace=True)

    assert plan.argv == (
        "/usr/bin/qemu-aarch64", "-strace", str(target.resolve()), "hello world",
    )
    assert plan.metadata["architecture"] == "aarch64"
    assert plan.metadata["sandbox"] is False
    assert plan.capabilities == ProviderCapabilities(launch=True, system_trace=True)


def test_qemu_user_plan_rejects_architecture_mismatch(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setattr(
        "src.execution.loaders.load_binary",
        lambda _path: SimpleNamespace(format="elf", architecture="x86_64"),
    )
    with pytest.raises(ValueError, match="does not match"):
        QemuUserProvider().launch_plan(target, architecture="aarch64")


def test_qemu_user_plan_accepts_equivalent_architecture_alias(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "sample"
    target.write_bytes(b"\x7fELF")
    monkeypatch.setattr(
        "src.execution.loaders.load_binary",
        lambda _path: SimpleNamespace(format="elf", architecture="x86_64"),
    )
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: f"/usr/bin/{name}" if name == "qemu-x86_64" else None,
    )
    plan = QemuUserProvider().launch_plan(target, architecture="amd64")
    assert plan.metadata["architecture"] == "x86_64"


def test_qemu_tcg_plugin_plan_is_shell_free(tmp_path: Path, monkeypatch) -> None:
    plugin = tmp_path / "trace.so"
    plugin.write_bytes(b"plugin")
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: "/usr/bin/qemu-system-x86_64"
        if name == "qemu-system-x86_64" else None,
    )
    monkeypatch.setattr(
        QemuTcgPluginProvider,
        "_supports_plugins",
        staticmethod(lambda _executable: True),
    )

    plan = QemuTcgPluginProvider().plugin_plan(
        plugin,
        architecture="amd64",
        plugin_arguments=["mode=coverage"],
        qemu_arguments=["-machine", "none", "-S"],
    )

    assert plan.argv == (
        "/usr/bin/qemu-system-x86_64", "-accel", "tcg", "-plugin",
        f"file={plugin.resolve()},mode=coverage", "-machine", "none", "-S",
    )
    assert plan.metadata["tcg_plugin_api"] is True
    assert plan.metadata["sandbox"] is False


def test_qemu_tcg_plugin_loads_in_real_qemu(tmp_path: Path) -> None:
    provider = QemuTcgPluginProvider()
    if not provider.available() or shutil.which("gcc") is None:
        pytest.skip("plugin-capable QEMU system emulator and gcc are required")
    source = Path(__file__).parent / "fixtures" / "qemu_plugin_smoke.c"
    plugin = tmp_path / "qemu_plugin_smoke.so"
    built = subprocess.run(
        [
            "gcc", "-shared", "-fPIC", "-fvisibility=hidden",
            str(source), "-o", str(plugin),
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert built.returncode == 0, built.stderr
    plan = provider.plugin_plan(plugin, architecture="x86_64")
    process = subprocess.Popen(plan.argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate(timeout=5)

    assert "ANGERONA_QEMU_PLUGIN_LOADED" in f"{stdout}\n{stderr}"


def test_frida_spawn_and_script_load_work_in_real_runtime() -> None:
    provider = FridaProvider()
    if not provider.available():
        pytest.skip("Frida CLI is required")
    script = Path(__file__).parent / "fixtures" / "frida_smoke.js"
    plan = provider.launch_plan("/bin/true", script)
    completed = subprocess.run(plan.argv, capture_output=True, text=True, timeout=15)
    output = f"{completed.stdout}\n{completed.stderr}"
    assert completed.returncode == 0, output
    assert "angerona-frida-smoke" in output


def test_lldb_launch_plan_runs_real_binary(tmp_path: Path) -> None:
    provider = LldbProvider()
    if not provider.available() or shutil.which("gcc") is None:
        pytest.skip("LLDB and gcc are required")
    source = Path(__file__).parent / "fixtures" / "symbolic_add.c"
    target = tmp_path / "lldb-smoke"
    built = subprocess.run(
        ["gcc", "-O0", "-g", str(source), "-o", str(target)],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert built.returncode == 0, built.stderr
    commands = tmp_path / "commands.lldb"
    commands.write_text("breakpoint set -n main\nrun\nregister read rip\n")
    plan = provider.launch_plan(target, commands)

    completed = subprocess.run(plan.argv, capture_output=True, text=True, timeout=20)

    assert completed.returncode == 0, f"{completed.stdout}\n{completed.stderr}"
    assert "rip =" in completed.stdout


def test_bpftrace_plan_is_ndjson_and_shell_free(tmp_path: Path, monkeypatch) -> None:
    script = tmp_path / "trace.bt"
    script.write_text('BEGIN { printf("ready\\n"); exit(); }\n')
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: "/usr/bin/bpftrace" if name == "bpftrace" else None,
    )

    plan = BpftraceProvider().script_plan(script, privileged=False)

    assert plan.argv == ("/usr/bin/bpftrace", "-f", "json", str(script.resolve()))
    assert plan.metadata["output_format"] == "ndjson"
    assert plan.metadata["requires_privilege"] is True

    dry_plan = BpftraceProvider().script_plan(script, dry_run=True, privileged=False)
    assert "--dry-run" in dry_plan.argv
    assert "-d" not in dry_plan.argv


def test_bpftrace_privileged_plan_uses_verified_noninteractive_sudo(
    tmp_path: Path, monkeypatch
) -> None:
    script = tmp_path / "trace.bt"
    script.write_text('BEGIN { exit(); }\n')
    monkeypatch.setattr(
        "src.execution.providers.shutil.which",
        lambda name: f"/usr/bin/{name}" if name in {"bpftrace", "sudo"} else None,
    )
    monkeypatch.setattr("src.execution.providers.os.geteuid", lambda: 1000)
    monkeypatch.setattr(BpftraceProvider, "sudo_noninteractive_available", staticmethod(lambda: True))

    plan = BpftraceProvider().script_plan(script, privileged=True)

    assert plan.argv[:4] == ("/usr/bin/sudo", "-n", "/usr/bin/bpftrace", "-f")
    assert plan.metadata["privilege_mode"] == "sudo-noninteractive"


def test_bpftrace_ndjson_parser_preserves_machine_records() -> None:
    events = parse_bpftrace_ndjson(
        '{"type":"attached_probes","count":1,"data":{"probes":1}}\n'
        '{"type":"printf","data":"angerona-ok\\n"}\n'
    )

    assert [event.kind for event in events] == ["attached_probes", "printf"]
    assert events[1].properties["data"] == "angerona-ok\n"
    assert all(event.verify_integrity() for event in events)


def test_bpftrace_ndjson_parser_fails_closed_on_non_json() -> None:
    with pytest.raises(ValueError, match="line 2"):
        parse_bpftrace_ndjson('{"type":"printf","data":"ok"}\nnot-json\n')


def test_qemu_strace_parser_normalizes_syscalls_and_retains_unknown_lines() -> None:
    events = parse_qemu_strace(
        '42 openat(-100,"/etc/ld.so.cache",O_RDONLY) = 3\n'
        '--- SIGTERM ---\n'
    )

    assert events[0].kind == "syscall"
    assert events[0].process_id == 42
    assert events[0].properties["syscall"] == "openat"
    assert events[0].properties["result"] == "3"
    assert events[1].kind == "qemu_trace"
    assert events[1].properties["parsed"] is False

    terminal = parse_qemu_strace("42 exit(37)\n")[0]
    assert terminal.properties["syscall"] == "exit"
    assert terminal.properties["no_return"] is True


def test_provider_finds_console_script_next_to_current_interpreter(tmp_path: Path, monkeypatch) -> None:
    scripts = tmp_path / "bin"
    scripts.mkdir()
    frida = scripts / "frida"
    frida.write_text("#!/bin/sh\nexit 0\n")
    frida.chmod(0o755)
    monkeypatch.setattr("src.execution.providers.shutil.which", lambda _name: None)
    monkeypatch.setattr("src.execution.providers.sysconfig.get_path", lambda _name: str(scripts))

    provider = FridaProvider()

    assert provider.executable() == str(frida.resolve())
    assert provider.available()


def test_artifact_sender_authentication_requires_runner_and_lineage() -> None:
    command = Path(f"/proc/{os.getpid()}/cmdline").read_bytes().split(b"\0")[0]
    assert _authorized_artifact_sender(
        os.getpid(), boundary_pid=os.getppid(), expected_runner=command, max_depth=1
    )
    assert not _authorized_artifact_sender(
        os.getpid(), boundary_pid=-1, expected_runner=command, max_depth=1
    )
    assert not _authorized_artifact_sender(
        os.getpid(), boundary_pid=os.getppid(), expected_runner=b"not-the-runner", max_depth=1
    )
