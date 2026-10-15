from pathlib import Path
import shutil
import subprocess

import pytest

from src.execution.providers import QemuUserProvider
from src.execution.runtime_trace import parse_qemu_strace


FIXTURE = Path(__file__).parent / "fixtures" / "aarch64_exit.S"


def test_real_cross_arch_aarch64_execution_and_native_syscall_trace(tmp_path: Path) -> None:
    clang = shutil.which("clang")
    qemu_aarch64 = shutil.which("qemu-aarch64")
    if clang is None or qemu_aarch64 is None or shutil.which("ld.lld") is None:
        pytest.skip("clang/lld and qemu-aarch64 are required")

    binary = tmp_path / "aarch64-exit"
    compiled = subprocess.run([
        clang, "--target=aarch64-linux-gnu", "-fuse-ld=lld", "-nostdlib", "-static",
        "-Wl,-e,_start", str(FIXTURE), "-o", str(binary),
    ], capture_output=True, text=True, timeout=30)
    assert compiled.returncode == 0, compiled.stderr

    plan = QemuUserProvider().launch_plan(binary, syscall_trace=True)
    completed = subprocess.run(plan.argv, capture_output=True, text=True, timeout=10)

    assert completed.returncode == 37
    events = parse_qemu_strace(completed.stderr)
    assert any(
        event.kind == "syscall" and event.properties.get("syscall") in {"exit", "exit_group"}
        for event in events
    )
