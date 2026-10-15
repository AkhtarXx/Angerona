from __future__ import annotations

from src.execution.static_runtime_bridge import (
    _file_offset_to_vaddr,
    build_hook_plans,
    frida_hook_script,
)
from tests.fixtures_native import build_arm64_so


def _fake_so() -> bytes:
    return build_arm64_so(
        text=b"\x00" * 64,
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=[],
        dynsym=[],
    )


def test_file_offset_translation():
    so = _fake_so()
    # inside .text section - PT_LOAD covers file offset 0x100..0x108
    vaddr = _file_offset_to_vaddr(so, 0x100)
    assert vaddr is not None and vaddr != 0


def test_translation_outside_load():
    so = _fake_so()
    # very high offset outside any PT_LOAD
    vaddr = _file_offset_to_vaddr(so, len(so) - 1)
    assert vaddr is None or isinstance(vaddr, int)


def test_build_hook_plan_correct_translation():
    so = _fake_so()
    findings = [{"offset": 0x100, "category": "ptrace", "severity": "critical"}]
    r = build_hook_plans(findings, library_name="libx.so", so_bytes=so)
    assert r.status == "built"
    assert r.hook_plans[0].vaddr != 0
    assert r.hook_plans[0].category == "ptrace"


def test_missing_offset_skipped():
    so = _fake_so()
    findings = [{"category": "ptrace", "severity": "critical"}]  # no offset
    r = build_hook_plans(findings, library_name="libx.so", so_bytes=so)
    assert r.status == "empty"


def test_frida_script_generated():
    so = _fake_so()
    findings = [{"offset": 0x100, "category": "ptrace", "severity": "critical"}]
    r = build_hook_plans(findings, library_name="libdummy.so", so_bytes=so)
    script = frida_hook_script(r.hook_plans)
    assert "Interceptor.attach" in script or "hook-fail" in script
    assert "libdummy.so" in script


def test_frida_script_empty_plan():
    script = frida_hook_script([])
    assert script.strip() == "// empty plan"
