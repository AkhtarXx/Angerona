from __future__ import annotations

import zipfile

from src.analysis.native_anti_tamper_scanner import (
    AntiTamperResult,
    scan_apk_native_libs,
    scan_so_bytes,
)


def _mk(with_markers: bytes = b"") -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 32 + with_markers + b"\x00" * 128


def test_clear_binary_reports_clear():
    res = scan_so_bytes(_mk())
    assert res.status == "clear"
    assert res.sites == []
    assert res.trust == "untrusted_child"


def test_ptrace_string_flags_critical():
    blob = _mk(b"ptrace\x00PTRACE_TRACEME")
    res = scan_so_bytes(blob)
    assert res.status == "defended"
    assert "ptrace" in res.categories
    assert res.max_severity == "critical"
    ptrace_hits = [s for s in res.sites if s.category == "ptrace"]
    assert ptrace_hits


def test_tracer_pid_and_proc_maps():
    blob = _mk(b"/proc/self/status\x00TracerPid\x00/proc/self/maps\x00frida")
    res = scan_so_bytes(blob)
    cats = set(res.categories)
    assert {"tracer_pid", "frida_scan"} <= cats


def test_imports_of_interest_detected():
    blob = _mk(b"gettimeofday\x00ptrace\x00")
    res = scan_so_bytes(blob)
    assert "gettimeofday" in res.imports_of_interest
    assert "ptrace" in res.imports_of_interest


def test_apk_scan_only_reads_libs(tmp_path):
    blob = _mk(b"TracerPid")
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/armeabi-v7a/libt.so", blob)
        zf.writestr("assets/blob.bin", b"TracerPid")  # must not be scanned
    out = scan_apk_native_libs(str(apk))
    assert list(out) == ["lib/armeabi-v7a/libt.so"]
    assert out["lib/armeabi-v7a/libt.so"].status == "defended"


def test_byte_offsets_point_at_needle():
    marker = b"/proc/self/maps"
    blob = _mk(marker)
    res = scan_so_bytes(blob)
    site = next(s for s in res.sites if s.pattern == "/proc/self/maps path")
    assert blob[site.offset : site.offset + len(marker)] == marker
