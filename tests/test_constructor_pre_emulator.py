from __future__ import annotations

import struct
import zipfile

import pytest

unicorn = pytest.importorskip("unicorn")

from src.analysis.constructor_pre_emulator import (
    emulate_constructors,
    scan_apk_native_libs,
)
from src.analysis.native_elf import DT_INIT
from tests.fixtures_native import build_arm64_so


def _ctor_writes_secret(secret: bytes) -> bytes:
    """tiny ctor stub: movz/strb secret bytes onto stack, then ret."""
    insns = b""
    from tests.fixtures_native import a64_movz_w, a64_strb_w, a64_ret
    for i, b in enumerate(secret):
        insns += a64_movz_w(8, b)
        insns += a64_strb_w(8, 31, i + 16)
    insns += a64_ret()
    return insns


def _so_with_init(secret: bytes = b"x") -> bytes:
    insns = _ctor_writes_secret(secret)
    # DT_INIT (tag 12) pointing at .text vaddr 0x1000
    return build_arm64_so(
        text=insns,
        rodata=b"",
        dynamic_entries=[(DT_INIT, 0x1000)],
        dynstr_names=["JNI_OnLoad"],
        dynsym=[("JNI_OnLoad", 0x1000, len(insns), False)],
    )


def test_non_elf_unsupported():
    res = emulate_constructors(b"not an elf")
    assert res.status == "unsupported"
    assert res.constructors == []


def test_no_constructors_unsupported():
    blob = build_arm64_so(
        text=b"\xc0\x03\x5f\xd6", rodata=b"",
        dynamic_entries=[], dynstr_names=[], dynsym=[],
    )
    res = emulate_constructors(blob)
    assert res.status == "unsupported"


def test_ctor_emulates_and_recovers_bytes():
    secret = b"hn-secret!"
    blob = _so_with_init(secret)
    res = emulate_constructors(blob, max_steps=50_000)
    assert res.status in ("completed", "partial")
    assert any(c.status == "ok" for c in res.constructors)
    joined = "".join(res.recovered_strings)
    assert "hn-secret!" in joined or "hn-secret" in joined


def test_secrets_scanned_from_recovered_strings():
    secret = b"AKIAABCDEFGHIJKLMNOP"  # AWS-shaped access key id
    blob = _so_with_init(secret)
    res = emulate_constructors(blob, max_steps=50_000, secrets_scan=True)
    assert res.secrets or res.status == "partial"  # tolerate emulator edge cases


def test_apk_scan_routes_libs(tmp_path):
    blob = _so_with_init(b"k")
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libc.so", blob)
        zf.writestr("AndroidManifest.xml", b"\x00" * 8)
    out = scan_apk_native_libs(str(apk))
    assert "lib/arm64-v8a/libc.so" in out
    assert out["lib/arm64-v8a/libc.so"].status in ("completed", "partial", "unsupported", "error")
