from __future__ import annotations

import struct
import zipfile

import pytest

capstone = pytest.importorskip("capstone")

from src.analysis.key_derivation_carver import (
    FillPattern,
    carve_key_derivations,
    scan_apk_native_libs,
)
from tests.fixtures_native import (
    a64_movk_x,
    a64_movz_x,
    a64_ret,
    build_arm64_so,
    build_keyfill_so,
    build_movk_chain_so,
)


def test_unsupported_on_non_elf():
    res = carve_key_derivations(b"MZ not elf")
    assert res.status == "unsupported"
    assert res.trust == "untrusted_child"


def test_movz_strb_key_carved_exactly():
    key = b"ABCDEFGH"
    blob = build_keyfill_so(key)
    res = carve_key_derivations(blob)
    assert res.status in ("carved", "partial")
    carved = [c for c in res.candidates if c.pattern == FillPattern.WIMM_AARCH64.value]
    assert len(carved) >= len(key)
    seq = bytes(b for c in carved[: len(key)] for b in c.bytes_carved)
    assert seq == key


def test_movz_movk_chain_carved():
    # 0x4142434445464748 as four 16-bit chunks little-endian
    chunks = [(0x4748, 0), (0x4546, 16), (0x4344, 32), (0x4142, 48)]
    blob = build_movk_chain_so(chunks)
    res = carve_key_derivations(blob)
    chain = [c for c in res.candidates if c.pattern == FillPattern.MOVZ_MOVK_CHAIN.value]
    assert chain, "movz/movk chain not carved"
    assert chain[0].partial is False
    assert chain[0].bytes_carved == b"HGFEDCBA"


def test_movz_movk_chain_survives_interleaved_instruction():
    # A 64-bit constant built with an unrelated instruction interleaved
    # between movk steps must stay a single exact 4-step chain (regression:
    # the scanner used to close every in-flight chain on any non-chain
    # instruction, splitting the value into two wrong "exact" fragments).
    chunks = [(0x4748, 0), (0x4546, 16), (0x4344, 32), (0x4142, 48)]
    insns = b""
    first = True
    for i, (imm16, shift) in enumerate(chunks):
        insns += a64_movz_x(0, imm16, shift) if first else a64_movk_x(0, imm16, shift)
        first = False
        if i == 1:
            insns += struct.pack("<I", 0x8B030041)  # add x1, x2, x3 (unrelated)
    insns += a64_ret()
    blob = build_arm64_so(
        text=insns,
        rodata=b"",
        dynamic_entries=[],
        dynstr_names=[],
        dynsym=[],
    )
    res = carve_key_derivations(blob)
    chains = [c for c in res.candidates if c.pattern == FillPattern.MOVZ_MOVK_CHAIN.value]
    assert len(chains) == 1, f"expected single chain, got {[c.bytes_carved.hex() for c in chains]}"
    assert chains[0].partial is False
    assert chains[0].bytes_carved == b"HGFEDCBA"


def test_xor_loop_flagged_partial():
    # tiny xor loop between loop_start and the backward b.ne:
    #   loop: ldrb w10, [x0], #1 ; eor w10, w10, w11 ; strb w10, [x1], #1
    #         cmp x2, x3 ; b.ne loop ; ret
    insns = (
        b"\x0a\x04\x40\x38"          # ldrb w10, [x0], #1
        b"\x4a\x01\x0b\x4a"          # eor w10, w10, w11
        b"\x2a\x04\x00\x38"          # strb w10, [x1], #1
        b"\x5f\x00\x03\xeb"          # cmp x2, x3
        b"\xa1\xff\xff\x54"          # b.ne loop (back to ldrb)
        b"\xc0\x03\x5f\xd6"          # ret
    )
    blob = build_arm64_so(text=insns, rodata=b"", dynamic_entries=[], dynstr_names=[], dynsym=[])
    res = carve_key_derivations(blob)
    loops = [c for c in res.candidates if c.pattern == FillPattern.XOR_LOOP_HEURISTIC.value]
    assert loops, "xor loop not flagged"
    assert all(c.partial for c in loops)


def test_empty_text_reports_none():
    blob = build_arm64_so(text=b"\xc0\x03\x5f\xd6", rodata=b"", dynamic_entries=[], dynstr_names=[], dynsym=[])
    res = carve_key_derivations(blob)
    assert res.status == "none"
    assert res.candidates == []


def test_apk_scan(tmp_path):
    key = b"SK03"
    blob = build_keyfill_so(key)
    apk = tmp_path / "a.apk"
    with zipfile.ZipFile(apk, "w") as zf:
        zf.writestr("lib/arm64-v8a/libk.so", blob)
        zf.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    out = scan_apk_native_libs(str(apk))
    assert "lib/arm64-v8a/libk.so" in out
    assert out["lib/arm64-v8a/libk.so"].status in ("carved", "partial")
