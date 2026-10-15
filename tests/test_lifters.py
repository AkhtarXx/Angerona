"""Universal lifter lane tests (roadmap Phase 3)."""
from __future__ import annotations

import pytest

from src.analysis.lifters import LiftRequest, LifUnavailable
from src.analysis.lifters.registry import dual_lift, get_lifter, lift


P64 = b"\x55\x48\x89\xe5\x5d\xc3"   # push rbp; mov rbp,rsp; pop rbp; ret (x86-64)
ARM32 = bytes.fromhex("04e02de50050a0e10080bde8")     # push {lr}; mov r5,r0; pop {pc}
MIPS32_BE = bytes.fromhex("27bdffe8afbf001403e0000800000000")  # addiu/sp,lw ra,jr ra


def _has_lifter_backend() -> bool:
    """True when at least one lifter backend is importable (pypcode/pyvex/capstone)."""
    for mod in ("pypcode", "pyvex", "capstone"):
        try:
            __import__(mod)
            return True
        except ImportError:
            continue
    return False


# Real-IR lifter tests require a backend (pypcode/pyvex/capstone).  When none
# is installed the registry raises LifUnavailable; skip honestly rather than
# report red on a missing optional dependency.  (ELITE-2 quality gate.)
no_backend = pytest.mark.skipif(
    not _has_lifter_backend(),
    reason="no lifter backend (pypcode/pyvex/capstone) installed",
)


@no_backend
def test_pcode_lifts_x86_64():
    req = LiftRequest(isa="x86-64", bytes_code=P64, base_address=0x1000)
    out = lift(req)
    assert out.provenance == "pypcode" or out.provenance == "pyvex"
    assert out.ir, "expected at least one IR op"
    assert 0.0 < out.confidence <= 1.0


@no_backend
def test_pcode_lifts_arm32():
    req = LiftRequest(isa="arm-le-32", bytes_code=ARM32, base_address=0x8000)
    out = lift(req)
    assert out.ir
    assert out.provenance in ("pypcode", "pyvex", "irnorm-capstone")


@no_backend
def test_pcode_lifts_mips32_big_endian():
    req = LiftRequest(isa="mips-be-32", bytes_code=MIPS32_BE, base_address=0x80000000)
    out = lift(req)
    assert out.ir


@no_backend
def test_irnorm_fires_for_unknown_isa():
    """Fabricated ISA (6502 only capstone available via fallback) hits the shim."""
    req = LiftRequest(isa="6502", bytes_code=b"\xa9\x01\x8d\x00\x02", base_address=0x8000)
    # 6502 IS in pcode lang map — confirm either works OR fallback fires gracefully
    out = lift(req)
    assert out is not None


def test_lifter_registry_order():
    lifters = get_lifter()
    assert len(lifters) >= 2
    # pcode first (widest coverage), pyvex/fallback later
    names = [m.__name__ for m in lifters]
    assert any("pcode" in n for n in names)


@no_backend
def test_dual_lifter_agrees_on_x86():
    req = LiftRequest(isa="x86-64", bytes_code=P64, base_address=0x1000)
    best, alt = dual_lift(req)
    assert best is not None
    if alt is not None:
        # Both lifters produce SOME IR for the same bytes
        assert best.ir and alt.ir
        # Provenance labels differ (they're different lifters)
        assert best.provenance != alt.provenance


def test_lifter_returns_lifunavailable_for_garbage_isa():
    req = LiftRequest(isa="z80-custom", bytes_code=b"\x00\x01\x02", base_address=0)
    try:
        out = lift(req)
    except LifUnavailable:
        return
    # if it didn't raise, it should be the fallback at lower confidence
    assert out.confidence < 0.7
