"""Unit tests for the IDA per-function decompile watchdog/cancellation logic.

These do NOT require an IDA license or idalib: ``ida_dump.py`` keeps every IDA
import deferred inside functions, so the module imports under plain CPython. We
inject fake ``ida_kernwin`` / ``ida_hexrays`` modules into ``sys.modules`` and
drive the cancellation state machine, verifying that:

* the watchdog sets IDA's global cancel flag after the configured budget,
* ``_decompile`` reports ``"timeout"`` when the (injected) decompiler blocks past
  the budget and the cancel flag is observed,
* a timely decompile reports ``"ok"`` and the watchdog is disarmed + flag cleared,
* disarming clears the cancel flag so a timeout on one function cannot poison
  the next.
"""

from __future__ import annotations

import importlib.util
import sys
import threading
import types
from pathlib import Path

import pytest

_IDA_DUMP = Path(__file__).resolve().parents[1] / "src" / "scripts" / "ida_dump.py"


def _load_ida_dump():
    spec = importlib.util.spec_from_file_location("angerona_ida_dump_test", _IDA_DUMP)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _install_fake_ida_modules(*, cancel_after_decompile: bool = False):
    """Install fake ida_kernwin + ida_hexrays into sys.modules.

    ``ida_kernwin`` tracks a module-level cancel flag with set/clr/user_cancelled.
    ``ida_hexrays.decompile`` blocks on an event until the watchdog fires the cancel
    flag (or is released early by the test), mirroring a pathological sprawl.
    """
    kernwin = types.ModuleType("ida_kernwin")
    _flag = {"cancelled": False}

    kernwin.set_cancelled = lambda: _flag.__setitem__("cancelled", True)
    kernwin.clr_cancelled = lambda: _flag.__setitem__("cancelled", False)
    kernwin.user_cancelled = lambda: _flag["cancelled"]

    hexrays = types.ModuleType("ida_hexrays")
    _release = threading.Event()

    class _Cfunc:
        def __str__(self):
            return "int fake(void) { return 0; }"

    def _decompile(ea):
        # Emulate a pathological function: spin until either the watchdog raises the
        # cancel flag or the test releases us early.
        while not _flag["cancelled"]:
            if _release.wait(0.01):
                return _Cfunc()
        return None  # decompiler unwinds with "None" on cancel, just like the real one

    hexrays.init_hexrays_plugin = lambda: True
    hexrays.decompile = _decompile
    hexrays._release = _release
    hexrays._flag = _flag

    sys.modules["ida_kernwin"] = kernwin
    sys.modules["ida_hexrays"] = hexrays
    return kernwin, hexrays, _flag, _release


def _teardown_fake_ida():
    sys.modules.pop("ida_kernwin", None)
    sys.modules.pop("ida_hexrays", None)


@pytest.fixture
def ida_dump():
    mod = _load_ida_dump()
    yield mod
    _teardown_fake_ida()


def test_decompile_timeout_is_cancellable_and_reports_timeout(ida_dump):
    """A pathological decompile that blocks past its budget is interrupted via the
    kernel cancel flag and reported as 'timeout' — not skipped silently."""
    _, _hexrays, _flag, _release = _install_fake_ida_modules()
    try:
        # Tiny budget so the watchdog fires almost immediately. The decompile spins
        # until the flag is set.
        result = ida_dump._decompile(0x1000, timeout=0.2)
        c_text, cfunc, status = result
        assert status == "timeout", f"expected timeout, got {status}"
        assert c_text is None and cfunc is None
        # The watchdog raised the flag during the call (which is what unwound the
        # decompiler), but disarm must have cleared it afterward so later functions
        # decompile normally — the critical "no poisoning" guarantee.
        assert _flag["cancelled"] is False
    finally:
        _release.set()
        _teardown_fake_ida()


def test_decompile_ok_when_fast_disarms_watchdog(ida_dump):
    """A fast decompile returns ok and leaves the cancel flag clear."""
    _, _hexrays, _flag, _release = _install_fake_ida_modules()
    try:
        # Release the decompiler immediately so it returns before the (large) budget.
        _release.set()
        result = ida_dump._decompile(0x1000, timeout=30.0)
        c_text, _cfunc, status = result
        assert status == "ok"
        assert c_text == "int fake(void) { return 0; }"
        assert _flag["cancelled"] is False
        # No lingering armed watchdog thread.
        assert ida_dump._CANCEL_ACTIVE["thread"] is None
    finally:
        _teardown_fake_ida()


def test_timeout_on_one_function_does_not_poison_next(ida_dump):
    """After a timeout, the cancel flag is cleared, so the next function decompiles."""
    _, _hexrays, _flag, _release = _install_fake_ida_modules()
    try:
        r1 = ida_dump._decompile(0x1000, timeout=0.2)
        assert r1[2] == "timeout"
        assert _flag["cancelled"] is False  # disarmed/cleared

        # Second function: release it fast; must succeed with flag still clear.
        _release.set()
        r2 = ida_dump._decompile(0x2000, timeout=30.0)
        assert r2[2] == "ok"
        assert _flag["cancelled"] is False
    finally:
        _release.set()
        _teardown_fake_ida()


def test_decompile_unavailable_when_hexrays_init_fails(ida_dump):
    """If Hex-Rays cannot initialise, status is 'unavailable' and no watchdog runs."""
    kernwin = types.ModuleType("ida_kernwin")
    kernwin.set_cancelled = lambda: None
    kernwin.clr_cancelled = lambda: None
    kernwin.user_cancelled = lambda: False
    hexrays = types.ModuleType("ida_hexrays")
    hexrays.init_hexrays_plugin = lambda: False
    sys.modules["ida_kernwin"] = kernwin
    sys.modules["ida_hexrays"] = hexrays
    try:
        # Force re-init by clearing the cached hexrays state.
        ida_dump._HEXRAYS["init"] = False
        c_text, cfunc, status = ida_dump._decompile(0x1000, timeout=5.0)
        assert status == "unavailable"
        assert c_text is None and cfunc is None
    finally:
        ida_dump._HEXRAYS["init"] = False
        _teardown_fake_ida()


def test_progress_carries_optional_fields(ida_dump, capsys):
    """The heartbeat now accepts extra fields (decompiled/timed_out counts) without
    breaking existing callers that pass only stage/completed/expected."""
    ida_dump._progress("functions", 25, 10472, decompiled=20, timed_out=1)
    out = capsys.readouterr().err
    assert "ANGERONA_IDA_PROGRESS" in out
    assert '"timed_out": 1' in out
    assert '"decompiled": 20' in out
