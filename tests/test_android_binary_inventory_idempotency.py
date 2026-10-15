"""R3: materialize_binary_evidence must be disk-idempotent on resume.

On a 3rd resume it re-runs objdump/IDA on all 33469 artifacts because there is
no check for an existing `_angerona_binary_evidence/<sha>/manifest.json`. This
makes resume take ~3.7h instead of seconds. The fix reuses on-disk evidence
when the item's manifest is internally consistent (sha256 + bytes match).
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from src.analysis.android_binary_inventory import materialize_binary_evidence


def _fake_elf(root: Path, name: str = "native.so") -> Path:
    target = root / name
    target.write_bytes(b"\x7fELF" + b"\x00" * 128)
    return target


def _stub_ida_and_disassembly(monkeypatch, *, complete: bool = True):
    """Count invocations of IDA + objdump so a second materialize can prove
    it skipped them via disk cache."""
    calls = {"ida": 0, "objdump": 0}

    def fake_ida(_target, output, **_kwargs):
        calls["ida"] += 1
        output.write_text("IDA evidence\n")
        return {"status": "success", "complete": complete}

    def fake_disassembly(_target, output, **_kwargs):
        calls["objdump"] += 1
        output.write_text("disasm\n")
        return {"status": "success", "complete": True, "tool": "objdump",
                "bytes": 7, "published": True}

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence", fake_ida
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_disassembly", fake_disassembly
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )
    # Pin the producer contract so the live contract matches any precomputed
    # record's contract (isolate R3 — disk idempotency — from R4 contract drift).
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.producer_contract_sha256",
        lambda self, **_kwargs: "producer-contract-test",
    )
    return calls


def test_materialize_binary_evidence_is_disk_idempotent(tmp_path, monkeypatch, native_elf_bytes, route_native, precompute_native):
    """Second call on the same artifacts must NOT re-invoke IDA/objdump."""
    root = tmp_path / "artifacts"
    root.mkdir()
    (root / "native.so").write_bytes(native_elf_bytes)
    routing = route_native(root)
    calls = _stub_ida_and_disassembly(monkeypatch)

    # First materialization: IDA runs once. With complete IDA, objdump is
    # deliberately skipped (IDA evidence already covers disassembly).
    precomputed = precompute_native(root, routing, tmp_path / "static")
    materialize_binary_evidence(root, precomputed_native_records=precomputed, **routing.materialize_kwargs)
    assert calls["ida"] == 1
    assert calls["objdump"] == 0  # complete IDA skips redundant objdump

    # Second materialization (resume): must reuse on-disk evidence — zero new
    # IDA invocations.
    calls2 = _stub_ida_and_disassembly(monkeypatch)
    progress = []
    result = materialize_binary_evidence(root, progress_callback=progress.append, **routing.materialize_kwargs)
    assert calls2["ida"] == 0, "resume re-invoked IDA despite on-disk evidence"
    assert calls2["objdump"] == 0
    assert result["checkpoint_hits"] == 1
    assert progress[-1]["cache_hit"] is True

    # And the records still report analysis_complete.
    assert result["files"][0]["analysis_complete"] is True
