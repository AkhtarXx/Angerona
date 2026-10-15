"""R11: analyze_native_static_evidence must reuse on-disk receipts (no IDA re-run).

The deterministic native-static stage re-ran IDA (hours) on every re-run because
it never checked for the hash-attested ``native_static_receipt.json`` it had
already written. This pins disk idempotency: a second call on the same evidence
root reuses the on-disk evidence and does NOT re-invoke ``_write_ida_evidence``.
"""
from __future__ import annotations

import json
import hashlib
from pathlib import Path

from src.analysis.android_binary_inventory import analyze_native_static_evidence


def _fake_elf(path: Path) -> None:
    path.write_bytes(b"\x7fELF" + b"\x00" * 128)


def test_native_static_reuses_disk_evidence(tmp_path, monkeypatch, native_elf_bytes, route_native):
    target = tmp_path / "native.so"
    target.write_bytes(native_elf_bytes)
    routing = route_native(tmp_path)
    evidence_root = tmp_path / "native_static_evidence"
    calls = {"ida": 0}

    def fake_ida(tgt, output, **_kwargs):
        calls["ida"] += 1
        output.write_text("IDA semantic evidence\n")
        return {
            "status": "success",
            "complete": True,
            "target_sha256": hashlib.sha256(tgt.read_bytes()).hexdigest(),
            "target_bytes": tgt.stat().st_size,
            "producer_contract_sha256": "producer-contract-test",
        }

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence", fake_ida
    )
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )

    first = analyze_native_static_evidence(
        [str(target)], evidence_root=evidence_root, timeout=120, **routing.static_kwargs
    )
    assert calls["ida"] == 1
    assert first["complete"] is True

    # Second call (resume): must reuse on-disk evidence — zero new IDA runs.
    second = analyze_native_static_evidence(
        [str(target)], evidence_root=evidence_root, timeout=120, **routing.static_kwargs
    )
    assert calls["ida"] == 1, "resume re-invoked IDA despite on-disk evidence"
    assert second["complete"] is True
    assert second["records"][0]["ida"]["cache_hit"] is True
    assert second["records"][0]["complete"] is True
    # The reconstructed record still satisfies the precomputed-IDA validator.
    from src.analysis.android_binary_inventory import _validated_precomputed_ida
    record = second["records"][0]
    assert _validated_precomputed_ida(
        record, target_sha256=record["sha256"], target_bytes=record["bytes"]
    ) is not None
