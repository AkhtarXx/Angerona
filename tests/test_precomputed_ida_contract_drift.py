"""R4: precomputed IDA must be reused despite producer-contract drift.

The deterministic native pass writes a hash-attested receipt + ``ida_analysis.txt``
whose own embedded ``ida_producer_contract_sha256`` is the authority. An unrelated
live edit to ``ida_dump.py`` (e.g. the timeout watchdog) drifts the *live* contract
and must NOT force a multi-hour IDA re-run: the on-disk evidence is self-attesting,
so it is reused as long as the disk artifact's embedded contract matches the record.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from src.analysis.android_binary_inventory import materialize_binary_evidence


def _precomputed_record(target: Path, contract: str, binding: dict) -> list[dict]:
    from src.analysis.evidence_signing import sign_document
    data = target.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    # Keep the deterministic evidence OUTSIDE the artifact root so it is not
    # swept up as an artifact by materialize_binary_evidence's rglob.
    item_root = target.parent.parent / "deterministic" / digest
    item_root.mkdir(parents=True, exist_ok=True)
    ida_path = item_root / "ida_analysis.txt"
    ida_path.write_text("trusted deterministic IDA evidence\n")
    ida_hash = hashlib.sha256(ida_path.read_bytes()).hexdigest()
    native_data_path = item_root / "native_nonexec_data.json"
    native_data_path.write_text('{"status":"complete","complete":true}\n')
    native_data_hash = hashlib.sha256(native_data_path.read_bytes()).hexdigest()
    receipt_path = item_root / "native_static_receipt.json"
    receipt_path.write_text(json.dumps(sign_document({
        "schema_version": 2,
        "status": "complete",
        "target_sha256": digest,
        "target_bytes": len(data),
        "ida_semantic_complete": True,
        "ida_producer_contract_sha256": contract,
        "native_data_complete": True,
        "native_routing": binding,
        "evidence_sha256": {
            str(ida_path): ida_hash,
            str(native_data_path): native_data_hash,
        },
    }), sort_keys=True))
    receipt_hash = hashlib.sha256(receipt_path.read_bytes()).hexdigest()
    return [{
        "path": str(target),
        "sha256": digest,
        "bytes": len(data),
        "complete": True,
        "native_routing": binding,
        "ida": {
            "status": "success", "complete": True,
            "target_sha256": digest,
            "target_bytes": len(data),
            "producer_contract_sha256": contract,
        },
        "native_data": {"status": "complete", "complete": True},
        "required_evidence": [str(ida_path), str(native_data_path), str(receipt_path)],
        "evidence_sha256": {
            str(ida_path): ida_hash,
            str(native_data_path): native_data_hash,
            str(receipt_path): receipt_hash,
        },
        "receipt": str(receipt_path),
    }]


def test_precomputed_ida_reused_despite_live_contract_drift(tmp_path, monkeypatch, native_elf_bytes, route_native):
    """Hash-attested on-disk IDA is reused even when the live producer contract
    has drifted — the disk artifact's embedded contract is the authority."""
    root = tmp_path / "artifacts"
    root.mkdir()
    target = root / "native.so"
    target.write_bytes(native_elf_bytes)
    routing = route_native(root)
    from src.analysis.native_ownership_manifest import native_routing_context
    _, _, _, binding = native_routing_context(routing.static_kwargs['ownership_manifest'], routing.static_kwargs['native_universe'])

    # Record was produced by contract "producer-contract-v1"...
    precomputed = _precomputed_record(target, "producer-contract-v1", binding)
    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._elf_nonexec_data_profile",
        lambda *_: {"status": "complete", "complete": True},
    )
    # ...but the live ida_dump.py has since been edited (contract drifts).
    monkeypatch.setattr(
        "src.engines.ida.IdaEngine.producer_contract_sha256",
        lambda self, **_kwargs: "producer-contract-v2-drifted",
    )

    def unexpected(*_args, **_kwargs):
        raise AssertionError("self-attested deterministic IDA must be reused")

    monkeypatch.setattr(
        "src.analysis.android_binary_inventory._write_ida_evidence", unexpected,
    )

    result = materialize_binary_evidence(
        root, precomputed_native_records=precomputed, **routing.materialize_kwargs,
    )

    native = result["files"][0]
    assert native["analysis_complete"] is True
    assert native["native_cache_hit"] is True
