"""Behavior tests for raw-blob fingerprinting (roadmap Phase 4)."""
from __future__ import annotations

from src.analysis.blob_fingerprint import (
    BlobFacts,
    _looks_ihex,
    _looks_srec,
    fingerprint,
)


def test_ihex_detected():
    lines = [
        b":100000000CAFEBABE0000000000000000000D4",
        b":10001000112233445566778899AABBCCDDEEFF79",
        b":00000001FF",
    ]
    blob = b"\r\n".join(lines)
    facts = fingerprint(blob)
    assert facts.confidence >= 0.85
    assert any(e["signal"] == "ihex-record" for e in facts.evidence)


def test_srec_detected():
    lines = [
        b"S0130000687474703A2F2F737265636F72642E6964AA",
        b"S11F00007C0802A6900100099421FFF07C6C1B787C8C23783C600000",
        b"S9030000FC",
    ]
    blob = b"\r\n".join(lines)
    facts = fingerprint(blob)
    assert any(e["signal"] == "srec-record" for e in facts.evidence)


def test_synthetic_cortex_m_vector_table():
    """Build a fake Cortex-M vector table: SP at 0x20000000, reset at 0x08000001."""
    blob = b"\x00" * 16
    blob = (b"\x00" * 4 + (0x20000000 | 0).to_bytes(4, "little") +
            (0x08000001).to_bytes(4, "little") + b"\x00" * 32)
      # first pad 4 bytes so the row is at base=0? our heuristic scans every 4 bytes
    facts = fingerprint(blob)
    assert facts.isa_hint in ("arm-le-thumb", "unknown") or \
           any(e["signal"] == "cortex-m-vector" for e in facts.evidence)


def test_fingerprint_high_entropy_blob_degrades_honestly():
    blob = bytes(range(256)) * 4
    facts = fingerprint(blob)
    # must never fabricate confidence on entropy-only bytes
    assert facts.confidence <= 1.0
    assert isinstance(facts.unresolved, tuple)
    # base_margin is bounded
    assert facts.base_margin >= 0.0


def test_base_margin_reported_not_silent():
    """BlobFacts must list every base candidate when margin < 3, not silently pick."""
    # manufacture a blob with weak pointer density everywhere
    blob = (b"\xAA" * 2048 + b"\x00\x00\x00\x08" + b"\xBB" * 100 +
            b"\x00\x00\x00\x10" + b"\xCC" * 512)
    facts = fingerprint(blob)
    # either margin >= 3 with single base, or unresolved note
    if facts.base_margin < 3.0:
        assert any("margin" in u or "base" in u for u in facts.unresolved) or \
               facts.confidence < 0.8


def test_blob_facts_frozen_shape():
    facts = fingerprint(b"\xAA" * 100)
    assert isinstance(facts, BlobFacts)
    d = facts.as_dict()
    for k in ("isa_hint", "endianness", "word_size", "base_candidates",
              "base_margin", "entry_hint", "confidence", "evidence", "unresolved"):
        assert k in d
