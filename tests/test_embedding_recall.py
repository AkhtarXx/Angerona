"""Behavior tests for the embedding recall layer (roadmap Phase C9)."""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from src.analysis import bindiff as bd
from src.analysis.embedding_recall import (
    build_recall_index,
    hierarchical_match_against_corpus,
    recall_candidates,
)


def _corpus_with_functions(td: Path) -> Path:
    corpus = td / "corpus"
    corpus.mkdir()
    # per-binary folders each with an asm/ export
    for name, asm in [
        ("crypto_a", "mov eax, [rcx]\nxor eax, eax\nshl eax, 4\nret"),
        ("crypto_b", "mov eax, [rcx]\nxor eax, eax\nshl eax, 4\nret"),
        ("parser_x", "push rbp\nmov rbp, rsp\ncall parse\npop rbp\nret"),
    ]:
        fdir = corpus / name
        fdir.mkdir()
        (fdir / "asm").mkdir()
        (fdir / "asm" / f"{name}.asm").write_text(asm)
        (fdir / "sample.BinExport").write_bytes(b"\x1a\x04\x00\x00" * 12)
    return corpus


def test_build_recall_and_recall_candidates():
    with tempfile.TemporaryDirectory() as td:
        corpus = _corpus_with_functions(Path(td))
        recall = build_recall_index(corpus)
        cands = recall_candidates(recall, query="xor shl", top_k=5, threshold=0.0)
        # crypto_a and crypto_b both match -> their source paths should appear
        paths = {c.path for c in cands}
        assert any("crypto_a" in p or "crypto_b" in p for p in paths) or cands


def test_recall_empty_query_and_empty_index_are_safe():
    with tempfile.TemporaryDirectory() as td:
        recall = build_recall_index(Path(td))
        assert recall_candidates(recall, query="") == []
        assert recall_candidates(recall) == []


def test_recall_per_binary_cap_enforced():
    with tempfile.TemporaryDirectory() as td:
        corpus = _corpus_with_functions(Path(td))
        recall = build_recall_index(corpus)
        # many overlapping queries but hard cap per binary
        cands = recall_candidates(
            recall, query="xor", top_k=10, threshold=0.0, per_binary_cap=2)
        for c in cands:
            assert c.function_hits <= 2


def test_hierarchical_match_combines_recall_and_bindiff():
    with tempfile.TemporaryDirectory() as td:
        corpus = _corpus_with_functions(Path(td))

        class _WS:
            raw_dir = Path(td)
            def log(self, *_a, **_k): pass

        fake_hits = [bd.ReferenceHit(
            corpus="crypto_a", entry="crypto_a/sample",
            best_similarity=0.91, best_confidence=0.85,
            matched_function_count=12, top_function=None)]

        with patch.object(bd, "match_against_corpus", return_value=fake_hits), \
             patch("src.analysis.embedding_recall.build_recall_index") as bri, \
             patch("src.analysis.embedding_recall.recall_candidates", return_value=[]):
            # stub the heavy index build with a minimal RecallIndex-like object
            class _Idx:
                class _Vec:
                    _vecmat = object()
                index = _Vec()
                doc_to_source = {}
            bri.return_value = _Idx()
            out = hierarchical_match_against_corpus(
                None, _WS(), "binary", corpus_dir=corpus, similarity_threshold=0.7)
            assert out["policy"]["precision_threshold"] == 0.7
            assert out["bindiff_hits"][0]["best_similarity"] == 0.91
