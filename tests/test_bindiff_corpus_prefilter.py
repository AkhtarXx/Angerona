"""Behavior tests for hierarchical corpus search (roadmap Phase A3).

Proves the function-count prefilter:
  1. estimates function counts deterministically from .BinExport-shaped bytes.
  2. prunes corpus entries whose size ratio makes the similarity threshold unreachable.
  3. never prunes when counts are unknown (0) — fail-open on size uncertainty.
  4. caps the shortlist to max_candidates by closeness of size ratio.
  5. end-to-end: match_against_corpus only spends diff_binary on the shortlist.
"""
from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import patch

from src.analysis import bindiff as bd


def _fake_binexport(path: Path, n_functions: int) -> Path:
    """Bytes shaped like a real .BinExport: one name marker per function record."""
    record = b"\x1a" + bytes([8]) + b"sub_0001" + b"\x00" * 16
    path.write_bytes(record * n_functions)
    return path


class _WS:
    def __init__(self, root: Path):
        self.raw_dir = root

    def log(self, *_a, **_k):  # tolerate ws.log call
        pass


# ---------------------------------------------------------------- count parsing

def test_function_count_estimator_is_deterministic():
    with tempfile.TemporaryDirectory() as td:
        p = _fake_binexport(Path(td) / "x.BinExport", 20)
        a = bd._binexport_function_count(p)
        b = bd._binexport_function_count(p)
        assert a == b > 0


def test_function_count_unreadable_is_zero():
    assert bd._binexport_function_count("/nonexistent/nope.BinExport") == 0
    with tempfile.TemporaryDirectory() as td:
        empty = Path(td) / "empty.BinExport"
        empty.write_bytes(b"")
        assert bd._binexport_function_count(empty) == 0


# ---------------------------------------------------------------- prefilter

def test_prefilter_prunes_size_mismatched():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subject = _fake_binexport(td / "subject.BinExport", 100)
        refs = [
            _fake_binexport(td / f"ref{i}.BinExport", n)
            for i, n in enumerate([100, 95, 30, 5, 120])
        ]
        shortlist, stats = bd._corpus_prefilter(
            subject, refs, similarity_threshold=0.7, size_factor=0.5)
        # threshold floor = 0.7*0.5 = 0.35 -> 5/100 (0.05) and 30/100 (0.30) pruned
        names = {p.name for p in shortlist}
        assert "ref2.BinExport" not in names  # 30 functions
        assert "ref3.BinExport" not in names  # 5 functions
        assert {"ref0.BinExport", "ref1.BinExport", "ref4.BinExport"} <= names
        assert stats["prefiltered"] == 2


def test_prefilter_failopen_when_count_unknown():
    """Unparseable entries are kept (cannot reject on size)."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subject = td / "subject.BinExport"
        subject.write_bytes(b"\x00" * 4)   # zero estimated count
        refs = [_fake_binexport(td / "ref.BinExport", 10)]
        shortlist, stats = bd._corpus_prefilter(subject, refs, similarity_threshold=0.9)
        assert refs == shortlist and stats["prefiltered"] == 0


def test_prefilter_caps_by_ratio_closeness():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subject = _fake_binexport(td / "s.BinExport", 100)
        refs = [
            _fake_binexport(td / "close.BinExport", 100),
            _fake_binexport(td / "medium.BinExport", 70),
            _fake_binexport(td / "far.BinExport", 40),
        ]
        shortlist, _ = bd._corpus_prefilter(
            subject, refs, similarity_threshold=0.2, max_candidates=2, size_factor=0.5)
        assert len(shortlist) == 2
        assert shortlist[0].name == "close.BinExport"      # ratio 1.0 first
        assert "far.BinExport" not in {p.name for p in shortlist}


def test_prefilter_threshold_zero_keeps_all():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        subject = _fake_binexport(td / "s.BinExport", 100)
        refs = [_fake_binexport(td / "r.BinExport", 3)]
        shortlist, stats = bd._corpus_prefilter(
            subject, refs, similarity_threshold=0.0, size_factor=0.5)
        assert shortlist == refs


# ---------------------------------------------------------------- end-to-end

def test_match_against_corpus_only_diffs_shortlist():
    """diff_binary must be invoked once per shortlisted entry, not per corpus file."""
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        corpus = td / "corpus"
        corpus.mkdir()
        subject = _fake_binexport(td / "subject.BinExport", 100)
        # 20 corpus files, most size-mismatched
        for i, n in enumerate([100, 90, 110] + [5] * 17):
            _fake_binexport(corpus / f"ref{i:03d}.BinExport", n)

        called_with: list[str] = []

        def _fake_diff(_cfg, _ws, primary, secondary, **_kw):
            called_with.append(Path(secondary).name)
            return bd.DiffResult(primary=str(primary), secondary=str(secondary),
                                 overall_similarity=0.9, overall_confidence=0.9)

        with patch.object(bd, "cached_export", lambda *_a, **_k: subject), \
             patch.object(bd, "diff_binary", side_effect=_fake_diff):
            hits = bd.match_against_corpus(
                None, _WS(td), binary="binary", corpus_dir=corpus,
                similarity_threshold=0.7, max_diffs=10,
            )

        # only the 3 size-plausible refs survived the prefilter
        assert set(called_with) == {"ref000.BinExport", "ref001.BinExport", "ref002.BinExport"}
        # no per-function match rows -> all hits filtered by the similarity threshold
        assert hits == []


def test_match_against_corpus_logs_prefilter_stats():
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        corpus = td / "corpus"
        corpus.mkdir()
        subject = _fake_binexport(td / "subject.BinExport", 100)
        for i, n in enumerate([100, 5, 5]):
            _fake_binexport(corpus / f"ref{i}.BinExport", n)

        logs: list[str] = []

        class WS(_WS):
            def log(self, tag, msg):
                logs.append(f"{tag}: {msg}")

        with patch.object(bd, "cached_export", lambda *_a, **_k: subject), \
             patch.object(bd, "diff_binary", side_effect=RuntimeError("skip")):
            bd.match_against_corpus(None, WS(td), "bin", corpus, similarity_threshold=0.7)

        assert any("prefilter shortlisted" in line for line in logs)
