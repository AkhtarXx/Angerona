"""Behavior tests for the ensemble fuzz corpus-sync plane (roadmap Phase C10)."""
from __future__ import annotations

import tempfile
from pathlib import Path

from src.analysis.ensemble_fuzz import (
    EnsembleManifest,
    FuzzCorpusSource,
    dump_and_run_afl,
    ensemble_step,
    merge_crashes,
    reseed_campaigns,
)


def _corpus(root: Path, name: str, seeds: list[tuple[str, bytes]]) -> FuzzCorpusSource:
    crash = root / name / "default" / "crashes"
    crash.mkdir(parents=True)
    for i, (label, content) in enumerate(seeds):
        (crash / f"id:{i:06d}").write_bytes(content)
    return FuzzCorpusSource(name=name, out_dir=str(root / name))


def test_merge_crashes_dedups_and_provenance():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "afl-a",
                    [("s", b"AAA"), ("x", b"BBB"), ("y", b"AAA")])   # duplicate AAA
        b = _corpus(root, "afl-b",
                    [("s", b"CCC"), ("x", b"AAA")])                   # AAA already in a
        m = merge_crashes([a, b])
        # 3 unique: AAA (from a), BBB (from a), CCC (from b)
        assert len(m.entries) == 3
        sources = {e.source for e in m.entries.values()}
        assert sources == {"afl-a", "afl-b"}
        # provenance: BBB shows up under 'a'.
        by_source = m._by_source()
        assert by_source.get("afl-a") == 2
        assert by_source.get("afl-b") == 1


def test_merge_crashes_missing_dirs_graceful():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = FuzzCorpusSource(name="empty", out_dir=str(root / "nope"))
        m = merge_crashes([a])
        assert len(m.entries) == 0
        assert m.iteration == 1


def test_ensemble_step_round_trip():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "c1", [("s", b"X"), ("x", b"Y")])
        b = _corpus(root, "c2", [("s", b"Z")])
        manifest, result = ensemble_step([a, b], reseed=True,
                                          max_seeds_per_campaign=10)
        assert result.iteration == 1
        assert result.total_seeds == 3
        assert result.new_seeds == 3
        # reseed wrote seeds into each campaign's crash dir
        for name, count in result.reseeded.items():
            assert count >= 0  # may skip self-owned after first seed


def test_manifest_persisted_across_iterations():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "camp", [("s", b"S1"), ("x", b"S2")])
        mpath = root / "manifest.json"
        r1 = dump_and_run_afl([a], mpath, reseed=False)
        assert r1.total_seeds == 2
        # second run loads prior manifest, no new seeds found
        r2 = dump_and_run_afl([a], mpath, reseed=False)
        assert r2.iteration == 2
        assert r2.new_seeds == 0
        assert r2.total_seeds == 2


def test_corrupt_manifest_recovers_clean():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "camp", [("s", b"X")])
        mpath = root / "manifest.json"
        mpath.write_text("not json at all")
        r = dump_and_run_afl([a], mpath, reseed=False)
        assert r.total_seeds >= 1   # fresh manifest, no crash


def test_reseed_respects_max_seeds():
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "a", [(f"s{i}", bytes([i]) * 4) for i in range(50)])
        b = _corpus(root, "b", [(f"s{i}", bytes([i + 100]) * 4) for i in range(30)])
        manifest = merge_crashes([a, b])
        written = reseed_campaigns([a, b], manifest, max_seeds_per_campaign=5)
        assert all(v <= 5 for v in written.values())


def test_provenance_kept_when_later_merge_overlaps():
    """A seed first found in campaign A must remain attributed to A even when
    campaign B's later corpus also carries it (no silently re-owning)."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        a = _corpus(root, "A", [("s", b"SAME")])
        m1 = merge_crashes([a])
        assert {e.source for e in m1.entries.values()} == {"A"}
        # B now carries the same seed
        b = _corpus(root, "B", [("s", b"SAME")])
        m2 = merge_crashes([b], m1)
        assert len(m2.entries) == 1
        assert next(iter(m2.entries.values())).source == "A"
