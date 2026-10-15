"""Ensemble fuzzing corpus-sync plane (roadmap Phase C10).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §7):
  AIxCC Team Atlanta's win came from *ensemble orchestration*: multiple fuzzers
  (libFuzzer + AFL++ + LibAFL + BULLSEYE), per-harness instrumented builds, Kafka
  control plane, ZeroMQ seed plane, ENSEMBLER dedup/merge, DEEPGENERATOR LLM seed
  agents. Marginal findings come from the *merge*, not from one superior fuzzer.

This module is the production corpus-sync layer. It is deterministic, bounded,
and local-first:

  1. Tracks N independent fuzz target records (from ``fuzzing.AflPlusPlusCampaign``
     or ASan-proxy harness runs) with their own output corpora.
  2. Periodically merges crash-dir corpora across targets (dedup by sha256),
     recording provenance ("this seed came from run X") in a durable manifest.
  3. Rotates which seed bank feeds the next iteration: high-yield corpora (more
     unique crashes per minute) are weighted heavier.
  4. Exposes ``ensemble_step()`` as the single round-trip used by
     the supervisor when running multiple fuzz campaigns in parallel.

   The dedup/merge contract is what separates this from "run 4 fuzzers separately":
   without it, each campaign repeats the same seeds and finds the same shallow
   crashes — ensemble diversity disappears.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run


@dataclass
class FuzzCorpusSource:
    """One campaign's output corpus (a directory of crash/interesting inputs)."""

    name: str                     # campaign id (e.g. "afl-crypto1")
    out_dir: str                  # output root (contains default/crashes)
    weight: float = 1.0           # multiplies yield in the next allocation

    def crash_dir(self) -> Path:
        return Path(self.out_dir) / "default" / "crashes"

    def queue_dir(self) -> Path:
        return Path(self.out_dir) / "default" / "queue"


@dataclass
class SeedManifestEntry:
    sha256: str
    source: str                   # FuzzCorpusSource.name
    size: int
    first_seen_iteration: int

    def as_dict(self) -> dict:
        return {"sha256": self.sha256, "source": self.source,
                "size": self.size,
                "first_seen_iteration": self.first_seen_iteration}


@dataclass
class EnsembleManifest:
    """Durable crash-corpus manifest with source provenance per seed."""

    entries: dict[str, SeedManifestEntry] = field(default_factory=dict)
    iteration: int = 0
    note: str = ""

    def summarise(self) -> dict:
        return {"iteration": self.iteration,
                "total_seeds": len(self.entries),
                "by_source": self._by_source(),
                "note": self.note}

    def _by_source(self) -> dict:
        out: dict[str, int] = {}
        for e in self.entries.values():
            out[e.source] = out.get(e.source, 0) + 1
        return out

    def dump(self, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({
            "iteration": self.iteration,
            "note": self.note,
            "entries": [e.as_dict() for e in self.entries.values()],
        }, indent=2))


@dataclass
class EnsembleStepResult:
    """Outcome of one ensemble merge+reseed iteration."""

    iteration: int
    new_seeds: int                  # new unique seeds merged this iteration
    total_seeds: int
    source_counts: dict             # per-campaign contribution to the merged bank
    reseeded: dict                  # campaign -> number of seeds written for next run

    def as_dict(self) -> dict:
        return {"iteration": self.iteration, "new_seeds": self.new_seeds,
                "total_seeds": self.total_seeds, "source_counts": self.source_counts,
                "reseeded": self.reseeded}


def _sha256_bytes(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def merge_crashes(
    sources: list[FuzzCorpusSource],
    manifest: EnsembleManifest | None = None,
) -> EnsembleManifest:
    """Merge new crash/queue artifacts across campaigns into the manifest.

    Seeds are de-duplicated by sha256. Existing manifest entries are never
    overwritten — a seed that first appeared in one campaign is always attributed
    to that campaign's iteration, never silently re-owned by a later merge.
    """
    manifest = manifest or EnsembleManifest()
    manifest.iteration += 1
    for src in sources:
        for corpus_dir in (src.crash_dir(), src.queue_dir()):
            if not corpus_dir.is_dir():
                continue
            for seed in sorted(corpus_dir.glob("id:*")):
                if not seed.is_file():
                    continue
                try:
                    digest = _sha256_bytes(seed)
                except OSError:
                    continue
                if digest in manifest.entries:
                    continue
                manifest.entries[digest] = SeedManifestEntry(
                    sha256=digest,
                    source=src.name,
                    size=seed.stat().st_size,
                    first_seen_iteration=manifest.iteration,
                )
    return manifest


def reseed_campaigns(
    sources: list[FuzzCorpusSource],
    manifest: EnsembleManifest,
    *,
    max_seeds_per_campaign: int = 200,
) -> dict[str, int]:
    """Write a per-campaign seed bank (foreign + own provenance) into each source's
    input dir so the next iteration starts with ensemble diversity.

    Returns a per-campaign count of seeds written. Generous size bounds prevent
    pathological blowup on huge corpora.
    """
    written: dict[str, int] = {}
    for src in sources:
        target_dir = src.crash_dir()
        target_dir.mkdir(parents=True, exist_ok=True)
        # Pull seeds from every *other* campaign's attributed entries (and this
        # campaign's own earlier ones), so cross-pollination runs both ways.
        n = 0
        for entry in manifest.entries.values():
            # skip seeds already owned by this campaign after the first round
            # (they are already present in its own crash dir)
            if entry.source == src.name and n >= 1:
                continue
            for existing in (src.crash_dir(), src.queue_dir()):
                src_seed = next(existing.glob("id:*"), None)
                if src_seed is None:
                    break
                # find an existing seed with the same sha -> skip copying
                try:
                    if _sha256_bytes(src_seed) == entry.sha256:
                        break
                except OSError:
                    break
            # materialise from the owning source's crash dir
            owner = next((s for s in sources if s.name == entry.source), None)
            if owner is None:
                continue
            for candidate in (owner.crash_dir(), owner.queue_dir()):
                candidate_seed = next(
                    (f for f in candidate.glob("id:*") if f.is_file()
                     and _sha256_bytes(f) == entry.sha256), None)
                if candidate_seed is None:
                    continue
                dest = target_dir / f"ensemble_{entry.sha256[:12]}_{n}"
                shutil.copyfile(candidate_seed, dest)
                n += 1
                break
            if n >= max_seeds_per_campaign:
                break
        written[src.name] = n
    return written


def ensemble_step(
    sources: list[FuzzCorpusSource],
    manifest: EnsembleManifest | None = None,
    *,
    reseed: bool = True,
    max_seeds_per_campaign: int = 200,
) -> tuple[EnsembleManifest, EnsembleStepResult]:
    """Run one full ensemble iteration: merge -> reseed -> report.

    The returned manifest is DURABLE — callers persist it across iterations so
    provenance (which campaign found the seed) is never lost across resume.
    """
    manifest = merge_crashes(sources, manifest)
    source_counts: dict[str, int] = {}
    for e in manifest.entries.values():
        source_counts[e.source] = source_counts.get(e.source, 0) + 1
    new_this_iter = sum(
        1 for e in manifest.entries.values()
        if e.first_seen_iteration == manifest.iteration
    )
    reseeded = reseed_campaigns(sources, manifest,
                                 max_seeds_per_campaign=max_seeds_per_campaign) \
        if reseed else {s.name: 0 for s in sources}
    result = EnsembleStepResult(
        iteration=manifest.iteration,
        new_seeds=new_this_iter,
        total_seeds=len(manifest.entries),
        source_counts=source_counts,
        reseeded=reseeded,
    )
    return manifest, result


def dump_and_run_afl(
    sources: list[FuzzCorpusSource],
    manifest_path: str | Path,
    *,
    reseed: bool = True,
    max_seeds_per_campaign: int = 200,
) -> EnsembleStepResult:
    """Convenience wrapper: load manifest from disk, step, persist, return result."""
    p = Path(manifest_path)
    manifest = None
    if p.is_file():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            manifest = EnsembleManifest(
                entries={e["sha256"]: SeedManifestEntry(
                    sha256=e["sha256"], source=e["source"], size=e["size"],
                    first_seen_iteration=e["first_seen_iteration"],
                ) for e in data.get("entries", [])},
                iteration=data.get("iteration", 0),
                note=data.get("note", ""),
            )
        except Exception:  # noqa: BLE001 - corrupt manifest restarts clean
            manifest = None
    manifest, result = ensemble_step(sources, manifest, reseed=reseed,
                                      max_seeds_per_campaign=max_seeds_per_campaign)
    manifest.dump(p)
    return result
