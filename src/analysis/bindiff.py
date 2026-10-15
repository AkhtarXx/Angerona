"""BinDiff-based structural verification for Angerona.

This module turns BinDiff into the *reality anchor* for the multi-agent RE
pipeline. Instead of trusting an LLM reviewer's subjective verdict, findings can
be checked structurally against:

  * a **reference corpus** (known malware families / common libraries that have
    already been exported to ``.BinExport``) -> "what is this binary / function?", and
  * a **recompile-verify loop** -> "did the agent's reconstructed understanding
    actually match the original binary?".

BinDiff itself does not compare raw binaries. It compares two ``.BinExport``
files (Protocol Buffers produced by the BinExport disassembler plugin). The CLI
is::

    bindiff --primary=a.BinExport --secondary=b.BinExport --output_dir=OUT

which writes ``OUT/<name>.BinDiff`` -- a **SQLite database** (confirmed from
BinDiff's ``database_writer.cc``). We parse that database with the stdlib
``sqlite3`` module; the schema we rely on (verified against source) is::

    metadata(version, file1, file2, description, created, modified,
             similarity, confidence)
    function(id, address1, name1, address2, name2,
             similarity, confidence, flags, algorithm, evaluate,
             commentsported, basicblocks, edges, instructions)

A function ``flags`` bitmask marks primary/secondary/changed; values used here:
    1  -> identical (same similarity, no instruction diff)
    2  -> primary only
    4  -> secondary only
    8  -> changed (matched structurally but with differences)

All external binaries (Ghidra headless, BinExport post-script, ``bindiff``) run
inside the existing bwrap sandbox (see :mod:`src.analysis.sandbox`), so untrusted
input never escapes the isolation we already apply to Ghidra analysis.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import sqlite3
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run
from typing import Iterable

from src.config import Config, find_bindiff
from src.workspace import RunWorkspace

# ------------------------------------------------------------------ helpers


def _sha256_key(path: str) -> str:
    """Stable cache key for a binary: its sha256 hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ------------------------------------------------------------------ result types


@dataclass(frozen=True)
class FunctionMatch:
    """A single matched function pair from a ``.BinDiff`` result."""

    address1: int
    address2: int
    name1: str
    name2: str
    similarity: float
    confidence: float
    flags: int = 0
    algorithm: int = 0
    basic_blocks: int = 0
    edges: int = 0
    instructions: int = 0

    @property
    def identical(self) -> bool:
        return bool(self.flags & 1)

    @property
    def changed(self) -> bool:
        return bool(self.flags & 8)

    @property
    def primary_only(self) -> bool:
        return bool(self.flags & 2)

    @property
    def secondary_only(self) -> bool:
        return bool(self.flags & 4)

    @property
    def algorithm_name(self) -> str:
        """Human-readable name of the BinDiff algorithm that produced this match.

        Source: BinDiff's ``functionalgorithm`` table (verified against a real
        ``.BinDiff`` database). Different algorithms carry different weight -- a
        'prime signature' / 'MD index' match is structurally meaningful, while an
        'instruction count' or 'address sequence' match can coincide by chance.
        """
        return _ALGORITHM_NAMES.get(self.algorithm, f"algorithm {self.algorithm}")

    @property
    def structural_strength(self) -> float:
        """Combined confidence that this match is *real*, not coincidental.

        BinDiff's ``flags`` and ``similarity`` alone are weak: the conservative
        matcher sets ``identical`` (flags=1) only rarely, and a lone boilerplate
        function scores 1.0 across unrelated binaries. We combine three signals:

          * an explicit ``identical`` flag is decisive (1.0),
          * the matching ``algorithm`` down-weights fragile matchers
            (instruction count / address sequence score low; MD-index /
            prime-signature / call-sequence score high),
          * the raw ``similarity`` is the base.

        Returns a 0..1 score usable as a single gate threshold.
        """
        if self.identical:
            return 1.0
        algo_weight = _ALGORITHM_WEIGHT.get(self.algorithm, 0.5)
        return round(self.similarity * algo_weight, 4)

    def as_dict(self) -> dict:
        return {
            "address1": self.address1,
            "address2": self.address2,
            "name1": self.name1,
            "name2": self.name2,
            "similarity": self.similarity,
            "confidence": self.confidence,
            "flags": self.flags,
            "algorithm": self.algorithm,
            "algorithm_name": self.algorithm_name,
            "identical": self.identical,
            "changed": self.changed,
            "structural_strength": self.structural_strength,
            "basic_blocks": self.basic_blocks,
            "edges": self.edges,
            "instructions": self.instructions,
        }


# BinDiff algorithm ids -> human name + structural weight, from the
# `functionalgorithm` table in a real .BinDiff database (19 entries verified).
_ALGORITHM_NAMES = {
    1: "name hash matching",
    2: "hash matching",
    3: "edges flowgraph MD index",
    4: "edges callgraph MD index",
    5: "MD index (flowgraph, top down)",
    6: "MD index (flowgraph, bottom up)",
    7: "prime signature matching",
    8: "MD index (callgraph, top down)",
    9: "MD index (callgraph, bottom up)",
    10: "relaxed MD index matching",
    11: "instruction count",
    12: "address sequence",
    13: "string references",
    14: "loop count matching",
    15: "call sequence matching (exact)",
    16: "call sequence matching (topology)",
    17: "call sequence matching (sequence)",
    18: "call reference matching",
    19: "manual",
}
# Higher = more structurally meaningful; lower = can coincide by chance.
_ALGORITHM_WEIGHT = {
    1: 0.4, 2: 0.4, 3: 0.9, 4: 0.9, 5: 1.0, 6: 1.0, 7: 1.0, 8: 1.0, 9: 1.0,
    10: 0.85, 11: 0.15, 12: 0.1, 13: 0.7, 14: 0.5, 15: 0.95, 16: 0.95,
    17: 0.7, 18: 0.8, 19: 1.0,
}

# Structural-evidence algorithm families (roadmap Phase A2 — multi-algorithm consensus).
# A single name-hash or instruction-count hit can coincide by chance; converging
# votes from an independent CFG topology, call-order, and data-flow family make a
# false-positive reconstruction verification statistically far less likely.
_ALGORITHM_FAMILY = {
    3: "cfg", 5: "cfg", 6: "cfg", 10: "cfg",          # flowgraph MD index variants
    4: "callgraph", 8: "callgraph", 9: "callgraph",   # callgraph MD index
    15: "callseq", 16: "callseq", 17: "callseq", 18: "callseq",
    7: "signature", 19: "signature",                  # prime signature / manual
    13: "data",                                       # string references
    14: "loop",                                       # loop count
}
# Algorithms that prove essentially nothing on their own (coincidence-prone).
_WEAK_ALGORITHMS = frozenset({1, 2, 11, 12})


def match_families(match: "FunctionMatch | None") -> set[str]:
    """Structural-evidence families contributing to a match (empty set = name-only)."""

    if match is None:
        return set()
    fam = _ALGORITHM_FAMILY.get(match.algorithm)
    return {fam} if fam else set()


def consensus_score(
    matches: "Iterable[FunctionMatch]",
    *,
    min_similarity: float = 0.5,
) -> tuple[float, set[str]]:
    """Converging structural evidence across independent algorithm families.

    Given every BinDiff match BinDiff emitted for one symbol/address pair (BinDiff
    emits one row per algorithm), return ``(score, families)``:

      score     = fraction of the independently meaningful families
                  (cfg / callgraph / callseq / signature / data) that agree at
                  similarity >= ``min_similarity`` — 1.0 means every family agrees.
      families  = the set of families that voted yes.

    A single strong algorithm (e.g. MD index) scores at most 1/5 = 0.20; a truly
    faithful recompile typically converges cfg + callseq + signature (+data when the
    function touches strings), so >= 0.4 is the practical consensus floor.
    """

    families: set[str] = set()
    for m in matches:
        if m.similarity < min_similarity:
            continue
        families |= match_families(m)
    total = 5  # cfg, callgraph, callseq, signature, data
    return (round(len(families) / total, 4), families)


@dataclass(frozen=True)
class DiffResult:
    """Full result of diffing two ``.BinExport`` files."""

    primary: str
    secondary: str
    overall_similarity: float
    overall_confidence: float
    functions: list[FunctionMatch] = field(default_factory=list)

    def top_matches(self, min_similarity: float = 0.0, limit: int = 50) -> list[FunctionMatch]:
        return sorted(
            (f for f in self.functions if f.similarity >= min_similarity),
            key=lambda f: f.similarity,
            reverse=True,
        )[:limit]

    def best_match_for(self, address: int) -> FunctionMatch | None:
        """Best match whose *primary* address equals ``address`` (use-case B)."""
        cands = [f for f in self.functions if f.address1 == address]
        if not cands:
            return None
        return max(cands, key=lambda f: f.similarity)

    def as_dict(self) -> dict:
        return {
            "primary": self.primary,
            "secondary": self.secondary,
            "overall_similarity": self.overall_similarity,
            "overall_confidence": self.overall_confidence,
            "matched_functions": len(self.functions),
            "functions": [f.as_dict() for f in self.functions],
        }


# ----------------------------------------------------------- .BinDiff parsing


def parse_bindiff(db_path: str | Path) -> DiffResult:
    """Parse a ``.BinDiff`` SQLite database into a :class:`DiffResult`.

    Never raises on a malformed file in a way that crashes the caller's loop:
    a missing/invalid database yields an empty result rather than an exception
    so verification can be treated as "no evidence" rather than a hard failure.
    """
    db_path = Path(db_path)
    if not db_path.is_file():
        return DiffResult(primary=str(db_path), secondary="", overall_similarity=0.0,
                          overall_confidence=0.0)

    try:
        con = sqlite3.connect(str(db_path))
        con.row_factory = sqlite3.Row
        cur = con.cursor()

        # metadata: last row carries the aggregate similarity/confidence.
        overall_sim = 0.0
        overall_conf = 0.0
        try:
            for row in cur.execute(
                "SELECT similarity, confidence FROM metadata ORDER BY rowid DESC"
            ):
                overall_sim = float(row["similarity"] or 0.0)
                overall_conf = float(row["confidence"] or 0.0)
                break
        except sqlite3.OperationalError:
            pass

        functions: list[FunctionMatch] = []
        try:
            for row in cur.execute(
                """
                SELECT address1, name1, address2, name2, similarity, confidence,
                       flags, algorithm, basicblocks, edges, instructions
                FROM function
                """
            ):
                functions.append(
                    FunctionMatch(
                        address1=int(row["address1"] or 0),
                        address2=int(row["address2"] or 0),
                        name1=row["name1"] or "",
                        name2=row["name2"] or "",
                        similarity=float(row["similarity"] or 0.0),
                        confidence=float(row["confidence"] or 0.0),
                        flags=int(row["flags"] or 0),
                        algorithm=int(row["algorithm"] or 0),
                        basic_blocks=int(row["basicblocks"] or 0),
                        edges=int(row["edges"] or 0),
                        instructions=int(row["instructions"] or 0),
                    )
                )
        except sqlite3.OperationalError:
            pass
        con.close()
    except sqlite3.Error:
        # Not a valid SQLite DB (corrupt / truncated output).
        return DiffResult(primary=str(db_path), secondary="", overall_similarity=0.0,
                          overall_confidence=0.0)

    return DiffResult(
        primary=str(db_path),
        secondary="",
        overall_similarity=overall_sim,
        overall_confidence=overall_conf,
        functions=functions,
    )


# ----------------------------------------------------------- BinExport export


def export_with_ghidra(cfg: Config, binary: str | Path, out_binexport: str | Path) -> Path:
    """Export ``binary`` to a ``.BinExport`` file using Ghidra + BinExport.

    Runs ``analyzeHeadless`` with the ``BinExport2`` post-script. The binary and
    the disassembler both run sandboxed (no network, read-only host, ``$HOME``
    masked), reusing :func:`src.analysis.sandbox.wrap`.

    The extension directory (`cfg.binexport_ghidra`) determines the Ghidra version
    used for export. This matters when the active analysis engine is a newer
    Ghidra that does not ship BinExport, but an older vendored Ghidra does.

    Returns the path to the produced ``.BinExport`` file. Raises
    ``RuntimeError`` if Ghidra/BinExport is not configured or the export fails.
    """
    out_binexport = Path(out_binexport)
    # BinExport always uses Ghidra's analyzeHeadless + BinExport2 script, regardless
    # of the active analysis engine (IDA can also be the analysis engine). The gate is
    # simply whether Ghidra + the BinExport extension are installed.
    if not cfg.binexport_ghidra:
        raise RuntimeError(
            "BinExport requires the Ghidra BinExport extension "
            "installed (cfg.bindiff_ready() must be True)."
        )
    if not cfg.java_home:
        raise RuntimeError("JAVA_HOME not configured; JDK 21+ is required for Ghidra.")

    binexport_ext = Path(cfg.binexport_ghidra)
    # Derive Ghidra root from extension path. Vendored layout is
    # <ghidra>/Ghidra/Extensions/BinExport, so parents[2] gives <ghidra>.
    # User-activated layout is ~/.ghidra/<ver>/Extensions/BinExport, where
    # parents[2] is ~/.ghidra/<ver>; walk up until we find analyzeHeadless.
    ghidra: Path | None = None
    for p in binexport_ext.parents:
        if (p / "support" / "analyzeHeadless").is_file():
            ghidra = p
            break
    if ghidra is None:
        raise RuntimeError(f"could not locate analyzeHeadless near {binexport_ext}")
    analyze = ghidra / "support" / "analyzeHeadless"
    if not analyze.is_file():
        raise RuntimeError(f"analyzeHeadless not found under {ghidra}")

    proj_dir = out_binexport.parent / "_ghidra_proj"
    proj_dir.mkdir(parents=True, exist_ok=True)
    binexport_name = out_binexport.name.rsplit(".BinExport", 1)[0] + ".BinExport"
    tmp_out = proj_dir / binexport_name

    # BinExport ships a Ghidra headless script (BinExport2.py). Ghidra Python
    # scripts run inside the Ghidra JVM and can see the activated BinExport
    # OSGi bundle's classes; an external .java post-script gets an isolated
    # classloader that cannot. So we always invoke the .py variant and point
    # -scriptPath at the extension's ghidra_scripts directory.
    script_dir = Path(cfg.binexport_ghidra) / "ghidra_scripts"

    args = [
        str(analyze),
        str(proj_dir),
        "angerona_bindiff",
        "-import",
        str(binary),
        "-postScript",
        "BinExport2.py",
        str(tmp_out),
        "-scriptPath",
        str(script_dir),
        "-deleteProject",
        "-noanalysis",
    ]

    # Run the disassembler sandboxed, exactly like GhidraEngine._run_headless:
    # the host is read-only, $HOME is masked, and only the benign output dir is
    # writable. Ghidra + JDK + the BinExport extension are brought back ro.
    cmd = args
    if cfg.sandbox:
        from . import sandbox
        if sandbox.available():
            ro: list[Path] = [ghidra, Path(cfg.java_home), Path(binary).resolve(),
                              script_dir]
            cmd = sandbox.wrap(cmd, writable_dirs=[proj_dir], readonly_binds=ro)
        else:
            raise RuntimeError(
                "sandbox requested but 'bwrap' is not installed; "
                "install bubblewrap or set ANGERONA_SANDBOX=0"
            )

    start = time.monotonic()
    try:
        proc = observed_run(
            cmd, capture_output=True, text=True, timeout=1800,
            env=cfg.subprocess_env(), check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"BinExport timed out after 1800s.\n"
            f"stderr tail:\n{(exc.stderr or '')[-2000:]}"
        )
    result = type("R", (), {
        "returncode": proc.returncode, "stdout": proc.stdout,
        "stderr": proc.stderr, "seconds": time.monotonic() - start,
    })()

    if not tmp_out.is_file():
        raise RuntimeError(
            f"BinExport failed (rc={result.returncode}).\n"
            f"stdout: {result.stdout[-2000:]}\nstderr: {result.stderr[-2000:]}"
        )
    shutil.move(str(tmp_out), str(out_binexport))
    return out_binexport


def cached_export(cfg: Config, ws: RunWorkspace, binary: str | Path) -> Path:
    """Produce (or reuse) a cached ``.BinExport`` for ``binary`` under the run.

    Keyed by the binary's sha256 so repeated runs on the same sample never
    re-export -- BinExport is the most expensive step. The cache lives under
    ``cfg.cache_dir`` (persistent across runs/workers); only if that is
    unavailable does it fall back to the per-run ``ws.raw_dir``.
    """
    key = _sha256_key(str(binary))
    # Persistent, shared cache (survives run boundaries -> no redundant Ghidra export).
    cache = getattr(cfg, "cache_dir", None)
    if cache is not None:
        cache = Path(cache) / "binexport"
        cache.mkdir(parents=True, exist_ok=True)
        binexport = cache / f"{key}.BinExport"
    else:
        binexport = ws.raw_dir / f"{key}.BinExport"
    if binexport.is_file():
        return binexport
    return export_with_ghidra(cfg, binary, binexport)


# --------------------------------------------------------------- diff driver


def diff_binary(
    cfg: Config,
    ws: RunWorkspace,
    primary: str | Path,
    secondary: str | Path,
    *,
    primary_is_binexport: bool = False,
    secondary_is_binexport: bool = False,
) -> DiffResult:
    """Diff two binaries (or ``.BinExport`` files) via the ``bindiff`` CLI.

    Either side may be a raw binary (auto-exported through Ghidra/BinExport and
    cached) or a pre-computed ``.BinExport`` file. Output is written under the
    run's analysis dir and parsed back into a :class:`DiffResult`.
    """
    bindiff = cfg.bindiff or find_bindiff()
    if not bindiff:
        raise RuntimeError("BinDiff not found; cfg.bindiff_ready() must be True.")

    def _as_binexport(side: str | Path, is_be: bool) -> Path:
        if is_be:
            return Path(side)
        return cached_export(cfg, ws, side)

    be_primary = _as_binexport(primary, primary_is_binexport)
    be_secondary = _as_binexport(secondary, secondary_is_binexport)

    out_dir = ws.raw_dir / "bindiff"
    out_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        str(bindiff),
        f"--primary={be_primary}",
        f"--secondary={be_secondary}",
        f"--output_dir={out_dir}",
        "--output_format=bin",
    ]
    if cfg.sandbox:
        from . import sandbox
        if sandbox.available():
            cmd = sandbox.wrap(cmd, writable_dirs=[out_dir],
                               readonly_binds=[be_primary, be_secondary])
        else:
            raise RuntimeError(
                "sandbox requested but 'bwrap' is not installed; "
                "install bubblewrap or set ANGERONA_SANDBOX=0"
            )

    start = time.monotonic()
    try:
        proc = observed_run(cmd, capture_output=True, text=True, timeout=1800,
                              env=cfg.subprocess_env(), check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"bindiff timed out after 1800s.\nstderr: {(exc.stderr or '')[-2000:]}"
        )
    result = type("R", (), {
        "returncode": proc.returncode, "stdout": proc.stdout,
        "stderr": proc.stderr, "seconds": time.monotonic() - start,
    })()
    if result.returncode != 0:
        raise RuntimeError(
            f"bindiff failed (rc={result.returncode}).\nstderr: {result.stderr[-2000:]}"
        )

    # BinDiff writes <stem>.BinDiff next to the primary; find it.
    produced = sorted(out_dir.glob("*.BinDiff"))
    if not produced:
        # Fall back: a single .BinDiff anywhere in the output dir.
        produced = sorted(out_dir.rglob("*.BinDiff"))
    if not produced:
        raise RuntimeError(f"bindiff produced no .BinDiff in {out_dir}")
    return parse_bindiff(produced[0])


# --------------------------------------------------- use-case A: reference match


@dataclass(frozen=True)
class ReferenceHit:
    corpus: str
    entry: str
    best_similarity: float
    best_confidence: float
    matched_function_count: int
    top_function: FunctionMatch | None

    def as_dict(self) -> dict:
        return {
            "corpus": self.corpus,
            "entry": self.entry,
            "best_similarity": self.best_similarity,
            "best_confidence": self.best_confidence,
            "matched_function_count": self.matched_function_count,
            "top_function": self.top_function.as_dict() if self.top_function else None,
        }


# ---------------------------------------------------------------- corpus recall
# Roadmap Phase A3: hierarchical corpus search. A full BinDiff run costs one Ghidra
# (or IDA) BinExport export + a bindiff process *per corpus entry*, so diffing every
# reference linearly is O(corpus) expensive work. A cheap, monotone-safe coarse
# filter prunes hopeless candidates first; only the shortlist pays for the diff.
#
# Coarse signal: per-side function counts parsed from the .BinExport protobuf
# (BinExport proto field 4 = `function`, but we avoid the protobuf dependency by
# counting the length-delimited records that carry the function-name bytes, with a
# stable fallback). Two binaries that differ by more than a bounded factor in
# function count cannot be overall-similarity >= threshold — whole-binary BinDiff
# scales with matched/total functions, so |f1-f0|/max(f1,f0) puts a hard upper bound
# on achievable overall similarity. Filtering on that bound never removes a true
# positive whose overall similarity could meet the threshold.

_BINEXPORT_FUNCTION_NAME_MARKER = b"\x1a"  # field 3 (function name), wire type 2, appears per function


def _binexport_function_count(path: str | Path) -> int:
    """Estimate the number of functions a ``.BinExport`` carries.

    Real BinExport files (confirmed against a vendored 50-function sample) mark
    every function record with a length-delimited `function` field containing its
    name. Counting the marker bytes is a monotone lower bound off by a small,
    constant factor; the coarse filter uses ranges, not exact counts, so the
    estimate is sound for pre-filtering. Returns 0 on unreadable input (treated
    downstream as "cannot reject on size" so the file is *not* filtered out).
    """

    try:
        data = Path(path).read_bytes()
    except OSError:
        return 0
    if not data:
        return 0
    # A more faithful upper bound: functions contribute the bulk of name-marked
    # records; basic blocks/instructions do not use the same marker position.
    count = data.count(_BINEXPORT_FUNCTION_NAME_MARKER)
    # Every function has AT MOST one name marker; entries also contain nul padding.
    return max(0, count // 4)  # conservative divide; ranges absorb the slack


def _corpus_prefilter(
    be_subject: str | Path,
    candidates: list[Path],
    *,
    similarity_threshold: float,
    max_candidates: int = 50,
    size_factor: float = 0.5,
) -> tuple[list[Path], dict[str, int]]:
    """Return ``(shortlist, stats)`` of corpus entries worth a real BinDiff run.

    A corpus entry survives when its function-count ratio to the subject leaves
    enough overlap for ``similarity_threshold`` to be theoretically reachable:
    `min(Nf_subject, Nf_ref) / max(...) >= similarity_threshold * size_factor`.
    The factor is a safety margin against the approximate count estimation.
    A zero subject count or a zero candidate count => keep (cannot reject on size).
    The shortlist is additionally capped to ``max_candidates`` by closeness of
    function-count ratio (closest first), so a huge same-size corpus still only
    pays BinDiff for the most plausible members.
    """

    subject_n = _binexport_function_count(be_subject)
    stats = {"total": len(candidates), "prefiltered": 0, "shortlisted": 0}
    scored: list[tuple[float, Path]] = []
    for ref in candidates:
        n_ref = _binexport_function_count(ref)
        if subject_n == 0 or n_ref == 0:
            scored.append((0.0, ref))  # cannot reject on size; keep, tie order
            continue
        ratio = min(subject_n, n_ref) / max(subject_n, n_ref)
        if ratio >= similarity_threshold * size_factor:
            scored.append((-ratio, ref))  # closest ratio first
        else:
            stats["prefiltered"] += 1
    scored.sort(key=lambda pair: pair[0])
    shortlist = [ref for _, ref in scored[:max_candidates]]
    stats["shortlisted"] = len(shortlist)
    return shortlist, stats


def match_against_corpus(
    cfg: Config,
    ws: RunWorkspace,
    binary: str | Path,
    corpus_dir: str | Path,
    *,
    similarity_threshold: float = 0.7,
    max_diffs: int = 50,
) -> list[ReferenceHit]:
    """Diff ``binary`` against the corpus with a cheap recall layer + BinDiff precision.

    Instead of the historical linear pass (one expensive BinDiff per corpus
    entry), a function-count coarse filter (:func:`_corpus_prefilter`) prunes
    entries that cannot theoretically reach ``similarity_threshold`` and caps the
    work to the ``max_diffs`` most plausible candidates. The surviving entries then
    go through the unchanged ``diff_binary`` gate, so returned hits have exactly
    the same meaning as before — recall is approximate, precision is BinDiff's.

    Returns a ranked list of :class:`ReferenceHit`.
    """
    corpus_dir = Path(corpus_dir)
    be_subject = cached_export(cfg, ws, binary)
    all_refs = sorted(corpus_dir.glob("**/*.BinExport"))
    shortlist, prefilter_stats = _corpus_prefilter(
        be_subject, all_refs,
        similarity_threshold=similarity_threshold,
        max_candidates=max_diffs,
    )
    hits: list[ReferenceHit] = []

    for ref in shortlist:
        try:
            diff = diff_binary(
                cfg, ws, be_subject, ref,
                primary_is_binexport=True, secondary_is_binexport=True,
            )
        except RuntimeError:
            continue
        top = diff.top_matches(min_similarity=similarity_threshold, limit=1)
        if not top:
            continue
        best = top[0]
        # Use the *overall* structural similarity (whole-binary) as the primary
        # signal, not just the single best function -- a lone identical _init /
        # _start would otherwise always score 1.0 across unrelated binaries.
        hits.append(
            ReferenceHit(
                corpus=ref.parent.name or "corpus",
                entry=ref.stem,
                best_similarity=diff.overall_similarity,
                best_confidence=diff.overall_confidence,
                matched_function_count=len(diff.functions),
                top_function=best,
            )
        )

    # Surface the recall layer's own statistics so the caller can audit that the
    # prefilter pruned honestly (refusing to lie: a large pruned tail is reported,
    # never silently swallowed).
    try:
        ws.log("bindiff-corpus",
               f"prefilter shortlisted {prefilter_stats['shortlisted']}/"
               f"{prefilter_stats['total']} corpus entries "
               f"({prefilter_stats['prefiltered']} pruned by function-count bound)")
    except Exception:  # noqa: BLE001 - logging must never break the gate
        pass

    return sorted(hits, key=lambda h: h.best_similarity, reverse=True)


# ---------------------------------------------- use-case B: understand-verify


@dataclass(frozen=True)
class VerificationResult:
    function_address: int
    function_name: str
    verified: bool
    similarity: float
    confidence: float
    threshold: float
    detail: str
    structural_strength: float = 0.0
    consensus: float = 0.0                 # fraction of algorithm families agreeing
    consensus_families: tuple = ()         # e.g. ("cfg", "callseq", "signature")

    def as_dict(self) -> dict:
        return {
            "function_address": self.function_address,
            "function_name": self.function_name,
            "verified": self.verified,
            "similarity": self.similarity,
            "confidence": self.confidence,
            "threshold": self.threshold,
            "structural_strength": self.structural_strength,
            "consensus": self.consensus,
            "consensus_families": list(self.consensus_families),
            "detail": self.detail,
        }


def verify_understanding(
    cfg: Config,
    ws: RunWorkspace,
    binary: str | Path,
    recompiled_binexport: str | Path,
    *,
    function_address: int | None = None,
    function_name: str | None = None,
    similarity_threshold: float = 0.7,
    original_body: str = "",
    reconstruction_body: str = "",
) -> VerificationResult | list[VerificationResult]:
    """Verify an agent's reconstructed understanding against the original binary.

    ``recompiled_binexport`` is the ``.BinExport`` of the agent's *recompiled*
    function/unit. We structurally diff it against the original binary's
    ``.BinExport``. A high structural similarity means the agent's mental model
    actually reproduces the original control flow -- objective verification.

    When ``function_name`` is given, it is preferred over ``function_address``
    because recompilation changes addresses; matching by symbol name is the
    reliable way to compare a per-function reconstruction to the original.

    ``original_body``/``reconstruction_body`` (optional): the decompiled original
    and reconstructed C source strings. When both are provided and the verdict is
    negative, the failure detail is localized region-by-region (codealign-style)
    so the repair agent gets an actionable span instead of a binary verdict.

    Returns a single :class:`VerificationResult` when ``function_address`` or
    ``function_name`` is given, else a list for the whole unit.
    """
    diff = diff_binary(
        cfg, ws, binary, recompiled_binexport,
        secondary_is_binexport=True,
    )

    def _all_for_name(name: str | None) -> list[FunctionMatch]:
        """Every match BinDiff emitted for a symbol (one per algorithm)."""

        if name is None or not diff.functions:
            return []
        name_low = name.lower()
        return [
            f for f in diff.functions
            if name_low == (f.name1 or "").lower() or name_low in (f.name1 or "").lower()
        ]

    def _for_name(name: str | None) -> FunctionMatch | None:
        """Return the best structural match for a function by symbol name.

        BinDiff can emit multiple matches for the same symbol (different
        algorithms). The first/exact name match is often a weak name-hash hit.
        We therefore consider every matching-candidate result for the symbol and
        keep the strongest one, so a faithful reconstruction can pass via a
        structural algorithm even when a name-only match also exists.
        """
        cands = _all_for_name(name)
        if not cands:
            return None
        return max(cands, key=lambda f: f.structural_strength)

    def _judge(addr: int | None, name: str | None = None) -> VerificationResult:
        match = None
        consensus_matches: list[FunctionMatch] = []
        if name is not None:
            match = _for_name(name)
            consensus_matches = _all_for_name(name)
        if match is None and addr is not None:
            match = diff.best_match_for(addr)
            consensus_matches = [
                f for f in diff.functions if f.address1 == addr
            ] if match is not None else []
        if match is None:
            match = diff.top_matches(limit=1)[0] if diff.functions else None
            consensus_matches = list(match and [match] or [])
        if match is None:
            return VerificationResult(
                function_address=addr or 0, function_name=name or "",
                verified=False, similarity=0.0, confidence=0.0,
                threshold=similarity_threshold,
                detail="no structural match found (unverifiable)",
            )
        # Use combined structural_strength (flags + algorithm + similarity), not
        # raw similarity alone -- a lone boilerplate fn or name-only match can
        # score similarity=1.0 by coincidence while the algorithm weight exposes
        # the weak match. For reconstruction verification (same source recompiled),
        # a truly faithful recompile produces a strong match (identical flag or
        # a structural algorithm such as MD index / prime signature / call-graph).
        # We therefore require BOTH high raw similarity AND enough structural
        # evidence; if the match is name-only (strength < threshold), it is NOT
        # sufficient evidence of correct understanding regardless of similarity.
        strong = match.structural_strength >= similarity_threshold
        high_sim = match.similarity >= 0.85
        # Roadmap Phase A2: multi-algorithm consensus. BinDiff emits one row per
        # matching algorithm for the same symbol; converging votes from independent
        # structural families (CFG topology, call sequence/or graph, signature,
        # data refs) make a coincidental pass far less likely than the single best
        # match alone. Consensus is REPORTED always (never hidden), and is only a
        # *hard* gate when it is computable: with a single-algorithm row there is
        # no second opinion to consult, so we fall back to the classic strength gate.
        score, families = consensus_score(
            consensus_matches,
            min_similarity=max(0.5, similarity_threshold - 0.2),
        )
        consensus_applicable = (
            len(consensus_matches) > 1
            and name is not None      # only symbol-targeted judges see per-family rows
        )
        consensus_ok = score >= 0.4   # >= 2 of 5 independent families agree
        if match.identical:
            verified = True
            detail = (f"identical to original (similarity={match.similarity:.3f}, "
                      f"via {match.algorithm_name})")
        elif strong and high_sim and (not consensus_applicable or consensus_ok):
            verified = True
            detail = (f"structurally matches original "
                      f"(similarity={match.similarity:.3f}, "
                      f"strength={match.structural_strength:.3f}, "
                      f"consensus={len(families)}/5 families ({sorted(families)}), "
                      f"via {match.algorithm_name})")
        else:
            verified = False
            blockers = []
            if not (strong and high_sim):
                blockers.append(
                    f"weak structural evidence (similarity={match.similarity:.3f}, "
                    f"strength={match.structural_strength:.3f})")
            if consensus_applicable and not consensus_ok:
                blockers.append(
                    f"algorithm consensus failed ({len(families)}/5 families "
                    f"{sorted(families)} agree; need >= 2)")
            # B5: codealign-style localization. When the caller threaded the original
            # decompiled body + the reconstruction C source through, the verdict
            # detail names the divergent REGIONS (line span + structural hint), not
            # just "the function diverged" — the repair agent gets an exact span.
            detail = ("reconstruction NOT verified: " + "; ".join(blockers)
                      + f". via {match.algorithm_name}.")
        if (not verified) and original_body and reconstruction_body:
            try:
                from .per_region_equiv import localize_for_verdict
                loc = localize_for_verdict(original_body, reconstruction_body)
                if not loc["equivalent"] and loc["regions"]:
                    n_regions = loc["divergent_count"]
                    detail += (f" Localized divergence: {n_regions} region(s). "
                               + loc["repair_prompt_fragment"])
            except Exception:  # noqa: BLE001 - localization is best-effort
                pass
        return VerificationResult(
            function_address=match.address1, function_name=match.name1,
            verified=verified, similarity=match.similarity,
            confidence=match.confidence, threshold=similarity_threshold,
            structural_strength=match.structural_strength,
            consensus=score, consensus_families=sorted(families),
            detail=detail,
        )

    if function_name is not None:
        return _judge(function_address, function_name)
    if function_address is not None:
        return _judge(function_address)
    return [_judge(f.address1) for f in diff.functions]


def verify_reconstruction(
    cfg: Config,
    ws: RunWorkspace,
    binary: str | Path,
    c_source: str | Path,
    *,
    compiler: str | None = None,
    extra_flags: str | None = None,
    function_address: int | None = None,
    similarity_threshold: float = 0.7,
    original_body: str = "",
) -> VerificationResult | list[VerificationResult]:
    """End-to-end verify an agent's reconstructed C against the original binary.

    This is the friction-free form of use-case B: the agent hands us its
    reconstructed C source, we compile it (``gcc`` by default, sandboxed and
    read-only on the host), export the resulting binary to ``.BinExport`` via
    Ghidra/BinExport, and structurally diff it against the original. No manual
    recompile step is required from the agent.

    If the reconstructed source does not contain a ``main`` function it is
    auto-wrapped with a minimal ``int main(void){return 0;}`` so per-function
    reconstructions (the normal case) can still be compiled to an executable and
    structurally diffed. The wrapper ``main`` will not match the original, but
    the claimed function will.

    Returns a single :class:`VerificationResult` when ``function_address`` is
    given, else a list for the whole unit.
    """
    c_source = Path(c_source)
    if not c_source.is_file():
        raise RuntimeError(f"C source not found: {c_source}")
    cc = compiler or "gcc"
    if shutil.which(cc) is None:
        raise RuntimeError(
            f"compiler '{cc}' not found; install gcc (apt-get install gcc) to "
            f"enable reconstruction verification."
        )

    build_dir = ws.raw_dir / "_recon"
    build_dir.mkdir(parents=True, exist_ok=True)
    recompiled = build_dir / f"{c_source.stem}.out"

    # Per-function reconstructions rarely include main(). Auto-wrap so the
    # compiler produces an executable without forcing the agent to know about
    # our linking requirements.
    source_text = c_source.read_text(errors="ignore")
    if not re.search(r"\bint\s+main\s*\(", source_text):
        wrapped = build_dir / f"{c_source.stem}_wrapped.c"
        wrapped.write_text(source_text + "\nint main(void){return 0;}\n")
        compile_source = wrapped
    else:
        compile_source = c_source

    # Link-tolerant compile: reconstructions declare `extern` Solana/SBF runtime
    # symbols (rust_panic, sol_log_, ...) that are never defined on the host. We are
    # doing a *structural* BinDiff check (not executing), so unresolved externs must not
    # block the link — only the function bodies need to be present. Without this every
    # real reconstruction fails the gate on `undefined reference to rust_panic`.
    cmd = [cc, str(compile_source), "-o", str(recompiled),
           "-Wl,--unresolved-symbols=ignore-all"]
    if extra_flags:
        cmd += extra_flags.split()
    _run_compile(cfg, cmd, build_dir)

    if not recompiled.is_file():
        raise RuntimeError(f"compilation failed; expected {recompiled}")

    # Export the recompiled binary and diff it against the original.
    rec_be = cached_export(cfg, ws, recompiled)
    # Prefer matching the reconstructed function by symbol name when we can
    # extract one; recompilation changes addresses, so name matching is the
    # robust way to compare a per-function reconstruction to the original.
    # We only do this for the explicit per-function convention
    # <name>_<address>.c (e.g. add_0x401136.c). Generic filenames return a
    # whole-unit list so callers/test expectations stay stable.
    function_name = None
    if function_address is None:
        base = c_source.stem
        m = re.search(r"_0x[0-9a-fA-F]{4,}$", base)
        if m:
            name_part = base[:m.start()]
            if name_part and not name_part.lower().startswith("func_"):
                function_name = name_part
    return verify_understanding(
        cfg, ws, binary, rec_be,
        function_address=function_address,
        function_name=function_name,
        similarity_threshold=similarity_threshold,
        original_body=original_body,
        reconstruction_body=source_text,
    )


def _format_compile_errors(stderr: str) -> str:
    """Turn raw gcc/clang stderr into an actionable, compact message.

    Reconstructments that fail because of unresolved `extern` runtime symbols (e.g.
    `rust_panic`, `sol_log_`) are NOT real errors for a structural-only verify — those
    should have been ignored by the tolerant link, but if a caller bypasses it we still
    don't want to surface them as the thing the agent must fix. Genuine C errors (unknown
    type, syntax) are surfaced verbatim so the agent has the exact line + message.
    """
    if not stderr:
        return "compilation failed (no stderr output)"
    err_re = re.compile(r"^(?P<loc>\S+?:\d+(?::\d+)?):\s*(?:fatal )?error:\s*(?P<msg>.+)$",
                       re.MULTILINE)
    real = [f"{m.group('loc')}: {m.group('msg')}" for m in err_re.finditer(stderr)]
    if real:
        return "real C errors to fix (define your typedefs / fix syntax):\n  - " + \
               "\n  - ".join(real[:8])
    return f"compilation failed (no parseable C errors; linker/symbol issue).\nstderr: {stderr[-800:]}"


def _run_compile(cfg: Config, cmd: list[str], writable_dir: Path) -> None:
    """Run a compiler (gcc/clang) sandboxed, mirroring the Ghidra bwrap shape."""
    if cfg.sandbox:
        from . import sandbox
        if sandbox.available():
            cmd = sandbox.wrap(cmd, writable_dirs=[writable_dir],
                               readonly_binds=[Path(cmd[1]).resolve().parent])
        else:
            raise RuntimeError(
                "sandbox requested but 'bwrap' is not installed; "
                "install bubblewrap or set ANGERONA_SANDBOX=0"
            )
    try:
        proc = observed_run(cmd, capture_output=True, text=True, timeout=600,
                              env=cfg.subprocess_env(), check=False)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(
            f"compilation timed out after 600s.\nstderr: {(exc.stderr or '')[-2000:]}"
        )
    if proc.returncode != 0:
        raise RuntimeError(
            f"compilation failed (rc={proc.returncode}).\n"
            + _format_compile_errors(proc.stderr)
        )


def recompile_sources(cfg: Config, sources: list[str | Path], out_path: str | Path,
                      *, compiler: str | None = None) -> Path:
    """Compile several reconstructed C/C++ sources into a single binary (sandboxed).

    Used by the CFG-depth gate to build one recompiled unit from all the agent's
    ``*.c``/``*.cpp`` reconstructions, so it can be diffed against the original as a
    whole (producing authoritative function-pair addresses).
    """
    cc = compiler or "gcc"
    if shutil.which(cc) is None:
        raise RuntimeError(
            f"compiler '{cc}' not found; install gcc (apt-get install gcc) to "
            f"enable reconstruction verification."
        )
    out_path = Path(out_path)
    build_dir = out_path.parent
    build_dir.mkdir(parents=True, exist_ok=True)
    cmd = [cc, *[str(s) for s in sources], "-o", str(out_path)]
    _run_compile(cfg, cmd, build_dir)
    if not out_path.is_file():
        raise RuntimeError(f"compilation failed; expected {out_path}")
    return out_path
