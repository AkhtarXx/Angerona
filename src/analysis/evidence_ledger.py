"""Evidence ledgers for worker claims and exported RE artifacts.

This module keeps two related ledgers:
  - cross-worker address claims for contradiction detection;
  - content-addressed export artifacts for immutable RE evidence.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# capture "func@0x1000 is X" or "0x1000 = X" style attributions in worker text.
# The value is captured as the FULL remainder (not just the first token) so that
# "0x100 = returns 0" vs "0x100 = returns 1" are seen as DIFFERENT values
# (a one-word capture would treat both as "returns" and miss the contradiction).
_ADDR_CLAIM = re.compile(
    r"func(?:tion)?\s*(?:@|at)\s*(0x[0-9a-fA-F]+)"
    r"(?:\s*(?:is|=|:|->)\s*([^\n]{1,80}))?"
    r"|"
    r"(0x[0-9a-fA-F]+)\s*(?:=|:|is|->)\s*([^\n]{1,80})",
    re.I,
)


def _norm_claim(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().strip(".:")).lower()


def parse_address_claims(text: str) -> dict[str, list[str]]:
    """Extract {address: [claim tokens]} from a worker's free-text report."""
    out: dict[str, list[str]] = {}
    for m in _ADDR_CLAIM.finditer(text or ""):
        addr = m.group(1) or m.group(3)
        if not addr:
            continue
        addr = addr.lower()
        value = m.group(2) or m.group(4)
        if value:
            out.setdefault(addr, []).append(_norm_claim(value))
    return out


@dataclass
class Contradiction:
    address: str
    workers: list[str]
    values: list[str]

    def as_dict(self) -> dict:
        return {"address": self.address, "workers": self.workers, "values": self.values}


@dataclass
class EvidenceLedger:
    claims: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    contradictions: list[Contradiction] = field(default_factory=list)

    def add_worker(self, worker_id: str, report_text: str) -> None:
        ac = parse_address_claims(report_text)
        for addr, claims in ac.items():
            self.claims.setdefault(addr, {}).setdefault(worker_id, [])
            self.claims[addr][worker_id].extend(claims)

    def detect_contradictions(self) -> list[Contradiction]:
        """Flag addresses where >1 distinct value is claimed."""
        out: list[Contradiction] = []
        for addr, by_worker in self.claims.items():
            all_values: set[str] = set()
            workers: list[str] = []
            for wid, vals in by_worker.items():
                for v in vals:
                    if v not in all_values:
                        all_values.add(v)
                        workers.append(wid)
            distinct = {v for vals in by_worker.values() for v in set(vals)}
            if len(distinct) > 1:
                out.append(Contradiction(address=addr, workers=sorted(set(workers)),
                                         values=sorted(distinct)))
        self.contradictions = out
        return out

    def independent_support(self, addr: str, value: str) -> int:
        """Count how many distinct workers assert ``value`` at ``addr``."""
        return sum(1 for _wid, vals in self.claims.get(addr, {}).items()
                   if value in set(vals))

    def as_dict(self) -> dict:
        return {
            "addresses": len(self.claims),
            "claims": {a: {w: c for w, c in wc.items()} for a, wc in self.claims.items()},
            "contradictions": [c.as_dict() for c in self.contradictions],
        }


def build_ledger(worker_reports: list[tuple[str, str]]) -> EvidenceLedger:
    """Build a worker-claim ledger from [(worker_id, report_text), ...]."""
    ledger = EvidenceLedger()
    for wid, txt in worker_reports:
        ledger.add_worker(wid, txt)
    ledger.detect_contradictions()
    return ledger


LEDGER_SCHEMA_VERSION = 1
LEDGER_FILENAME = "EVIDENCE_LEDGER.json"


def sha256_file(path: str | Path) -> str:
    """Return the SHA-256 digest for a file without loading it all at once."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _artifact_role(relative_path: str) -> str:
    if relative_path == "analysis.json":
        return "raw_engine_analysis"
    if relative_path == "all_decompiled.c":
        return "combined_decompiled_source"
    if relative_path.startswith("decompiled/") and relative_path.endswith(".c"):
        return "function_decompiled_source"
    if relative_path == "functions.csv":
        return "function_index"
    if relative_path == "anchor_instructions.json":
        return "anchor_instruction_evidence_map"
    if relative_path == "anchor_instructions.md":
        return "anchor_instruction_summary"
    if relative_path in {"strings.txt", "imports.txt", "exports.txt", "symbols.txt"}:
        return "raw_symbol_context"
    if relative_path == "security_properties.json":
        return "binary_hardening_context"
    if relative_path == "injection_scan.json":
        return "prompt_injection_scan"
    if relative_path == "EXPORT_MANIFEST.json":
        return "export_manifest"
    return "supporting_artifact"


def _safe_export_name(name: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in name)[:60] or "fn"


def decompiled_filename(function: dict[str, Any]) -> str:
    """Return the path export_analysis uses for a decompiled function."""
    name = str(function.get("name", "fn"))
    entry = str(function.get("entry", ""))
    addr = entry.lower().removeprefix("0x")
    if name.startswith(("FUN_", "thunk_FUN_", "LAB_", "SUB_")) or (addr and addr in name.lower()):
        fname = f"{_safe_export_name(name)}.c"
    else:
        fname = f"{_safe_export_name(name)}_{entry}.c"
    return f"decompiled/{fname}"


def _artifact_record(dest: Path, path: Path, producer: str) -> dict[str, Any]:
    relative = path.relative_to(dest).as_posix()
    return {
        "path": relative,
        "role": _artifact_role(relative),
        "producer": producer,
        "sha256": sha256_file(path),
        "size_bytes": path.stat().st_size,
        "mutable": False,
    }


def _function_record(function: dict[str, Any], dest: Path) -> dict[str, Any]:
    rel = decompiled_filename(function)
    source_path = dest / rel
    has_decompiled_source = source_path.is_file()
    record = {
        "name": str(function.get("name", "")),
        "entry": str(function.get("entry", "")),
        "size": function.get("size"),
        "signature": str(function.get("signature", "")),
        "callers": function.get("callers", []),
        "callees": function.get("callees", []),
        "has_decompiled_source": has_decompiled_source,
        "decompiled_path": rel if has_decompiled_source else None,
        "state": "raw_decompiled" if has_decompiled_source else "needs_lift",
        "confidence": "engine_output",
        "verification": "not_started",
    }
    if has_decompiled_source:
        record["decompiled_sha256"] = sha256_file(source_path)
    return record


def build_export_evidence_ledger(
    *,
    dest: str | Path,
    binary: str | Path,
    producer: str,
    engine: str,
    analysis: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build a ledger that separates raw truth from reconstructed convenience.

    The ledger is intentionally content-addressed and excludes its own file to
    avoid circular hashes. Agents can propose cleaner reconstructions later, but
    those proposals must point back to these immutable records.
    """
    dest = Path(dest)
    binary_path = Path(binary)
    functions = analysis.get("functions", [])
    artifacts = [
        _artifact_record(dest, path, producer)
        for path in sorted(dest.rglob("*"))
        if path.is_file() and path.name != LEDGER_FILENAME
    ]
    targets = [_function_record(function, dest) for function in functions]
    ledger = {
        "schema_version": LEDGER_SCHEMA_VERSION,
        "model": "raw_truth_plus_reconstruction",
        "producer": producer,
        "engine": engine,
        "binary": {
            "path": str(binary_path),
            "sha256": sha256_file(binary_path) if binary_path.is_file() else None,
            "size_bytes": binary_path.stat().st_size if binary_path.is_file() else None,
        },
        "policy": {
            "raw_artifacts_are_immutable": True,
            "ai_may_write": "reconstruction_proposals_only",
            "verification_source_of_truth": "binary_and_raw_engine_ir",
        },
        "manifest": {
            "status": manifest.get("status"),
            "counts": manifest.get("counts", {}),
            "effective_max_functions": manifest.get("effective_max_functions"),
        },
        "artifacts": artifacts,
        "artifact_count": len(artifacts),
        "file_count": len(artifacts),
        "reconstruction_targets": targets,
        "reconstruction_target_count": len(targets),
        "security_graph_seed": {
            "imports": len(analysis.get("imports", [])),
            "exports": len(analysis.get("exports", [])),
            "strings": len(analysis.get("strings", [])),
            "symbols": len(analysis.get("symbols", [])),
            "candidate_state": "not_started",
        },
    }
    return ledger


def write_export_evidence_ledger(
    *,
    dest: str | Path,
    binary: str | Path,
    producer: str,
    engine: str,
    analysis: dict[str, Any],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    """Build and atomically persist ``EVIDENCE_LEDGER.json``."""
    dest = Path(dest)
    ledger = build_export_evidence_ledger(
        dest=dest,
        binary=binary,
        producer=producer,
        engine=engine,
        analysis=analysis,
        manifest=manifest,
    )
    path = dest / LEDGER_FILENAME
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(ledger, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    return ledger
