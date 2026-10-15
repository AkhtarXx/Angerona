"""RE-core analysis orchestrator — runs all fact-based RE strength passes on an export.

Production glue: given a binary's exported code/ dir (from export_analysis), run the
RE-core modules (similarity embedding, symbol recovery, obfuscation deobf, struct
recovery, IR normalization) PLUS the verification-completeness passes the research flagged
as under-addressed (A3 forced re-execution, A4 behavioral oracle, B3 coverage tiering,
B4 corpus caveat) — and write a consolidated ``re_analysis.json`` into the workspace.

Graceful: every sub-pass degrades individually; a missing dependency or empty input
never breaks the whole analysis.
"""

from __future__ import annotations

import json
import hashlib
import os
import shutil
from pathlib import Path
from typing import Optional


def run_re_analysis(code_dir: str | Path,
                    corpus_dirs: Optional[list[str | Path]] = None,
                    corpus_contract: Optional[dict] = None,
                    report_text: Optional[str] = None,
                    source_db: Optional[str | Path] = None,
                    worker_reports: Optional[list[tuple[str, str]]] = None,
                    firmware: Optional[str | Path] = None,
                    firmware_arch: Optional[str] = None,
                    family_db: Optional[dict[str, set[str]]] = None,
                    engine_fallback: bool = False,
                    obscure_isa: Optional[str] = None,
                    cve_seed: Optional[tuple[str, str]] = None,
                    bcrl_index: Optional[object] = None) -> dict:
    """Run all RE-core + verification-completeness passes; return a consolidated dict."""
    d = Path(code_dir)
    out: dict = {"code_dir": "<TARGET_CODE_EXPORT>", "passes": {}}
    effective_corpus_contract = None
    if corpus_dirs:
        from .similarity_corpus import (
            resolve_similarity_corpora,
            similarity_corpus_contract,
        )
        current_contract = similarity_corpus_contract(
            resolve_similarity_corpora(corpus_dirs)
        )
        if corpus_contract is not None and current_contract != corpus_contract:
            raise RuntimeError("similarity corpus content no longer matches its pinned contract")
        effective_corpus_contract = corpus_contract or current_contract

    # --- RE-4: struct recovery from decompiled C ---
    try:
        from .structrecovery import recover_structs
        structs: list[dict] = []
        for cf in sorted(d.glob("decompiled/*.c")):
            rep = recover_structs(cf.read_text(errors="ignore"))
            for s in rep.structs:
                structs.append({"file": cf.name, **s.as_dict()})
        out["passes"]["struct_recovery"] = {
            "structs_found": len(structs), "structs": structs[:50]}
    except Exception as exc:  # noqa: BLE001
        out["passes"]["struct_recovery"] = {"error": str(exc)}

    # --- RE-5: IR normalization (semantic signatures per function) ---
    try:
        from .irnorm import semantic_signature
        sigs: dict[str, str] = {}
        for cf in sorted(d.glob("decompiled/*.c")):
            sigs[cf.stem] = semantic_signature(cf.read_text(errors="ignore"))
        out["passes"]["ir_norm"] = {"functions_signed": len(sigs)}
    except Exception as exc:  # noqa: BLE001
        out["passes"]["ir_norm"] = {"error": str(exc)}

    # --- RE-1 + RE-2: similarity + symbol recovery against a pinned corpus ---
    if corpus_dirs:
        try:
            from .simindex import AUDIT_SIMILARITY_POLICY, SimilarityIndex
            from .symbolrecovery import recover_symbols
            from .similarity_corpus import similarity_corpus_summary
            contract_digest = hashlib.sha256(
                json.dumps(
                    effective_corpus_contract,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            index_identity = {
                "corpus_contract_sha256": contract_digest,
                "policy": AUDIT_SIMILARITY_POLICY,
            }
            contract_rows = list((effective_corpus_contract or {}).get("corpora") or [])
            corpus_ids = [str(row.get("tree_sha256") or "") for row in contract_rows]
            if len(corpus_ids) != len(corpus_dirs) or not all(corpus_ids):
                raise RuntimeError("similarity corpus contract/order is incomplete")
            index_path = d / "similarity_index"
            index_reused = False
            if index_path.with_suffix(".json").is_file() and index_path.with_suffix(".npz").is_file():
                candidate = SimilarityIndex.load(index_path)
                expected_sources = set(corpus_ids)
                if (
                    set(getattr(candidate, "_sources", [])) == expected_sources
                    and getattr(candidate, "_backend", "") == "hashing"
                    and getattr(candidate, "_search_backend", "") == "exact"
                    and int(getattr(candidate, "dim_reduce", 0))
                    == int(AUDIT_SIMILARITY_POLICY["dimension"])
                    and getattr(candidate, "_identity", {}) == index_identity
                ):
                    idx = candidate
                    index_reused = True
                else:
                    idx = SimilarityIndex(
                        dim_reduce=int(AUDIT_SIMILARITY_POLICY["dimension"]),
                        backend="hashing", search_backend="exact",
                    )
            else:
                idx = SimilarityIndex(
                    dim_reduce=int(AUDIT_SIMILARITY_POLICY["dimension"]),
                    backend="hashing", search_backend="exact",
                )
            corpus_counts = []
            if not index_reused:
                for corpus, corpus_id in zip(corpus_dirs, corpus_ids):
                    before = len(idx._docs)
                    added = idx.add_corpus(corpus)
                    idx._sources[before:] = [corpus_id] * added
                    corpus_counts.append({
                        "corpus_id": corpus_id,
                        "functions": added,
                    })
                if not getattr(idx, "_docs", []):
                    raise RuntimeError("configured corpus contains no indexable functions")
                idx.build()
                idx.save(index_path, identity=index_identity)
            else:
                for corpus_id in corpus_ids:
                    corpus_counts.append({
                        "corpus_id": corpus_id,
                        "functions": sum(
                            1 for source in getattr(idx, "_sources", [])
                            if source == corpus_id
                        ),
                    })
            bcrl_index = idx
            out["passes"]["similarity_index"] = {
                "status": "built",
                "indexed_functions": len(idx._docs),
                "backend": getattr(idx, "_backend", "unknown"),
                "artifacts": [
                    index_path.with_suffix(".json").name,
                    index_path.with_suffix(".npz").name,
                ],
                "corpora": corpus_counts,
                "contract": similarity_corpus_summary(effective_corpus_contract),
                "policy": AUDIT_SIMILARITY_POLICY,
                "trust": {
                    "classification": "untrusted_external_labels",
                    "rule": "similarity is candidate evidence, never identity or vulnerability proof",
                },
            }
            rep = recover_symbols(
                d, list(corpus_dirs),
                threshold=float(AUDIT_SIMILARITY_POLICY["threshold"]), index=idx
            )
            out["passes"]["symbol_recovery"] = rep.as_dict()
        except Exception as exc:  # noqa: BLE001
            out["passes"]["similarity_index"] = {"error": str(exc)}
            out["passes"]["symbol_recovery"] = {"error": str(exc)}
            raise RuntimeError(f"configured similarity analysis failed: {exc}") from exc
    else:
        out["passes"]["similarity_index"] = {"note": "no trusted corpus configured; skipped"}
        out["passes"]["symbol_recovery"] = {"note": "no corpus provided; skipped"}

    # --- RE-3: obfuscation deobfuscation (best-effort on decompiled C) ---
    try:
        from .deobfuscate import deobfuscate_function
        deobf: list[dict] = []
        for cf in sorted(d.glob("decompiled/*.c"))[:200]:
            res = deobfuscate_function(cf.read_text(errors="ignore"),
                                        entry=cf.stem, arch="x86_64")
            if res.available and res.recovered_blocks:
                deobf.append({"file": cf.name, "recovered_blocks": len(res.recovered_blocks),
                              "summary": res.summary})
        out["passes"]["deobfuscation"] = {"functions_processed": len(deobf)}
    except Exception as exc:  # noqa: BLE001
        out["passes"]["deobfuscation"] = {"error": str(exc)}

    # --- A3: forced-default re-execution of any C block in the agent report ---
    if report_text:
        try:
            from .auto_reexec import forced_reexec
            findings = forced_reexec(report_text)
            out["passes"]["forced_reexec"] = {
                "blocks_found": len(findings),
                "failed_compile": sum(1 for f in findings if not f.compiled),
                "failed_equiv": sum(1 for f in findings if not f.equivalent and f.compiled),
                "findings": [f.as_dict() for f in findings[:50]],
            }
        except Exception as exc:  # noqa: BLE001
            out["passes"]["forced_reexec"] = {"error": str(exc)}

    # --- A4: behavioral equivalence oracle availability note ---
    compiler = shutil.which("gcc")
    out["passes"]["behavioral_oracle"] = {
        "available": compiler is not None,
        "compiler": compiler,
        "note": (
            "behavioral equivalence via recompile + input/output diff (A4)"
            if compiler else "gcc unavailable; behavioral equivalence skipped"
        ),
    }

    # --- B3: coverage stratified by evaluability tier (REFORGE-style) ---
    # Lift-confidence is computed on demand here (cheap: reads already-exported files)
    # so a weak/unknown-opcode lift demotes the affected functions to tier0 instead of
    # letting them inflate the evaluable/high-confidence counts.
    try:
        from .coverage_tier import stratify_coverage
        try:
            from .lift_confidence import assess_lift as _assess_lift_cov
            _cov_lift = _assess_lift_cov(d, engine_fallback=engine_fallback)
        except Exception:  # noqa: BLE001
            _cov_lift = None
        cov = stratify_coverage(d, lift_report=_cov_lift)
        out["passes"]["coverage_tier"] = cov.as_dict()
        out["passes"]["coverage_tier"]["summary"] = cov.summary_line()
    except Exception as exc:  # noqa: BLE001
        out["passes"]["coverage_tier"] = {"error": str(exc)}

    # --- B4: corpus-coverage caveat (only when a corpus was actually compared) ---
    if corpus_dirs:
        try:
            from .corpus_caveat import attach_corpus_caveat
            cc = attach_corpus_caveat(list(corpus_dirs)[0], matched=False)
            caveat = cc.as_dict()
            caveat["corpus_path"] = str(
                ((effective_corpus_contract or {}).get("corpora") or [{}])[0].get(
                    "tree_sha256", "unknown"
                )
            )
            out["passes"]["corpus_caveat"] = caveat
        except Exception as exc:  # noqa: BLE001
            out["passes"]["corpus_caveat"] = {"error": str(exc)}

    # --- Part 3 P1: source-DB anchor retrieval (Pattern D-i, Gagnon 2607.09452) ---
    if source_db:
        try:
            from .anchor_retrieval import rank_from_export
            hits = rank_from_export(d, source_db, top_k=10)
            out["passes"]["anchor_retrieval"] = {
                "source_db": str(source_db), "top_hits": [h.as_dict() for h in hits[:10]]}
        except Exception as exc:  # noqa: BLE001
            out["passes"]["anchor_retrieval"] = {"error": str(exc)}

    # --- Part 3 P2: cross-worker evidence ledger + contradiction detection ---
    if worker_reports:
        try:
            from .evidence_ledger import build_ledger
            ledger = build_ledger(worker_reports)
            out["passes"]["evidence_ledger"] = {
                "addresses": ledger.as_dict()["addresses"],
                "contradictions": [c.as_dict() for c in ledger.contradictions],
            }
        except Exception as exc:  # noqa: BLE001
            out["passes"]["evidence_ledger"] = {"error": str(exc)}

    # --- Part 4: firmware extraction + MCU vector/entry recovery ---
    if firmware:
        try:
            from .firmware_extract import run_binwalk, detect_format
            fm_dir = d / "_firmware_extract"
            man = run_binwalk(firmware, fm_dir)
            fmt = detect_format(firmware)
            vrec = None
            if firmware_arch:
                from .vector_recovery import recover_vector, confidence_tier
                vr = recover_vector(firmware_arch, firmware)
                vrec = {**vr.as_dict(), "tier": confidence_tier(vr)}
            out["passes"]["firmware"] = {
                "format": fmt, "tool": man.tool, "hits": len(man.hits),
                "extracted_dir": man.extracted_dir,
                "vector_recovery": vrec,
            }
        except Exception as exc:  # noqa: BLE001
            out["passes"]["firmware"] = {"error": str(exc)}

    # --- Part 5 Rec 6: malware triage (hypothesis, not verdict) ---
    try:
        from .malware_triage import triage
        tr = triage(d, family_db=family_db)
        out["passes"]["malware_triage"] = tr.as_dict()
    except Exception as exc:  # noqa: BLE001
        out["passes"]["malware_triage"] = {"error": str(exc)}

    # --- Part 6 P0: lift-confidence caveat (obscure-arch silent-failure guard) ---
    try:
        from .lift_confidence import assess_lift
        lr = assess_lift(d, engine_fallback=engine_fallback)
        out["passes"]["lift_confidence"] = lr.as_dict()
    except Exception as exc:  # noqa: BLE001
        out["passes"]["lift_confidence"] = {"error": str(exc)}

    # --- Part 6 P2: Unicorn execution oracle (re-exec re-enabler) ---
    if obscure_isa:
        try:
            from .unicorn_oracle import arch_supported
            out["passes"]["unicorn_oracle"] = {
                "arch": obscure_isa,
                "supported": arch_supported(obscure_isa),
                "note": "execution oracle available; re-executability gate re-enabled",
            }
        except Exception as exc:  # noqa: BLE001
            out["passes"]["unicorn_oracle"] = {"error": str(exc)}

    # --- Part 5 Rec 3: Binary-BPE context-efficient tokenizer / chunker ---
    try:
        from .binary_bpe import BPETokenizer, chunk_for_context
        out["passes"]["binary_bpe"] = {
            "available": True,
            "note": "trainable BPE tokenizer + context-budgeted chunker for agent loops",
        }
    except Exception as exc:  # noqa: BLE001
        out["passes"]["binary_bpe"] = {"error": str(exc)}

    # --- Part 7: structure recovery + optional seed-driven variant retrieval ---
    try:
        from .pcode_struct import recover_structs_from_decompiled
        from .variant_analysis import find_variants
        structs = recover_structs_from_decompiled(d)
        out["passes"]["bcrl_struct"] = {
            "candidate_structs": [s.as_dict() for s in structs],
            "method_note": (
                "structure candidates are separate; similarity uses deterministic mnemonic "
                "TF-IDF and discards operands, so masking adds no independent signal"
            ),
        }
        if bcrl_index is not None:
            if cve_seed:
                vr = find_variants(cve_seed[1], bcrl_index, cve=cve_seed[0])
                out["passes"]["variant_analysis"] = vr.as_dict()
            else:
                out["passes"]["variant_analysis"] = {
                    "note": "no CVE/function seed configured; variant retrieval not executed"
                }
            out["passes"]["similarity_consumer"] = {
                "indexed_functions": len(getattr(bcrl_index, "_docs", [])),
                "available": True,
                "note": (
                    "deterministic similarity index is available to seed-driven variant analysis; "
                    "this is capability state, not a BCRL evaluation result"
                ),
            }
    except Exception as exc:  # noqa: BLE001
        out["passes"]["bcrl_struct"] = {"error": str(exc)}

    # --- Part 10 G1: obfuscation pre-pass classifier ---
    try:
        from .obfuscation_detect import detect_in_export, classify_function
        obf = detect_in_export(d)
        out["passes"]["obfuscation"] = {
            "functions_scanned": len(obf),
            "flagged": [o.as_dict() for o in obf if o.label != "clean"],
        }
    except Exception as exc:  # noqa: BLE001
        out["passes"]["obfuscation"] = {"error": str(exc)}

    # --- Roadmap Phase B (SOTA reconstruction/verification upgrades) ---

    # B6: runtime differential on worker's reconstruction dir (if present)
    try:
        recon_dir = d / "reconstruction"
        if recon_dir.is_dir():
            from .differential_runtime import verify_whole_reconstruction_dir
            rt = verify_whole_reconstruction_dir(recon_dir, corpus_size=8, timeout=30)
            out["passes"]["runtime_differential"] = {
                "verdict": rt["verdict"], "total": rt["total"],
                "compile_ok": rt["compile_ok"], "behavior_ok": rt["behavior_ok"],
                "status": rt["verdict"],
            }
        else:
            out["passes"]["runtime_differential"] = {
                "note": "no code/reconstruction dir; behavioral oracle not executed"
            }
    except Exception as exc:  # noqa: BLE001
        out["passes"]["runtime_differential"] = {"error": str(exc)}

    # B4: ReSym-style constraint aggregation of LLM type claims under deterministic
    # paint over deterministic field-facts from pcode_struct.
    try:
        llm_claims_env = os.environ.get("ANGERONA_LLM_TYPE_CLAIMS", "").strip()
        claims_text = ""
        if llm_claims_env and Path(llm_claims_env).is_file():
            claims_text = Path(llm_claims_env).read_text(encoding="utf-8",
                                                          errors="ignore")
        from .resym_solver import solve_from_code_dir
        out["passes"]["resym_types"] = solve_from_code_dir(d, claims_text)
    except Exception as exc:  # noqa: BLE001
        out["passes"]["resym_types"] = {"error": str(exc)}

    # C8: ASan-proxy fuzz verdict on the worker's reconstruction dir (if present).
    try:
        recon_dir = d / "reconstruction"
        if recon_dir.is_dir():
            from .asan_proxy import fuzz_reconstruction_with_asan, promote_asan_verdict
            report = fuzz_reconstruction_with_asan(recon_dir, seeds=8, timeout=15)
            out["passes"]["asan_proxy"] = {
                "overall": report.overall,
                "crashers": report.crashers,
                "runs": report.runs,
                "verdict": promote_asan_verdict(report),
                "units": [u.as_dict() for u in report.units[:20]],
            }
        else:
            out["passes"]["asan_proxy"] = {
                "note": "no code/reconstruction dir; ASan-proxy not executed"
            }
    except Exception as exc:  # noqa: BLE001
        out["passes"]["asan_proxy"] = {"error": str(exc)}

    # --- Stage B hardening: summarize pass success/failure so the orchestrator can
    # REJECT a run where core RE-core passes crashed (the "gate that can never fail"
    # trap). A pass counts as FAILED only if it carries an "error" key AND no
    # explanatory "note" (notes = intentionally skipped, e.g. no corpus provided).
    ok, failed, skipped = 0, 0, 0
    failed_names = []
    for name, res in out["passes"].items():
        if "error" in res and "note" not in res:
            failed += 1
            failed_names.append(name)
        elif res.get("available") is True or res.get("supported") is True:
            ok += 1
        elif "note" in res:
            skipped += 1
        else:
            ok += 1
    out["summary"] = {
        "passes_ok": ok,
        "passes_failed": failed,
        "passes_skipped": skipped,
        "failed_passes": failed_names,
        "status": "ok" if failed == 0 else "degraded",
    }
    return out


def write_re_analysis(code_dir: str | Path,
                      corpus_dirs: Optional[list[str | Path]] = None,
                      report_text: Optional[str] = None,
                      corpus_contract: Optional[dict] = None) -> Path:
    """Run and persist re_analysis.json next to the export."""
    report = run_re_analysis(
        code_dir, corpus_dirs, corpus_contract=corpus_contract,
        report_text=report_text,
    )
    p = Path(code_dir) / "re_analysis.json"
    p.write_text(json.dumps(report, indent=2))
    return p
