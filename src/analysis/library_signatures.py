"""Library function signature matcher.

The IDA Pro Book highlights FLIRT signatures as the primary way IDA removes
library noise before the analyst (or an AI agent) sees the disassembly.
Angerona uses a lightweight, engine-agnostic MinHash/Jaccard approach over
normalized instruction sequences. Signatures can be built from known static
libraries, standard object files, or from Ghidra/IDA exported function bodies.

Features:
  - Build signature DB from directories of binaries or exported JSON.
  - Normalize instructions (mnemonic + genericized operands) for stability.
  - Match unknown functions and label them as library with a confidence score.
  - Export/import DB as JSON for version control.

The normalization intentionally discards absolute immediates and register names
so that different compiler versions/optimization levels still match the same
library routine.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable


# Exact C/POSIX boundaries are useful evidence, but are not user-authored code.
_LIBRARY_EXACT_NAMES = {
    "abort", "calloc", "fprintf", "fputs", "free", "getenv", "malloc",
    "memcmp", "memcpy", "memmove", "memset", "printf", "puts", "realloc",
    "snprintf", "sprintf", "strcmp", "strcpy", "strlen", "strncpy",
}
_RUNTIME_PREFIXES = (
    "__cxa_", "__gxx_", "__libc_", "__stack_chk_", "__ubsan_", "__asan_",
    "__tsan_", "__msan_", "_unwind_", "_itm_", "__gmon_", "___crt", "_crt",
)
_COMPILER_SCAFFOLD_NAMES = {
    "_init", "_fini", "_init_0", "_fini_0", "init_proc", "term_proc", "frame_dummy",
    "register_tm_clones", "deregister_tm_clones", "__do_global_dtors_aux",
}
_STANDARD_MANGLED_PREFIXES = (
    "_znst", "_znkst", "_zst", "_znsa", "_zn9__gnu_cxx",
    "_znk9__gnu_cxx", "_zn10__cxxabiv1", "_zdl", "_zda", "_znw", "_zna",
)


def _normalized_symbol_name(name: str | None) -> str:
    value = (name or "").strip()
    value = value[1:] if value.startswith(".") else value
    return value.split("@@", 1)[0]


def _is_likely_library_name(name: str | None) -> bool:
    """Conservative name-only library classification.

    A generic Itanium ``_Z`` prefix is *not* sufficient: user-authored C++
    functions are mangled the same way.  Only known runtime/standard-library
    namespaces and exact external APIs are accepted here.
    """
    value = _normalized_symbol_name(name)
    if not value:
        return False
    low = value.lower()
    if low in _LIBRARY_EXACT_NAMES or low in _COMPILER_SCAFFOLD_NAMES:
        return True
    if low.startswith(_RUNTIME_PREFIXES) or low.startswith(_STANDARD_MANGLED_PREFIXES):
        return True
    return (
        "std::" in low
        or "__gnu_cxx::" in low
        or "__cxxabiv1::" in low
        or low.startswith("operator new")
        or low.startswith("operator delete")
    )


def classify_library_function(fn: dict) -> tuple[bool, str]:
    """Classify one engine function without throwing away boundary evidence.

    The boolean is intended for prioritization/noise suppression.  Callers
    should retain the original function/import records so security sinks and
    user-to-library call boundaries remain queryable.
    """
    if bool(fn.get("is_external")):
        return True, "engine_external"
    memory_block = str(fn.get("memory_block") or "").lower()
    if memory_block in {".plt", ".plt.sec", ".plt.got", "extern", ".idata"}:
        return True, "linkage_section"
    if memory_block in {".init", ".fini"}:
        return True, "runtime_scaffolding_section"
    callers = {
        _normalized_symbol_name(str(value)).lower()
        for value in (fn.get("callers") or [])
        if value
    }
    callees = {
        _normalized_symbol_name(str(value)).lower()
        for value in (fn.get("callees") or [])
        if value
    }
    referenced_symbols = {
        _normalized_symbol_name(str(value)).lower()
        for value in (fn.get("referenced_symbols") or [])
        if value
    }
    runtime_evidence = callees | referenced_symbols
    low_name = str(fn.get("name") or "").lower()
    is_auto_named = low_name.startswith(("fun_", "sub_", "loc_", "nullsub_"))
    try:
        size = int(fn.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    xrefs = [
        row for row in (fn.get("xrefs_to") or [])
        if isinstance(row, dict)
    ]
    xref_blocks = {
        str(row.get("from_memory_block") or "").lower()
        for row in xrefs
    }
    itm_scaffolding = {
        symbol for symbol in runtime_evidence
        if symbol.startswith((
            "_itm_registertmclonetable",
            "_itm_deregistertmclonetable",
        ))
    }
    non_scaffolding_callees = {
        symbol for symbol in callees
        if not symbol.startswith((
            "_itm_registertmclonetable",
            "_itm_deregistertmclonetable",
        ))
    }
    if (
        is_auto_named
        and 0 < size <= 96
        and itm_scaffolding
        and not non_scaffolding_callees
    ):
        return True, "runtime_scaffolding_behavior"
    if (
        is_auto_named
        and 0 < size <= 128
        and ".fini_array" in xref_blocks
        and "__cxa_finalize" in runtime_evidence
        and not callers
        and len(callees) <= 2
    ):
        return True, "runtime_scaffolding_behavior"
    if (
        callers
        and callers <= {"_init_0", "frame_dummy"}
        and "_itm_registertmclonetable" in callees
    ):
        return True, "runtime_scaffolding_behavior"
    namespace = str(fn.get("namespace") or "").lower()
    if "<external>" in namespace:
        return True, "external_namespace"
    if "std::" in namespace or namespace.endswith("::std") or "__gnu_cxx" in namespace:
        return True, "standard_namespace"
    if bool(fn.get("is_thunk")):
        return True, "engine_thunk"
    if _is_likely_library_name(fn.get("name")):
        return True, "known_runtime_symbol"
    return False, "user_or_unknown"


def classify_user_fragment(fn: dict) -> tuple[bool, str]:
    """Identify compiler-split user-code fragments without calling them library noise.

    Engines disagree on whether switch arms, cold paths, and exception landing
    pads are standalone functions.  This role is intentionally separate from
    :func:`classify_library_function`: fragment code remains available to the
    call graph, sink analysis, and decompiler consumers.
    """
    name = str(fn.get("name") or "")
    low_name = name.lower()
    namespace = str(fn.get("namespace") or "").lower()
    xrefs = [row for row in (fn.get("xrefs_to") or []) if isinstance(row, dict)]
    callers = [str(value) for value in (fn.get("callers") or []) if value]
    callees = {
        _normalized_symbol_name(str(value)).lower()
        for value in (fn.get("callees") or [])
        if value
    }

    if ".cold" in low_name or "[clone .cold" in low_name:
        return True, "cold_code_fragment"

    is_switch_named = (
        namespace.startswith("switchd_")
        or low_name == "default"
        or low_name.startswith(("cased_", "case_"))
    )
    has_switch_evidence = namespace.startswith("switchd_") or any(
        "jump" in str(row.get("type") or "").lower()
        for row in xrefs
    )
    if is_switch_named and has_switch_evidence:
        return True, "switch_code_fragment"

    def address_number(value: object) -> int | None:
        try:
            return int(str(value).strip(), 16)
        except (TypeError, ValueError):
            return None

    def address_is_in_body(value: object) -> bool:
        address = address_number(value)
        if address is None:
            return False
        for body_range in fn.get("body_ranges") or []:
            if not isinstance(body_range, dict):
                continue
            start = address_number(body_range.get("start"))
            end = address_number(body_range.get("end"))
            if start is not None and end is not None and start <= address <= end:
                return True
        return False

    # Ghidra may apply the parent DWARF symbol to a separate cold range while
    # IDA emits the same range as ``symbol.cold``.  A same-name jump from
    # outside this function's body distinguishes that split from a self-loop.
    same_symbol_external_jump = any(
        "jump" in str(row.get("type") or "").lower()
        and str(row.get("from_function") or "").lower() == low_name
        and not address_is_in_body(row.get("from"))
        for row in xrefs
    )
    if not callers and same_symbol_external_jump:
        return True, "split_function_fragment"

    is_auto_named = low_name.startswith(
        ("fun_", "sub_", "loc_", "lab_", "nullsub_")
    )
    incoming_code_xrefs = [
        row for row in xrefs
        if any(
            token in str(row.get("type") or "").lower()
            for token in ("jump", "call")
        )
    ]
    incoming_jump_from_function = any(
        "jump" in str(row.get("type") or "").lower()
        and str(row.get("from_function") or "")
        for row in incoming_code_xrefs
    )
    if is_auto_named and not callers and incoming_jump_from_function:
        return True, "jump_target_fragment"

    exception_runtime = {
        "__cxa_begin_catch", "__cxa_end_catch", "__cxa_rethrow",
        "_unwind_resume",
    }
    if (
        is_auto_named
        and not callers
        and incoming_code_xrefs
        and callees.intersection(exception_runtime)
    ):
        return True, "exception_landing_pad_fragment"

    try:
        size = int(fn.get("size") or 0)
    except (TypeError, ValueError):
        size = 0
    shared_epilogue_jump = any(
        str(row.get("type") or "").upper() == "UNCONDITIONAL_JUMP"
        for row in incoming_code_xrefs
    )
    if (
        is_auto_named
        and 0 < size <= 8
        and len(callers) == 1
        and not callees
        and shared_epilogue_jump
    ):
        return True, "shared_epilogue_fragment"

    switch_callers = callers and all(
        caller.lower() == "default"
        or caller.lower().startswith(("cased_", "case_"))
        for caller in callers
    )
    if is_auto_named and 0 < size <= 8 and switch_callers:
        return True, "tiny_switch_fragment"

    return False, "user_primary"


def _split_mnemonic(line: str) -> str:
    """Extract the mnemonic token from a disassembly text line."""
    parts = line.strip().split(None, 1)
    return parts[0].lower() if parts else ""


def _genericize_operands(operands: str) -> str:
    """Replace immediates with GEN_IMM, registers with GEN_REG, addresses with GEN_ADDR."""
    # Normalize spacing and ptr annotations.
    s = operands
    # hex immediates (including negative)
    s = re.sub(r"[+-]?\b0x[0-9a-fA-F]+\b", "GEN_IMM", s)
    # decimal immediates
    s = re.sub(r"[+-]?\b\d+\b", "GEN_IMM", s)
    # Any bare hex address inside brackets becomes GEN_ADDR; keep structure.
    s = re.sub(r"\[\s*0x[0-9a-fA-F]+\s*\]", "[GEN_ADDR]", s)
    s = re.sub(r"\[(.*?)0x[0-9a-fA-F]+(.*?)\]", r"[\1GEN_ADDR\2]", s)
    s = re.sub(r"\[(.*?)\d+(.*?)\]", r"[\1GEN_IMM\2]", s)

    # register-ish tokens (heuristic: short alphanumeric, not mnemonic)
    tokens = []
    _REGS = {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "esp", "ebp",
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rsp", "rbp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
        "w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7",
        "rip", "eip",
    }
    for tok in re.split(r"([,\+\-\*\(\)\[\] ])", s):
        tok = tok.strip()
        if not tok:
            continue
        low = tok.lower()
        if tok in ("GEN_IMM", "GEN_ADDR"):
            tokens.append(tok)
        elif low in _REGS:
            tokens.append("GEN_REG")
        elif tok.isdigit() or (tok.startswith("0x") and len(tok) > 2):
            tokens.append("GEN_IMM")
        else:
            tokens.append(tok)
    return " ".join(tokens)


def _normalize_disasm(disasm: list[str] | str) -> str:
    """Normalize a disassembly block into a sequence of generic mnemonics+operands."""
    if isinstance(disasm, str):
        try:
            parsed = json.loads(disasm)
            if isinstance(parsed, list):
                lines = [str(item) for item in parsed]
            else:
                lines = disasm.splitlines()
        except json.JSONDecodeError:
            lines = disasm.splitlines()
    else:
        lines = [str(line) for line in disasm] if disasm else []
    out: list[str] = []
    for raw in lines:
        # Strip leading address prefixes just in case.
        line = re.sub(r"^\s*[0-9a-fA-F]+[:\s]+", "", raw)
        parts = line.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0].lower()
        operands = _genericize_operands(parts[1]) if len(parts) > 1 else ""
        out.append(f"{mnemonic} {operands}".strip())
    return "\n".join(out)


def _shingles(text: str, k: int = 3) -> set[str]:
    """Produce k-gram shingles from a text block."""
    tokens = text.replace("\n", " ; ").split()
    if len(tokens) < k:
        return set(tokens)
    return set(" ".join(tokens[i:i + k]) for i in range(len(tokens) - k + 1))


def _minhash(shingles: set[str], num_hashes: int = 128, seed: int = 0xACE1) -> list[int]:
    """Simple stable MinHash vector using a multiplicative hash family."""
    def _hash(s: str, a: int, b: int) -> int:
        h = seed
        for ch in s:
            h = ((h * a) ^ (ord(ch) * b)) & 0xFFFFFFFF
        return h
    vec = []
    for i in range(num_hashes):
        a = 2654435761 + i * 7
        b = 805306457 + i * 13
        if shingles:
            vec.append(min(_hash(s, a, b) for s in shingles))
        else:
            vec.append(0xFFFFFFFF)
    return vec


def _jaccard(a: set[str], b: set[str]) -> float:
    if not a or not b:
        return 0.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _minhash_similarity(a: list[int], b: list[int]) -> float:
    if not a or not b:
        return 0.0
    matches = sum(1 for x, y in zip(a, b) if x == y)
    return matches / len(a)


@dataclass
class Signature:
    library: str
    name: str
    normalized_text: str
    num_instructions: int
    shingle_hash: str
    minhash: list[int]
    shingles: frozenset[str] = field(default_factory=frozenset)  # cached for fast match
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.shingles, (list, set)):
            object.__setattr__(self, "shingles", frozenset(self.shingles))

    def as_dict(self) -> dict:
        return {
            "library": self.library,
            "name": self.name,
            "normalized_text": self.normalized_text,
            "num_instructions": self.num_instructions,
            "shingle_hash": self.shingle_hash,
            "minhash": self.minhash,
            "shingles": sorted(self.shingles),
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Signature":
        return cls(
            library=d["library"],
            name=d["name"],
            normalized_text=d.get("normalized_text", ""),
            num_instructions=d.get("num_instructions", 0),
            shingle_hash=d.get("shingle_hash", ""),
            minhash=d.get("minhash", []),
            shingles=frozenset(d.get("shingles", [])),
            metadata=d.get("metadata", {}),
        )


class SignatureDB:
    """Indexed collection of library function signatures.

    Uses MinHash LSH bands for coarse pre-filtering so that match_many() does not
    perform full pairwise comparisons against huge signature DBs.
    """

    _BANDS = 16
    _ROWS = 8

    def __init__(self, signatures: list[Signature] | None = None) -> None:
        self.signatures: list[Signature] = signatures or []
        self._lsh: dict[str, set[int]] = {}
        self._rebuild_lsh()

    def _rebuild_lsh(self) -> None:
        """Build/refresh MinHash LSH bucket index."""
        self._lsh = {}
        for idx, sig in enumerate(self.signatures):
            if not sig.minhash:
                continue
            for band in range(self._BANDS):
                start = band * self._ROWS
                end = start + self._ROWS
                bucket = (band, tuple(sig.minhash[start:end]))
                key = str(bucket)
                self._lsh.setdefault(key, set()).add(idx)

    def add(self, sig: Signature) -> None:
        self.signatures.append(sig)
        idx = len(self.signatures) - 1
        if not sig.minhash:
            return
        for band in range(self._BANDS):
            start = band * self._ROWS
            end = start + self._ROWS
            bucket = (band, tuple(sig.minhash[start:end]))
            self._lsh.setdefault(str(bucket), set()).add(idx)

    def build_from_export(self, library_name: str, data: dict, *, disasm_key: str = "disassembly",
                          name_key: str = "name", min_funcs: int = 0) -> int:
        """Build signatures from an analysis JSON export (e.g. REDump output)."""
        added = 0
        for fn in data.get("functions", []):
            name = fn.get(name_key, "")
            disasm = fn.get(disasm_key)
            if not disasm:
                # If no disassembly, try to use decompiled text as a fallback (coarse).
                disasm = fn.get("decompiled", "")
                if not disasm:
                    continue
            norm = _normalize_disasm(disasm)
            if not norm:
                continue
            sig = self._make_sig(library_name, name, norm, fn)
            self.add(sig)
            added += 1
        return added

    def build_from_directory(self, root: str | Path,
                             loader: Callable[[Path], dict] | None = None) -> None:
        """Recursively import analysis JSON files as signature libraries.

        Loader defaults to JSON.parse of a .json file.
        """
        root = Path(root)
        loader = loader or (lambda p: json.loads(p.read_text(encoding="utf-8")))
        for path in root.rglob("*.json"):
            try:
                data = loader(path)
                lib_name = path.stem
                self.build_from_export(lib_name, data)
            except Exception:
                # One corrupted file should not abort bulk import.
                pass

    @classmethod
    def _make_sig(cls, library: str, name: str, normalized: str, metadata: dict) -> Signature:
        lines = [l for l in normalized.splitlines() if l.strip()]
        sh = _shingles(normalized)
        sig_text = " ".join(lines)
        return Signature(
            library=library,
            name=name,
            normalized_text=normalized,
            num_instructions=len(lines),
            shingle_hash=hashlib.sha256(normalized.encode()).hexdigest()[:16],
            minhash=_minhash(sh),
            shingles=sh,
            metadata=metadata,
        )

    def _candidate_indices(self, minhash: list[int]) -> set[int]:
        """Return LSH candidate signature indices for a target minhash vector."""
        candidates: set[int] = set()
        for band in range(self._BANDS):
            start = band * self._ROWS
            end = start + self._ROWS
            bucket = (band, tuple(minhash[start:end]))
            candidates |= self._lsh.get(str(bucket), set())
        return candidates

    def match(self, name: str | None, disasm: list[str] | str | None,
              threshold: float = 0.8, minhash_threshold: float = 0.65) -> dict | None:
        """Return best matching signature above thresholds, or None."""
        if not disasm:
            return None
        norm = _normalize_disasm(disasm)
        if not norm:
            return None
        target_shingles = _shingles(norm)
        target_minhash = _minhash(target_shingles)

        candidates = self._candidate_indices(target_minhash)
        # Fall back to full scan when the DB is small or no LSH candidates found.
        if len(self.signatures) < 200 or not candidates:
            candidates = set(range(len(self.signatures)))

        best: Signature | None = None
        best_score = 0.0
        best_method = ""
        for idx in candidates:
            sig = self.signatures[idx]
            if not sig.normalized_text:
                continue
            sig_shingles = sig.shingles or _shingles(sig.normalized_text)
            jacc = _jaccard(target_shingles, sig_shingles)
            mh_sim = _minhash_similarity(target_minhash, sig.minhash)
            if sig.num_instructions <= 8:
                score = jacc
                method = "jaccard"
            else:
                if jacc >= mh_sim:
                    score = jacc
                    method = "jaccard"
                else:
                    score = mh_sim
                    method = "minhash"
            if score > best_score:
                best_score = score
                best = sig
                best_method = method

        # If the name already indicates library code, lower the bar slightly.
        name_bonus = 1.05 if _is_likely_library_name(name) else 1.0
        effective_threshold = threshold / name_bonus
        if best is None or best_score < effective_threshold:
            return None

        return {
            "matched": True,
            "library": best.library,
            "name": best.name,
            "score": round(best_score, 4),
            "method": best_method,
        }

    def match_many(self, functions: list[dict],
                   threshold: float = 0.8, minhash_threshold: float = 0.65) -> dict[str, dict]:
        """Match a list of function dicts; return map of function name -> match result."""
        results: dict[str, dict] = {}
        for fn in functions:
            name = fn.get("name") or fn.get("entry") or "unknown"
            match = self.match(name, fn.get("disassembly") or fn.get("decompiled"),
                               threshold=threshold, minhash_threshold=minhash_threshold)
            results[str(name)] = match or {"matched": False}
        return results

    def save_json(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps([s.as_dict() for s in self.signatures], indent=2),
                              encoding="utf-8")

    @classmethod
    def load_json(cls, path: str | Path) -> "SignatureDB":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls([Signature.from_dict(d) for d in data])


# Convenience helpers used by the CLI and agents


def match_functions_against_db(functions: list[dict], db: SignatureDB,
                               threshold: float = 0.8) -> dict[str, dict]:
    return db.match_many(functions, threshold=threshold)


def build_signature_db_from_exports(export_paths: list[str | Path],
                                      library_names: list[str] | None = None) -> SignatureDB:
    """Build a SignatureDB from a set of exported analysis JSON files."""
    db = SignatureDB()
    for i, path in enumerate(export_paths):
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        lib_name = (library_names[i] if library_names and i < len(library_names)
                    else Path(path).stem)
        db.build_from_export(lib_name, data)
    return db


def quick_library_mark(functions: list[dict]) -> dict[str, bool]:
    """Fast conservative filter using engine flags, namespaces, and known names."""
    return {
        str(fn.get("name") or fn.get("entry") or "unknown"): classify_library_function(fn)[0]
        for fn in functions
    }


def library_classification_report(functions: list[dict]) -> list[dict]:
    """Return auditable library/noise and user-code role decisions."""
    report: list[dict] = []
    for fn in functions:
        is_library, reason = classify_library_function(fn)
        role = "library"
        if not is_library:
            is_fragment, fragment_reason = classify_user_fragment(fn)
            role = "user_fragment" if is_fragment else "user_primary"
            reason = fragment_reason
        report.append({
            "name": str(fn.get("name") or fn.get("entry") or "unknown"),
            "entry": fn.get("entry"),
            "is_library": is_library,
            "role": role,
            "reason": reason,
        })
    return report
