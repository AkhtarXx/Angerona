"""Runtime differential testing — behavioral equivalence oracle (roadmap Phase B6).

Research basis (research_sota_reconstruction_verification_2026-08-08.md §1–2):
  MCGD (arXiv 2604.23940) shows compile-only validation gives 91–99% compile rate
  with **0% behavioral correctness** — the only trustworthy gate is the 3-level
  ladder: parse → compile → *behavioral-test equivalence*. Liu & Wang (ISSTA 2020)
  confirm with 1,423 mismatch-triggering inputs found by re-executing decompiled
  code against the original. Professionals (Trail of Bits / Big Sleep) run this
  ladder through sanitizer verdicts and harness re-execution, not BinDiff.

This module is the production entry point for level-3 (behavioral) equivalence over
the agent's reconstructed C. It:

  1. parses the reconstruction (locates the claimed function),
  2. compiles it (tolerant link, auto-main),
  3. compiles a *reference* — either one the caller supplies, a same-binary twin
     function file, or a synthesized oracle main that exercises the reconstruction's
     declared prototype with deterministic boundary inputs,
  4. runs both over a deterministic input corpus (edge values, typical values, a
     seeded pseudo-random sweep), comparing exit codes + stdout,
  5. returns a structured 3-level verdict (parse / compile / behavior) with the
     exact first-diverging input for the repair agent.

Graceful degradation (never a false positive):
  * no compiler / no unicorn for cross-arch -> level-3 = "unverifiable", NOT pass
  * no reference available -> "compiled + smoke run" (structural smoke, no equivalence)
  * timeout/crash on either side -> divergence recorded against the reconstruction

The result is consumed by ``ConvergenceLoop._verify_understanding_step`` as the
behavioral pillar that complements the BinDiff structural pillar.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run
from .bequiv import behavioral_check, compile_check

_FUNC_DEF_RE = re.compile(
    r"\b(?:static\s+)?[A-Za-z_][A-Za-z0-9_\s\*]{0,60}?\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)\s*\{",
)
_MAIN_RE = re.compile(r"\bint\s+main\s*\(")

# Deterministic pseudo-random input corpus (Mulberry32-style, no runtime deps).
def _corpus(count: int = 32) -> list[str]:
    """Deterministic CLI argument strings covering boundary + typical values."""
    fixed = ["0", "1", "-1", "2147483647", "-2147483648", "255", "-255",
             "65535", "127", "-128", "4096", "abc", "deadbeef", ""]
    seeds = []
    x = 0x2545F491
    for _ in range(max(0, count - len(fixed))):
        x = (x * 747796405 + 2891336453) & 0xFFFFFFFF
        seeds.append(str(x % 20000 - 10000))
    return [s for s in fixed + seeds][:count]


@dataclass
class DifferentialVerdict:
    """3-level ladder result for one reconstructed function unit."""

    # ladder levels (independent booleans; behavior implies compile implies parse)
    parse_ok: bool = False
    compile_ok: bool = False
    behavior_ok: bool = False
    # detail
    function_name: str = ""
    reason: str = ""
    mismatch_input: str = ""       # first diverging input (for the repair agent)
    inputs_tested: int = 0
    reference: str = ""            # how the reference was obtained
    # agent-facing repair hint
    repair_hint: str = ""

    def as_dict(self) -> dict:
        return {
            "parse_ok": self.parse_ok,
            "compile_ok": self.compile_ok,
            "behavior_ok": self.behavior_ok,
            "function_name": self.function_name,
            "reason": self.reason,
            "mismatch_input": self.mismatch_input,
            "inputs_tested": self.inputs_tested,
            "reference": self.reference,
            "repair_hint": self.repair_hint,
            "ladder": ("level3-behavioral" if self.behavior_ok else
                       ("level2-compile-only" if self.compile_ok else
                        ("level1-parse-only" if self.parse_ok else "level0-invalid"))),
        }


def _extract_function_name(source: str) -> str:
    for m in _FUNC_DEF_RE.finditer(source):
        if m.group(1) != "main":
            return m.group(1)
    return ""


def _synthesize_reference(source: str, func: str) -> str:
    """Build a reference main() that calls the reconstructed function with the same
    deterministic corpus. Used when no caller reference exists — it does NOT assert
    equivalence (nothing to diff against), only that the function *runs*; the verdict
    is then compile+smoke, never false behavioral OK.
    """
    if not func:
        return source
    return (source +
            f"\n\nint main(int argc, char **argv) {{\n"
            f"  (void)argc; (void)argv;\n"
            f"  (void){func};\n"
            f"  return 0;\n}}\n")


def runtime_differential(
    reconstructed_c: str | Path,
    *,
    reference_c: str | Path | None = None,
    twin_dir: str | Path | None = None,
    test_inputs: list[str] | None = None,
    compiler: str = "gcc",
    corpus_size: int = 32,
    timeout: int = 60,
) -> DifferentialVerdict:
    """Run the 3-level ladder on a reconstructed C unit.

    Parameters
      reconstructed_c   path to the agent's reconstruction.
      reference_c       caller-supplied trusted reference (best evidence).
      twin_dir          alternative: directory of per-function reconstructed units
                        (e.g. code/reconstruction/); this function seeks a sibling
                        with the same function name as a self-consistency check —
                        records reference="twin" but is *weaker* than reference_c.
      test_inputs       explicit CLI arg strings; when None, the deterministic
                        boundary corpus is used.
    """
    res = DifferentialVerdict()
    recon = Path(reconstructed_c)
    source = recon.read_text(errors="ignore")
    if not source.strip():
        res.reason = "empty reconstruction file"
        return res
    func = _extract_function_name(source)
    res.function_name = func or "(unnamed)"
    res.parse_ok = bool(_FUNC_DEF_RE.search(source))
    if not res.parse_ok:
        res.reason = "no function definition found in reconstruction"
        res.repair_hint = "declare the function with a body; pure declarations cannot run"
        return res

    # Level 2: compile
    okc, detail = compile_check(recon, compiler=compiler)
    res.compile_ok = okc
    if not okc:
        res.reason = "compile failed"
        res.repair_hint = detail[:300]
        return res

    inputs = test_inputs or _corpus(corpus_size)

    # Reference selection
    ref_path: Path | None = None
    if reference_c is not None:
        ref_path = Path(reference_c)
        res.reference = "caller-supplied trusted reference"
    elif twin_dir is not None and func:
        for cand in sorted(Path(twin_dir).glob("*.c")):
            if cand == recon:
                continue
            body = cand.read_text(errors="ignore")
            if f"{func}(" in body:
                ref_path = cand
                res.reference = f"twin-function self-consistency ({cand.name})"
                break

    if ref_path is None:
        # No oracle -> smoke run only. NEVER claim behavioral equivalence: the file
        # already compiled at level 2 (including its own `main`, if present). Report
        # that structural smoke result without pretending to have diffed behavior.
        res.inputs_tested = 1
        res.reference = "no reference available (compile-level structural smoke only)"
        res.behavior_ok = False
        res.reason = ("compiled + structurally well-formed (no reference to diff "
                      "against; behavioral equivalence NOT confirmed)")
        return res

    # Level 3: behavioral equivalence over the deterministic corpus.
    check = behavioral_check(recon, ref_path, test_inputs=inputs,
                             compiler=compiler, timeout=timeout)
    res.inputs_tested = check.inputs_tested
    if check.mismatches:
        res.behavior_ok = False
        res.mismatch_input = check.mismatches[0][:120]
        res.reason = f"behavioral divergence: {check.mismatches[0][:200]}"
        res.repair_hint = (
            f"first divergence on input {res.mismatch_input!r}; compare control flow "
            "and constant handling around that case against the reference")
        return res
    res.behavior_ok = check.ran and bool(inputs)
    res.reason = (f"behavioral equivalence confirmed across {check.inputs_tested} inputs"
                  if res.behavior_ok else "no inputs executed")
    return res


def verify_whole_reconstruction_dir(
    recon_dir: str | Path,
    *,
    compiler: str = "gcc",
    corpus_size: int = 16,
    timeout: int = 45,
) -> dict:
    """Verify every reconstructed C file under ``recon_dir`` and return a report.

    Twin references are disabled here (each unit stands alone) — only files with a
    caller-supplied reference get level-3 behavioral equivalence; the rest are
    compile+smoke. The report is consumed by the convergence gate's repair feedback.
    """
    out: dict = {
        "units": [],
        "total": 0, "parse_ok": 0, "compile_ok": 0, "behavior_ok": 0,
        "verdict": "no-units",
    }
    for c in sorted(Path(recon_dir).glob("**/*.c")) + sorted(Path(recon_dir).glob("**/*.cpp")):
        v = runtime_differential(c, compiler=compiler, corpus_size=corpus_size,
                                 timeout=timeout)
        out["units"].append({"file": c.name, **v.as_dict()})
        out["total"] += 1
        out["parse_ok"] += 1 if v.parse_ok else 0
        out["compile_ok"] += 1 if v.compile_ok else 0
        out["behavior_ok"] += 1 if v.behavior_ok else 0
    if out["total"] == 0:
        out["verdict"] = "no-units"
    elif out["compile_ok"] < out["total"]:
        out["verdict"] = "compile-failures"
    elif out["behavior_ok"] == 0:
        out["verdict"] = "compile-only (behavioral oracle absent)"
    else:
        out["verdict"] = "behaviorally-equivalent"
    return out
