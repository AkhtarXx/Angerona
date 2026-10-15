"""Behavioral equivalence oracle (A4, research Part 2) — input/output, not just structure.

Research basis (angerona research notes, 2026-07-15, Part 2 A3/A4):
  LLM4Decompile (2403.05286), CoDe-R (2604.12913), Decaf (2605.11501), codealign
  (2501.04811) all converge: "readable-looking" decompiled C that does NOT re-execute to
  the same behavior is worse than useless. Structural BinDiff similarity is NOT behavioral
  equivalence — two functions can match structurally yet diverge on inputs the pipeline
  never runs (angerona is static-only by default). A4 argues correctness needs a finer,
  *behavioral* check.

This module is that check. Given the agent's reconstructed C for a function (or a
self-contained reconstruction), it:
  1. compiles it (sandboxed gcc),
  2. requires self-contained translation units with caller-supplied drivers,
  3. runs BOTH the recompiled function and a reference (original-lifted or the agent's
     stated expected behavior) over a set of inputs,
  4. compares outputs -> behavioral equivalence verdict.

Because a full harness synthesizer is a research project of its own (Part 9 roadmap), this
module implements the PRACTICAL, production-grade core: it compiles + runs the reconstructed
unit against a user/agent-supplied test-input set (or auto-generated fuzz inputs via a
driver) and reports (a) does it compile, (b) does it run without crash, (c) does its output
match the reference on the supplied inputs. This compares exit status and exact
stdout/stderr bytes, not all memory or filesystem side effects. No compiler means
"not verifiable". A behavioral comparison requires a reference; compile_check is
available separately for structural compilation without one.
"""

from __future__ import annotations

import re
import shutil
import signal
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..subprocess_observability import observed_run


# Linker tolerance: reconstruction files reference Solana/SBF runtime symbols (rust_panic,
# sol_log_, anchor_*) declared `extern` that are never defined on the host. We are doing a
# *structural* (BinDiff) check, not executing the code, so unresolved externs must NOT block
# the link — only the function bodies need to be present in the produced binary. Without
# this, every real reconstruction fails the gate on `undefined reference to rust_panic`
# instead of on genuine behavioural divergence, and the agent can never converge.
_UNRESOLVED_IGNORE = ["-Wl,--unresolved-symbols=ignore-all"]

# A gcc error line, e.g. "f.c:24:5: error: unknown type name 'u32'".
_GCC_ERROR_RE = re.compile(
    r"^(?P<loc>\S+?:\d+(?::\d+)?):\s*(?P<level>error|fatal error):\s*(?P<msg>.+)$",
    re.MULTILINE,
)
_UNDEFINED_REF_RE = re.compile(r"undefined reference to `(?P<sym>[^']+)'")
_MISSING_MAIN_RE = re.compile(r"undefined reference to `main'")


@dataclass
class BehavioralResult:
    compiled: bool = False
    ran: bool = False
    equivalent: bool = False
    inputs_tested: int = 0
    mismatches: list[str] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {
            "compiled": self.compiled, "ran": self.ran, "equivalent": self.equivalent,
            "inputs_tested": self.inputs_tested,
            "mismatches": self.mismatches[:20], "detail": self.detail,
        }


def _have(cc: str) -> bool:
    return shutil.which(cc) is not None


def _has_main(source_text: str) -> bool:
    return re.search(r"\bint\s+main\s*\(", source_text) is not None


def _sandbox_compile(cmd: list[str], source: Path, out_dir: Path) -> list[str]:
    """Sandbox a gcc/clang invocation when bwrap is available; else run plain.

    Compiling untrusted C *text* is far lower risk than executing it, so on a
    host without bubblewrap we degrade to an unsandboxed compile (matching the
    pre-sandbox behavior) rather than failing the gate. Execution of the
    produced binary is handled separately and is always fail-closed.
    """
    from . import sandbox
    if not sandbox.available():
        return cmd
    return sandbox.wrap(
        cmd, writable_dirs=[out_dir], readonly_binds=[source.resolve().parent]
    )


def compile_problems(c_source: str | Path, *, compiler: str = "gcc",
                     extra_flags: str = "") -> list[dict]:
    """Compile a reconstruction with a *tolerant* link and return parsed real errors.

    The link is tolerant in two ways that don't affect structural verification:
      * no ``main`` -> auto-wrap ``int main(void){return 0;}`` (structural diff only
        needs the reconstructed function bodies, not an entry point);
      * unresolved extern symbols -> ``-Wl,--unresolved-symbols=ignore-all`` (we are
        not executing, so undefined Solana/SBF runtime calls are irrelevant).

    What is NOT tolerated (and still surfaces as a problem): genuine C errors — bad
    syntax, unknown types, missing typedefs. Those block producing any function body
    and are exactly what the agent must fix.

    Returns a list of ``{"kind", "message"}``. Empty list == compiles cleanly under
    the tolerant link.
    """
    c_source = Path(c_source)
    if not _have(compiler):
        return [{"kind": "no_compiler", "message": f"compiler {compiler} not found"}]
    source_text = c_source.read_text(errors="ignore")
    with tempfile.TemporaryDirectory() as td:
        tdpath = Path(td)
        compile_source = c_source
        if not _has_main(source_text):
            wrapped = tdpath / f"{c_source.stem}_wrapped.c"
            wrapped.write_text(source_text + "\nint main(void){return 0;}\n")
            compile_source = wrapped
        out = tdpath / "a.out"
        cmd = ([compiler, str(compile_source), "-o", str(out)]
               + extra_flags.split() + _UNRESOLVED_IGNORE)
        r = observed_run(
            _sandbox_compile(cmd, compile_source, tdpath),
            capture_output=True, text=True, timeout=120, check=False,
        )
        if r.returncode == 0:
            return []
        problems: list[dict] = []
        # Distinguish missing-main (now auto-handled, so if it still appears the agent
        # wrote something exotic) and unresolved symbols (tolerated) from real errors.
        for m in _GCC_ERROR_RE.finditer(r.stderr):
            problems.append({"kind": "compile_error",
                              "message": f"{m.group('loc')}: {m.group('msg')}"})
        if not problems:
            # The linker is already configured to tolerate unresolved symbols.
            # A nonzero exit is failure even when diagnostics cannot be parsed.
            problems.append({
                "kind": "compile_error",
                "message": f"compiler exited {r.returncode}: {(r.stderr or r.stdout or 'no diagnostics')[-1500:]}",
            })
        return problems


def compile_check(c_source: str | Path, *, compiler: str = "gcc",
                  extra_flags: str = "") -> tuple[bool, str]:
    """Compile the reconstructed C. Returns (ok, error_or_path).

    Link-tolerant: auto-wraps a missing ``main`` and ignores unresolved extern symbols,
    so structural reconstructions that reference undefined Solana/SBF runtime calls still
    compile. Genuine C syntax/type errors still fail (returned in the detail string).
    """
    c_source = Path(c_source)
    problems = compile_problems(c_source, compiler=compiler, extra_flags=extra_flags)
    if problems and problems[0].get("kind") == "no_compiler":
        return False, problems[0]["message"]
    if problems:
        return False, "\n".join(p["message"] for p in problems)[:1500]
    # Compiled cleanly under the tolerant link; report a sentinel path for callers that
    # only inspect the bool (behavioral_check recompiles itself with its own path).
    return True, "ok"


def behavioral_check(reconstructed_c: str | Path, reference_c: str | Path,
                     test_inputs: list[str] | None = None, *,
                     compiler: str = "gcc", timeout: int = 60) -> BehavioralResult:
    """Compare exit status and exact stdout/stderr bytes on supplied inputs.

    ``test_inputs`` is a list of CLI argument strings (one per run). If None, we run a
    single no-arg invocation as a smoke test. Returns a BehavioralResult.

    Graceful: missing compiler -> compiled=False (not verifiable, never a false positive).
    """
    import shlex
    import tempfile
    from . import sandbox
    res = BehavioralResult()
    if test_inputs == []:
        res.detail = "no test inputs supplied; no behavioral evidence"
        return res
    if timeout <= 0:
        res.detail = "execution timeout must be positive"
        return res
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        rec_out = tdp / "rec.out"
        ref_out = tdp / "ref.out"
        if not _have(compiler):
            res.detail = f"compiler {compiler} not found"
            return res
        rec_src = Path(reconstructed_c)
        ref_src = Path(reference_c)
        r1 = observed_run(
            _sandbox_compile([compiler, str(rec_src), "-o", str(rec_out)], rec_src, tdp),
            capture_output=True, text=True, timeout=120, check=False,
        )
        r2 = observed_run(
            _sandbox_compile([compiler, str(ref_src), "-o", str(ref_out)], ref_src, tdp),
            capture_output=True, text=True, timeout=120, check=False,
        )
        res.compiled = r1.returncode == 0 and r2.returncode == 0
        if not res.compiled:
            res.detail = (f"compile failed: rec={r1.stderr[-400:]} "
                          f"ref={r2.stderr[-400:]}")
            return res
        if not sandbox.available():
            # Executing reconstructed (attacker-influenced) binaries unsandboxed
            # would hand them full host + network access. Refuse rather than run.
            res.detail = ("bubblewrap (bwrap) unavailable; refusing to execute "
                          "reconstructed binaries without isolation")
            return res
        inputs = [""] if test_inputs is None else test_inputs
        for inp in inputs:
            try:
                args = shlex.split(inp) if inp else []
            except ValueError as exc:
                res.mismatches.append(f"invalid input quoting for {inp!r}: {exc}")
                continue
            try:
                # Neither untrusted program may replace the other oracle binary.
                # Give each invocation private writable state; compiled artifacts
                # remain read-only in both sandboxes.
                with tempfile.TemporaryDirectory(dir=tdp) as rec_work, tempfile.TemporaryDirectory(dir=tdp) as ref_work:
                    a = observed_run(
                        sandbox.wrap([str(rec_out), *args], writable_dirs=[Path(rec_work)], readonly_binds=[tdp]),
                        cwd=rec_work, capture_output=True, timeout=timeout, check=False,
                    )
                    b = observed_run(
                        sandbox.wrap([str(ref_out), *args], writable_dirs=[Path(ref_work)], readonly_binds=[tdp]),
                        cwd=ref_work, capture_output=True, timeout=timeout, check=False,
                    )
            except subprocess.TimeoutExpired:
                res.mismatches.append(f"timeout on input {inp!r}")
                continue
            except OSError as exc:
                res.mismatches.append(f"execution failed on input {inp!r}: {exc}")
                continue
            # Bubblewrap translates child signals to 128+signal. That range
            # is ambiguous, never positive equivalence evidence. Statuses above
            # the platform's signal range (e.g. Linux exit 255) still compare.
            if any(p.returncode < 0 or 128 < p.returncode < 128 + signal.NSIG for p in (a, b)):
                res.mismatches.append(f"signal termination or ambiguous high exit status on input {inp!r}: rec={a.returncode}, ref={b.returncode}")
                continue
            if any(re.search(rb"(?m)^bwrap:" if isinstance(p.stderr, bytes) else r"(?m)^bwrap:", p.stderr or (b"" if isinstance(p.stderr, bytes) else "")) for p in (a, b)):
                res.mismatches.append(f"sandbox startup failed on input {inp!r}")
                continue
            res.ran = True
            res.inputs_tested += 1
            if a.returncode != b.returncode or a.stdout != b.stdout or a.stderr != b.stderr:
                res.mismatches.append(
                    f"input {inp!r}: rc {a.returncode}!={b.returncode} or "
                    f"out {a.stdout[:80]!r}!={b.stdout[:80]!r} or "
                    f"err {a.stderr[:80]!r}!={b.stderr[:80]!r}")
    res.equivalent = res.ran and not res.mismatches
    res.detail = ("behavioral equivalence confirmed on "
                  f"{res.inputs_tested} inputs" if res.equivalent
                  else f"{len(res.mismatches)} mismatch(es) over {res.inputs_tested} inputs")
    return res
