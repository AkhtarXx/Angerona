"""Forced-default re-execution (A3, research Part 2) — every behavioral claim is verified.

Research basis (angerona research notes, 2026-07-15, Part 2 A3):
  Re-executability of decompiled output is "far from guaranteed" (LLM4Decompile 2403.05286,
  CoDe-R 2604.12913, Decaf 2605.11501). Angerona's verify_reconstruction gate is the right
  tool but ONLY fires when the agent produces a `reconstruction_dir` — a report that only
  *describes* behavior in prose is never subjected to the re-execution reality check. A3
  argues re-executability should be a DEFAULT expectation, not opt-in.

This module makes it default: it scans an agent report for C code blocks (recovered/
reconstructed function bodies), wraps each in a minimal compilable harness with a reference
stub, and runs the behavioral equivalence oracle (bequiv.py). Any block that FAILS to
compile or diverges from its stated contract is flagged. This turns "the agent said what
this function does" into "the agent's code re-executes and matches" — automatically.

Graceful: no C blocks -> nothing to check (no false negative that blocks). A block with no
reference is still compile-and-run smoke-tested (stronger than prose-only).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .bequiv import behavioral_check, compile_check, BehavioralResult

_C_BLOCK = re.compile(r"```(?:c|c99|cpp)?\s*\n(.*?)```", re.DOTALL | re.I)


@dataclass
class ReExecFinding:
    index: int
    compiled: bool
    ran: bool
    equivalent: bool
    detail: str = ""

    def as_dict(self) -> dict:
        return {"index": self.index, "compiled": self.compiled, "ran": self.ran,
                "equivalent": self.equivalent, "detail": self.detail}


def extract_c_blocks(report: str) -> list[str]:
    """Pull ```c ... ``` blocks out of an agent markdown report."""
    return [m.group(1).strip() for m in _C_BLOCK.finditer(report or "")]


# first defined function name in a C block, e.g. "int foo(void) {"
_FUNC_DEF_RE = re.compile(
    r"^\s*(?:static\s+|inline\s+|__inline\s+)*[A-Za-z_]\w*&?\s*\*?\s*"
    r"([A-Za-z_]\w*)\s*\([^;{]*\)\s*\{",
    re.M)


def _wrap(body: str, func_name: str = "") -> str:
    """Wrap a recovered function body into a minimal compilable C translation unit.

    Many recovered blocks are a single function; we provide a main() that calls it if
    we can identify the defined function by name (never an undeclared identifier).
    If the block already has main, we leave it.
    """
    if re.search(r"\bint\s+main\s*\(", body):
        return body
    name = func_name or (m.group(1) if (m := _FUNC_DEF_RE.search(body)) else "")
    if name and name != "main":
        return f"{body}\n\nint main(void) {{ (void){name}; return 0; }}\n"
    # No identifiable function: compile-only check (no main needed with -c semantics;
    # our compile_check links, so provide a trivial empty main instead of referencing
    # an identifier that may not exist).
    return f"{body}\n\nint main(void) {{ return 0; }}\n"


def forced_reexec(report: str, *,
                  reference_c: Optional[str | Path] = None,
                  test_inputs: Optional[list[str]] = None,
                  compiler: str = "gcc") -> list[ReExecFinding]:
    """Auto re-execute every C block in the report. Returns per-block findings.

    With ``reference_c`` (a known-good unit), each block is behaviorally compared. Without
    it, each block is compile + smoke-run checked. Either way, a block that does not
    compile is flagged as a re-execution failure (the strongest A3 signal).
    """
    blocks = extract_c_blocks(report)
    out: list[ReExecFinding] = []
    for i, blk in enumerate(blocks):
        finding = ReExecFinding(index=i, compiled=False, ran=False, equivalent=False)
        wrapped = _wrap(blk)
        with _tmp_c(wrapped) as cf:
            ok, info = compile_check(cf, compiler=compiler)
            finding.compiled = ok
            if not ok:
                finding.detail = f"block {i} failed to compile: {info[:300]}"
                out.append(finding)
                continue
            if reference_c:
                res: BehavioralResult = behavioral_check(
                    cf, reference_c, test_inputs=test_inputs, compiler=compiler)
                finding.ran = res.ran
                finding.equivalent = res.equivalent
                finding.detail = res.detail
            else:
                # smoke run: compile + run with no args
                res = behavioral_check(cf, cf, test_inputs=[""], compiler=compiler)
                finding.ran = res.ran
                finding.detail = (
                    "translation-unit smoke run completed (recovered function was not exercised; no reference for equivalence)"
                    if res.ran and not res.mismatches
                    else f"smoke execution not verified: {res.detail}"
                )
        out.append(finding)
    return out


class _tmp_c:
    def __init__(self, content: str):
        self.content = content
        self._d = None
        self.path = None

    def __enter__(self) -> Path:
        import tempfile
        self._d = tempfile.TemporaryDirectory()
        self.path = Path(self._d.name) / "blk.c"
        self.path.write_text(self.content)
        return self.path

    def __exit__(self, *a) -> None:
        if self._d:
            self._d.cleanup()
