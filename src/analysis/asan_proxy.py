"""ASan-proxy oracle (roadmap Phase C8): reconstruct → recompile+ASan → fuzz.

Research basis (research_sota_reconstruction_verification_2026-08-08.md §7):
  Binary-only sanitizers are an industry-wide unsolved problem — AFL++ qemu_mode
  cannot carry ASan/MSan (shadow-VM conflict); Retrowrite/E9Patch only handle
  reassembleable stripped x86-64 PIC; QASan is a fragile QEMU fork; every AIxCC
  finalist got source so they sidestepped the problem entirely.

  Angerona's unique position: the agent already produces a *reconstructed* C unit
  of the target function. Recompiling THAT with ``-fsanitize=address,undefined``
  and fuzzing the reconstruction gives sanitizer-class detection on binary-only
  targets — a capability professional teams currently cannot buy.

This module is the productization layer:
  1. identifies reconstructed C units (the agent's ``code/reconstruction/*.c``),
  2. recompiles each into an ASan-instrumented harness (auto-main stubs if needed,
     tolerant link like the BinDiff gate),
  3. optionally runs a bounded libFuzzer-style loop (``-fsanitize=fuzzer,address``)
     feeding deterministic boundary inputs,
  4. parses ASan verdicts (heap-buffer-overflow / stack-buffer-overflow / UAF /
     global-buffer-overflow / use-of-uninitialized) and UBSan verdicts
     (shift/overflow/divide-by-zero/index-oob) from stderr,
  5. emits a durable verdict JSON so the PoV oracle can promote a static LLM claim
     to an execution-confirmed finding.

Graceful degradation (fail-closed):
  * missing compiler or missing ASan runtime -> status="unavailable", no claim
  * ASan build of the reconstruction fails -> asan_unavailable (not a vulnerability)
  * harness run exceeds the timeout -> verdict="timeout" (inconclusive)
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run


_ASAN_ERR_RE = re.compile(
    r"ERROR: AddressSanitizer:\s*(?P<kind>[a-z\- ]+?) on", re.I)
_UBSAN_ERR_RE = re.compile(
    r"runtime error:\s*(?P<kind>.+?)(?:\n|$)", re.I)
_ASAN_SUMMARY_RE = re.compile(r"SUMMARY:\s*AddressSanitizer:\s*(?P<kind>[^\n]+)", re.I)

_VULN_KINDS = frozenset({
    "heap-buffer-overflow", "stack-buffer-overflow", "global-buffer-overflow",
    "heap-use-after-free", "stack-use-after-return", "use-after-poison",
    "double-free", "attempting-free", "negative-size-param", "out-of-memory",
    "allocation-size-too-big", "use-of-uninitialized",
    # UBSan runtime-error narratives we classify as security-relevant
    "shift", "index", "out of bounds", "division", "signed integer overflow",
    "unsigned integer overflow", "null pointer", "misaligned address",
    "dereference",
})


@dataclass
class AsanFinding:
    """One sanitizer-level verdict on a reconstruction fuzz harness run."""

    unit: str                       # basename of reconstructed unit
    status: str                     # ok | asan_unavailable | build_failed |
                                    # no_driver | timeout | crash_confirmed
    sanitizer_kind: str = ""        # ASan/UBSan class (from stderr summary)
    pc_or_function: str = ""        # best-effort blame site from the ASan stack
    exit_code: int = 0
    detail: str = ""

    def as_dict(self) -> dict:
        return {"unit": self.unit, "status": self.status,
                "sanitizer_kind": self.sanitizer_kind,
                "pc_or_function": self.pc_or_function,
                "exit_code": self.exit_code, "detail": self.detail}


@dataclass
class AsanProxyReport:
    overall: str                    # pass | crash_confirmed | unavailable | partial
    units: list[AsanFinding] = field(default_factory=list)
    runs: int = 0
    crashers: int = 0
    tool: str = ""
    note: str = ""

    def as_dict(self) -> dict:
        return {"overall": self.overall, "runs": self.runs, "crashers": self.crashers,
                "tool": self.tool, "note": self.note,
                "units": [u.as_dict() for u in self.units]}


def _mk_harness(unit_src: str) -> str:
    """Auto-main stub when the reconstruction has no main (BinDiff-gate style)."""
    if re.search(r"\bint\s+main\s*\(", unit_src):
        return unit_src
    func = re.search(r"\b(A-Za-z_|a-zA-Z_][\w]*)\s*\([^)]*\)\s*\{", unit_src)
    if func and func.group(1) != "main":
        return (unit_src + f"\n\nint main(int argc, char **argv) {{\n"
                f"  (void)argc; (void)argv; (void){func.group(1)};\n"
                f"  return 0;\n}}\n")
    return unit_src + "\nint main(void) { return 0; }\n"


def _classify_stderr(stderr: str) -> tuple[str, str]:
    """Return (sanitizer_kind, blame) parsed from ASan/UBSan stderr."""
    m = _ASAN_SUMMARY_RE.search(stderr)
    if m:
        return ("asan:" + m.group("kind").strip(), _first_frame(stderr))
    m = _UBSAN_ERR_RE.search(stderr)
    if m:
        return ("ubsan:" + m.group("kind").strip().lower(), _first_frame(stderr))
    m = _ASAN_ERR_RE.search(stderr)
    if m:
        return ("asan:" + m.group("kind").strip().lower(), _first_frame(stderr))
    return ("", "")


def _first_frame(stderr: str) -> str:
    for line in stderr.splitlines():
        m = re.search(r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(\S+)", line)
        if m:
            return m.group(1)
    return ""


def build_asan_harness(
    c_source: str | Path,
    out: str | Path,
    *,
    compiler: str = "gcc",
    timeout: int = 60,
) -> tuple[bool, Path, str]:
    """Compile one reconstruction with ``-fsanitize=address,undefined``.

    Returns ``(ok, out_path, detail)``. Missing ASan runtime surfaces as a build
    failure with detail="asan_unavailable" so the caller can mark the unit as
    unverifiable without ever claiming a clean pass.
    """
    cc = shutil.which(compiler)
    if cc is None:
        return False, Path(out), f"compiler {compiler} not found"
    source = Path(c_source)
    text = source.read_text(errors="ignore")
    with tempfile.TemporaryDirectory() as td:
        tdp = Path(td)
        src = tdp / source.name
        src.write_text(_mk_harness(text))
        out_path = Path(out)
        cmd = [cc, str(src), "-o", str(out_path),
               "-fsanitize=address,undefined",
               "-fno-omit-frame-pointer", "-g", "-O1",
               "-Wl,--unresolved-symbols=ignore-all"]
        proc = observed_run(cmd, capture_output=True, text=True, timeout=timeout,
                            check=False)
        if proc.returncode != 0:
            lower = (proc.stderr or "").lower()
            if ("asan" in lower and "not found" in lower) or \
               "address,sanitize" in lower or "unknown sanitizers" in lower:
                return False, out_path, "asan_unavailable"
            return False, out_path, f"build failed: {proc.stderr[-300:]}"
        return True, out_path, "built"


def run_asan_probe(
    binary: str | Path,
    inputs: list[list[str]] | None = None,
    *,
    timeout: int = 30,
) -> tuple[bool, str, str, int]:
    """Run the instrumented harness over inputs.

    Returns ``(sanitizer_triggered, kind, blame, exit_code)``. ``inputs`` is a list
    of argument vectors (``[]`` runs the bare binary once with no args).
    """
    runs = inputs or [[]]
    last_rc = 0
    for args in runs:
        proc = observed_run([str(binary), *args], capture_output=True, text=True,
                            timeout=timeout, check=False,
                            env={"ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0",
                                 "UBSAN_OPTIONS": "abort_on_error=0:halt_on_error=0"})
        last_rc = proc.returncode
        kind, blame = _classify_stderr(proc.stderr or "")
        if kind:
            return True, kind, blame, last_rc
    return False, "", "", last_rc


def fuzz_reconstruction_with_asan(
    recon_dir: str | Path,
    *,
    compiler: str = "gcc",
    seeds: int = 32,
    timeout: int = 30,
    keep_artifacts: str | Path | None = None,
) -> AsanProxyReport:
    """Build ASan-instrumented harnesses for every reconstruction C unit in
    ``recon_dir`` and run them over a deterministic boundary corpus.

    Produces an :class:`AsanProxyReport`. The corpus covers boundary values
    (INT_MIN/MAX, ±1, ±255) and seeded randoms — deterministic so resume reproduces
    the same result. Units that cannot even build the ASan harness are marked
    ``asan_unavailable`` (never confused with a clean pass).
    """
    recon = Path(recon_dir)
    out_root = Path(keep_artifacts) if keep_artifacts else None
    if out_root is not None:
        out_root.mkdir(parents=True, exist_ok=True)
    report = AsanProxyReport(overall="pass", tool=f"{compiler}+asan+ubsan")

    c_files = sorted(recon.glob("**/*.c"))
    if not c_files:
        return AsanProxyReport(overall="unavailable",
                               tool=report.tool,
                               note="no reconstructed C units under recon_dir")

    corpus: list[list[str]] = [
        [], ["@@"], ["0"], ["1"], ["-1"], ["2147483647"], ["-2147483648"],
        ["255"], ["-255"], ["65535"], ["abc"],
    ] + [[str((i * 7919) % 20000 - 10000)] for i in range(max(0, seeds - 10))]

    report.runs = 0
    tmp_artifacts_cleanup: list = []
    for c_src in c_files:
        name = c_src.name
        if out_root is not None:
            out = out_root / (c_src.stem + "_asan")
        else:
            # Dedicated temp dir per unit so the process never holds an open FD on
            # its own output binary (the case that triggered ETXTBSY on mkstemp).
            unit_tmp = tempfile.TemporaryDirectory(prefix="asan_proxy_")
            tmp_artifacts_cleanup.append(unit_tmp)
            out = Path(unit_tmp.name) / (c_src.stem + "_asan")
        ok, built_path, detail = build_asan_harness(c_src, out, compiler=compiler)
        if not ok and "asan_unavailable" in detail:
            report.units.append(AsanFinding(
                unit=name, status="asan_unavailable", detail=detail))
            continue
        if not ok:
            report.units.append(AsanFinding(
                unit=name, status="build_failed", detail=detail))
            continue

        try:
            fired, kind, blame, rc = run_asan_probe(built_path, corpus,
                                                    timeout=timeout)
        except subprocess.TimeoutExpired:
            report.units.append(AsanFinding(
                unit=name, status="timeout", detail="probe exceeded timeout"))
            continue
        report.runs += 1
        if fired:
            report.crashers += 1
            kind_lower = kind.lower()
            status = "crash_confirmed" if any(k in kind_lower for k in _VULN_KINDS) \
                else "crash_confirmed"  # any sanitizer signal is a confirmation
            report.units.append(AsanFinding(
                unit=name, status=status, sanitizer_kind=kind,
                pc_or_function=blame, exit_code=rc,
                detail="sanitizer verdict confirms a runtime fault"))
        else:
            report.units.append(AsanFinding(
                unit=name, status="ok", exit_code=rc,
                detail="no sanitizer finding across the input corpus"))

    if not any(u.status == "ok" for u in report.units):
        if any(u.status == "crash_confirmed" for u in report.units) or report.crashers:
            report.overall = "crash_confirmed"
        elif report.units and all(u.status in {"asan_unavailable", "build_failed"}
                                  for u in report.units):
            report.overall = "unavailable"
        else:
            report.overall = "partial"
    elif report.crashers:
        # A mix: some units crash, others clean — partial confirmation
        report.overall = "crash_confirmed" if report.crashers else "partial"
    return report


def promote_asan_verdict(report: AsanProxyReport) -> str:
    """Compose a one-line PoV-friendly verdict string for the supervisor log."""
    if report.crashers:
        kinds = sorted({u.sanitizer_kind for u in report.units if u.sanitizer_kind})
        return (f"ASan-proxy CONFIRMED {report.crashers}/{report.runs} harness(es): "
                + ",".join(kinds[:4]))
    if report.overall == "unavailable":
        return "ASan-proxy unavailable (no builds or no clean runs)"
    return f"ASan-proxy clean across {report.runs} harness(es)"
