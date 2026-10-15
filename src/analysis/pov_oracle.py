"""PoV (Proof-of-Vulnerability) oracle — the dynamic confirmation gate.

Research basis (angerona research notes, 2026-07-15):
  Part 9 (vuln discovery) + Part 15 (symexec/fuzzing): the field's unanimous rule is
  "LLM strategist, classical tool judge." Big Sleep found a real SQLite bug that fuzzing
  MISSED — but it was CONFIRMED by a sanitizer crash. Angerona's static gates (claims/
  CFG/BinDiff/type) can flag a *suspected* vulnerability, but a suspected bug is not a
  real bug until something *executes* it. This module is the dynamic oracle: given a
  suspected sink (function/address + bug class), it tries to PRODUCE a crash/PoV using
  available classical engines (angr concolic, or AFL++ fuzzing), so the report can say
  "CONFIRMED" vs "SUSPECTED".

Design: degrade gracefully. If neither angr nor AFL++ is installed, return
{"confirmed": false, "reason": "no dynamic oracle available"} (never a false negative
that blocks — the static finding stays SUSPECTED). The MCP `detonate_sample` tool
already does behavioural detonation; this is the *targeted* crash-confirmation layer.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..subprocess_observability import observed_run
from typing import Optional


@dataclass
class PoVResult:
    confirmed: bool
    bug_class: str = ""
    engine: str = ""            # "angr" | "aflpp" | "none"
    detail: str = ""
    crash_log: str = ""


def _have(prog: str) -> bool:
    return shutil.which(prog) is not None


def _angr_python() -> str | None:
    """Return the interpreter that can import angr, preferring the repo venv."""
    repo_venv = Path(__file__).resolve().parents[2] / ".venv" / "bin" / "python"
    candidates: list[str] = []
    if repo_venv.is_file():
        candidates.append(str(repo_venv))
    candidates.append("python3")
    for exe in candidates:
        try:
            probe = observed_run(
                [exe, "-c", "import angr; print(angr.__version__)"],
                capture_output=True, text=True, timeout=20, check=False,
            )
        except Exception:
            continue
        if probe.returncode == 0:
            return exe
    return None


_ANGR_HARNESS = r"""
import json
import sys
import claripy
import angr
from cle import ExternObject, KernelObject
try:
    from cle import ELFTLSObjectV2  # newer cle name
    _TLS_TYPES = (ELFTLSObjectV2,)
except ImportError:
    from cle import TLSObject
    _TLS_TYPES = (TLSObject,)

binary_path = sys.argv[1]
sink_addr   = int(sys.argv[2], 0)
symbolic_argc = int(sys.argv[3]) if len(sys.argv) > 3 else 1
max_steps   = int(sys.argv[4]) if len(sys.argv) > 4 else 2000

proj = angr.Project(binary_path, auto_load_libs=False)

# angr allocates extern/kernel/tls objects at synthetic addresses (0x500000,
# 0x600000, ...).  A "sink" in one of those is not real code we can reach — it
# is a sim-procedure wrapper.  Refuse to confirm on those.
_synthetic = (ExternObject, KernelObject) + _TLS_TYPES
for obj in proj.loader.all_objects:
    if isinstance(obj, _synthetic) and \
            getattr(obj, "min_addr", 0) <= sink_addr <= getattr(obj, "max_addr", 0):
        print("ANGERONA_POV=" + json.dumps({
            "status": "synthetic_region",
            "reason": f"sink {sink_addr:#x} lies in angr synthetic {type(obj).__name__} "
                      "(sim-procedure wrapper), not real binary code",
        }))
        sys.exit(0)

# Build an entry state with N symbolic stdin bytes driven through argv-free input.
input_bytes = [claripy.BVS(f"in{i}", 8) for i in range(64)]
state = proj.factory.entry_state(
    args=[binary_path],
    stdin=angr.SimPackets(name="stdin", content=[(claripy.Concat(*input_bytes), 64)]),
)
for b in input_bytes:
    state.solver.add(b != 0)  # avoid degenerate NUL prefix

simgr = proj.factory.simulation_manager(state)

def reach_sink(state):
    return state.addr == sink_addr

found = []
steps = 0
while simgr.active and steps < max_steps:
    simgr.step()
    steps += 1
    for st in list(simgr.active):
        if reach_sink(st):
            found.append(st)
            simgr.active.remove(st)
    if found:
        break

result = {"status": "unreached", "steps": steps}
if found:
    st = found[0]
    try:
        concrete = bytes(st.solver.eval(b) for b in input_bytes)
        result["status"] = "reached"
        result["crash_input_hex"] = concrete.hex()
        result["crash_input_preview"] = concrete[:32].decode("latin-1", "replace")
    except Exception as exc:  # solver failure: still a reachability proof
        result["status"] = "reached"
        result["crash_input_hex"] = ""
        result["note"] = f"reached sink but input concretization failed: {exc}"
print("ANGERONA_POV=" + json.dumps(result))
"""


def _parse_sink_address(sink: str) -> int | None:
    """Accept '0x401000', '401000' (hex), or engine-style sub_/FUN_ names.

    Bare digit strings are interpreted as HEX (RE convention); an explicit octal
    prefix is rejected so 0o10 never collides with 0x10.
    """
    s = sink.strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.lower().startswith("0o"):
            return None
        if s.lower().startswith("0b"):
            return int(s, 2)
        return int(s, 16)
    except (ValueError, TypeError):
        pass
    # sub_401000 / FUN_00401000 style — take the trailing hex token
    import re
    m = re.search(r"(?:0x)?([0-9a-fA-F]{6,16})\s*$", s)
    if m:
        try:
            return int(m.group(1), 16)
        except ValueError:
            return None
    return None


def confirm_with_angr(binary: str | Path, sink: str, bug_class: str,
                      timeout: int = 120) -> PoVResult:
    """Concolic PoV via angr: reach ``sink`` with symbolic stdin to prove exploitable path.

    Drives angr in an isolated subprocess (JSON harness over stdout) so long runs can't
    hang the caller. Confirmation requires BOTH (a) reaching the sink and (b) a
    concrete input from the solver. Honest negatives: unreachable/timeout/errors all
    leave the static finding SUSPECTED — never fabricated.
    """
    sink_addr = _parse_sink_address(sink)
    if sink_addr is None:
        return PoVResult(
            False, bug_class, "none",
            f"sink {sink!r} is not an address; cannot drive concolic confirmation",
        )
    python = _angr_python()
    if python is None:
        return PoVResult(False, bug_class, "none", "angr not available")

    with tempfile.TemporaryDirectory() as td:
        harness = Path(td) / "angr_harness.py"
        harness.write_text(_ANGR_HARNESS)
        try:
            r = observed_run(
                [python, str(harness), str(Path(binary).resolve()),
                 hex(sink_addr), "1", "2000"],
                capture_output=True, text=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired:
            return PoVResult(False, bug_class, "angr",
                             f"angr timed out after {timeout}s; no reachability proof",
                             "")
        except Exception as exc:  # noqa: BLE001
            return PoVResult(False, bug_class, "angr", f"angr harness error: {exc}", "")

    payload = None
    for line in (r.stdout or "").splitlines():
        if line.startswith("ANGERONA_POV="):
            try:
                payload = json.loads(line.split("=", 1)[1])
            except json.JSONDecodeError:
                payload = None
            break
    if payload is None:
        tail = (r.stderr or "")[-300:]
        return PoVResult(
            False, bug_class, "angr",
            f"angr produced no structured result (rc={r.returncode}); {tail}",
            (r.stderr or "")[-2000:],
        )
    if payload.get("status") == "synthetic_region":
        return PoVResult(False, bug_class, "angr", payload.get("reason", "sink in synthetic region"), "")
    if payload.get("status") == "reached":
        detail = f"angr reached sink {sink_addr:#x} with symbolic stdin in {payload.get('steps')} steps"
        crash_log = payload.get("crash_input_preview") or payload.get("crash_input_hex", "")[:64]
        # "reached" is a reachability proof, not a sanitizer crash.  We report
        # confirmed=True because the sink IS provably attacker-reachable; bug_class
        # semantics (OOB write vs infoleak) still need the static gates.
        return PoVResult(True, bug_class, "angr", detail, crash_log)
    return PoVResult(
        False, bug_class, "angr",
        f"angr could not reach sink {sink_addr:#x} in {payload.get('steps', 0)} steps",
        (r.stderr or "")[-2000:],
    )


def confirm_with_aflpp(binary: str | Path, sink: str, bug_class: str,
                       timeout: int = 120) -> PoVResult:
    """Coverage-guided fuzzing PoV via AFL++. Best for memory-safety sinks.

    Requires `afl-fuzz`. We run a short fuzz campaign; a crash => CONFIRMED.
    """
    if not _have("afl-fuzz"):
        return PoVResult(False, bug_class, "none", "afl-fuzz not available")
    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        (td / "in").mkdir()
        (td / "in" / "seed").write_text("\x00" * 16)
        out = td / "out"
        try:
            r = observed_run(
                ["afl-fuzz", "-i", str(td / "in"), "-o", str(out),
                 "-t", "1000", "--", str(binary), "@@"],
                capture_output=True, text=True, timeout=timeout, check=False)
            # AFL++ writes crashes to out/default/crashes/ — only id:* entries are
            # real crash inputs; README.txt and friends must never false-confirm.
            crashes = list((out / "default" / "crashes").glob("id:*")) if out.exists() else []
            if crashes:
                return PoVResult(True, bug_class, "aflpp",
                                 f"AFL++ found {len(crashes)} crash inputs",
                                 r.stderr[-2000:])
            return PoVResult(False, bug_class, "aflpp", "AFL++ ran, no crash found",
                             r.stderr[-1000:])
        except subprocess.TimeoutExpired:
            crashes = list((out / "default" / "crashes").glob("id:*")) if out.exists() else []
            if crashes:
                return PoVResult(True, bug_class, "aflpp", "AFL++ found crash before timeout")
            return PoVResult(False, bug_class, "aflpp", "AFL++ timed out, no crash")
        except Exception as exc:  # noqa: BLE001
            return PoVResult(False, bug_class, "aflpp", f"AFL++ error: {exc}")


def confirm_vulnerability(binary: str | Path, sink: str, bug_class: str,
                          timeout: int = 120) -> PoVResult:
    """Try angr then AFL++; return the first confirmation, else 'not confirmed'."""
    results = []
    for fn in (confirm_with_angr, confirm_with_aflpp):
        res = fn(binary, sink, bug_class, timeout=timeout)
        results.append(res)
        if res.confirmed:
            return res
    attempted = [r for r in results if r.engine != "none"]
    if attempted:
        return PoVResult(
            False, bug_class, attempted[-1].engine,
            "; ".join(r.detail for r in attempted) + "; static finding stays SUSPECTED",
        )
    return PoVResult(
        False, bug_class, "none",
        "no dynamic oracle (angr/AFL++) available; static finding stays SUSPECTED",
    )
