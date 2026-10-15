"""Symbolic / concolic execution runner backed by angr (optional dependency)."""

from __future__ import annotations

import base64
from typing import Any

from src.execution.models import MemorySnapshot
from src.execution.runners.base import AbstractRunner, RunnerResult
from src.execution.symbolic.fallback import static_probe_fallback
from src.execution.symbolic.models import (
    InputSeed,
    MemoryWriteObservation,
    PathConstraint,
    SymbolicProbeRequest,
    SymbolicProbeResult,
)

# Keep the heavy angr import inside methods only.  This module is loaded by
# ProbeRunner.__init__, so an import-time failure or long import would break
# every CLI command even when angr is unused.


class SymbolicRunner(AbstractRunner):
    """Runner that performs symbolic/concolic execution using angr."""

    name = "symbolic"
    _have_angr: bool | None = None

    @classmethod
    def _lazy_check(cls) -> bool:
        if cls._have_angr is None:
            try:
                import angr  # noqa: F401
                import z3  # noqa: F401
                cls._have_angr = True
            except Exception:  # noqa: BLE001
                cls._have_angr = False
        return cls._have_angr

    def can_run(self) -> bool:
        return self._lazy_check()

    def run(self, probe: Any, binary_path: str | None = None) -> RunnerResult:
        request = self._build_request(probe)
        if not self._lazy_check():
            return RunnerResult(
                status="unavailable",
                note="Symbolic execution requires 'pip install angr z3-solver'.",
                detail={"backend": self.name},
            )

        if not binary_path:
            return RunnerResult(
                status="error",
                note="symbolic probe requires a binary path",
            )

        try:
            result = self._run_symbolic(request, binary_path)
        except Exception as exc:
            return RunnerResult(
                status="error",
                note=f"symbolic exploration failed: {exc}",
            )

        return self._to_runner_result(result, binary_path)

    def _build_request(self, probe: Any) -> SymbolicProbeRequest:
        """Accept EmulatorProbeRequest or SymbolicProbeRequest."""
        if isinstance(probe, SymbolicProbeRequest):
            return probe

        # Probe is an EmulatorProbeRequest-like object.
        fn_name = getattr(probe, "function_name", "") or ""
        args = list(getattr(probe, "args", []) or [])
        ranges = list(getattr(probe, "capture_memory_ranges", []) or [])
        addr = getattr(probe, "function_address", None)
        try:
            if addr is not None:
                addr = int(addr, 0) if isinstance(addr, str) else int(addr)
        except Exception:
            addr = None

        # Treat all function arguments as symbolic by default for an EmulatorProbeRequest.
        symbolic_args = list(range(len(args)))
        return SymbolicProbeRequest(
            function_name=fn_name,
            function_address=addr,
            args=args,
            symbolic_args=symbolic_args,
            capture_memory_ranges=[tuple(r) for r in ranges],
            expected_backend=getattr(probe, "expected_backend", "symbolic") or "symbolic",
        )

    def _run_symbolic(self, request: SymbolicProbeRequest, binary_path: str) -> SymbolicProbeResult:
        import angr
        import claripy

        project = angr.Project(binary_path, auto_load_libs=False)
        fn_addr = request.function_address
        if fn_addr is None:
            fn_addr = self._resolve_symbol(project, request.function_name, binary_path)
        if fn_addr is None:
            return SymbolicProbeResult(
                status="missing_symbol",
                notes=[f"could not resolve address for {request.function_name}"],
            )

        call_args = list(request.args)
        symbolic_vars: dict[int, Any] = {}
        for idx in request.symbolic_args:
            if idx >= len(call_args):
                continue
            sym_arg = claripy.BVS(f"arg{idx}", 64, explicit_name=True)
            call_args[idx] = sym_arg
            symbolic_vars[idx] = sym_arg

        state = project.factory.call_state(fn_addr, *call_args)

        simgr = project.factory.simulation_manager(state)

        # Bounded exploration.
        try:
            if request.target_addresses:
                targets = set(request.target_addresses)
                simgr.explore(
                    find=lambda s: s.addr in targets,
                    num_find=request.max_paths,
                    n=request.max_steps,
                )
                result_states = list(simgr.found[:request.max_paths])
            else:
                simgr.run(n=request.max_steps)
                result_states = list(simgr.deadended[:request.max_paths])
                if not result_states:
                    result_states = list(simgr.active[:request.max_paths])
        except Exception as exc:
            return SymbolicProbeResult(
                status="error",
                notes=[f"exploration exception: {exc}"],
            )

        paths: list[PathConstraint] = []
        for idx, found_state in enumerate(result_states):
            trace = self._trace_from_state(found_state)
            seeds: dict[int, InputSeed] = {}
            for arg_idx, sym in symbolic_vars.items():
                try:
                    val = found_state.solver.eval(sym)
                    seeds[arg_idx] = InputSeed(arg_index=arg_idx, concrete_value=val, width_bits=64)
                except Exception:
                    seeds[arg_idx] = InputSeed(arg_index=arg_idx, width_bits=64)
            paths.append(
                PathConstraint(
                    path_id=idx,
                    reachable=True,
                    input_seeds=seeds,
                    block_trace=trace,
                    hit_target=bool(request.target_addresses and any(a in request.target_addresses for a in trace)),
                )
            )

        # Avoid blocking indefinitely when angr stalls.
        writes = self._collect_writes(simgr, request)

        return SymbolicProbeResult(
            backend="symbolic",
            status="success" if paths else "inconclusive",
            paths=paths,
            memory_writes=writes,
            notes=[f"explored {len(paths)} path(s) for {request.function_name}"],
            detail={
                "found_states": len(getattr(simgr, "found", [])),
                "deadended_states": len(getattr(simgr, "deadended", [])),
                "active_states": len(getattr(simgr, "active", [])),
                "symbolic_arguments": sorted(symbolic_vars),
            },
        )

    def _resolve_symbol(self, project: Any, name: str, binary_path: str) -> int | None:
        try:
            sym = project.loader.main_object.get_symbol(name)
            if sym is not None:
                return int(sym.rebased_addr)
        except Exception:
            pass
        # Resolve via binary string scan as a last-ditch fallback.
        needle = name.encode() + b"\x00"
        try:
            data = open(binary_path, "rb").read()
            offset = data.find(needle)
            if offset >= 0:
                # Without a symbol table we cannot map string offset to address.
                return None
        except Exception:
            pass
        return None

    def _trace_from_state(self, state: Any) -> list[int]:
        """Return the list of block addresses visited in a state history."""
        try:
            addrs = state.history.bbl_addrs
            if addrs is not None:
                return list(addrs)
        except Exception:
            pass
        return []

    def _collect_writes(self, simgr: Any, request: SymbolicProbeRequest) -> list[MemoryWriteObservation]:
        """Harvest memory writes from angr action log if available."""
        writes: list[MemoryWriteObservation] = []
        source_states = list(getattr(simgr, "found", [])) + list(getattr(simgr, "active", []))
        for state in source_states:
            try:
                for act in state.history.actions:
                    if act.type != "mem" or act.action != "write":
                        continue
                    addr = getattr(act, "addr", None)
                    data = getattr(act, "data", None)
                    concrete_addr = None
                    try:
                        concrete_addr = int(state.solver.eval(addr)) if addr is not None else None
                    except Exception:
                        pass
                    concrete_value = None
                    try:
                        concrete_value = int(state.solver.eval(data)) if data is not None else None
                    except Exception:
                        pass
                    writes.append(
                        MemoryWriteObservation(
                            address_expr=str(addr) if addr is not None else None,
                            concrete_address=concrete_addr,
                            value_expr=str(data) if data is not None else None,
                            concrete_value=concrete_value,
                            width_bits=8,
                        )
                    )
            except Exception:
                continue
        return writes[:128]

    def _to_runner_result(self, result: SymbolicProbeResult, binary_path: str) -> RunnerResult:
        detail = result.as_dict()
        detail["binary_path"] = binary_path
        if result.status != "success":
            return RunnerResult(
                status=result.status,
                note=result.notes[0] if result.notes else "symbolic probe was inconclusive",
                detail=detail,
            )
        # Encode the symbolic result as a MemorySnapshot with zero-length payload
        # so the existing enrichment loop can carry it without a schema change.
        snapshot = MemorySnapshot(
            address=f"0x{result.paths[0].block_trace[0] & 0xFFFFFFFFFFFFFFFF:x}"
                    if result.paths and result.paths[0].block_trace else "0x0",
            bytes_b64=base64.b64encode(
                result.as_dict().__str__().encode("utf-8")
            ).decode("ascii"),
            length=0,
            source="symbolic",
            timestamp="",
            name=f"symbolic:{result.backend}",
            properties={"symbolic_result": result.as_dict()},
        )
        return RunnerResult(
            status="success",
            snapshot=snapshot,
            note=result.notes[0] if result.notes else "symbolic probe completed",
            detail=detail,
        )


class FakeSymbolicRunner(AbstractRunner):
    """In-memory fake symbolic runner for pipeline tests.

    Returns deterministic path constraints and memory writes without angr.
    """

    name = "symbolic"

    def __init__(self, result: SymbolicProbeResult | None = None) -> None:
        self.result = result or SymbolicProbeResult(
            backend="symbolic",
            status="success",
            paths=[
                PathConstraint(
                    path_id=0,
                    reachable=True,
                    predicate_text=["argc > 1"],
                    block_trace=[0x401000, 0x401020, 0x401050],
                    hit_target=True,
                ),
                PathConstraint(
                    path_id=1,
                    reachable=True,
                    predicate_text=["argc <= 1"],
                    block_trace=[0x401000, 0x401020, 0x401030],
                    hit_target=False,
                ),
            ],
            memory_writes=[
                MemoryWriteObservation(concrete_address=0x404000, concrete_value=0x41, width_bits=8),
            ],
        )

    def can_run(self) -> bool:
        return True

    def run(self, probe: Any, binary_path: str | None = None) -> RunnerResult:
        runner = SymbolicRunner()
        request = runner._build_request(probe)
        return runner._to_runner_result(self.result, binary_path or "fake")
