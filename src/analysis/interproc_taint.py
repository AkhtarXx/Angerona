"""Inter-procedural taint tracking over the canonical SSA IR.

This module extends the intra-procedural :class:`TaintEngine` from
``src.analysis.canonical_ir`` across function boundaries using the
function-level call graph exposed by :class:`AnalysisGraph` (edges whose
``kind == "calls"``).

Research basis:

* Summary-based / flow-sensitive inter-procedural dataflow follows the
  classical Sharir-Pnueli functional approach and Reps-Horwitz-Sagiv (RHS '95)
  IFDS intuition: propagate facts from call sites into callee parameters and
  from callee return values back into callers, iterating to a fixpoint.
* Argument and return binding follows System V AMD64 / AArch64 / ARM AAPCS /
  MIPS calling conventions: values named ``arg0..argN``, ``a0..a3``,
  ``rdi/rsi/rdx/rcx/r8/r9``, ``x0..x7`` / ``w0..w7`` are treated as formal
  parameters; returns bind to ``rax/eax``, ``r0``, ``v0``, ``x0``/``w0``.
* The fixpoint is monotone over a finite taint lattice, so termination is
  guaranteed in theory; the engine still enforces a hard iteration cap
  (``4 * total_functions``) and raises :class:`InterprocTaintError` on
  non-convergence rather than hanging (fail-closed policy consistent with the
  rest of the codebase: malformed input yields ``[]``).

Stdlib only.
"""

from __future__ import annotations

from dataclasses import dataclass
from collections import deque
from typing import Any, Iterable

from src.analysis.canonical_ir import (
    CanonicalIR,
    TaintEngine,
)

__all__ = [
    "CallSiteInfo",
    "CallGraphIndex",
    "InterprocTaintEngine",
    "InterprocTaintFinding",
    "InterprocTaintError",
    "find_interproc_paths",
]

CALL_LIKE_OPCODES = frozenset({"CALL", "CALLIND", "BL", "BLX"})

# Formal-parameter naming conventions, most significant (arg index 0) first.
# System V AMD64 integer args, AArch64 x0..x7/w0..w7, ARM/MIPS a0..a3, plus
# generic arg0..argN used by the SSA converter / decompiler annotations.
_PARAMETER_NAME_ORDERS: tuple[tuple[str, ...], ...] = (
    ("arg0", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7"),
    ("rdi", "rsi", "rdx", "rcx", "r8", "r9"),
    ("a0", "a1", "a2", "a3"),
    ("x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7"),
    ("w0", "w1", "w2", "w3", "w4", "w5", "w6", "w7"),
)

# Return-register conventions: SysV AMD64, ARM/AArch64, MIPS v0.
_RETURN_NAMES = frozenset({"rax", "eax", "r0", "v0", "x0", "w0"})

_ITERATIONS_PER_FUNCTION = 4


class InterprocTaintError(RuntimeError):
    """Raised when the inter-procedural fixpoint fails to converge."""


@dataclass(frozen=True)
class CallSiteInfo:
    """A resolved call site connecting a caller operation to a callee."""

    caller_function_id: str
    callee_function_id: str
    callsite_operation_id: str
    actual_args: tuple[str, ...] = ()
    return_value: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "caller_function_id": self.caller_function_id,
            "callee_function_id": self.callee_function_id,
            "callsite_operation_id": self.callsite_operation_id,
            "actual_args": list(self.actual_args),
            "return_value": self.return_value,
        }


def _norm_callsite_address(address: Any) -> str:
    """Canonicalize an instruction address for call-site disambiguation.

    Graph-edge addresses and IR-operation addresses are both reduced to a
    lowercase ``0x..`` hex form so the two sides compare equal regardless of
    int-vs-str, case, or zero-padding differences.  Unparseable values are
    returned lower-cased as-is (best effort, never raises).
    """
    if address is None:
        return ""
    try:
        if isinstance(address, int):
            value = address
        else:
            text = str(address).strip()
            if text.lower().startswith("addr("):
                text = text[5:-1].strip()
            value = int(text, 0)
        return f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"
    except (ValueError, TypeError):
        return str(address).strip().lower()


class CallGraphIndex:
    """Function-level call graph derived from ``kind == "calls"`` edges.

    Accepts either an :class:`AnalysisGraph`-like object (anything exposing an
    ``edges`` iterable with ``.src`` / ``.dst`` / ``.kind``) or a plain mapping
    ``{caller_id: [callee_id, ...]}``.
    """

    def __init__(self, graph_or_callmap: Any) -> None:
        callees: dict[str, set[str]] = {}
        callers: dict[str, set[str]] = {}
        # Call-site (instruction) address -> callee id, per caller.  Populated
        # only when the source graph annotates ``calls`` edges with an
        # ``address``; plain call maps carry no address, so this stays empty and
        # call-site resolution falls back to positional pairing.
        self._callsites: dict[str, dict[str, str]] = {}
        try:
            triples = self._extract_triples(graph_or_callmap)
        except Exception:
            triples = []
        for caller, callee, address in triples:
            if not caller or not callee or caller == callee:
                callees.setdefault(caller, set())
                continue
            callees.setdefault(caller, set()).add(callee)
            callers.setdefault(callee, set()).add(caller)
            if address:
                self._callsites.setdefault(caller, {})[
                    _norm_callsite_address(address)
                ] = callee
        self._callees = {key: frozenset(value) for key, value in callees.items()}
        self._callers = {key: frozenset(value) for key, value in callers.items()}

    @staticmethod
    def _extract_triples(
        graph_or_callmap: Any,
    ) -> list[tuple[str, str, str | None]]:
        """Extract ``(caller, callee, callsite_address)`` triples.

        ``callsite_address`` is ``None`` for plain call maps (dicts) and for
        graph edges that do not carry an address annotation.
        """
        if graph_or_callmap is None:
            return []
        if isinstance(graph_or_callmap, dict):
            triples: list[tuple[str, str, str | None]] = []
            for caller, targets in graph_or_callmap.items():
                if targets is None:
                    continue
                if isinstance(targets, (str, bytes)):
                    triples.append((str(caller), str(targets), None))
                    continue
                for target in targets:
                    triples.append((str(caller), str(target), None))
            return triples
        edges = getattr(graph_or_callmap, "edges", None)
        if edges is None:
            return []
        triples = []
        for edge in edges:
            if getattr(edge, "kind", None) == "calls":
                src = getattr(edge, "src", None)
                dst = getattr(edge, "dst", None)
                if src is not None and dst is not None:
                    triples.append(
                        (str(src), str(dst), getattr(edge, "address", None))
                    )
        return triples

    def callees(self, function_id: str) -> tuple[str, ...]:
        """Return the functions directly called by ``function_id``."""
        return tuple(sorted(self._callees.get(function_id, ())))

    def callers(self, function_id: str) -> tuple[str, ...]:
        """Return the functions that directly call ``function_id``."""
        return tuple(sorted(self._callers.get(function_id, ())))

    def callee_for_callsite(self, function_id: str, address: Any) -> str | None:
        """Resolve a call-site address within ``function_id`` to its callee.

        Only call sites whose ``calls`` edge carried an ``address`` annotation
        are resolvable this way; plain call maps never annotate addresses, so
        this returns ``None`` for them and the caller falls back to positional
        pairing.  Addresses are compared in canonical ``0x..`` hex form.
        """
        by_address = self._callsites.get(function_id)
        if by_address is None or address is None:
            return None
        return by_address.get(_norm_callsite_address(address))

    def functions(self) -> tuple[str, ...]:
        """Return every function participating in the call graph."""
        return tuple(sorted(set(self._callees) | set(self._callers)))

    def topological(self) -> list[str]:
        """Kahn's algorithm with force-progress cycle breaking.

        Mirrors the cycle guard in ``spawn_plan.order_by_dependencies``: when
        no node has in-degree zero (a cycle), the lexicographically smallest
        remaining node is emitted anyway so the algorithm always terminates
        and returns an order covering every function.
        """
        nodes = set(self._callees) | set(self._callers)
        remaining = set(nodes)
        result: list[str] = []
        while remaining:
            zero = sorted(
                node for node in remaining if not self._callers.get(node, frozenset()) & remaining
            )
            if not zero:  # cycle guard: force-progress
                zero = [sorted(remaining)[0]]
            for node in zero:
                result.append(node)
                remaining.discard(node)
        return result

    def as_dict(self) -> dict[str, Any]:
        return {
            "functions": list(self.functions()),
            "edges": [
                {"caller": caller, "callee": callee}
                for caller in self.functions()
                for callee in self.callees(caller)
            ],
        }


@dataclass(frozen=True)
class InterprocTaintFinding:
    """A tainted sink reached through one or more function boundaries."""

    sink_function_id: str
    sink_operation: str
    tainted_inputs: tuple[str, ...]
    path: tuple[tuple[str, str], ...] = ()
    slice_operations: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "sink_function_id": self.sink_function_id,
            "sink_operation": self.sink_operation,
            "tainted_inputs": list(self.tainted_inputs),
            "path": [list(hop) for hop in self.path],
            "slice_operations": list(self.slice_operations),
        }




def _formal_parameters(ir: CanonicalIR, arity: int) -> list[str]:
    """Map actual-argument positions onto callee parameter value ids.

    Scans the callee IR for values whose *name* matches a known parameter
    convention (arg0..argN, a0..a3, rdi..r9, x0..x7, w0..w7) and returns the
    version-0 ids in convention order, truncated to ``arity``.
    """
    by_name: dict[str, list[str]] = {}
    for value_id, value in ir.values.items():
        name = (value.name or "").lower()
        version = name_version(value_id)
        if version == "0" or version.startswith("0:"):
            by_name.setdefault(name, []).append(value_id)
    ordered: list[str] = []
    for convention in _PARAMETER_NAME_ORDERS:
        if any(name in by_name for name in convention):
            for name in convention:
                ordered.extend(sorted(by_name.get(name, [])))
            if ordered:
                break
    if not ordered:
        # Fallback: generic argN naming regardless of version.
        for index in range(arity):
            name = f"arg{index}"
            candidates = sorted(
                value_id for value_id, value in ir.values.items() if (value.name or "").lower() == name
            )
            ordered.extend(candidates[:1])
    return ordered[:arity]


def _return_values(ir: CanonicalIR) -> set[str]:
    """Callee value ids matching returning-register conventions."""
    result = set()
    for value_id, value in ir.values.items():
        if (value.name or "").lower() in _RETURN_NAMES:
            result.add(value_id)
    return result


def name_version(value_id: str) -> str:
    """Suffix after the last ``@`` used for version-0 parameter detection."""
    return value_id.rsplit("@", 1)[-1]


class InterprocTaintEngine:
    """Whole-program explicit-flow taint over the function call graph.

    Runs the intra-procedural :class:`TaintEngine` per function and closes
    taint over call edges both ways (arguments forward, return values
    backward) until a bounded fixpoint is reached.
    """

    def analyze(
        self,
        graph_or_callmap: Any,
        irs_by_function: dict[str, CanonicalIR],
        *,
        sources: dict[str, Iterable[str]],
        sink_opcodes: Iterable[str] = ("CALLIND", "STORE", "BRANCHIND"),
        sanitizer_opcodes: Iterable[str] = (),
    ) -> list[InterprocTaintFinding]:
        try:
            return self._analyze_inner(
                graph_or_callmap,
                irs_by_function,
                sources=sources,
                sink_opcodes=sink_opcodes,
                sanitizer_opcodes=sanitizer_opcodes,
            )
        except InterprocTaintError:
            raise
        except Exception:
            return []

    # ------------------------------------------------------------ internals

    def _analyze_inner(
        self,
        graph_or_callmap: Any,
        irs_by_function: dict[str, CanonicalIR],
        *,
        sources: dict[str, Iterable[str]],
        sink_opcodes: Iterable[str],
        sanitizer_opcodes: Iterable[str],
    ) -> list[InterprocTaintFinding]:
        if not isinstance(irs_by_function, dict) or not irs_by_function:
            return []
        irs = {
            str(function_id): ir
            for function_id, ir in irs_by_function.items()
            if isinstance(ir, CanonicalIR)
        }
        if not irs:
            return []
        index = CallGraphIndex(graph_or_callmap)
        sinks = {opcode.upper() for opcode in sink_opcodes}
        sanitizers = {opcode.upper() for opcode in sanitizer_opcodes}
        per_fn_sources: dict[str, set[str]] = {
            function_id: set()
            for function_id in irs
        }
        for function_id, values in (sources or {}).items():
            key = str(function_id)
            if key in per_fn_sources and values is not None:
                per_fn_sources[key] = {str(value) for value in values}

        callsites = self._resolve_callsites(index, irs)
        total_functions = max(1, len(irs))
        max_iterations = _ITERATIONS_PER_FUNCTION * total_functions

        tainted: dict[str, set[str]] = {
            function_id: set(per_fn_sources[function_id]) for function_id in irs
        }
        engine = TaintEngine()

        iterations = 0
        changed = True
        while changed:
            iterations += 1
            if iterations > max_iterations:
                raise InterprocTaintError(
                    f"inter-procedural taint fixpoint did not converge within "
                    f"{max_iterations} iterations ({total_functions} functions)"
                )
            changed = False
            for function_id, ir in irs.items():
                before = len(tainted[function_id])
                self._propagate_intraprocedural(ir, tainted[function_id], sanitizers)
                if len(tainted[function_id]) != before:
                    changed = True
            for site in callsites:
                if site.caller_function_id not in irs or site.callee_function_id not in irs:
                    continue
                callee_ir = irs[site.callee_function_id]
                caller_taint = tainted[site.caller_function_id]
                callee_taint = tainted[site.callee_function_id]
                # Forward: tainted actuals -> callee formal parameters.
                tainted_actuals = [arg for arg in site.actual_args if arg in caller_taint]
                if tainted_actuals:
                    formals = _formal_parameters(callee_ir, len(site.actual_args))
                    for position, formal in enumerate(formals):
                        if position < len(site.actual_args) and site.actual_args[position] in caller_taint:
                            if formal not in callee_taint:
                                callee_taint.add(formal)
                                changed = True
                # Backward: tainted callee returns -> callsite return value.
                if site.return_value is not None and site.return_value not in caller_taint:
                    callee_returns = _return_values(callee_ir)
                    if callee_returns & callee_taint:
                        caller_taint.add(site.return_value)
                        changed = True

        findings: list[InterprocTaintFinding] = []
        for function_id, ir in sorted(irs.items()):
            intra_findings = engine.analyze(
                ir,
                sources=tainted[function_id],
                sink_opcodes=sinks,
                sanitizer_opcodes=sanitizers,
            )
            slice_prefix = f"{function_id}:"
            for intra in intra_findings:
                path = self._trace_path(
                    function_id, per_fn_sources, index, tainted, callsites
                )
                merged_slice = tuple(f"{slice_prefix}{op}" for op in intra.slice_operations)
                finding = InterprocTaintFinding(
                    sink_function_id=function_id,
                    sink_operation=intra.sink_operation,
                    tainted_inputs=tuple(intra.tainted_inputs),
                    path=path,
                    slice_operations=merged_slice,
                )
                if finding not in findings:
                    findings.append(finding)
        return findings

    @staticmethod
    def _propagate_intraprocedural(
        ir: CanonicalIR, tainted: set[str], sanitizers: set[str]
    ) -> None:
        """Close taint over one function's IR in place (explicit flows)."""
        ordered = [ir.operations[op_id] for block in ir.blocks.values() for op_id in block]
        changed = True
        guard = 0
        guard_limit = max(4, 2 * (len(ordered) + 1))
        while changed:
            guard += 1
            if guard > guard_limit:
                return
            changed = False
            for operation in ordered:
                if (
                    operation.output is not None
                    and operation.opcode not in sanitizers
                    and operation.output not in tainted
                    and any(value in tainted for value in operation.inputs)
                ):
                    tainted.add(operation.output)
                    changed = True

    def _resolve_callsites(
        self, index: CallGraphIndex, irs: dict[str, CanonicalIR]
    ) -> list[CallSiteInfo]:
        """Connect CALL-like operations to callees in topological order.

        Each call-like operation is bound to its callee by the call-site
        address annotated on the graph edge (when present), so argument
        binding stays correct even when a caller's source call order differs
        from the sorted-id ordering of its callee list.  Operations whose
        address is not annotated fall back to positional pairing against the
        remaining graph-ordered callees; extra operations or dangling graph
        edges are dropped silently (fail-closed).
        """
        sites: list[CallSiteInfo] = []
        order = index.topological()
        for caller in order:
            caller_ir = irs.get(caller)
            if caller_ir is None:
                continue
            call_ops = [
                operation
                for block in caller_ir.blocks.values()
                for op_id in block
                if (operation := caller_ir.operations[op_id]).opcode in CALL_LIKE_OPCODES
            ]
            callee_list = list(index.callees(caller))
            # Address-resolved bindings take priority so argument order cannot
            # be scrambled by the arbitrary sorted-id ordering of callee_list.
            by_operation: dict[str, str] = {}
            for operation in call_ops:
                callee = index.callee_for_callsite(caller, operation.address)
                if callee is not None and callee not in by_operation.values():
                    by_operation[operation.id] = callee
            remaining = [
                callee for callee in callee_list if callee not in by_operation.values()
            ]
            position = 0
            for operation in call_ops:
                callee = by_operation.get(operation.id)
                if callee is None:
                    if position >= len(remaining):
                        continue
                    callee = remaining[position]
                    position += 1
                if callee not in irs:
                    continue
                sites.append(
                    CallSiteInfo(
                        caller_function_id=caller,
                        callee_function_id=callee,
                        callsite_operation_id=operation.id,
                        actual_args=tuple(operation.inputs),
                        return_value=operation.output,
                    )
                )
        return sites

    def _trace_path(
        self,
        sink_function_id: str,
        per_fn_sources: dict[str, set[str]],
        index: CallGraphIndex,
        tainted: dict[str, set[str]],
        callsites: list[CallSiteInfo],
    ) -> tuple[tuple[str, str], ...]:
        """BFS from any function holding an initial source to the sink."""
        seeded = [
            function_id
            for function_id, values in per_fn_sources.items()
            if values and function_id in tainted
        ]
        if sink_function_id in seeded:
            return ()
        adjacency: dict[str, set[str]] = {}
        for site in callsites:
            adjacency.setdefault(site.caller_function_id, set()).add(site.callee_function_id)
        queue = deque((seed, ()) for seed in sorted(seeded))
        visited = set(seeded)
        while queue:
            node, path = queue.popleft()
            for callee in sorted(adjacency.get(node, ())):
                if callee in visited:
                    continue
                next_path = path + ((node, callee),)
                if callee == sink_function_id:
                    return next_path
                visited.add(callee)
                queue.append((callee, next_path))
        return ()


def find_interproc_paths(
    finding: InterprocTaintFinding, call_graph_index: CallGraphIndex
) -> list[CallSiteInfo]:
    """Return the ordered source -> sink call chain for reporting.

    Reconstructs :class:`CallSiteInfo` hops along ``finding.path``.  When the
    finding carries no path (intra-function flow only) this returns ``[]``.
    """
    if not finding.path:
        return []
    chain: list[CallSiteInfo] = []
    for caller, callee in finding.path:
        chain.append(
            CallSiteInfo(
                caller_function_id=caller,
                callee_function_id=callee,
                callsite_operation_id="",
                actual_args=(),
                return_value=None,
            )
        )
    return chain
