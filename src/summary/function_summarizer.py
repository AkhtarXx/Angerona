"""Generate natural-language function summaries from an analysis graph."""

from __future__ import annotations

from typing import Any

from src.models.analysis_graph import AnalysisGraph, Node
from src.summary.models import FunctionSummary


# Imports that are strong signals of risky behavior. Kept small and evidence-based.
_RISKY_IMPORTS = {
    "system", "exec", "popen", "_system", "CreateProcess", "WinExec", "ShellExecute",
    "memcpy", "strcpy", "strcat", "gets", "sprintf", "scanf",
    "VirtualProtect", "mprotect", "VirtualAlloc", "malloc", "free",
}

_CRYPTO_IMPORTS = {"AES", "DES", "RC4", "RSA", "encrypt", "decrypt", "crypt"}


class FunctionSummarizer:
    """Summarize function purpose, I/O, and risk using graph evidence."""

    def __init__(self, graph: AnalysisGraph) -> None:
        self.graph = graph

    def summarize_all(self, top_n: int | None = None) -> list[FunctionSummary]:
        """Summarize all functions.  Optionally limit to the top N by call count."""
        fns = [n for n in self.graph.nodes if n.kind == "function"]
        if top_n:
            fns = sorted(fns, key=lambda n: self._call_count(n.id), reverse=True)[:top_n]
        return [self.summarize(fn.id) for fn in fns]

    def summarize(self, function_id: str) -> FunctionSummary:
        fn = self._find_function(function_id)
        if fn is None:
            return FunctionSummary(
                function_id=function_id,
                name=function_id,
                purpose=f"function not found: {function_id}",
                confidence="low",
            )

        calls = self._callees(fn.id)
        strings = self._strings(fn.id)
        writes = self._writes(fn.id)

        purpose = self._purpose_from_calls_and_strings(fn, calls, strings)
        io_summary = self._io_from_signature_and_writes(fn, writes)
        risks = self._risk_flags(fn, calls, strings, writes)

        evidence = sum([
            bool(calls),
            bool(strings),
            bool(writes),
            bool(fn.properties.get("signature")),
            len(self._blocks(fn.id)) > 0,
        ])
        confidence = "high" if evidence >= 4 else ("medium" if evidence >= 2 else "low")

        return FunctionSummary(
            function_id=fn.id,
            address=fn.address,
            name=fn.name,
            purpose=purpose,
            io_summary=io_summary,
            risk_flags=risks,
            confidence=confidence,
        )

    def _find_function(self, function_id: str) -> Node | None:
        node = self.graph.get_node(function_id)
        if node is not None and node.kind == "function":
            return node
        for n in self.graph.nodes:
            if n.kind == "function" and (n.id == function_id or n.name == function_id or n.address == function_id):
                return n
        return None

    def _blocks(self, fn_id: str) -> list[Node]:
        out = []
        for edge in self.graph.edges:
            if edge.kind == "contains" and edge.src == fn_id:
                blk = self.graph.get_node(edge.dst)
                if blk and blk.kind == "block":
                    out.append(blk)
        return out

    def _callees(self, fn_id: str) -> list[str]:
        names: list[str] = []
        for edge in self.graph.edges:
            if edge.src == fn_id and edge.kind == "calls":
                callee = self.graph.get_node(edge.dst)
                if callee:
                    names.append(callee.name or callee.id)
        # Also include calls from instructions inside the function.
        for block in self._blocks(fn_id):
            for edge in self.graph.edges:
                if edge.src == block.id and edge.kind == "calls":
                    callee = self.graph.get_node(edge.dst)
                    if callee:
                        names.append(callee.name or callee.id)
        return sorted(set(names))

    def _strings(self, fn_id: str) -> list[str]:
        result: list[str] = []
        for block in self._blocks(fn_id):
            for insn in self._instructions(block.id):
                for edge in self.graph.edges:
                    if edge.src == insn.id and edge.kind in {"data_read", "references"}:
                        ref = self.graph.get_node(edge.dst)
                        if ref and ref.kind == "string":
                            result.append(ref.name or ref.properties.get("value") or ref.id)
        return sorted(set(result))

    def _instructions(self, block_id: str) -> list[Node]:
        insns: list[Node] = []
        for edge in self.graph.edges:
            if edge.kind == "contains" and edge.src == block_id:
                insn = self.graph.get_node(edge.dst)
                if insn and insn.kind == "instruction":
                    insns.append(insn)
        return insns

    def _writes(self, fn_id: str) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for block in self._blocks(fn_id):
            for insn in self._instructions(block.id):
                for edge in self.graph.edges:
                    if edge.src == insn.id and edge.kind == "data_write":
                        props = dict(edge.properties)
                        props["address"] = edge.address
                        out.append(props)
        return out

    def _call_count(self, fn_id: str) -> int:
        return sum(1 for edge in self.graph.edges if edge.dst == fn_id and edge.kind == "calls")

    def _purpose_from_calls_and_strings(self, fn: Node, calls: list[str], strings: list[str]) -> str:
        tokens: list[str] = []
        if strings:
            token = f"references strings: {', '.join(strings[:3])}"
            if len(strings) > 3:
                token += f" (+{len(strings) - 3} more)"
            tokens.append(token)
        if calls:
            tokens.append(f"calls {len(calls)} function(s): {', '.join(calls[:5])}")
        if self._is_crypto_heavy(calls, strings):
            tokens.append("suspected cryptography/auxiliary transform")
        if not tokens:
            tokens.append("no clear purpose recovered from static evidence")
        desc = "; ".join(tokens)
        return f"{fn.name or fn.id} likely {desc}."

    def _io_from_signature_and_writes(self, fn: Node, writes: list[dict[str, Any]]) -> str:
        sig = fn.properties.get("signature")
        if sig:
            return f"signature {sig}; observed {len(writes)} memory write(s)"
        return f"observed {len(writes)} memory write(s); arguments unknown"

    def _risk_flags(self, fn: Node, calls: list[str], strings: list[str], writes: list[dict[str, Any]]) -> list[str]:
        flags: list[str] = []
        call_set = {c.lower() for c in calls}
        if call_set & {r.lower() for r in _RISKY_IMPORTS}:
            flags.append("uses-known-risky-api")
        if call_set & {c.lower() for c in _CRYPTO_IMPORTS}:
            flags.append("cryptographic-operations")
        if len(writes) >= 5:
            flags.append("heavy-memory-writes")
        if any("exec" in s or "system" in s for s in strings):
            flags.append("suspicious-string-reference")
        return flags

    def _is_crypto_heavy(self, calls: list[str], strings: list[str]) -> bool:
        call_set = {c.lower() for c in calls}
        return bool(call_set & {c.lower() for c in _CRYPTO_IMPORTS})
