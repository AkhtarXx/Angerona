"""Vulnerability sink hunter.

Chapter 22 of the IDA Pro Book emphasizes that finding dangerous functions
(strcpy, memcpy, sprintf, etc.) is easy, but proving exploitability requires
tracking how attacker-controllable data reaches them. This module provides:

  1. A configurable sink catalog (dangerous functions and behavioral patterns).
  2. Discovery by function name or import name.
  3. Call-chain reachability from program entrypoints / exports.
  4. Exploit-geometry helpers: stack-buffer sizes, buffer-to-return distances
     (if IDA/Ghidra frames are available), and format-string offsets.

The module works on the engine-agnostic XrefGraph. False-positive notes live in
the result objects and should be consumed by downstream agents.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from ..analysis.xref_graph import XrefGraph


# Default dangerous sink catalog from Chapter 22 + modern extensions.
_DEFAULT_SINKS = {
    "memory_copy": {
        "names": [
            "strcpy", "strncpy", "strcat", "strncat", "strlcpy", "strlcat",
            "wcscpy", "wcsncpy", "memcpy", "memmove", "bcopy",
            "gets",
            "recv", "recvfrom",
        ],
        "description": "Potential memory corruption / overflow",
        "severity": "HIGH",
    },
    "bounded_memory_copy": {
        "names": [
            "snprintf", "vsnprintf", "strncpy", "strncat", "fgets", "fread",
        ],
        "description": "Bounded copy; still vulnerable if size miscalculated",
        "severity": "MEDIUM",
    },
    "allocation": {
        "names": [
            "malloc", "calloc", "realloc", "free", "VirtualAlloc",
            "VirtualProtect", "HeapAlloc", "HeapFree",
        ],
        "description": "Heap allocator / double-free / UAF signal",
        "severity": "MEDIUM",
    },
    "format_string": {
        "names": [
            "printf", "fprintf", "sprintf", "snprintf", "vsprintf",
            "vfprintf", "vprintf", "wprintf", "__printf_chk", "__fprintf_chk",
        ],
        "description": "Potential format-string vulnerability",
        "severity": "HIGH",
    },
    "anti_analysis": {
        "names": [
            "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
            "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "RtlGetTickCount",
            "NtSetInformationThread",
        ],
        "description": "Anti-analysis / evasion indicator",
        "severity": "INFO",
    },
    "exec_payload": {
        "names": [
            "system", "popen", "ShellExecuteA", "ShellExecuteW",
            "CreateProcessA", "CreateProcessW", "WinExec", "LoadLibraryA", "LoadLibraryW",
            "GetProcAddress", "VirtualProtect", "VirtualAlloc", "WriteProcessMemory",
            "CreateRemoteThread",
        ],
        "description": "Code execution / injection API",
        "severity": "HIGH",
    },
    "crypto_generic": {
        "names": [
            "CryptEncrypt", "CryptDecrypt", "CryptHashData", "CryptCreateHash",
            "EVP_EncryptInit", "EVP_DecryptInit", "AES_set_encrypt_key",
            "RC4_set_key", "SHA1_Init", "MD5_Init", "RSA_public_encrypt",
        ],
        "description": "Cryptographic operation indicator",
        "severity": "INFO",
    },
}

_SOLANA_SINKS = {
    "solana_cpi": {
        "names": [
            "sol_invoke",
            "sol_invoke_",
            "sol_invoke_c",
            "sol_invoke_signed",
            "sol_invoke_signed_c",
            "sol_invoke_signed_rust",
        ],
        "description": "Solana cross-program invocation boundary; validate account authority, signer, owner, and writable flags",
        "severity": "HIGH",
    },
    "solana_pda_derivation": {
        "names": [
            "sol_create_program_address",
            "sol_try_find_program_address",
        ],
        "description": "Solana PDA derivation boundary; validate seed control, bump handling, and authority binding",
        "severity": "MEDIUM",
    },
    "solana_memory_helper": {
        "names": [
            "sol_memcpy_",
            "sol_memmove_",
            "sol_memcmp_",
            "sol_memset_",
        ],
        "description": "Solana memory helper; inspect size derivation and account-data bounds",
        "severity": "MEDIUM",
    },
    "solana_abort_or_panic": {
        "names": [
            "abort",
            "sol_panic_",
            "sol_log_",
            "sol_log_64_",
        ],
        "description": "Solana diagnostic/abort boundary; useful for error-path and invariant mapping",
        "severity": "INFO",
    },
}


@dataclass
class SinkMatch:
    node_id: str
    name: str
    category: str
    severity: str
    description: str
    source_distance: int | None = None
    shortest_path: list[str] | None = None
    semantic_source_distance: int | None = None
    semantic_shortest_path: list[str] | None = None
    reachable: bool = False
    evidence: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "source_distance": self.source_distance,
            "shortest_path": self.shortest_path,
            "semantic_source_distance": self.semantic_source_distance,
            "semantic_shortest_path": self.semantic_shortest_path,
            "reachable": self.reachable,
            "evidence": self.evidence or {},
        }


class SinkHunter:
    """Find dangerous sinks and their call-chain context in an XrefGraph."""

    def __init__(self, graph: XrefGraph,
                 catalog: dict[str, dict] | None = None,
                 source_node_ids: list[str] | None = None) -> None:
        self.graph = graph
        self.catalog = catalog or self._default_catalog_for_graph(graph)
        self.source_evidence: dict[str, str] = {}
        if source_node_ids is None:
            self.source_node_ids = self._default_sources()
        else:
            self.source_node_ids = list(dict.fromkeys(
                node_id for node_id in source_node_ids if node_id
            ))
            self.source_evidence = {
                node_id: "caller_supplied"
                for node_id in self.source_node_ids
            }

    @staticmethod
    def _default_catalog_for_graph(graph: XrefGraph) -> dict[str, dict]:
        catalog = dict(_DEFAULT_SINKS)
        metadata_text = " ".join(
            str(value).lower()
            for value in (graph.metadata or {}).values()
            if not isinstance(value, (dict, list, tuple, set))
        )
        if any(token in metadata_text for token in ("solana", "sbf", "ebpf", "ebpfsol")):
            catalog.update(_SOLANA_SINKS)
        return catalog

    def _default_sources(self) -> list[str]:
        """Resolve explicit and inferred callable security boundaries."""
        sources: list[str] = []

        def add_source(node_id: str | None, reason: str) -> None:
            if not node_id or node_id not in self.graph.g:
                return
            if node_id not in sources:
                sources.append(node_id)
                self.source_evidence[node_id] = reason

        entry_names = {
            "entry", "_start", "start", "main", "wmain", "winmain",
            "dllmain", "driverentry",
        }

        entry = str(self.graph.metadata.get("entry_point") or "")
        if entry:
            add_source(
                self.graph.function_by_address(entry),
                "metadata_entry_point",
            )

        callable_exports: list[tuple[str, str]] = []
        for n, d in self.graph.g.nodes(data=True):
            if d.get("kind") != "export":
                continue
            for target in self.graph.g.successors(n):
                edge = self.graph.g.edges[n, target]
                if (
                    edge.get("kind") != "resolves"
                    or self.graph.g.nodes[target].get("kind") != "function"
                    or self.graph.is_library(target)
                ):
                    continue
                export_name = str(d.get("name") or "").lstrip(".").lower()
                target_name = str(
                    self.graph.g.nodes[target].get("name") or ""
                ).lstrip(".").lower()
                reason = (
                    "entry_export"
                    if export_name in entry_names or target_name in entry_names
                    else "callable_export"
                )
                callable_exports.append((target, reason))

        # Keep all genuine callable boundaries. Runtime-only exports do not
        # suppress the fallback because they were filtered above.
        for target, reason in sorted(
            callable_exports,
            key=lambda item: (item[1] != "entry_export", item[0]),
        ):
            add_source(target, reason)

        # Roots are deliberately a fallback. Treating every orphan fragment as
        # an entry source makes disconnected sinks appear reachable.
        if sources:
            return sources
        for n in self.graph.function_nodes():
            call_predecessors = [
                pred for pred in self.graph.g.predecessors(n)
                if self.graph.g.edges[pred, n].get("kind") == "calls"
            ]
            if call_predecessors:
                continue
            props = self.graph.g.nodes[n].get("properties") or {}
            memory_block = str(props.get("memory_block") or "").lower()
            inferred_callsite = props.get("inferred_from") == "orphan_code_xref"
            internal_code = (
                not bool(props.get("is_external"))
                and memory_block in {".text", "text", "code", "__text"}
            )
            if not inferred_callsite and (
                internal_code or not self.graph.is_library(n)
            ):
                add_source(n, "fallback_call_root")
        return sources

    def _normalize_name(self, name: str | None) -> str:
        if not name:
            return ""
        # Strip common decoration and case-fold.
        name = name.strip()
        name = name.split("@@", 1)[0]
        name = name[1:] if name.startswith(".") else name
        name = re.sub(r"^__imp_", "", name, flags=re.IGNORECASE)
        name = re.sub(r"^(?:j_|thunk_|plt_|sym\.imp\.|imp\.)", "", name, flags=re.IGNORECASE)
        name = re.sub(r"^\w+:\s*", "", name)  # namespace prefixes
        name = re.sub(r"\s+\(.*$", "", name)    # signature trailers
        return name.lower()

    def _is_sink_name(self, name: str) -> tuple[str, dict] | None:
        norm = self._normalize_name(name)
        if not norm:
            return None
        # Whole-name or suffix-segment matching. Avoids flagging long strings
        # containing embedded substrings (e.g. panic messages mentioning "memcpy").
        for category, spec in self.catalog.items():
            for sink in spec.get("names", []):
                sink_key = sink.lower()
                if sink_key == norm:
                    return category, spec
                # Match well-known library suffixes such as "_chk" variants or plt stubs.
                suffixes = ("", "@plt", "_chk", "_nse", "_or_die")
                for suffix in suffixes:
                    if norm == (sink_key + suffix):
                        return category, spec
        return None

    # ---------------------------------------------------------------- find

    def find_sinks(self) -> list[SinkMatch]:
        """Find logical sinks, retaining engine aliases as evidence."""
        grouped: dict[tuple[str, str], SinkMatch] = {}

        allowed_kinds = {"function", "import", "export", "symbol"}
        for n, d in self.graph.g.nodes(data=True):
            kind = d.get("kind")
            if kind not in allowed_kinds:
                continue
            name = d.get("name") or ""
            hit = self._is_sink_name(name)
            if not hit:
                continue
            category, spec = hit
            logical_name = self._normalize_name(name)
            for suffix in ("_ptr", "_got", "_iat"):
                if logical_name.endswith(suffix):
                    logical_name = logical_name[:-len(suffix)]
                    break
            key = (category, logical_name)
            if key in grouped:
                evidence = grouped[key].evidence or {}
                evidence.setdefault("alias_node_ids", []).append(n)
                evidence.setdefault("alias_kinds", []).append(kind)
                grouped[key].evidence = evidence
                continue
            grouped[key] = SinkMatch(
                node_id=n,
                name=name,
                category=category,
                severity=spec.get("severity", "MEDIUM"),
                description=spec.get("description", ""),
                evidence={"alias_node_ids": [n], "alias_kinds": [kind]},
            )
        return list(grouped.values())

    def find_sinks_by_regex(self, pattern: str) -> list[SinkMatch]:
        """Find sink nodes by a user-supplied regex over names."""
        rx = re.compile(pattern, re.IGNORECASE)
        matches: list[SinkMatch] = []
        for n, d in self.graph.g.nodes(data=True):
            name = d.get("name") or ""
            if rx.search(name):
                matches.append(SinkMatch(
                    node_id=n, name=name, category="regex", severity="MEDIUM",
                    description=f"Matched pattern {pattern!r}",
                ))
        return matches

    # ---------------------------------------------------------------- reachability

    def with_reachability(self, matches: list[SinkMatch],
                          max_depth: int = 16) -> list[SinkMatch]:
        """Augment sink matches with source reachability and shortest paths."""
        candidate_ids_by_match: dict[int, list[str]] = {}
        all_candidate_ids: set[str] = set()
        for m in matches:
            aliases = list((m.evidence or {}).get("alias_node_ids") or [m.node_id])
            boundary_ids = [
                node_id for node_id in aliases
                if self._is_callable_sink_boundary(node_id)
            ]
            candidate_ids = boundary_ids or aliases
            candidate_ids_by_match[id(m)] = candidate_ids
            all_candidate_ids.update(candidate_ids)

        paths_by_source = {
            src: self.graph.shortest_paths_from(
                src,
                all_candidate_ids,
                max_depth=max_depth,
            )
            for src in self.source_node_ids
            if src in self.graph.g
        }

        for m in matches:
            best_distance: int | None = None
            best_path: list[str] | None = None
            best_node_id = m.node_id
            best_source_id: str | None = None
            aliases = list((m.evidence or {}).get("alias_node_ids") or [m.node_id])
            boundary_ids = [
                node_id for node_id in aliases
                if self._is_callable_sink_boundary(node_id)
            ]
            # Internal wrappers can inherit an import's name after stripping.
            # Prefer the actual PLT/IAT/external callable boundary so a wrapper
            # cannot satisfy reachability as a misleading zero-hop alias.
            candidate_ids = candidate_ids_by_match.get(id(m), boundary_ids or aliases)
            for src in self.source_node_ids:
                source_paths = paths_by_source.get(src) or {}
                for candidate_id in candidate_ids:
                    path = source_paths.get(candidate_id)
                    if path is not None:
                        dist = len(path) - 1
                        if best_distance is None or dist < best_distance:
                            best_distance = dist
                            best_path = path
                            best_node_id = candidate_id
                            best_source_id = src
            if best_distance is not None:
                m.node_id = best_node_id
                m.reachable = True
                m.source_distance = best_distance
                m.shortest_path = best_path
                evidence = m.evidence or {}
                assert best_source_id is not None
                semantic_path = self.graph.semantic_shortest_path(
                    best_source_id,
                    best_node_id,
                    max_depth=max_depth,
                )
                if semantic_path is not None:
                    m.semantic_source_distance = int(semantic_path["distance"])
                    m.semantic_shortest_path = list(semantic_path["path"])
                    evidence["semantic_collapsed_nodes"] = list(
                        semantic_path["collapsed_nodes"]
                    )
                    evidence["semantic_raw_path"] = list(semantic_path["raw_path"])
                source_props = (
                    self.graph.g.nodes[best_source_id].get("properties") or {}
                    if best_source_id in self.graph.g else {}
                )
                evidence.update({
                    "reachability_source_node_id": best_source_id,
                    "reachability_source_provenance": self.source_evidence.get(
                        best_source_id, "unknown"
                    ),
                    "reachability_source_inferred": (
                        source_props.get("inferred_from") == "orphan_code_xref"
                    ),
                    "reachability_target_node_id": best_node_id,
                    "reachability_target_is_boundary": (
                        best_node_id in boundary_ids
                    ),
                })
                m.evidence = evidence
            else:
                m.reachable = False
        return matches

    def _is_callable_sink_boundary(self, node_id: str) -> bool:
        """Return whether an alias is a real callable linkage/API boundary."""
        if node_id not in self.graph.g:
            return False
        node = self.graph.g.nodes[node_id]
        if node.get("kind") != "function":
            return False
        props = node.get("properties") or {}
        memory_block = str(props.get("memory_block") or "").lower()
        if bool(props.get("is_external")):
            return True
        if memory_block in {
            ".plt", ".plt.sec", ".plt.got", ".idata", "extern", "external",
        }:
            return True
        namespace = str(props.get("namespace") or "").lower()
        return "<external>" in namespace and memory_block not in {
            ".text", "text", "code", "__text",
        }

    def reachable_sinks_only(self) -> list[SinkMatch]:
        return [m for m in self.with_reachability(self.find_sinks()) if m.reachable]

    # ---------------------------------------------------------------- exploit geometry

    def compute_stack_buffer_offsets(self, func_node_id: str,
                                     threshold_bytes: int = 32) -> list[dict]:
        """Use frame properties when available to flag large stack buffers.

        This is the book's `findStackBuffers` heuristic, ported to the graph node
        properties. Ghidra/IDA export may include stack frame layouts; if not,
        the result is empty.
        """
        if func_node_id not in self.graph.g:
            return []
        props = self.graph.g.nodes[func_node_id].get("properties", {})
        frames = props.get("frame") or props.get("local_vars") or []
        if not frames:
            return []
        candidates = []
        prev = None
        for entry in frames:
            offs = entry.get("offset")
            size = entry.get("size") or 0
            name = entry.get("name", "")
            if prev is not None and isinstance(offs, int) and isinstance(prev["offset"], int):
                delta = offs - prev["offset"]
                if delta >= threshold_bytes:
                    candidates.append({
                        "function": self.graph.node_name(func_node_id),
                        "buffer": prev["name"],
                        "offset": prev["offset"],
                        "bytes_to_next": delta,
                        "next_var": name,
                        "risk": "large inline buffer",
                    })
            prev = entry
        return candidates

    # ---------------------------------------------------------------- result helpers

    def run(self, max_depth: int = 16) -> dict[str, Any]:
        """Full sink-hunter pass: find, classify, and reachability-check."""
        sinks = self.find_sinks()
        sinks = self.with_reachability(sinks, max_depth=max_depth)
        by_category: dict[str, list[dict]] = {}
        reachable_count = 0
        severity_counts: dict[str, int] = {}
        for m in sinks:
            by_category.setdefault(m.category, []).append(m.as_dict())
            reachable_count += 1 if m.reachable else 0
            severity_counts[m.severity] = severity_counts.get(m.severity, 0) + 1

        high_risk_paths = [
            m.as_dict() for m in sinks
            if m.reachable and m.severity in ("HIGH", "CRITICAL")
        ]

        return {
            "total_sinks": len(sinks),
            "reachable_sinks": reachable_count,
            "severity_counts": severity_counts,
            "categories": by_category,
            "high_risk_reachable": high_risk_paths,
            "source_nodes": self.source_node_ids,
            "source_evidence": [
                {
                    "node_id": node_id,
                    "provenance": self.source_evidence.get(node_id, "unknown"),
                }
                for node_id in self.source_node_ids
            ],
            "catalog": list(self.catalog.keys()),
        }

    def save_report(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.run(), indent=2, default=str), encoding="utf-8")


# Convenience helpers

def quick_sink_scan(graph: XrefGraph) -> dict[str, Any]:
    return SinkHunter(graph).run()


def sink_catalog() -> dict[str, dict]:
    """Return a copy of the built-in catalog for callers to extend."""
    return json.loads(json.dumps(_DEFAULT_SINKS))
