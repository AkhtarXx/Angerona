"""Hash-bound DEX call graph and JNI/native edge reconciliation."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from .jni_registration_resolver import resolve_jni_registration
from .smali_reconstruction import _parse_smali


SCHEMA = "angerona/cross-layer-graph/v2"
WORK_SCHEMA = "angerona/cross-layer-work-unit/v2"
_INVOKE_RE = re.compile(r"\binvoke-[^\s]+\s+\{[^}]*\},\s*(L[^;]+;->[^(\s]+\([^\s]+)")
_CONST_STRING_RE = re.compile(r'^const-string(?:/jumbo)?\s+([vp]\d+),\s+"(.*)"$')
_LOAD_LIBRARY_RE = re.compile(r"Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V")
_DYNAMIC_APIS = {
    "Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;",
    "Ljava/lang/ClassLoader;->loadClass(Ljava/lang/String;)Ljava/lang/Class;",
    "Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;",
    "Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;",
}


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with tmp.open("wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
        fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    finally:
        tmp.unlink(missing_ok=True)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _method_index(dex_root: Path) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    by_qualified: dict[str, dict[str, Any]] = {}
    by_id: dict[str, dict[str, Any]] = {}
    for path in sorted(dex_root.glob("dex/*/methods/*.json")):
        try:
            row = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        if not isinstance(row, dict) or row.get("schema") != "angerona/dex-method-receipt/v2":
            continue
        enriched = {**row, "receipt_path": str(path), "receipt_sha256": _sha256_path(path)}
        by_qualified[str(row["qualified_name"])] = enriched
        by_id[str(row["method_id"])] = enriched
    return by_qualified, by_id


def _jni_encode(value: str) -> str:
    result = []
    for char in value:
        if char.isascii() and char.isalnum():
            result.append(char)
        elif char == "/":
            result.append("_")
        elif char == "_":
            result.append("_1")
        elif char == ";":
            result.append("_2")
        elif char == "[":
            result.append("_3")
        else:
            result.append(f"_0{ord(char):04x}")
    return "".join(result)


def _expected_jni_symbols(method: dict[str, Any]) -> tuple[str, str]:
    class_name = str(method["class_descriptor"])[1:-1]
    short = f"Java_{_jni_encode(class_name)}_{_jni_encode(str(method['name']))}"
    params = str(method["prototype"])[1:str(method["prototype"]).index(")")]
    return short, short + "__" + _jni_encode(params)


def _native_inventory(
    audit_root: Path,
    cache_root: Path,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, dict[str, Any]]]]:
    target_paths: dict[str, Path] = {}
    for path in sorted((audit_root / "targets").rglob("*")):
        if path.is_file():
            target_paths.setdefault(_sha256_path(path), path)
    function_index: dict[str, dict[str, dict[str, Any]]] = {}
    for analysis_path in sorted(audit_root.glob("ghidra-results/*/*/code/analysis.json")):
        try:
            analysis = json.loads(analysis_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            continue
        target_sha = str((analysis.get("metadata") or {}).get("sha256") or "").lower()
        if target_sha not in target_paths:
            continue
        analysis_sha = _sha256_path(analysis_path)
        names: dict[str, dict[str, Any]] = {}
        for function in analysis.get("functions") or []:
            if not isinstance(function, dict):
                continue
            names[str(function.get("name") or "")] = {
                "target_sha256": target_sha,
                "target_path": str(target_paths[target_sha]),
                "entry": str(function.get("entry") or ""),
                "name": str(function.get("name") or ""),
                "function_id": f"elf:{target_sha}:{str(function.get('entry') or '')}",
                "analysis_path": str(analysis_path),
                "analysis_sha256": analysis_sha,
            }
        function_index[target_sha] = names

    libraries: list[dict[str, Any]] = []
    for target_sha, path in sorted(target_paths.items()):
        checkpoint_path = cache_root / f"{target_sha}.json"
        if checkpoint_path.is_file():
            try:
                cached = json.loads(checkpoint_path.read_text(encoding="utf-8"))
            except (OSError, ValueError, TypeError):
                cached = None
            if (isinstance(cached, dict)
                    and cached.get("schema") == "angerona/native-registration-checkpoint/v2"
                    and cached.get("target_sha256") == target_sha):
                libraries.append(cached["result"])
                continue
        try:
            registration = resolve_jni_registration(path.read_bytes())
        except (OSError, ValueError, TypeError):
            continue
        dynamic = []
        for row in registration.dynamically_registered:
            dynamic.append({
                "name": str(row.java_name),
                "signature": str(row.signature),
                "function_address": int(row.fn_addr),
            })
        library = {
            "target_sha256": target_sha,
            "target_path": str(path),
            "statically_named": list(registration.statically_named),
            "dynamically_registered": dynamic,
            "jni_onload_present": bool(registration.jni_onload_present),
            "registernatives_imported": bool(registration.registernatives_imported),
            "registration_status": str(registration.status),
        }
        libraries.append(library)
        _atomic(checkpoint_path, json.dumps({
            "schema": "angerona/native-registration-checkpoint/v2",
            "target_sha256": target_sha,
            "target_bytes": path.stat().st_size,
            "result": library,
        }, indent=2, sort_keys=True).encode() + b"\n")
    return libraries, function_index


def _edge_id(kind: str, source: str, target: str, evidence: str) -> str:
    return hashlib.sha256(f"{kind}\0{source}\0{target}\0{evidence}".encode()).hexdigest()


def build_cross_layer_graph(
    smali_root: str | Path,
    dex_receipt_root: str | Path,
    audit_root: str | Path,
    output_dir: str | Path,
) -> dict[str, Any]:
    smali = Path(smali_root).resolve()
    dex_root = Path(dex_receipt_root).resolve()
    audit = Path(audit_root).resolve()
    output = Path(output_dir).resolve()
    methods, _methods_by_id = _method_index(dex_root)
    libraries, native_functions = _native_inventory(audit, output / "native-registration-cache")
    edges: list[dict[str, Any]] = []
    work_units: list[dict[str, Any]] = []
    native_declarations: list[dict[str, Any]] = []
    load_libraries: list[dict[str, Any]] = []
    invoke_sites = 0

    for path in sorted(smali.rglob("*.smali")):
        class_descriptor, parsed = _parse_smali(path)
        if not class_descriptor:
            continue
        source_sha = _sha256_path(path)
        for parsed_method in parsed:
            qualified = f"{class_descriptor}->{parsed_method['name']}{parsed_method['prototype']}"
            source = methods.get(qualified)
            if source is None:
                continue
            header = parsed_method["body"].splitlines()[0] if parsed_method["body"] else ""
            if " native " in f" {header} ":
                native_declarations.append({
                    "method_id": source["method_id"],
                    "qualified_name": qualified,
                    "class_descriptor": source["class_descriptor"],
                    "name": source["name"],
                    "prototype": source["prototype"],
                    "smali_sha256": source_sha,
                    "implementations": [],
                    "disposition": "unresolved",
                })
            registers: dict[str, str] = {}
            for line_number, line in enumerate(parsed_method["body"].splitlines(), parsed_method["start_line"]):
                token = line.strip()
                const = _CONST_STRING_RE.match(token)
                if const:
                    registers[const.group(1)] = const.group(2)
                invoke = _INVOKE_RE.search(token)
                if not invoke:
                    continue
                invoke_sites += 1
                target_qualified = invoke.group(1)
                target = methods.get(target_qualified)
                disposition = "resolved-internal" if target is not None else "terminal-external-reference"
                edge = {
                    "edge_id": _edge_id("dex-invoke", source["method_id"], target_qualified, f"{source_sha}:{line_number}"),
                    "kind": "dex-invoke",
                    "source_method_id": source["method_id"],
                    "source_qualified_name": qualified,
                    "target_method_id": target["method_id"] if target else None,
                    "target_qualified_name": target_qualified,
                    "disposition": disposition,
                    "evidence": {"path": str(path), "sha256": source_sha, "line": line_number},
                }
                edges.append(edge)
                if target_qualified in _DYNAMIC_APIS:
                    edge["disposition"] = "dynamic-target-unresolved"
                    work_units.append({
                        "schema": WORK_SCHEMA,
                        "unit_id": _edge_id("dynamic-dex-target", source["method_id"], target_qualified, edge["edge_id"]),
                        "unit_kind": "dynamic_dex_target_resolution",
                        "state": "pending",
                        "edge_id": edge["edge_id"],
                        "unresolved_reasons": ["reflection-or-runtime-class-loading"],
                    })
                if _LOAD_LIBRARY_RE.search(target_qualified):
                    register_match = re.search(r"\{\s*([vp]\d+)", token)
                    library_name = registers.get(register_match.group(1)) if register_match else None
                    load_libraries.append({
                        "source_method_id": source["method_id"],
                        "library_name": library_name,
                        "resolved_literal": library_name is not None,
                        "evidence": edge["evidence"],
                    })

    static_exports: dict[str, list[dict[str, Any]]] = {}
    dynamic_exports: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for library in libraries:
        target_sha = library["target_sha256"]
        for symbol in library["statically_named"]:
            function = native_functions.get(target_sha, {}).get(symbol)
            static_exports.setdefault(symbol, []).append(function or {
                "target_sha256": target_sha,
                "target_path": library["target_path"],
                "entry": "",
                "name": symbol,
                "function_id": None,
            })
        for dynamic in library["dynamically_registered"]:
            address = int(dynamic["function_address"])
            entry_variants = {f"{address:x}", f"0x{address:x}", f"{address:08x}", f"{address:016x}"}
            function = next((row for row in native_functions.get(target_sha, {}).values()
                             if str(row.get("entry") or "").lower() in entry_variants), None)
            dynamic_exports.setdefault((dynamic["name"], dynamic["signature"]), []).append(function or {
                "target_sha256": target_sha,
                "target_path": library["target_path"],
                "entry": f"0x{address:x}",
                "name": dynamic["name"],
                "function_id": f"elf:{target_sha}:0x{address:x}",
            })

    jni_edges = 0
    for declaration in native_declarations:
        short, long_name = _expected_jni_symbols(declaration)
        implementations = list(static_exports.get(long_name, [])) or list(static_exports.get(short, []))
        implementations.extend(dynamic_exports.get((declaration["name"], declaration["prototype"]), []))
        unique = {
            (row.get("target_sha256"), row.get("entry"), row.get("name")): row
            for row in implementations
        }
        declaration["implementations"] = list(unique.values())
        if unique:
            declaration["disposition"] = "resolved-static-or-table"
            for implementation in unique.values():
                edges.append({
                    "edge_id": _edge_id("jni-binding", declaration["method_id"], str(implementation.get("function_id")), str(implementation.get("target_sha256"))),
                    "kind": "jni-binding",
                    "source_method_id": declaration["method_id"],
                    "source_qualified_name": declaration["qualified_name"],
                    "target_function_id": implementation.get("function_id"),
                    "target_sha256": implementation.get("target_sha256"),
                    "target_entry": implementation.get("entry"),
                    "disposition": "resolved",
                })
                jni_edges += 1
        else:
            work_units.append({
                "schema": WORK_SCHEMA,
                "unit_id": _edge_id("jni-unresolved", declaration["method_id"], short, long_name),
                "unit_kind": "jni_binding_resolution",
                "state": "pending",
                "method_id": declaration["method_id"],
                "expected_symbols": [short, long_name],
                "unresolved_reasons": ["no-static-or-dynamic-registration-match"],
            })

    summary = {
        "schema": SCHEMA,
        "dex_methods": len(methods),
        "native_libraries": len(libraries),
        "invoke_sites": invoke_sites,
        "edges": edges,
        "native_declarations": native_declarations,
        "jni_edges": jni_edges,
        "load_library_sites": load_libraries,
        "pending_work_units": len(work_units),
        "all_invoke_sites_accounted": len([row for row in edges if row["kind"] == "dex-invoke"]) == invoke_sites,
        "all_native_declarations_dispositioned": all(row["disposition"] != "unresolved" for row in native_declarations),
        "graph_complete": not work_units,
    }
    summary_bytes = _canonical(summary)
    summary_sha = hashlib.sha256(summary_bytes).hexdigest()
    summary["manifest_sha256"] = summary_sha
    for unit in work_units:
        unit["input_manifest_sha256"] = summary_sha
    _atomic(output / "CROSS_LAYER_WORK_UNITS.jsonl", b"".join(_canonical(row) for row in sorted(work_units, key=lambda row: row["unit_id"])))
    _atomic(output / "CROSS_LAYER_GRAPH.json", json.dumps(summary, indent=2, sort_keys=True).encode() + b"\n")
    return summary
