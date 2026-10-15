"""Build focused vulnerability-analysis slices from sink reachability evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SECURITY_SLICE_SCHEMA_VERSION = 1
SECURITY_SLICES_FILENAME = "security_slices.json"


def _load_json(value: dict[str, Any] | str | Path | None) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    path = Path(value)
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _target_keys(target: dict[str, Any]) -> set[str]:
    keys = set()
    name = str(target.get("name") or "")
    entry = str(target.get("entry") or "")
    if name:
        keys.add(f"name:{name}")
    if entry:
        norm = entry.lower().replace("0x", "")
        keys.add(f"addr:{norm}")
    return keys


def _ledger_indexes(ledger: dict[str, Any]) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    targets: dict[str, dict[str, Any]] = {}
    for target in ledger.get("reconstruction_targets", []):
        if not isinstance(target, dict):
            continue
        for key in _target_keys(target):
            targets[key] = target
    artifacts = {
        str(artifact.get("path")): artifact
        for artifact in ledger.get("artifacts", [])
        if isinstance(artifact, dict) and artifact.get("path")
    }
    return targets, artifacts


def _node_data(xref_graph: Any, node_id: str) -> dict[str, Any]:
    if not node_id or node_id not in xref_graph.g:
        return {"node_id": node_id, "missing": True}
    data = xref_graph.g.nodes[node_id]
    return {
        "node_id": node_id,
        "kind": data.get("kind"),
        "name": data.get("name") or node_id,
        "address": data.get("address"),
        "library": bool(xref_graph.is_library(node_id)),
        "properties": dict(data.get("properties") or {}),
    }


def _target_for_node(
    node: dict[str, Any],
    targets_by_key: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    name = str(node.get("name") or "")
    address = str(node.get("address") or "")
    if address:
        found = targets_by_key.get(f"addr:{address.lower().replace('0x', '')}")
        if found:
            return found
    if name:
        return targets_by_key.get(f"name:{name}")
    return None


def _record_path(
    xref_graph: Any,
    path: list[str],
    targets_by_key: dict[str, dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    nodes: list[dict[str, Any]] = []
    targets: list[dict[str, Any]] = []
    decompiled_files: list[str] = []
    seen_targets: set[tuple[str, str]] = set()
    seen_files: set[str] = set()
    for node_id in path:
        node = _node_data(xref_graph, node_id)
        target = _target_for_node(node, targets_by_key)
        if target:
            node["reconstruction_state"] = target.get("state")
            node["decompiled_path"] = target.get("decompiled_path")
            key = (str(target.get("entry")), str(target.get("name")))
            if key not in seen_targets:
                targets.append({
                    "name": target.get("name"),
                    "entry": target.get("entry"),
                    "state": target.get("state"),
                    "decompiled_path": target.get("decompiled_path"),
                    "decompiled_sha256": target.get("decompiled_sha256"),
                    "verification": target.get("verification"),
                })
                seen_targets.add(key)
            rel = target.get("decompiled_path")
            if rel and rel not in seen_files:
                decompiled_files.append(str(rel))
                seen_files.add(str(rel))
        nodes.append(node)
    return nodes, targets, decompiled_files


def _artifact_refs(paths: list[str], artifacts_by_path: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    refs = []
    for rel in paths:
        artifact = artifacts_by_path.get(rel)
        if not artifact:
            refs.append({"path": rel, "missing": True})
            continue
        refs.append({
            "path": rel,
            "role": artifact.get("role"),
            "sha256": artifact.get("sha256"),
            "size_bytes": artifact.get("size_bytes"),
        })
    return refs


def _slice_id(index: int, source_id: str, sink_id: str, category: str) -> str:
    raw = f"{source_id}->{sink_id}:{category}".encode("utf-8", errors="replace")
    return f"slice-{index:04d}-{hashlib.sha1(raw).hexdigest()[:12]}"


def _candidate_sinks(sink_report: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    high_risk = [
        sink for sink in sink_report.get("high_risk_reachable", [])
        if isinstance(sink, dict)
    ]
    if high_risk:
        return high_risk, 0
    reachable = []
    deferred = 0
    for sinks in sink_report.get("categories", {}).values():
        if not isinstance(sinks, list):
            continue
        for sink in sinks:
            if not isinstance(sink, dict):
                continue
            if sink.get("reachable"):
                reachable.append(sink)
            else:
                deferred += 1
    return reachable, deferred


def build_security_slices(
    *,
    xref_graph: Any,
    sink_report: dict[str, Any],
    evidence_ledger: dict[str, Any] | str | Path | None = None,
    max_slices: int = 100,
) -> dict[str, Any]:
    """Convert reachable sink findings into focused AI/verifier work units."""
    ledger = _load_json(evidence_ledger)
    targets_by_key, artifacts_by_path = _ledger_indexes(ledger)
    candidates, deferred_unreachable = _candidate_sinks(sink_report)
    slices: list[dict[str, Any]] = []
    for sink in candidates[:max_slices]:
        evidence = dict(sink.get("evidence") or {})
        source_id = str(evidence.get("reachability_source_node_id") or "")
        sink_id = str(evidence.get("reachability_target_node_id") or sink.get("node_id") or "")
        raw_path = (
            evidence.get("semantic_raw_path")
            or sink.get("shortest_path")
            or sink.get("semantic_shortest_path")
            or []
        )
        if not isinstance(raw_path, list):
            raw_path = []
        if not raw_path and source_id and sink_id:
            raw_path = [source_id, sink_id]
        path_nodes, reconstruction_targets, decompiled_files = _record_path(
            xref_graph,
            [str(node_id) for node_id in raw_path],
            targets_by_key,
        )
        idx = len(slices) + 1
        slices.append({
            "slice_id": _slice_id(idx, source_id, sink_id, str(sink.get("category") or "")),
            "status": "candidate",
            "risk": {
                "severity": sink.get("severity"),
                "category": sink.get("category"),
                "sink_name": sink.get("name"),
                "description": sink.get("description"),
                "reachable": bool(sink.get("reachable")),
                "source_distance": sink.get("source_distance"),
                "semantic_source_distance": sink.get("semantic_source_distance"),
            },
            "source": {
                **_node_data(xref_graph, source_id),
                "provenance": evidence.get("reachability_source_provenance", "unknown"),
                "inferred": bool(evidence.get("reachability_source_inferred")),
            },
            "sink": {
                **_node_data(xref_graph, sink_id),
                "boundary": bool(evidence.get("reachability_target_is_boundary")),
            },
            "path": {
                "node_ids": [node["node_id"] for node in path_nodes],
                "nodes": path_nodes,
                "semantic_node_ids": sink.get("semantic_shortest_path") or [],
                "collapsed_nodes": evidence.get("semantic_collapsed_nodes") or [],
            },
            "evidence": {
                "sink": evidence,
                "decompiled_files": _artifact_refs(decompiled_files, artifacts_by_path),
                "required_raw_artifacts": _artifact_refs(
                    [
                        "analysis.json",
                        "functions.csv",
                        "imports.txt",
                        "strings.txt",
                        "symbols.txt",
                        "security_properties.json",
                        "EXPORT_MANIFEST.json",
                    ],
                    artifacts_by_path,
                ),
            },
            "reconstruction_targets": reconstruction_targets,
            "validation": {
                "state": "not_started",
                "required_checks": [
                    "confirm_source_to_sink_data_control",
                    "check_argument_bounds_or_sanitization",
                    "prove_or_reject_with_static_or_dynamic_oracle",
                ],
            },
            "ai_scope": {
                "allowed_inputs": sorted(set(decompiled_files + [
                    "analysis.json",
                    "functions.csv",
                    "imports.txt",
                    "strings.txt",
                    "symbols.txt",
                ])),
                "write_policy": "propose_reconstruction_and_vulnerability_hypothesis_only",
            },
        })
    return {
        "schema_version": SECURITY_SLICE_SCHEMA_VERSION,
        "model": "focused_security_slices",
        "summary": {
            "total_sinks": sink_report.get("total_sinks", 0),
            "reachable_sinks": sink_report.get("reachable_sinks", 0),
            "candidate_slices": len(slices),
            "deferred_unreachable_sinks": deferred_unreachable,
            "truncated": len(candidates) > max_slices,
        },
        "slices": slices,
    }


def write_security_slices(
    *,
    path: str | Path,
    xref_graph: Any,
    sink_report: dict[str, Any],
    evidence_ledger: dict[str, Any] | str | Path | None = None,
    max_slices: int = 100,
) -> dict[str, Any]:
    """Build and atomically write a security slice report."""
    report = build_security_slices(
        xref_graph=xref_graph,
        sink_report=sink_report,
        evidence_ledger=evidence_ledger,
        max_slices=max_slices,
    )
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)
    return report
