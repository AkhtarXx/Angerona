"""Evidence-driven security work planning over a sealed application graph.

The planner intentionally has no vulnerability-domain catalogue.  It derives
scopes from graph topology and signed facts, then requires models to return
only unconfirmed, occurrence/address-bound hypotheses.  Confirmation remains
outside this module and requires deterministic or runtime validation.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict, deque
from pathlib import Path
import re
from typing import Any, Iterable

from .audit_lineage import (
    load_audit_epoch, open_verified_artifact, output_is_in_epoch,
    verify_checkpoint_set,
)
from .clean_audit_routing import verify_clean_apk_routing_plan
from .evidence_signing import canonical_payload, verify_document
from .schema_validation import canonical_order_rows, canonical_order_values, require_int_field
from .signed_artifact_io import load_signed_canonical, write_signed_canonical
from .reverse_knowledge_pack import (
    materialize_knowledge_retrieval, verify_knowledge_pack,
    verify_knowledge_retrieval,
)


PLANNER_SCHEMA = "angerona/dynamic-security-plan/v1"
QUEUE_SCHEMA = "angerona/dynamic-security-queue/v1"
WORK_SCHEMA = "angerona/dynamic-security-work-unit/v1"
ANCHOR_SCHEMA = "angerona/dynamic-security-anchor-index/v1"
LINEAGE_SCHEMA = "angerona/dynamic-security-derived-queue/v1"
FOLLOWUP_SCHEMA = "angerona/dynamic-security-followup-plan/v1"
CROSS_RECEIPT_SCHEMA = "angerona/clean-cross-layer-merge-receipt/v1"
CROSS_GRAPH_SCHEMA = "angerona/cross-layer-graph/v2"
SURFACE_OCCURRENCE_SCHEMA = "angerona/application-surface-occurrence-index/v1"
_FACET_KEY = re.compile(
    r"(?:boundary|capabilit|parser|decoder|store|storage|protocol|operation|workflow|"
    r"permission|exposure|unresolved|gap)", re.I,
)
_URI_SCHEME = re.compile(rb"\b([A-Za-z][A-Za-z0-9+.-]{1,31})://")


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_line(document: dict[str, Any]) -> bytes:
    return canonical_payload(document) + b"\n"


def _atomic(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != payload:
            raise FileExistsError(f"refusing to replace immutable planner artifact: {path}")
        return
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("xb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _descriptor(path: str | Path) -> dict[str, str]:
    resolved = Path(path).resolve(strict=True)
    return {"path": str(resolved), "sha256": _sha(resolved.read_bytes())}


def _strings(value: Any, prefix: str = "") -> Iterable[tuple[str, str]]:
    if isinstance(value, dict):
        for key in sorted(value):
            child = f"{prefix}.{key}" if prefix else str(key)
            yield from _strings(value[key], child)
    elif isinstance(value, list):
        for index, child_value in enumerate(value):
            yield from _strings(child_value, f"{prefix}[{index}]")
    elif isinstance(value, (str, int, float, bool)) and not isinstance(value, bool):
        yield prefix, str(value)


def _endpoint(edge: dict[str, Any], side: str) -> str:
    candidates = (
        ("source_method_id", "source_function_id", "source_node_id", "source_qualified_name")
        if side == "source" else
        ("target_method_id", "target_function_id", "target_node_id", "target_qualified_name")
    )
    for key in candidates:
        value = edge.get(key)
        if value not in (None, ""):
            return str(value)
    return f"unresolved:{edge['edge_id']}:{side}"


def _namespace(node_id: str) -> str:
    if node_id.startswith("elf:"):
        return "elf"
    if node_id.startswith("dex:") or node_id.startswith("L"):
        return "dex"
    return node_id.split(":", 1)[0].split("/", 1)[0]


def _graph_model(graph: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    raw_edges = graph.get("edges")
    if not isinstance(raw_edges, list):
        raise ValueError("sealed cross-layer graph edges must be an array")
    edges: list[dict[str, Any]] = []
    nodes: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_edges):
        if not isinstance(raw, dict):
            raise ValueError(f"cross-layer edge {index} is not an object")
        edge_id = raw.get("edge_id")
        if not isinstance(edge_id, str) or not edge_id:
            raise ValueError(f"cross-layer edge {index} lacks an identity")
        source, target = _endpoint(raw, "source"), _endpoint(raw, "target")
        row = {**raw, "edge_id": edge_id, "source_node_id": source, "target_node_id": target}
        edges.append(row)
        for node_id, side in ((source, "source"), (target, "target")):
            nodes.setdefault(node_id, {
                "node_id": node_id, "namespace": _namespace(node_id),
                "observed_roles": [], "evidence_edge_ids": [],
            })
            nodes[node_id]["observed_roles"].append(side)
            nodes[node_id]["evidence_edge_ids"].append(edge_id)
    for node in nodes.values():
        node["observed_roles"] = sorted(set(node["observed_roles"]))
        node["evidence_edge_ids"] = sorted(set(node["evidence_edge_ids"]))
    return (
        canonical_order_rows("angerona/dynamic-security-plan/v1", "nodes", list(nodes.values())),
        canonical_order_rows("angerona/dynamic-security-plan/v1", "edges", edges),
    )


def _artifact_line_anchor(
    edge: dict[str, Any], roots: Iterable[str | Path],
) -> dict[str, Any] | None:
    evidence = edge.get("evidence")
    if not isinstance(evidence, dict):
        return None
    path, sha = evidence.get("path"), evidence.get("sha256")
    line = evidence.get("line")
    if not isinstance(path, str) or not isinstance(sha, str):
        return None
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        return None
    artifact_path, payload = open_verified_artifact(
        {"path": path, "sha256": sha}, roots,
    )
    lines = payload.splitlines(keepends=True)
    if line > len(lines):
        raise ValueError(f"graph edge {edge['edge_id']} cites an absent source line")
    start = sum(len(value) for value in lines[:line - 1])
    excerpt = lines[line - 1]
    body = {
        "anchor_kind": "occurrence", "artifact": {"path": str(artifact_path), "sha256": sha},
        "entity_id": edge["source_node_id"], "edge_id": edge["edge_id"],
        "byte_start": start, "byte_end": start + len(excerpt),
        "line_start": line, "line_end": line, "excerpt_sha256": _sha(excerpt),
        "semantic_role": "graph-edge-evidence",
    }
    return {**body, "anchor_id": "dynamic-occurrence:" + _sha(canonical_payload(body))}


def _address_anchor(edge: dict[str, Any]) -> dict[str, Any] | None:
    target_sha = edge.get("target_sha256")
    address = edge.get("target_entry")
    function_id = edge.get("target_function_id")
    if not isinstance(target_sha, str) or not target_sha or address in (None, ""):
        return None
    body = {
        "anchor_kind": "address", "target_sha256": target_sha,
        "address": str(address), "function_id": str(function_id or ""),
        "edge_id": edge["edge_id"], "semantic_role": "graph-edge-target",
    }
    return {**body, "anchor_id": "dynamic-address:" + _sha(canonical_payload(body))}


def _fact(kind: str, value: str, *, node_ids: Iterable[str] = (), edge_ids: Iterable[str] = ()) -> dict[str, Any]:
    body = {
        "dimension": kind, "value": value,
        "node_ids": sorted(set(node_ids)), "edge_ids": sorted(set(edge_ids)),
    }
    return {**body, "fact_id": "dynamic-fact:" + _sha(canonical_payload(body))}


def _facts(
    graph: dict[str, Any], nodes: list[dict[str, Any]], edges: list[dict[str, Any]],
    anchors: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    facts: dict[str, dict[str, Any]] = {}
    for edge in edges:
        source, target = edge["source_node_id"], edge["target_node_id"]
        candidates = [_fact("cross-layer-edge", str(edge.get("kind") or "edge"), node_ids=(source, target), edge_ids=(edge["edge_id"],))]
        if _namespace(source) != _namespace(target):
            candidates.append(_fact("reachable-trust-boundary", f"{_namespace(source)}->{_namespace(target)}", node_ids=(source, target), edge_ids=(edge["edge_id"],)))
        disposition = str(edge.get("disposition") or "")
        if any(token in disposition.lower() for token in ("unresolved", "pending", "external")):
            candidates.append(_fact("unresolved-gap", disposition, node_ids=(source, target), edge_ids=(edge["edge_id"],)))
        candidates.append(_fact("operation", str(edge.get("target_qualified_name") or target), node_ids=(target,), edge_ids=(edge["edge_id"],)))
        for candidate in candidates:
            facts[candidate["fact_id"]] = candidate
    node_ids = {row["node_id"] for row in nodes}
    edge_ids = {row["edge_id"] for row in edges}
    for path, value in _strings(graph):
        if not _FACET_KEY.search(path):
            continue
        related_nodes = sorted(node_id for node_id in node_ids if node_id and node_id in value)
        related_edges = sorted(edge_id for edge_id in edge_ids if edge_id and edge_id in value)
        candidate = _fact("graph-declared-facet", f"{path}={value}", node_ids=related_nodes, edge_ids=related_edges)
        facts[candidate["fact_id"]] = candidate
    for anchor in anchors:
        if anchor["anchor_kind"] == "occurrence":
            artifact_path, payload = open_verified_artifact(anchor["artifact"], [Path(anchor["artifact"]["path"]).parent])
            excerpt = payload[anchor["byte_start"]:anchor["byte_end"]]
            for match in _URI_SCHEME.finditer(excerpt):
                candidate = _fact("observed-protocol", match.group(1).decode("ascii").lower(), node_ids=(anchor["entity_id"],), edge_ids=(anchor["edge_id"],))
                facts[candidate["fact_id"]] = candidate

    adjacency: dict[str, set[str]] = defaultdict(set)
    edge_by_pair: dict[tuple[str, str], list[str]] = defaultdict(list)
    for edge in edges:
        source, target = edge["source_node_id"], edge["target_node_id"]
        adjacency[source].add(target); adjacency[target].add(source)
        edge_by_pair[tuple(sorted((source, target)))].append(edge["edge_id"])
    remaining = set(node_ids)
    while remaining:
        root = min(remaining); queue = deque([root]); component: set[str] = set()
        while queue:
            current = queue.popleft()
            if current in component:
                continue
            component.add(current); queue.extend(sorted(adjacency[current] - component))
        remaining -= component
        component_edges = sorted(
            edge["edge_id"] for edge in edges
            if edge["source_node_id"] in component and edge["target_node_id"] in component
        )
        candidate = _fact("business-workflow", f"connected-flow:{min(component)}", node_ids=component, edge_ids=component_edges)
        facts[candidate["fact_id"]] = candidate
    return canonical_order_rows(PLANNER_SCHEMA, "facts", list(facts.values()))


def _load_surface_occurrences(
    descriptors: Iterable[dict[str, Any]], roots: Iterable[str | Path],
    *, epoch_id: str, plan_id: str,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for descriptor in descriptors:
        _path, document = load_signed_canonical(descriptor, roots, schema=SURFACE_OCCURRENCE_SCHEMA)
        if document.get("audit_epoch", {}).get("epoch_id") != epoch_id or document.get("plan_id") != plan_id:
            raise ValueError("surface occurrence index has mixed epoch/plan lineage")
        for occurrence in document.get("occurrences") or []:
            if not isinstance(occurrence, dict):
                raise ValueError("surface occurrence row is malformed")
            body = {
                "anchor_kind": "occurrence", "artifact": occurrence["artifact"],
                "entity_id": str(occurrence["entity_id"]), "edge_id": "",
                "byte_start": occurrence["byte_start"], "byte_end": occurrence["byte_end"],
                "line_start": 0, "line_end": 0,
                "excerpt_sha256": occurrence["excerpt_sha256"],
                "semantic_role": occurrence["semantic_role"],
                "source_occurrence_id": occurrence["occurrence_id"],
            }
            rows.append({**body, "anchor_id": "dynamic-occurrence:" + _sha(canonical_payload(body))})
    return rows


def _partition(values: list[Any], size: int) -> Iterable[list[Any]]:
    for start in range(0, len(values), size):
        yield values[start:start + size]


def _work_unit_identity(row: dict[str, Any]) -> str:
    """Hash a work unit while canonically breaking the base-unit self-root cycle."""
    body = dict(row)
    body.pop("unit_id", None)
    prefix = "dynamic-security-followup:" if require_int_field(
        body, "evidence_depth", context="dynamic security unit identity", minimum=0,
    ) else "dynamic-security:"
    roots = body.get("root_unit_ids")
    existing_id = row.get("unit_id")
    if body["evidence_depth"] == 0 and roots == [existing_id]:
        body["root_unit_ids"] = []
    return prefix + _sha(canonical_payload(body))


def _knowledge_query_terms(
    nodes: Iterable[dict[str, Any]], edges: Iterable[dict[str, Any]],
    facts: Iterable[dict[str, Any]], extra: Iterable[str] = (),
) -> list[str]:
    values = [str(value) for value in extra]
    values.extend(str(row.get("namespace") or "") for row in nodes)
    values.extend(str(row.get("kind") or "") for row in edges)
    for row in facts:
        values.extend((str(row.get("dimension") or ""), str(row.get("value") or "")))
    tokens = {
        token.lower() for value in values
        for token in re.findall(r"[A-Za-z0-9_.+-]{3,48}", value)
    }
    return sorted(tokens)[:32]


def build_dynamic_security_plan(
    *, plan_path: str | Path, audit_epoch: str | Path,
    cross_layer_receipt: str | Path, output_dir: str | Path,
    occurrence_indexes: Iterable[str | Path] = (),
    knowledge_pack: str | Path | None = None, max_nodes_per_unit: int = 64,
    max_edges_per_unit: int = 128, max_anchors_per_unit: int = 256,
) -> dict[str, Any]:
    if max_nodes_per_unit < 1 or max_edges_per_unit < 1 or max_anchors_per_unit < 1:
        raise ValueError("dynamic planner context bounds must be positive")
    plan = verify_clean_apk_routing_plan(plan_path)
    epoch = load_audit_epoch(audit_epoch)
    output = output_is_in_epoch(output_dir, epoch)
    roots = epoch["trusted_read_roots"]
    knowledge_descriptor = _descriptor(knowledge_pack) if knowledge_pack is not None else None
    knowledge_document = (
        verify_knowledge_pack(knowledge_descriptor, roots) if knowledge_descriptor else None
    )
    if knowledge_document and knowledge_document.get("audit_epoch_id") != epoch["epoch_id"]:
        raise ValueError("reverse knowledge pack belongs to a different audit epoch")
    receipt_descriptor = _descriptor(cross_layer_receipt)
    _receipt_path, receipt_payload = open_verified_artifact(receipt_descriptor, roots)
    receipt = json.loads(receipt_payload)
    if (
        receipt.get("schema") != CROSS_RECEIPT_SCHEMA
        or not verify_document(receipt, require_signature=True)
        or receipt.get("plan_id") != plan["plan_id"]
        or receipt.get("routing_set_id") != plan["routing_set_id"]
        or receipt.get("ownership_policy") != plan["ownership_policy"]
        or receipt.get("audit_epoch", {}).get("epoch_id") != epoch["epoch_id"]
        or receipt.get("hold_count") != 0
    ):
        raise ValueError("dynamic planner requires an exact complete cross-layer receipt")
    graph_descriptor = receipt.get("cross_layer_graph")
    _graph_path, graph_payload = open_verified_artifact(graph_descriptor, roots)
    graph = json.loads(graph_payload)
    if graph.get("schema") != CROSS_GRAPH_SCHEMA or graph.get("graph_complete") is not True:
        raise ValueError("dynamic planner rejects incomplete or unknown cross-layer graph")
    nodes, edges = _graph_model(graph)
    supplied_occurrence_descriptors = [_descriptor(path) for path in occurrence_indexes]
    anchors = _load_surface_occurrences(
        supplied_occurrence_descriptors, roots,
        epoch_id=epoch["epoch_id"], plan_id=plan["plan_id"],
    )
    for edge in edges:
        occurrence = _artifact_line_anchor(edge, roots)
        address = _address_anchor(edge)
        if occurrence is not None:
            anchors.append(occurrence)
        if address is not None:
            anchors.append(address)
    anchors = canonical_order_rows(ANCHOR_SCHEMA, "anchors", anchors)
    known_nodes = {row["node_id"] for row in nodes}
    for anchor in anchors:
        entity_id = str(anchor.get("entity_id") or anchor.get("function_id") or "")
        if entity_id and entity_id not in known_nodes:
            nodes.append({
                "node_id": entity_id, "namespace": "surface-evidence",
                "observed_roles": ["evidence"], "evidence_edge_ids": [],
            })
            known_nodes.add(entity_id)
    nodes = canonical_order_rows(PLANNER_SCHEMA, "nodes", nodes)
    facts = _facts(graph, nodes, edges, anchors)

    edge_by_node: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        edge_by_node[edge["source_node_id"]].append(edge)
        edge_by_node[edge["target_node_id"]].append(edge)
    anchors_by_entity: dict[str, list[dict[str, Any]]] = defaultdict(list)
    global_anchors: list[dict[str, Any]] = []
    for anchor in anchors:
        entity = str(anchor.get("entity_id") or anchor.get("function_id") or "")
        (anchors_by_entity[entity] if entity else global_anchors).append(anchor)

    units: list[dict[str, Any]] = []
    first_scope = True
    global_facts = [row for row in facts if not row["node_ids"] and not row["edge_ids"]]
    for node_chunk in _partition(nodes, max_nodes_per_unit):
        node_ids = [row["node_id"] for row in node_chunk]
        related_edges = {
            row["edge_id"]: row for node_id in node_ids for row in edge_by_node[node_id]
        }
        ordered_edges = sorted(related_edges.values(), key=lambda row: row["edge_id"])
        edge_groups = list(_partition(ordered_edges, max_edges_per_unit)) or [[]]
        for edge_chunk in edge_groups:
            edge_ids = [row["edge_id"] for row in edge_chunk]
            related_facts = [
                row for row in facts
                if set(row["node_ids"]).intersection(node_ids) or set(row["edge_ids"]).intersection(edge_ids)
            ]
            related_anchors = {
                row["anchor_id"]: row
                for node_id in node_ids for row in anchors_by_entity.get(node_id, [])
            }
            for edge_id in edge_ids:
                for row in anchors:
                    if row.get("edge_id") == edge_id:
                        related_anchors[row["anchor_id"]] = row
            anchor_rows = sorted(related_anchors.values(), key=lambda row: row["anchor_id"])
            if first_scope:
                related_facts = sorted(
                    {row["fact_id"]: row for row in related_facts + global_facts}.values(),
                    key=lambda row: row["fact_id"],
                )
                anchor_rows = sorted(
                    {row["anchor_id"]: row for row in anchor_rows + global_anchors}.values(),
                    key=lambda row: row["anchor_id"],
                )
            anchor_groups = list(_partition(anchor_rows, max_anchors_per_unit)) or [[]]
            for anchor_chunk in anchor_groups:
                context = {
                    "schema": "angerona/dynamic-security-scope-context/v1",
                    "audit_epoch_id": epoch["epoch_id"], "plan_id": plan["plan_id"],
                    "graph": graph_descriptor, "nodes": node_chunk, "edges": edge_chunk,
                    "facts": related_facts, "anchors": anchor_chunk,
                }
                context_payload = _canonical_line(context)
                context_sha = _sha(context_payload)
                context_path = output / "scope-contexts" / f"{context_sha}.json"
                _atomic(context_path, context_payload)
                inputs = [{"kind": "sealed-attack-surface-scope", "path": str(context_path), "sha256": context_sha}]
                knowledge_query: list[str] = []
                retrieval: dict[str, Any] | None = None
                if knowledge_descriptor is not None:
                    knowledge_query = _knowledge_query_terms(node_chunk, edge_chunk, related_facts)
                    retrieval = materialize_knowledge_retrieval(
                        pack_descriptor=knowledge_descriptor, roots=roots,
                        query_terms=knowledge_query,
                        output_dir=output / "knowledge-retrievals",
                    )
                    inputs.append({
                        "kind": "untrusted-reverse-methodology-reference",
                        "path": retrieval["path"], "sha256": retrieval["sha256"],
                    })
                input_manifest_sha = _sha(canonical_payload(inputs))
                body = {
                    "schema": WORK_SCHEMA, "unit_kind": "dynamic_graph_security_scope",
                    "class_id": "dynamic-scope:" + context_sha,
                    "input_manifest_sha256": input_manifest_sha,
                    "inputs": inputs,
                    "audit_epoch_id": epoch["epoch_id"], "plan_id": plan["plan_id"],
                    "routing_set_id": plan["routing_set_id"],
                    "ownership_policy": plan["ownership_policy"],
                    "graph": graph_descriptor,
                    "graph_node_ids": sorted(node_ids), "graph_edge_ids": sorted(edge_ids),
                    "focus_fact_ids": sorted(row["fact_id"] for row in related_facts),
                    "occurrence_ids": sorted(row["anchor_id"] for row in anchor_chunk if row["anchor_kind"] == "occurrence"),
                    "address_ids": sorted(row["anchor_id"] for row in anchor_chunk if row["anchor_kind"] == "address"),
                    "ownership_semantics": "signed-graph-only-no-model-inference",
                    "confirmation_semantics": "hypotheses-only-deterministic-or-runtime-proof-required",
                    **({
                        "knowledge_pack": knowledge_descriptor,
                        "knowledge_pack_id": knowledge_document["pack_id"],
                        "knowledge_retrieval": {"path": retrieval["path"], "sha256": retrieval["sha256"]},
                        "knowledge_retrieval_id": retrieval["retrieval_id"],
                        "knowledge_citation_ids": retrieval["citation_ids"],
                        "knowledge_query_terms": knowledge_query,
                        "knowledge_semantics": "untrusted-suggestions-only-no-actions-no-confirmation",
                    } if retrieval is not None else {}),
                    "evidence_depth": 0, "root_unit_ids": [], "parent_bindings": [],
                }
                body["unit_id"] = _work_unit_identity(body)
                body["root_unit_ids"] = [body["unit_id"]]
                units.append(body)
                first_scope = False
    if not units and (nodes or edges or anchors or facts):
        raise ValueError("dynamic planner failed to materialize a nonempty sealed graph")
    units = canonical_order_rows(QUEUE_SCHEMA, "$rows", units)
    queue_path = output / "DYNAMIC_SECURITY_WORK_UNITS.jsonl"
    queue_payload = b"".join(_canonical_line(row) for row in units)
    _atomic(queue_path, queue_payload)
    anchor_descriptor = write_signed_canonical(output / "DYNAMIC_EVIDENCE_ANCHORS.json", {
        "schema": ANCHOR_SCHEMA, "audit_epoch": plan["audit_epoch"],
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "ownership_policy": plan["ownership_policy"], "graph": graph_descriptor,
        "anchors": anchors, "anchor_count": len(anchors),
    })

    node_membership = {node["node_id"]: sorted(unit["unit_id"] for unit in units if node["node_id"] in unit["graph_node_ids"]) for node in nodes}
    edge_membership = {edge["edge_id"]: sorted(unit["unit_id"] for unit in units if edge["edge_id"] in unit["graph_edge_ids"]) for edge in edges}
    fact_membership = {fact["fact_id"]: sorted(unit["unit_id"] for unit in units if fact["fact_id"] in unit["focus_fact_ids"]) for fact in facts}
    anchor_membership = {anchor["anchor_id"]: sorted(unit["unit_id"] for unit in units if anchor["anchor_id"] in unit["occurrence_ids"] + unit["address_ids"]) for anchor in anchors}
    if any(not value for value in node_membership.values()) or any(not value for value in edge_membership.values()):
        raise ValueError("dynamic graph node/edge conservation is incomplete")
    manifest_body = {
        "schema": PLANNER_SCHEMA, "audit_epoch": plan["audit_epoch"],
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "ownership_policy": plan["ownership_policy"],
        "cross_layer_receipt": receipt_descriptor, "graph": graph_descriptor,
        "source_occurrence_indexes": supplied_occurrence_descriptors,
        "anchor_index": anchor_descriptor,
        "queue": {"path": str(queue_path), "sha256": _sha(queue_payload)},
        "unit_count": len(units), "unit_ids": [row["unit_id"] for row in units],
        "nodes": nodes, "node_ids": [row["node_id"] for row in nodes],
        "edges": edges, "edge_ids": [row["edge_id"] for row in edges],
        "facts": facts, "fact_ids": [row["fact_id"] for row in facts],
        "anchor_ids": [row["anchor_id"] for row in anchors],
        "node_membership": node_membership, "edge_membership": edge_membership,
        "fact_membership": fact_membership, "anchor_membership": anchor_membership,
        "planner_semantics": "graph-derived-no-predefined-vulnerability-domains",
        "confirmation_semantics": "model-output-never-confirms-requires-independent-proof",
        "knowledge_pack": knowledge_descriptor,
        "knowledge_pack_id": knowledge_document["pack_id"] if knowledge_document else None,
    }
    manifest_descriptor = write_signed_canonical(output / "DYNAMIC_SECURITY_PLAN.json", manifest_body)
    lineage_descriptor = write_signed_canonical(queue_path.with_name(queue_path.name + ".lineage.json"), {
        "schema": LINEAGE_SCHEMA, "generation": "base", "audit_epoch_id": epoch["epoch_id"],
        "audit_epoch": plan["audit_epoch"],
        "plan_id": plan["plan_id"], "routing_set_id": plan["routing_set_id"],
        "ownership_policy": plan["ownership_policy"], "queue_path": str(queue_path),
        "queue_sha256": _sha(queue_payload), "unit_count": len(units),
        "planner_manifest": manifest_descriptor, "parent_checkpoint_set": None,
        "knowledge_pack": knowledge_descriptor,
        "max_depth": 0,
    })
    verify_dynamic_security_queue(queue_path, audit_epoch)
    return {
        "queue": _descriptor(queue_path), "manifest": manifest_descriptor,
        "lineage": lineage_descriptor, "anchor_index": anchor_descriptor,
        "units": len(units), "nodes": len(nodes), "edges": len(edges),
        "facts": len(facts), "anchors": len(anchors),
    }


def verify_dynamic_security_queue(queue: str | Path, audit_epoch: str | Path | dict[str, Any]) -> str:
    epoch = load_audit_epoch(audit_epoch) if not isinstance(audit_epoch, dict) else audit_epoch
    roots = epoch["trusted_read_roots"]
    queue_path = Path(queue).resolve(strict=True)
    queue_payload = queue_path.read_bytes()
    lineage_descriptor = _descriptor(queue_path.with_name(queue_path.name + ".lineage.json"))
    _lineage_path, lineage = load_signed_canonical(lineage_descriptor, roots, schema=LINEAGE_SCHEMA)
    if (
        lineage.get("audit_epoch_id") != epoch["epoch_id"]
        or lineage.get("queue_path") != str(queue_path)
        or lineage.get("queue_sha256") != _sha(queue_payload)
    ):
        raise ValueError("dynamic security queue has mixed epoch/path/hash lineage")
    epoch_path, _epoch_payload = open_verified_artifact(
        lineage.get("audit_epoch"), roots,
    )
    _manifest_path, manifest = load_signed_canonical(
        lineage.get("planner_manifest"), roots,
        schema=PLANNER_SCHEMA if lineage.get("generation") == "base" else FOLLOWUP_SCHEMA,
    )
    rows = [json.loads(line) for line in queue_payload.splitlines() if line.strip()]
    ordered = canonical_order_rows(QUEUE_SCHEMA, "$rows", rows)
    if rows != ordered:
        raise ValueError("dynamic security queue is not in canonical unit order")
    unit_ids = [row["unit_id"] for row in rows]
    if (
        require_int_field(manifest, "unit_count", context="dynamic security manifest", minimum=0) != len(rows)
        or manifest.get("unit_ids") != unit_ids
        or lineage.get("unit_count") != len(rows)
    ):
        raise ValueError("dynamic security queue membership differs from signed manifest")
    if manifest.get("knowledge_pack") != lineage.get("knowledge_pack"):
        raise ValueError("dynamic security manifest/lineage knowledge-pack mismatch")
    for row in rows:
        if (
            row.get("schema") != WORK_SCHEMA
            or row.get("audit_epoch_id") != epoch["epoch_id"]
            or row.get("plan_id") != lineage.get("plan_id")
            or row.get("routing_set_id") != lineage.get("routing_set_id")
            or row.get("ownership_policy") != lineage.get("ownership_policy")
            or row.get("ownership_semantics") != "signed-graph-only-no-model-inference"
            or row.get("confirmation_semantics") != "hypotheses-only-deterministic-or-runtime-proof-required"
        ):
            raise ValueError(f"dynamic security unit has mixed lineage: {row.get('unit_id')}")
        if row.get("unit_id") != _work_unit_identity(row):
            raise ValueError(f"dynamic security unit identity is invalid: {row.get('unit_id')}")
        if require_int_field(
            row, "evidence_depth", context=f"dynamic security unit {row.get('unit_id')}", minimum=0,
        ) == 0 and row.get("root_unit_ids") != [row.get("unit_id")]:
            raise ValueError("dynamic base unit does not own its canonical root identity")
        for field in (
            "graph_node_ids", "graph_edge_ids", "focus_fact_ids",
            "occurrence_ids", "address_ids", "root_unit_ids",
        ):
            values = row.get(field)
            if not isinstance(values, list) or values != sorted(set(values)):
                raise ValueError(f"dynamic security unit {field} is noncanonical")
        for artifact in row.get("inputs") or []:
            open_verified_artifact(artifact, roots)
        knowledge = row.get("knowledge_pack")
        retrieval = row.get("knowledge_retrieval")
        if bool(knowledge) != bool(retrieval):
            raise ValueError("dynamic security unit has incomplete knowledge binding")
        if knowledge != manifest.get("knowledge_pack"):
            raise ValueError("dynamic security unit/manifest knowledge-pack mismatch")
        if knowledge:
            pack = verify_knowledge_pack(knowledge, roots)
            if (
                row.get("knowledge_pack_id") != pack.get("pack_id")
                or pack.get("audit_epoch_id") != epoch["epoch_id"]
            ):
                raise ValueError("dynamic security unit knowledge-pack identity mismatch")
            retrieved = verify_knowledge_retrieval(
                retrieval, knowledge, roots, row.get("knowledge_query_terms") or [],
            )
            if (
                row.get("knowledge_retrieval_id") != retrieved.get("retrieval_id")
                or row.get("knowledge_citation_ids") != [
                    item["citation_id"] for item in retrieved.get("excerpts") or []
                ]
                or row.get("knowledge_semantics") != "untrusted-suggestions-only-no-actions-no-confirmation"
                or not any(
                    item.get("kind") == "untrusted-reverse-methodology-reference"
                    and item.get("path") == retrieval.get("path")
                    and item.get("sha256") == retrieval.get("sha256")
                    for item in row.get("inputs") or []
                )
            ):
                raise ValueError("dynamic security unit knowledge retrieval binding mismatch")
    if lineage.get("generation") == "base":
        anchor_path, anchor_document = load_signed_canonical(
            manifest.get("anchor_index"), roots, schema=ANCHOR_SCHEMA,
        )
        anchors = anchor_document.get("anchors")
        if (
            not isinstance(anchors, list)
            or anchors != canonical_order_rows(ANCHOR_SCHEMA, "anchors", anchors)
            or require_int_field(
                anchor_document, "anchor_count", context="dynamic anchor index", minimum=0,
            ) != len(anchors)
            or anchor_document.get("audit_epoch", {}).get("epoch_id") != epoch["epoch_id"]
            or anchor_document.get("plan_id") != lineage.get("plan_id")
            or anchor_document.get("routing_set_id") != lineage.get("routing_set_id")
            or anchor_document.get("ownership_policy") != lineage.get("ownership_policy")
        ):
            raise ValueError(f"dynamic anchor index is invalid: {anchor_path}")
        for anchor in anchors:
            if anchor.get("anchor_kind") == "occurrence":
                _artifact_path, artifact_payload = open_verified_artifact(anchor.get("artifact"), roots)
                start, end = anchor.get("byte_start"), anchor.get("byte_end")
                if (
                    not isinstance(start, int) or isinstance(start, bool)
                    or not isinstance(end, int) or isinstance(end, bool)
                    or start < 0 or end <= start or end > len(artifact_payload)
                    or _sha(artifact_payload[start:end]) != anchor.get("excerpt_sha256")
                ):
                    raise ValueError("dynamic occurrence anchor bytes/hash are invalid")
            elif anchor.get("anchor_kind") == "address":
                if not anchor.get("target_sha256") or anchor.get("address") in (None, ""):
                    raise ValueError("dynamic address anchor is incomplete")
            else:
                raise ValueError("dynamic anchor kind is unknown")
        expected_sets = {
            "node": set(manifest.get("node_ids") or []),
            "edge": set(manifest.get("edge_ids") or []),
            "fact": set(manifest.get("fact_ids") or []),
            "anchor": set(manifest.get("anchor_ids") or []),
        }
        observed_sets = {
            "node": {value for row in rows for value in row.get("graph_node_ids") or []},
            "edge": {value for row in rows for value in row.get("graph_edge_ids") or []},
            "fact": {value for row in rows for value in row.get("focus_fact_ids") or []},
            "anchor": {value for row in rows for value in (row.get("occurrence_ids") or []) + (row.get("address_ids") or [])},
        }
        observed_membership = {
            "node": {value: sorted(row["unit_id"] for row in rows if value in row.get("graph_node_ids", [])) for value in expected_sets["node"]},
            "edge": {value: sorted(row["unit_id"] for row in rows if value in row.get("graph_edge_ids", [])) for value in expected_sets["edge"]},
            "fact": {value: sorted(row["unit_id"] for row in rows if value in row.get("focus_fact_ids", [])) for value in expected_sets["fact"]},
            "anchor": {value: sorted(row["unit_id"] for row in rows if value in (row.get("occurrence_ids", []) + row.get("address_ids", []))) for value in expected_sets["anchor"]},
        }
        for kind in expected_sets:
            if observed_sets[kind] != expected_sets[kind]:
                raise ValueError(f"dynamic security {kind} conservation mismatch")
        for kind, membership in (
            ("node", manifest.get("node_membership")), ("edge", manifest.get("edge_membership")),
            ("fact", manifest.get("fact_membership")), ("anchor", manifest.get("anchor_membership")),
        ):
            if not isinstance(membership, dict) or set(membership) != expected_sets[kind]:
                raise ValueError(f"dynamic security {kind} membership ledger mismatch")
            if membership != observed_membership[kind] or any(
                not isinstance(values, list) or not values or values != sorted(set(values))
                for values in membership.values()
            ):
                raise ValueError(f"dynamic security {kind} membership is noncanonical")
    else:
        parent = lineage.get("parent_checkpoint_set")
        if not isinstance(parent, dict):
            raise ValueError("dynamic follow-up queue lacks an exact parent checkpoint set")
        parent_path, parent_payload = open_verified_artifact(parent, roots)
        parent_document = json.loads(parent_payload)
        verify_checkpoint_set(parent_path, parent_document["queue_path"], epoch_path)
        parent_entries = {row["unit_id"]: row for row in parent_document["entries"]}
        for row in rows:
            bindings = row.get("parent_bindings") or []
            if len(bindings) != 1 or bindings[0].get("unit_id") not in parent_entries:
                raise ValueError("dynamic follow-up unit lacks immediate-parent ownership")
            if bindings[0].get("checkpoint_set_sha256") != parent["sha256"]:
                raise ValueError("dynamic follow-up parent set hash mismatch")
            parent_entry = parent_entries[bindings[0]["unit_id"]]
            if bindings[0].get("response_sha256") != parent_entry.get("response_sha256"):
                raise ValueError("dynamic follow-up parent response hash mismatch")
    return _sha(queue_payload)


def build_dynamic_followup_plan(
    *, base_queue: str | Path, parent_checkpoint_set: str | Path,
    audit_epoch: str | Path, output_dir: str | Path, max_depth: int = 3,
) -> dict[str, Any]:
    """Materialize evidence-request workers bound to one verified terminal set."""
    if max_depth < 1 or max_depth > 8:
        raise ValueError("dynamic follow-up max_depth is out of range")
    epoch = load_audit_epoch(audit_epoch)
    output = output_is_in_epoch(output_dir, epoch)
    verify_dynamic_security_queue(base_queue, epoch)
    set_descriptor = _descriptor(parent_checkpoint_set)
    set_path, set_payload = open_verified_artifact(set_descriptor, epoch["trusted_read_roots"])
    set_document = json.loads(set_payload)
    verified_set = verify_checkpoint_set(set_path, base_queue, audit_epoch)
    base_rows = {
        row["unit_id"]: row for row in (
            json.loads(line) for line in Path(base_queue).read_bytes().splitlines() if line.strip()
        )
    }
    entries = {row["unit_id"]: row for row in verified_set["entries"]}
    if list(entries) != list(base_rows):
        raise ValueError("dynamic follow-up parent set does not exactly conserve its queue")
    children: list[dict[str, Any]] = []
    requests_ledger: list[dict[str, Any]] = []
    held_requests: list[dict[str, Any]] = []
    from .semantic_ai_controller import _validate_result
    for unit_id in base_rows:
        unit, entry = base_rows[unit_id], entries[unit_id]
        checkpoint_path, checkpoint_payload = open_verified_artifact(
            {"path": entry["checkpoint_path"], "sha256": entry["checkpoint_sha256"]},
            epoch["trusted_read_roots"],
        )
        checkpoint = json.loads(checkpoint_payload)
        result = checkpoint.get("result")
        if not isinstance(result, dict):
            raise ValueError("dynamic parent checkpoint lacks its strict stored result")
        _validate_result(result, unit)
        depth = require_int_field(unit, "evidence_depth", context=f"dynamic parent {unit_id}", minimum=0)
        for request in result.get("evidence_requests") or []:
            ledger = {
                "request_id": request["request_id"], "parent_unit_id": unit_id,
                "target_kind": request["target_kind"], "target_id": request["target_id"],
                "reason": request["reason"],
            }
            requests_ledger.append(ledger)
            if depth >= max_depth:
                held_requests.append({**ledger, "hold_reason": "maximum-evidence-depth-reached"})
                continue
            context_path, context_payload = open_verified_artifact(
                unit["inputs"][0], epoch["trusted_read_roots"],
            )
            context = json.loads(context_payload)
            target_kind, target_id = request["target_kind"], request["target_id"]
            nodes = context.get("nodes") or []
            edges = context.get("edges") or []
            anchors = context.get("anchors") or []
            if target_kind == "node":
                selected_nodes = [row for row in nodes if row.get("node_id") == target_id]
                selected_edges = [row for row in edges if target_id in {row.get("source_node_id"), row.get("target_node_id")}]
                endpoint_ids = {value for row in selected_edges for value in (row.get("source_node_id"), row.get("target_node_id")) if value}
                selected_nodes = [row for row in nodes if row.get("node_id") in endpoint_ids] or selected_nodes
                selected_anchors = [row for row in anchors if row.get("entity_id") == target_id]
            elif target_kind == "edge":
                selected_edges = [row for row in edges if row.get("edge_id") == target_id]
                endpoint_ids = {value for row in selected_edges for value in (row.get("source_node_id"), row.get("target_node_id")) if value}
                selected_nodes = [row for row in nodes if row.get("node_id") in endpoint_ids]
                selected_anchors = [row for row in anchors if row.get("edge_id") == target_id]
            else:
                selected_anchors = [row for row in anchors if row.get("anchor_id") == target_id]
                selected_edges = [row for row in edges if row.get("edge_id") in {anchor.get("edge_id") for anchor in selected_anchors}]
                endpoint_ids = {value for row in selected_edges for value in (row.get("source_node_id"), row.get("target_node_id")) if value}
                endpoint_ids.update(str(row.get("entity_id") or "") for row in selected_anchors if row.get("entity_id"))
                selected_nodes = [row for row in nodes if row.get("node_id") in endpoint_ids]
            if not selected_nodes and not selected_edges and not selected_anchors:
                raise ValueError("validated dynamic evidence request resolved to no sealed evidence")
            followup_context = {
                "schema": "angerona/dynamic-security-followup-context/v1",
                "audit_epoch_id": epoch["epoch_id"], "parent_checkpoint": {
                    "path": str(checkpoint_path), "sha256": _sha(checkpoint_payload),
                },
                "request": request, "nodes": selected_nodes, "edges": selected_edges,
                "anchors": selected_anchors,
            }
            followup_payload = _canonical_line(followup_context)
            followup_sha = _sha(followup_payload)
            followup_path = output / "scope-contexts" / f"{followup_sha}.json"
            _atomic(followup_path, followup_payload)
            roots = unit.get("root_unit_ids") or [unit_id]
            knowledge = unit.get("knowledge_pack")
            knowledge_query = _knowledge_query_terms(
                selected_nodes, selected_edges, [],
                (request["target_kind"], request["target_id"], request["reason"]),
            ) if knowledge else []
            retrieval = materialize_knowledge_retrieval(
                pack_descriptor=knowledge, roots=epoch["trusted_read_roots"],
                query_terms=knowledge_query, output_dir=output / "knowledge-retrievals",
            ) if knowledge else None
            child_inputs = [{"kind": "sealed-followup-scope", "path": str(followup_path), "sha256": followup_sha}]
            if retrieval:
                child_inputs.append({
                    "kind": "untrusted-reverse-methodology-reference",
                    "path": retrieval["path"], "sha256": retrieval["sha256"],
                })
            child = {
                **{key: unit[key] for key in (
                    "schema", "unit_kind", "audit_epoch_id", "plan_id", "routing_set_id",
                    "ownership_policy", "graph", "ownership_semantics", "confirmation_semantics",
                )},
                "class_id": "dynamic-followup:" + followup_sha,
                "input_manifest_sha256": _sha(canonical_payload(child_inputs)),
                "inputs": child_inputs,
                "graph_node_ids": sorted(str(row["node_id"]) for row in selected_nodes),
                "graph_edge_ids": sorted(str(row["edge_id"]) for row in selected_edges),
                "focus_fact_ids": [],
                "occurrence_ids": sorted(str(row["anchor_id"]) for row in selected_anchors if row["anchor_kind"] == "occurrence"),
                "address_ids": sorted(str(row["anchor_id"]) for row in selected_anchors if row["anchor_kind"] == "address"),
                "evidence_depth": depth + 1, "root_unit_ids": sorted(roots),
                "parent_bindings": [{
                    "checkpoint_set_sha256": set_descriptor["sha256"],
                    "unit_id": unit_id, "response_sha256": entry["response_sha256"],
                }],
                "followup_request": request,
                **({
                    "knowledge_pack": knowledge,
                    "knowledge_pack_id": unit["knowledge_pack_id"],
                    "knowledge_retrieval": {"path": retrieval["path"], "sha256": retrieval["sha256"]},
                    "knowledge_retrieval_id": retrieval["retrieval_id"],
                    "knowledge_citation_ids": retrieval["citation_ids"],
                    "knowledge_query_terms": knowledge_query,
                    "knowledge_semantics": "untrusted-suggestions-only-no-actions-no-confirmation",
                } if retrieval else {}),
            }
            child["unit_id"] = _work_unit_identity(child)
            children.append(child)
    children = canonical_order_rows(QUEUE_SCHEMA, "$rows", children)
    requests_ledger.sort(key=lambda row: (row["parent_unit_id"], row["request_id"]))
    held_requests.sort(key=lambda row: (row["parent_unit_id"], row["request_id"]))
    queue_path = output / "DYNAMIC_SECURITY_FOLLOWUP_WORK_UNITS.jsonl"
    queue_payload = b"".join(_canonical_line(row) for row in children)
    _atomic(queue_path, queue_payload)
    base_lineage = _descriptor(Path(base_queue).with_name(Path(base_queue).name + ".lineage.json"))
    manifest_descriptor = write_signed_canonical(output / "DYNAMIC_SECURITY_FOLLOWUP_PLAN.json", {
        "schema": FOLLOWUP_SCHEMA, "audit_epoch": _descriptor(audit_epoch),
        "audit_epoch_id": epoch["epoch_id"], "base_queue": _descriptor(base_queue),
        "base_lineage": base_lineage, "parent_checkpoint_set": set_descriptor,
        "queue": {"path": str(queue_path), "sha256": _sha(queue_payload)},
        "unit_count": len(children), "unit_ids": [row["unit_id"] for row in children],
        "requests": requests_ledger, "held_requests": held_requests,
        "knowledge_pack": next((row.get("knowledge_pack") for row in base_rows.values() if row.get("knowledge_pack")), None),
        "generation_semantics": "evidence-request-targeted-no-domain-specialist",
    })
    lineage_descriptor = write_signed_canonical(queue_path.with_name(queue_path.name + ".lineage.json"), {
        "schema": LINEAGE_SCHEMA, "generation": "followup", "audit_epoch_id": epoch["epoch_id"],
        "audit_epoch": _descriptor(audit_epoch),
        "plan_id": children[0]["plan_id"] if children else base_rows[next(iter(base_rows))]["plan_id"],
        "routing_set_id": children[0]["routing_set_id"] if children else base_rows[next(iter(base_rows))]["routing_set_id"],
        "ownership_policy": children[0]["ownership_policy"] if children else base_rows[next(iter(base_rows))]["ownership_policy"],
        "queue_path": str(queue_path), "queue_sha256": _sha(queue_payload),
        "unit_count": len(children), "planner_manifest": manifest_descriptor,
        "parent_checkpoint_set": set_descriptor,
        "knowledge_pack": next((row.get("knowledge_pack") for row in base_rows.values() if row.get("knowledge_pack")), None),
        "max_depth": max((row["evidence_depth"] for row in children), default=0),
    })
    verify_dynamic_security_queue(queue_path, audit_epoch)
    return {
        "queue": _descriptor(queue_path), "manifest": manifest_descriptor,
        "lineage": lineage_descriptor, "units": len(children),
        "requests": len(requests_ledger), "held": len(held_requests),
    }
