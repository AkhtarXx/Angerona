"""Apply execution memory snapshots back into an AnalysisGraph."""

from __future__ import annotations

from typing import Any

from src.execution.models import MemoryImage, MemorySnapshot
from src.models.analysis_graph import AnalysisGraph, Edge, Node


class SnapshotApplier:
    """Idempotent applier of memory snapshots to the canonical analysis graph."""

    def __init__(self, graph: AnalysisGraph) -> None:
        self.graph = graph

    def apply(self, snapshot: MemorySnapshot, target_fn_id: str | None = None) -> list[dict[str, Any]]:
        """Add or update a ``segment`` node for ``snapshot`` and wire contains edges.

        If ``target_fn_id`` is provided, only that function node is marked as
        enriched, preventing unrelated functions from being incorrectly tagged.
        """
        changes: list[dict[str, Any]] = []
        address = self._norm_hex(snapshot.address)
        # Backward-compatible default id; disambiguate with name on collisions.
        seg_id = f"segment:{address}"
        if snapshot.name and snapshot.name != "snapshot":
            seg_id = f"segment:{snapshot.name}:{address}"

        existing = self.graph.get_node(seg_id)
        if existing is not None:
            # Merge: update timestamp and keep latest bytes.
            existing.properties.update({
                "length": snapshot.length,
                "bytes_b64": snapshot.bytes_b64,
                "timestamp": snapshot.timestamp,
                "source": snapshot.source,
            })
            changes.append({"op": "update", "node": seg_id, "reason": "snapshot refreshed"})
        else:
            node = Node(
                id=seg_id,
                kind="segment",
                address=address,
                name=snapshot.name,
                properties={
                    "length": snapshot.length,
                    "bytes_b64": snapshot.bytes_b64,
                    "source": snapshot.source,
                    "timestamp": snapshot.timestamp,
                    **dict(snapshot.properties),
                },
            )
            self.graph.add_node(node)
            changes.append({"op": "add_node", "node": seg_id, "kind": "segment"})

            program_id = self._program_id()
            if program_id is not None:
                self.graph.add_edge(Edge(src=program_id, dst=seg_id, kind="contains"))
                changes.append({"op": "add_edge", "src": program_id, "dst": seg_id, "kind": "contains"})

        # Mark only the probed function as enriched.
        if target_fn_id:
            target = self.graph.get_node(target_fn_id)
            if target is not None and target.kind == "function":
                target.properties["enriched_from_execution"] = True
                target.properties["execution_source"] = snapshot.source
                if snapshot.source == "symbolic":
                    target.properties["symbolic_result"] = snapshot.properties.get("symbolic_result")
                    self._apply_symbolic_constraints(target, snapshot.properties, changes)
        return changes

    def apply_image(
        self,
        image: MemoryImage,
        target_fn_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """Persist a verified runtime image and its address-correlated event stream."""
        valid, errors = image.verify_integrity()
        if not valid:
            raise ValueError("invalid memory image: " + "; ".join(errors))
        changes: list[dict[str, Any]] = []
        manifests = self.graph.metadata.setdefault("dynamic_evidence", [])
        if not any(row.get("capture_id") == image.capture_id for row in manifests):
            manifests.append({
                "capture_id": image.capture_id,
                "provider": image.provider,
                "target_sha256": image.target_sha256,
                "captured_at": image.captured_at,
                "architecture": image.architecture,
                "event_count": len(image.events),
                "region_count": len(image.regions),
            })
            changes.append({"op": "add_evidence", "capture_id": image.capture_id})

        program_id = self._program_id()
        for module in image.modules:
            module_node_id = f"runtime_module:{module.module_id}:{module.runtime_base}"
            if self.graph.get_node(module_node_id) is None:
                self.graph.add_node(Node(
                    id=module_node_id,
                    kind="runtime_module",
                    address=module.runtime_base,
                    name=module.name,
                    properties={**module.as_dict(), "capture_id": image.capture_id},
                ))
                changes.append({"op": "add_node", "node": module_node_id, "kind": "runtime_module"})
                if program_id:
                    self.graph.add_edge(Edge(src=program_id, dst=module_node_id, kind="loaded_as"))

        address_nodes = {
            self._norm_hex(node.address): node.id
            for node in self.graph.nodes
            if node.address is not None and node.kind in {"function", "block", "instruction"}
        }
        for event in image.events:
            event_id = f"runtime_event:{image.capture_id}:{event.sequence}"
            if self.graph.get_node(event_id) is not None:
                continue
            self.graph.add_node(Node(
                id=event_id,
                kind="runtime_event",
                address=event.runtime_address,
                name=event.kind,
                properties={**event.as_dict(), "capture_id": image.capture_id},
            ))
            changes.append({"op": "add_node", "node": event_id, "kind": "runtime_event"})
            if target_fn_id and self.graph.get_node(target_fn_id) is not None:
                self.graph.add_edge(Edge(src=target_fn_id, dst=event_id, kind="observed_runtime"))
            static_id = (
                address_nodes.get(self._norm_hex(event.static_address))
                if event.static_address is not None else None
            )
            if static_id:
                self.graph.add_edge(Edge(src=event_id, dst=static_id, kind="corroborates"))
        return changes

    def _apply_symbolic_constraints(
        self,
        target: Node,
        properties: dict[str, Any],
        changes: list[dict[str, Any]],
    ) -> None:
        """Add constraint nodes and edges for a symbolic snapshot."""
        sym_result = properties.get("symbolic_result")
        if not sym_result:
            return
        paths = sym_result.get("paths", [])
        for path in paths:
            path_id = path.get("path_id", 0)
            preds = path.get("predicate_text", []) or path.get("predicate_smt", [])
            if not preds:
                continue
            cst_id = f"constraint:{target.id}:{path_id}"
            existing = self.graph.get_node(cst_id)
            if existing is None:
                cst_node = Node(
                    id=cst_id,
                    kind="constraint",
                    name=f"path {path_id} predicate",
                    properties={
                        "predicate_text": list(preds),
                        "reachable": path.get("reachable", True),
                    },
                )
                self.graph.add_node(cst_node)
                changes.append({"op": "add_node", "node": cst_id, "kind": "constraint"})
            self.graph.add_edge(
                Edge(src=target.id, dst=cst_id, kind="symbolic_constraint")
            )
            changes.append({
                "op": "add_edge",
                "src": target.id,
                "dst": cst_id,
                "kind": "symbolic_constraint",
            })
            for addr in path.get("block_trace", []):
                try:
                    block_id = f"block:0x{int(str(addr), 0) & 0xFFFFFFFFFFFFFFFF:x}"
                except Exception:
                    continue
                if block_id and self.graph.get_node(block_id):
                    self.graph.add_edge(
                        Edge(src=cst_id, dst=block_id, kind="proves_reachable")
                    )
                    changes.append({
                        "op": "add_edge",
                        "src": cst_id,
                        "dst": block_id,
                        "kind": "proves_reachable",
                    })

    def _program_id(self) -> str | None:
        for node in self.graph.nodes:
            if node.kind == "program":
                return node.id
        return self.graph.metadata.get("program_id")

    @staticmethod
    def _norm_hex(value: Any) -> str:
        if value is None or value == "":
            return "0x0"
        try:
            if isinstance(value, int):
                return f"0x{value & 0xFFFFFFFFFFFFFFFF:x}"
            return f"0x{int(str(value).strip(), 0) & 0xFFFFFFFFFFFFFFFF:x}"
        except Exception:
            return str(value)
