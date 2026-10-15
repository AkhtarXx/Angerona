"""Strict primitives for fail-closed audit schema validation."""

from __future__ import annotations

from typing import Any, Mapping, Sequence


# Signed array fields whose order is the canonical set representation.  A
# value of () means an array of non-empty string identities.  A non-empty
# tuple names the row fields forming the canonical lexical key.  "$rows" is
# the JSONL row stream associated with the schema rather than a JSON field.
ORDERED_SET_FIELD_REGISTRY: dict[str, dict[str, tuple[str, ...]]] = {
    "angerona/reverse-knowledge-pack/v1": {
        "allowed_paths": (),
        "files": ("relative_path",),
        "scan_findings": ("finding_id",),
        "excerpts": ("excerpt_id",),
    },
    "angerona/reverse-knowledge-retrieval/v1": {
        "query_terms": (),
        "excerpts": ("citation_id",),
    },
    "angerona/dynamic-security-plan/v1": {
        "nodes": ("node_id",),
        "edges": ("edge_id",),
        "facts": ("fact_id",),
        "unit_ids": (), "node_ids": (), "edge_ids": (), "fact_ids": (),
        "anchor_ids": (),
    },
    "angerona/dynamic-security-queue/v1": {
        "$rows": ("unit_id",),
    },
    "angerona/dynamic-security-anchor-index/v1": {
        "anchors": ("anchor_id",),
    },
    "angerona/dynamic-security-followup-plan/v1": {
        "unit_ids": (),
    },
    "angerona/canonical-unit-jsonl/v1": {
        "$rows": ("unit_id",),
    },
    "angerona/canonical-derived-unit/v1": {
        "parent_bindings": ("checkpoint_set_sha256", "unit_id"),
        "root_unit_ids": (),
    },
    "angerona/canonical-target-set/v1": {
        "expected": (),
        "processed": (),
        "excluded": (),
        "hold": (),
        "rows": ("target_sha256",),
    },
    "angerona/canonical-artifact-set/v1": {
        "artifacts": ("path", "sha256"),
    },
    "angerona/application-surface-manifest/v1": {
        "entities": ("entity_id",),
    },
    "angerona/manifest-component-definition-receipt/v1": {
        "manifest_occurrence_ids": (),
    },
    "angerona/application-surface-occurrence-index/v1": {
        "occurrences": ("occurrence_id",),
    },
    "angerona/application-surface-work-unit/v1": {
        "occurrences": ("occurrence_id",),
        "occurrence_ids": (),
    },
    "angerona/application-surface-queue/v1": {
        "$rows": ("unit_id",),
        "unit_ids": (),
        "parent_receipts": ("path", "sha256"),
        "source_extracted_manifests": ("path", "sha256"),
    },
    "angerona/application-surface-derived-queue/v1": {
        "parent_receipts": ("path", "sha256"),
        "source_extracted_manifests": ("path", "sha256"),
    },
    "angerona/semantic-checkpoint-set/v1": {
        "entries": ("unit_id",),
    },
    "angerona/app-owned-semantic-queue-manifest/v1": {
        "$rows": ("unit_id",),
    },
    "angerona/jadx-class-chunk-queue/v1": {
        "$rows": ("unit_id",),
    },
    "angerona/derived-semantic-queue/v2": {
        "$rows": ("unit_id",),
        "parent_checkpoint_sets": ("path", "sha256"),
    },
    "angerona/class-evidence-resolution/v1": {
        "parent_checkpoint_sets": ("path", "sha256"),
    },
    "angerona/class-consolidation-manifest/v1": {
        "parent_checkpoint_sets": ("path", "sha256"),
    },
    "angerona/jadx-class-chunk-work-unit/v1": {
        "parent_bindings": ("checkpoint_set_sha256", "unit_id"),
        "root_unit_ids": (),
    },
    "angerona/semantic-method-work-unit/v2": {
        "parent_bindings": ("checkpoint_set_sha256", "unit_id"),
        "root_unit_ids": (),
    },
    "angerona/method-fragment-consolidation-set/v1": {
        "checkpoint_set_sha256": (),
        "unit_ids": (),
    },
}


def _ordered_set_spec(schema: str, field: str) -> tuple[str, ...]:
    fields = ORDERED_SET_FIELD_REGISTRY.get(schema)
    if fields is None or field not in fields:
        raise ValueError(f"no canonical ordered-set registry entry for {schema}.{field}")
    return fields[field]


def canonical_order_values(
    schema: str, field: str, values: Sequence[Any], *, context: str = "document",
) -> list[str]:
    if _ordered_set_spec(schema, field):
        raise ValueError(f"{schema}.{field} is registered as a row array")
    identities: list[str] = []
    for index, value in enumerate(values):
        if not isinstance(value, str) or not value:
            raise ValueError(f"{context}.{field}[{index}] must be a non-empty string")
        identities.append(value)
    ordered = sorted(identities)
    if len(ordered) != len(set(ordered)):
        raise ValueError(f"{context}.{field} contains duplicate identities")
    return ordered


def canonical_order_rows(
    schema: str, field: str, rows: Sequence[Any], *, context: str = "document",
) -> list[dict[str, Any]]:
    keys = _ordered_set_spec(schema, field)
    if not keys:
        raise ValueError(f"{schema}.{field} is registered as a scalar identity array")
    keyed: list[tuple[tuple[str, ...], dict[str, Any]]] = []
    for index, row in enumerate(rows):
        if not isinstance(row, dict):
            raise ValueError(f"{context}.{field}[{index}] must be an object")
        key: list[str] = []
        for name in keys:
            value = row.get(name)
            if not isinstance(value, str) or not value:
                raise ValueError(
                    f"{context}.{field}[{index}].{name} must be a non-empty string"
                )
            key.append(value)
        keyed.append((tuple(key), row))
    keyed.sort(key=lambda item: item[0])
    identities = [key for key, _row in keyed]
    if len(identities) != len(set(identities)):
        raise ValueError(f"{context}.{field} contains duplicate canonical identities")
    return [row for _key, row in keyed]


def require_canonical_ordered_field(
    document: Mapping[str, Any], field: str, *, context: str = "document",
) -> list[Any]:
    schema = document.get("schema")
    if not isinstance(schema, str) or not schema:
        raise ValueError(f"{context}.schema must be a non-empty string")
    values = require_list_field(document, field, context=context)
    spec = _ordered_set_spec(schema, field)
    ordered: list[Any]
    if spec:
        ordered = canonical_order_rows(schema, field, values, context=context)
    else:
        ordered = canonical_order_values(schema, field, values, context=context)
    if values != ordered:
        raise ValueError(f"{context}.{field} is not in canonical identity order")
    return values


def require_int_value(
    value: Any, *, field: str, minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if minimum is not None and value < minimum:
        raise ValueError(f"{field} must be >= {minimum}")
    if maximum is not None and value > maximum:
        raise ValueError(f"{field} must be <= {maximum}")
    return value


def require_int_field(
    document: Mapping[str, Any], field: str, *, context: str = "document",
    minimum: int | None = None, maximum: int | None = None,
) -> int:
    if field not in document:
        raise ValueError(f"{context} is missing required integer field {field}")
    return require_int_value(
        document[field], field=f"{context}.{field}",
        minimum=minimum, maximum=maximum,
    )


def optional_int_field(
    document: Mapping[str, Any], field: str, *, default: int,
    context: str = "document", minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    if field not in document:
        return require_int_value(
            default, field=f"{context}.{field} default",
            minimum=minimum, maximum=maximum,
        )
    return require_int_field(
        document, field, context=context, minimum=minimum, maximum=maximum,
    )


def optional_nullable_int_field(
    document: Mapping[str, Any], field: str, *, default: int,
    context: str = "document", minimum: int | None = None,
    maximum: int | None = None,
) -> int:
    """Read a schema-declared nullable integer; missing/null maps explicitly."""
    if field not in document or document[field] is None:
        return require_int_value(
            default, field=f"{context}.{field} nullable default",
            minimum=minimum, maximum=maximum,
        )
    return require_int_field(
        document, field, context=context, minimum=minimum, maximum=maximum,
    )


def require_list_field(
    document: Mapping[str, Any], field: str, *, context: str = "document",
) -> list[Any]:
    if field not in document or not isinstance(document[field], list):
        raise ValueError(f"{context}.{field} must be an array")
    return document[field]


def require_dict_field(
    document: Mapping[str, Any], field: str, *, context: str = "document",
) -> dict[str, Any]:
    if field not in document or not isinstance(document[field], dict):
        raise ValueError(f"{context}.{field} must be an object")
    return document[field]
