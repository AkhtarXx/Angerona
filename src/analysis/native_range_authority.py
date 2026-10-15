"""Fail-closed native executable-range authority and evidence validation."""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Iterable


PARTITION_SCHEMA = "angerona/native-executable-partition/v1"
AUTHORITY_TOKEN_SCHEMA = "angerona/native-launch-authority-token/v1"
REDACTED_ADDRESS = "REDACTED_OUTSIDE_NATIVE_AUTHORITY"


def canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_canonical(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _intervals(rows: Iterable[dict[str, Any]], label: str) -> list[tuple[int, int]]:
    result: list[tuple[int, int]] = []
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"{label} range is not an object")
        address, size = row.get("address"), row.get("size")
        if not isinstance(address, int) or not isinstance(size, int) or address < 0 or size <= 0:
            raise ValueError(f"{label} range is malformed")
        result.append((address, address + size))
    return sorted(result)


def _merge(intervals: Iterable[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[list[int]] = []
    for start, end in sorted(intervals):
        if end <= start:
            raise ValueError("native executable interval is empty")
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], end)
        else:
            merged.append([start, end])
    return [(start, end) for start, end in merged]


def derive_partition(
    executable_ranges: list[dict[str, Any]],
    allowed_candidates: list[dict[str, Any]],
    excluded_candidates: list[dict[str, Any]],
) -> dict[str, Any]:
    """Clip candidates and classify every executable byte exactly once.

    Candidate overlaps, uncovered code, and same-class collisions become explicit
    ambiguity. They never inherit an allow/exclude decision.
    """
    executable = _merge(_intervals(executable_ranges, "executable"))
    allowed = _intervals(allowed_candidates, "allowed candidate")
    excluded = _intervals(excluded_candidates, "excluded candidate")
    for start, end in [*allowed, *excluded]:
        if not any(exec_start <= start and end <= exec_end for exec_start, exec_end in executable):
            raise ValueError("native partition candidate escapes executable bytes")
    boundaries: set[int] = {point for interval in executable for point in interval}
    for start, end in [*allowed, *excluded]:
        for exec_start, exec_end in executable:
            clipped_start, clipped_end = max(start, exec_start), min(end, exec_end)
            if clipped_end > clipped_start:
                boundaries.update((clipped_start, clipped_end))
    segments: list[tuple[str, int, int]] = []
    points = sorted(boundaries)
    for left, right in zip(points, points[1:]):
        if not any(start <= left and right <= end for start, end in executable):
            continue
        a_count = sum(start <= left and right <= end for start, end in allowed)
        e_count = sum(start <= left and right <= end for start, end in excluded)
        category = (
            "allowed" if a_count == 1 and e_count == 0
            else "excluded" if e_count == 1 and a_count == 0
            else "ambiguous"
        )
        if segments and segments[-1][0] == category and segments[-1][2] == left:
            previous = segments.pop()
            segments.append((category, previous[1], right))
        else:
            segments.append((category, left, right))
    partition = {
        "schema": PARTITION_SCHEMA,
        "address_domain": "ELF_VIRTUAL_ADDRESS",
        "executable_ranges": [
            {"address": start, "size": end - start} for start, end in executable
        ],
        "allowed_ranges": [
            {"address": start, "size": end - start, "route": "ANALYZE_CUSTOM_EXECUTABLE"}
            for category, start, end in segments if category == "allowed"
        ],
        "excluded_ranges": [
            {"address": start, "size": end - start, "route": "SKIP_PROVEN_LIBRARY_EXECUTABLE"}
            for category, start, end in segments if category == "excluded"
        ],
        "ambiguous_ranges": [
            {"address": start, "size": end - start, "route": "HOLD_AMBIGUOUS_EXECUTABLE"}
            for category, start, end in segments if category == "ambiguous"
        ],
    }
    return validate_partition(partition)


def validate_partition(partition: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(partition, dict) or partition.get("schema") != PARTITION_SCHEMA:
        raise ValueError("native executable partition schema mismatch")
    executable = _merge(_intervals(partition.get("executable_ranges") or [], "executable"))
    if not executable:
        raise ValueError("native executable partition has no executable bytes")
    categories = {
        "allowed": _intervals(partition.get("allowed_ranges") or [], "allowed"),
        "excluded": _intervals(partition.get("excluded_ranges") or [], "excluded"),
        "ambiguous": _intervals(partition.get("ambiguous_ranges") or [], "ambiguous"),
    }
    labelled = sorted(
        (start, end, category)
        for category, intervals in categories.items() for start, end in intervals
    )
    for index, (start, end, _category) in enumerate(labelled):
        if not any(exec_start <= start and end <= exec_end for exec_start, exec_end in executable):
            raise ValueError("native partition range escapes executable bytes")
        if index and start < labelled[index - 1][1]:
            raise ValueError("native partition ranges overlap")
    if _merge((start, end) for start, end, _category in labelled) != executable:
        raise ValueError("native partition has an executable-byte gap")
    counts = {
        f"{category}_bytes": sum(end - start for start, end in intervals)
        for category, intervals in categories.items()
    }
    counts.update({
        f"{category}_range_count": len(intervals)
        for category, intervals in categories.items()
    })
    counts["executable_bytes"] = sum(end - start for start, end in executable)
    core = {key: partition[key] for key in (
        "schema", "address_domain", "executable_ranges",
        "allowed_ranges", "excluded_ranges", "ambiguous_ranges",
    )}
    expected_hash = sha256_canonical(core)
    supplied_hash = partition.get("partition_sha256")
    supplied_counts = partition.get("partition_counts")
    if (
        supplied_hash is not None and supplied_hash != expected_hash
    ) or (
        supplied_counts is not None and supplied_counts != counts
    ):
        raise ValueError("native partition hash/count mismatch")
    return {**core, "partition_counts": counts, "partition_sha256": expected_hash}


def launch_authority_token(row: dict[str, Any]) -> str:
    partition = validate_partition(row.get("executable_partition") or {})
    body = {
        "schema": AUTHORITY_TOKEN_SCHEMA,
        "target_sha256": row.get("target_sha256"),
        "analysis_scope": row.get("analysis_scope"),
        "range_authority_sha256": row.get("range_authority_sha256"),
        "partition_sha256": partition["partition_sha256"],
        "partition_counts": partition["partition_counts"],
        "address_domain": partition["address_domain"],
    }
    return sha256_canonical(body)


def validate_launch_authority(row: dict[str, Any], token: str | None = None) -> dict[str, Any]:
    partition = validate_partition(row.get("executable_partition") or {})
    expected = launch_authority_token({**row, "executable_partition": partition})
    supplied = token if token is not None else row.get("native_launch_authority_token")
    if supplied != expected:
        raise ValueError("native launch authority token mismatch")
    if row.get("partition_sha256") != partition["partition_sha256"]:
        raise ValueError("native launch partition binding mismatch")
    if row.get("partition_counts") != partition["partition_counts"]:
        raise ValueError("native launch partition counts mismatch")
    if row.get("analysis_scope") == "selective_ranges" and partition["ambiguous_ranges"]:
        raise ValueError("ambiguous executable bytes prevent selective native launch")
    return partition


def address_allowed(address: int, allowed: list[dict[str, Any]], bias: int = 0) -> bool:
    return any(
        int(row["address"]) + bias <= address
        < int(row["address"]) + bias + int(row["size"])
        for row in allowed
    )


_ADDRESS_KEYS = {
    "address", "entry", "start", "end", "from", "to", "target_address",
    "source_address", "caller_address", "callee_address", "xref_address",
    "instruction_address", "pcode_address",
}
_TEXT_ADDRESS = re.compile(
    r"(?P<prefix>0x|FUN_|DAT_|PTR_|LAB_|sub_|off_|loc_)(?P<value>[0-9a-fA-F]{4,16})"
)


def _parse_address(value: Any) -> int | None:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str) or value == REDACTED_ADDRESS:
        return None
    token = value.strip().lower()
    try:
        if token.startswith("0x"):
            return int(token, 16)
    except ValueError:
        pass
    return None


def validate_restricted_evidence(
    evidence: Any, allowed: list[dict[str, Any]], *, bias: int = 0,
) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []

    def visit(value: Any, path: str, key: str | None = None) -> None:
        if (
            path.startswith("$.metadata.executable_coverage")
            or path.startswith("$.allowed_executable_ranges")
            or path.startswith("$.restricted_allowed_coverage")
        ):
            return
        if isinstance(value, dict):
            for child_key, child in value.items():
                visit(child, f"{path}.{child_key}", child_key)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                visit(child, f"{path}[{index}]", key)
        elif key in _ADDRESS_KEYS:
            address = _parse_address(value)
            if address is not None and not address_allowed(address, allowed, bias):
                violations.append({"path": path, "address": hex(address)})

    visit(evidence, "$")
    return {
        "schema": "angerona/native-restricted-evidence-validation/v1",
        "allowed_ranges_sha256": sha256_canonical(allowed),
        "native_address_bias": bias,
        "violation_count": len(violations),
        "violations": violations[:100],
        "valid": not violations,
    }


def canonicalize_cross_range_references(
    value: Any, allowed: list[dict[str, Any]], *, bias: int = 0,
) -> Any:
    """Remove content from references not authorized for semantic publication."""
    address_keys = _ADDRESS_KEYS

    def canonicalize(node: Any, context: str = "") -> Any:
        if isinstance(node, dict):
            address_values = [
                (key, node.get(key)) for key in address_keys if key in node
            ]
            if address_values:
                parsed = [_parse_address(raw) for _key, raw in address_values]
                if any(raw == REDACTED_ADDRESS for _key, raw in address_values) or any(
                    address is not None and not address_allowed(address, allowed, bias)
                    for address in parsed
                ):
                    return {
                        "redacted": REDACTED_ADDRESS,
                        "reference_kind": context or "cross_range_reference",
                    }
            return {key: canonicalize(child, key) for key, child in node.items()}
        if isinstance(node, list):
            if context in {"callers", "callees", "xrefs_to", "imports", "exports"}:
                result = []
                for child in node:
                    if not isinstance(child, dict):
                        result.append({
                            "redacted": REDACTED_ADDRESS,
                            "reference_kind": context,
                        })
                    else:
                        result.append(canonicalize(child, context))
                return result
            return [canonicalize(child, context) for child in node]
        return node

    return canonicalize(value)


def sanitize_restricted_text(text: str, allowed: list[dict[str, Any]], *, bias: int = 0) -> tuple[str, dict[str, Any]]:
    redacted: list[str] = []

    def replace(match: re.Match[str]) -> str:
        address = int(match.group("value"), 16)
        if address_allowed(address, allowed, bias):
            return match.group(0)
        redacted.append(match.group(0))
        return REDACTED_ADDRESS

    sanitized = _TEXT_ADDRESS.sub(replace, text)
    return sanitized, {
        "schema": "angerona/native-restricted-text-redaction/v1",
        "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
        "sanitized_sha256": hashlib.sha256(sanitized.encode()).hexdigest(),
        "redaction_count": len(redacted),
        "redacted_token_sha256": sha256_canonical(sorted(redacted)),
    }
