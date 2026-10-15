"""Normalized debugger/instrumentation traces and deterministic replay."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from src.execution.models import DynamicEvent, MemoryImage


TRACE_SCHEMA_VERSION = "angerona.runtime-trace/v1"
MAX_TRACE_FILE_BYTES = 256 * 1024 * 1024
MAX_TRACE_EVENTS = 2_000_000
MAX_PROVIDER_LINE_BYTES = 1024 * 1024

_QEMU_STRACE_LINE = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<syscall>[A-Za-z_][A-Za-z0-9_]*)"
    r"\((?P<arguments>.*)\)\s+=\s+(?P<result>.*)$"
)
_QEMU_STRACE_NORETURN = re.compile(
    r"^\s*(?P<pid>\d+)\s+(?P<syscall>exit|exit_group)\((?P<arguments>.*)\)$"
)


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(encoded).hexdigest()


@dataclass
class RuntimeTrace:
    """Content-addressed event stream tied to one exact binary."""

    provider: str
    target_sha256: str
    events: list[DynamicEvent]
    memory_images: list[MemoryImage] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = TRACE_SCHEMA_VERSION
    trace_id: str = ""

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError("trace provider must be non-empty")
        digest = self.target_sha256.lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("target_sha256 must be a SHA-256 hex digest")
        self.target_sha256 = digest
        if len(self.events) > MAX_TRACE_EVENTS:
            raise ValueError("trace event count exceeds safety limit")
        if [event.sequence for event in self.events] != list(range(len(self.events))):
            raise ValueError("trace event sequences must be contiguous from zero")
        for event in self.events:
            if not event.verify_integrity():
                raise ValueError(f"event {event.sequence} digest mismatch")
        for image in self.memory_images:
            if image.target_sha256 != self.target_sha256:
                raise ValueError("memory image target does not match trace target")
            valid, errors = image.verify_integrity()
            if not valid:
                raise ValueError("invalid memory image: " + "; ".join(errors))
        expected = self.compute_trace_id()
        if self.trace_id and self.trace_id != expected:
            raise ValueError("trace digest mismatch")
        self.trace_id = expected

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "target_sha256": self.target_sha256,
            "events": [event.as_dict() for event in self.events],
            "memory_images": [image.as_dict() for image in self.memory_images],
            "metadata": dict(self.metadata),
        }

    def compute_trace_id(self) -> str:
        return _canonical_sha256(self._unsigned_dict())

    def as_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "trace_id": self.trace_id}

    @classmethod
    def from_dict(cls, row: dict[str, Any]) -> "RuntimeTrace":
        return cls(
            provider=str(row.get("provider") or ""),
            target_sha256=str(row.get("target_sha256") or ""),
            events=[DynamicEvent.from_dict(event) for event in row.get("events") or []],
            memory_images=[MemoryImage.from_dict(image) for image in row.get("memory_images") or []],
            metadata=dict(row.get("metadata") or {}),
            schema_version=str(row.get("schema_version") or TRACE_SCHEMA_VERSION),
            trace_id=str(row.get("trace_id") or ""),
        )


class TraceIngestor:
    """Bounded importer for canonical JSON or JSONL provider output."""

    @staticmethod
    def read(path: str | Path) -> RuntimeTrace:
        source = Path(path)
        size = source.stat().st_size
        if size > MAX_TRACE_FILE_BYTES:
            raise ValueError("trace file exceeds safety limit")
        with source.open("r", encoding="utf-8") as handle:
            first = handle.readline()
            if not first:
                raise ValueError("empty trace file")
            if first.lstrip().startswith("{"):
                remainder = handle.read()
                try:
                    row = json.loads(first + remainder)
                    if "events" in row:
                        return RuntimeTrace.from_dict(row)
                except json.JSONDecodeError:
                    pass
            handle.seek(0)
            header = json.loads(handle.readline())
            if header.get("record_type") != "trace_header":
                raise ValueError("JSONL trace must start with trace_header")
            events: list[DynamicEvent] = []
            images: list[MemoryImage] = []
            for line_number, line in enumerate(handle, 2):
                if not line.strip():
                    continue
                if len(events) + len(images) >= MAX_TRACE_EVENTS:
                    raise ValueError("trace record count exceeds safety limit")
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"invalid JSON at trace line {line_number}") from exc
                kind = record.pop("record_type", "event")
                if kind == "event":
                    events.append(DynamicEvent.from_dict(record))
                elif kind == "memory_image":
                    images.append(MemoryImage.from_dict(record))
                else:
                    raise ValueError(f"unsupported trace record type {kind!r}")
        return RuntimeTrace(
            provider=str(header.get("provider") or ""),
            target_sha256=str(header.get("target_sha256") or ""),
            events=events,
            memory_images=images,
            metadata=dict(header.get("metadata") or {}),
            trace_id=str(header.get("trace_id") or ""),
        )

    @staticmethod
    def write_jsonl(trace: RuntimeTrace, path: str | Path) -> None:
        """Atomically persist a trace; incomplete writes never replace a good file."""
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        header = {
            "record_type": "trace_header",
            "schema_version": trace.schema_version,
            "provider": trace.provider,
            "target_sha256": trace.target_sha256,
            "metadata": trace.metadata,
            "trace_id": trace.trace_id,
        }
        descriptor, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(header, sort_keys=True) + "\n")
                for event in trace.events:
                    handle.write(json.dumps({"record_type": "event", **event.as_dict()}, sort_keys=True) + "\n")
                for image in trace.memory_images:
                    handle.write(json.dumps({"record_type": "memory_image", **image.as_dict()}, sort_keys=True) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, destination)
        except Exception:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise


class TraceReplayer:
    """Deterministic, side-effect-free cursor over immutable trace evidence."""

    def __init__(self, trace: RuntimeTrace) -> None:
        self.trace = trace
        self.position = 0

    def seek(self, sequence: int) -> DynamicEvent:
        if not 0 <= sequence < len(self.trace.events):
            raise IndexError("trace sequence out of range")
        self.position = sequence
        return self.trace.events[sequence]

    def step(self, count: int = 1) -> list[DynamicEvent]:
        if count < 0:
            raise ValueError("step count must be non-negative")
        end = min(len(self.trace.events), self.position + count)
        rows = self.trace.events[self.position:end]
        self.position = end
        return rows

    def reset(self) -> None:
        self.position = 0

    def iter_events(
        self,
        *,
        kinds: set[str] | None = None,
        thread_id: int | None = None,
    ) -> Iterator[DynamicEvent]:
        for event in self.trace.events:
            if kinds is not None and event.kind not in kinds:
                continue
            if thread_id is not None and event.thread_id != thread_id:
                continue
            yield event


def normalize_provider_events(
    provider: str,
    rows: Iterable[dict[str, Any]],
) -> list[DynamicEvent]:
    """Assign canonical sequence numbers and hashes to provider-native rows."""
    events: list[DynamicEvent] = []
    for sequence, row in enumerate(rows):
        reserved = {
            "kind", "timestamp", "process_id", "thread_id",
            "runtime_address", "static_address", "module_id",
        }
        events.append(DynamicEvent.create(
            sequence,
            str(row.get("kind") or "provider_event"),
            provider,
            timestamp=row.get("timestamp"),
            process_id=row.get("process_id"),
            thread_id=row.get("thread_id"),
            runtime_address=row.get("runtime_address"),
            static_address=row.get("static_address"),
            module_id=row.get("module_id"),
            properties={key: value for key, value in row.items() if key not in reserved},
        ))
    return events


def parse_bpftrace_ndjson(payload: str | Iterable[str]) -> list[DynamicEvent]:
    """Parse bpftrace ``-f json`` output without silently dropping bad records."""
    lines = payload.splitlines() if isinstance(payload, str) else payload
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if len(line.encode("utf-8", errors="replace")) > MAX_PROVIDER_LINE_BYTES:
            raise ValueError(f"bpftrace record {line_number} exceeds line limit")
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"invalid bpftrace JSON at line {line_number}: {exc.msg}") from exc
        if not isinstance(decoded, dict) or not isinstance(decoded.get("type"), str):
            raise ValueError(f"invalid bpftrace record at line {line_number}")
        data = decoded.get("data")
        row: dict[str, Any] = {
            "kind": decoded["type"],
            "data": data,
            "bpftrace_record": decoded,
        }
        if isinstance(data, dict):
            if isinstance(data.get("pid"), int):
                row["process_id"] = data["pid"]
            if isinstance(data.get("tid"), int):
                row["thread_id"] = data["tid"]
        rows.append(row)
        if len(rows) > MAX_TRACE_EVENTS:
            raise ValueError("bpftrace output exceeds event limit")
    return normalize_provider_events("bpftrace", rows)


def parse_qemu_strace(payload: str | Iterable[str]) -> list[DynamicEvent]:
    """Normalize QEMU user-mode ``-strace`` text while retaining every raw line."""
    lines = payload.splitlines() if isinstance(payload, str) else payload
    rows: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(lines, 1):
        line = raw_line.rstrip("\r\n")
        if not line:
            continue
        if len(line.encode("utf-8", errors="replace")) > MAX_PROVIDER_LINE_BYTES:
            raise ValueError(f"QEMU strace record {line_number} exceeds line limit")
        match = _QEMU_STRACE_LINE.match(line)
        if match is None:
            terminal = _QEMU_STRACE_NORETURN.match(line)
            if terminal is None:
                rows.append({"kind": "qemu_trace", "raw": line, "parsed": False})
            else:
                fields = terminal.groupdict()
                rows.append({
                    "kind": "syscall",
                    "process_id": int(fields["pid"]),
                    "syscall": fields["syscall"],
                    "arguments": fields["arguments"],
                    "result": None,
                    "no_return": True,
                    "raw": line,
                    "parsed": True,
                })
        else:
            fields = match.groupdict()
            rows.append({
                "kind": "syscall",
                "process_id": int(fields["pid"]),
                "syscall": fields["syscall"],
                "arguments": fields["arguments"],
                "result": fields["result"],
                "raw": line,
                "parsed": True,
            })
        if len(rows) > MAX_TRACE_EVENTS:
            raise ValueError("QEMU strace output exceeds event limit")
    return normalize_provider_events("qemu-user", rows)
