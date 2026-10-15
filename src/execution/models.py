"""Shared execution-enrichment data models."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


DYNAMIC_MEMORY_SCHEMA_VERSION = "angerona.dynamic-memory.v1"
DYNAMIC_EVENT_SCHEMA_VERSION = "angerona.dynamic-event.v1"


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_address(value: str | int | None) -> str | None:
    if value is None or value == "":
        return None
    try:
        parsed = value if isinstance(value, int) else int(str(value).strip(), 0)
        if parsed < 0 or parsed > 0xFFFFFFFFFFFFFFFF:
            raise ValueError
        return f"0x{parsed:x}"
    except (TypeError, ValueError):
        raise ValueError(f"invalid address: {value!r}") from None


def _canonical_sha256(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _validate_sha256(value: str, *, field_name: str, allow_empty: bool = False) -> str:
    value = str(value or "").lower()
    if allow_empty and not value:
        return ""
    if len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 hex digest")
    return value


@dataclass
class ModuleMapping:
    """One runtime module mapped into a captured process address space."""

    module_id: str
    name: str
    runtime_base: str
    size: int
    preferred_base: str | None = None
    path: str | None = None
    sha256: str = ""
    build_id: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.module_id:
            raise ValueError("module_id must be non-empty")
        if self.size < 0:
            raise ValueError("module size must be non-negative")
        self.runtime_base = _normalize_address(self.runtime_base) or "0x0"
        self.preferred_base = _normalize_address(self.preferred_base)
        self.sha256 = _validate_sha256(
            self.sha256,
            field_name="module sha256",
            allow_empty=True,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "module_id": self.module_id,
            "name": self.name,
            "runtime_base": self.runtime_base,
            "preferred_base": self.preferred_base,
            "size": self.size,
            "path": self.path,
            "sha256": self.sha256,
            "build_id": self.build_id,
            "properties": dict(self.properties),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ModuleMapping":
        return cls(
            module_id=str(data.get("module_id") or ""),
            name=str(data.get("name") or ""),
            runtime_base=data.get("runtime_base") or "0x0",
            preferred_base=data.get("preferred_base"),
            size=int(data.get("size") or 0),
            path=data.get("path"),
            sha256=str(data.get("sha256") or ""),
            build_id=data.get("build_id"),
            properties=dict(data.get("properties") or {}),
        )


@dataclass
class MemoryRegion:
    """A mapped memory region with optional captured bytes and provenance."""

    name: str
    address: str
    size: int
    permissions: str = "r--"
    kind: str = "anonymous"
    module_id: str | None = None
    file_offset: int | None = None
    bytes_b64: str | None = None
    content_sha256: str = ""
    properties: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.address = _normalize_address(self.address) or "0x0"
        if self.size < 0:
            raise ValueError("memory region size must be non-negative")
        if self.file_offset is not None and self.file_offset < 0:
            raise ValueError("file_offset must be non-negative")
        if len(self.permissions) != 3 or any(
            ch not in allowed
            for ch, allowed in zip(self.permissions, ("r-", "w-", "x-"))
        ):
            raise ValueError("permissions must be a three-character rwx mask")
        if self.content_sha256:
            self.content_sha256 = _validate_sha256(
                self.content_sha256,
                field_name="region content_sha256",
            )
        if self.bytes_b64 is not None:
            payload = self.to_bytes()
            if len(payload) != self.size:
                raise ValueError("captured region byte length does not match size")
            digest = hashlib.sha256(payload).hexdigest()
            if self.content_sha256 and digest != self.content_sha256:
                raise ValueError("captured region bytes do not match content_sha256")
            self.content_sha256 = digest

    @classmethod
    def from_bytes(
        cls,
        *,
        name: str,
        address: str | int,
        payload: bytes,
        permissions: str = "rw-",
        kind: str = "captured",
        module_id: str | None = None,
        file_offset: int | None = None,
        properties: dict[str, Any] | None = None,
    ) -> "MemoryRegion":
        raw = bytes(payload)
        return cls(
            name=name,
            address=_normalize_address(address) or "0x0",
            size=len(raw),
            permissions=permissions,
            kind=kind,
            module_id=module_id,
            file_offset=file_offset,
            bytes_b64=base64.b64encode(raw).decode("ascii"),
            content_sha256=hashlib.sha256(raw).hexdigest(),
            properties=dict(properties or {}),
        )

    @property
    def end_address(self) -> str:
        return f"0x{int(self.address, 0) + self.size:x}"

    def to_bytes(self) -> bytes:
        if self.bytes_b64 is None:
            return b""
        try:
            return base64.b64decode(self.bytes_b64, validate=True)
        except Exception as exc:  # noqa: BLE001 - normalize malformed evidence
            raise ValueError("invalid captured region base64") from exc

    def verify_integrity(self) -> bool:
        if self.bytes_b64 is None:
            return not self.content_sha256 or len(self.content_sha256) == 64
        payload = self.to_bytes()
        return (
            len(payload) == self.size
            and hashlib.sha256(payload).hexdigest() == self.content_sha256
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "address": self.address,
            "end_address": self.end_address,
            "size": self.size,
            "permissions": self.permissions,
            "kind": self.kind,
            "module_id": self.module_id,
            "file_offset": self.file_offset,
            "bytes_b64": self.bytes_b64,
            "content_sha256": self.content_sha256,
            "properties": dict(self.properties),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryRegion":
        return cls(
            name=str(data.get("name") or "region"),
            address=data.get("address") or "0x0",
            size=int(data.get("size") or 0),
            permissions=str(data.get("permissions") or "r--"),
            kind=str(data.get("kind") or "anonymous"),
            module_id=data.get("module_id"),
            file_offset=data.get("file_offset"),
            bytes_b64=data.get("bytes_b64"),
            content_sha256=str(data.get("content_sha256") or ""),
            properties=dict(data.get("properties") or {}),
        )


@dataclass
class DynamicEvent:
    """One ordered, address-normalized runtime observation."""

    sequence: int
    kind: str
    provider: str
    timestamp: str
    process_id: int | None = None
    thread_id: int | None = None
    runtime_address: str | None = None
    static_address: str | None = None
    module_id: str | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    schema_version: str = DYNAMIC_EVENT_SCHEMA_VERSION
    event_sha256: str = ""

    def __post_init__(self) -> None:
        if self.sequence < 0:
            raise ValueError("event sequence must be non-negative")
        if not self.kind or not self.provider:
            raise ValueError("event kind and provider must be non-empty")
        if self.process_id is not None and self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        if self.thread_id is not None and self.thread_id < 0:
            raise ValueError("thread_id must be non-negative")
        self.runtime_address = _normalize_address(self.runtime_address)
        self.static_address = _normalize_address(self.static_address)
        expected = self.compute_sha256()
        if self.event_sha256 and self.event_sha256 != expected:
            raise ValueError("dynamic event digest mismatch")
        self.event_sha256 = expected

    @classmethod
    def create(
        cls,
        sequence: int,
        kind: str,
        provider: str,
        *,
        timestamp: str | None = None,
        process_id: int | None = None,
        thread_id: int | None = None,
        runtime_address: str | int | None = None,
        static_address: str | int | None = None,
        module_id: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> "DynamicEvent":
        return cls(
            sequence=sequence,
            kind=kind,
            provider=provider,
            timestamp=timestamp or _utc_now(),
            process_id=process_id,
            thread_id=thread_id,
            runtime_address=_normalize_address(runtime_address),
            static_address=_normalize_address(static_address),
            module_id=module_id,
            properties=dict(properties or {}),
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            "kind": self.kind,
            "provider": self.provider,
            "timestamp": self.timestamp,
            "process_id": self.process_id,
            "thread_id": self.thread_id,
            "runtime_address": self.runtime_address,
            "static_address": self.static_address,
            "module_id": self.module_id,
            "properties": dict(self.properties),
        }

    def compute_sha256(self) -> str:
        return _canonical_sha256(self._unsigned_dict())

    def verify_integrity(self) -> bool:
        return self.event_sha256 == self.compute_sha256()

    def as_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "event_sha256": self.event_sha256}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DynamicEvent":
        return cls(
            sequence=int(data.get("sequence") or 0),
            kind=str(data.get("kind") or ""),
            provider=str(data.get("provider") or ""),
            timestamp=str(data.get("timestamp") or ""),
            process_id=data.get("process_id"),
            thread_id=data.get("thread_id"),
            runtime_address=data.get("runtime_address"),
            static_address=data.get("static_address"),
            module_id=data.get("module_id"),
            properties=dict(data.get("properties") or {}),
            schema_version=str(data.get("schema_version") or DYNAMIC_EVENT_SCHEMA_VERSION),
            event_sha256=str(data.get("event_sha256") or ""),
        )


@dataclass
class MemoryImage:
    """Content-addressed runtime image bound to the exact analyzed target."""

    provider: str
    target_sha256: str
    architecture: str
    pointer_size: int
    captured_at: str
    regions: list[MemoryRegion] = field(default_factory=list)
    modules: list[ModuleMapping] = field(default_factory=list)
    registers: dict[str, int | str] = field(default_factory=dict)
    events: list[DynamicEvent] = field(default_factory=list)
    load_base: str | None = None
    entry_point: str | None = None
    process_id: int | None = None
    properties: dict[str, Any] = field(default_factory=dict)
    schema_version: str = DYNAMIC_MEMORY_SCHEMA_VERSION
    capture_id: str = ""

    def __post_init__(self) -> None:
        if not self.provider:
            raise ValueError("memory image provider must be non-empty")
        self.target_sha256 = _validate_sha256(
            self.target_sha256,
            field_name="target_sha256",
        )
        if self.pointer_size not in (1, 2, 4, 8, 16):
            raise ValueError("pointer_size must be a supported byte width")
        self.load_base = _normalize_address(self.load_base)
        self.entry_point = _normalize_address(self.entry_point)
        if self.process_id is not None and self.process_id < 0:
            raise ValueError("process_id must be non-negative")
        sequences = [event.sequence for event in self.events]
        if sequences != sorted(set(sequences)):
            raise ValueError("dynamic event sequences must be unique and increasing")
        expected = self.compute_capture_id()
        if self.capture_id and self.capture_id != expected:
            raise ValueError("memory image capture digest mismatch")
        self.capture_id = expected

    @classmethod
    def create(
        cls,
        *,
        provider: str,
        target_sha256: str,
        architecture: str,
        pointer_size: int,
        captured_at: str | None = None,
        regions: list[MemoryRegion] | None = None,
        modules: list[ModuleMapping] | None = None,
        registers: dict[str, int | str] | None = None,
        events: list[DynamicEvent] | None = None,
        load_base: str | int | None = None,
        entry_point: str | int | None = None,
        process_id: int | None = None,
        properties: dict[str, Any] | None = None,
    ) -> "MemoryImage":
        return cls(
            provider=provider,
            target_sha256=target_sha256,
            architecture=architecture,
            pointer_size=pointer_size,
            captured_at=captured_at or _utc_now(),
            regions=list(regions or []),
            modules=list(modules or []),
            registers=dict(registers or {}),
            events=list(events or []),
            load_base=_normalize_address(load_base),
            entry_point=_normalize_address(entry_point),
            process_id=process_id,
            properties=dict(properties or {}),
        )

    def _unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "provider": self.provider,
            "target_sha256": self.target_sha256,
            "architecture": self.architecture,
            "pointer_size": self.pointer_size,
            "captured_at": self.captured_at,
            "load_base": self.load_base,
            "entry_point": self.entry_point,
            "process_id": self.process_id,
            "regions": [region.as_dict() for region in self.regions],
            "modules": [module.as_dict() for module in self.modules],
            "registers": dict(sorted(self.registers.items())),
            "events": [event.as_dict() for event in self.events],
            "properties": dict(self.properties),
        }

    def compute_capture_id(self) -> str:
        return _canonical_sha256(self._unsigned_dict())

    def verify_integrity(self) -> tuple[bool, list[str]]:
        errors: list[str] = []
        for index, region in enumerate(self.regions):
            if not region.verify_integrity():
                errors.append(f"region[{index}] content digest mismatch")
        for index, event in enumerate(self.events):
            if not event.verify_integrity():
                errors.append(f"event[{index}] digest mismatch")
        if self.capture_id != self.compute_capture_id():
            errors.append("capture digest mismatch")
        return not errors, errors

    def as_dict(self) -> dict[str, Any]:
        return {**self._unsigned_dict(), "capture_id": self.capture_id}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "MemoryImage":
        return cls(
            provider=str(data.get("provider") or ""),
            target_sha256=str(data.get("target_sha256") or ""),
            architecture=str(data.get("architecture") or "unknown"),
            pointer_size=int(data.get("pointer_size") or 0),
            captured_at=str(data.get("captured_at") or ""),
            load_base=data.get("load_base"),
            entry_point=data.get("entry_point"),
            process_id=data.get("process_id"),
            regions=[MemoryRegion.from_dict(row) for row in data.get("regions") or []],
            modules=[ModuleMapping.from_dict(row) for row in data.get("modules") or []],
            registers=dict(data.get("registers") or {}),
            events=[DynamicEvent.from_dict(row) for row in data.get("events") or []],
            properties=dict(data.get("properties") or {}),
            schema_version=str(data.get("schema_version") or DYNAMIC_MEMORY_SCHEMA_VERSION),
            capture_id=str(data.get("capture_id") or ""),
        )


@dataclass
class MemorySnapshot:
    """A captured memory region from an emulation / Appcall probe."""

    address: str
    bytes_b64: str
    length: int
    source: str
    timestamp: str
    name: str = "snapshot"
    properties: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_bytes(
        cls,
        address: str | int,
        payload: bytes,
        *,
        source: str = "unknown",
        name: str = "snapshot",
        timestamp: str | None = None,
        properties: dict[str, Any] | None = None,
    ) -> "MemorySnapshot":
        """Create a snapshot from raw bytes."""
        if isinstance(address, int):
            address = f"0x{address & 0xFFFFFFFFFFFFFFFF:x}"
        if timestamp is None:
            timestamp = datetime.now(timezone.utc).isoformat()
        if isinstance(payload, (bytes, bytearray)):
            encoded = base64.b64encode(payload).decode("ascii")
        else:
            encoded = str(payload)
        return cls(
            address=address,
            bytes_b64=encoded,
            length=len(payload),
            source=source,
            timestamp=timestamp,
            name=name,
            properties=properties or {},
        )

    def to_bytes(self) -> bytes:
        """Decode the snapshot payload."""
        return base64.b64decode(self.bytes_b64, validate=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "length": self.length,
            "bytes_b64": self.bytes_b64,
            "source": self.source,
            "timestamp": self.timestamp,
            "name": self.name,
            "properties": dict(self.properties),
        }


@dataclass
class EnrichmentResult:
    """Result of a single enrichment iteration."""

    status: str
    snapshot: MemorySnapshot | None = None
    discovered_types: list[dict[str, Any]] = field(default_factory=list)
    changes: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
