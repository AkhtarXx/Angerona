"""Typed, JSON-serializable contracts shared by Angerona services."""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Generic, Protocol, TypeVar


class ServiceStatus(StrEnum):
    SUCCEEDED = "succeeded"
    CONTRADICTED = "contradicted"
    UNVERIFIABLE = "unverifiable"
    FAILED = "failed"


@dataclass(frozen=True)
class EvidenceEnvelope:
    """Immutable evidence with content identity and explicit provenance."""

    kind: str
    producer: str
    payload: dict[str, Any]
    source_sha256: str
    evidence_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    schema_version: int = 1
    synthetic: bool = False

    @classmethod
    def for_file(
        cls,
        *,
        kind: str,
        producer: str,
        source: str | Path,
        payload: dict[str, Any],
        synthetic: bool = False,
    ) -> "EvidenceEnvelope":
        digest = hashlib.sha256()
        with Path(source).open("rb") as fh:
            for chunk in iter(lambda: fh.read(1 << 20), b""):
                digest.update(chunk)
        return cls(
            kind=kind,
            producer=producer,
            payload=payload,
            source_sha256=digest.hexdigest(),
            synthetic=synthetic,
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class AnalysisRequest:
    binary: str
    engine: str
    max_functions: int = 0
    force: bool = False
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass(frozen=True)
class ExecutionRequest:
    binary: str
    function: str
    backend: str
    arguments: tuple[Any, ...] = ()
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass(frozen=True)
class VerificationRequest:
    binary: str
    report: str
    facts_dir: str
    strict: bool = True
    request_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)


T = TypeVar("T")


@dataclass(frozen=True)
class ServiceResponse(Generic[T]):
    status: ServiceStatus
    result: T | None = None
    evidence: tuple[EvidenceEnvelope, ...] = ()
    errors: tuple[str, ...] = ()
    request_id: str = ""
    trace_id: str = ""

    @property
    def succeeded(self) -> bool:
        return self.status is ServiceStatus.SUCCEEDED

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str, sort_keys=True)


class AnalysisService(Protocol):
    def analyze(self, request: AnalysisRequest) -> ServiceResponse[dict[str, Any]]: ...


class ExecutionService(Protocol):
    def execute(self, request: ExecutionRequest) -> ServiceResponse[dict[str, Any]]: ...


class VerificationService(Protocol):
    def verify(self, request: VerificationRequest) -> ServiceResponse[dict[str, Any]]: ...
