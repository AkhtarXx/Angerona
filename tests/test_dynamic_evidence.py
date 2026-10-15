"""Canonical dynamic-evidence and memory-image contracts."""

from __future__ import annotations

import hashlib

import pytest

from src.execution.models import (
    DynamicEvent,
    MemoryImage,
    MemoryRegion,
    ModuleMapping,
)
from src.execution.runners.base import RunnerResult


TARGET = hashlib.sha256(b"target").hexdigest()


def _image() -> MemoryImage:
    module = ModuleMapping(
        module_id="main",
        name="sample",
        runtime_base=0x55550000,
        preferred_base=0x400000,
        size=0x3000,
        sha256=TARGET,
    )
    region = MemoryRegion.from_bytes(
        name=".text",
        address=0x55551000,
        payload=b"\x90\xc3",
        permissions="r-x",
        kind="module",
        module_id="main",
        file_offset=0x1000,
    )
    event = DynamicEvent.create(
        0,
        "basic_block",
        "test-provider",
        timestamp="2026-08-04T00:00:00+00:00",
        process_id=42,
        thread_id=7,
        runtime_address=0x55551000,
        static_address=0x401000,
        module_id="main",
        properties={"size": 2},
    )
    return MemoryImage.create(
        provider="test-provider",
        target_sha256=TARGET,
        architecture="x86_64",
        pointer_size=8,
        captured_at="2026-08-04T00:00:01+00:00",
        load_base=0x55550000,
        entry_point=0x55551000,
        process_id=42,
        regions=[region],
        modules=[module],
        registers={"rip": 0x55551002, "rsp": 0x7FFFFFF0},
        events=[event],
    )


def test_dynamic_event_normalizes_addresses_and_is_content_addressed() -> None:
    event = _image().events[0]
    assert event.runtime_address == "0x55551000"
    assert event.static_address == "0x401000"
    assert len(event.event_sha256) == 64
    assert event.verify_integrity()


def test_memory_region_binds_exact_captured_bytes() -> None:
    region = _image().regions[0]
    assert region.to_bytes() == b"\x90\xc3"
    assert region.end_address == "0x55551002"
    assert region.verify_integrity()


def test_memory_image_round_trip_preserves_capture_identity() -> None:
    image = _image()
    restored = MemoryImage.from_dict(image.as_dict())
    assert restored.as_dict() == image.as_dict()
    assert restored.capture_id == image.capture_id
    assert restored.verify_integrity() == (True, [])


def test_memory_image_refuses_target_or_event_identity_tampering() -> None:
    payload = _image().as_dict()
    payload["target_sha256"] = hashlib.sha256(b"different").hexdigest()
    with pytest.raises(ValueError, match="capture digest mismatch"):
        MemoryImage.from_dict(payload)

    payload = _image().as_dict()
    payload["events"][0]["properties"]["size"] = 3
    with pytest.raises(ValueError, match="dynamic event digest mismatch"):
        MemoryImage.from_dict(payload)


def test_memory_region_rejects_malformed_or_mismatched_capture() -> None:
    with pytest.raises(ValueError, match="base64"):
        MemoryRegion(name="bad", address="0x1", size=1, bytes_b64="not-base64")
    with pytest.raises(ValueError, match="byte length"):
        MemoryRegion(name="bad", address="0x1", size=9, bytes_b64="QQ==")
    with pytest.raises(ValueError, match="rwx mask"):
        MemoryRegion(name="bad", address="0x1", size=0, permissions="rrrr")
    with pytest.raises(ValueError, match="invalid address"):
        MemoryRegion(name="bad", address=-1, size=0)


def test_memory_image_requires_monotonic_unique_event_sequence() -> None:
    first = _image().events[0]
    second = DynamicEvent.create(
        0,
        "return",
        "test-provider",
        timestamp="2026-08-04T00:00:02+00:00",
    )
    with pytest.raises(ValueError, match="unique and increasing"):
        MemoryImage.create(
            provider="test-provider",
            target_sha256=TARGET,
            architecture="x86_64",
            pointer_size=8,
            events=[first, second],
        )


def test_runner_result_keeps_legacy_snapshot_list_compatible() -> None:
    from src.execution.models import MemorySnapshot

    snapshot = MemorySnapshot.from_bytes(0x1000, b"A", source="test")
    result = RunnerResult(status="success", snapshot=snapshot)
    assert result.snapshots == [snapshot]
    result = RunnerResult(status="success", snapshots=[snapshot])
    assert result.snapshot is snapshot
