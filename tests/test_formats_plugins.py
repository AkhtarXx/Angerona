import struct

import pytest

from src.execution.loaders import BinaryLoadError, load_binary_bytes
from src.plugins.sdk import PluginContext, PluginManifest, PluginRegistry


def _macho64() -> bytes:
    data = bytearray(0x300)
    # mach_header_64: x86_64, MH_EXECUTE, two commands, MH_PIE.
    struct.pack_into("<IiiIIIII", data, 0, 0xFEEDFACF, 0x01000007, 3, 2, 2, 96, 0x00200000, 0)
    # LC_SEGMENT_64 __TEXT, file offset 0, VM address 0x100000000.
    struct.pack_into(
        "<II16sQQQQiiII", data, 32,
        0x19, 72, b"__TEXT\0" + b"\0" * 9,
        0x100000000, 0x1000, 0, len(data), 7, 5, 0, 0,
    )
    # LC_MAIN, entry at file offset 0x100.
    struct.pack_into("<IIQQ", data, 104, 0x80000028, 24, 0x100, 0)
    data[0x100:0x102] = b"\x90\xc3"
    return bytes(data)


def test_macho_loader_maps_lc_main_and_rebases_pie() -> None:
    image = load_binary_bytes(_macho64(), requested_base=0x200000000)
    assert image.format == "macho"
    assert image.architecture == "x86_64"
    assert image.entry_point == 0x200000100
    assert image.load_delta == 0x100000000


def test_fat_macho_requires_explicit_slice_selection() -> None:
    with pytest.raises(BinaryLoadError, match="fat Mach-O"):
        load_binary_bytes(b"\xca\xfe\xba\xbe" + b"\0" * 32)


class _Plugin:
    manifest = PluginManifest("sample.plugin", "1.2.3", "1.0", ("analyzer",))
    active = False
    def activate(self, context): self.active = True
    def deactivate(self): self.active = False


def test_versioned_plugin_lifecycle_and_capability_lookup() -> None:
    registry = PluginRegistry()
    plugin = _Plugin()
    registry.register(plugin)
    registry.activate("sample.plugin", PluginContext())
    assert plugin.active
    assert registry.by_capability("analyzer") == [plugin]
    assert registry.status()[0]["active"] is True
    registry.deactivate("sample.plugin")
    assert not plugin.active


def test_plugin_api_major_mismatch_is_rejected() -> None:
    class Future:
        manifest = PluginManifest("future.plugin", "1.0.0", "2.0", ("loader",))
        def activate(self, context): pass
        def deactivate(self): pass
    with pytest.raises(ValueError, match="requires API"):
        PluginRegistry().register(Future())
