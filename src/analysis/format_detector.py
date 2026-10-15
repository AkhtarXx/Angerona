"""Universal format detector — the front door of Angerona's agnostic pipeline.

Resolves any byte sequence to a single immutable :class:`FormatProfile` — the
boundary type every downstream layer (router, lifter, agent loop) consumes.
No layer above reads raw bytes; every layer below works off FormatProfile.

Resolution order (per MASTER_PLAN §2.2):
  1. Magic signature lookup (strongest, confidence = signature's confidence)
  2. Polyglot multi-offset scan (returns *set* of interpretations)
  3. Format-specific structural probes (e.g. .pyc heuristic)
  4. Statistical sniff fallback (family-only, capped confidence)

The profile is NEVER silent: ``unresolved`` lists exactly which facts the detector
could not establish.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from .formats.detect import Identification, identify
from .formats.loader import load_signatures
from .formats.polyglot import scan_polyglot
from .formats.sniff import FamilyProposal, sniff


@dataclass(frozen=True)
class FormatProfile:
    """The one immutable boundary type the rest of the pipeline consumes."""

    family: str                # elf|pe|macho|dex|jvm|cil|pyc|lua|wasm|beam|
                               # v8|zip|squashfs|uimage|fit|ihex|srec|...|blob
    variant: str               # "pe64", "lua54", "pyc-313", "arm-le-32"
    confidence: float          # 0..1; magic-hit=signature.confidence, sniff<=0.62
    polyglot: tuple[str, ...]  # alternative format ids (max 3), by polyrank
    container: bool            # needs L1 unwrap
    packed_family: str = ""    # e.g. "upx" | "themida" — filled by L1 packing_detect
    blob_facts: tuple = ()     # filled by L1 blob_fingerprint when family=="raw"
    primary_preference_rank: int = 50
    recommended_engine: str = ""
    recommended_processor: str | None = None
    evidence: tuple = ()       # tuple of evidence dicts
    unresolved: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {
            "family": self.family,
            "variant": self.variant,
            "confidence": round(self.confidence, 3),
            "polyglot": list(self.polyglot),
            "container": self.container,
            "packed_family": self.packed_family,
            "primary_preference_rank": self.primary_preference_rank,
            "recommended_engine": self.recommended_engine,
            "recommended_processor": self.recommended_processor,
            "evidence": list(self.evidence),
            "unresolved": list(self.unresolved),
        }


_CONTAINER_FAMILIES = {
    "zip", "gzip", "squashfs", "ubifs", "uimage", "fit",
    "ole2", "wim", "iso9660", "android_sparse", "lz4", "bz2", "lzo",
    "pgp_armor",
}
_BYTECODE_PROCESSORS = {
    "dex": "dex", "jvm": "jvm", "cil": "cil", "pyc": "pyc",
    "wasm": "wasm", "beam": "beam",
    # Lua resolves per-version at detect-time (lua51/lua53/lua54).
    "lua": None,
}
_ENGINE_HINTS = {
    "elf": "ida|ghidra", "pe": "ida", "macho": "ida", "macho_fat": "ida",
    "dex": "processor:dex", "jvm": "processor:jvm", "cil": "processor:cil",
    "pyc": "processor:pyc", "lua": "processor:lua", "wasm": "processor:wasm",
    "beam": "processor:beam", "zip": "unpack-then-reroute",
}


def _route_hint(ident: Identification) -> tuple[str, str | None]:
    """Return (engine_hint, processor_key) for an identification."""
    family = ident.signature.family
    proc = _BYTECODE_PROCESSORS.get(family)
    if proc:
        return f"processor:{proc}", proc
    engine = _ENGINE_HINTS.get(family, "")
    return engine, None


# Lua bytecode carries its version at byte 4 of the file (0x51/0x52/0x53/0x54).
# The signature table only matches "\x1bLua" (4 bytes); the variant byte is
# resolved at detect time so we route to lua51 / lua53 / lua54 processors that
# actually exist in the registry (ProcessorRegistry keys lua51/lua53/lua54).
_LUA_VERSION_TAG = {0x51: "lua51", 0x52: "lua53", 0x53: "lua53", 0x54: "lua54"}


def _lua_processors(data: bytes) -> tuple[str, str | None]:
    if len(data) < 5 or data[:4] != b"\x1bLua":
        return ("processor:lua51", "lua51")      # generic fallback
    v = data[4]
    key = _LUA_VERSION_TAG.get(v)
    if key:
        return (f"processor:{key}", key)
    return ("processor:lua51", "lua51")


def detect(source: bytes | str | Path) -> FormatProfile:
    """Resolve ``source`` (bytes or path) into a FormatProfile.

    Never raises: missing file, malformed bytes, and unsupported formats all degrade
    to a blob-family profile with an honest ``unresolved`` list.
    """
    if isinstance(source, (str, Path)):
        try:
            data = Path(source).read_bytes()
        except OSError as exc:
            return FormatProfile(
                family="missing", variant="", confidence=0.0, polyglot=(),
                container=False, unresolved=(f"cannot read: {exc}",),
            )
    else:
        data = bytes(source)

    signatures = load_signatures()
    if not data:
        return FormatProfile(
            family="empty", variant="", confidence=0.0, polyglot=(),
            container=False, unresolved=("zero bytes",),
        )

    forward = identify(data, signatures)
    if not forward:
        # fallback: statistical family sniff, never label a specific format
        proposal = sniff(data)
        return FormatProfile(
            family=f"blob-{proposal.family}" if proposal.family != "empty" else "empty",
            variant="",
            confidence=proposal.confidence,
            polyglot=(),
            container=False,
            evidence=(proposal.evidence,),
            unresolved=(f"no magic match; sniff family={proposal.family} "
                        f"(confidence={proposal.confidence})",),
        )

    primary = forward[0]
    if primary.signature.family == "lua":
        engine, processor = _lua_processors(data)
    else:
        engine, processor = _route_hint(primary)
    poly = scan_polyglot(data, signatures)
    alts = tuple(p.signature.family for p in poly.interpretations[1:])

    unresolved: list[str] = []
    if len(forward) == 1 and primary.confidence < 0.9:
        unresolved.append(
            f"single structural hit at confidence {primary.confidence}; "
            "ambiguous classification")
    if primary.signature.family == "cil" or primary.signature.variant == "dotnet-pe":
        unresolved.append("cil vs pe requires CLR-header probe during lifter lane")

    return FormatProfile(
        family=primary.signature.family,
        variant=(processor
                  if (primary.signature.family == "lua" and processor is not None)
                  else primary.signature.variant),
        confidence=primary.confidence,
        polyglot=alts,
        container=primary.signature.family in _CONTAINER_FAMILIES,
        primary_preference_rank=primary.signature.polyrank,
        recommended_engine=engine if engine else "blob-lane",
        recommended_processor=processor,
        evidence=tuple({
            "signature": primary.signature.name,
            "puid": primary.signature.puid,
            "offset": primary.offset,
            "confidence": primary.confidence,
        } for forward in forward),
        unresolved=tuple(unresolved),
    )


def detect_file(path: str | Path) -> FormatProfile:
    """Alias for :func:`detect` accepting a path lazily."""
    return detect(path)
