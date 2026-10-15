"""Multi-source triage with confidence scoring for binary samples.

Implements structural pre-disassembly triage inspired by standard UNIX
triage workflows (file/readelf/strings/nm/ldd) and "multi-source triage with
confidence scoring" from The IDA Pro Book.  The implementation is fully
self-contained: pyelftools and pefile are used when present, otherwise the
module falls back to minimal struct parsing.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TriageProfile:
    """Confidence-annotated structural profile for a binary sample."""

    format: str = "unknown"
    arch: str = "unknown"
    bitness: int = 0
    endian: str = "unknown"
    linker: str | None = None
    stripped: bool | None = None
    packed_entropy: float | None = None
    compiler: str | None = None
    confidence: dict[str, float] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)


class MultiSourceTriager:
    """Run structural checks on a binary and produce a confidence-scored profile."""

    # ELF machine -> (arch, bitness)
    _ELF_MACHINE_MAP: dict[int, tuple[str, int]] = {
        0x02: ("SPARC", 32),
        0x03: ("x86", 32),
        0x08: ("MIPS", 32),
        0x0A: ("MIPS", 32),
        0x0B: ("MIPS", 32),
        0x0E: ("PA-RISC", 32),
        0x14: ("PowerPC", 32),
        0x15: ("PowerPC", 64),
        0x16: ("S390", 32),
        0x28: ("ARM", 32),
        0x29: ("SuperH", 32),
        0x2A: ("SPARC", 64),
        0x2B: ("SPARC", 64),
        0x32: ("IA-64", 64),
        0x3E: ("x86-64", 64),
        0x8C: ("MSP430", 16),
        0xB7: ("ARM64", 64),
        0xDC: ("Colossus", 32),
        0xF3: ("RISC-V", 32),
        0xF7: ("BPF", 64),
        0x101: ("WDC 65C816", 16),
    }

    # PE machine -> (arch, bitness)
    _PE_MACHINE_MAP: dict[int, tuple[str, int]] = {
        0x014C: ("x86", 32),
        0x01C0: ("ARM", 32),
        0x01C2: ("ARM", 32),
        0x01C4: ("ARM", 32),
        0x8664: ("x86-64", 64),
        0xAA64: ("ARM64", 64),
        0x01C6: ("ARM64", 64),
        0x01C7: ("ARM64", 64),
        0x0162: ("MIPS", 16),
        0x0166: ("MIPS", 16),
        0x0266: ("MIPS", 16),
        0x0366: ("MIPS", 16),
        0x0466: ("MIPS", 16),
        0x0184: ("Alpha", 32),
        0x01A2: ("SH3", 32),
        0x01A3: ("SH3-DSP", 32),
        0x01A4: ("SH3E", 32),
        0x01A6: ("SH4", 32),
        0x01A8: ("SH5", 64),
        0x01C8: ("ARM", 32),
        0x01D3: ("AM33", 32),
        0x01F0: ("PowerPC", 32),
        0x01F1: ("PowerPC", 32),
        0x0200: ("IA-64", 64),
        0x0284: ("Alpha", 64),
        0x0520: ("Tricore", 32),
        0x0CEF: ("CEF", 32),
        0x0EBC: ("EFI", 32),
        0x5032: ("RISC-V", 32),
        0x5064: ("RISC-V", 64),
        0x5128: ("RISC-V", 128),
        0x6414: ("LoongArch", 32),
        0x6264: ("LoongArch", 64),
        0x9041: ("M32R", 32),
        0xA641: ("ARM64EC", 64),
        0xA64E: ("ARM64X", 64),
    }

    _PACKER_SIGNATURES: dict[str, list[str]] = {
        "UPX": ["UPX!", "UPX0", "UPX1", "$Info: This file is packed with the UPX"],
        "ASPack": ["ASPack", ".aspack"],
        "Themida": ["Themida"],
        "VMProtect": ["VMProtect"],
        "Petite": ["Petite"],
        "FSG": ["FSG!"],
        "MPRESS": ["MPRESS"],
        "PECompact": ["PECompact2"],
        "NSIS": ["NullsoftInstallSystem", "NSIS"],
        "ELF packer/protector": ["elfpack", "shiva", "burneye"],
    }

    _COMPILER_SIGNATURES: dict[str, list[str]] = {
        "GCC": ["GCC:"],
        "Clang/LLVM": ["clang version", "LLVM"],
        "MSVC": ["Microsoft Visual C++", "MSVC", "Visual Studio"],
        "Delphi": ["Borland Delphi"],
        "Go": ["go.buildinfo", "Go build ID:", "runtime.gc"],
        "Rust": ["rust_begin_unwind", "RUST_BACKTRACE"],
    }

    _LINKER_SIGNATURES: dict[str, list[str]] = {
        "GNU ld": ["/lib/ld-linux", "GNU ld"],
        "ld.lld": ["ld.lld"],
        "MSVC linker": ["link.exe"],
        "gold": ["GNU gold"],
    }

    def triage(self, path: str | Path) -> TriageProfile:
        """Run all triage sources and aggregate a confidence-scored profile."""
        p = Path(path)
        profile = TriageProfile()
        profile.evidence["path"] = str(p.resolve())

        if not p.exists() or not p.is_file():
            profile.indicators.append("path not found or not a regular file")
            profile.confidence["existence"] = 0.0
            return profile

        profile.confidence["existence"] = 1.0

        # Source: file magic
        magic_info = self._read_magic(p)
        profile.evidence["magic"] = magic_info
        fmt = magic_info.get("format", "unknown")
        if fmt != "unknown":
            profile.format = fmt
            profile.confidence["magic"] = 0.95
        else:
            profile.confidence["magic"] = 0.1

        # Source: format-specific header
        header_info: dict[str, Any] = {}
        if fmt == "ELF":
            header_info = self._inspect_elf(p)
            profile.confidence["header"] = 0.92 if header_info.get("parsed") else 0.45
        elif fmt == "PE":
            header_info = self._inspect_pe(p)
            profile.confidence["header"] = 0.92 if header_info.get("parsed") else 0.45
        else:
            profile.confidence["header"] = 0.0

        profile.evidence["header"] = header_info
        arch = header_info.get("arch", "unknown")
        bitness = header_info.get("bitness", 0)
        endian = header_info.get("endian", "unknown")
        stripped = header_info.get("stripped")
        if arch != "unknown":
            profile.arch = arch
        if bitness != 0:
            profile.bitness = bitness
        if endian != "unknown":
            profile.endian = endian
        if stripped is not None:
            profile.stripped = stripped

        # Source: strings / content
        strings = self._sample_strings(p, n=200)
        profile.evidence["strings_sample"] = strings
        profile.confidence["strings"] = 0.75 if strings else 0.1

        # Source: entropy
        entropy = self._compute_entropy(p)
        profile.packed_entropy = entropy
        profile.evidence["entropy"] = entropy
        profile.confidence["entropy"] = 0.85 if entropy is not None else 0.0

        # Derived indicators
        indicators = self._scan_packer_indicators(strings, entropy)
        profile.indicators.extend(indicators)

        # Compiler/linker hints from strings
        compiler = self._detect_signature(strings, self._COMPILER_SIGNATURES)
        linker = self._detect_signature(strings, self._LINKER_SIGNATURES)
        if compiler:
            profile.compiler = compiler
            profile.indicators.append(f"compiler hint: {compiler}")
        if linker:
            profile.linker = linker
            profile.indicators.append(f"linker hint: {linker}")

        # Source: symbol table presence (derived from ELF section names / PE import directory)
        sym_info = header_info.get("symbols", {})
        profile.evidence["symbols"] = sym_info
        if isinstance(sym_info, dict) and sym_info.get("has_symbols") is True:
            profile.confidence["symbols"] = 0.8
            profile.stripped = False
        elif isinstance(sym_info, dict) and sym_info.get("has_symbols") is False:
            profile.confidence["symbols"] = 0.7
            profile.stripped = True
        else:
            profile.confidence["symbols"] = 0.3

        profile.confidence = self._score_sources(profile)
        return profile

    def _read_magic(self, path: Path) -> dict[str, Any]:
        """Identify the binary format from its magic header bytes."""
        try:
            with open(path, "rb") as f:
                magic = f.read(16)
        except OSError as exc:
            return {"error": str(exc)}

        if len(magic) < 4:
            return {"format": "unknown", "magic": magic.hex()}

        info: dict[str, Any] = {"magic_bytes": magic.hex()}

        if magic[:4] == b"\x7fELF":
            info["format"] = "ELF"
        elif magic[:2] == b"MZ":
            info["format"] = "PE"
        elif magic[:4] in (b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
            info["format"] = "Mach-O"
            info["note"] = "Mach-O parsing not implemented in this triager"
        else:
            info["format"] = "unknown"

        return info

    def _inspect_elf(self, path: Path) -> dict[str, Any]:
        """Parse ELF header using pyelftools if available, else struct."""
        try:
            from elftools.elf.elffile import ELFFile  # type: ignore[import-untyped]
        except ImportError:
            return self._inspect_elf_struct(path)

        try:
            with open(path, "rb") as f:
                elf = ELFFile(f)
                header = elf.header
                e_machine = header["e_machine"]
                arch, mapped_bitness = self._ELF_MACHINE_MAP.get(
                    e_machine, ("unknown", 0)
                )
                if arch == "unknown":
                    try:
                        detected_arch = str(elf.get_machine_arch() or "unknown")
                    except Exception:  # noqa: BLE001
                        detected_arch = "unknown"
                    if detected_arch and "unknown" not in detected_arch.lower():
                        arch = detected_arch
                # ELF class is authoritative for pointer width.  Machine IDs
                # describe an ISA and may be vendor-specific (for example the
                # Solana eBPF fixture uses 0x107), so an unknown machine must
                # not erase a perfectly valid ELF64/ELF32 class.
                bitness = int(getattr(elf, "elfclass", 0) or mapped_bitness)

                endian = "little"
                if header["e_ident"].get("EI_DATA") == "ELFDATA2MSB":
                    endian = "big"

                symbols = {"has_symbols": False, "dynamic": False}
                has_symtab = elf.get_section_by_name(".symtab") is not None
                has_dynsym = elf.get_section_by_name(".dynsym") is not None
                if has_symtab or has_dynsym:
                    symbols["has_symbols"] = True
                    symbols["static"] = has_symtab
                    symbols["dynamic"] = has_dynsym

                stripped = not (has_symtab or has_dynsym)
                compiler = self._guess_compiler_from_sections(elf)

                return {
                    "parsed": True,
                    "arch": arch,
                    "bitness": bitness,
                    "endian": endian,
                    "e_machine": e_machine,
                    "e_type": header["e_type"],
                    "stripped": stripped,
                    "symbols": symbols,
                    "compiler": compiler,
                    "interpreter": self._elf_interpreter(elf),
                }
        except Exception as exc:  # noqa: BLE001
            return {"parsed": False, "error": str(exc)}

    def _inspect_elf_struct(self, path: Path) -> dict[str, Any]:
        """Minimal ELF header parsing via struct.unpack."""
        try:
            with open(path, "rb") as f:
                data = f.read(64)
        except OSError as exc:
            return {"parsed": False, "error": str(exc)}

        if len(data) < 52 or data[:4] != b"\x7fELF":
            return {"parsed": False, "error": "not a valid ELF file"}

        ei_class = data[4]
        ei_data = data[5]

        bitness = 32 if ei_class == 1 else 64 if ei_class == 2 else 0
        endian = "little" if ei_data == 1 else "big" if ei_data == 2 else "unknown"
        endian_char = "<" if ei_data == 1 else ">" if ei_data == 2 else "<"

        if bitness == 32:
            fmt = f"{endian_char}16xHHI"  # skip e_ident, read e_type/e_machine/e_version
            size = struct.calcsize(fmt)
            if len(data) < size:
                return {"parsed": False, "error": "ELF32 header too short"}
            e_type, e_machine, _ = struct.unpack(fmt, data[:size])
        elif bitness == 64:
            fmt = f"{endian_char}16xHHI"  # skip e_ident, read e_type/e_machine/e_version
            size = struct.calcsize(fmt)
            if len(data) < size:
                return {"parsed": False, "error": "ELF64 header too short"}
            e_type, e_machine, _ = struct.unpack(fmt, data[:size])
        else:
            return {"parsed": False, "error": "unknown ELF word size"}

        arch, _ = self._ELF_MACHINE_MAP.get(e_machine, ("unknown", 0))

        # Best-effort stripped check: scan first chunk for section names
        stripped = None
        try:
            with open(path, "rb") as f:
                chunk = f.read(4096)
            stripped = b".symtab" not in chunk and b".dynsym" not in chunk
        except OSError:
            pass

        return {
            "parsed": True,
            "arch": arch,
            "bitness": bitness,
            "endian": endian,
            "e_machine": e_machine,
            "e_type": e_type,
            "stripped": stripped,
            "symbols": {"has_symbols": not stripped if stripped is not None else None},
            "note": "fallback struct parser; pyelftools not installed",
        }

    def _elf_interpreter(self, elf: Any) -> str | None:
        """Return the ELF interpreter path, if present."""
        try:
            for segment in elf.iter_segments():
                if hasattr(segment, "get_interpreter"):
                    interp = segment.get_interpreter()
                    if interp:
                        return interp
        except Exception:  # noqa: BLE001
            pass
        return None

    def _guess_compiler_from_sections(self, elf: Any) -> str | None:
        """Heuristic compiler detection from ELF section names/comments."""
        try:
            comment = elf.get_section_by_name(".comment")
            if comment:
                data = comment.data() if hasattr(comment, "data") else b""
                text = data.decode("utf-8", "ignore")
                if "GCC" in text:
                    return "GCC"
                if "clang" in text.lower():
                    return "Clang/LLVM"
        except Exception:  # noqa: BLE001
            pass
        return None

    def _inspect_pe(self, path: Path) -> dict[str, Any]:
        """Parse PE header via pefile if available, else minimal struct parsing."""
        try:
            import pefile  # type: ignore[import-untyped]
        except ImportError:
            return self._inspect_pe_struct(path)

        try:
            pe = pefile.PE(str(path), fast_load=True)
            machine = pe.FILE_HEADER.Machine
            arch, bitness = self._PE_MACHINE_MAP.get(machine, ("unknown", 0))

            optional = getattr(pe, "OPTIONAL_HEADER", None)
            subsystem = optional.Subsystem if optional else None

            symbols = {"has_symbols": False, "exports": False, "imports": False}
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
                symbols["has_symbols"] = True
                symbols["exports"] = True
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT") and pe.DIRECTORY_ENTRY_IMPORT:
                symbols["has_symbols"] = True
                symbols["imports"] = True

            symbols["timestamp"] = pe.FILE_HEADER.TimeDateStamp

            return {
                "parsed": True,
                "arch": arch,
                "bitness": bitness,
                "endian": "little",
                "machine": machine,
                "subsystem": subsystem,
                "stripped": not symbols["has_symbols"],
                "symbols": symbols,
            }
        except Exception as exc:  # noqa: BLE001
            return {"parsed": False, "error": str(exc)}

    def _inspect_pe_struct(self, path: Path) -> dict[str, Any]:
        """Minimal PE header parsing via struct.unpack."""
        try:
            with open(path, "rb") as f:
                data = f.read(256)
        except OSError as exc:
            return {"parsed": False, "error": str(exc)}

        if len(data) < 64 or data[:2] != b"MZ":
            return {"parsed": False, "error": "not a valid PE file"}

        pe_offset = struct.unpack("<L", data[60:64])[0]
        if len(data) < pe_offset + 26:
            try:
                with open(path, "rb") as f:
                    f.seek(pe_offset)
                    pe_header = f.read(26)
            except OSError as exc:
                return {"parsed": False, "error": str(exc)}
        else:
            pe_header = data[pe_offset : pe_offset + 26]

        if len(pe_header) < 26 or pe_header[:4] != b"PE\x00\x00":
            return {"parsed": False, "error": "invalid PE signature"}

        machine = struct.unpack("<H", pe_header[4:6])[0]
        arch, bitness = self._PE_MACHINE_MAP.get(machine, ("unknown", 0))

        # Optional header magic -> bitness refinement
        if len(pe_header) >= 24:
            optional_magic = struct.unpack("<H", pe_header[24:26])[0]
            if optional_magic == 0x10B:
                bitness = 32
            elif optional_magic == 0x20B:
                bitness = 64

        return {
            "parsed": True,
            "arch": arch,
            "bitness": bitness,
            "endian": "little",
            "machine": machine,
            "stripped": None,
            "symbols": {"has_symbols": None},
            "note": "fallback struct parser; pefile not installed",
        }

    def _sample_strings(self, path: Path, n: int = 200) -> list[str]:
        """Read up to n printable ASCII strings of length >= 4 from the file."""
        results: list[str] = []
        current = bytearray()

        try:
            with open(path, "rb") as f:
                while len(results) < n:
                    chunk = f.read(8192)
                    if not chunk:
                        if current:
                            candidate = current.decode("ascii", "ignore")
                            if candidate:
                                results.append(candidate)
                        break

                    for byte in chunk:
                        if 32 <= byte <= 126:
                            current.append(byte)
                        else:
                            if len(current) >= 4:
                                candidate = current.decode("ascii", "ignore")
                                if candidate:
                                    results.append(candidate)
                            current = bytearray()
        except OSError:
            return results

        return results[:n]

    def _compute_entropy(self, path: Path) -> float | None:
        """Compute Shannon entropy (base-2) of the file bytes."""
        counts = [0] * 256
        length = 0
        try:
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    length += len(chunk)
                    for byte in chunk:
                        counts[byte] += 1
        except OSError:
            return None

        if length == 0:
            return 0.0

        entropy = 0.0
        for count in counts:
            if count == 0:
                continue
            p = count / length
            entropy -= p * math.log2(p)

        return entropy

    def _scan_packer_indicators(
        self, strings: list[str], entropy: float | None
    ) -> list[str]:
        """Return notable indicators based on string signatures and entropy."""
        indicators: list[str] = []

        if entropy is not None:
            if entropy > 7.5:
                indicators.append("high file entropy (possible packing/encryption)")
            elif entropy > 6.8:
                indicators.append("elevated file entropy")

        joined = "\n".join(strings).lower()
        for packer, sigs in self._PACKER_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in joined:
                    indicators.append(f"{packer} packer/protector signature")
                    break

        return indicators

    def _detect_signature(self, strings: list[str], signatures: dict[str, list[str]]) -> str | None:
        """Return the first matching signature category found in strings."""
        joined = "\n".join(strings)
        for category, sigs in signatures.items():
            for sig in sigs:
                if sig in joined:
                    return category
        return None

    def _score_sources(self, profile: TriageProfile) -> dict[str, float]:
        """Recalculate per-source confidences and return an aggregate map.

        The returned dictionary keeps per-source confidences and adds an
        overall entry that combines them using a simple weighted average.
        """
        confidences: dict[str, float] = dict(profile.confidence)

        # Magic/header agreement bonus
        if confidences.get("magic", 0) > 0.8 and confidences.get("header", 0) > 0.8:
            confidences["agreement"] = 0.95
        elif confidences.get("magic", 0) > 0.5:
            confidences["agreement"] = 0.7
        else:
            confidences["agreement"] = 0.3

        # Entropy-derived confidence only if high enough to be meaningful
        if profile.packed_entropy is not None:
            if profile.packed_entropy > 7.5:
                confidences["entropy_signal"] = 0.85
            else:
                confidences["entropy_signal"] = 0.5

        # Strings confidence only if we found useful evidence
        if len(profile.evidence.get("strings_sample", [])) > 20:
            confidences["strings_signal"] = 0.75

        # Overall weighted score
        weights = {
            "magic": 0.25,
            "header": 0.30,
            "symbols": 0.15,
            "strings": 0.15,
            "entropy": 0.10,
            "agreement": 0.05,
        }
        total_weight = 0.0
        weighted_sum = 0.0
        for key, weight in weights.items():
            value = confidences.get(key, 0.0)
            weighted_sum += value * weight
            total_weight += weight

        if total_weight > 0:
            confidences["overall"] = round(weighted_sum / total_weight, 3)
        else:
            confidences["overall"] = 0.0

        return confidences


def format_triage(profile: TriageProfile) -> str:
    """Return a human-friendly ASCII summary of a TriageProfile."""
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("TRIAGE PROFILE")
    lines.append("=" * 60)
    lines.append(f"Format      : {profile.format}")
    lines.append(f"Arch        : {profile.arch}")
    lines.append(f"Bitness     : {profile.bitness}")
    lines.append(f"Endian      : {profile.endian}")
    lines.append(f"Stripped    : {profile.stripped}")
    lines.append(f"Linker      : {profile.linker or 'unknown'}")
    lines.append(f"Compiler    : {profile.compiler or 'unknown'}")
    if profile.packed_entropy is not None:
        lines.append(f"Entropy     : {profile.packed_entropy:.3f}")
    else:
        lines.append("Entropy     : N/A")
    lines.append("-" * 60)

    if profile.indicators:
        lines.append("Indicators:")
        for indicator in profile.indicators:
            lines.append(f"  - {indicator}")
    else:
        lines.append("Indicators  : none")
    lines.append("-" * 60)

    if profile.confidence:
        lines.append("Confidence:")
        for source, score in sorted(profile.confidence.items()):
            bar_len = int(round(score * 20))
            bar = "#" * bar_len + "-" * (20 - bar_len)
            lines.append(f"  {source:20s} [{bar}] {score:.2f}")
    else:
        lines.append("Confidence  : none")
    lines.append("=" * 60)

    return "\n".join(lines) + "\n"
