"""Compiler personality / obfuscation detection.

Heuristically determines the toolchain personality of a binary (compiler,
linker, packer, protector) and flags likely obfuscation indicators.

Based on Chapter 19/20 vocabulary of *The IDA Pro Book*: compiler-specific
artifacts (startup signatures, runtime library names, section names, entry-point
patterns) are observable evidence, while obfuscation raises entropy, anti-
analysis strings, and control-flow anomalies.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _shannon_entropy(data: bytes) -> float:
    """Return the Shannon entropy of ``data`` in bits per byte."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    entropy = 0.0
    for c in counts:
        if c == 0:
            continue
        p = c / total
        entropy -= p * math.log2(p)
    return entropy


@dataclass
class CompilerPersonality:
    """Detected toolchain personality and confidence."""

    compiler: str | None = None
    compiler_confidence: float = 0.0
    linker: str | None = None
    linker_confidence: float = 0.0
    packer: str | None = None
    packer_confidence: float = 0.0
    protector: str | None = None
    protector_confidence: float = 0.0
    language_runtime: str | None = None
    notes: list[str] = field(default_factory=list)


@dataclass
class ObfuscationProfile:
    """Obfuscation and anti-analysis heuristics."""

    entropy: float = 0.0
    high_entropy: bool = False
    stripped: bool = False
    section_anomalies: list[str] = field(default_factory=list)
    anti_debug_strings: list[str] = field(default_factory=list)
    vm_bytecode_signatures: list[str] = field(default_factory=list)
    import_table_tiny: bool = False
    import_table_huge: bool = False
    suspected_obfuscation: bool = False
    suggested_backend: str = "none"


class CompilerPersonalityDetector:
    """Detect compiler / packer / protector from binary content and metadata."""

    # Compiler signatures: library names, startup object names, section names.
    _COMPILER_HINTS: dict[str, dict[str, list[str]]] = {
        "msvc": {
            "libs": [
                "msvcrt", "msvcr", "msvcp", "vcruntime",
                "ucrtbase", "kernel32", "ntdll",
            ],
            "sections": [r"\.text$", r"\.rdata$", r"\.data$", r"\.pdata$", r"\.xdata$"],
            "strings": ["Visual C++", "Microsoft Visual"],
        },
        "gcc": {
            "libs": ["libc", "libgcc_s", "libstdc++", "ld-linux"],
            "sections": [r"\.gcc_except_table", r"\.gnu", r"\.note\.gcc"],
            "strings": ["GCC:", "__GLIBC__"],
        },
        "clang": {
            "libs": ["libc++", "clang_rt"],
            "sections": ["__llvm_prf", "__llvm_cov"],
            "strings": ["clang version"],
        },
        "delphi": {
            "libs": ["borlndmm", "rtl"],
            "sections": ["CODE", "DATA", "BSS", r"\.itext"],
            "strings": ["Borland", "Delphi"],
        },
        "go": {
            "libs": [],
            "sections": [r"\.go_buildinfo", r"\.gosymtab", r"\.gopclntab"],
            "strings": ["go.buildid", "runtime.g", "fmt.Println"],
        },
        "rust": {
            "libs": ["std-"],
            "sections": [r"\.rustc"],
            "strings": ["rust_panic", "RUST_BACKTRACE"],
        },
    }

    _PACKER_HINTS: dict[str, list[str]] = {
        "upx": ["UPX!", "UPX0", "UPX1", "UPX2", "upx -d"],
        "petite": ["Petite"],
        "aspack": ["ASPack"],
        "themida": ["Themida", "WinLicense"],
        "vmp": ["VMProtect"],
        "enigma": ["Enigma"],
        "arma": ["Armadillo"],
    }

    _PROTECTOR_HINTS: dict[str, list[str]] = {
        "vmp": ["VMProtect", "vmp0", "vmp1"],
        "themida": ["Themida", "WinLicense"],
        "safengine": ["Safengine"],
        "obsidium": ["Obsidium"],
        "telock": ["tElock"],
    }

    _ANTI_DEBUG_STRINGS: tuple[str, ...] = (
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtGlobalFlag",
        "QueryInformationProcess", "SetInformationThread", "OutputDebugString",
        "FindWindow", "NtSetInformationThread", "HideThreadFromDebugger",
        "IsProcessorFeaturePresent",
    )

    _VM_SIGNATURES: dict[str, list[str]] = {
        "x86_vm": ["PUSHEBP", "POPEBP", "VM_ENTER", "vm_enter"],
        "dotnet": [".NET", "mscorlib", "System.Reflection"],
        "java": ["java/lang", "Ljavax"],
        "solana_bpf": [" BPF]", "solana_program", "solana_sdk"],
        "evm": ["PUSH1", "PUSH2", "SSTORE", "JUMPI"],
    }

    def __init__(self, sample_bytes: bytes | None = None, strings: list[str] | None = None) -> None:
        self.sample = sample_bytes or b""
        self.strings = strings or []
        self._joined_strings = "\n".join(self.strings)
        self._lower_strings = self._joined_strings.lower()

    @classmethod
    def from_file(cls, path: str | Path, strings: list[str] | None = None) -> "CompilerPersonalityDetector":
        """Create a detector from a file path."""
        p = Path(path)
        data = b""
        if p.exists():
            data = p.read_bytes()
        return cls(sample_bytes=data, strings=strings)

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "CompilerPersonalityDetector":
        """Create a detector from an existing triage profile dictionary."""
        strings = profile.get("strings", []) or []
        data = b""
        if profile.get("sample_bytes"):
            data = profile["sample_bytes"]
        elif profile.get("path"):
            p = Path(profile["path"])
            if p.exists():
                data = p.read_bytes()
        return cls(sample_bytes=data, strings=strings)

    def detect(self) -> dict[str, Any]:
        """Run all detection heuristics and return a combined report."""
        personality = self.detect_personality()
        obfuscation = self.detect_obfuscation()
        suggestion = self.suggest_backend(obfuscation)
        return {
            "compiler": {
                "name": personality.compiler,
                "confidence": round(personality.compiler_confidence, 3),
            },
            "linker": {
                "name": personality.linker,
                "confidence": round(personality.linker_confidence, 3),
            },
            "packer": {
                "name": personality.packer,
                "confidence": round(personality.packer_confidence, 3),
            },
            "protector": {
                "name": personality.protector,
                "confidence": round(personality.protector_confidence, 3),
            },
            "language_runtime": personality.language_runtime,
            "obfuscation": {
                "entropy": round(obfuscation.entropy, 3),
                "high_entropy": obfuscation.high_entropy,
                "stripped": obfuscation.stripped,
                "section_anomalies": obfuscation.section_anomalies,
                "anti_debug_strings": obfuscation.anti_debug_strings,
                "vm_bytecode_signatures": obfuscation.vm_bytecode_signatures,
                "import_table_tiny": obfuscation.import_table_tiny,
                "import_table_huge": obfuscation.import_table_huge,
                "suspected_obfuscation": obfuscation.suspected_obfuscation,
            },
            "suggested_backend": suggestion,
            "notes": personality.notes,
        }

    def detect_personality(self) -> CompilerPersonality:
        """Infer compiler/linker/packer/protector from heuristics."""
        scores: dict[str, float] = {}
        notes: list[str] = []
        for compiler, hints in self._COMPILER_HINTS.items():
            score = 0.0
            for lib in hints["libs"]:
                if lib.lower() in self._lower_strings:
                    score += 0.2
            for section in hints["sections"]:
                if re.search(section, self._joined_strings, re.IGNORECASE):
                    score += 0.15
            for s in hints["strings"]:
                if s in self._joined_strings:
                    score += 0.25
            scores[compiler] = score

        compiler = max(scores, key=scores.get) if scores else None
        compiler_confidence = scores.get(compiler, 0.0) if compiler else 0.0
        if compiler_confidence > 1.0:
            compiler_confidence = 1.0
        elif compiler and compiler_confidence < 0.15:
            notes.append(f"{compiler} hint detected but confidence is low")

        packer, packer_confidence = self._best_match(self._PACKER_HINTS)
        protector, protector_confidence = self._best_match(self._PROTECTOR_HINTS)
        linker = self._detect_linker(compiler)
        language_runtime = self._detect_language_runtime()

        if packer_confidence > 0.5:
            notes.append(f"likely packed with {packer} (confidence {packer_confidence:.2f})")
        if protector_confidence > 0.5:
            notes.append(f"likely protected with {protector} (confidence {protector_confidence:.2f})")

        return CompilerPersonality(
            compiler=compiler,
            compiler_confidence=compiler_confidence,
            linker=linker,
            packer=packer,
            packer_confidence=packer_confidence,
            protector=protector,
            protector_confidence=protector_confidence,
            language_runtime=language_runtime,
            notes=notes,
        )

    def detect_obfuscation(self) -> ObfuscationProfile:
        """Compute obfuscation heuristics."""
        entropy = _shannon_entropy(self.sample)
        high_entropy = entropy >= 7.2
        anti_debug = [s for s in self._ANTI_DEBUG_STRINGS if s in self._joined_strings]
        vm_sigs: list[str] = []
        for vm, hints in self._VM_SIGNATURES.items():
            if any(h in self._joined_strings for h in hints):
                vm_sigs.append(vm)

        section_anomalies = self._section_anomalies()
        stripped = len(self.strings) < 30 and len(section_anomalies) == 0 and len(self.sample) > 4096

        # Import hints: look for common import patterns.
        import_count = self._rough_import_count()
        import_table_tiny = import_count < 3 and len(self.sample) > 8192
        import_table_huge = import_count > 512

        packer_name, packer_score = self._best_match(self._PACKER_HINTS)
        protector_name, protector_score = self._best_match(self._PROTECTOR_HINTS)
        suspected = bool(
            high_entropy
            or packer_name
            or protector_name
            or anti_debug
            or import_table_tiny
            or section_anomalies
        )

        backend = "none"
        if "vmp" in set(vm_sigs) or self._best_match(self._PROTECTOR_HINTS)[1] > 0.5:
            backend = "bochs_idb"
        elif "dotnet" in vm_sigs or "java" in vm_sigs:
            backend = "none"  # managed runtime: need different engine
        elif high_entropy:
            backend = "bochs_idb"

        return ObfuscationProfile(
            entropy=round(entropy, 3),
            high_entropy=high_entropy,
            stripped=stripped,
            section_anomalies=section_anomalies,
            anti_debug_strings=anti_debug,
            vm_bytecode_signatures=vm_sigs,
            import_table_tiny=import_table_tiny,
            import_table_huge=import_table_huge,
            suspected_obfuscation=suspected,
            suggested_backend=backend,
        )

    def suggest_backend(self, obfuscation: ObfuscationProfile | None = None) -> str:
        """Suggest an execution backend based on detected personality."""
        if obfuscation is None:
            obfuscation = self.detect_obfuscation()
        if obfuscation.vm_bytecode_signatures:
            if "solana_bpf" in obfuscation.vm_bytecode_signatures:
                return "custom_isa:solana-bpf"
            if "evm" in obfuscation.vm_bytecode_signatures:
                return "custom_isa:evm"
        if obfuscation.suspected_obfuscation and obfuscation.suggested_backend:
            return obfuscation.suggested_backend
        return "none"

    def _best_match(self, table: dict[str, list[str]]) -> tuple[str | None, float]:
        best_name: str | None = None
        best_score = 0.0
        for name, hints in table.items():
            score = sum(0.5 for h in hints if h in self._joined_strings or h.lower() in self._lower_strings)
            if score > best_score:
                best_score = score
                best_name = name
        return best_name, min(best_score, 1.0)

    def _detect_linker(self, compiler: str | None) -> str | None:
        if compiler == "gcc":
            return "ld/gnu"
        if compiler == "clang":
            return "ld.lld"
        if compiler == "msvc":
            return "link"
        if compiler == "go":
            return "go linker"
        if compiler == "rust":
            return "lld"
        return None

    def _detect_language_runtime(self) -> str | None:
        lower = self._lower_strings
        if "msvcrt" in lower and "msvcp" in lower:
            return "msvc_cpp"
        if "libstdc++" in lower or "libc++" in lower:
            return "cpp_stdlib"
        if "go.buildid" in lower:
            return "go"
        if "rustc" in lower:
            return "rust"
        if any(s in lower for s in ("python", "py_initialize")):
            return "python"
        if any(s in lower for s in ("jvm", "java/lang")):
            return "java"
        if any(s in lower for s in ("mscorlib", ".net")):
            return "dotnet"
        if "solana_program" in lower:
            return "solana_rust_c"
        return None

    def _section_anomalies(self) -> list[str]:
        anomalies: list[str] = []
        lower = self._lower_strings
        if "entropy" in lower and "high" in lower:
            anomalies.append("explicit entropy mention")
        # Common packer-specific section names.
        packer_sections = ["upx", "petite", "aspack", "vmp", " Themida"]
        for sec in packer_sections:
            if sec.lower() in lower:
                anomalies.append(f"packer section: {sec.strip()}")
        # Executable section with high entropy is flagged elsewhere.
        return anomalies

    def _rough_import_count(self) -> int:
        joined = self._joined_strings
        common_imports = [
            "kernel32", "ntdll", "user32", "advapi32", "shell32",
            "msvcrt", "libc", "libpthread", "libdl",
        ]
        count = 0
        for imp in common_imports:
            count += joined.lower().count(imp)
        return count
