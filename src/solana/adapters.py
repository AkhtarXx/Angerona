"""Optional Solana/SBF reverse-engineering backend adapters.

The external Solana RE plugins run inside their native tools:

* Ghidra: a Solana/eBPF language/extension for headless analysis.
* IDA Pro: Decurity-style Solana processor under IDA's ``procs`` directory.
* Binary Ninja: OtterSec's Solana eBPF plugin, when Binary Ninja is available.

This module deliberately does not install or mutate tool directories.  It only
detects capabilities and gives the pipeline a stable, engine-neutral view of
what Solana-specific help is available on the host.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Any, Iterable

from src.config import Config
from src.engines.selector import _elf_machine


SOLANA_ELF_MACHINES: dict[int, str] = {
    0x00F7: "generic_ebpf",
    0x0107: "solana_sbf",
}


@dataclass(frozen=True)
class SolanaAdapterStatus:
    """Detected state for one optional Solana RE backend adapter."""

    name: str
    engine: str
    available: bool
    installed: bool
    reason: str
    path: str | None = None
    capabilities: tuple[str, ...] = ()
    install_hint: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def is_solana_elf(binary: str | Path) -> bool:
    """Return whether ``binary`` is an ELF using a known eBPF/Solana machine ID."""

    machine = _elf_machine(Path(binary))
    return machine in SOLANA_ELF_MACHINES


def collect_solana_adapter_status(config: Config) -> list[SolanaAdapterStatus]:
    """Detect all Solana-specific RE adapters without changing host state."""

    return [
        _detect_ghidra_solana(config),
        _detect_ida_solana(config),
        _detect_binja_solana(),
        _detect_cli_utility(
            name="utility-radare2",
            binaries=("r2", "radare2"),
            capabilities=(
                "secondary_disassembly",
                "function_discovery",
                "strings_symbols_crosscheck",
                "json_metadata",
            ),
            install_hint="Install radare2/r2 to add an engine-neutral disassembly cross-check.",
        ),
        _detect_cli_utility(
            name="utility-llvm-objdump",
            binaries=("llvm-objdump",),
            capabilities=(
                "elf_section_headers",
                "sbf_disassembly_when_supported",
                "relocation_symbol_crosscheck",
            ),
            install_hint="Install LLVM llvm-objdump to add a lightweight ELF/SBF disassembly cross-check.",
        ),
        _detect_cli_utility(
            name="utility-anchor-cli",
            binaries=("anchor",),
            capabilities=(
                "anchor_version_context",
                "anchor_idl_project_context",
                "anchor_framework_semantics",
            ),
            install_hint="Install anchor-cli to add Anchor framework/IDL context when project files are available.",
        ),
        _detect_cli_utility(
            name="utility-solana-cli",
            binaries=("solana",),
            capabilities=(
                "solana_cli_version_context",
                "public_program_metadata_when_explicitly_requested",
            ),
            install_hint="Install solana-cli to add Solana CLI context. Network/program lookups stay opt-in.",
        ),
    ]


def ghidra_solana_language(config: Config) -> str | None:
    """Return the strongest installed Ghidra language ID for Solana/eBPF."""

    status = _detect_ghidra_solana(config)
    if not status.available or not status.path:
        return None
    base = Path(status.path)
    if _contains_any(base, ("eBPFSol.ldefs", "eBPFSol.slaspec", "eBPFSol.sla")):
        return "eBPFSol:LE:64:default"
    if _contains_any(base, ("eBPF.ldefs", "eBPF_le.slaspec", "eBPF_le.sla")):
        return "eBPF:LE:64:default"
    return None


def preferred_solana_adapters(config: Config, engine: str | None = None) -> list[SolanaAdapterStatus]:
    """Return adapter order for a Solana scan.

    The active engine stays first.  Other available adapters are second-opinion
    evidence sources, not hard dependencies.
    """

    requested = (engine or config.engine or "").lower()
    statuses = collect_solana_adapter_status(config)
    rank = {
        requested: 0,
        "ghidra": 1 if requested != "ghidra" else 0,
        "ida": 2 if requested != "ida" else 0,
        "binaryninja": 3 if requested != "binaryninja" else 0,
        "utility": 10,
    }
    return sorted(
        statuses,
        key=lambda s: (
            not s.available,
            rank.get(s.engine, 50),
            s.name,
        ),
    )


def probe_solana_adapter_runtime(
    config: Config,
    binary: str | Path,
    *,
    engines: tuple[str, ...] = ("ghidra", "ida"),
    max_functions: int = 5,
    timeout: int = 300,
) -> list[SolanaAdapterStatus]:
    """Run a small real analysis probe and return runtime-validated statuses.

    This is intentionally explicit because it launches heavyweight RE tools.
    Static detection answers "is something installed?"; this function answers
    "can Angerona actually analyze this Solana binary through that adapter?".
    """

    from src.config import load_config

    binary_path = Path(binary).expanduser().resolve()
    static_by_engine = {
        status.engine: status for status in collect_solana_adapter_status(config)
    }
    results: list[SolanaAdapterStatus] = []

    for engine_name in engines:
        base = static_by_engine.get(engine_name)
        if base is None:
            continue
        if engine_name == "ghidra":
            engine_config = load_config("ghidra")
            ready, ready_reason = engine_config.ghidra_ready()
            if not ready:
                results.append(replace(
                    base,
                    available=False,
                    installed=base.installed,
                    reason=f"Ghidra runtime probe skipped: {ready_reason}",
                ))
                continue
            try:
                from src.engines.ghidra import GhidraEngine

                data = GhidraEngine(engine_config).analyze(
                    binary_path,
                    decompile=True,
                    max_functions=max_functions,
                    force=True,
                    timeout=timeout,
                )
                funcs = data.get("functions") or []
                decompiled = sum(1 for fn in funcs if fn.get("decompiled"))
                if not funcs:
                    raise RuntimeError("probe produced zero functions")
                expected_language = ghidra_solana_language(engine_config)
                expected_processor = (
                    expected_language.split(":", 1)[0]
                    if expected_language
                    else None
                )
                observed_processor = (
                    (data.get("metadata") or {}).get("processor")
                    or data.get("processor")
                )
                if (
                    expected_processor == "eBPFSol"
                    and observed_processor != expected_processor
                ):
                    raise RuntimeError(
                        "Solana extension was detected but Ghidra used "
                        f"{observed_processor or 'an unknown processor'}"
                    )
                results.append(replace(
                    base,
                    available=True,
                    installed=True,
                    reason=(
                        f"Ghidra runtime probe passed: {len(funcs)} functions, "
                        f"{decompiled} decompiled, processor={observed_processor}"
                    ),
                ))
            except Exception as exc:  # noqa: BLE001
                results.append(replace(
                    base,
                    available=False,
                    installed=base.installed,
                    reason=f"Ghidra runtime probe failed: {exc}",
                ))
        elif engine_name == "ida":
            engine_config = load_config("ida")
            ready, ready_reason = engine_config.ida_ready()
            if not ready:
                results.append(replace(
                    base,
                    available=False,
                    installed=base.installed,
                    reason=f"IDA runtime probe skipped: {ready_reason}",
                ))
                continue
            try:
                from src.engines.ida import IdaEngine

                data = IdaEngine(engine_config).analyze(
                    binary_path,
                    decompile=True,
                    max_functions=max_functions,
                    force=True,
                    timeout=timeout,
                )
                funcs = data.get("functions") or []
                decompiled = sum(1 for fn in funcs if fn.get("decompiled"))
                if not funcs:
                    raise RuntimeError("probe produced zero functions")
                results.append(replace(
                    base,
                    available=True,
                    installed=True,
                    reason=(
                        f"IDA runtime probe passed: {len(funcs)} functions, "
                        f"{decompiled} decompiled"
                    ),
                ))
            except Exception as exc:  # noqa: BLE001
                results.append(replace(
                    base,
                    available=False,
                    installed=base.installed,
                    reason=f"IDA runtime probe failed: {exc}",
                ))

    return results


def _detect_ghidra_solana(config: Config) -> SolanaAdapterStatus:
    candidates = list(_env_paths("ANGERONA_GHIDRA_SOLANA_EXTENSION"))
    if config.ghidra_install:
        ghidra = config.ghidra_install
        candidates.extend(
            [
                ghidra / "Ghidra" / "Extensions" / "Solana-eBPF-for-Ghidra",
                ghidra / "Ghidra" / "Extensions" / "eBPF-for-Ghidra",
                ghidra / "Ghidra" / "Extensions" / "eBPFSol",
                ghidra / "Ghidra" / "Processors" / "eBPFSol",
                ghidra / "Ghidra" / "Processors" / "eBPF",
            ]
        )
    home = os.environ.get("HOME")
    if home:
        candidates.extend(Path(home).glob(".ghidra/.*/*/Extensions/Solana-eBPF-for-Ghidra"))
        candidates.extend(Path(home).glob(".ghidra/.*/*/Extensions/eBPF-for-Ghidra"))
        candidates.extend(Path(home).glob(".ghidra/.*/*/Extensions/eBPFSol"))
        candidates.extend(Path(home).glob(".ghidra/*/Extensions/Solana-eBPF-for-Ghidra"))
        candidates.extend(Path(home).glob(".ghidra/*/Extensions/eBPF-for-Ghidra"))
        candidates.extend(Path(home).glob(".ghidra/*/Extensions/eBPFSol"))

    existing = _existing_dirs(candidates)
    for base in existing:
        if _contains_any(base, ("eBPFSol.ldefs", "eBPFSol.slaspec", "eBPFSol.sla")):
            return SolanaAdapterStatus(
                name="ghidra-solana-ebpf",
                engine="ghidra",
                available=True,
                installed=True,
                reason="Ghidra Solana/eBPF language files detected",
                path=str(base),
                capabilities=(
                    "sbf_disassembly",
                    "sbf_decompile",
                    "solana_syscall_signatures",
                    "headless_analysis",
                ),
            )
    for base in existing:
        if _contains_any(base, ("eBPF.ldefs", "eBPF_le.slaspec", "eBPF_le.sla")):
            return SolanaAdapterStatus(
                name="ghidra-solana-ebpf",
                engine="ghidra",
                available=True,
                installed=True,
                reason=(
                    "Ghidra generic eBPF processor detected; Solana-specific "
                    "extension not detected"
                ),
                path=str(base),
                capabilities=(
                    "ebpf_disassembly",
                    "ebpf_decompile",
                    "headless_analysis",
                ),
                install_hint=(
                    "Install a Solana-specific Ghidra extension for richer "
                    "syscall/account semantics."
                ),
            )

    ready, ready_reason = config.ghidra_ready()
    reason = (
        "Ghidra ready but Solana/eBPF language extension was not detected"
        if ready
        else f"Ghidra unavailable: {ready_reason}"
    )
    return SolanaAdapterStatus(
        name="ghidra-solana-ebpf",
        engine="ghidra",
        available=False,
        installed=ready,
        reason=reason,
        install_hint=(
            "Install a compatible Solana/eBPF Ghidra extension and/or set "
            "ANGERONA_GHIDRA_SOLANA_EXTENSION to its extension directory."
        ),
    )


def _detect_ida_solana(config: Config) -> SolanaAdapterStatus:
    candidates = list(_env_paths("ANGERONA_IDA_SOLANA_PROCESSOR"))
    if config.ida_install:
        candidates.extend(
            [
                config.ida_install / "procs",
                config.ida_install / "plugins",
            ]
        )
    loader_path = (
        config.ida_install / "loaders" / "solana_sbf.py"
        if config.ida_install
        else None
    )
    loader_available = bool(loader_path and loader_path.is_file() and config.idat)
    ready, ready_reason = config.ida_ready()

    for base in _existing_dirs(candidates):
        if (
            (base / "solana-init.py").is_file()
            and (base / "solana" / "processor.py").is_file()
        ) or _contains_any(base, ("solana-init.py", "processor.py")):
            available = bool(ready and loader_available)
            if available:
                reason = (
                    "IDA Solana processor and Angerona custom SBF loader detected; "
                    "idat headless Solana route is available"
                )
            elif not ready:
                reason = f"IDA Solana processor detected but IDA unavailable: {ready_reason}"
            else:
                reason = (
                    "IDA Solana processor detected but Angerona custom SBF loader "
                    "or idat executable is missing"
                )
            return SolanaAdapterStatus(
                name="ida-solana-processor",
                engine="ida",
                available=available,
                installed=True,
                reason=reason,
                path=str(base),
                capabilities=(
                    "sbf_disassembly",
                    "sbf_custom_loader",
                    "headless_idat_analysis",
                    "json_export",
                    "relocation_recovery",
                    "string_recovery",
                    "flirt_signature_input",
                ),
                install_hint=(
                    None
                    if available
                    else "Install loaders/solana_sbf.py and ensure IDA idat is available."
                ),
            )

    reason = (
        "IDA ready but Solana processor was not detected"
        if ready
        else f"IDA unavailable: {ready_reason}"
    )
    return SolanaAdapterStatus(
        name="ida-solana-processor",
        engine="ida",
        available=False,
        installed=ready,
        reason=reason,
        install_hint=(
            "Install the Solana processor into IDA's procs directory or set "
            "ANGERONA_IDA_SOLANA_PROCESSOR to the processor root."
        ),
    )


def _detect_binja_solana() -> SolanaAdapterStatus:
    candidates = list(_env_paths("ANGERONA_BINJA_SOLANA_PLUGIN"))
    for base in _existing_dirs(candidates):
        if (base / "solanaview.py").is_file() and (base / "types.c").is_file():
            return SolanaAdapterStatus(
                name="binja-solana-ebpf",
                engine="binaryninja",
                available=True,
                installed=True,
                reason="Binary Ninja Solana plugin files detected",
                path=str(base),
                capabilities=(
                    "llil_lift",
                    "solana_memory_map",
                    "solana_sdk_types",
                    "anchor_idl_helpers",
                ),
            )

    if shutil.which("binaryninja") or shutil.which("binaryninja-headless"):
        reason = "Binary Ninja found but Solana eBPF plugin was not detected"
    else:
        reason = "Binary Ninja was not detected on PATH"
    return SolanaAdapterStatus(
        name="binja-solana-ebpf",
        engine="binaryninja",
        available=False,
        installed=False,
        reason=reason,
        install_hint=(
            "Install OtterSec's Binary Ninja Solana plugin and/or set "
            "ANGERONA_BINJA_SOLANA_PLUGIN to the plugin directory."
        ),
    )


def _detect_cli_utility(
    *,
    name: str,
    binaries: tuple[str, ...],
    capabilities: tuple[str, ...],
    install_hint: str,
) -> SolanaAdapterStatus:
    for binary in binaries:
        path = shutil.which(binary)
        if path:
            return SolanaAdapterStatus(
                name=name,
                engine="utility",
                available=True,
                installed=True,
                reason=f"{binary} detected on PATH; available as optional Solana utility evidence",
                path=path,
                capabilities=capabilities,
            )
    return SolanaAdapterStatus(
        name=name,
        engine="utility",
        available=False,
        installed=False,
        reason=f"{'/'.join(binaries)} was not detected on PATH",
        capabilities=capabilities,
        install_hint=install_hint,
    )


def _env_paths(var: str) -> Iterable[Path]:
    raw = os.environ.get(var, "")
    for part in raw.split(os.pathsep):
        part = part.strip()
        if part:
            yield Path(part).expanduser()


def _existing_dirs(paths: Iterable[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for path in paths:
        try:
            resolved = path.resolve()
        except Exception:
            resolved = path
        key = str(resolved)
        if key in seen or not path.is_dir():
            continue
        seen.add(key)
        out.append(path)
    return out


def _contains_any(base: Path, names: tuple[str, ...]) -> bool:
    for name in names:
        if any(base.rglob(name)):
            return True
    return False
