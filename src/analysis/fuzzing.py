"""Reproducible AFL++ campaign lifecycle and crash-corpus management."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


MAX_SEED_BYTES = 16 * 1024 * 1024
MAX_SEEDS = 100_000


@dataclass(frozen=True)
class FuzzTarget:
    binary: str
    arguments: tuple[str, ...] = ("@@",)
    input_mode: str = "file"
    environment: dict[str, str] = field(default_factory=dict, compare=False)
    timeout_ms: int = 1_000
    memory_limit_mb: int = 512

    def __post_init__(self) -> None:
        binary = Path(self.binary)
        if not binary.is_file():
            raise ValueError("fuzz target must be a regular file")
        if self.input_mode not in {"file", "stdin"}:
            raise ValueError("input_mode must be file or stdin")
        placeholders = sum(argument.count("@@") for argument in self.arguments)
        if self.input_mode == "file" and placeholders != 1:
            raise ValueError("file-mode fuzz target requires exactly one @@ placeholder")
        if self.input_mode == "stdin" and placeholders:
            raise ValueError("stdin-mode fuzz target must not contain @@")
        if not 10 <= self.timeout_ms <= 600_000 or not 16 <= self.memory_limit_mb <= 1_048_576:
            raise ValueError("fuzz resource limits are invalid")


@dataclass(frozen=True)
class FuzzPlan:
    argv: tuple[str, ...]
    input_dir: str
    output_dir: str
    target_sha256: str
    mode: str
    environment: dict[str, str]


class SeedCorpus:
    """Content-addressed, bounded seed corpus builder."""

    def build(self, seeds: Iterable[str | Path | bytes], destination: str | Path) -> list[dict[str, Any]]:
        output = Path(destination)
        output.mkdir(parents=True, exist_ok=True)
        records: list[dict[str, Any]] = []
        seen: set[str] = set()
        for seed in seeds:
            payload = bytes(seed) if isinstance(seed, bytes) else Path(seed).read_bytes()
            if not payload:
                payload = b"\x00"
            if len(payload) > MAX_SEED_BYTES:
                raise ValueError("seed exceeds size limit")
            digest = hashlib.sha256(payload).hexdigest()
            if digest in seen:
                continue
            seen.add(digest)
            name = f"id_{len(records):06d}_{digest[:12]}"
            (output / name).write_bytes(payload)
            records.append({"name": name, "sha256": digest, "size": len(payload)})
            if len(records) >= MAX_SEEDS:
                raise ValueError("seed count exceeds safety limit")
        if not records:
            return self.build([b"\x00"], output)
        return records


class AflPlusPlusCampaign:
    """Build version-independent AFL++ argv plans and parse durable outcomes."""

    def plan(
        self,
        target: FuzzTarget,
        input_dir: str | Path,
        output_dir: str | Path,
        *,
        mode: str = "auto",
        dictionary: str | Path | None = None,
        deterministic: bool = False,
        instance: str = "default",
    ) -> FuzzPlan:
        executable = shutil.which("afl-fuzz")
        if executable is None:
            raise RuntimeError("afl-fuzz is unavailable")
        if mode not in {"auto", "instrumented", "qemu", "frida", "unicorn"}:
            raise ValueError("unsupported AFL++ mode")
        argv = [
            executable, "-i", str(Path(input_dir).resolve(strict=True)),
            "-o", str(Path(output_dir).resolve()),
            "-t", str(target.timeout_ms), "-m", str(target.memory_limit_mb),
            "-S", instance,
        ]
        if mode == "qemu":
            argv.append("-Q")
        elif mode == "frida":
            argv.append("-O")
        elif mode == "unicorn":
            argv.append("-U")
        if deterministic:
            argv.extend(["-p", "explore"])
        if dictionary is not None:
            argv.extend(["-x", str(Path(dictionary).resolve(strict=True))])
        argv.extend(["--", str(Path(target.binary).resolve(strict=True)), *target.arguments])
        digest = hashlib.sha256(Path(target.binary).read_bytes()).hexdigest()
        environment = {"AFL_NO_UI": "1", "AFL_SKIP_CPUFREQ": "1", **target.environment}
        return FuzzPlan(tuple(argv), str(Path(input_dir).resolve()), str(Path(output_dir).resolve()), digest, mode, environment)

    @staticmethod
    def status(output_dir: str | Path, instance: str = "default") -> dict[str, Any]:
        root = Path(output_dir) / instance
        stats: dict[str, Any] = {}
        stats_file = root / "fuzzer_stats"
        if stats_file.is_file():
            for line in stats_file.read_text(errors="replace").splitlines():
                if ":" in line:
                    key, value = line.split(":", 1)
                    stats[key.strip()] = value.strip()
        crashes = sorted(path for path in (root / "crashes").glob("id:*")) if (root / "crashes").is_dir() else []
        hangs = sorted(path for path in (root / "hangs").glob("id:*")) if (root / "hangs").is_dir() else []
        return {
            "stats": stats,
            "crashes": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in crashes],
            "hangs": [{"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in hangs],
            "queue_count": len(list((root / "queue").glob("id:*"))) if (root / "queue").is_dir() else 0,
        }

    @staticmethod
    def minimization_plan(target: FuzzTarget, crashing_input: str | Path, output: str | Path) -> tuple[str, ...]:
        executable = shutil.which("afl-tmin")
        if executable is None:
            raise RuntimeError("afl-tmin is unavailable")
        argv = [
            executable, "-i", str(Path(crashing_input).resolve(strict=True)),
            "-o", str(Path(output).resolve()), "-t", str(target.timeout_ms),
            "-m", str(target.memory_limit_mb), "--", str(Path(target.binary).resolve(strict=True)),
            *target.arguments,
        ]
        return tuple(argv)


def write_campaign_manifest(plan: FuzzPlan, seeds: list[dict[str, Any]], path: str | Path) -> None:
    payload = {
        "schema_version": "angerona.fuzz-campaign/v1",
        "target_sha256": plan.target_sha256,
        "mode": plan.mode,
        "argv": list(plan.argv),
        "environment": dict(sorted(plan.environment.items())),
        "seeds": seeds,
    }
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True))
