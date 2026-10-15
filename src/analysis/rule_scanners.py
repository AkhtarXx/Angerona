"""Normalized capa and YARA results with rule provenance."""

from __future__ import annotations

import hashlib
import json
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable


@dataclass(frozen=True)
class RuleMatch:
    engine: str
    rule: str
    namespace: str | None
    target_sha256: str
    locations: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict, compare=False)

    def as_dict(self) -> dict[str, Any]:
        return {
            "engine": self.engine, "rule": self.rule, "namespace": self.namespace,
            "target_sha256": self.target_sha256, "locations": list(self.locations),
            "tags": list(self.tags), "metadata": dict(self.metadata),
        }


class CapaAdapter:
    def plan(
        self,
        target: str | Path,
        rules: str | Path | None = None,
        signatures: str | Path | None = None,
    ) -> tuple[str, ...]:
        executable = shutil.which("capa")
        if executable is None:
            raise RuntimeError("capa is unavailable")
        argv = [executable, "--json"]
        if rules is not None:
            argv.extend(["--rules", str(Path(rules).resolve(strict=True))])
        if signatures is not None:
            argv.extend(["--signatures", str(Path(signatures).resolve(strict=True))])
        argv.append(str(Path(target).resolve(strict=True)))
        return tuple(argv)

    def ingest(self, payload: dict[str, Any], *, target_sha256: str) -> list[RuleMatch]:
        matches: list[RuleMatch] = []
        for name, row in sorted((payload.get("rules") or {}).items()):
            meta = row.get("meta") or {}
            locations: set[str] = set()
            for match_group in row.get("matches") or []:
                for item in match_group if isinstance(match_group, list) else [match_group]:
                    address = item.get("address") if isinstance(item, dict) else None
                    if address is not None:
                        locations.add(str(address))
            matches.append(RuleMatch(
                "capa", str(name), meta.get("namespace"), target_sha256,
                tuple(sorted(locations)), tuple(sorted(
                    a if isinstance(a, str) else json.dumps(a, sort_keys=True)
                    for a in (meta.get("attack") or [])
                )), dict(meta),
            ))
        return matches


class YaraAdapter:
    def scan(self, target: str | Path, rule_paths: Iterable[str | Path]) -> list[RuleMatch]:
        try:
            import yara
        except ImportError as exc:
            raise RuntimeError("YARA scanning requires yara-python") from exc
        target_path = Path(target).resolve(strict=True)
        digest = hashlib.sha256(target_path.read_bytes()).hexdigest()
        filepaths = {f"rules_{index}": str(Path(path).resolve(strict=True)) for index, path in enumerate(rule_paths)}
        if not filepaths:
            raise ValueError("at least one YARA rule file is required")
        rules = yara.compile(filepaths=filepaths)
        result: list[RuleMatch] = []
        for match in rules.match(str(target_path), timeout=60):
            offsets: list[str] = []
            for string in match.strings:
                instances = getattr(string, "instances", None)
                if instances is not None:
                    offsets.extend(f"0x{instance.offset:x}" for instance in instances)
                elif isinstance(string, tuple):
                    offsets.append(f"0x{int(string[0]):x}")
            result.append(RuleMatch(
                "yara", match.rule, getattr(match, "namespace", None), digest,
                tuple(sorted(offsets)), tuple(sorted(match.tags)), dict(match.meta),
            ))
        return result


def write_rule_report(matches: Iterable[RuleMatch], path: str | Path) -> None:
    rows = [match.as_dict() for match in matches]
    Path(path).write_text(json.dumps({
        "schema_version": "angerona.rule-matches/v1", "matches": rows,
    }, indent=2, sort_keys=True))
