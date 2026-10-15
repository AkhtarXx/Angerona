#!/usr/bin/env python3
"""Regenerate Angerona's mechanical codebase-memory documentation.

The semantic architecture/feature documents remain human-maintained. This script
owns the generated state blocks and the exhaustive symbol reference, then verifies
that every tracked source and test file is represented in the semantic catalogs.
"""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


REPO = Path(__file__).resolve().parent.parent
PROJECT_PREFIX = "home-ubuntu-akhtar-angerona."
AUTO_START = "<!-- codebase-docs:auto:start -->"
AUTO_END = "<!-- codebase-docs:auto:end -->"
MEMORY = REPO / "MEMORY.md"
DOC_INDEX = REPO / "docs" / "codebase" / "README.md"
SYMBOLS = REPO / "docs" / "codebase" / "SYMBOL_REFERENCE.md"
FEATURES = REPO / "docs" / "codebase" / "FEATURES.md"
TEST_STATUS = REPO / "docs" / "codebase" / "TESTING_AND_STATUS.md"

SOURCE_INPUTS = (
    "src/",
    "tests/",
    "benchmarks/",
    "scripts/",
    ".githooks/",
    "bin/",
    "docker/",
    "frontend/",
    "demo_flow.py",
    "pyproject.toml",
)


class RefreshError(RuntimeError):
    """Raised when documentation cannot be regenerated safely."""


@dataclass(frozen=True)
class Symbol:
    label: str
    file: str
    start: int
    end: int
    qualified_name: str
    signature: str = ""
    base_classes: str = ""


def _run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        args,
        cwd=REPO,
        text=True,
        capture_output=True,
        check=False,
    )
    if check and result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RefreshError(f"command failed ({' '.join(args)}): {detail}")
    return result


def _git(*args: str) -> str:
    return _run("git", *args).stdout.strip()


def _tracked_files(*patterns: str) -> list[str]:
    tracked_command = ["git", "ls-files"]
    tracked_command.extend(patterns)
    untracked_command = ["git", "ls-files", "--others", "--exclude-standard"]
    if patterns:
        untracked_command.append("--")
        untracked_command.extend(patterns)
    paths = set(_run(*tracked_command).stdout.splitlines())
    paths.update(_run(*untracked_command).stdout.splitlines())
    return sorted(path for path in paths if path)


def _source_inputs() -> list[str]:
    paths = []
    for path in _tracked_files():
        if any(path == prefix or path.startswith(prefix) for prefix in SOURCE_INPUTS):
            paths.append(path)
    return sorted(paths)


def _source_fingerprint(paths: list[str]) -> str:
    digest = hashlib.sha256()
    for relative in paths:
        path = REPO / relative
        if not path.is_file():
            continue
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def _parse_cli_json(output: str) -> dict[str, Any]:
    for line in reversed(output.splitlines()):
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise RefreshError("codebase-memory-mcp did not return a JSON object")


def _mcp(tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
    executable = shutil.which("codebase-memory-mcp")
    if not executable:
        raise RefreshError(
            "codebase-memory-mcp is required; install it before refreshing codebase docs"
        )
    result = _run(executable, "cli", tool, json.dumps(arguments, separators=(",", ":")))
    return _parse_cli_json(result.stdout)


def _index_repository() -> str:
    result = _mcp(
        "index_repository",
        {"repo_path": str(REPO), "mode": "fast", "persistence": True},
    )
    project = result.get("project")
    if not isinstance(project, str) or not project:
        raise RefreshError(f"index_repository returned no project: {result}")
    return project


def _current_project() -> str:
    result = _mcp("list_projects", {})
    for item in result.get("projects", []):
        if not isinstance(item, dict):
            continue
        root = item.get("root_path")
        if isinstance(root, str) and root.strip() and Path(root).resolve() == REPO:
            return str(item["name"])
    raise RefreshError("repository is not indexed; run without --check first")


def _graph_schema(project: str) -> dict[str, int]:
    result = _mcp("get_graph_schema", {"project": project})
    return {
        str(item["label"]): int(item["count"])
        for item in result.get("node_labels", [])
        if isinstance(item, dict) and "label" in item and "count" in item
    }


def _query_symbols(project: str, label: str) -> list[Symbol]:
    query = (
        f"MATCH (n:{label}) "
        "RETURN n.file_path AS file, n.start_line AS start_line, "
        "n.end_line AS end_line, n.qualified_name AS qualified_name, "
        "n.signature AS signature, n.base_classes AS base_classes "
        "ORDER BY file, start_line, qualified_name"
    )
    result = _mcp(
        "query_graph",
        {"project": project, "max_rows": 5000, "query": query},
    )
    symbols = []
    for row in result.get("rows", []):
        symbols.append(
            Symbol(
                label=label,
                file=str(row[0] or "(unknown)"),
                start=int(row[1] or 0),
                end=int(row[2] or 0),
                qualified_name=str(row[3] or ""),
                signature=_one_line(row[4]),
                base_classes=_one_line(row[5]),
            )
        )
    return symbols


def _one_line(value: Any) -> str:
    if value is None:
        return ""
    return " ".join(str(value).split())


def _python_ast_supplement(graph_symbols: list[Symbol]) -> list[Symbol]:
    seen = {
        (symbol.file, symbol.start, "Class" if symbol.label == "Class" else "Def")
        for symbol in graph_symbols
    }
    missing: list[Symbol] = []

    class Visitor(ast.NodeVisitor):
        def __init__(self, relative: str) -> None:
            self.relative = relative
            self.scopes: list[tuple[str, str]] = []

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            qualified = ".".join([scope[0] for scope in self.scopes] + [node.name])
            key = (self.relative, node.lineno, "Class")
            if key not in seen:
                missing.append(
                    Symbol(
                        label="Class",
                        file=self.relative,
                        start=node.lineno,
                        end=node.end_lineno or node.lineno,
                        qualified_name=qualified,
                        base_classes=", ".join(ast.unparse(base) for base in node.bases),
                    )
                )
            self.scopes.append((node.name, "Class"))
            self.generic_visit(node)
            self.scopes.pop()

        def _visit_function(
            self, node: ast.FunctionDef | ast.AsyncFunctionDef
        ) -> None:
            qualified = ".".join([scope[0] for scope in self.scopes] + [node.name])
            label = "Method" if self.scopes and self.scopes[-1][1] == "Class" else "Function"
            key = (self.relative, node.lineno, "Def")
            if key not in seen:
                signature = f"({ast.unparse(node.args)})"
                if node.returns is not None:
                    signature += f" -> {ast.unparse(node.returns)}"
                if isinstance(node, ast.AsyncFunctionDef):
                    qualified = f"async {qualified}"
                missing.append(
                    Symbol(
                        label=label,
                        file=self.relative,
                        start=node.lineno,
                        end=node.end_lineno or node.lineno,
                        qualified_name=qualified,
                        signature=_one_line(signature),
                    )
                )
            self.scopes.append((node.name, "Function"))
            self.generic_visit(node)
            self.scopes.pop()

        visit_FunctionDef = _visit_function
        visit_AsyncFunctionDef = _visit_function

    for relative in _tracked_files("*.py"):
        path = REPO / relative
        if not path.is_file():
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
        except (SyntaxError, UnicodeDecodeError) as exc:
            raise RefreshError(f"cannot parse tracked Python file {relative}: {exc}") from exc
        Visitor(relative).visit(tree)

    return sorted(
        missing,
        key=lambda item: (item.file, item.start, item.label, item.qualified_name),
    )


def _escape_code(value: str) -> str:
    return value.replace("`", "\\`")


def _symbol_line(symbol: Symbol) -> str:
    location = f"L{symbol.start}"
    if symbol.end and symbol.end != symbol.start:
        location += f"-L{symbol.end}"
    display = symbol.qualified_name
    if display.startswith(PROJECT_PREFIX):
        display = display[len(PROJECT_PREFIX) :]
    if symbol.label in {"Function", "Method"} and symbol.signature:
        display += symbol.signature
    if symbol.label == "Class" and symbol.base_classes:
        display += f" [bases: {symbol.base_classes}]"
    return f"- {location} | {symbol.label} | `{_escape_code(display)}`"


def _render_section(title: str, symbols: list[Symbol]) -> str:
    lines = [f"## {title}", ""]
    current = None
    for symbol in symbols:
        if symbol.file != current:
            current = symbol.file
            lines.extend((f"### `{_escape_code(current)}`", ""))
        lines.append(_symbol_line(symbol))
    lines.append("")
    return "\n".join(lines)


def _counts(symbols: list[Symbol]) -> dict[str, int]:
    return {
        label: sum(symbol.label == label for symbol in symbols)
        for label in ("Class", "Function", "Method")
    }


def _render_symbols(
    graph_symbols: list[Symbol], supplement: list[Symbol], head: str, fingerprint: str
) -> str:
    graph_symbols = sorted(
        graph_symbols,
        key=lambda item: (item.file, item.start, item.label, item.qualified_name),
    )
    graph_counts = _counts(graph_symbols)
    extra_counts = _counts(supplement)
    combined = {
        label: graph_counts[label] + extra_counts[label]
        for label in graph_counts
    }
    production = [item for item in graph_symbols if not item.file.startswith("tests/")]
    tests = [item for item in graph_symbols if item.file.startswith("tests/")]

    header = f"""# Exhaustive Symbol Reference

Generated from the full codebase-memory graph and an independent Python AST audit.

- Base `HEAD`: `{head}`
- Source fingerprint: `{fingerprint}`
- Graph ledger: {graph_counts['Class']:,} classes, {graph_counts['Function']:,} functions,
  {graph_counts['Method']:,} methods ({len(graph_symbols):,} rows)
- Python AST supplement: {extra_counts['Class']:,} classes,
  {extra_counts['Function']:,} functions, {extra_counts['Method']:,} methods
  ({len(supplement):,} rows)
- Combined reference: **{combined['Class']:,} classes**, **{combined['Function']:,}
  functions**, and **{combined['Method']:,} methods** (**{len(graph_symbols) + len(supplement):,}
  rows**)

Line numbers and the source fingerprint describe the generated source state. The
AST supplement is authoritative for tracked Python definition completeness; the
graph sections provide call-graph-qualified names and non-Python coverage. Do not
hand-edit this file; run `python3 scripts/update_codebase_docs.py`.

"""
    text = header
    text += _render_section("Production, Tooling, And Benchmark Symbols", production)
    text += _render_section("Test Symbols", tests)
    text += _render_section("Python AST Completeness Supplement", supplement)
    return text.rstrip() + "\n"


def _replace_auto_block(text: str, body: str) -> str:
    replacement = f"{AUTO_START}\n{body.rstrip()}\n{AUTO_END}"
    pattern = re.compile(
        re.escape(AUTO_START) + r".*?" + re.escape(AUTO_END),
        flags=re.DOTALL,
    )
    if not pattern.search(text):
        raise RefreshError("missing codebase-docs auto block markers")
    return pattern.sub(replacement, text, count=1)


def _state_block(
    head: str,
    fingerprint: str,
    schema: dict[str, int],
    graph_symbols: list[Symbol],
    supplement: list[Symbol],
) -> str:
    combined = _counts([*graph_symbols, *supplement])
    return "\n".join(
        (
            "Generated by `scripts/update_codebase_docs.py`; do not edit this block.",
            "",
            f"- Base `HEAD`: `{head}`",
            f"- Source fingerprint: `{fingerprint}`",
            f"- Graph code symbols: {schema.get('Class', 0):,} classes, "
            f"{schema.get('Function', 0):,} functions, {schema.get('Method', 0):,} methods",
            f"- Complete merged ledger: {combined['Class']:,} classes, "
            f"{combined['Function']:,} functions, {combined['Method']:,} methods",
            f"- Tracked Python files: {len(_tracked_files('*.py')):,}",
        )
    )


def _validate_semantic_catalogs() -> None:
    feature_text = FEATURES.read_text(encoding="utf-8")
    status_text = TEST_STATUS.read_text(encoding="utf-8")
    missing_sources = [
        path
        for path in _tracked_files("src/**")
        if f"`{path}`" not in feature_text
    ]
    missing_tests = [
        path
        for path in _tracked_files("tests/*.py")
        if f"`{path}`" not in status_text
    ]
    messages = []
    if missing_sources:
        messages.append("FEATURES.md is missing: " + ", ".join(missing_sources))
    if missing_tests:
        messages.append("TESTING_AND_STATUS.md is missing: " + ", ".join(missing_tests))
    if messages:
        raise RefreshError("; ".join(messages))


def _write_or_check(path: Path, expected: str, check_only: bool) -> bool:
    current = path.read_text(encoding="utf-8") if path.exists() else ""
    if current == expected:
        return False
    if check_only:
        raise RefreshError(f"generated documentation is stale: {path.relative_to(REPO)}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(expected, encoding="utf-8")
    return True


def refresh(check_only: bool = False, *, reindex: bool = True) -> list[str]:
    _validate_semantic_catalogs()
    inputs = _source_inputs()
    fingerprint = _source_fingerprint(inputs)
    head = _git("rev-parse", "HEAD")
    project = _index_repository() if reindex else _current_project()
    schema = _graph_schema(project)
    graph_symbols = []
    for label in ("Class", "Function", "Method"):
        graph_symbols.extend(_query_symbols(project, label))
    # The graph may retain ignored/generated files from an earlier index. Keep the
    # durable symbol reference limited to the same Git-visible source set used by
    # the fingerprint so browser traces and build output cannot leak into docs.
    allowed_paths = set(inputs)
    graph_symbols = [symbol for symbol in graph_symbols if symbol.file in allowed_paths]
    schema = _counts(graph_symbols)
    supplement = _python_ast_supplement(graph_symbols)
    state = _state_block(head, fingerprint, schema, graph_symbols, supplement)

    expected_symbols = _render_symbols(graph_symbols, supplement, head, fingerprint)
    expected_memory = _replace_auto_block(MEMORY.read_text(encoding="utf-8"), state)
    expected_index = _replace_auto_block(DOC_INDEX.read_text(encoding="utf-8"), state)

    changed = []
    for path, expected in (
        (SYMBOLS, expected_symbols),
        (MEMORY, expected_memory),
        (DOC_INDEX, expected_index),
    ):
        if _write_or_check(path, expected, check_only):
            changed.append(str(path.relative_to(REPO)))

    return changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Fail when generated documentation differs instead of writing files.",
    )
    args = parser.parse_args(argv)
    try:
        if args.check:
            changed = refresh(check_only=True, reindex=False)
        else:
            changed_set: set[str] = set()
            for _ in range(4):
                pass_changes = refresh(check_only=False)
                changed_set.update(pass_changes)
                if not pass_changes:
                    break
            else:
                raise RefreshError("generated documentation did not reach a fixed point")
            changed = sorted(changed_set)
    except RefreshError as exc:
        print(f"codebase-docs: {exc}", file=sys.stderr)
        return 1
    if args.check:
        print("codebase-docs: generated documentation is current")
    elif changed:
        print("codebase-docs: updated " + ", ".join(changed))
    else:
        print("codebase-docs: no generated changes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
