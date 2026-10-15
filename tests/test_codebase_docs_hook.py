from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "scripts" / "update_codebase_docs.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("update_codebase_docs", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_parse_cli_json_ignores_mcp_log_prefix():
    docs = _load_module()
    parsed = docs._parse_cli_json('level=info msg=ready\n{"project":"angerona"}\n')
    assert parsed == {"project": "angerona"}


def test_replace_auto_block_preserves_manual_content():
    docs = _load_module()
    original = f"before\n{docs.AUTO_START}\nold\n{docs.AUTO_END}\nafter\n"
    updated = docs._replace_auto_block(original, "new\nstate")
    assert updated == f"before\n{docs.AUTO_START}\nnew\nstate\n{docs.AUTO_END}\nafter\n"


def test_repository_hook_runs_refresh_and_fixed_point_check():
    hook = (REPO / ".githooks" / "pre-commit").read_text(encoding="utf-8")
    assert "scripts/update_codebase_docs.py" in hook
    assert "scripts/update_codebase_docs.py --check" in hook
    assert "refusing partial source staging" in hook
    assert "stage semantic catalog changes" in hook
    assert "frontend/*" in hook


def test_frontend_is_part_of_documentation_fingerprint():
    docs = _load_module()
    assert "frontend/" in docs.SOURCE_INPUTS


def test_current_project_ignores_empty_root_paths(monkeypatch):
    docs = _load_module()
    monkeypatch.setattr(docs, "_mcp", lambda *_args: {
        "projects": [
            {"name": "stale-nested-project", "root_path": ""},
            {"name": "angerona", "root_path": str(docs.REPO)},
        ],
    })
    assert docs._current_project() == "angerona"


def test_docs_index_persists_graph_for_fixed_point_check(monkeypatch):
    docs = _load_module()
    seen = {}

    def fake_mcp(tool, arguments):
        seen.update(arguments)
        return {"project": "angerona"}

    monkeypatch.setattr(docs, "_mcp", fake_mcp)
    assert docs._index_repository() == "angerona"
    assert seen["persistence"] is True
