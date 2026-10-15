import json
import hashlib
import pytest
from src.analysis.android_binary_inventory import (
    materialize_binary_evidence, analyze_native_static_evidence,
)
from src.analysis.native_ownership_manifest import native_routing_context
from src.agents.context_harness import ContextHarnessConfig, apply_observed_context_limit, _context_policy_record


def test_learned_window_does_not_change_recovery_policy(tmp_path):
    env = {'ANGERONA_CONTEXT_PROFILE_DIR': str(tmp_path)}
    first = ContextHarnessConfig.from_env(env, agent_family='codex', model_hint='fixture')
    learned = apply_observed_context_limit(env, first, {'context_limit_tokens': 256000}, trusted=True)
    resumed = ContextHarnessConfig.from_env({'ANGERONA_CONTEXT_PROFILE_DIR': str(tmp_path)}, agent_family='codex', model_hint='fixture')
    assert resumed.context_window_tokens == learned.context_window_tokens == 256000
    assert _context_policy_record(resumed) == _context_policy_record(first)
    explicit = ContextHarnessConfig.from_env({'ANGERONA_CONTEXT_WINDOW_TOKENS': '128000'}, agent_family='codex', model_hint='fixture')
    assert _context_policy_record(explicit) != _context_policy_record(first)


def test_signed_native_route_and_unrouted_rejection(tmp_path, native_elf_bytes, route_native, monkeypatch):
    root = tmp_path / 'artifacts'
    root.mkdir()
    target = root / 'native.so'
    target.write_bytes(native_elf_bytes)
    with pytest.raises(ValueError, match='signed native ownership'):
        materialize_binary_evidence(root)
    assert not (root / '_angerona_binary_evidence').exists()
    routing = route_native(root)
    _, selected, _, _ = native_routing_context(routing.static_kwargs['ownership_manifest'], routing.static_kwargs['native_universe'])
    assert len(selected) == 1
    calls = []
    def fake_ida(path, output, **kwargs):
        calls.append(path)
        assert kwargs['native_authority_token']
        output.write_text('synthetic engine evidence\n')
        return {'status': 'success', 'complete': True,
                'target_sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'target_bytes': path.stat().st_size, 'producer_contract_sha256': 'fixture-contract'}
    monkeypatch.setattr('src.analysis.android_binary_inventory._write_ida_evidence', fake_ida)
    monkeypatch.setattr('src.analysis.android_binary_inventory._elf_nonexec_data_profile', lambda _: {'status': 'complete', 'complete': True})
    result = analyze_native_static_evidence([target], evidence_root=tmp_path / 'native', **routing.static_kwargs)
    assert result['complete'] is True
    materialized = materialize_binary_evidence(root, precomputed_native_records=result['records'], **routing.materialize_kwargs)
    assert materialized['files'][0]['native_cache_hit'] is True
    assert materialized['files'][0]['analysis_complete'] is True
    assert json.loads((root / '_angerona_binary_evidence/NATIVE_ROUTED_OUTPUT.json').read_text())['trust'] == 'operator_signed'
    copied = next(root / name for name in materialized['files'][0]['required_evidence'] if name.endswith('ida_analysis.txt'))
    copied.write_text('tampered cached evidence\n')
    repaired = materialize_binary_evidence(root, precomputed_native_records=result['records'], **routing.materialize_kwargs)
    assert repaired['checkpoint_hits'] == 0
    assert copied.read_text() == 'synthetic engine evidence\n'
    receipt = result['records'][0]['receipt']
    from pathlib import Path
    tampered = json.loads(Path(receipt).read_text())
    tampered['signature'] = ''
    Path(receipt).write_text(json.dumps(tampered))
    regenerated = analyze_native_static_evidence([target], evidence_root=tmp_path / 'native', **routing.static_kwargs)
    assert len(calls) == 2, 'unsigned native cache was reused'
    assert regenerated['complete'] is True


def test_web_lists_actual_legacy_runs_and_rejects_ambiguous_ids(tmp_path, monkeypatch):
    from src.web import server
    monkeypatch.setattr(server, '_state_dir', lambda: tmp_path)
    monkeypatch.setattr(server, '_LIVE', {})
    legacy = tmp_path / 'runs/batch/20261015__fixture'
    legacy.mkdir(parents=True)
    (legacy / 'run.json').write_text('{}')
    assert [run['id'] for run in server._list_runs()] == [legacy.name]
    assert server._run_root(legacy.name) == legacy
    duplicate = tmp_path / 'runs' / legacy.name
    duplicate.mkdir()
    assert server._run_root(legacy.name) is None
    assert server._list_runs() == []
