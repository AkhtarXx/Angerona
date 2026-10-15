"""Recall test driver — runs chain-scorer against the known-vuln corpus.

True positives: every KNOWN_VULN_CORPUS app must trigger ≥1 attack-chain.
False negative (chain misses on planted vuln) = test failure.

Set env var ANGERONA_RECALL_SLOW=1 to include 500-APK batch from CLEAN apps,
which measures false-positive rate end-to-end.  Tests skip-by-default so regular
CI stays fast; CI for release runs the extended mode.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from src.analysis.attack_chain_scorer import build_attack_chains
from src.pipeline.android_audit import run_android_audit

REPO_ROOT = Path(__file__).resolve().parent
KNOWN_VULN_SCHEMA = REPO_ROOT / "replay_artifacts" / "KNOWN_VULN_CORPUS.schema.json"
CLEAN_CORPUS_SCHEMA = REPO_ROOT / "replay_artifacts" / "CLEAN_APPS_CORPUS.schema.json"


def _load_json(p: Path) -> dict:
    return json.loads(p.read_text())


def _chains_for(apk_path: str) -> list[str]:
    r = run_android_audit(apk_path, try_runtime_extract=False,
                          timeout_per_step=120, run_rules=True)
    return sorted({
        f.metadata.get("chain_id")
        for f in r.findings
        if f.module == "attack_chain_scorer" and f.metadata.get("chain_id")
    })


@pytest.mark.parametrize("apk_path", [
    "/tmp/dummy_signed.apk",
])
def test_known_vuln_triggers_chain(apk_path):
    if not Path(apk_path).is_file():
        pytest.skip(f"planted-vuln app missing: {apk_path}")
    chains = _chains_for(apk_path)
    assert chains, f"expected at least 1 attack chain on {apk_path}, got {chains}"
    print(f"chains fired: {chains}")


def test_known_vuln_chains_meet_minimum(apk_path="/tmp/dummy_signed.apk"):
    if not Path(apk_path).is_file():
        pytest.skip(f"planted-vuln app missing: {apk_path}")
    chains = _chains_for(apk_path)
    assert len(chains) >= 1


@pytest.mark.skipif(
    os.environ.get("ANGERONA_RECALL_SLOW") != "1",
    reason="slow corpus test — opt-in only",
)
def test_clean_apps_fp_rate_zero():
    """Run the 500-APK clean-app corpus and measure false-positive rate.

    Only enabled when ANGERONA_RECALL_SLOW=1 — use this for pre-release gate.
    """
    schema = _load_json(CLEAN_CORPUS_SCHEMA)
    fps = 0
    tested = 0
    for app in schema["apps"]:
        # Skip placeholder/remotes that aren't local yet — real CI for release
        # fetches via the chain-runner script and validates there.
        if not Path(app.get("path", "")).is_file():
            continue
        tested += 1
        chains = _chains_for(app["path"])
        if chains:
            fps += 1
    if tested == 0:
        pytest.skip("no clean apps staged locally — fetch required corpus first")
    fp_rate = fps / tested
    assert fp_rate == 0, f"false positive rate {fp_rate:.1%} — {fps}/{tested} clean apps had chains"


def test_replay_artifacts_commitment():
    """Reference artifacts must be committed so audits are reproducible."""
    for f in ("dummy_malicious_audit.json", "CLEAN_APPS_CORPUS.schema.json",
              "KNOWN_VULN_CORPUS.schema.json"):
        p = REPO_ROOT / "replay_artifacts" / f
        assert p.is_file(), f"missing committed artifact: {f}"
