from __future__ import annotations

from src.analysis.finding import (
    CONFIRMED, INCONCLUSIVE, LIKELY, NOT_APPLICABLE, REFUSAL,
    Finding, coerce_legacy_dict,
)


def test_finding_valid_verdicts():
    for v in (CONFIRMED, LIKELY, INCONCLUSIVE, NOT_APPLICABLE, REFUSAL):
        f = Finding(module="m", kind="x", severity="medium", verdict=v, detail="d")
        assert f.verdict == v
        assert f.trust == "untrusted_child"


def test_finding_invalid_verdict_rejected():
    import pytest
    with pytest.raises(ValueError, match="invalid verdict"):
        Finding(module="m", kind="x", severity="medium", verdict="CRITICAL", detail="d")


def test_as_dict_shape():
    f = Finding(module="m", kind="k", severity="high", verdict=CONFIRMED,
                detail="hello", evidence="ev", rule_layer="java", line_no=10,
                runtime_corroborated=True)
    d = f.as_dict()
    assert d["module"] == "m" and d["kind"] == "k"
    assert d["verdict"] == "CONFIRMED"
    assert d["rule_layer"] == "java"
    assert d["runtime_corroborated"] is True
    assert d["trust"] == "untrusted_child"


def test_coerce_legacy_basic():
    d = {"kind": "legacy-kind", "severity": "high", "detail": "legacy detail",
         "line_no": 42}
    f = coerce_legacy_dict("legacy-mod", d)
    assert f.module == "legacy-mod"
    assert f.kind == "legacy-kind"
    assert f.severity == "high"
    assert f.verdict == LIKELY  # default


def test_coerce_legacy_rule_alias():
    d = {"rule": "old-rule-name", "message": "old message text"}
    f = coerce_legacy_dict("legacy-mod", d)
    assert f.kind == "old-rule-name"
    assert f.detail == "old message text"
