"""Behavior tests for the DEX reflection/dynamic-loader/ProcessBuilder tracker."""
from __future__ import annotations

from src.analysis.dex_reflection_tracker import (
    TRUST_TAG,
    scan_smali_text,
    scan_source_text,
)


SMALI_SAMPLE = """
.class public Lcom/x/Loader;
.method public run()V
    .locals 3
    const-string v0, "com.evil.Payload"
    const-string v1, "/data/local/tmp/payload.dex"
    invoke-static {v0}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;
    new-instance v2, Ldalvik/system/DexClassLoader;
    invoke-direct {v2, v1}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/lang/Class;->getDeclaredMethod()Ljava/lang/reflect/Method;
.end method
"""

JAVA_SAMPLE = """
public class R {
    void go(String name) throws Exception {
        Class<?> c = Class.forName(name);
        new ProcessBuilder("/system/bin/sh", "-c", "id").start();
        Runtime.getRuntime().exec("su");
        m.invoke(null);
    }
}
"""

CLEAN_JAVA = """
public class Clean {
    void go() { int x = 1 + 1; }
}
"""


def test_smali_sites_with_literal_resolution():
    out = scan_smali_text(SMALI_SAMPLE)
    assert out.status == "success"
    kinds = {s.kind for s in out.sites}
    assert "reflection-class-load" in kinds
    assert "dynamic-dex-load" in kinds
    assert out.dynamic_loads >= 1
    literal_sites = [s for s in out.sites if s.metadata.get("argument_kind") == "literal"]
    assert any(s.metadata.get("literal") == "com.evil.Payload" for s in literal_sites)


def test_java_processbuilder_and_exec_flagged():
    out = scan_source_text(JAVA_SAMPLE)
    kinds = {s.kind for s in out.sites}
    assert "process-builder" in kinds
    assert "runtime-exec" in kinds
    assert "reflection-class-load" in kinds
    assert "reflection-invoke" in kinds
    sev = {s.kind: s.severity for s in out.sites}
    assert sev["process-builder"] == "high"
    assert sev["runtime-exec"] == "high"


def test_clean_source_no_sites():
    out = scan_source_text(CLEAN_JAVA)
    assert out.sites == []
    assert out.dynamic_loads == 0


def test_empty_input_and_trust_envelope():
    assert scan_smali_text("").status == "empty"
    assert scan_source_text("").status == "empty"
    out = scan_source_text(JAVA_SAMPLE)
    assert out.trust == TRUST_TAG == "untrusted_child"
    for s in out.sites:
        assert s.trust == "untrusted_child"
        assert s.line_no >= 1 and s.evidence == "java"
    d = out.as_dict()
    assert "policy" in d and "dynamic_loads" in d


def test_variable_argument_marked_not_literal():
    out = scan_source_text(JAVA_SAMPLE)
    forname = [s for s in out.sites if s.kind == "reflection-class-load"][0]
    assert forname.metadata.get("argument_kind") == "variable"
    assert forname.metadata.get("literal") is None
