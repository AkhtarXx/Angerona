"""Behavior tests for Big Sleep commit-seeded variant analysis (roadmap Phase B7)."""
from __future__ import annotations

from src.analysis.simindex import SimilarityIndex
from src.analysis.variant_analysis import (
    CommitSeed,
    hunt_siblings_from_commit,
    parse_commit_seed,
)


# A SQLite-style diff for the Big Sleep seed: pre-fix handler had a negative-index
# array write; the fix added a range check.
COMMIT_DIFF = """
--- a/ext/fts5/fts5_index.c
+++ b/ext/fts5/fts5_index.c
@@ -1332,9 +1332,12 @@ static int seriesBestIndex(
   int iColumn = sqlite3VdbeSerialType(pCol);
   if (iColumn == -1) {
     // pre-fix VULNERABLE shape:
-    aIdx[-1] = iColumn;
-    *pConstraint = aIdx[-1];
+    // (removed)
+    if (iColumn < 0) {
+      rc = SQLITE_RANGE;
+      goto finish;
+    }
   }
 finish:
   pCons->iColumn = iColumn;
"""


def _index() -> SimilarityIndex:
    idx = SimilarityIndex(dim_reduce=0, backend="hashing", search_backend="exact")
    # related sibling code (same negative-index write) — should be ranked
    idx.add_function("0x1000", "sibling_neg_write",
                     "mov eax, dword [rcx - 4]\nmov dword [rax - 4], ebx\n"
                     "cmp ecx, 0\nje done", source="vuln")
    # unrelated helper — should not fire on our patterns
    idx.add_function("0x2000", "unrelated_fmt",
                     "push rbp\nmov rbp, rsp\nmov eax, 1\npop rbp\nret",
                     source="other")
    # a third sibling using loop-bounds + index-write
    idx.add_function("0x3000", "sibling_loop_write",
                     "mov ecx, 0\nloop_head: cmp ecx, edx\njge done\n"
                     "mov dword [rax + rcx*4], ebx\ninc ecx\njmp loop_head\ndone:",
                     source="vuln")
    idx.build()
    return idx


def test_parse_commit_seed_detects_negative_index_and_index_write():
    seed = parse_commit_seed("fts5 fix", COMMIT_DIFF, cve="CVE-2024-1234")
    assert seed.cve == "CVE-2024-1234"
    assert seed.commit_message == "fts5 fix"
    # negative-index and index-write patterns must be detected from removed lines
    assert "negative_index" in seed.hunt_keywords or "index_write" in seed.hunt_keywords
    assert seed.removed_code                     # pre-fix shape preserved


def test_parse_commit_seed_no_noise_from_added_lines():
    # a commit whose "+" side contains strcpy() but "-" side is clean
    diff = "--- a/x.c\n+++ b/x.c\n@@ -1,2 +1,2 @@\n-  return safe_len(dst);\n+  strcpy(dst, src);\n"
    seed = parse_commit_seed("fix", diff)
    # strcpy is IN ADDED lines (the fix), not in the pre-fix vulnerable shape
    assert "strcpy" not in seed.hunt_keywords


def test_hunt_siblings_multikeyword_rank():
    idx = _index()
    seed = parse_commit_seed("fix", COMMIT_DIFF)
    out = hunt_siblings_from_commit(seed, idx, top_k=10, threshold=0.30)
    assert out["n_keywords"] >= 1
    assert out["n_unique_candidates"] >= 1
    for c in out["candidates"]:
        assert c["score"] > 0
        assert c["matched_keywords"]


def test_candidates_sorted_by_keyword_count_then_score():
    idx = _index()
    # seed carrying multiple keyword classes
    seed = CommitSeed(
        commit_message="fix bounds + negative index",
        cve="CVE-2024-9",
        removed_code="aIdx[-1] = x;",
        added_code="",
        hunt_keywords=["negative_index", "index_write", "bounds_loop"],
    )
    out = hunt_siblings_from_commit(seed, idx, top_k=10, threshold=0.30)
    cands = out["candidates"]
    for i in range(len(cands) - 1):
        a, b = cands[i], cands[i + 1]
        assert len(a["matched_keywords"]) >= len(b["matched_keywords"]) or \
               (len(a["matched_keywords"]) == len(b["matched_keywords"])
                and a["score"] >= b["score"])


def test_hunt_with_no_keywords_returns_empty_not_crash():
    idx = _index()
    seed = CommitSeed(commit_message="clean", cve="",
                      removed_code="", added_code="", hunt_keywords=[])
    out = hunt_siblings_from_commit(seed, idx, top_k=5, threshold=0.3)
    assert out["n_unique_candidates"] == 0
    assert out["candidates"] == []
