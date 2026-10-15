"""Data-only, fail-closed reverse-engineering methodology knowledge packs.

This module never imports or executes vendor code. It copies an exact,
explicitly allowlisted Markdown corpus into non-executable CAS objects, scans
every line for prompt/action content, and permits retrieval only from clean
bounded excerpts. Retrieved text is always labelled untrusted reference data.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tempfile
from typing import Any, Iterable

from .audit_lineage import load_audit_epoch, open_verified_artifact, output_is_in_epoch
from .evidence_signing import (
    canonical_payload, verify_document_identity, with_document_identity,
)
from .schema_validation import (
    canonical_order_rows, canonical_order_values, require_canonical_ordered_field,
    require_int_field,
)
from .signed_artifact_io import load_signed_canonical, write_signed_canonical


PACK_SCHEMA = "angerona/reverse-knowledge-pack/v1"
RETRIEVAL_SCHEMA = "angerona/reverse-knowledge-retrieval/v1"
PINNED_UPSTREAM_COMMIT = "41bd788c34f82d26ad9e51bcba838b0d1220928e"
MAX_SOURCE_BYTES = 96 * 1024
MAX_PACK_BYTES = 768 * 1024
MAX_EXCERPT_BYTES = 1400
MAX_RETRIEVAL_BYTES = 6000
MAX_RETRIEVAL_EXCERPTS = 6

# Files are data, never prompt authorities. Scripts, configs, bootstrap/MCP,
# RULES/AGENTS/README_AI, exploit/pentest/CTF/EDR content are absent by design.
ALLOWLIST_MODULES: dict[str, tuple[str, ...]] = {
    "apk-reverse": (
        "skills/apk-reverse/SKILL.md",
        "skills/apk-reverse/references/android-advanced.md",
        "skills/apk-reverse/references/apk-security-checklist.md",
    ),
    "binary-diff": (
        "skills/binary-diff/SKILL.md",
        "skills/binary-diff/references/prompt-template.md",
    ),
    "ghidra-reverse": (
        "skills/ghidra-reverse/SKILL.md",
        "skills/ghidra-reverse/references/ghidra-cheatsheet.md",
    ),
    "ida-reverse": (
        "skills/ida-reverse/SKILL.md",
        "skills/ida-reverse/references/ida-mcp-cheatsheet.md",
    ),
    "radare2": (
        "skills/radare2/SKILL.md",
        "skills/radare2/references/cheatsheet.md",
    ),
    "reverse-engineering": (
        "skills/reverse-engineering/elf-analysis.md",
        "skills/reverse-engineering/references/ai-assisted-re.md",
        "skills/reverse-engineering/references/re-agent-workflow.md",
    ),
    "case-review": ("skills/case-review/SKILL.md",),
    "sbom-methodology": (
        "skills/supply-chain-security/references/sbom-sca-methodology.md",
    ),
}
ALLOWED_PATH_TO_MODULE = {
    path: module for module, paths in ALLOWLIST_MODULES.items() for path in paths
}
LICENSE_PATH = "LICENSE"
ALLOWLIST_POLICY = {
    "policy": "angerona/reverse-methodology-data-only/v1",
    "forbidden_families": [
        "scripts", "bootstrap-install-mcp", "RULES-AGENTS-README_AI",
        "pentest-attack-exploit-ctf-edr",
    ],
}
SAFETY_CONTRACT = {
    "wrapper": "UNTRUSTED_REFERENCE_DATA",
    "allowed_use": ["hypothesis-suggestion", "method-choice-suggestion"],
    "prohibited_use": [
        "scope-change", "tool-install", "command-execution", "network-contact",
        "ownership-selection", "excluded-code-selection", "finding-confirmation",
    ],
    "actions_require_signed_angerona_gates": True,
}

_PROMPT_PATTERNS = {
    "prompt-ignore": re.compile(r"\bignore\s+(?:all|any|the|previous|prior)\b", re.I),
    "prompt-role": re.compile(r"\b(?:system|developer|assistant)\s*(?:message|prompt|:)\b", re.I),
    "prompt-override": re.compile(r"\b(?:override|bypass|disregard)\b.{0,48}\b(?:rule|instruction|policy|scope)\b", re.I),
    "prompt-secret": re.compile(r"\b(?:reveal|exfiltrate|print|return)\b.{0,48}\b(?:secret|credential|token|key)\b", re.I),
    "prompt-wrapper-boundary": re.compile(r"(?:BEGIN|END)_UNTRUSTED_REFERENCE_DATA", re.I),
}
_ACTION_PATTERNS = {
    "action-code-fence": re.compile(r"^\s*```"),
    "action-shell-command": re.compile(r"^\s*(?:\$|>|PS>|#\s*(?:apt|yum|dnf)|(?:sudo\s+)?(?:apt|yum|dnf|pip|npm|git|curl|wget|python|powershell|bash|sh)\b)", re.I),
    "action-tool-control": re.compile(r"\b(?:install|bootstrap|execute|run|launch|start|invoke|connect|download)\b.{0,64}\b(?:tool|script|command|mcp|server|endpoint|package|binary)\b", re.I),
    "action-network": re.compile(r"(?:https?://|\b(?:curl|wget)\b|\bcontact\s+(?:the\s+)?network\b)", re.I),
    "action-scope": re.compile(r"\b(?:change|expand|override|ignore)\b.{0,48}\b(?:scope|routing|ownership|exclusion)\b", re.I),
    "action-imperative": re.compile(r"^\s*(?:[-*]\s*)?(?:read|write|open|check|inspect|analyze|review|confirm|record|create|generate|extract|decompile|debug|patch|hook|search|verify)\b", re.I),
    "action-modal": re.compile(r"\b(?:MUST|SHOULD|DO NOT|NEVER|ALWAYS)\b"),
}
_TOKEN = re.compile(r"[A-Za-z0-9_.+-]{3,48}")
_STOPWORDS = {
    "and", "are", "for", "from", "into", "not", "only", "that", "the",
    "this", "use", "with", "your", "must", "should", "will", "then",
}


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _canonical_line(document: dict[str, Any]) -> bytes:
    return canonical_payload(document) + b"\n"


def _safe_relative(value: str) -> str:
    pure = PurePosixPath(value)
    if not value or pure.is_absolute() or ".." in pure.parts or str(pure) != value:
        raise ValueError(f"unsafe knowledge-pack relative path: {value!r}")
    return value


def _strict_regular(root: Path, relative: str, *, max_bytes: int) -> tuple[Path, bytes]:
    _safe_relative(relative)
    cursor = root
    for part in PurePosixPath(relative).parts:
        cursor = cursor / part
        info = cursor.lstat()
        if stat.S_ISLNK(info.st_mode):
            raise ValueError(f"knowledge-pack source contains a symlink: {relative}")
    info = cursor.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise ValueError(f"knowledge-pack source is not a unique regular file: {relative}")
    if info.st_size > max_bytes:
        raise ValueError(f"knowledge-pack source exceeds byte bound: {relative}")
    payload = cursor.read_bytes()
    if len(payload) != info.st_size or b"\x00" in payload:
        raise ValueError(f"knowledge-pack source changed or contains NUL: {relative}")
    payload.decode("utf-8", "strict")
    return cursor, payload


def _git_commit(source: Path) -> str:
    git = source / ".git"
    if git.is_symlink() or not git.is_dir():
        raise ValueError("knowledge-pack source lacks a local .git directory")
    head_path, head_payload = _strict_regular(source, ".git/HEAD", max_bytes=256)
    head = head_payload.decode("ascii", "strict").strip()
    if re.fullmatch(r"[0-9a-f]{40}", head):
        return head
    if not head.startswith("ref: "):
        raise ValueError(f"invalid vendor HEAD: {head_path}")
    reference = head[5:]
    if not reference.startswith("refs/"):
        raise ValueError("vendor HEAD reference is outside refs")
    direct = git / reference
    if direct.is_file():
        _path, payload = _strict_regular(source, f".git/{reference}", max_bytes=256)
        commit = payload.decode("ascii", "strict").strip()
        if re.fullmatch(r"[0-9a-f]{40}", commit):
            return commit
    _path, packed = _strict_regular(source, ".git/packed-refs", max_bytes=256 * 1024)
    matches = []
    for line in packed.decode("ascii", "strict").splitlines():
        if not line or line.startswith(("#", "^")):
            continue
        commit, separator, name = line.partition(" ")
        if separator and name == reference and re.fullmatch(r"[0-9a-f]{40}", commit):
            matches.append(commit)
    if len(matches) != 1:
        raise ValueError("vendor HEAD reference is absent or duplicated")
    return matches[0]


def _atomic_data(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        if path.is_symlink() or path.read_bytes() != payload:
            raise FileExistsError(f"refusing to replace knowledge CAS object: {path}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o400)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _keywords(text: str, module: str) -> list[str]:
    values = {token.lower() for token in _TOKEN.findall(text)}
    values.update(token.lower() for token in re.split(r"[-_]", module) if len(token) >= 3)
    return sorted(value for value in values if value not in _STOPWORDS)[:96]


def _scan(relative: str, module: str, payload: bytes) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    findings: list[dict[str, Any]] = []
    safe_lines: list[tuple[int, int, int, bytes]] = []
    cursor = 0
    in_code_fence = False
    for line_number, line in enumerate(payload.splitlines(keepends=True), 1):
        end = cursor + len(line)
        text = line.decode("utf-8", "strict")
        fence_line = bool(re.match(r"^\s*```", text))
        matches = [
            ("prompt_injection", name) for name, pattern in _PROMPT_PATTERNS.items()
            if pattern.search(text)
        ] + [
            ("action_directive", name) for name, pattern in _ACTION_PATTERNS.items()
            if pattern.search(text)
        ]
        if in_code_fence and not fence_line:
            matches.append(("action_directive", "action-code-fence-content"))
        if matches:
            for category, pattern_id in matches:
                body = {
                    "relative_path": relative, "line_start": line_number,
                    "line_end": line_number, "line_sha256": _sha(line),
                    "category": category, "pattern_id": pattern_id,
                    "disposition": "QUARANTINED_NOT_RETRIEVABLE",
                }
                findings.append({**body, "finding_id": "knowledge-scan:" + _sha(canonical_payload(body))})
        else:
            safe_lines.append((line_number, cursor, end, line))
        if fence_line:
            in_code_fence = not in_code_fence
        cursor = end
    if in_code_fence:
        raise ValueError(f"knowledge-pack source has an unterminated code fence: {relative}")
    if cursor != len(payload):
        raise ValueError(f"knowledge-pack scan did not conserve source bytes: {relative}")
    excerpts: list[dict[str, Any]] = []
    chunk: list[tuple[int, int, int, bytes]] = []

    def flush() -> None:
        if not chunk:
            return
        raw = b"".join(row[3] for row in chunk)
        if not raw.strip():
            chunk.clear()
            return
        body = {
            "relative_path": relative, "module": module,
            "byte_start": chunk[0][1], "byte_end": chunk[-1][2],
            "line_start": chunk[0][0], "line_end": chunk[-1][0],
            "excerpt_sha256": _sha(raw),
            "keywords": _keywords(raw.decode("utf-8", "strict"), module),
        }
        excerpts.append({**body, "excerpt_id": "knowledge-excerpt:" + _sha(canonical_payload(body))})
        chunk.clear()

    previous_line = 0
    current_bytes = 0
    for row in safe_lines:
        gap = previous_line and row[0] != previous_line + 1
        paragraph = row[3].strip() == b""
        if gap or current_bytes + len(row[3]) > MAX_EXCERPT_BYTES:
            flush(); current_bytes = 0
        chunk.append(row); current_bytes += len(row[3]); previous_line = row[0]
        if paragraph:
            flush(); current_bytes = 0
    flush()
    return (
        sorted(findings, key=lambda row: row["finding_id"]),
        sorted(excerpts, key=lambda row: row["excerpt_id"]),
    )


def _requested_paths(paths: Iterable[str] | None) -> list[str]:
    selected = sorted(set(paths or ALLOWED_PATH_TO_MODULE))
    if not selected:
        raise ValueError("knowledge pack requires at least one methodology file")
    unknown = sorted(set(selected) - set(ALLOWED_PATH_TO_MODULE))
    if unknown:
        raise ValueError(f"unallowlisted knowledge-pack path: {unknown[0]}")
    return selected


def import_knowledge_snapshot(
    *, source_root: str | Path, output_dir: str | Path, audit_epoch: str | Path,
    expected_commit: str = PINNED_UPSTREAM_COMMIT,
    paths: Iterable[str] | None = None,
) -> dict[str, Any]:
    source = Path(source_root).expanduser().absolute()
    if source.is_symlink() or not source.is_dir():
        raise ValueError("knowledge-pack source root must be a non-symlink directory")
    source = source.resolve(strict=True)
    if not re.fullmatch(r"[0-9a-f]{40}", expected_commit):
        raise ValueError("knowledge-pack expected commit must be exact SHA-1")
    actual_commit = _git_commit(source)
    if actual_commit != expected_commit:
        raise ValueError(f"knowledge-pack upstream drift: {actual_commit} != {expected_commit}")
    epoch = load_audit_epoch(audit_epoch)
    output = output_is_in_epoch(output_dir, epoch)
    selected = _requested_paths(paths)
    _license_path, license_payload = _strict_regular(source, LICENSE_PATH, max_bytes=64 * 1024)
    license_sha = _sha(license_payload)
    license_object = output / "objects" / f"{license_sha}.license"
    _atomic_data(license_object, license_payload)
    license_descriptor = {
        "path": str(license_object), "sha256": license_sha,
        "source_relative_path": LICENSE_PATH, "license_expression": "MIT",
    }
    files: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    excerpts: list[dict[str, Any]] = []
    total = 0
    for relative in selected:
        _path, payload = _strict_regular(source, relative, max_bytes=MAX_SOURCE_BYTES)
        total += len(payload)
        if total > MAX_PACK_BYTES:
            raise ValueError("knowledge-pack selected corpus exceeds total byte bound")
        digest = _sha(payload)
        artifact = output / "objects" / f"{digest}.md"
        _atomic_data(artifact, payload)
        module = ALLOWED_PATH_TO_MODULE[relative]
        scanned_findings, scanned_excerpts = _scan(relative, module, payload)
        files.append({
            "relative_path": relative, "module": module,
            "source_sha256": digest, "bytes": len(payload),
            "artifact": {"path": str(artifact), "sha256": digest},
            "license_expression": "MIT", "license_sha256": license_sha,
            "scan_finding_ids": sorted(row["finding_id"] for row in scanned_findings),
            "retrievable_excerpt_ids": sorted(row["excerpt_id"] for row in scanned_excerpts),
        })
        findings.extend(scanned_findings); excerpts.extend(scanned_excerpts)
    files = canonical_order_rows(PACK_SCHEMA, "files", files)
    findings = canonical_order_rows(PACK_SCHEMA, "scan_findings", findings)
    excerpts = canonical_order_rows(PACK_SCHEMA, "excerpts", excerpts)
    body = with_document_identity({
        "schema": PACK_SCHEMA,
        "audit_epoch_id": epoch["epoch_id"],
        "source": {
            "repository_path_provenance": str(source),
            "commit": actual_commit,
            "import_semantics": "local-read-only-no-upstream-code-execution",
        },
        "allowed_paths": canonical_order_values(PACK_SCHEMA, "allowed_paths", selected),
        "allowlist_policy": ALLOWLIST_POLICY,
        "license_provenance": license_descriptor,
        "files": files, "scan_findings": findings, "excerpts": excerpts,
        "file_count": len(files), "source_bytes": total,
        "scan_finding_count": len(findings), "retrievable_excerpt_count": len(excerpts),
        "safety_contract": SAFETY_CONTRACT,
    })
    descriptor = write_signed_canonical(output / "REVERSE_KNOWLEDGE_PACK.json", body)
    verify_knowledge_pack(descriptor, epoch["trusted_read_roots"], expected_commit=expected_commit)
    return {**descriptor, "pack_id": body["pack_id"], "file_count": len(files), "scan_findings": len(findings), "excerpts": len(excerpts)}


def verify_knowledge_pack(
    descriptor: dict[str, Any], roots: Iterable[str | Path], *,
    expected_commit: str | None = PINNED_UPSTREAM_COMMIT,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    manifest_path, document = load_signed_canonical(descriptor, roots, schema=PACK_SCHEMA)
    if not verify_document_identity(document):
        raise ValueError("reverse knowledge-pack identity mismatch")
    if expected_commit is not None and document.get("source", {}).get("commit") != expected_commit:
        raise ValueError("reverse knowledge-pack commit mismatch")
    allowed = require_canonical_ordered_field(document, "allowed_paths", context="reverse knowledge pack")
    if not allowed or not set(allowed).issubset(ALLOWED_PATH_TO_MODULE):
        raise ValueError("reverse knowledge-pack contains an unallowlisted path")
    files = require_canonical_ordered_field(document, "files", context="reverse knowledge pack")
    findings = require_canonical_ordered_field(document, "scan_findings", context="reverse knowledge pack")
    excerpts = require_canonical_ordered_field(document, "excerpts", context="reverse knowledge pack")
    if [row.get("relative_path") for row in files] != allowed:
        raise ValueError("reverse knowledge-pack allowlist/file membership mismatch")
    if require_int_field(document, "file_count", context="reverse knowledge pack", minimum=1) != len(files):
        raise ValueError("reverse knowledge-pack file count mismatch")
    if require_int_field(document, "scan_finding_count", context="reverse knowledge pack", minimum=0) != len(findings):
        raise ValueError("reverse knowledge-pack scan finding count mismatch")
    if require_int_field(document, "retrievable_excerpt_count", context="reverse knowledge pack", minimum=0) != len(excerpts):
        raise ValueError("reverse knowledge-pack excerpt count mismatch")
    license_row = document.get("license_provenance")
    if not isinstance(license_row, dict) or license_row.get("license_expression") != "MIT":
        raise ValueError("reverse knowledge-pack lacks exact license provenance")
    license_path, license_payload = open_verified_artifact(license_row, roots)
    if (
        _sha(license_payload) != license_row.get("sha256")
        or license_path.parent != manifest_path.parent / "objects"
        or license_path.name != f"{_sha(license_payload)}.license"
        or stat.S_IMODE(license_path.stat().st_mode) & 0o111
        or license_row.get("source_relative_path") != LICENSE_PATH
    ):
        raise ValueError("reverse knowledge-pack license hash mismatch")
    recomputed_findings: list[dict[str, Any]] = []
    recomputed_excerpts: list[dict[str, Any]] = []
    total = 0
    for row in files:
        relative = str(row.get("relative_path") or "")
        if row.get("module") != ALLOWED_PATH_TO_MODULE.get(relative):
            raise ValueError("reverse knowledge-pack module/path mismatch")
        artifact_path, payload = open_verified_artifact(row.get("artifact"), roots)
        if artifact_path.is_symlink() or artifact_path.parent != manifest_path.parent / "objects":
            raise ValueError("reverse knowledge-pack object escapes exact CAS directory")
        if artifact_path.name != f"{_sha(payload)}.md" or stat.S_IMODE(artifact_path.stat().st_mode) & 0o111:
            raise ValueError("reverse knowledge-pack object is not immutable non-executable CAS data")
        if row.get("source_sha256") != _sha(payload) or row.get("bytes") != len(payload):
            raise ValueError("reverse knowledge-pack file descriptor mismatch")
        if row.get("license_sha256") != license_row.get("sha256") or row.get("license_expression") != "MIT":
            raise ValueError("reverse knowledge-pack per-file license binding mismatch")
        scanned_findings, scanned_excerpts = _scan(relative, row["module"], payload)
        if row.get("scan_finding_ids") != sorted(item["finding_id"] for item in scanned_findings):
            raise ValueError("reverse knowledge-pack per-file scan ledger mismatch")
        if row.get("retrievable_excerpt_ids") != sorted(item["excerpt_id"] for item in scanned_excerpts):
            raise ValueError("reverse knowledge-pack per-file excerpt ledger mismatch")
        recomputed_findings.extend(scanned_findings); recomputed_excerpts.extend(scanned_excerpts)
        total += len(payload)
    if findings != canonical_order_rows(PACK_SCHEMA, "scan_findings", recomputed_findings):
        raise ValueError("reverse knowledge-pack scan findings changed")
    if excerpts != canonical_order_rows(PACK_SCHEMA, "excerpts", recomputed_excerpts):
        raise ValueError("reverse knowledge-pack excerpt index changed")
    if require_int_field(document, "source_bytes", context="reverse knowledge pack", minimum=0) != total:
        raise ValueError("reverse knowledge-pack byte conservation mismatch")
    if document.get("allowlist_policy") != ALLOWLIST_POLICY:
        raise ValueError("reverse knowledge-pack fixed allowlist policy mismatch")
    if document.get("safety_contract") != SAFETY_CONTRACT:
        raise ValueError("reverse knowledge-pack fixed safety contract mismatch")
    if source_root is not None:
        source = Path(source_root).expanduser().absolute()
        if source.is_symlink() or _git_commit(source.resolve(strict=True)) != document["source"]["commit"]:
            raise ValueError("reverse knowledge-pack upstream drift")
        for row in files:
            _path, payload = _strict_regular(source.resolve(strict=True), row["relative_path"], max_bytes=MAX_SOURCE_BYTES)
            if _sha(payload) != row["source_sha256"]:
                raise ValueError(f"reverse knowledge-pack upstream file drift: {row['relative_path']}")
    return document


def _normalize_query(terms: Iterable[str]) -> list[str]:
    values: set[str] = set()
    for term in terms:
        if not isinstance(term, str):
            raise ValueError("knowledge retrieval query terms must be strings")
        values.update(token.lower() for token in _TOKEN.findall(term))
    return sorted(value for value in values if value not in _STOPWORDS)[:32]


def _retrieval_body(
    pack_descriptor: dict[str, Any], pack: dict[str, Any], roots: Iterable[str | Path],
    query_terms: Iterable[str], *, max_excerpts: int, max_bytes: int,
) -> dict[str, Any]:
    if max_excerpts < 0 or max_excerpts > MAX_RETRIEVAL_EXCERPTS:
        raise ValueError("knowledge retrieval excerpt bound is invalid")
    if max_bytes < 0 or max_bytes > MAX_RETRIEVAL_BYTES:
        raise ValueError("knowledge retrieval byte bound is invalid")
    query = _normalize_query(query_terms)
    files = {row["relative_path"]: row for row in pack["files"]}
    ranked = []
    for row in pack["excerpts"]:
        score = len(set(query).intersection(row.get("keywords") or []))
        if score:
            ranked.append((-score, row["relative_path"], row["byte_start"], row))
    selected: list[dict[str, Any]] = []
    consumed = 0
    for _negative_score, _relative, _start, row in sorted(ranked):
        if len(selected) >= max_excerpts:
            break
        source = files[row["relative_path"]]
        _path, payload = open_verified_artifact(source["artifact"], roots)
        raw = payload[row["byte_start"]:row["byte_end"]]
        if _sha(raw) != row["excerpt_sha256"]:
            raise ValueError("knowledge retrieval excerpt bytes changed")
        if consumed + len(raw) > max_bytes:
            continue
        citation_body = {
            "pack_id": pack["pack_id"], "excerpt_id": row["excerpt_id"],
            "relative_path": row["relative_path"], "source_sha256": source["source_sha256"],
            "byte_start": row["byte_start"], "byte_end": row["byte_end"],
            "line_start": row["line_start"], "line_end": row["line_end"],
            "excerpt_sha256": row["excerpt_sha256"],
        }
        citation_id = "knowledge-citation:" + _sha(canonical_payload(citation_body))
        text = raw.decode("utf-8", "strict")
        selected.append({
            **citation_body, "citation_id": citation_id,
            "content": (
                f"BEGIN_UNTRUSTED_REFERENCE_DATA citation_id={citation_id}\n"
                f"{text}\nEND_UNTRUSTED_REFERENCE_DATA citation_id={citation_id}"
            ),
        })
        consumed += len(raw)
    selected = canonical_order_rows(RETRIEVAL_SCHEMA, "excerpts", selected)
    return {
        "schema": RETRIEVAL_SCHEMA, "pack": pack_descriptor,
        "pack_id": pack["pack_id"],
        "query_terms": canonical_order_values(RETRIEVAL_SCHEMA, "query_terms", query),
        "max_excerpts": max_excerpts, "max_source_bytes": max_bytes,
        "excerpts": selected, "excerpt_count": len(selected),
        "retrieved_source_bytes": consumed,
        "safety_contract": pack["safety_contract"],
        "retrieval_semantics": "deterministic-token-overlap-no-actions-no-authority",
    }


def materialize_knowledge_retrieval(
    *, pack_descriptor: dict[str, Any], roots: Iterable[str | Path],
    query_terms: Iterable[str], output_dir: str | Path,
    max_excerpts: int = MAX_RETRIEVAL_EXCERPTS,
    max_bytes: int = MAX_RETRIEVAL_BYTES,
) -> dict[str, Any]:
    pack = verify_knowledge_pack(pack_descriptor, roots, expected_commit=PINNED_UPSTREAM_COMMIT)
    body = with_document_identity(_retrieval_body(
        pack_descriptor, pack, roots, query_terms,
        max_excerpts=max_excerpts, max_bytes=max_bytes,
    ))
    path = Path(output_dir).resolve() / f"{body['retrieval_id']}.json"
    descriptor = write_signed_canonical(path, body)
    verify_knowledge_retrieval(descriptor, pack_descriptor, roots, query_terms)
    return {
        **descriptor, "retrieval_id": body["retrieval_id"],
        "excerpt_count": body["excerpt_count"],
        "citation_ids": [row["citation_id"] for row in body["excerpts"]],
    }


def verify_knowledge_retrieval(
    descriptor: dict[str, Any], pack_descriptor: dict[str, Any],
    roots: Iterable[str | Path], query_terms: Iterable[str],
) -> dict[str, Any]:
    _path, document = load_signed_canonical(descriptor, roots, schema=RETRIEVAL_SCHEMA)
    if not verify_document_identity(document):
        raise ValueError("reverse knowledge retrieval identity mismatch")
    pack = verify_knowledge_pack(pack_descriptor, roots, expected_commit=PINNED_UPSTREAM_COMMIT)
    if document.get("pack") != pack_descriptor or document.get("pack_id") != pack["pack_id"]:
        raise ValueError("reverse knowledge retrieval pack binding mismatch")
    expected = with_document_identity(_retrieval_body(
        pack_descriptor, pack, roots, query_terms,
        max_excerpts=require_int_field(document, "max_excerpts", context="knowledge retrieval", minimum=0, maximum=MAX_RETRIEVAL_EXCERPTS),
        max_bytes=require_int_field(document, "max_source_bytes", context="knowledge retrieval", minimum=0, maximum=MAX_RETRIEVAL_BYTES),
    ))
    semantic = {key: value for key, value in document.items() if key not in {"trust", "payload_sha256", "signature", "signature_key_id"}}
    if semantic != expected:
        raise ValueError("reverse knowledge retrieval differs from deterministic reconstruction")
    if require_int_field(document, "excerpt_count", context="knowledge retrieval", minimum=0) != len(document["excerpts"]):
        raise ValueError("reverse knowledge retrieval excerpt count mismatch")
    return document


def knowledge_pack_status(
    descriptor: dict[str, Any], roots: Iterable[str | Path], *,
    source_root: str | Path | None = None,
) -> dict[str, Any]:
    pack = verify_knowledge_pack(
        descriptor, roots, expected_commit=PINNED_UPSTREAM_COMMIT,
        source_root=source_root,
    )
    return {
        "schema": "angerona/reverse-knowledge-pack-status/v1",
        "status": "VERIFIED_NO_DRIFT" if source_root is not None else "VERIFIED_SNAPSHOT",
        "pack_id": pack["pack_id"], "source_commit": pack["source"]["commit"],
        "file_count": pack["file_count"],
        "scan_finding_count": pack["scan_finding_count"],
        "retrievable_excerpt_count": pack["retrievable_excerpt_count"],
        "execution_semantics": "data-only-no-script-tool-network-execution",
    }
