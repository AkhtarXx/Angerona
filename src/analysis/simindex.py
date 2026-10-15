"""Deterministic mnemonic TF-IDF candidate index over IDA/Ghidra exports.

Research basis (angerona research notes, 2026-07-15):
  Part 7 (deep-learning BCRL) + Part 14 (benchmarks): binary code representation
  learning turns "compiled code" into "vectors you can search" — enabling function
  similarity, variant/malware-family detection, provenance, and dedup at scale. The
  SOTA stacks fuse graph structure (CFG) + token sequences. This module brings that
  capability IN-HOUSE over angerona's own exports, so variant analysis and provenance
  clustering work on the local corpus without any cloud call.

Design (production-grade, dependency-light, deterministic):
  * Feature = TF-weighted instruction-mnemonic n-grams (1-2). Operands and call targets
    are intentionally discarded; this implementation does not claim CFG or learned
    structural embeddings.
  * Embedding = L2-normalized log-TF-IDF vector in a fixed hashing space OR a trained
    TruncatedSVD reduction. We use scikit-learn's TfidfVectorizer (hashing) + an
    optional SVD for dimensionality, then FAISS (IndexFlatIP) for cosine search.
  * The audit harness pins exact NumPy cosine search. Standalone callers may opt into
    FAISS, but those results are not exact-resume audit evidence.

Use cases wired downstream:
  - variant detection: cluster functions across a corpus of known samples
  - provenance: "this function also appears in <known family>" (BinDiff-class signal)
  - dedup: skip re-analyzing near-identical functions across runs
"""

from __future__ import annotations

import csv
import io
import hashlib
import json
import math
import re
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import numpy as np

AUDIT_SIMILARITY_POLICY = {
    "feature_backend": "hashing_tfidf",
    "dimension": 512,
    "search_backend": "exact_numpy",
    "threshold": 0.80,
    "tie_margin": 0.02,
    "max_distinct_ties": 256,
    "minimum_tokens": 6,
    "minimum_unique_tokens": 4,
    "max_function_feature_tokens": 8192,
    "max_indexed_functions": 50_000,
    "max_aggregate_feature_tokens": 5_000_000,
    "max_function_body_bytes": 512 * 1024,
    "max_single_asm_bytes": 16 * 1024 * 1024,
    # One comparison is one 512-dimensional vector dot product.  Keeping the
    # unit explicit avoids understating this as 1,000,000 scalar operations.
    "max_vector_dot_products": 1_000_000,
    "max_emitted_candidates": 100_000,
    "max_query_candidates": 256,
}

# ----------------------------------------------------------------------- features
# Strip operands to mnemonics: "mov eax, 1" -> "mov"; keep call targets symbolically.
_MNEMON = re.compile(r"^\s*([a-z][a-z0-9.]*)", re.I)
_CALL = re.compile(r"\b(call|bl|jal|jmp)\b", re.I)
_SAFE_CORPUS_LABEL = re.compile(r"^[A-Za-z_~][A-Za-z0-9_.$@:~?]{0,127}$")
_UNSAFE_LABEL_CONTENT = re.compile(
    r"(?:ignore_?(?:all_?)?(?:previous_?)?instructions?|system_?prompt|jailbreak|"
    r"declare_?(?:critical|vulnerable|rce)|assistant_?message|prompt_?injection)", re.I
)
_ADDRESS_PREFIX = re.compile(r"^\s*(?:0x)?[0-9a-f]{4,16}\s*:\s*", re.I)
_OBJDUMP_PREFIX = re.compile(
    r"^\s*(?:0x)?[0-9a-f]{4,16}\s+(?:(?:[0-9a-f]{2})\s+){1,16}", re.I
)


def _function_tokens(asm: str) -> list[str]:
    """Extract mnemonic n-grams from a function's disassembly text."""
    mnems: list[str] = []
    max_tokens = int(AUDIT_SIMILARITY_POLICY["max_function_feature_tokens"])
    max_mnemonics = max_tokens // 2 + 1
    for line in io.StringIO(asm or ""):
        # drop address/offset prefixes like "0x401000:  mov ..."
        line = _ADDRESS_PREFIX.sub("", line, count=1)
        line = _OBJDUMP_PREFIX.sub("", line, count=1)
        m = _MNEMON.search(line)
        if m:
            op = m.group(1).lower()
            mnems.append(op)
            if _CALL.search(line):
                mnems.append("__call__")  # call-site signal
            if len(mnems) > max_mnemonics:
                break
    # build 1-2 grams
    grams = list(mnems)
    for i in range(len(mnems) - 1):
        grams.append(f"{mnems[i]}>{mnems[i + 1]}")
    return grams


def _safe_label(value: str) -> str:
    label = (value or "").strip()
    if _SAFE_CORPUS_LABEL.fullmatch(label) and not _UNSAFE_LABEL_CONTENT.search(label):
        return label
    return "corpus_fn_" + hashlib.sha256(label.encode("utf-8", errors="replace")).hexdigest()[:16]


def _safe_address(value: str) -> str:
    address = (value or "").strip()
    if re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", address):
        return address
    if re.fullmatch(r"corpus_addr_[0-9a-f]{16}", address):
        return address
    generated = re.fullmatch(r"(?:FUN_|SUB_|sub_)([0-9a-fA-F]{1,16})", address)
    if generated:
        return "0x" + generated.group(1).lower()
    return "corpus_addr_" + hashlib.sha256(
        address.encode("utf-8", errors="replace")
    ).hexdigest()[:16]


def _normalize_rows(matrix: np.ndarray) -> np.ndarray:
    matrix = np.asarray(matrix, dtype=np.float32)
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


def _bucket(token: str, dimension: int) -> int:
    return zlib.crc32(token.encode("utf-8", errors="ignore")) % dimension


def _hash_tfidf_fit(texts: list[str], dimension: int) -> tuple[np.ndarray, np.ndarray]:
    """Dependency-free, fixed-memory TF-IDF feature hashing backend."""
    rows: list[dict[int, int]] = []
    document_frequency = np.zeros(dimension, dtype=np.float32)
    for text in texts:
        counts: dict[int, int] = {}
        for token in text.split():
            slot = _bucket(token, dimension)
            counts[slot] = counts.get(slot, 0) + 1
        rows.append(counts)
        for slot in counts:
            document_frequency[slot] += 1.0

    n_docs = max(len(texts), 1)
    idf = np.log((1.0 + n_docs) / (1.0 + document_frequency)) + 1.0
    matrix = np.zeros((len(rows), dimension), dtype=np.float32)
    for row, counts in enumerate(rows):
        for slot, count in counts.items():
            matrix[row, slot] = (1.0 + math.log(count)) * idf[slot]
    return matrix, idf


def _hash_tfidf_transform(
    texts: list[str],
    dimension: int,
    idf: np.ndarray,
) -> np.ndarray:
    matrix = np.zeros((len(texts), dimension), dtype=np.float32)
    for row, text in enumerate(texts):
        counts: dict[int, int] = {}
        for token in text.split():
            slot = _bucket(token, dimension)
            counts[slot] = counts.get(slot, 0) + 1
        for slot, count in counts.items():
            matrix[row, slot] = (1.0 + math.log(count)) * idf[slot]
    return matrix


def _cosine_top_k(
    train: np.ndarray,
    queries: np.ndarray,
    top_k: int,
) -> tuple[np.ndarray, np.ndarray]:
    """Memory-bounded exact cosine search over normalized rows."""
    k = min(max(int(top_k), 0), len(train))
    if k == 0:
        shape = (len(queries), 0)
        return np.empty(shape, dtype=np.float32), np.empty(shape, dtype=np.int64)
    all_scores = np.empty((len(queries), k), dtype=np.float32)
    all_ids = np.empty((len(queries), k), dtype=np.int64)
    for row, query in enumerate(queries):
        scores = train @ query
        if k < len(scores):
            candidate_ids = np.argpartition(scores, -k)[-k:]
        else:
            candidate_ids = np.arange(len(scores))
        order = candidate_ids[np.argsort(scores[candidate_ids])[::-1]]
        all_ids[row] = order
        all_scores[row] = scores[order]
    return all_scores, all_ids


@dataclass
class FunctionEmbedding:
    addr: str
    name: str
    vector: np.ndarray
    size: int = 0


@dataclass
class Match:
    addr: str
    name: str
    score: float           # cosine similarity
    other_addr: str = ""
    other_name: str = ""
    other_source: str = ""
    query_token_count: int = 0
    query_unique_tokens: int = 0
    other_token_count: int = 0
    other_unique_tokens: int = 0

    def as_dict(self) -> dict:
        return {"addr": self.addr, "name": self.name,
                "score": round(float(self.score), 4),
                "other_addr": self.other_addr, "other_name": self.other_name,
                "other_source": self.other_source,
                "query_token_count": self.query_token_count,
                "query_unique_tokens": self.query_unique_tokens,
                "other_token_count": self.other_token_count,
                "other_unique_tokens": self.other_unique_tokens}


class SimilarityIndex:
    """Trainable binary-similarity index over exported functions.

    Usage:
        idx = SimilarityIndex()
        idx.add_corpus(export_dir)          # from one binary's functions.csv+asm
        idx.build()                          # fit TF-IDF + FAISS
        matches = idx.query(export_dir2, top_k=5)
    """

    def __init__(self, dim_reduce: int = 256, backend: str = "auto",
                 search_backend: str = "auto"):
        if backend not in {"auto", "sklearn", "hashing"}:
            raise ValueError("similarity backend must be auto, sklearn, or hashing")
        if search_backend not in {"auto", "exact", "faiss"}:
            raise ValueError("similarity search backend must be auto, exact, or faiss")
        self.dim_reduce = dim_reduce
        self._requested_backend = backend
        self._search_backend = search_backend
        self._docs: list[tuple[str, str, str]] = []   # (addr, name, asm_text)
        self._sources: list[str] = []
        self._token_stats: list[tuple[int, int]] = []
        self._token_documents: list[str] = []
        self._aggregate_tokens = 0
        self._identity: dict = {}
        self._unsafe_label_count = 0
        self._funcs: list[FunctionEmbedding] = []
        self._vecmat: Optional[np.ndarray] = None
        self._index = None
        self._faiss = None if search_backend == "exact" else self._try_faiss()
        if search_backend == "faiss" and self._faiss is None:
            raise RuntimeError("FAISS search backend requested but unavailable")
        self._backend = ""
        self._vectorizer = None
        self._svd = None
        self._hash_idf: Optional[np.ndarray] = None
        self._hash_dim = max(int(dim_reduce or 2048), 8)

    @staticmethod
    def _try_faiss():
        try:
            import faiss  # type: ignore
            return faiss
        except Exception:
            return None

    # --------------------------------------------------------------- ingestion
    def add_function(self, addr: str, name: str, asm_text: str, source: str = "",
                     token_count: int | None = None,
                     unique_token_count: int | None = None) -> None:
        safe_name = _safe_label(name)
        if safe_name != (name or "").strip():
            self._unsafe_label_count += 1
        self._docs.append((_safe_address(addr), safe_name, asm_text))
        self._sources.append(source)
        tokens = _function_tokens(asm_text) if token_count is None else []
        resolved_count = len(tokens) if token_count is None else int(token_count)
        resolved_unique = len(set(tokens)) if unique_token_count is None else int(unique_token_count)
        if resolved_count > int(AUDIT_SIMILARITY_POLICY["max_function_feature_tokens"]):
            self._docs.pop()
            self._sources.pop()
            raise ValueError("function exceeds similarity feature-token limit")
        if len(self._docs) > int(AUDIT_SIMILARITY_POLICY["max_indexed_functions"]):
            self._docs.pop()
            self._sources.pop()
            raise ValueError("similarity corpus exceeds indexed-function limit")
        if self._aggregate_tokens + resolved_count > int(
            AUDIT_SIMILARITY_POLICY["max_aggregate_feature_tokens"]
        ):
            self._docs.pop()
            self._sources.pop()
            raise ValueError("similarity corpus exceeds aggregate feature-token limit")
        self._aggregate_tokens += resolved_count
        self._token_stats.append((resolved_count, resolved_unique))
        self._token_documents.append(" ".join(tokens) if token_count is None else "")

    def add_corpus(self, code_dir: str | Path) -> int:
        """Ingest functions from an export dir (functions.csv + decompiled/*.c asm).

        We prefer the per-function disassembly if present; falls back to decompiled C
        tokenization (less ideal but still informative). Returns count ingested.
        """
        d = Path(code_dir)
        # Prefer a dumped asm dir if the engine wrote one.
        asm_dir = d / "asm"
        count = 0
        # functions.csv: name,entry,size,signature
        fcsv = d / "functions.csv"
        names: dict[str, str] = {}
        if fcsv.is_file():
            with fcsv.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                for row in csv.DictReader(handle):
                    name = str(row.get("name") or "").strip()
                    entry = str(row.get("entry") or "").strip()
                    if name and entry:
                        names[entry] = name

        def canonical_name(stem: str) -> str:
            exact_names = {name for name in names.values() if stem == name}
            if len(exact_names) == 1:
                return next(iter(exact_names))
            matched: set[str] = set()
            for entry, name in names.items():
                clean_entry = entry.lower().removeprefix("0x").lstrip("0") or "0"
                if re.search(
                    rf"(?<![0-9a-f])(?:0x)?0*{re.escape(clean_entry)}(?![0-9a-f])",
                    stem,
                    re.I,
                ):
                    matched.add(name)
            if len(matched) == 1:
                return next(iter(matched))
            return stem

        def canonical_entry(stem: str) -> str:
            matched: set[str] = set()
            for entry in names:
                clean_entry = entry.lower().removeprefix("0x").lstrip("0") or "0"
                if re.search(
                    rf"(?<![0-9a-f])(?:0x)?0*{re.escape(clean_entry)}(?![0-9a-f])",
                    stem,
                    re.I,
                ):
                    matched.add(entry)
            return next(iter(matched)) if len(matched) == 1 else stem

        if asm_dir.is_file():
            # single asm file: split per-function by marker
            if asm_dir.stat().st_size > int(AUDIT_SIMILARITY_POLICY["max_single_asm_bytes"]):
                raise ValueError("single-file similarity assembly exceeds byte limit")
            text = asm_dir.read_text(errors="ignore")
            for block in re.split(r"\n-{10,}\n", text):
                head = re.search(r"([0-9a-fA-Fx]+)\s+(\w+)", block)
                if head:
                    self.add_function(
                        head.group(1), head.group(2), block, source=str(d)
                    )
                    count += 1
        elif asm_dir.is_dir():
            for af in sorted(asm_dir.glob("*.asm")):
                if af.stat().st_size > int(AUDIT_SIMILARITY_POLICY["max_function_body_bytes"]):
                    raise ValueError(f"similarity function body exceeds byte limit: {af.name}")
                text = af.read_text(errors="ignore")
                self.add_function(
                    canonical_entry(af.stem), canonical_name(af.stem), text, source=str(d)
                )
                count += 1
        # fallback: per-function decompiled C (tokenize as pseudo-asm)
        if count == 0:
            for cf in sorted(d.glob("decompiled/*.c")):
                if cf.stat().st_size > int(AUDIT_SIMILARITY_POLICY["max_function_body_bytes"]):
                    raise ValueError(f"similarity function body exceeds byte limit: {cf.name}")
                asm = cf.read_text(errors="ignore")
                self.add_function(
                    canonical_entry(cf.stem), canonical_name(cf.stem), asm, source=str(d)
                )
                count += 1
        return count

    # ------------------------------------------------------------------ build
    # ----------------------------------------------------- raw-asm query / embed
    def embed_function(self, asm: str) -> Optional[np.ndarray]:
        """Return the embedding vector for one function's disassembly text.

        Requires build() to have run. Used by the BCRL stage (Part 7) so a masked
        asm string can be embedded directly without a code_dir.
        """
        if self._vecmat is None:
            return None
        return self._embed_texts([" ".join(_function_tokens(asm))])[0]

    def _embed_texts(self, texts: list[str]) -> np.ndarray:
        if self._backend == "sklearn" and self._vectorizer is not None:
            matrix = self._vectorizer.transform(texts)
            if self._svd is not None:
                matrix = self._svd.transform(matrix)
            else:
                matrix = matrix.toarray()
            return _normalize_rows(matrix)
        if self._backend == "hashing" and self._hash_idf is not None:
            return _normalize_rows(
                _hash_tfidf_transform(
                    texts,
                    self._hash_dim,
                    self._hash_idf,
                )
            )
        raise RuntimeError("similarity index is not built")

    def query_text(self, asm: str, top_k: int = 5,
                   threshold: float = 0.70) -> list[Match]:
        """Query the index by raw disassembly text (Part 7 / BCRL). Returns
        Match objects (name=other_name of indexed function)."""
        if self._vecmat is None:
            return []
        if top_k > int(AUDIT_SIMILARITY_POLICY["max_query_candidates"]):
            raise ValueError("similarity query exceeds candidate-output limit")
        qv = self._embed_texts([" ".join(_function_tokens(asm))])
        if not qv.any():
            return []
        X_train = self._vecmat
        if self._faiss is not None:
            import faiss  # type: ignore
            idx = faiss.IndexFlatIP(X_train.shape[1])
            idx.add(X_train)
            scores, ids = idx.search(qv, min(top_k, len(X_train)))
        else:
            scores, ids = _cosine_top_k(X_train, qv, top_k)
        out: list[Match] = []
        for rank in range(min(top_k, len(ids[0]))):
            j = int(ids[0][rank])
            if j < 0:
                continue
            sc = float(scores[0][rank])
            if sc < threshold:
                continue
            taddr, tname, _ = self._docs[j]
            out.append(Match(
                addr=taddr, name=tname, score=sc,
                other_source=self._sources[j] if j < len(self._sources) else "",
            ))
        return out

    # ------------------------------------------------------------------ build
    def build(self) -> None:
        if not self._docs:
            raise RuntimeError("no functions ingested; call add_corpus/add_function first")
        corpus = list(self._token_documents)
        try:
            if self._requested_backend == "hashing":
                raise ImportError("deterministic hashing backend requested")
            from sklearn.decomposition import TruncatedSVD
            from sklearn.feature_extraction.text import TfidfVectorizer

            self._vectorizer = TfidfVectorizer(
                tokenizer=str.split,
                preprocessor=lambda x: x,
                token_pattern=None,
                max_features=20000,
                sublinear_tf=True,
            )
            X = self._vectorizer.fit_transform(corpus)
            if self.dim_reduce and self.dim_reduce < X.shape[1]:
                try:
                    self._svd = TruncatedSVD(
                        n_components=min(self.dim_reduce, X.shape[1] - 1),
                        random_state=0,
                    )
                    X = self._svd.fit_transform(X)
                except Exception:
                    self._svd = None
                    X = X.toarray()
            else:
                X = X.toarray()
            self._backend = "sklearn"
        except ImportError:
            if self._requested_backend == "sklearn":
                raise
            X, self._hash_idf = _hash_tfidf_fit(corpus, self._hash_dim)
            self._backend = "hashing"
            self._vectorizer = None
            self._svd = None
        X = _normalize_rows(X)
        self._vecmat = X
        self._funcs = [FunctionEmbedding(addr, name, X[i])
                       for i, (addr, name, _) in enumerate(self._docs)]
        if self._faiss is not None:
            import faiss  # type: ignore
            index = faiss.IndexFlatIP(X.shape[1])
            index.add(X)
            self._index = index
        else:
            self._index = None

    # ------------------------------------------------------------------ query
    def query(self, code_dir: str | Path, top_k: int = 5,
              threshold: float = 0.70) -> list[Match]:
        """Find functions in this index similar to functions in ``code_dir``.

        Encodes query functions in the SAME fitted TF-IDF/SVD or hashing space
        as the index, then searches via FAISS or exact NumPy cosine. Returns
        matches above ``threshold`` (cosine similarity).
        """
        if self._vecmat is None:
            return []
        if top_k > int(AUDIT_SIMILARITY_POLICY["max_query_candidates"]):
            raise ValueError("similarity query exceeds candidate-output limit")
        tmp = SimilarityIndex(dim_reduce=self.dim_reduce)
        tmp.add_corpus(code_dir)
        if not tmp._docs:
            return []
        if len(tmp._docs) * len(self._docs) > int(
            AUDIT_SIMILARITY_POLICY["max_vector_dot_products"]
        ):
            raise ValueError("similarity query exceeds vector-dot-product work limit")
        query_texts = list(tmp._token_documents)
        X_train = self._vecmat
        X_query = self._embed_texts(query_texts)
        zero_mask = np.linalg.norm(X_query, axis=1) == 0
        # zero-vector queries (no shared vocabulary) must not match anything
        if self._faiss is not None:
            import faiss  # type: ignore
            idx = faiss.IndexFlatIP(X_train.shape[1])
            idx.add(X_train)
            scores, ids = idx.search(X_query, min(top_k + 1, len(X_train)))
        else:
            scores, ids = _cosine_top_k(X_train, X_query, top_k + 1)
        out: list[Match] = []
        for qi, (qaddr, qname, _) in enumerate(tmp._docs):
            if zero_mask[qi]:
                continue  # no shared vocabulary -> cannot match
            for rank in range(min(top_k, len(ids[qi]))):
                j = int(ids[qi][rank])
                if j < 0:
                    continue
                sc = float(scores[qi][rank])
                if sc < threshold:
                    continue
                if len(out) >= int(
                    AUDIT_SIMILARITY_POLICY["max_emitted_candidates"]
                ):
                    raise ValueError(
                        "similarity query exceeds aggregate candidate-output limit"
                    )
                taddr, tname, _ = self._docs[j]
                out.append(Match(addr=qaddr, name=qname, score=sc,
                                 other_addr=taddr, other_name=tname,
                                 other_source=(
                                     self._sources[j] if j < len(self._sources) else ""
                                 )))
        return out

    def query_ties(
        self,
        code_dir: str | Path,
        *,
        threshold: float = 0.70,
        margin: float = 0.02,
        max_distinct: int = 256,
    ) -> tuple[
        list[Match], set[tuple[str, str]], set[tuple[str, str]]
    ]:
        """Return one candidate per distinct corpus/source label near each best score.

        Unlike top-k ANN retrieval, duplicate corpus rows cannot crowd a conflicting
        equally-scored label out of ambiguity analysis. The second return value marks
        query keys whose distinct tie set exceeded the explicit output bound.
        The third return value preserves low-information query rejection evidence.
        """

        if self._vecmat is None:
            return [], set(), set()
        tmp = SimilarityIndex(
            dim_reduce=self.dim_reduce, backend=self._requested_backend,
            search_backend="exact",
        )
        tmp.add_corpus(code_dir)
        if not tmp._docs:
            return [], set(), set()
        eligible_rows = sum(
            1 for count, unique in tmp._token_stats
            if count >= int(AUDIT_SIMILARITY_POLICY["minimum_tokens"])
            and unique >= int(AUDIT_SIMILARITY_POLICY["minimum_unique_tokens"])
        )
        if eligible_rows * len(self._docs) > int(
            AUDIT_SIMILARITY_POLICY["max_vector_dot_products"]
        ):
            raise ValueError("similarity query exceeds vector-dot-product work limit")
        query_texts = list(tmp._token_documents)
        query_vectors = self._embed_texts(query_texts)
        out: list[Match] = []
        truncated: set[tuple[str, str]] = set()
        low_information: set[tuple[str, str]] = set()
        for row, (qaddr, qname, _asm) in enumerate(tmp._docs):
            if (
                tmp._token_stats[row][0] < int(AUDIT_SIMILARITY_POLICY["minimum_tokens"])
                or tmp._token_stats[row][1]
                < int(AUDIT_SIMILARITY_POLICY["minimum_unique_tokens"])
            ):
                low_information.add((qaddr, qname))
                continue
            vector = query_vectors[row]
            if not vector.any():
                continue
            scores = self._vecmat @ vector
            best_score = float(np.max(scores)) if len(scores) else 0.0
            floor = max(float(threshold), best_score - max(float(margin), 0.0))
            candidate_ids = np.flatnonzero(scores >= floor)
            ordered = candidate_ids[np.argsort(scores[candidate_ids])[::-1]]
            distinct: set[tuple[str, str]] = set()
            key = (qaddr, qname)
            for candidate_id in ordered:
                index = int(candidate_id)
                taddr, tname, corpus_asm = self._docs[index]
                source = self._sources[index] if index < len(self._sources) else ""
                identity = (source, tname)
                if identity in distinct:
                    continue
                distinct.add(identity)
                if len(distinct) > max_distinct:
                    truncated.add(key)
                    break
                corpus_stats = (
                    self._token_stats[index]
                    if index < len(self._token_stats)
                    else (len(_function_tokens(corpus_asm)), len(set(_function_tokens(corpus_asm))))
                )
                if len(out) >= int(
                    AUDIT_SIMILARITY_POLICY["max_emitted_candidates"]
                ):
                    raise ValueError(
                        "similarity query exceeds aggregate candidate-output limit"
                    )
                out.append(Match(
                    addr=qaddr, name=qname, score=float(scores[index]),
                    other_addr=taddr, other_name=tname, other_source=source,
                    query_token_count=tmp._token_stats[row][0],
                    query_unique_tokens=tmp._token_stats[row][1],
                    other_token_count=corpus_stats[0],
                    other_unique_tokens=corpus_stats[1],
                ))
        return out, truncated, low_information

    def save(self, path: str | Path, *, identity: dict | None = None) -> None:
        """Persist a complete, safely loadable fitted index for exact local reuse."""
        path = Path(path)
        if self._vecmat is None:
            self.build()
        arrays: dict[str, np.ndarray] = {"vectors": np.asarray(self._vecmat)}
        vocabulary: list[list[object]] = []
        if self._backend == "hashing" and self._hash_idf is not None:
            arrays["hash_idf"] = np.asarray(self._hash_idf)
        elif self._backend == "sklearn" and self._vectorizer is not None:
            arrays["idf"] = np.asarray(self._vectorizer.idf_)
            vocabulary = sorted(
                [[str(token), int(slot)] for token, slot in self._vectorizer.vocabulary_.items()],
                key=lambda row: int(row[1]),
            )
            if self._svd is not None:
                arrays["svd_components"] = np.asarray(self._svd.components_)
        else:
            raise RuntimeError("similarity index backend is incomplete")
        meta = {
            "schema_version": 1,
            "backend": self._backend,
            "requested_backend": self._requested_backend,
            "search_backend": self._search_backend,
            "dim_reduce": self.dim_reduce,
            "hash_dim": self._hash_dim,
            "vocabulary": vocabulary,
            "documents": [
                {
                    "addr": addr,
                    "name": name,
                    "source": self._sources[index] if index < len(self._sources) else "",
                    "token_count": self._token_stats[index][0],
                    "unique_token_count": self._token_stats[index][1],
                }
                for index, (addr, name, _asm) in enumerate(self._docs)
            ],
            "identity": identity or self._identity,
            "unsafe_label_count": self._unsafe_label_count,
        }
        path.parent.mkdir(parents=True, exist_ok=True)
        npz_tmp = path.with_suffix(".npz.tmp")
        json_tmp = path.with_suffix(".json.tmp")
        with npz_tmp.open("wb") as handle:
            np.savez_compressed(handle, **arrays)
        json_tmp.write_text(json.dumps(meta, sort_keys=True), encoding="utf-8")
        npz_tmp.replace(path.with_suffix(".npz"))
        json_tmp.replace(path.with_suffix(".json"))

    @classmethod
    def load(cls, path: str | Path) -> "SimilarityIndex":
        """Load an index written by :meth:`save` without pickle execution."""

        path = Path(path)
        meta = json.loads(path.with_suffix(".json").read_text(encoding="utf-8"))
        if not isinstance(meta, dict) or meta.get("schema_version") != 1:
            raise ValueError("unsupported similarity index metadata")
        with np.load(path.with_suffix(".npz"), allow_pickle=False) as stored:
            arrays = {name: np.asarray(stored[name]) for name in stored.files}
        vectors = arrays.get("vectors")
        documents = meta.get("documents")
        if vectors is None or not isinstance(documents, list) or len(vectors) != len(documents):
            raise ValueError("similarity index metadata/vector count mismatch")
        idx = cls(
            dim_reduce=int(meta.get("dim_reduce") or 0),
            backend=str(meta.get("requested_backend") or meta.get("backend") or "auto"),
            search_backend=str(meta.get("search_backend") or "exact"),
        )
        idx._hash_dim = int(meta.get("hash_dim") or idx._hash_dim)
        idx._backend = str(meta.get("backend") or "")
        loaded_identity = meta.get("identity")
        if loaded_identity is not None and not isinstance(loaded_identity, dict):
            raise ValueError("invalid similarity index identity metadata")
        idx._identity = dict(loaded_identity or {})
        persisted_unsafe_count = int(meta.get("unsafe_label_count") or 0)
        for item in documents:
            if not isinstance(item, dict):
                raise ValueError("invalid similarity index document metadata")
            idx.add_function(
                str(item.get("addr") or ""),
                str(item.get("name") or ""),
                "",
                source=str(item.get("source") or ""),
                token_count=int(item.get("token_count") or 0),
                unique_token_count=int(item.get("unique_token_count") or 0),
            )
        idx._unsafe_label_count = persisted_unsafe_count
        idx._vecmat = _normalize_rows(vectors)
        idx._funcs = [
            FunctionEmbedding(addr, name, idx._vecmat[row])
            for row, (addr, name, _asm) in enumerate(idx._docs)
        ]
        if idx._backend == "hashing":
            if "hash_idf" not in arrays:
                raise ValueError("hashing similarity index is missing IDF weights")
            idx._hash_idf = arrays["hash_idf"]
        elif idx._backend == "sklearn":
            try:
                from sklearn.decomposition import TruncatedSVD
                from sklearn.feature_extraction.text import TfidfVectorizer
            except ImportError as exc:
                raise RuntimeError("scikit-learn is required to load this index") from exc
            vocabulary = meta.get("vocabulary")
            if not isinstance(vocabulary, list) or "idf" not in arrays:
                raise ValueError("sklearn similarity index is missing fitted state")
            vocab = {str(row[0]): int(row[1]) for row in vocabulary}
            vectorizer = TfidfVectorizer(
                tokenizer=str.split,
                preprocessor=lambda value: value,
                token_pattern=None,
                max_features=20000,
                sublinear_tf=True,
                vocabulary=vocab,
            )
            vectorizer.idf_ = arrays["idf"]
            idx._vectorizer = vectorizer
            if "svd_components" in arrays:
                components = arrays["svd_components"]
                svd = TruncatedSVD(n_components=len(components), random_state=0)
                svd.components_ = components
                svd.n_features_in_ = components.shape[1]
                idx._svd = svd
        else:
            raise ValueError(f"unsupported similarity index backend: {idx._backend!r}")
        return idx
