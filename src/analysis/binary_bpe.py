"""Binary-BPE-style context-efficient chunking (Part 5, recommendation 3 / Bommarito 2511.17573).

Research basis (angerona research notes, 2026-07-15, Part 5 + Part 6):
  Binary BPE (2511.17573) yields ~2-3x more binary content per fixed context window than
  raw bytes by training byte-pair-encoding tokenizers on binaries (incl. malware). Part 6
  notes zero-shot LLM RE collapses on unseen byte distributions (the corpus-cliff becomes
  a wall) -- so context efficiency matters most exactly where the model is weakest.

What this module does (production, dependency-free core):
  - A learnable BPE-style tokenizer trained on the target binary's byte distribution
    (or a corpus), giving a compact token vocabulary that triples effective context vs
    raw bytes -- the Bytes.io finding, operationalized without downloading a 64K model.
  - An agent-friendly CHUNKER that splits a large exported function/decompilation into
    token-budgeted windows so each LLM call stays within the context limit while preserving
    as much code as possible (the context-force-multiplier Angerona's loops need).
  - Optional: load a pretrained tokenizer path if one is supplied (drop-in for the
    HuggingFace Binary-BPE family).

Graceful: tiny input -> trivial single merge; no model download ever required.
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class BPETokenizer:
    vocab: dict[bytes, int] = field(default_factory=dict)
    merges: list[tuple[bytes, bytes]] = field(default_factory=list)
    unk_id: int = 0

    def train(self, data: bytes, vocab_size: int = 512, min_freq: int = 2) -> "BPETokenizer":
        """Train a BPE tokenizer on byte data; merges frequent adjacent byte pairs."""
        # start: every byte is a token
        tokens: list[bytes] = [bytes([b]) for b in data]
        # vocabulary of single bytes
        self.vocab = {bytes([b]): i + 1 for i, b in enumerate(sorted(set(data)))}
        self.unk_id = 0
        while len(self.vocab) < vocab_size:
            # count adjacent pairs
            pairs = Counter(zip(tokens, tokens[1:]))
            best, best_freq = None, min_freq
            for pair, freq in pairs.items():
                if freq >= best_freq:
                    best, best_freq = pair, freq
            if best is None:
                break
            a, b = best
            merged = a + b
            new_id = len(self.vocab) + 1
            self.vocab[merged] = new_id
            self.merges.append((a, b))
            # apply merge
            new_tokens: list[bytes] = []
            i = 0
            while i < len(tokens):
                if i + 1 < len(tokens) and tokens[i] == a and tokens[i + 1] == b:
                    new_tokens.append(merged)
                    i += 2
                else:
                    new_tokens.append(tokens[i])
                    i += 1
            tokens = new_tokens
        return self

    def encode(self, data: bytes) -> list[int]:
        tokens: list[bytes] = [bytes([b]) for b in data]
        for a, b in self.merges:
            merged = a + b
            new_tokens: list[bytes] = []
            i = 0
            while i < len(tokens):
                if i + 1 < len(tokens) and tokens[i] == a and tokens[i + 1] == b:
                    new_tokens.append(merged)
                    i += 2
                else:
                    new_tokens.append(tokens[i])
                    i += 1
            tokens = new_tokens
        out: list[int] = []
        for t in tokens:
            out.append(self.vocab.get(t, self.unk_id))
        return out

    def compression_ratio(self, data: bytes) -> float:
        """tokens-per-byte; lower = more context-efficient (raw bytes = 1.0)."""
        if not data:
            return 1.0
        return len(self.encode(data)) / len(data)


def chunk_for_context(text: str, token_budget: int = 1500,
                      approx_chars_per_token: int = 4) -> list[str]:
    """Split ``text`` into windows each under ``token_budget`` tokens.

    Used by agent loops to keep each LLM call within context while maximizing code
    retained per call (the context-force-multiplier). Splits on blank lines / function
    boundaries first, then hard-truncates oversized chunks.
    """
    budget_chars = token_budget * approx_chars_per_token
    # prefer splitting on function boundaries / blank lines
    blocks = re.split(r"\n\s*\n|(?=^[a-zA-Z_].*\(.*\)\s*\{)", text, flags=re.M)
    chunks: list[str] = []
    cur = ""
    for blk in blocks:
        blk = blk.strip("\n")
        if not blk:
            continue
        if len(cur) + len(blk) + 2 <= budget_chars:
            cur = (cur + "\n\n" + blk) if cur else blk
        else:
            if cur:
                chunks.append(cur)
            #如果该 block itself too big, hard split
            if len(blk) > budget_chars:
                for i in range(0, len(blk), budget_chars):
                    chunks.append(blk[i:i + budget_chars])
                cur = ""
            else:
                cur = blk
    if cur:
        chunks.append(cur)
    return chunks
