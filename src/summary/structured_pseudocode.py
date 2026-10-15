"""Phoenix/DREAM-style structured pseudocode over :class:`FunctionCFG`.

This module turns a control flow graph (as produced by
:mod:`src.analysis.cfg_spine`) into goto-free, C-like pseudocode wherever the
control flow is *provably* structured.  The philosophy follows the Phoenix
decompiler (Emery & Berger, CCS 2013) and DREAM's shaping discipline: only
emit a high-level construct (``if`` / ``else`` / ``while`` / ``do-while``)
when the graph shape *proves* it; anything that does not match a known shape
degrades to an explicit ``goto <label>;`` so control flow is never invented —
SOTA truthfulness beats pretty output.

Pipeline:
  1. ``compute_postdominators`` — classic meet-over-paths over the reversed
     CFG, stdlib only, correct even when the CFG has no real return block
     (a synthetic virtual exit keeps the dataflow well-founded).
  2. ``find_back_edges`` + region analysis — detect while / do-while loops
     from back edges and if-then / if-then-else diamonds from immediate
     post-dominators.
  3. Emission — nesting depth is preserved in :class:`PseudocodeLine`; raw
     assembly stays inline as ``// asm: <text>`` comments unless the caller
     passes ``render_asm=False``.

Truthfulness rules:
  * A condition is only rendered when the preceding ``cmp``/``test`` operands
    are known; otherwise a deterministic ``/* <branch mnemonic> */ cond``
    marker is emitted.  Nothing is fabricated.
  * Malformed graphs (missing entry, dangling successors, ...) never raise —
    the generator degrades to flat output with a ``// unstructured`` marker.
"""

from __future__ import annotations

from typing import Any, Iterable, Sequence

from src.analysis.cfg_spine import BasicBlock, FunctionCFG
from src.summary.models import PseudocodeFunction, PseudocodeLine

__all__ = [
    "match_condition",
    "negate_condition",
    "compute_dominators",
    "compute_postdominators",
    "find_back_edges",
    "StructuredPseudocode",
    "StructuredPseudocodeGenerator",
]


# ----------------------------------------------------------------------------- condition inference

_UNCONDITIONAL_JUMPS = {"jmp", "b", "br", "bra"}
_RETURN_MNEMONICS = {"ret", "retn", "retf", "iret", "iretd", "iretq", "eret", "mret", "sret"}
_FLOAT_COMPARES = {"fcom", "fcomp", "fcompp", "fucom", "fucomp", "fucompp", "fcomi", "fucomi"}
_COMPARE_MNEMONICS = {"cmp", "cmn", "test", "tst"} | _FLOAT_COMPARES

# x86-style mnemonic -> operator between the two operands of the FIRST compare
# that the branch reads flags from.
_X86_CONDITIONS: dict[str, str] = {
    "je": "==", "jz": "==",
    "jne": "!=", "jnz": "!=",
    "jl": "<", "jnge": "<",
    "jle": "<=", "jng": "<=",
    "jg": ">", "jnle": ">",
    "jge": ">=", "jnl": ">=",
    "ja": ">", "jnbe": ">",                      # unsigned
    "jae": ">=", "jnb": ">=", "jnc": ">=",
    "jb": "<", "jnae": "<", "jc": "<",
    "jbe": "<=", "jna": "<=",
    "jo": "overflow", "jno": "!overflow",
    "js": "< 0", "jns": ">= 0",
    "jp": "parity", "jpe": "parity",
    "jnp": "!parity", "jpo": "!parity",
}

_ARM_CONDITION_SUFFIXES: dict[str, str] = {
    "eq": "==", "ne": "!=", "lt": "<", "le": "<=", "gt": ">", "ge": ">=",
    "hi": ">", "lo": "<", "hs": ">=", "ls": "<=",
    "cs": ">=", "cc": "<", "mi": "< 0", "pl": ">= 0",
    "vs": "overflow", "vc": "!overflow",
}

# MIPS: the comparison is folded into the branch instruction itself.
_MIPS_BRANCHES: dict[str, tuple[str, str | None]] = {
    "beq": ("==", None), "bne": ("!=", None),       # two-register compare
    "beqz": ("==", "0"), "bnez": ("!=", "0"),
    "bgez": (">=", "0"), "bgtz": (">", "0"),
    "blez": ("<=", "0"), "bltz": ("<", "0"),
}

# eBPF / SBF: comparison folded into the branch (jset is a bitmask test).
_SBF_CONDITIONS: dict[str, str] = {
    "jeq": "==", "jne": "!=", "jlt": "<", "jle": "<=",
    "jgt": ">", "jge": ">=", "jset": "&",
}

# Flagless x86 loop/test branches: register compared to zero implicitly.
_X86_FLAGLESS: dict[str, tuple[str, str]] = {
    "jcxz": ("cx", "=="), "jecxz": ("ecx", "=="), "jrcxz": ("rcx", "=="),
    "loop": ("ecx", "!="), "loope": ("ecx", "=="), "loopne": ("ecx", "!="),
}

import re as _re

# Register-telling regexes used to disambiguate x86 vs SBF ``jne`` etc.
_SBF_REGISTER_RE = _re.compile(r"\b[rw](?:1[0-5]|[0-9])\b")
_X86_REGISTER_RE = _re.compile(
    r"\b(?:e?[abcd]x|r(?:1[0-5]|[89])(?:[bwd])?|e?[sd]i|e?[sb]p|"
    r"[abcd][hl]|r(?:ip|sp|bp|di|si)|[abcd]x|[sd]i|[sb]p)\b")


def _split_operands(text: str) -> list[str]:
    """Split an operand string on top-level commas, honoring brackets/parens."""
    parts: list[str] = []
    depth = 0
    cur: list[str] = []
    for ch in text or "":
        if ch in "[(":
            depth += 1
        elif ch in "])":
            depth = max(0, depth - 1)
        if ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    tail = "".join(cur).strip()
    if tail:
        parts.append(tail)
    return parts


def _find_flag_setter(instructions: Sequence[dict[str, Any]]) -> dict[str, Any] | None:
    """Find the last cmp/test before the trailing branch (if any).

    Only ``cmp``/``test``/``tst``/``fcom*`` qualify: they never overwrite their
    operands, so their operands provably define the branch condition.  Stops
    at the first other instruction because anything else may clobber flags.
    """
    for instr in reversed(list(instructions)):
        mnemonic = str(instr.get("mnemonic", "")).lower().strip()
        if mnemonic in _COMPARE_MNEMONICS:
            return instr
        if _is_conditional_branch(mnemonic) or mnemonic in _UNCONDITIONAL_JUMPS:
            continue
        break
    return None


def match_condition(mnemonic: str, operands: str | Iterable[str]) -> str:
    """Render a readable condition for a conditional branch.

    ``mnemonic`` is the branch mnemonic (e.g. ``je``); ``operands`` carries
    the operands of the *preceding compare/test* (string ``"eax, 5"`` or list
    ``["eax", "5"]``), or the branch's own operands for architectures that
    fold the comparison into the branch (MIPS/SBF) or flagless x86 branches.

    Unmatched inputs return the deterministic opaque marker
    ``/* <mnemonic> */ cond`` — nothing is fabricated.
    """
    m = (mnemonic or "").lower().strip()
    if isinstance(operands, str):
        ops = _split_operands(operands)
    else:
        ops = [str(o).strip() for o in operands if str(o).strip()]

    try:
        expr = _render_condition(m, ops)
    except Exception:
        expr = None
    return expr if expr else f"/* {m or 'unknown'} */ cond"


def _render_condition(m: str, ops: list[str]) -> str | None:
    if not m:
        return None

    if m in _X86_FLAGLESS:
        reg, op = _X86_FLAGLESS[m]
        return f"{reg} {op} 0"

    if m in _MIPS_BRANCHES:
        op, rhs = _MIPS_BRANCHES[m]
        if rhs is None and len(ops) >= 2:
            return f"{ops[0]} {op} {ops[1]}"
        if rhs is not None and ops:
            return f"{ops[0]} {op} {rhs}"
        return None

    if m in _SBF_CONDITIONS and len(ops) >= 2:
        op = _SBF_CONDITIONS[m]
        if op == "&":
            return f"({ops[0]} & {ops[1]}) != 0"
        return f"{ops[0]} {op} {ops[1]}"

    if m in _X86_CONDITIONS:
        op = _X86_CONDITIONS[m]
        if op in ("overflow", "!overflow", "parity", "!parity"):
            return f"flags: {op}"
        if op in ("< 0", ">= 0"):
            return f"{ops[0]} {op}" if ops else None
        if len(ops) >= 2:
            return f"{ops[0]} {op} {ops[1]}"
        if len(ops) == 1:
            # Single-operand compare (test eax, eax): read against zero.
            if op == "==":
                return f"{ops[0]} == 0"
            if op == "!=":
                return f"{ops[0]} != 0"
        return None

    # ARM / AArch64 suffixes: beq, bne, blt, bcs, bhi, blo, bhs, ...
    if m.startswith("b") and m not in {"b", "bal", "br", "bra", "bx", "blx", "bl", "blr"}:
        suffix = m[1:]
        if suffix in _ARM_CONDITION_SUFFIXES:
            op = _ARM_CONDITION_SUFFIXES[suffix]
        elif suffix.endswith(".w") and suffix[:-2] in _ARM_CONDITION_SUFFIXES:
            op = _ARM_CONDITION_SUFFIXES[suffix[:-2]]
        else:
            return None
        if op in ("< 0", ">= 0", "overflow", "!overflow"):
            return f"{ops[0]} {op}" if ops else None
        if len(ops) >= 2:
            return f"{ops[0]} {op} {ops[1]}"
        if len(ops) == 1:
            if op == "==":
                return f"{ops[0]} == 0"
            if op == "!=":
                return f"{ops[0]} != 0"
        return None

    return None


def negate_condition(cond: str) -> str:
    """Structurally negate a rendered condition string."""
    is_unknown = " cond" in cond and "/*" in cond
    flip = {"==": "!=", "!=": "==", "<=": ">", ">=": "<", "<": ">=", ">": "<="}
    for op in ("==", "!=", "<=", ">=", "<", ">"):
        token = f" {op} "
        if token in cond:
            lhs, rhs = cond.split(token, 1)
            negated = f"{lhs} {flip[op]} {rhs}"
            return f"!({negated})" if is_unknown else negated
    stripped = cond.strip()
    return f"!{stripped}" if is_unknown else (stripped[1:]
                                              if stripped.startswith("!(") and stripped.endswith(")")
                                              else f"!({stripped})")


# ----------------------------------------------------------------------------- dominator machinery


def compute_dominators(cfg: FunctionCFG) -> dict[str, set[str]]:
    """Forward dominators via classic iterative dataflow (stdlib only).

    Returns ``{block: set(dominators)}``; unreachable blocks map to ``{block}``.
    Never raises on malformed CFGs.
    """
    blocks = set(cfg.blocks)
    entry = cfg.entry if cfg.entry in cfg.blocks else None
    if entry is None and blocks:
        entry = sorted(blocks, key=_addr_sort_key)[0]

    dom: dict[str, set[str]] = {b: (set(blocks) if b != entry else {b}) for b in blocks}
    changed = True
    while changed:
        changed = False
        for addr in blocks:
            if addr == entry:
                continue
            preds = [p for p in cfg.blocks[addr].predecessors if p in blocks]
            if not preds:
                new = {addr}
            else:
                new = set(dom.get(preds[0], set()))
                for p in preds[1:]:
                    new &= dom.get(p, set())
                new.add(addr)
            if new != dom.get(addr, set()):
                dom[addr] = new
                changed = True
    return dom


def compute_postdominators(cfg: FunctionCFG) -> dict[str, set[str]]:
    """Post-dominators via meet-over-paths on the reversed CFG (stdlib only).

    A synthetic virtual exit makes the analysis well-founded even for CFGs
    whose natural exit is missing or that contain exit-less cycles.

    Returns ``{block: set(postdominators)}`` with the virtual exit scrubbed.
    """
    blocks = set(cfg.blocks)
    if not blocks:
        return {}

    virtual = "__postdom_virtual_exit__"
    succ: dict[str, set[str]] = {}
    for addr in blocks:
        real = {s for s in cfg.blocks[addr].successors if s in blocks}
        succ[addr] = real if real else {virtual}

    postdom: dict[str, set[str]] = {b: set(blocks) | {virtual} for b in blocks}
    postdom[virtual] = {virtual}
    # Sinks are their own postdominators (plus the virtual exit).
    for addr in blocks:
        if succ[addr] == {virtual}:
            postdom[addr] = {addr, virtual}

    changed = True
    while changed:
        changed = False
        for addr in blocks:
            new: set[str] | None = None
            for t in succ[addr]:
                new = set(postdom[t]) if new is None else (new & postdom[t])
            if new is None:
                new = set(postdom[virtual])
            new.add(addr)
            if new != postdom[addr]:
                postdom[addr] = new
                changed = True

    return {b: {p for p in postdom[b] if p != virtual} for b in blocks}


def find_back_edges(cfg: FunctionCFG) -> list[tuple[str, str]]:
    """Return ``(tail, header)`` edges where the tail jumps to a dominator."""
    if not cfg.blocks:
        return []
    dom = compute_dominators(cfg)
    edges: list[tuple[str, str]] = []
    for addr, block in cfg.blocks.items():
        for s in block.successors:
            if s in cfg.blocks and s in dom.get(addr, set()) and s != addr:
                edges.append((addr, s))
            elif s == addr:
                edges.append((addr, s))  # self-loop
    return edges


# ----------------------------------------------------------------------------- instruction helpers

def _is_conditional_branch(mnemonic: str) -> bool:
    """True for conditional branches across x86/ARM/AArch64/MIPS/SBF."""
    m = (mnemonic or "").lower().strip()
    if not m or m in _UNCONDITIONAL_JUMPS or m in _RETURN_MNEMONICS:
        return False
    if m in _X86_CONDITIONS or m in _X86_FLAGLESS or m in _MIPS_BRANCHES or m in _SBF_CONDITIONS:
        return True
    if m in {"b", "bal", "bl", "blr", "bx", "blx", "br", "bra", "call", "callq", "jal", "jalr", "jr"}:
        return False
    if m.startswith("j"):
        return True  # conservative: any other j* is a conditional jump
    if m.startswith("b") and len(m) <= 5:
        suffix = m[1:]
        return suffix in _ARM_CONDITION_SUFFIXES or (
            suffix.endswith(".w") and suffix[:-2] in _ARM_CONDITION_SUFFIXES)
    return False


def _block_branch_mnemonic(block: BasicBlock) -> str | None:
    if not block.instructions:
        return None
    m = str(block.instructions[-1].get("mnemonic", "")).lower().strip()
    if _is_conditional_branch(m) or m in _UNCONDITIONAL_JUMPS or m in _RETURN_MNEMONICS:
        return m
    return None


def _block_is_conditional(block: BasicBlock) -> bool:
    m = _block_branch_mnemonic(block)
    return m is not None and _is_conditional_branch(m)


def _block_is_unconditional(block: BasicBlock) -> bool:
    m = _block_branch_mnemonic(block)
    return m is not None and m in _UNCONDITIONAL_JUMPS


def _branch_arch_hint(block: BasicBlock, mnemonic: str) -> str:
    """Best-effort architecture hint for ambiguous mnemonics (``jne`` etc.).

    ``jne`` is an x86 branch *and* an SBF branch; the register naming of the
    compare / branch operands disambiguates.  SBF uses ``rN``/``wN`` scalar
    registers exclusively, x86 uses named GPRs.  Unknown mnemonics default to
    x86 because that is overwhelmingly the common case in the corpora this
    project ingests.
    """
    if mnemonic not in _SBF_CONDITIONS:
        return "x86"
    texts: list[str] = []
    for instr in block.instructions:
        texts.append(str(instr.get("operands", "")).lower())
    joined = " ".join(texts)
    if _SBF_REGISTER_RE.search(joined) and not _X86_REGISTER_RE.search(joined):
        return "sbf"
    return "x86"


def block_condition(block: BasicBlock) -> str:
    """Derive the true-side (taken-branch) condition for a conditional block."""
    mnemonic = _block_branch_mnemonic(block)
    if mnemonic is None:
        return "cond"
    arch = _branch_arch_hint(block, mnemonic)
    if mnemonic in _X86_FLAGLESS or mnemonic in _MIPS_BRANCHES or (
            arch == "sbf" and mnemonic in _SBF_CONDITIONS):
        return match_condition(mnemonic, str(block.instructions[-1].get("operands", "")))
    setter = _find_flag_setter(block.instructions[:-1])
    if setter is not None:
        expr = _render_condition(mnemonic, _split_operands(str(setter.get("operands", ""))))
        if expr:
            return expr
        # Ambiguous mnemonic whose x86 parse failed: try the SBF encoding.
        if arch == "x86" and mnemonic in _SBF_CONDITIONS:
            return match_condition(mnemonic, str(block.instructions[-1].get("operands", "")))
        return f"/* {mnemonic} */ cond"
    if arch == "sbf":
        return match_condition(mnemonic, str(block.instructions[-1].get("operands", "")))
    return match_condition(mnemonic, "")


def _is_empty_block(block: BasicBlock) -> bool:
    """Blocks with no statement-level content (branch-only or empty)."""
    return len(block.instructions) <= 1


def _addr_sort_key(addr: str) -> int:
    try:
        return int(str(addr).replace("addr(", "").replace(")", ""), 0)
    except Exception:
        return 0


# ----------------------------------------------------------------------------- structurer


class _Region:
    """A matched high-level region over a set of blocks."""

    def __init__(self, kind: str, head: str, body: list[str], else_body: list[str] | None = None) -> None:
        self.kind = kind          # "if" | "if_else" | "while" | "do_while" | "switch"
        self.head = head          # conditional/dispatcher block address
        self.body = body          # structured body block addresses (ordered)
        self.else_body = else_body
        self.inverted = False     # true when the body successor is the FALL-THROUGH
        self.join: str | None = None   # reconvergence block for if/loops
        # Switch-specific (kind == "switch"):
        self.case_succs: list[str] = []     # case-target block addresses (ordered)
        self.default_succ: str | None = None  # shared default successor (= join)


class _Structurer:
    """Region analysis + emission for one FunctionCFG."""

    def __init__(self, cfg: FunctionCFG, render_asm: bool) -> None:
        self.cfg = cfg
        self.render_asm = render_asm
        self.lines: list[PseudocodeLine] = []
        self.emitted: set[str] = set()
        self.postdom = compute_postdominators(cfg)
        self.dom = compute_dominators(cfg)
        self.back_edges = find_back_edges(cfg)
        self.gotos: set[str] = set()   # blocks that must keep an L<label>
        self._absorbed_redirects: dict[str, str] = {}  # landing pad -> real target

    # ------------------------------------------------------------------ analysis

    def loop_anchors(self) -> dict[str, tuple[str, set[str]]]:
        """Collect back edges, collapsing mutants (tail == header)."""
        anchors: dict[str, tuple[str, set[str]]] = {}
        for tail, header in self.back_edges:
            if tail == header:
                # Self-loop mutant: the conditional block is both tail and header.
                anchors[tail] = (tail, {tail})
            else:
                _, region = anchors.get(header, (header, set()))
                region.add(tail)
                anchors[header] = (header, region)
        return anchors

    def loop_regions(self) -> dict[str, set[str]]:
        """Natural loop region per back-edge header (backward slice to header)."""
        loops: dict[str, set[str]] = {}
        for tail, header in self.back_edges:
            region = {tail}
            if tail != header:
                region.add(header)
            work = [tail]
            while work:
                x = work.pop()
                for p in self.cfg.blocks[x].predecessors:
                    if p in self.cfg.blocks and p not in region:
                        if p == header or p in self.dom.get(header, set()) or header in self.dom.get(x, set()):
                            region.add(p)
                            if p != header:
                                work.append(p)
            loops.setdefault(header, set()).update(region)
        # Drop empty/unsound regions.
        return {h: r for h, r in loops.items()}

    def immediate_postdom(self, addr: str) -> str | None:
        pdoms = self.postdom.get(addr, set()) - {addr}
        real = [p for p in pdoms if p in self.cfg.blocks]
        if not real:
            return None
        return min(real, key=lambda p: len(self.postdom.get(p, set()) or self.cfg.blocks.keys()))

    def classify_loop(self, header: str, region: set[str]) -> _Region | None:
        """Match a whole loop region (merged across back edges) against shapes.

        The region passed in already merges all back edges of the dominant
        (innermost) loop rooted at ``header`` — a header never dominates its
        own tail for separate natural loops of one reducible function.
        """
        head_block = self.cfg.blocks[header]
        if not _block_is_conditional(head_block):
            return None
        succs = [s for s in head_block.successors if s in self.cfg.blocks]
        if len(succs) != 2:
            return None

        body_addrs = sorted((region - {header}), key=_addr_sort_key)
        back_tails = {t for t, h in self.back_edges if h == header}

        # do-while: the conditional block itself loops back (tail == header).
        if header in back_tails:
            exit_side = [s for s in succs if s not in region]
            in_loop = [s for s in succs if s == header or s in region]
            if exit_side and in_loop:
                region = _Region("do_while", header, body_addrs)
                keep = in_loop[0]
                region.inverted = (keep == succs[1])
                region.join = exit_side[0]
                return region
            return None

        # while: one header successor enters the body, the other exits.
        exit_cands = [s for s in succs if s not in region]
        keep_cands = [s for s in succs if s in region and s != header]
        if exit_cands and (keep_cands or not body_addrs):
            region = _Region("while", header, body_addrs)
            keep = keep_cands[0] if keep_cands else None
            region.inverted = (keep == succs[1])
            region.join = exit_cands[0]
            return region
        return None

    def classify_switch(self, addr: str, skip: set[str]) -> _Region | None:
        """Match a switch-table dispatcher: one block with >=3 successors.

        Shape: the dispatcher's immediate post-dominator is the *default*
        successor; every OTHER successor is a case target whose own forward
        path either falls through to the default (break) or flows to another
        case (fall-through). We never fabricate the selector variable — it
        comes from the dispatcher's preceding comparison or is an explicit
        `selector` placeholder.
        """
        block = self.cfg.blocks[addr]
        if addr in skip:
            return None
        succs = [s for s in block.successors if s in self.cfg.blocks]
        if len(succs) < 3:
            return None

        ipd = self.immediate_postdom(addr)
        if ipd is None or ipd not in succs:
            return None
        default = ipd
        cases = [s for s in succs if s != default]
        if len(cases) < 2:
            return None

        # Cases must not be dominated by any conditional that isn't the
        # dispatcher (keeps nested ifs from being merged into one switch).
        for c in cases:
            if c in skip:
                return None
        region = _Region("switch", addr, cases)
        region.default_succ = default
        region.case_succs = cases
        region.join = default
        return region

    def classify_if(self, addr: str, skip: set[str]) -> _Region | None:
        """Match if-then / if-then-else for a conditional block not consumed."""
        block = self.cfg.blocks[addr]
        if not _block_is_conditional(block):
            return None
        succs = [s for s in block.successors if s in self.cfg.blocks]
        if len(succs) != 2:
            return None
        taken, fall = succs[0], succs[1]
        if taken == fall:
            return None

        ipd = self.immediate_postdom(addr)
        if ipd is None:
            return None

        # if-then-else: both arms are empty unconditional jumps reconverging at ipd.
        if (ipd not in (taken, fall)
                and taken in self.cfg.blocks and fall in self.cfg.blocks
                and _block_is_unconditional(self.cfg.blocks[taken])
                and self.cfg.blocks[taken].successors[:1] == [ipd]
                and _block_is_unconditional(self.cfg.blocks[fall])
                and self.cfg.blocks[fall].successors[:1] == [ipd]):
            region = _Region("if_else", addr, [taken], [fall])
            region.join = ipd
            return region

        # if-then: one side flows straight into the reconvergence point.
        for arm, through in ((fall, taken), (taken, fall)):
            if through == ipd and arm != ipd and arm not in skip and arm in self.cfg.blocks:
                region = _Region("if", addr, [arm])
                region.inverted = (arm == fall)  # negate guard when body is fall-through
                region.join = ipd
                return region
        return None

    def analyze(self) -> tuple[list[Any], dict[str, _Region]]:
        """Produce a nesting tree of regions plus standalone block addresses.

        Returns ``(ordered_items, region_by_head)`` where ``ordered_items`` is
        a list of ``("block", addr)`` / ``("region", _Region)`` tuples in a
        faithful control-flow order (DFS from entry, fall-through first so
        if-then bodies stay adjacent to their guard).
        """
        if not self.cfg.blocks:
            return [], {}
        entry = self.cfg.entry if self.cfg.entry in self.cfg.blocks else sorted(
            self.cfg.blocks, key=_addr_sort_key)[0]

        self.postdom = compute_postdominators(self.cfg)
        self.dom = compute_dominators(self.cfg)

        # Merge back edges per header into one dominant loop region per header.
        per_header: dict[str, set[str]] = {}
        for tail, header in self.back_edges:
            per_header.setdefault(header, set()).add(tail)

        merged: dict[str, set[str]] = {}
        for header, tails in per_header.items():
            inner = [h2 for h2 in per_header if h2 != header and h2 in self.dom.get(header, set())]
            seeds: set[str] = set(tails)
            for h2 in inner:
                seeds |= per_header[h2] | {h2}
            merged[header] = seeds

        entry_addr = self.cfg.entry if self.cfg.entry in self.cfg.blocks else None

        loops: dict[str, set[str]] = {}
        for header, seeds in merged.items():
            body: set[str] = set(seeds) | {header}
            work = list(seeds)
            while work:
                x = work.pop()
                for p in self.cfg.blocks[x].predecessors:
                    if p in self.cfg.blocks and p not in body and p != entry_addr and (
                            p == header or p in self.dom.get(header, set())
                            or header in self.dom.get(p, set())):
                        body.add(p)
                        work.append(p)
            loops[header] = body

        # Constrain each loop body: blocks *outside* the loop whose successors
        # lead back in are reconvergence/duplicate arms, not loop members.
        for header, body in loops.items():
            trimmed = set(body)
            for addr in list(body):
                if addr == header:
                    continue
                preds_in = [p for p in self.cfg.blocks[addr].predecessors
                            if p in body]
                if not preds_in:
                    trimmed.discard(addr)
            loops[header] = trimmed

        regions: dict[str, _Region] = {}
        consumed: set[str] = set()

        # Innermost loops first.
        for header in sorted(loops, key=lambda h: len(loops[h])):
            body = loops[header]
            if header in consumed or header not in self.cfg.blocks:
                continue
            region = self.classify_loop(header, body)
            if region is not None:
                regions[header] = region
                consumed.update(set(region.body) - {header}
                                if region.kind != "do_while"
                                else set(region.body) | {header})

        # DFS order: taken branch first; fall-through comes right after the
        # guard, so if-then bodies keep the original layout contiguity.
        ordered: list[str] = []
        seen: set[str] = set()
        stack = [entry]
        while stack:
            addr = stack.pop()
            if addr in seen or addr not in self.cfg.blocks:
                continue
            seen.add(addr)
            ordered.append(addr)
            succs = [s for s in self.cfg.blocks[addr].successors if s in self.cfg.blocks]
            for s in reversed(succs):
                if s not in seen:
                    stack.append(s)

        items: list[Any] = []
        for addr in ordered:
            if addr in regions:
                items.append(("region", regions[addr]))
                continue
            if addr in consumed:
                continue  # loop body / captured arm: emits *inside* its region
            # Absorb reconvergence-landing pad blocks: they only jump onward.
            block = self.cfg.blocks[addr]
            if (_is_empty_block(block) and _block_is_unconditional(block)
                    and block.successors[:1] and block.successors[0] in self.cfg.blocks
                    and any(r.join == addr for r in regions.values()) is False
                    and len(block.predecessors) <= 1):
                self._absorbed_redirects[addr] = block.successors[0]
                continue
            sw = self.classify_switch(addr, consumed | set(regions))
            if sw is not None:
                regions[addr] = sw
                consumed.update(sw.body)
                items.append(("region", sw))
                continue
            if _block_is_conditional(block):
                region = self.classify_if(addr, consumed | set(regions))
                if region is not None:
                    arms = set(region.body) | set(region.else_body or [])
                    if not (arms & (consumed | set(regions))):
                        regions[addr] = region
                        consumed.update(arms)
                        items.append(("region", region))
                        continue
            items.append(("block", addr))
        return items, regions

    # ------------------------------------------------------------------ lifecycle accessors

    # ------------------------------------------------------------------ emission

    def label(self, addr: str) -> str:
        return f"L{str(addr).replace('0x', 'x')}"

    def _resolve_target(self, addr: str) -> str:
        """Redirect goto targets through absorbed landing pads."""
        seen: set[str] = set()
        while addr in self._absorbed_redirects and addr not in seen:
            seen.add(addr)
            addr = self._absorbed_redirects[addr]
        return addr

    def condition_for(self, addr: str) -> str:
        return block_condition(self.cfg.blocks[addr])

    def emit(self) -> list[PseudocodeLine]:
        items, regions = self.analyze()
        # Pass 1: dry-run to learn which blocks need an L<label>.
        saved = self.lines
        self.lines = []
        for kind, payload in items:
            self._emit_item(kind, payload, 1)
        self.lines = saved
        # Pass 2: real emission with labels known up front.
        for kind, payload in items:
            self._emit_item(kind, payload, 1)
        return self.lines

    def _emit_item(self, kind: str, payload: Any, depth: int) -> None:
        if kind == "block":
            self._emit_block(payload, depth)
        else:
            self._emit_region(payload, depth)

    def _collect_gotos(self, items: list[Any]) -> None:
        """Blocks that incoming control flow actually jumps to need a label."""
        structured_targets: set[str] = set()
        for kind, payload in items:
            if kind != "region":
                continue
            region: _Region = payload
            for body_block in region.body:
                for s in self.cfg.blocks[body_block].successors:
                    if s in self.cfg.blocks and s not in set(region.body) and s != region.head:
                        structured_targets.add(s)
        for addr in structured_targets:
            self.gotos.add(addr)

    def _emit_region(self, region: _Region, depth: int) -> None:
        if region.kind == "while":
            self._emit_while(region, depth)
        elif region.kind == "do_while":
            self._emit_do_while(region, depth)
        elif region.kind == "if_else":
            self._emit_if_else(region, depth)
        elif region.kind == "switch":
            self._emit_switch(region, depth)
        else:
            self._emit_if(region, depth)

    def _selector_expr(self, addr: str) -> str:
        """The variable being switched on — an honest placeholder when we
        cannot recover it from the dispatcher's preceding compare."""
        block = self.cfg.blocks.get(addr)
        if block is None:
            return "selector"
        setter = _find_flag_setter(block.instructions[:-1])
        if setter is not None:
            ops = _split_operands(str(setter.get("operands", "")))
            if ops:
                return ops[0]  # the compared-against register is the selector
        # Indirect jump through a table: use the jump operand if it exists.
        if block.instructions:
            last = block.instructions[-1]
            ops = _split_operands(str(last.get("operands", "")))
            if ops:
                return ops[0].lstrip("*")
        return "selector"

    def _emit_switch(self, region: _Region, depth: int) -> None:
        selector = self._selector_expr(region.head)
        self._emit_block(region.head, depth, suppress_branch=True)
        self.lines.append(PseudocodeLine(
            depth=depth, text=f"switch ({selector}) {{", kind="loop_header"))
        for idx, case in enumerate(region.case_succs):
            self.lines.append(PseudocodeLine(
                depth=depth, text=f"case {case}:", kind="branch"))
            self._emit_block(case, depth + 1,
                             suppress_branch=self.cfg.blocks[case].successors[:1] == [region.default_succ])
        if region.default_succ is not None:
            self.lines.append(PseudocodeLine(
                depth=depth, text=f"default: // {self.label(region.default_succ)}", kind="branch"))
        self.lines.append(PseudocodeLine(depth=depth, text="}", kind="branch"))

    def _emit_if(self, region: _Region, depth: int) -> None:
        cond = self.condition_for(region.head)
        if region.inverted:
            cond = negate_condition(cond)
        self._emit_block(region.head, depth, suppress_branch=True)
        self.lines.append(PseudocodeLine(depth=depth, text=f"if ({cond}) {{", kind="branch"))
        for addr in region.body:
            # The arm's trailing jump to the join block is implied by the brace.
            arm_block = self.cfg.blocks.get(addr)
            suppress = (arm_block is not None and region.join is not None
                        and arm_block.successors[:1] == [region.join]
                        and _block_is_unconditional(arm_block))
            self._emit_block(addr, depth + 1, suppress_branch=suppress)
        self.lines.append(PseudocodeLine(depth=depth, text="}", kind="branch"))

    def _emit_if_else(self, region: _Region, depth: int) -> None:
        cond = self.condition_for(region.head)
        self._emit_block(region.head, depth, suppress_branch=True)
        self.lines.append(PseudocodeLine(depth=depth, text=f"if ({cond}) {{", kind="branch"))
        for addr in region.body:
            self._emit_block(addr, depth + 1, suppress_branch=True)
        self.lines.append(PseudocodeLine(depth=depth, text="} else {", kind="branch"))
        for addr in region.else_body or []:
            self._emit_block(addr, depth + 1, suppress_branch=True)
        self.lines.append(PseudocodeLine(depth=depth, text="}", kind="branch"))

    def _keep_condition(self, region: _Region) -> str:
        """Condition that keeps control flow *inside* the structure."""
        cond = self.condition_for(region.head)
        return negate_condition(cond) if region.inverted else cond

    def _emit_while(self, region: _Region, depth: int) -> None:
        cond = self._keep_condition(region)
        self.lines.append(PseudocodeLine(depth=depth, text=f"while ({cond}) {{",
                                         kind="loop_header"))
        self._emit_block(region.head, depth + 1, suppress_branch=True)
        for addr in region.body:
            # A latch that jumps straight back to the header is implied.
            blk = self.cfg.blocks.get(addr)
            suppress = (blk is not None and _block_is_unconditional(blk)
                        and blk.successors[:1] == [region.head])
            self._emit_block(addr, depth + 1, suppress_branch=suppress)
        self.lines.append(PseudocodeLine(depth=depth, text="}", kind="branch"))

    def _emit_do_while(self, region: _Region, depth: int) -> None:
        self.lines.append(PseudocodeLine(depth=depth, text="do {", kind="loop_header"))
        for addr in region.body:
            blk = self.cfg.blocks.get(addr)
            suppress = (blk is not None and _block_is_unconditional(blk)
                        and blk.successors[:1] == [region.head])
            self._emit_block(addr, depth + 1, suppress_branch=suppress)
        cond = self._keep_condition(region)
        self._emit_block(region.head, depth + 1, suppress_branch=True)
        self.lines.append(PseudocodeLine(
            depth=depth, text=f"}} while ({cond});", kind="loop_header"))

    def _emit_block(self, addr: str, depth: int, *, suppress_branch: bool = False) -> None:
        block = self.cfg.blocks.get(addr)
        if block is None:
            self.lines.append(PseudocodeLine(
                depth=depth, label=addr,
                text=f"{self.label(addr)}: /* missing block */", kind="comment"))
            return
        self.emitted.add(addr)
        if addr in self.gotos:
            self.lines.append(PseudocodeLine(
                depth=depth, label=addr, text=f"{self.label(addr)}:", kind="comment"))

        for i, instr in enumerate(block.instructions):
            mnemonic = str(instr.get("mnemonic", "")).lower().strip()
            is_last = i == len(block.instructions) - 1
            is_ctrl = is_last and (
                _is_conditional_branch(mnemonic) or mnemonic in _UNCONDITIONAL_JUMPS
                or mnemonic in _RETURN_MNEMONICS)
            if not is_ctrl:
                operands = str(instr.get("operands", "")).strip()
                text = str(instr.get("text", "")).strip() or f"{mnemonic} {operands}".strip()
                if self.render_asm:
                    self.lines.append(PseudocodeLine(
                        depth=depth, label=str(instr.get("address")) or None,
                        text=f"// asm: {text}", kind="comment"))
                continue
            self._emit_terminator(addr, block, mnemonic, depth,
                                  suppress_branch=suppress_branch)

    def _emit_terminator(self, addr: str, block: BasicBlock, mnemonic: str,
                         depth: int, *, suppress_branch: bool) -> None:
        succs = [s for s in block.successors if s in self.cfg.blocks]
        if suppress_branch:
            return
        if mnemonic in _RETURN_MNEMONICS:
            self.lines.append(PseudocodeLine(depth=depth, label=addr,
                                             text="return;", kind="return"))
            return
        if mnemonic in _UNCONDITIONAL_JUMPS:
            if succs:
                target = self._resolve_target(succs[0])
                self.gotos.add(target)
                self.lines.append(PseudocodeLine(
                    depth=depth, text=f"goto {self.label(target)};", kind="branch"))
            else:
                self.lines.append(PseudocodeLine(
                    depth=depth, text="goto ?;", kind="branch"))
            return
        if _is_conditional_branch(mnemonic) or mnemonic.startswith("j") or mnemonic.startswith("b"):
            cond = self.condition_for(addr)
            if succs:
                t0 = self._resolve_target(succs[0])
                self.gotos.add(t0)
                self.lines.append(PseudocodeLine(
                    depth=depth,
                    text=f"if ({cond}) goto {self.label(t0)};", kind="branch"))
            else:
                self.lines.append(PseudocodeLine(
                    depth=depth, text=f"if ({cond}) goto ?;", kind="branch"))
            if len(succs) > 1:
                t1 = self._resolve_target(succs[1])
                self.gotos.add(t1)
                self.lines.append(PseudocodeLine(
                    depth=depth, text=f"goto {self.label(t1)};", kind="branch"))
            return
        if mnemonic:
            self.lines.append(PseudocodeLine(
                depth=depth, text=f"/* {mnemonic} */", kind="comment"))


# ----------------------------------------------------------------------------- flat fallback


def _flat_fallback(cfg: FunctionCFG, reason: str, render_asm: bool) -> list[PseudocodeLine]:
    """Flat, faithful dump of every block whenever structuring bails."""
    lines = [PseudocodeLine(depth=1, text=f"// unstructured: {reason}", kind="comment")]
    if not cfg.blocks:
        lines.append(PseudocodeLine(depth=1, text="// empty function", kind="comment"))
        return lines
    structurer = _Structurer.__new__(_Structurer)
    structurer.cfg = cfg
    structurer.render_asm = render_asm
    structurer.lines = []
    structurer.emitted = set()
    structurer.gotos = {s for b in cfg.blocks.values() for s in b.successors if s in cfg.blocks}
    for addr in sorted(cfg.blocks, key=_addr_sort_key):
        structurer._emit_block(addr, 1)
    lines.extend(structurer.lines)
    return lines


# ----------------------------------------------------------------------------- public API


class StructuredPseudocode:
    """Goto-free pseudocode generator over :class:`FunctionCFG` (Phoenix-style).

    Usage::

        gen = StructuredPseudocode()
        pfn = gen.generate(cfg)
        for line in pfn.pseudocode:
            print("    " * line.depth + line.text)
    """

    def __init__(self, *, render_asm: bool = True) -> None:
        self.render_asm = render_asm

    def _signature(self, cfg: FunctionCFG) -> str:
        name = cfg.name or self._default_name(cfg)
        return f"void {name}(void)"

    @staticmethod
    def _default_name(cfg: FunctionCFG) -> str:
        addr = (cfg.address or "0x0").replace("addr(", "").replace(")", "")
        return f"sub_{addr.replace('0x', '')}"

    def generate(self, cfg: FunctionCFG, *, render_asm: bool | None = None) -> PseudocodeFunction:
        """Structure ``cfg`` and return a :class:`PseudocodeFunction`."""
        render = self.render_asm if render_asm is None else render_asm
        fn_id = cfg.address or "0x0"
        name = cfg.name
        signature = self._signature(cfg)

        lines: list[PseudocodeLine] = [
            PseudocodeLine(text=f"// function {name or fn_id} @ {cfg.address or '?'}"),
            PseudocodeLine(text=signature, kind="statement"),
            PseudocodeLine(text="{"),
        ]

        if not cfg.blocks:
            lines.append(PseudocodeLine(depth=1, text="// unstructured: no basic blocks",
                                        kind="comment"))
            lines.append(PseudocodeLine(text="}"))
            return PseudocodeFunction(function_id=fn_id, address=cfg.address, name=name,
                                      signature=signature, pseudocode=lines)

        try:
            if cfg.entry not in cfg.blocks:
                body = _flat_fallback(cfg, f"entry {cfg.entry!r} missing", render)
            else:
                structurer = _Structurer(cfg, render)
                body = structurer.emit()
                if not body:
                    body = _flat_fallback(cfg, "no structure recovered", render)
        except Exception as exc:  # fail-soft by contract, never raise
            body = _flat_fallback(cfg, f"structuring error: {exc.__class__.__name__}", render)

        lines.extend(body)
        lines.append(PseudocodeLine(text="}"))

        return PseudocodeFunction(
            function_id=fn_id,
            address=cfg.address,
            name=name,
            signature=signature,
            pseudocode=lines,
        )


class StructuredPseudocodeGenerator:
    """Convenience wrapper building a :class:`FunctionCFG` behind the scenes.

    Resolves a function id / name / address through the :class:`AnalysisGraph`
    and structures it via ``CFGSpine``.
    """

    def __init__(self, graph: "AnalysisGraph", *, render_asm: bool = True) -> None:
        from src.models.analysis_graph import AnalysisGraph
        from src.analysis.cfg_spine import CFGSpine
        if not isinstance(graph, AnalysisGraph):
            raise TypeError("StructuredPseudocodeGenerator requires an AnalysisGraph")
        self.graph = graph
        self.spine = CFGSpine(graph)
        self._gen = StructuredPseudocode(render_asm=render_asm)

    def _find_function(self, function_id: str):
        node = self.graph.get_node(function_id)
        if node is not None and node.kind == "function":
            return node
        for n in self.graph.nodes:
            if n.kind == "function" and (
                    n.id == function_id or n.name == function_id or n.address == function_id):
                return n
        return None

    def generate(self, function_id: str, *, render_asm: bool | None = None) -> PseudocodeFunction:
        fn_node = self._find_function(function_id)
        if fn_node is None:
            return PseudocodeFunction(
                function_id=function_id,
                name=function_id,
                pseudocode=[PseudocodeLine(text=f"// function not found: {function_id}")],
            )
        try:
            cfg = self.spine.build_function_cfg(fn_node)
        except Exception as exc:  # fail-soft by contract
            return PseudocodeFunction(
                function_id=fn_node.id,
                address=fn_node.address,
                name=fn_node.name,
                pseudocode=[PseudocodeLine(
                    text=f"// unstructured: cfg build failed ({exc.__class__.__name__})",
                    kind="comment")],
            )
        pfn = self._gen.generate(cfg, render_asm=render_asm)
        pfn.function_id = fn_node.id
        return pfn
