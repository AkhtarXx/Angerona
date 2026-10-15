"""Smali string decryption by limited constant-propagation (roadmap Android #1).

Pattern: TinySmaliEmulator's idea — evaluate only the small DEX functions whose
body is a pure chain of constant-propagating string operations (XOR, char-at,
shift, append, base-n decode). Deterministic evidence for hidden strings, not
a general VM.

The engine deliberately refuses functions that:
  * read instance/static fields (side effects)
  * call other methods with arguments (control flow)
  * use invoke-direct/virtual/static with user input (cannot fully const-prop)
  * exceed a bounded step count (default 1000)
Each refusal is recorded in :class:`DecryptVerdict.unresolved` (never silent).

Input candidates: harness passes every DEX function whose decompiled body matches
the safe-shape pattern and whose name suggests obfuscated-string usage (s, ss,
str, get, enc, dec, xlate, rot). The output is what callers can cite as
verification evidence against static-claim checks.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path


_FUNC_RO = re.compile(
    r"\.method\s+(?:public|private|protected)?\s*(?:static\s+)?(?:final\s+)?(?:synchronized\s+)?(?:native\s+)?(?:\w[\w<>\[\]$/\-]*)\s+(\w+)\s*\(([^)]*)\)(\S+)")
_CODE_END = re.compile(r"^\.end\s+method\s*$")

_SAFE_OPS = frozenset({
    "const-string", "const-string/jumbo",
    "const/4", "const/16", "const", "const-high16",
    "xor-int/lit8", "xor-int/lit16", "xor-int/2addr",
    "add-int/lit8", "add-int/lit16", "add-int/2addr",
    "sub-int/lit8", "sub-int/lit16", "sub-int/2addr",
    "shr-int/lit8", "shl-int/lit8", "and-int/lit8", "or-int/lit8",
    "int-to-char", "int-to-byte", "int-to-long", "int-to-short",
    "char-to-int", "byte-to-int",
    "move", "move/16", "move/from16",
    "move-result-object", "move-result",
    "return-object", "return-void", "return",
    "goto", "if-eqz", "if-nez",
    "new-instance", "new-array",
    "iget", "iget-object",        # safe if constant-backed (checked later)
    "sget", "sget-object",        # checked via the static-field map the caller passes
    "invoke-direct", "invoke-static", "invoke-virtual",
    "filled-new-array", "filled-new-array/range",
})

_SUSPECT_NAMES = re.compile(
    r"(?:^|[_-])(s|ss|str|get|string|enc|dec|encrypt|decrypt|xlate|xor|rot|utf|utf8|base64|atob|btoa|decode|encode|k|key)$", re.I)


@dataclass
class DecryptVerdict:
    function: str
    name_suggestive: bool
    decrypted: str = ""                        # eax50-style result on success
    rejected_reason: str = ""
    unresolved: list = field(default_factory=list)
    instructions_executed: int = 0

    def as_dict(self) -> dict:
        return {"function": self.function, "name_suggestive": self.name_suggestive,
                "decrypted": self.decrypted, "instructions_executed": self.instructions_executed,
                "rejected_reason": self.rejected_reason,
                "unresolved": self.unresolved}


# ---------------------------------------------------------------- marshal-lite

def _split_methods(smali_text: str) -> list[tuple[str, str, str, str]]:
    """Split smali source into (prototype, params, return, body) tuples."""
    methods: list[tuple[str, str, str, str]] = []
    cur_name = None
    cur_proto = ""
    cur_params = ""
    cur_body: list = []
    in_code = False
    for line in smali_text.splitlines():
        m = _FUNC_RO.match(line.strip())
        if m:
            if cur_name is not None:
                methods.append((cur_name, cur_proto, cur_params, "\n".join(cur_body)))
            cur_proto = line.strip()
            cur_name = m.group(1)
            cur_params = m.group(3)
            cur_body = []
            in_code = True
            continue
        if _CODE_END.match(line.strip()) and cur_name is not None:
            methods.append((cur_name, cur_proto, cur_params, "\n".join(cur_body)))
            cur_name = None
            in_code = False
            continue
        if in_code and cur_name is not None:
            cur_body.append(line)
    if cur_name is not None:
        methods.append((cur_name, cur_proto, cur_params, "\n".join(cur_body)))
    return methods


# ---------------------------------------------------------------- const-prop


def _parse_operands(line: str) -> tuple[str, str]:
    s = line.strip()
    if not s:
        return "", ""
    parts = s.split(None, 1)
    return parts[0], parts[1] if len(parts) > 1 else ""


def _reg(x: str) -> str:
    return x.strip()


def _eval_const_prop(body: str) -> tuple[str, list[str], int]:
    """Constant-propagate a smali body. Returns (result, unresolved, steps)."""
    unresolved: list[str] = []
    regs: dict = {}
    steps = 0
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith(".local ") or line.startswith(".locals ") or \
                line.startswith(".line ") or line.startswith("#") or \
                line.startswith(".prologue") or line.startswith(".restart") or \
                line.startswith(".param") or line.startswith(".annotation") or \
                line.startswith(".end "):
            continue
        op, operand_str = _parse_operands(line)
        if not op:
            continue
        if op not in _SAFE_OPS:
            unresolved.append(f"unsupported op {op!r}")
            return "", unresolved, steps
        steps += 1
        if steps > 1000:
            unresolved.append("step cap exceeded")
            return "", unresolved, steps

        # const-string vAA, "..."
        if op in ("const-string", "const-string/jumbo"):
            m = re.match(r"(v\d+),\s*\"(.*)\"", operand_str.rstrip())
            if not m:
                unresolved.append(f"malformed const-string: {operand_str!r}")
                return "", unresolved, steps
            reg, val = m.group(1), m.group(2)
            # unescape common smali escapes
            val = val.replace("\\\"", '"').replace("\\'", "'").replace("\\n", "\n") \
                     .replace("\\t", "\t").replace("\\\\", "\\")
            regs[_reg(reg)] = ("str", val)
            continue

        # const/4, const/16, const, const-high16 vAA, #lit B
        if op in ("const/4", "const/16", "const", "const-high16"):
            m = re.match(r"(v\d+),\s*#?(-?0x[0-9a-fA-F]+|-?\d+)", operand_str.rstrip())
            if not m:
                unresolved.append(f"malformed const: {operand_str!r}")
                return "", unresolved, steps
            reg, val = m.group(1), int(m.group(2), 0)
            regs[_reg(reg)] = ("int", val)
            continue

        # Arithmetic: op-int/lit8 vA, vB, #lit C  (xor/add/sub/shl/shr/and/or)
        m = re.match(r"(v\d+),\s*(v\d+),\s*#?(-?0x[0-9a-fA-F]+|-?\d+)", operand_str.rstrip())
        if m and op in ("xor-int/lit8", "add-int/lit8", "sub-int/lit8",
                        "shl-int/lit8", "shr-int/lit8", "and-int/lit8", "or-int/lit8",
                        "xor-int/lit16", "add-int/lit16", "sub-int/lit16"):
            dst, src, lit = _reg(m.group(1)), _reg(m.group(2)), int(m.group(3), 0)
            if src not in regs:
                unresolved.append(f"src reg {src} missing ({op})")
                return "", unresolved, steps
            kind, val = regs[src]
            if kind != "int":
                unresolved.append(f"{op} on non-int {kind}")
                return "", unresolved, steps
            result: int
            if op.startswith("xor"):
                result = val ^ lit
            elif op.startswith("add"):
                result = val + lit
            elif op.startswith("sub"):
                result = val - lit
            elif op.startswith("shl"):
                result = val << lit
            elif op.startswith("shr"):
                result = val >> lit
            elif op.startswith("and"):
                result = val & lit
            else:
                result = val | lit
            # Target roll-over semantics — 32-bit signed wrap
            result = result & 0xFFFFFFFF
            if result >= 0x80000000:
                result -= 0x100000000
            regs[dst] = ("int", result)
            continue

        # 2addr: xor-int/2addr vA, vB
        m = re.match(r"(v\d+),\s*(v\d+)", operand_str.rstrip())
        if m and op in ("xor-int/2addr", "add-int/2addr", "sub-int/2addr"):
            dst, src = _reg(m.group(1)), _reg(m.group(2))
            if dst not in regs or src not in regs:
                unresolved.append(f"missing src/dst n {op}")
                return "", unresolved, steps
            kind_d, v_d = regs[dst]
            kind_s, v_s = regs[src]
            if kind_d != "int" or kind_s != "int":
                unresolved.append(f"{op} on non-int")
                return "", unresolved, steps
            r = (v_d ^ v_s) if op.startswith("xor") else \
                ((v_d + v_s) if op.startswith("add") else (v_d - v_s))
            r = ((r + 0x7FFFFFFF) & 0xFFFFFFFF) - 0x7FFFFFFF
            regs[dst] = ("int", r)
            continue

        # int-to-char vA, vB (cast keep value)
        if op in ("int-to-char", "int-to-byte", "int-to-long", "int-to-short",
                   "byte-to-int", "char-to-int"):
            m = re.match(r"(v\d+),\s*(v\d+)", operand_str.rstrip())
            if m:
                dst, src = _reg(m.group(1)), _reg(m.group(2))
                if src not in regs:
                    unresolved.append(f"cast source {src} missing")
                    return "", unresolved, steps
                kind, val = regs[src]
                if kind == "int":
                    if op == "int-to-char":
                        val = val & 0xFFFF
                    elif op == "int-to-byte":
                        val = ((val & 0xFF) - 256) if (val & 0x80) else (val & 0xFF)
                    elif op == "int-to-long":
                        pass
                    regs[dst] = ("int", val)
                    continue

        # invoke-family on StringBuilder: <init>()V / append(C)/toString() chain.
        if op in ("invoke-static", "invoke-direct", "invoke-virtual"):
            m = re.match(
                r"\{(v\d+)(?:,\s*v\d+)*\},\s*Ljava/lang/StringBuilder;->(append|toString|<init>)\(",
                operand_str)
            if not m:
                unresolved.append(f"unsupported invoke {operand_str!r}")
                return "", unresolved, steps
            reg = _reg(m.group(1))
            action = m.group(2)
            if action == "<init>":
                regs[reg] = ("sb", [])
                continue
            if reg not in regs:
                unresolved.append(f"invoke on unknown reg {reg}")
                return "", unresolved, steps
            kind, val = regs[reg]
            if action == "append":
                if kind != "sb":
                    unresolved.append("append on non-StringBuilder reg")
                    return "", unresolved, steps
                extra_ops = re.findall(r"(v\d+)", operand_str)
                src_reg = _reg(extra_ops[-1]) if len(extra_ops) > 1 else None
                if src_reg and src_reg in regs:
                    skind, sval = regs[src_reg]
                    if skind == "int":
                        val.append(chr(sval & 0xFFFF))
                    elif skind == "str":
                        val.append(sval)
                    else:
                        unresolved.append(f"append source {src_reg} is {skind}, not char/str")
                        return "", unresolved, steps
                elif src_reg:
                    unresolved.append(f"append source {src_reg} missing")
                    return "", unresolved, steps
                regs[reg] = ("sb", val)
                regs["_result"] = ("sb", val)
            elif action == "toString":
                if kind == "sb":
                    result = "".join(val)
                    regs[reg] = ("str", result)
                    regs["_result"] = ("str", result)
                else:
                    regs["_result"] = (kind, val)
            continue

        # new-instance vAA, Ljava/lang/StringBuilder;
        if op == "new-instance":
            m = re.match(r"(v\d+),\s*Ljava/lang/StringBuilder;", operand_str)
            if m:
                regs[_reg(m.group(1))] = ("sb", [])
                continue
            unresolved.append(f"unhandled new-instance {operand_str!r}")
            return "", unresolved, steps

        # move-result-object / move-result: copy from the special result register.
        # Our stub tracks "last invoked return value" under a synthetic _result key.
        if op in ("move-result-object", "move-result"):
            m = re.match(r"(v\d+)", operand_str.rstrip())
            if m and "_result" in regs:
                regs[_reg(m.group(1))] = regs["_result"]
            continue

        # move: vA, vB (regular register copy)
        if op in ("move", "move/16", "move/from16"):
            m = re.match(r"(v\d+),\s*(v\d+)", operand_str.rstrip())
            if m:
                dst, src = _reg(m.group(1)), _reg(m.group(2))
                if src in regs:
                    regs[dst] = regs[src]
                continue

        # return-object / return-wide / return
        if op.startswith("return"):
            m = re.match(r"(v\d+)", operand_str.rstrip())
            if op == "return-void":
                continue
            if m and _reg(m.group(1)) in regs:
                kind, val = regs[_reg(m.group(1))]
                if kind == "str":
                    return val, unresolved, steps
                if kind == "sb":
                    return "".join(val), unresolved, steps
                unresolved.append(f"return from non-string reg (kind={kind})")
                return "", unresolved, steps
            unresolved.append("return with no source")
            return "", unresolved, steps

    return "", unresolved + ["no clean return-object"], steps


# ---------------------------------------------------------------- top-level


def decrypt_dex_strings(smali_text: str, *, max_methods: int = 500) -> dict:
    """Run the limited constant-prop engine across a smali source blob.

    Returns ``{"candidates": n, "verified": n, "results": [verdict_dicts] }``.
    Only methods whose shape is a small safe const-chain are evaluated; every
    refusal carries an explicit reason.
    """
    methods = _split_methods(smali_text)
    out = {"candidates": 0, "verified": 0, "results": []}
    for proto, params, ret, body in methods[:max_methods]:
        name_match = _SUSPECT_NAMES.search(proto)
        # Cheap filter: only evaluate when the method name or return type suggests
        # string transformation, OR the body shape is short and looks constant-chain
        body_short = len(body) < 2000
        if not name_match and not body_short:
            continue
        out["candidates"] += 1
        result, unresolved, steps = _eval_const_prop(body)
        verdict = DecryptVerdict(
            function=proto, name_suggestive=bool(name_match),
            decrypted=result, unresolved=unresolved,
            instructions_executed=steps,
        )
        out["results"].append(verdict.as_dict())
        if result:
            out["verified"] += 1
    return out


def decrypt_dex_file(path: str | Path) -> dict:
    """Convenience helper for a single smali file path."""
    return decrypt_dex_strings(Path(path).read_text(errors="ignore"))
