#!/usr/bin/env python3
"""SPRU430F 16-bit ADD/SUB/ADDB/INC/DEC eventual-state regressions.

The oracle is ordinary unbounded signed/unsigned arithmetic, not upstream
SLEIGH. The executor is a finite P-Code test harness, not a silicon simulator.
RPT use is deliberately outside this single-instruction flag tranche.
"""
from __future__ import annotations

from dataclasses import dataclass
from itertools import product
from random import Random

from pypcode import OpCode
from repeat_transfer_test import _execute, _reg, _translate


@dataclass(frozen=True)
class Form:
    family: str
    word: int
    destination: str
    left: str
    right: str | int
    subtract: bool = False


FORMS = (
    Form("ADD AX,loc16", 0x94A0, "AL", "AL", "AR0"),
    Form("ADD AX,loc16", 0x95A9, "AH", "AH", "AL"),
    Form("ADD AX,loc16", 0x94A9, "AL", "AL", "AL"),
    Form("ADD AX,loc16", 0x9484, "AL", "AL", "memory"),
    Form("ADD loc16,AX", 0x72A0, "AR0", "AR0", "AL"),
    Form("ADD loc16,AX", 0x72A9, "AL", "AL", "AL"),
    Form("ADD loc16,AX", 0x7384, "memory", "memory", "AH"),
    Form("SUB AX,loc16", 0x9EA0, "AL", "AL", "AR0", True),
    Form("SUB AX,loc16", 0x9FA9, "AH", "AH", "AL", True),
    Form("SUB AX,loc16", 0x9EA9, "AL", "AL", "AL", True),
    Form("SUB AX,loc16", 0x9E84, "AL", "AL", "memory", True),
    Form("SUB loc16,AX", 0x74A0, "AR0", "AR0", "AL", True),
    Form("SUB loc16,AX", 0x74A9, "AL", "AL", "AL", True),
    Form("SUB loc16,AX", 0x7584, "memory", "memory", "AH", True),
    Form("SUBR loc16,AX", 0xEAA0, "AR0", "AL", "AR0", True),
    Form("SUBR loc16,AX", 0xEAA9, "AL", "AL", "AL", True),
    Form("SUBR loc16,AX", 0xEB84, "memory", "AH", "memory", True),
    Form("INC loc16", 0x0AA0, "AR0", "AR0", 1),
    Form("INC loc16", 0x0AA9, "AL", "AL", 1),
    Form("INC loc16", 0x0A84, "memory", "memory", 1),
    Form("DEC loc16", 0x0BA0, "AR0", "AR0", 1, True),
    Form("DEC loc16", 0x0BA9, "AL", "AL", 1, True),
    Form("DEC loc16", 0x0B84, "memory", "memory", 1, True),
) + tuple(
    Form("ADDB AX,#s8", (0x9C00 if reg == "AL" else 0x9D00) | byte,
         reg, reg, (byte if byte < 128 else byte - 256) & 0xFFFF)
    for reg in ("AL", "AH") for byte in range(256)
)
FAMILIES = tuple(dict.fromkeys(form.family for form in FORMS))
BOUNDARIES = (0, 1, 2, 0x7E, 0x7F, 0x80, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF)


def signed16(value: int) -> int:
    return value - 0x10000 if value & 0x8000 else value


def check_family(family: str) -> int:
    count = 0
    rng = Random(0xC28)
    pairs = tuple(product(BOUNDARIES, repeat=2)) + tuple(
        (rng.randrange(65536), rng.randrange(65536)) for _ in range(32))
    for form in (item for item in FORMS if item.family == family):
        ops = _translate((form.word,))
        outputs = {_reg(op.output) for op in ops if op.output is not None}
        assert {"C", "V", "N", "Z"} <= outputs, f"{form}: missing flag writes {outputs}"
        forbidden = {"OVC", "OVM", "SXM", "PM", "TC"} & outputs
        assert not forbidden, f"{form}: unrelated status writes {forbidden}"
        assert not any(op.opcode in (OpCode.BRANCH, OpCode.CBRANCH) for op in ops)
        memory = "memory" in (form.left, form.right)
        loads = sum(op.opcode == OpCode.LOAD for op in ops)
        stores = sum(op.opcode == OpCode.STORE for op in ops)
        assert loads == int(memory), (form, "loads", loads)
        assert stores == int(form.destination == "memory"), (form, "stores", stores)
        vectors = pairs if isinstance(form.right, str) else ((a, form.right) for a in BOUNDARIES)
        for a, b in vectors:
            if form.right == form.left:
                b = a  # Same-register source/destination aliases the incoming value.
            for old_c, old_v in product((0, 1), repeat=2):
                initial = {"C": old_c, "V": old_v, "N": 1, "Z": 1}
                words = {0x2400: 0x1234, 0x2401: 0xBEEF}
                for source, value in ((form.left, a), (form.right, b)):
                    if source == "memory":
                        initial["XAR4"] = 0x2400
                        words[0x2400] = value
                    elif isinstance(source, str):
                        initial[source] = value
                trace = _execute(ops, initial, words)
                total = a - b if form.subtract else a + b
                stotal = signed16(a) - signed16(b) if form.subtract else signed16(a) + signed16(b)
                result = total & 0xFFFF
                expected = {"C": int(a >= b) if form.subtract else int(total > 0xFFFF),
                            "V": old_v | int(not -32768 <= stotal <= 32767),
                            "N": result >> 15, "Z": int(result == 0)}
                got = {flag: trace.register(flag) for flag in expected}
                assert got == expected, (form, hex(a), hex(b), old_c, old_v, got, expected)
                actual = trace.word(0x2400) if form.destination == "memory" else trace.register(form.destination)
                assert actual == result, (form, a, b, actual, result)
                if memory:
                    assert trace.register("XAR4") == 0x2401, (form, "postincrement")
                    assert trace.word(0x2401) == 0xBEEF, (form, "neighbor clobbered")
                count += 1
    assert count, f"unknown family: {family}"
    return count


def main() -> int:
    total = 0
    for family in FAMILIES:
        count = check_family(family)
        total += count
        print(f"ALU16_FLAG_FAMILY={family}; VECTORS={count}")
    print(f"ALU16_FLAG_FORMS={len(FORMS)}")
    print(f"ALU16_FLAG_VECTORS={total}")
    print("ALU16_FLAG_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
