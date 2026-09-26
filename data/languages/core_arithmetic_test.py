#!/usr/bin/env python3
"""Manual-based C28x arithmetic/status boundary regressions (SPRU430F).

Use unbounded Python arithmetic for expected values and the finite shared
P-Code executor for the module. This is not a hardware simulator.
"""
from __future__ import annotations

from itertools import product

from repeat_transfer_test import _execute, _reg, _translate


def execute(words, initial, memory=None):
    ops = _translate(words)
    present = {_reg(node) for op in ops for node in (*op.inputs, op.output)}
    trace = _execute(ops, {k: v for k, v in initial.items() if k in present}, memory)
    return trace, ops


def state(trace, initial, names):
    return {name: trace.register(name) if name in trace.registers else initial[name]
            for name in names}


def signed(value, width=32):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def check_mov_pm():
    # Table 2-3 and p.275: all eight PM encodings, including AMODE's 101 case.
    for source, opcode in (("AL", 0x5638), ("AH", 0x5639)):
        for amode, raw, p in product((0, 1), range(8), (0, 0x12345678, 0x81234567)):
            initial = {source: 0xA5F8 | raw, "PM": 0xFE, "AMODE": amode, "P": p}
            trace, ops = execute((opcode, 0x3FA0), initial)
            shift = (1, 0, -1, -2, -3, 4 if amode else -4, -5, -6)[raw]
            shifted = p << shift if shift >= 0 else signed(p) >> -shift
            expected = {"PM": shift & 0xFF, "AR0": shifted & 0xFFFF, source: initial[source]}
            assert state(trace, initial, expected) == expected, (source, amode, raw, hex(p))
            writes = {_reg(op.output) for op in ops if op.output is not None}
            assert writes - {None} == {"PM", "AR0"}, writes


def check_maxcul():
    # p.247: N/Z describe the preceding high-word MAXL. V is sticky and is
    # set here only when equal high words require replacing the low word.
    values = (0, 1, 2, 0x80000000, 0xFFFFFFFF)
    for n, z in ((0, 0), (0, 1), (1, 0)):
        for p, source, v in product(values, values, (0, 1)):
            initial = {"N": n, "Z": z, "V": v, "P": p, "XAR4": source}
            trace, ops = execute((0x5651, 0x00A4), initial)
            expected_p = source if n else (max(p, source) if z else p)
            expected = {"P": expected_p, "V": v | int(z and p < source), "N": n, "Z": z}
            assert state(trace, initial, expected) == expected, (initial, expected)
            writes = {_reg(op.output) for op in ops if op.output is not None}
            assert writes - {None} == {"P", "V"}, writes


if __name__ == "__main__":
    check_mov_pm()
    print("MOV_PM_VECTORS=96")
    check_maxcul()
    print("MAXCUL_VECTORS=150")
