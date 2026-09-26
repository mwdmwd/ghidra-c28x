#!/usr/bin/env python3
"""Finite, exact-valued MACF32 operand and accumulation regressions.

SPRUEO2B pp. 68-75 specify parallel source reads and alternating RPT pairs.
The operands below avoid rounding/underflow/overflow, which are separate from
these operand-order and repeat regressions.
"""
from __future__ import annotations

import struct

from pypcode import OpCode
from repeat_transfer_test import _execute, _reg, _translate


def bits(value: float) -> int:
    return struct.unpack("<I", struct.pack("<f", value))[0]


def check_parallel() -> None:
    values = (1.0, -2.0, 3.0, 5.0, -7.0, 11.0, 13.0, 17.0)
    for accumulator, product, opcode in ((3, 2, 0xE330), (7, 6, 0xE3C0)):
        for left in range(8):
            for right in range(8):
                # MOV32 R0H,*XAR4++ may replace either multiply source.
                words = (opcode | (right << 1) | (left >> 2),
                         ((left & 3) << 14) | (product << 11) | 0x84)
                ops = _translate(words)
                assert sum(op.opcode == OpCode.IMARK for op in ops) == 1
                initial = {f"R{i}H": bits(value) for i, value in enumerate(values)}
                initial.update(XAR4=0x2400, ARP=0, STF=0)
                present = {_reg(node) for op in ops for node in (*op.inputs, op.output)}
                initial = {name: value for name, value in initial.items() if name in present}
                moved = bits(-19.0)
                trace = _execute(ops, initial, {0x2400: moved & 0xFFFF,
                                               0x2401: moved >> 16})
                assert trace.register(f"R{accumulator}H") == bits(
                    values[accumulator] + values[product]), words
                assert trace.register(f"R{product}H") == bits(values[left] * values[right]), words
                assert trace.register("R0H") == moved, words
                assert trace.register("XAR4") == 0x2402, words
                assert len(trace.loads) == 1 and trace.loads[0][1:3] == (0x2400, 4), words
                assert not trace.stores, words


def check_repeat() -> None:
    # Use the per-cycle description (SPRUEO2B pp. 70-71). The example omits
    # the final R3+=R2/R7+=R6; TI acknowledged that documentation error:
    # https://e2e.ti.com/support/tools/code-composer-studio-group/ccs/f/code-composer-studio-forum/70835/
    initial = {"R3H": bits(2.0), "R2H": bits(3.0),
               "R7H": bits(7.0), "R6H": bits(5.0),
               "XAR6": 0x2400, "XAR7": 0x2800}
    for count in (2, 4, 6, 32):
        products = [float((i + 1) * (-2 if i & 1 else 3)) for i in range(count)]
        memory = {}
        for i in range(count):
            for base, value in ((0x2400, float(i + 1)),
                                (0x2800, float(-2 if i & 1 else 3))):
                value_bits = bits(value)
                memory[base + 2 * i] = value_bits & 0xFFFF
                memory[base + 2 * i + 1] = value_bits >> 16
        # A new immediate/register repeat and cascaded even repeats all begin
        # with R3/R2. Cascading must carry forward the pending last products.
        schedules = ((0xF600 | (count - 1), 0xE250, 0x1F86),
                     (0xF7A0, 0xE250, 0x1F86))
        if count > 2:
            schedules += ((0xF601, 0xE250, 0x1F86,
                           0xF600 | (count - 3), 0xE250, 0x1F86),)
        for words in schedules:
            ops = _translate(words)
            writes = {_reg(op.output) for op in ops if op.output is not None}
            assert {"R3H", "R2H", "R7H", "R6H"} <= writes, (words, writes)
            state = dict(initial)
            if words[0] == 0xF7A0:
                state["AR0"] = count - 1
            trace = _execute(ops, state, memory)
            expected = {"R3H": bits(5.0 + sum(products[:-2:2])),
                        "R7H": bits(12.0 + sum(products[1:-2:2])),
                        "R2H": bits(products[-2]), "R6H": bits(products[-1]),
                        "XAR6": 0x2400 + 2 * count, "XAR7": 0x2800 + 2 * count,
                        "RPTC": 0}
            assert {name: trace.register(name) for name in expected} == expected, words
            assert [(load[1], load[2]) for load in trace.loads] == [
                (base + 2 * i, 4) for i in range(count) for base in (0x2400, 0x2800)], words
            assert not trace.stores, words
    # Standalone remains one multiply with the R3/R2 pair only.
    ops = _translate((0xE250, 0x1F86))
    writes = {_reg(op.output) for op in ops if op.output is not None}
    assert not ({"R7H", "R6H", "RPTC"} & writes), writes
    trace = _execute(ops, {k: v for k, v in initial.items() if k not in ("R7H", "R6H")},
                     {0x2401: bits(2.0) >> 16, 0x2801: bits(3.0) >> 16})
    assert trace.register("R3H") == bits(5.0)
    assert trace.register("R2H") == bits(6.0)


if __name__ == "__main__":
    check_parallel()
    print("MACF32_PARALLEL_VECTORS=128")
    check_repeat()
    print("MACF32_REPEAT_TEST_PASS=all")
