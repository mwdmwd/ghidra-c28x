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


if __name__ == "__main__":
    check_parallel()
    print("MACF32_PARALLEL_VECTORS=128")
