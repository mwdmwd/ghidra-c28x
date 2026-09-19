#!/usr/bin/env python3
"""Executable tests for operand-specific C28x bit numbering and partial writes."""
from __future__ import annotations

from pypcode import OpCode
from repeat_transfer_test import _execute, _reg, _translate


def check_tbit() -> int:
    """SPRU430F pp.436-437: immediate bits are direct; T bits are reversed."""
    patterns = (0, 0xFFFF, 0xA55A, 0x1234) + tuple(1 << n for n in range(16))
    count = 0
    for loc, name in ((0xA9, "AL"), (0xA8, "AH"), (0xAC, "T"), (0x84, "memory")):
        ops = _translate((0x5625, loc))
        outputs = {_reg(op.output) for op in ops if _reg(op.output)}
        assert outputs == ({"TC", "XAR4", "ARP"} if name == "memory" else {"TC"}), outputs
        assert sum(op.opcode == OpCode.LOAD for op in ops) == int(name == "memory")
        assert not any(op.opcode in (OpCode.STORE, OpCode.BRANCH, OpCode.CBRANCH) for op in ops)
        for value in patterns:
            for t in (hi | low for hi in (0, 0x10, 0xA5A0, 0xFFF0) for low in range(16)):
                for tc in (0, 1):
                    initial = {"T": t, "TC": tc}
                    if name == "memory":
                        initial["XAR4"] = 0x2400
                    elif name != "T":
                        initial[name] = value
                    source = t if name == "T" else value
                    trace = _execute(ops, initial, {0x2400: value, 0x2401: 0xBEEF})
                    expected = (source >> (15 - (t & 15))) & 1
                    assert trace.register("TC") == expected, (name, value, t, tc, expected)
                    assert trace.register("T") == t
                    if name == "memory":
                        assert trace.register("XAR4") == 0x2401
                        assert trace.word(0x2400) == value and trace.word(0x2401) == 0xBEEF
                    elif name != "T":
                        assert trace.register(name) == value
                    count += 1
    # All 65,536 T values, including every combination of ignored upper bits.
    ops = _translate((0x5625, 0xA9))
    for t in range(65536):
        got = _execute(ops, {"AL": 0x4212, "T": t, "TC": t & 1})
        assert got.register("TC") == ((0x4212 >> (15 - (t & 15))) & 1), t
        count += 1
    # Immediate-form negative control: no reversed numbering and no T input.
    for bit in range(16):
        ops = _translate((0x40A9 | (bit << 8),))
        assert all(_reg(node) != "T" for op in ops for node in op.inputs)
        for value in patterns:
            for tc in (0, 1):
                got = _execute(ops, {"AL": value, "TC": tc})
                assert got.register("TC") == ((value >> bit) & 1), (bit, value)
                count += 1
    return count


def main() -> int:
    print(f"TBIT_OPERAND_VECTORS={check_tbit()}")
    print("BIT_OPERAND_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
