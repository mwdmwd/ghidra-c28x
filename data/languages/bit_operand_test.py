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


def check_mov_dp() -> int:
    """SPRU430F p.258: replace bits 9:0 without repositioning bits 15:10."""
    # Batch translation avoids reparsing the full language 2,048 times. Neither
    # MOV form changes decode context. Execute each IMARK-delimited instruction
    # independently, with fresh runtime registers for every oracle vector.
    def instructions(words: list[int]) -> list[list]:
        result: list[list] = []
        for op in _translate(words):
            if op.opcode == OpCode.IMARK:
                result.append([])
            else:
                result[-1].append(op)
        assert len(result) == len(words)
        return result

    moves = instructions([0xF800 | imm for imm in range(1024)])
    zero_moves = instructions([0xB800 | imm for imm in range(1024)])
    count = 0
    for imm in range(1024):
        ops = moves[imm]
        assert {_reg(op.output) for op in ops if _reg(op.output)} == {"DP"}
        assert not any(op.opcode in (OpCode.LOAD, OpCode.STORE, OpCode.BRANCH,
                                    OpCode.CBRANCH) for op in ops)
        for high in range(64):
            for low in (0, 0x3FF):
                old = (high << 10) | low
                got = _execute(ops, {"DP": old})
                expected = (old & 0xFC00) | imm
                assert got.register("DP") == expected, (hex(old), imm, got.register("DP"), expected)
                count += 1
        # MOVZ is a distinct, unchanged whole-register zero-extension.
        got = _execute(zero_moves[imm], {"DP": 0xFFFF})
        assert got.register("DP") == imm, ("MOVZ", imm)
        count += 1
    for high in range(64):
        old = (high << 10) | 0x3FF
        expected = (old & 0xFC00) | 0x123
        address = (expected << 6) | 0x2A
        # MOV DP,#0x123; MOV AL,@0x2a: preserve upper-page address data flow.
        got = _execute(_translate((0xF923, 0x922A)), {"DP": old}, {address: 0x55AA})
        assert got.register("DP") == expected
        assert got.register("AL") == 0x55AA
        assert len(got.loads) == 1 and got.loads[0][1:3] == (address, 2)
        count += 1
    return count


def main() -> int:
    print(f"TBIT_OPERAND_VECTORS={check_tbit()}")
    print(f"MOV_DP_OPERAND_VECTORS={check_mov_dp()}")
    print("BIT_OPERAND_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
