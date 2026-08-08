#!/usr/bin/env python3
"""Focused semantic regressions for high-value C28x P-Code behavior.

These tests inspect P-Code rather than instruction text.  Most assertions protect
structure, data dependencies, update order, and effective-address side effects;
a small integer-only evaluator also executes boundary vectors for selected
register-form arithmetic constructors.  It is not a hardware emulator.
"""

from __future__ import annotations

import math
import struct
import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from pypcode import Context, OpCode


@dataclass(frozen=True)
class Case:
    name: str
    words: tuple[int, ...]
    check: Callable[[list], None]


def _translate(words: Iterable[int]) -> list:
    # Context changes made with SLEIGH globalset() are retained by a Context.
    # Give every case an isolated context so an AMODE/PAGE0 transition at a
    # reused test address cannot influence a later regression.
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _key(varnode) -> tuple[str, int, int]:
    return (varnode.space.name, varnode.offset, varnode.size)


def _reg(varnode) -> str | None:
    if varnode is None or varnode.space.name != "register":
        return None
    return varnode.getRegisterName()


def _is_const(varnode, value: int) -> bool:
    return varnode.space.name == "const" and varnode.offset == value


def _find_index(ops: list, predicate: Callable, description: str) -> int:
    for index, op in enumerate(ops):
        if predicate(op):
            return index
    raise AssertionError(f"missing {description}")


def _find(ops: list, predicate: Callable, description: str):
    return ops[_find_index(ops, predicate, description)]


def _no_internal_cfg(ops: list) -> None:
    bad = [op.opcode.name for op in ops if op.opcode in (OpCode.BRANCH, OpCode.CBRANCH)]
    assert not bad, f"unexpected intra-instruction control flow: {bad}"


def _unique_definitions(ops: list) -> dict[tuple[str, int, int], object]:
    return {
        _key(op.output): op
        for op in ops
        if op.output is not None and op.output.space.name == "unique"
    }


def _definition_for(definitions: dict[tuple[str, int, int], object], node):
    exact = definitions.get(_key(node))
    if exact is not None:
        return exact
    for definition in definitions.values():
        output = definition.output
        if output is not None and output.space.name == "unique" and _overlaps(output, node):
            return definition
    return None


def _depends_on_register(ops: list, varnode, register: str) -> bool:
    definitions = _unique_definitions(ops)
    seen: set[tuple[str, int, int]] = set()

    def visit(node) -> bool:
        if _reg(node) == register:
            return True
        key = _key(node)
        if key in seen or node.space.name != "unique":
            return False
        seen.add(key)
        definition = _definition_for(definitions, node)
        return definition is not None and any(visit(value) for value in definition.inputs)

    return visit(varnode)


def _overlaps(left, right) -> bool:
    if left.space.name != right.space.name:
        return False
    left_end = left.offset + left.size
    right_end = right.offset + right.size
    return left.offset < right_end and right.offset < left_end


def _depends_on_varnode(ops: list, varnode, source) -> bool:
    """Follow unique-space definitions, including explicit subpiece aliases."""
    definitions = _unique_definitions(ops)
    seen: set[tuple[str, int, int]] = set()

    def visit(node) -> bool:
        if _overlaps(node, source):
            return True
        key = _key(node)
        if key in seen or node.space.name != "unique":
            return False
        seen.add(key)
        definition = _definition_for(definitions, node)
        return definition is not None and any(visit(value) for value in definition.inputs)

    return visit(varnode)


def _resolves_to_constant(ops: list, varnode, value: int) -> bool:
    """Follow COPY-only temporaries to prove an exact architectural address."""
    definitions = _unique_definitions(ops)
    seen: set[tuple[str, int, int]] = set()

    def visit(node) -> bool:
        if _is_const(node, value):
            return True
        key = _key(node)
        if key in seen or node.space.name != "unique":
            return False
        seen.add(key)
        definition = definitions.get(key)
        return (
            definition is not None
            and definition.opcode == OpCode.COPY
            and len(definition.inputs) == 1
            and visit(definition.inputs[0])
        )

    return visit(varnode)


def _evaluates_to_constant(ops: list, varnode, value: int) -> bool:
    """Evaluate the small integer-expression subset used by address helpers."""
    definitions = _unique_definitions(ops)
    active: set[tuple[str, int, int]] = set()

    def evaluate(node) -> int | None:
        if node.space.name == "const":
            return node.offset
        key = _key(node)
        if key in active or node.space.name != "unique":
            return None
        active.add(key)
        definition = _definition_for(definitions, node)
        if definition is None:
            active.remove(key)
            return None
        values = [evaluate(item) for item in definition.inputs]
        if any(item is None for item in values):
            active.remove(key)
            return None
        args = [int(item) for item in values]
        mask = (1 << (node.size * 8)) - 1
        opcode = definition.opcode
        result: int | None
        if opcode in (OpCode.COPY, OpCode.INT_ZEXT):
            result = args[0]
        elif opcode == OpCode.INT_AND:
            result = args[0] & args[1]
        elif opcode == OpCode.INT_OR:
            result = args[0] | args[1]
        elif opcode == OpCode.INT_XOR:
            result = args[0] ^ args[1]
        elif opcode == OpCode.INT_ADD:
            result = args[0] + args[1]
        elif opcode == OpCode.INT_SUB:
            result = args[0] - args[1]
        elif opcode == OpCode.INT_MULT:
            result = args[0] * args[1]
        elif opcode == OpCode.INT_LEFT:
            result = args[0] << args[1]
        elif opcode == OpCode.INT_RIGHT:
            result = args[0] >> args[1]
        else:
            result = None
        active.remove(key)
        return None if result is None else result & mask

    resolved = evaluate(varnode)
    return resolved == value


def _execute_integer_pcode(ops: list, initial: dict[str, int]) -> dict[str, int]:
    """Execute the integer-only P-Code subset used by focused flag tests.

    This intentionally rejects memory and control-flow operations.  It is a
    small execution harness for register-form arithmetic constructors, not a
    general C28x emulator.
    """

    cells: dict[tuple[str, int], int] = {}
    registers: dict[str, object] = {}

    for op in ops:
        for node in (*op.inputs, op.output):
            name = _reg(node)
            if name is not None:
                registers.setdefault(name, node)

    def mask(size: int) -> int:
        return (1 << (size * 8)) - 1

    def signed(value: int, size: int) -> int:
        sign = 1 << (size * 8 - 1)
        value &= mask(size)
        return value - (1 << (size * 8)) if value & sign else value

    def read(node) -> int:
        if node.space.name == "const":
            return node.offset & mask(node.size)
        value = 0
        for index in range(node.size):
            value |= cells.get((node.space.name, node.offset + index), 0) << (index * 8)
        return value

    def write(node, value: int) -> None:
        value &= mask(node.size)
        for index in range(node.size):
            cells[(node.space.name, node.offset + index)] = (value >> (index * 8)) & 0xFF

    for name, value in initial.items():
        node = registers.get(name)
        if node is None:
            raise AssertionError(f"register {name} is absent from P-Code")
        write(node, value)

    for op in ops:
        if op.output is None:
            raise AssertionError(f"unsupported side-effect P-Code op {op.opcode.name}")
        args = [read(node) for node in op.inputs]
        opcode = op.opcode
        result: int
        if opcode in (OpCode.COPY, OpCode.INT_ZEXT):
            result = args[0]
        elif opcode == OpCode.INT_SEXT:
            result = signed(args[0], op.inputs[0].size)
        elif opcode == OpCode.INT_ADD:
            result = args[0] + args[1]
        elif opcode == OpCode.INT_SUB:
            result = args[0] - args[1]
        elif opcode == OpCode.INT_MULT:
            result = args[0] * args[1]
        elif opcode == OpCode.INT_AND:
            result = args[0] & args[1]
        elif opcode == OpCode.INT_OR:
            result = args[0] | args[1]
        elif opcode == OpCode.INT_XOR:
            result = args[0] ^ args[1]
        elif opcode == OpCode.INT_NEGATE:
            result = ~args[0]
        elif opcode == OpCode.INT_2COMP:
            result = -args[0]
        elif opcode == OpCode.INT_LEFT:
            result = args[0] << args[1]
        elif opcode == OpCode.INT_RIGHT:
            result = args[0] >> args[1]
        elif opcode == OpCode.INT_SRIGHT:
            result = signed(args[0], op.inputs[0].size) >> args[1]
        elif opcode == OpCode.INT_EQUAL:
            result = int(args[0] == args[1])
        elif opcode == OpCode.INT_NOTEQUAL:
            result = int(args[0] != args[1])
        elif opcode == OpCode.INT_LESS:
            result = int(args[0] < args[1])
        elif opcode == OpCode.INT_LESSEQUAL:
            result = int(args[0] <= args[1])
        elif opcode == OpCode.INT_SLESS:
            result = int(
                signed(args[0], op.inputs[0].size) < signed(args[1], op.inputs[1].size)
            )
        elif opcode == OpCode.INT_SLESSEQUAL:
            result = int(
                signed(args[0], op.inputs[0].size) <= signed(args[1], op.inputs[1].size)
            )
        elif opcode == OpCode.BOOL_AND:
            result = int(bool(args[0]) and bool(args[1]))
        elif opcode == OpCode.BOOL_OR:
            result = int(bool(args[0]) or bool(args[1]))
        elif opcode == OpCode.BOOL_XOR:
            result = int(bool(args[0]) ^ bool(args[1]))
        elif opcode == OpCode.BOOL_NEGATE:
            result = int(not bool(args[0]))
        elif opcode == OpCode.SUBPIECE:
            result = args[0] >> (args[1] * 8)
        elif opcode == OpCode.PIECE:
            result = (args[0] << (op.inputs[1].size * 8)) | args[1]
        elif opcode == OpCode.INT_CARRY:
            result = int(args[0] + args[1] > mask(op.inputs[0].size))
        elif opcode == OpCode.INT_SCARRY:
            width = op.inputs[0].size
            total = signed(args[0], width) + signed(args[1], width)
            minimum = -(1 << (width * 8 - 1))
            maximum = (1 << (width * 8 - 1)) - 1
            result = int(total < minimum or total > maximum)
        elif opcode == OpCode.INT_SBORROW:
            width = op.inputs[0].size
            total = signed(args[0], width) - signed(args[1], width)
            minimum = -(1 << (width * 8 - 1))
            maximum = (1 << (width * 8 - 1)) - 1
            result = int(total < minimum or total > maximum)
        else:
            raise AssertionError(f"unsupported integer P-Code op {opcode.name}")
        write(op.output, result)

    return {name: read(node) for name, node in registers.items()}


def _float32_from_bits(bits: int) -> float:
    return struct.unpack("<f", struct.pack("<I", bits & 0xFFFFFFFF))[0]


def _float32_to_bits(value: float) -> int:
    try:
        return struct.unpack("<I", struct.pack("<f", value))[0]
    except OverflowError:
        return 0xFF800000 if math.copysign(1.0, value) < 0 else 0x7F800000


def _execute_divf32_pcode(ops: list, initial: dict[str, int]) -> dict[str, int]:
    """Execute the finite P-Code subset used by the DIVF32 constructor.

    Unlike the integer-only harness, this supports forward intra-instruction
    branches and IEEE single-precision FLOAT_DIV.  It remains a local
    regression harness, not a cycle-accurate C28x or TMU emulator.
    """

    cells: dict[tuple[str, int], int] = {}
    registers: dict[str, object] = {}

    for op in ops:
        for node in (*op.inputs, op.output):
            name = _reg(node)
            if name is not None:
                registers.setdefault(name, node)

    def mask(size: int) -> int:
        return (1 << (size * 8)) - 1

    def signed(value: int, size: int) -> int:
        sign = 1 << (size * 8 - 1)
        value &= mask(size)
        return value - (1 << (size * 8)) if value & sign else value

    def read(node) -> int:
        if node.space.name == "const":
            return node.offset & mask(node.size)
        value = 0
        for index in range(node.size):
            value |= cells.get((node.space.name, node.offset + index), 0) << (index * 8)
        return value

    def write(node, value: int) -> None:
        value &= mask(node.size)
        for index in range(node.size):
            cells[(node.space.name, node.offset + index)] = (value >> (index * 8)) & 0xFF

    for name, value in initial.items():
        node = registers.get(name)
        if node is None:
            raise AssertionError(f"register {name} is absent from DIVF32 P-Code")
        write(node, value)

    pc = 0
    steps = 0
    while pc < len(ops):
        steps += 1
        if steps > 1000:
            raise AssertionError("DIVF32 P-Code exceeded execution step limit")
        op = ops[pc]
        opcode = op.opcode
        if opcode == OpCode.BRANCH:
            pc += signed(read(op.inputs[0]), op.inputs[0].size)
            continue
        if opcode == OpCode.CBRANCH:
            if read(op.inputs[1]):
                pc += signed(read(op.inputs[0]), op.inputs[0].size)
            else:
                pc += 1
            continue
        if op.output is None:
            raise AssertionError(f"unsupported side-effect DIVF32 P-Code op {opcode.name}")

        args = [read(node) for node in op.inputs]
        result: int
        if opcode in (OpCode.COPY, OpCode.INT_ZEXT):
            result = args[0]
        elif opcode == OpCode.INT_SEXT:
            result = signed(args[0], op.inputs[0].size)
        elif opcode == OpCode.INT_ADD:
            result = args[0] + args[1]
        elif opcode == OpCode.INT_SUB:
            result = args[0] - args[1]
        elif opcode == OpCode.INT_MULT:
            result = args[0] * args[1]
        elif opcode == OpCode.INT_AND:
            result = args[0] & args[1]
        elif opcode == OpCode.INT_OR:
            result = args[0] | args[1]
        elif opcode == OpCode.INT_XOR:
            result = args[0] ^ args[1]
        elif opcode == OpCode.INT_NEGATE:
            result = ~args[0]
        elif opcode == OpCode.INT_2COMP:
            result = -args[0]
        elif opcode == OpCode.INT_LEFT:
            result = args[0] << args[1]
        elif opcode == OpCode.INT_RIGHT:
            result = args[0] >> args[1]
        elif opcode == OpCode.INT_SRIGHT:
            result = signed(args[0], op.inputs[0].size) >> args[1]
        elif opcode == OpCode.INT_EQUAL:
            result = int(args[0] == args[1])
        elif opcode == OpCode.INT_NOTEQUAL:
            result = int(args[0] != args[1])
        elif opcode == OpCode.INT_LESS:
            result = int(args[0] < args[1])
        elif opcode == OpCode.INT_LESSEQUAL:
            result = int(args[0] <= args[1])
        elif opcode == OpCode.INT_SLESS:
            result = int(
                signed(args[0], op.inputs[0].size) < signed(args[1], op.inputs[1].size)
            )
        elif opcode == OpCode.INT_SLESSEQUAL:
            result = int(
                signed(args[0], op.inputs[0].size) <= signed(args[1], op.inputs[1].size)
            )
        elif opcode == OpCode.BOOL_AND:
            result = int(bool(args[0]) and bool(args[1]))
        elif opcode == OpCode.BOOL_OR:
            result = int(bool(args[0]) or bool(args[1]))
        elif opcode == OpCode.BOOL_XOR:
            result = int(bool(args[0]) ^ bool(args[1]))
        elif opcode == OpCode.BOOL_NEGATE:
            result = int(not bool(args[0]))
        elif opcode == OpCode.SUBPIECE:
            result = args[0] >> (args[1] * 8)
        elif opcode == OpCode.PIECE:
            result = (args[0] << (op.inputs[1].size * 8)) | args[1]
        elif opcode == OpCode.FLOAT_DIV:
            numerator = _float32_from_bits(args[0])
            denominator = _float32_from_bits(args[1])
            if denominator == 0.0:
                if numerator == 0.0:
                    quotient = math.nan
                else:
                    quotient = math.copysign(math.inf, numerator * denominator)
            else:
                quotient = numerator / denominator
            result = _float32_to_bits(quotient)
        else:
            raise AssertionError(f"unsupported DIVF32 P-Code op {opcode.name}")
        write(op.output, result)
        pc += 1

    return {name: read(node) for name, node in registers.items()}


def _f32(value: float) -> int:
    return _float32_to_bits(value)


def check_divf32(ops: list) -> None:
    divides = [op for op in ops if op.opcode == OpCode.FLOAT_DIV]
    assert len(divides) == 1, f"DIVF32 must emit one FLOAT_DIV, got {len(divides)}"
    divide = divides[0]
    assert any(
        op.output is not None
        and _overlaps(op.output, divide.inputs[0])
        and any(_reg(value) == "R3H" for value in op.inputs)
        for op in ops
    ), "DIVF32 conditioned numerator must snapshot R3H"
    assert any(
        op.output is not None
        and _overlaps(op.output, divide.inputs[1])
        and any(_reg(value) == "R1H" for value in op.inputs)
        for op in ops
    ), "DIVF32 conditioned denominator must snapshot R1H"
    assert any(_reg(op.output) == "R0H" for op in ops), "DIVF32 must write R0H"

    stf_flags = {"STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"}
    flag_reads = {
        _reg(value)
        for op in ops
        for value in op.inputs
        if _reg(value) in stf_flags
    }
    assert not flag_reads, f"DIVF32 must not depend on STF flags or rounding state: {flag_reads}"
    flag_writes = [op for op in ops if _reg(op.output) in stf_flags]
    written = {_reg(op.output) for op in flag_writes}
    assert written == {"STF_LU", "STF_LV"}, f"unexpected DIVF32 STF writes: {written}"
    for op in flag_writes:
        assert (
            op.opcode == OpCode.COPY
            and len(op.inputs) == 1
            and _is_const(op.inputs[0], 1)
        ), f"DIVF32 flags must be sticky-set only: {op}"

    def run(
        numerator: int,
        denominator: int,
        expected_result: int,
        expected_lu: int,
        expected_lv: int,
        description: str,
        *,
        initial_lu: int = 0,
        initial_lv: int = 0,
    ) -> None:
        actual = _execute_divf32_pcode(
            ops,
            {
                "R0H": 0xDEADBEEF,
                "R3H": numerator,
                "R1H": denominator,
                "STF_LU": initial_lu,
                "STF_LV": initial_lv,
            },
        )
        expected = {
            "R0H": expected_result,
            "STF_LU": expected_lu,
            "STF_LV": expected_lv,
        }
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"

    run(_f32(6.0), _f32(2.0), _f32(3.0), 0, 0, "ordinary division")
    run(
        _f32(-6.0),
        _f32(2.0),
        _f32(-3.0),
        1,
        1,
        "ordinary division preserves flags",
        initial_lu=1,
        initial_lv=1,
    )
    run(
        0x00000000,
        0x00000000,
        0x00000000,
        1,
        1,
        "zero divided by zero",
        initial_lu=1,
    )
    run(
        0x00000000,
        0x7F800000,
        0x00000000,
        1,
        1,
        "zero divided by infinity",
        initial_lv=1,
    )
    run(0x7F800000, _f32(-2.0), 0xFF800000, 0, 1, "infinity divided by normal")
    run(
        0xFF800000,
        0x00000000,
        0xFF800000,
        0,
        1,
        "negative infinity divided by zero",
    )
    run(0x7F800000, 0xFF800000, 0xFF800000, 1, 0, "infinity divided by infinity")
    run(_f32(-4.0), 0x00000000, 0xFF800000, 0, 1, "normal divided by zero")
    run(_f32(-4.0), 0xFF800000, 0x00000000, 1, 0, "normal divided by infinity")
    run(0x80000000, _f32(-2.0), 0x00000000, 0, 0, "negative zero is positive zero")
    run(0x00000001, _f32(2.0), 0x00000000, 0, 0, "denormal numerator is positive zero")
    run(
        _f32(-4.0),
        0x80000000,
        0xFF800000,
        0,
        1,
        "negative zero denominator is positive zero",
    )
    run(0x7FC00001, _f32(2.0), 0x7F800000, 0, 1, "positive NaN is positive infinity")
    run(0xFFC00001, _f32(2.0), 0xFF800000, 0, 1, "negative NaN is negative infinity")
    run(_f32(2.0), 0xFFC00001, 0x00000000, 1, 0, "NaN denominator is signed infinity")
    run(0x00800000, _f32(2.0), 0x00000000, 1, 0, "subnormal result flushes to zero")
    run(0x7F7FFFFF, 0x00800000, 0x7F800000, 0, 1, "overflow returns infinity")


def check_divf32_aliased_numerator(ops: list) -> None:
    divides = [op for op in ops if op.opcode == OpCode.FLOAT_DIV]
    assert len(divides) == 1, f"aliased DIVF32 must emit one FLOAT_DIV, got {len(divides)}"
    divide = divides[0]
    assert any(
        op.output is not None
        and _overlaps(op.output, divide.inputs[0])
        and any(_reg(value) == "R1H" for value in op.inputs)
        for op in ops
    ), "aliased DIVF32 numerator must snapshot the incoming R1H value"
    assert any(
        op.output is not None
        and _overlaps(op.output, divide.inputs[1])
        and any(_reg(value) == "R0H" for value in op.inputs)
        for op in ops
    ), "aliased DIVF32 denominator must snapshot the incoming R0H value"
    actual = _execute_divf32_pcode(
        ops,
        {
            "R1H": _f32(6.0),
            "R0H": _f32(2.0),
            "STF_LU": 0,
            "STF_LV": 0,
        },
    )
    assert actual["R1H"] == _f32(3.0), (
        f"aliased DIVF32 lost its source before writeback: 0x{actual['R1H']:08x}"
    )
    assert actual["STF_LU"] == 0 and actual["STF_LV"] == 0, (
        "ordinary aliased DIVF32 unexpectedly changed LUF/LVF"
    )


def _assert_execution(
    ops: list, initial: dict[str, int], expected: dict[str, int], description: str
) -> None:
    actual = _execute_integer_pcode(ops, initial)
    mismatches = {
        name: (actual.get(name), value)
        for name, value in expected.items()
        if actual.get(name) != value
    }
    assert not mismatches, f"{description}: actual/expected {mismatches}"


def _last_load(ops: list, width: int):
    loads = [op for op in ops if op.opcode == OpCode.LOAD and op.output.size == width]
    assert loads, f"missing {width}-byte memory load"
    return loads[-1]


def check_banz(ops: list) -> None:
    sub = _find_index(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB and _reg(op.output) == "AR2",
        "AR2 post-decrement",
    )
    branch = _find_index(ops, lambda op: op.opcode == OpCode.CBRANCH, "BANZ conditional branch")
    assert sub < branch, "BANZ must perform its mandatory decrement before the branch"


def check_mov32_uncf(ops: list) -> None:
    _no_internal_cfg(ops)
    load = _find_index(ops, lambda op: op.opcode == OpCode.LOAD, "MOV32 memory load")
    write = _find_index(ops, lambda op: _reg(op.output) == "R0H", "MOV32 R0H write")
    flag_writes = [
        i for i, op in enumerate(ops) if _reg(op.output) in {"STF_NI", "STF_ZI", "STF_ZF", "STF_NF"}
    ]
    assert len(flag_writes) == 4, "MOV32 UNCF must update NI, ZI, ZF, and NF"
    assert load < write < min(flag_writes)


def check_parallel_mpy_add(ops: list) -> None:
    mul = _find_index(ops, lambda op: op.opcode == OpCode.FLOAT_MULT, "parallel multiply")
    add = _find_index(ops, lambda op: op.opcode == OpCode.FLOAT_ADD, "parallel add")
    r0_write = _find_index(ops, lambda op: _reg(op.output) == "R0H", "R0H destination write")
    r3_write = _find_index(ops, lambda op: _reg(op.output) == "R3H", "R3H destination write")
    assert max(mul, add) < min(
        r0_write, r3_write
    ), "parallel results must be computed from old sources before either destination is written"


def check_parallel_store_alias(ops: list) -> None:
    snapshot = _find_index(
        ops,
        lambda op: op.opcode == OpCode.COPY
        and op.inputs
        and _reg(op.inputs[0]) == "R0H"
        and op.output.space.name == "unique",
        "old R0H snapshot",
    )
    write = _find_index(ops, lambda op: _reg(op.output) == "R0H", "ADDF32 R0H write")
    store = _find_index(ops, lambda op: op.opcode == OpCode.STORE, "parallel MOV32 store")
    assert (
        snapshot < write < store
    ), "parallel store must retain the pre-ADDF32 value when source aliases destination"


def check_movxi(ops: list) -> None:
    _no_internal_cfg(ops)
    mask = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_AND
        and op.inputs
        and _reg(op.inputs[0]) == "R0H"
        and any(_is_const(v, 0xFFFF0000) for v in op.inputs[1:]),
        "MOVXI upper-half preservation mask",
    )
    write = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_OR and _reg(op.output) == "R0H",
        "MOVXI merged R0H write",
    )
    assert _key(mask.output) in {
        _key(v) for v in write.inputs
    }, "MOVXI merged value must include the preserved upper half"


def _check_neighbor_copy(ops: list, delta: int, width: int, load_description: str) -> None:
    loads = [op for op in ops if op.opcode == OpCode.LOAD and op.output.size == width]
    stores = [op for op in ops if op.opcode == OpCode.STORE and op.inputs[2].size == width]
    assert loads, f"missing {load_description}"
    assert stores, f"missing {width}-byte neighboring store"

    for add in (op for op in ops if op.opcode == OpCode.INT_ADD and len(op.inputs) == 2):
        const_inputs = [v for v in add.inputs if _is_const(v, delta)]
        if not const_inputs:
            continue
        base = add.inputs[0] if not _is_const(add.inputs[0], delta) else add.inputs[1]
        if base.space.name == "const":
            continue
        for store in stores:
            if _key(store.inputs[1]) != _key(add.output):
                continue
            matching_loads = [load for load in loads if _key(load.inputs[1]) == _key(base)]
            assert (
                matching_loads
            ), "neighboring copy must derive its store address from the architectural load address"
            load_values = {_key(load.output) for load in matching_loads}
            store_value = _key(store.inputs[2])
            if store_value in load_values:
                return
            # MOVAD/XMACD route the loaded value through T before storing it.
            routed = any(
                _reg(op.output) == "T"
                and _key(op.output) == store_value
                and op.inputs
                and _key(op.inputs[0]) in load_values
                for op in ops
            )
            assert (
                routed
            ), "neighboring store must copy the value loaded from the architectural operand"
            return
    raise AssertionError(f"missing architectural address + {delta} neighboring store")


def check_dmov(ops: list) -> None:
    _check_neighbor_copy(ops, delta=1, width=2, load_description="DMOV 16-bit load")


def check_movad(ops: list) -> None:
    _check_neighbor_copy(ops, delta=1, width=2, load_description="MOVAD 16-bit load")


def check_movdl(ops: list) -> None:
    _check_neighbor_copy(ops, delta=2, width=4, load_description="MOVDL 32-bit load")


def check_movd32(ops: list) -> None:
    _check_neighbor_copy(ops, delta=2, width=4, load_description="MOVD32 32-bit load")


def check_xmacd(ops: list) -> None:
    _check_neighbor_copy(ops, delta=1, width=2, load_description="XMACD data load")


def _check_xar_postincrement(ops: list, register: str, delta: int, width: int) -> None:
    snapshot = _find(
        ops,
        lambda op: op.opcode == OpCode.COPY
        and op.inputs
        and _reg(op.inputs[0]) == register
        and op.output.space.name == "unique",
        f"old {register} effective-address snapshot",
    )
    update = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and _reg(op.output) == register
        and any(_is_const(value, delta) for value in op.inputs),
        f"{register} + {delta} postincrement",
    )
    load = _last_load(ops, width)
    assert _key(load.inputs[1]) == _key(snapshot.output)
    assert ops.index(snapshot) < ops.index(update) < ops.index(load)


def check_xar_postincrement16(ops: list) -> None:
    _check_xar_postincrement(ops, register="XAR4", delta=1, width=2)


def check_xar_postincrement32(ops: list) -> None:
    _check_xar_postincrement(ops, register="XAR4", delta=2, width=4)


def check_xar_postincrement8(ops: list) -> None:
    _check_xar_postincrement(ops, register="XAR4", delta=1, width=2)


def _check_xar_predecrement(ops: list, register: str, delta: int, width: int) -> None:
    _no_internal_cfg(ops)
    update = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB
        and _reg(op.output) == register
        and any(_is_const(value, delta) for value in op.inputs),
        f"{register} - {delta} predecrement",
    )
    load = _last_load(ops, width)
    assert _depends_on_register(ops, load.inputs[1], register)
    assert ops.index(update) < ops.index(load), "predecrement must precede the memory access"


def check_xar_predecrement16(ops: list) -> None:
    _check_xar_predecrement(ops, register="XAR4", delta=1, width=2)


def check_xar_predecrement32(ops: list) -> None:
    _check_xar_predecrement(ops, register="XAR4", delta=2, width=4)


def _check_sp_update(ops: list, opcode: OpCode, delta: int, width: int) -> None:
    _no_internal_cfg(ops)
    update = _find(
        ops,
        lambda op: op.opcode == opcode
        and _reg(op.output) == "SP"
        and any(_is_const(value, delta) for value in op.inputs),
        f"SP {opcode.name} {delta}",
    )
    load = _last_load(ops, width)
    address = load.inputs[1]
    assert _depends_on_register(ops, address, "SP")
    if opcode == OpCode.INT_ADD:
        snapshot = _find(
            ops,
            lambda op: op.opcode == OpCode.INT_ZEXT
            and op.inputs
            and _reg(op.inputs[0]) == "SP"
            and _depends_on_varnode(ops, address, op.output),
            "old SP postincrement address",
        )
        assert ops.index(snapshot) < ops.index(update) < ops.index(load)
    else:
        assert ops.index(update) < ops.index(load)


def check_sp_postincrement16(ops: list) -> None:
    _check_sp_update(ops, OpCode.INT_ADD, delta=1, width=2)


def check_sp_postincrement32(ops: list) -> None:
    _check_sp_update(ops, OpCode.INT_ADD, delta=2, width=4)


def check_sp_predecrement16(ops: list) -> None:
    _check_sp_update(ops, OpCode.INT_SUB, delta=1, width=2)


def check_sp_predecrement32(ops: list) -> None:
    _check_sp_update(ops, OpCode.INT_SUB, delta=2, width=4)


def _arp_selected_pointer(ops: list, width: int):
    register_load = _find(
        ops,
        lambda op: op.opcode == OpCode.LOAD
        and op.output.size == 4
        and _depends_on_register(ops, op.inputs[1], "ARP"),
        "old ARP-selected XAR load",
    )
    ram_load = _last_load(ops, width)
    assert _key(ram_load.inputs[1]) == _key(register_load.output)
    return register_load, ram_load


def _check_c2x_postupdate(
    ops: list,
    opcode: OpCode,
    width: int,
    *,
    delta: int | None = None,
    use_ar0: bool = False,
    new_arp: int | None = None,
) -> None:
    _no_internal_cfg(ops)
    register_load, ram_load = _arp_selected_pointer(ops, width)
    register_store = _find(
        ops,
        lambda op: op.opcode == OpCode.STORE
        and _key(op.inputs[1]) == _key(register_load.inputs[1]),
        "ARP-selected XAR writeback",
    )
    update = _find(
        ops,
        lambda op: op.opcode == opcode
        and _key(op.output) == _key(register_store.inputs[2])
        and _key(register_load.output) in {_key(value) for value in op.inputs}
        and (delta is None or any(_is_const(value, delta) for value in op.inputs))
        and (not use_ar0 or any(_depends_on_register(ops, value, "AR0") for value in op.inputs)),
        "ARP-selected pointer update",
    )
    assert ops.index(register_load) < ops.index(update) < ops.index(register_store)
    if new_arp is None:
        assert ops.index(register_store) < ops.index(ram_load)
        return
    arp_write = _find(
        ops,
        lambda op: _reg(op.output) == "ARP"
        and op.opcode == OpCode.COPY
        and op.inputs
        and _is_const(op.inputs[0], new_arp),
        f"ARP={new_arp} update",
    )
    assert ops.index(register_store) < ops.index(arp_write) < ops.index(ram_load)


def _check_c2x_arp_selection(ops: list, width: int, new_arp: int) -> None:
    _no_internal_cfg(ops)
    register_load, ram_load = _arp_selected_pointer(ops, width)
    arp_write = _find(
        ops,
        lambda op: _reg(op.output) == "ARP"
        and op.opcode == OpCode.COPY
        and op.inputs
        and _is_const(op.inputs[0], new_arp),
        f"ARP={new_arp} selection",
    )
    assert not any(
        op.opcode == OpCode.STORE and _key(op.inputs[1]) == _key(register_load.inputs[1])
        for op in ops
    ), "*ARPn must not modify the old ARP-selected XAR"
    assert ops.index(register_load) < ops.index(arp_write) < ops.index(ram_load)


def check_c2x_postincrement16(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_ADD, width=2, delta=1)


def check_c2x_postdecrement16(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_SUB, width=2, delta=1)


def check_c2x_postincrement32(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_ADD, width=4, delta=2)


def check_c2x_postdecrement32(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_SUB, width=4, delta=2)


def check_c2x_postincrement8(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_ADD, width=2, delta=1)


def check_c2x_arp_selection16(ops: list) -> None:
    _check_c2x_arp_selection(ops, width=2, new_arp=2)


def check_amode1_arp_postdecrement16(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_SUB, width=2, delta=1, new_arp=2)


def check_amode1_arp_postdecrement32(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_SUB, width=4, delta=2, new_arp=3)


def check_amode1_arp_ar0_increment32(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_ADD, width=4, use_ar0=True, new_arp=3)


def check_amode1_arp_ar0_decrement32(ops: list) -> None:
    _check_c2x_postupdate(ops, OpCode.INT_SUB, width=4, use_ar0=True, new_arp=3)


def _indexed_word_address(ops: list, load_or_store_address, offset_register: str | None, delta: int) -> None:
    add = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and _depends_on_varnode(ops, load_or_store_address, op.output)
        and any(_depends_on_register(ops, value, "XAR4") for value in op.inputs),
        "indexed XAR4 word address",
    )
    if offset_register is None:
        assert any(
            _evaluates_to_constant(ops, value, delta) for value in add.inputs
        ), f"byte offset must map to word offset {delta}"
        return

    half_offset = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_RIGHT
        and any(_depends_on_register(ops, value, offset_register) for value in op.inputs)
        and any(_is_const(value, 1) for value in op.inputs),
        f"{offset_register} byte-to-word index conversion",
    )
    assert any(
        _depends_on_varnode(ops, value, half_offset.output) for value in add.inputs
    ), f"indexed address must use {offset_register} >> 1"


def check_movb_indexed_immediate_load(ops: list) -> None:
    _no_internal_cfg(ops)
    load = _last_load(ops, 2)
    _indexed_word_address(ops, load.inputs[1], offset_register=None, delta=1)
    parity = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_AND
        and any(_evaluates_to_constant(ops, value, 3) for value in op.inputs)
        and any(_is_const(value, 1) for value in op.inputs),
        "immediate byte-index parity",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_RIGHT
        and any(_depends_on_varnode(ops, value, load.output) for value in op.inputs)
        and any(_depends_on_varnode(ops, value, parity.output) for value in op.inputs),
        "odd indexed MOVB high-byte selection",
    )


def check_movb_indexed_ar0_load(ops: list) -> None:
    _no_internal_cfg(ops)
    load = _last_load(ops, 2)
    _indexed_word_address(ops, load.inputs[1], offset_register="AR0", delta=0)
    parity = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_AND
        and any(_depends_on_register(ops, value, "AR0") for value in op.inputs)
        and any(_is_const(value, 1) for value in op.inputs),
        "AR0 byte parity",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_RIGHT
        and any(_depends_on_varnode(ops, value, load.output) for value in op.inputs)
        and any(_depends_on_varnode(ops, value, parity.output) for value in op.inputs),
        "branch-free AR0-selected byte extraction",
    )


def _check_movb_indexed_store(ops: list, offset_register: str | None, delta: int) -> None:
    _no_internal_cfg(ops)
    loads = [op for op in ops if op.opcode == OpCode.LOAD and op.output.size == 2]
    stores = [op for op in ops if op.opcode == OpCode.STORE and op.inputs[2].size == 2]
    assert loads, "MOVB store must read the old 16-bit word"
    assert stores, "MOVB store must write the merged 16-bit word"
    load = loads[-1]
    store = stores[-1]
    assert _key(store.inputs[1]) == _key(load.inputs[1])
    assert ops.index(load) < ops.index(store)
    _indexed_word_address(ops, store.inputs[1], offset_register=offset_register, delta=delta)
    assert _depends_on_varnode(
        ops, store.inputs[2], load.output
    ), "MOVB store must preserve the untouched byte from memory"
    assert _depends_on_register(
        ops, store.inputs[2], "AL.LSB"
    ), "MOVB store must merge the selected AX byte"


def check_movb_indexed_immediate_store(ops: list) -> None:
    _check_movb_indexed_store(ops, offset_register=None, delta=1)
    parity = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_AND
        and any(_evaluates_to_constant(ops, value, 3) for value in op.inputs)
        and any(_is_const(value, 1) for value in op.inputs),
        "immediate byte-index parity",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_LEFT
        and any(_depends_on_register(ops, value, "AL.LSB") for value in op.inputs)
        and any(_depends_on_varnode(ops, value, parity.output) for value in op.inputs),
        "odd indexed MOVB high-byte insertion",
    )


def check_movb_indexed_ar0_store(ops: list) -> None:
    _check_movb_indexed_store(ops, offset_register="AR0", delta=0)


def check_ar0_modifier32(ops: list) -> None:
    register_load = _find(
        ops,
        lambda op: op.opcode == OpCode.LOAD
        and op.output.size == 4
        and _depends_on_register(ops, op.inputs[1], "ARP"),
        "ARP-selected XAR load",
    )
    register_store = _find(
        ops,
        lambda op: op.opcode == OpCode.STORE
        and _key(op.inputs[1]) == _key(register_load.inputs[1]),
        "ARP-selected XAR writeback",
    )
    update = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and _key(op.output) == _key(register_store.inputs[2])
        and _key(register_load.output) in {_key(value) for value in op.inputs}
        and any(_depends_on_register(ops, value, "AR0") for value in op.inputs),
        "*0++ AR0-scaled writeback",
    )
    assert not any(_is_const(value, 2) for value in update.inputs), "*0++ is not loc32 stride-scaled"
    ram_load = _last_load(ops, 4)
    assert _key(ram_load.inputs[1]) == _key(register_load.output)


def check_ar0_decrement32(ops: list) -> None:
    register_load = _find(
        ops,
        lambda op: op.opcode == OpCode.LOAD
        and op.output.size == 4
        and _depends_on_register(ops, op.inputs[1], "ARP"),
        "ARP-selected XAR load",
    )
    register_store = _find(
        ops,
        lambda op: op.opcode == OpCode.STORE
        and _key(op.inputs[1]) == _key(register_load.inputs[1]),
        "ARP-selected XAR writeback",
    )
    update = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB
        and _key(op.output) == _key(register_store.inputs[2])
        and _key(register_load.output) in {_key(value) for value in op.inputs}
        and any(_depends_on_register(ops, value, "AR0") for value in op.inputs),
        "*0-- AR0-scaled writeback",
    )
    assert not any(_is_const(value, 2) for value in update.inputs), "*0-- is not loc32 stride-scaled"
    ram_load = _last_load(ops, 4)
    assert _key(ram_load.inputs[1]) == _key(register_load.output)


def _check_bitreverse(ops: list, opcode: OpCode):
    _no_internal_cfg(ops)
    register_load = _find(
        ops,
        lambda op: op.opcode == OpCode.LOAD
        and op.output.size == 4
        and _depends_on_register(ops, op.inputs[1], "ARP"),
        "bit-reversed old XAR load",
    )
    register_store = _find(
        ops,
        lambda op: op.opcode == OpCode.STORE
        and _key(op.inputs[1]) == _key(register_load.inputs[1]),
        "bit-reversed XAR writeback",
    )
    low_update = _find(
        ops,
        lambda op: op.opcode == opcode
        and op.output.size == 2
        and not any(value.space.name == "const" for value in op.inputs),
        "16-bit bit-reversed pointer update",
    )
    assert any(
        op.opcode == OpCode.COPY and op.inputs and _reg(op.inputs[0]) == "AR0" for op in ops
    ), "bit-reversed update must use AR0 as the reversal step"
    assert _depends_on_varnode(ops, register_store.inputs[2], low_update.output)
    assert any(
        op.opcode == OpCode.INT_AND
        and any(_depends_on_varnode(ops, value, register_load.output) for value in op.inputs)
        and any(_is_const(value, 0xFFFF0000) for value in op.inputs)
        for op in ops
    ), "bit-reversed update must preserve XAR[31:16]"
    ram_load = _last_load(ops, 4 if any(op.opcode == OpCode.LOAD and op.output.size == 4 and _key(op.inputs[1]) == _key(register_load.output) for op in ops) else 2)
    assert _key(ram_load.inputs[1]) == _key(register_load.output)
    return register_store, ram_load


def check_bitreverse_increment(ops: list) -> None:
    _check_bitreverse(ops, OpCode.INT_ADD)


def check_bitreverse_decrement(ops: list) -> None:
    _check_bitreverse(ops, OpCode.INT_SUB)


def _check_amode1_arp_bitreverse(ops: list, opcode: OpCode, new_arp: int) -> None:
    register_store, ram_load = _check_bitreverse(ops, opcode)
    arp_write = _find(
        ops,
        lambda op: _reg(op.output) == "ARP"
        and op.opcode == OpCode.COPY
        and op.inputs
        and _is_const(op.inputs[0], new_arp),
        f"ARP={new_arp} bit-reverse update",
    )
    assert ops.index(register_store) < ops.index(arp_write) < ops.index(ram_load)


def check_amode1_arp_bitreverse_increment32(ops: list) -> None:
    _check_amode1_arp_bitreverse(ops, OpCode.INT_ADD, new_arp=3)


def check_amode1_arp_bitreverse_decrement32(ops: list) -> None:
    _check_amode1_arp_bitreverse(ops, OpCode.INT_SUB, new_arp=3)


def _check_circular(ops: list, delta: int, width: int) -> None:
    _no_internal_cfg(ops)
    snapshot = _find(
        ops,
        lambda op: op.opcode == OpCode.COPY
        and op.inputs
        and _reg(op.inputs[0]) == "XAR6"
        and op.output.space.name == "unique",
        "old circular-buffer address",
    )
    _find(
        ops,
        lambda op: op.opcode in (OpCode.INT_EQUAL, OpCode.INT_NOTEQUAL)
        and {_reg(value) for value in op.inputs} == {"AR1", "AR6"},
        "AR6[7:0] circular limit comparison",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and any(_reg(value) == "AR6" for value in op.inputs)
        and any(_is_const(value, delta) for value in op.inputs),
        f"circular +{delta} candidate",
    )
    load = _last_load(ops, width)
    assert _key(load.inputs[1]) == _key(snapshot.output)


def check_circular16(ops: list) -> None:
    _check_circular(ops, delta=1, width=2)


def check_circular32(ops: list) -> None:
    _check_circular(ops, delta=2, width=4)


def check_amode1_circular32(ops: list) -> None:
    _check_amode1_circular(ops, delta=2, width=4)


def _check_amode1_circular(ops: list, delta: int, width: int) -> None:
    _no_internal_cfg(ops)
    load = _last_load(ops, width)
    assert _depends_on_register(ops, load.inputs[1], "XAR6")
    assert _depends_on_register(ops, load.inputs[1], "AR1")
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_EQUAL
        and any(_depends_on_register(ops, value, "AR1") for value in op.inputs)
        and any(_reg(value) == "AR1H" for value in op.inputs),
        "AMODE=1 circular index/limit comparison",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and any(_depends_on_register(ops, value, "AR1") for value in op.inputs)
        and any(_is_const(value, delta) for value in op.inputs),
        f"AMODE=1 circular +{delta} candidate",
    )
    xar1_write = _find(ops, lambda op: _reg(op.output) == "XAR1", "AMODE=1 circular XAR1 write")
    assert xar1_write.opcode == OpCode.INT_OR
    assert not any(_reg(op.output) == "XAR6" for op in ops), "AMODE=1 circular mode must not update XAR6"


def check_amode1_circular16(ops: list) -> None:
    _check_amode1_circular(ops, delta=1, width=2)


def _check_amode1_direct(ops: list, width: int) -> None:
    load = _last_load(ops, width)
    assert _depends_on_register(ops, load.inputs[1], "DP")
    assert not _depends_on_register(ops, load.inputs[1], "SP")
    assert any(
        op.opcode == OpCode.INT_AND
        and any(_reg(value) == "DP" for value in op.inputs)
        and any(_is_const(value, 0xFFFE) for value in op.inputs)
        for op in ops
    ), "AMODE=1 direct addressing must ignore DP bit 0"


def check_amode1_direct(ops: list) -> None:
    _check_amode1_direct(ops, width=2)


def check_amode1_direct32(ops: list) -> None:
    _check_amode1_direct(ops, width=4)


def check_amode_clear_restores_stack(ops: list) -> None:
    loads = [op for op in ops if op.opcode == OpCode.LOAD and op.output.size == 2]
    assert len(loads) >= 2
    assert _depends_on_register(ops, loads[-1].inputs[1], "SP")
    assert not _depends_on_register(ops, loads[-1].inputs[1], "DP")


def _check_page0_direct(ops: list, width: int) -> None:
    load = _last_load(ops, width)
    address = load.inputs[1]
    assert _resolves_to_constant(
        ops, address, 3
    ), "PAGE0 direct address must be word 3 of data page zero"
    assert not _depends_on_register(ops, address, "DP")
    assert not _depends_on_register(ops, address, "SP")


def check_page0_direct(ops: list) -> None:
    _check_page0_direct(ops, width=2)


def check_page0_direct32(ops: list) -> None:
    _check_page0_direct(ops, width=4)


def _check_amode1_arp_postincrement(ops: list, delta: int, width: int) -> None:
    register_load = _find(
        ops,
        lambda op: op.opcode == OpCode.LOAD
        and op.output.size == 4
        and _depends_on_register(ops, op.inputs[1], "ARP"),
        "old ARP-selected XAR",
    )
    register_store = _find(
        ops,
        lambda op: op.opcode == OpCode.STORE
        and _key(op.inputs[1]) == _key(register_load.inputs[1]),
        "AMODE=1 postincrement writeback",
    )
    update = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and _key(op.output) == _key(register_store.inputs[2])
        and _key(register_load.output) in {_key(value) for value in op.inputs}
        and any(_is_const(value, delta) for value in op.inputs),
        "AMODE=1 *++,ARPn increment",
    )
    arp_write = _find(ops, lambda op: _reg(op.output) == "ARP", "new ARP selection")
    ram_load = _last_load(ops, width)
    assert _key(ram_load.inputs[1]) == _key(register_load.output)
    assert ops.index(update) < ops.index(register_store) < ops.index(arp_write) < ops.index(ram_load)


def check_amode1_arp_postincrement(ops: list) -> None:
    _check_amode1_arp_postincrement(ops, delta=1, width=2)


def check_amode1_arp_postincrement32(ops: list) -> None:
    _check_amode1_arp_postincrement(ops, delta=2, width=4)


def check_signed_acc_status(ops: list) -> None:
    _no_internal_cfg(ops)
    _find(
        ops,
        lambda op: op.opcode == OpCode.BOOL_OR and _reg(op.output) == "V",
        "sticky overflow update",
    )
    ovc_write = _find(ops, lambda op: _reg(op.output) == "OVC", "signed overflow-counter update")
    assert ovc_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_AND and any(_is_const(v, 0x3F) for v in op.inputs) for op in ops
    ), "OVC update must wrap as a six-bit counter"
    assert any(
        op.opcode == OpCode.INT_EQUAL and any(_reg(v) == "OVM" for v in op.inputs) for op in ops
    ), "OVC update must be suppressed while saturation mode is enabled"
    acc_write = _find(ops, lambda op: _reg(op.output) == "ACC", "OVM-selected ACC result")
    assert acc_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_XOR and any(_is_const(v, 0x7FFFFFFF) for v in op.inputs)
        for op in ops
    ), "OVM path must construct positive/negative saturation values"


def check_signed_carry_acc_status(ops: list) -> None:
    check_signed_acc_status(ops)
    carry_extend = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ZEXT
        and op.output.size == 5
        and op.inputs
        and _reg(op.inputs[0]) == "C",
        "five-byte carry-in extension",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ADD
        and op.output.size == 5
        and _key(carry_extend.output) in {_key(value) for value in op.inputs},
        "carry-in contribution to the full-width sum",
    )


def check_addcl_status(ops: list) -> None:
    check_signed_carry_acc_status(ops)
    vectors = (
        (
            {"ACC": 0xFFFFFFFF, "XAR6": 0xFFFFFFFF, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0xFFFFFFFF, "C": 1, "V": 0, "OVC": 0, "N": 1, "Z": 0},
            "ADDCL retains the second carry without a signed overflow",
        ),
        (
            {"ACC": 0x7FFFFFFF, "XAR6": 0, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
            "ADDCL positive overflow increments OVC",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0xFF, "N": 0, "Z": 0},
            "ADDCL negative overflow decrements OVC",
        ),
        (
            {"ACC": 0x7FFFFFFF, "XAR6": 0, "C": 1, "V": 0, "OVC": 5, "OVM": 1},
            {"ACC": 0x7FFFFFFF, "C": 0, "V": 1, "OVC": 5, "N": 0, "Z": 0},
            "ADDCL OVM saturation suppresses OVC",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_addcu_status(ops: list) -> None:
    check_signed_carry_acc_status(ops)
    vectors = (
        (
            {"ACC": 0xFFFFFFFF, "T": 0, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
            "ADDCU includes carry across 32 bits",
        ),
        (
            {"ACC": 0x7FFFFFFF, "T": 0, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
            "ADDCU carry-in participates in signed overflow",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_signed_borrow_acc_status(ops: list) -> None:
    check_signed_acc_status(ops)
    borrow = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_EQUAL
        and any(_reg(value) == "C" for value in op.inputs)
        and any(_is_const(value, 0) for value in op.inputs),
        "inverse-carry borrow input",
    )
    borrow_extend = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_ZEXT
        and op.output.size == 5
        and op.inputs
        and _key(op.inputs[0]) == _key(borrow.output),
        "five-byte borrow extension",
    )
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB
        and op.output.size == 5
        and _key(borrow_extend.output) in {_key(value) for value in op.inputs},
        "borrow contribution to the full-width difference",
    )


def check_subbl_status(ops: list) -> None:
    check_signed_borrow_acc_status(ops)
    vectors = (
        (
            {"ACC": 0, "XAR6": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0, "C": 0, "V": 0, "OVC": 0, "N": 0, "Z": 1},
            "SUBBL preserves borrow when operand plus inverse carry wraps",
        ),
        (
            {"ACC": 0x7FFFFFFF, "XAR6": 0xFFFFFFFF, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
            "SUBBL positive overflow increments OVC",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 1, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0xFF, "N": 0, "Z": 0},
            "SUBBL negative overflow decrements OVC",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 1, "C": 1, "V": 0, "OVC": 7, "OVM": 1},
            {"ACC": 0x80000000, "C": 1, "V": 1, "OVC": 7, "N": 1, "Z": 0},
            "SUBBL OVM negative saturation suppresses OVC",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_sbbu_status(ops: list) -> None:
    check_signed_borrow_acc_status(ops)
    vectors = (
        (
            {"ACC": 0, "T": 0, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0, "N": 1, "Z": 0},
            "SBBU subtracts inverse carry even for a zero operand",
        ),
        (
            {"ACC": 0x80000000, "T": 1, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0xFF, "N": 0, "Z": 0},
            "SBBU negative overflow decrements OVC",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def _check_unsigned_ovcu(ops: list, destination: str) -> None:
    _no_internal_cfg(ops)
    _find(ops, lambda op: _reg(op.output) == destination, f"{destination} result write")
    _find(ops, lambda op: _reg(op.output) == "C", "carry/no-borrow write")
    _find(
        ops,
        lambda op: op.opcode == OpCode.BOOL_OR and _reg(op.output) == "V",
        "sticky signed-overflow flag",
    )
    ovc_write = _find(ops, lambda op: _reg(op.output) == "OVC", "OVCU counter update")
    assert ovc_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_AND and any(_is_const(value, 0x3F) for value in op.inputs)
        for op in ops
    ), "OVCU must wrap in the architectural six-bit counter"
    assert not any(
        any(_reg(value) == "OVM" for value in op.inputs) for op in ops
    ), "OVM must not suppress unsigned OVCU carry/borrow accounting"
    _find(ops, lambda op: _reg(op.output) == "N", "negative flag update")
    _find(ops, lambda op: _reg(op.output) == "Z", "zero flag update")


def check_addul_acc(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="ACC")
    _check_addul_execution(ops, destination="ACC")


def check_addul_p(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="P")
    _check_addul_execution(ops, destination="P")


def check_subul_acc(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="ACC")
    _check_subul_execution(ops, destination="ACC")


def check_subul_p(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="P")
    _check_subul_execution(ops, destination="P")


def _check_addul_execution(ops: list, destination: str) -> None:
    vectors = (
        (
            {destination: 0xFFFFFFFF, "XAR6": 1, "V": 0, "OVC": 0x1F},
            {destination: 0, "C": 1, "V": 0, "OVC": 0xE0, "N": 0, "Z": 1},
            f"ADDUL {destination} wraps OVCU from +31 to -32 on carry",
        ),
        (
            {destination: 0x7FFFFFFF, "XAR6": 1, "V": 0, "OVC": 5},
            {destination: 0x80000000, "C": 0, "V": 1, "OVC": 5, "N": 1, "Z": 0},
            f"ADDUL {destination} sets sticky V without changing OVCU when no carry occurs",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def _check_subul_execution(ops: list, destination: str) -> None:
    vectors = (
        (
            {destination: 0, "XAR6": 1, "V": 0, "OVC": 0xE0},
            {destination: 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0x1F, "N": 1, "Z": 0},
            f"SUBUL {destination} wraps OVCU from -32 to +31 on borrow",
        ),
        (
            {destination: 0x80000000, "XAR6": 1, "V": 0, "OVC": 5},
            {destination: 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 5, "N": 0, "Z": 0},
            f"SUBUL {destination} sets sticky V without changing OVCU when no borrow occurs",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_cmpl_infinite_precision(ops: list) -> None:
    acc_extend = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SEXT
        and op.output.size == 5
        and op.inputs
        and _reg(op.inputs[0]) == "ACC",
        "CMPL five-byte ACC sign extension",
    )
    operand_extend = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SEXT
        and op.output.size == 5
        and op.inputs
        and _depends_on_register(ops, op.inputs[0], "XAR6"),
        "CMPL five-byte operand sign extension",
    )
    difference = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB
        and op.output.size == 5
        and {_key(value) for value in op.inputs}
        == {_key(acc_extend.output), _key(operand_extend.output)},
        "CMPL infinite-precision difference",
    )
    n_write = _find(ops, lambda op: _reg(op.output) == "N", "CMPL N update")
    assert _key(difference.output) in {_key(value) for value in n_write.inputs}
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_LESSEQUAL
        and any(_depends_on_register(ops, value, "ACC") for value in op.inputs)
        and any(_depends_on_register(ops, value, "XAR6") for value in op.inputs),
        "CMPL unsigned no-borrow comparison",
    )
    assert not any(_reg(op.output) == "V" for op in ops), "CMPL must leave sticky V unchanged"
    vectors = (
        (
            {"ACC": 0x80000000, "XAR6": 1},
            {"N": 1, "Z": 0, "C": 1},
            "CMPL infinite-precision signed negative with unsigned no-borrow",
        ),
        (
            {"ACC": 0, "XAR6": 0xFFFFFFFF},
            {"N": 0, "Z": 0, "C": 0},
            "CMPL signed positive result with unsigned borrow",
        ),
        (
            {"ACC": 0x12345678, "XAR6": 0x12345678},
            {"N": 0, "Z": 1, "C": 1},
            "CMPL equality",
        ),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_cmpl_signed_branch(ops: list) -> None:
    branch = _find(ops, lambda op: op.opcode == OpCode.CBRANCH, "signed CMPL branch")
    predicate = branch.inputs[1]
    assert _depends_on_register(ops, predicate, "N")
    assert not _depends_on_register(ops, predicate, "C")


def check_cmpl_unsigned_branch(ops: list) -> None:
    branch = _find(ops, lambda op: op.opcode == OpCode.CBRANCH, "unsigned CMPL branch")
    predicate = branch.inputs[1]
    assert _depends_on_register(ops, predicate, "C")
    assert _depends_on_register(ops, predicate, "Z")
    assert not _depends_on_register(ops, predicate, "N")


def check_max_snapshot(ops: list) -> None:
    snapshot = _find_index(
        ops,
        lambda op: op.opcode == OpCode.COPY
        and op.inputs
        and _reg(op.inputs[0]) == "R0H"
        and op.output.space.name == "unique",
        "MAXF32 old-R0H snapshot",
    )
    move_write = _find_index(
        ops,
        lambda op: _reg(op.output) == "R2H" and op.inputs and op.inputs[0].space.name == "unique",
        "parallel MOV32 R2H write",
    )
    assert snapshot < move_write


def check_push_st0_encoding(ops: list) -> None:
    _no_internal_cfg(ops)
    pm_decode_to_raw = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_SUB
        and len(op.inputs) == 2
        and _is_const(op.inputs[0], 1),
        "decoded PM to raw ST0 mapping",
    )
    pm_mask = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_AND
        and _key(pm_decode_to_raw.output) in {_key(v) for v in op.inputs}
        and any(_is_const(v, 7) for v in op.inputs),
        "three-bit PM mask",
    )
    pm_shift = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_LEFT
        and _key(pm_mask.output) in {_key(v) for v in op.inputs}
        and any(_is_const(v, 7) for v in op.inputs),
        "PM placement into ST0 bits 9:7",
    )
    st0_write = _find(ops, lambda op: _reg(op.output) == "ST0", "packed ST0 write")
    assert _key(pm_shift.output) in {
        _key(v) for op in ops if op.opcode == OpCode.INT_OR for v in op.inputs
    }
    assert st0_write.opcode == OpCode.INT_OR


def check_pop_st0_decoding(ops: list) -> None:
    _no_internal_cfg(ops)
    ovc_write = _find(ops, lambda op: _reg(op.output) == "OVC", "signed OVC write")
    assert ovc_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_AND and any(_is_const(v, 0xC0) for v in op.inputs) for op in ops
    ), "OVC must sign-extend raw bit 5 through bits 7:6"

    pm_write = _find(ops, lambda op: _reg(op.output) == "PM", "decoded PM write")
    assert pm_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_EQUAL and any(_is_const(v, 5) for v in op.inputs) for op in ops
    ), "raw PM 101 must receive AMODE-dependent handling"
    assert any(
        op.opcode == OpCode.INT_NOTEQUAL and any(_reg(v) == "AMODE" for v in op.inputs)
        for op in ops
    ), "PM raw 101 decode must inspect AMODE"


def check_branch_v_clear(ops: list) -> None:
    condition = _find(
        ops,
        lambda op: op.opcode in (OpCode.INT_EQUAL, OpCode.INT_NOTEQUAL)
        and any(_reg(v) == "V" for v in op.inputs),
        "pre-clear V condition snapshot",
    )
    clear = _find(
        ops,
        lambda op: _reg(op.output) == "V"
        and op.opcode == OpCode.COPY
        and len(op.inputs) == 1
        and _is_const(op.inputs[0], 0),
        "mandatory V clear",
    )
    branch = _find(ops, lambda op: op.opcode == OpCode.CBRANCH, "conditional branch")
    assert ops.index(condition) < ops.index(clear) < ops.index(branch)
    condition_key = _key(condition.output)
    branch_key = _key(branch.inputs[1])
    if condition_key == branch_key:
        return
    negate = _find(
        ops,
        lambda op: op.opcode == OpCode.BOOL_NEGATE
        and op.inputs
        and _key(op.inputs[0]) == condition_key
        and _key(op.output) == branch_key,
        "branch predicate derived from the pre-clear V snapshot",
    )
    assert ops.index(clear) < ops.index(negate) < ops.index(branch)


def check_unconditional_direct_branch(ops: list) -> None:
    branches = [op for op in ops if op.opcode == OpCode.BRANCH]
    conditional = [op for op in ops if op.opcode == OpCode.CBRANCH]
    assert len(branches) == 1, f"expected one direct branch, got {len(branches)}"
    assert not conditional, "UNC branch must not expose a conditional fallthrough"


def _check_xar7_code_target(ops: list, opcode: OpCode) -> None:
    flow = _find(ops, lambda op: op.opcode == opcode, f"{opcode.name} through XAR7")
    definitions = _unique_definitions(ops)
    target = _definition_for(definitions, flow.inputs[0])
    assert target is not None and target.opcode == OpCode.INT_AND
    assert any(_is_const(value, 0x3FFFFF) for value in target.inputs)
    assert any(_depends_on_register(ops, value, "XAR7") for value in target.inputs)


def check_lb_xar7_target(ops: list) -> None:
    _check_xar7_code_target(ops, OpCode.BRANCHIND)


def check_lc_xar7_target(ops: list) -> None:
    _check_xar7_code_target(ops, OpCode.CALLIND)


def check_movl_register_to_acc_flags(ops: list) -> None:
    copy = _find(
        ops,
        lambda op: op.opcode == OpCode.COPY and _reg(op.output) == "ACC",
        "MOVL destination write to ACC",
    )
    assert len(copy.inputs) == 1, "MOVL ACC source must be a single value"
    source = _reg(copy.inputs[0])
    assert source in {
        "ACC",
        "P",
        "XT",
        "XAR0",
        "XAR1",
        "XAR2",
        "XAR3",
        "XAR4",
        "XAR5",
        "XAR6",
        "XAR7",
    }, f"unexpected MOVL ACC source {source}"

    n_write = _find(
        ops, lambda op: _reg(op.output) == "N", "MOVL ACC negative-flag write"
    )
    z_write = _find(
        ops, lambda op: _reg(op.output) == "Z", "MOVL ACC zero-flag write"
    )
    assert ops.index(copy) < ops.index(n_write) < ops.index(z_write)
    assert any(
        _depends_on_register(ops, value, "ACC") for value in n_write.inputs
    ), "MOVL ACC N flag must depend on the copied ACC value"
    assert any(
        _depends_on_register(ops, value, "ACC") for value in z_write.inputs
    ), "MOVL ACC Z flag must depend on the copied ACC value"

    for value, expected_n, expected_z in (
        (0x00000000, 0, 1),
        (0x00000001, 0, 0),
        (0x80000000, 1, 0),
    ):
        _assert_execution(
            ops,
            {source: value, "N": 1 - expected_n, "Z": 1 - expected_z},
            {"ACC": value, "N": expected_n, "Z": expected_z},
            f"MOVL ACC,{source} flags for 0x{value:08x}",
        )


def check_movl_acc_self_flags(ops: list) -> None:
    assert not any(
        op.opcode == OpCode.COPY and _reg(op.output) == "ACC" for op in ops
    ), "MOVL ACC,ACC should not emit a redundant self-copy"

    n_write = _find(
        ops, lambda op: _reg(op.output) == "N", "MOVL ACC,ACC negative-flag write"
    )
    z_write = _find(
        ops, lambda op: _reg(op.output) == "Z", "MOVL ACC,ACC zero-flag write"
    )
    assert ops.index(n_write) < ops.index(z_write)
    assert any(
        _depends_on_register(ops, value, "ACC") for value in n_write.inputs
    ), "MOVL ACC,ACC N flag must depend on ACC"
    assert any(
        _depends_on_register(ops, value, "ACC") for value in z_write.inputs
    ), "MOVL ACC,ACC Z flag must depend on ACC"

    for value, expected_n, expected_z in (
        (0x00000000, 0, 1),
        (0x00000001, 0, 0),
        (0x80000000, 1, 0),
    ):
        _assert_execution(
            ops,
            {"ACC": value, "N": 1 - expected_n, "Z": 1 - expected_z},
            {"ACC": value, "N": expected_n, "Z": expected_z},
            f"MOVL ACC,ACC flags for 0x{value:08x}",
        )


CASES = (
    Case("BANZ decrements before branching", (0x000A, 0x0001), check_banz),
    Case("MOV32 UNCF flags are branch-free", (0xE2AF, 0x0021), check_mov32_uncf),
    Case("MPYF32||ADDF32 uses old sources", (0xE742, 0xC688), check_parallel_mpy_add),
    Case("ADDF32||MOV32 snapshots aliased source", (0xE014, 0x4080), check_parallel_store_alias),
    Case("MOVXI preserves upper half", (0xE808, 0x91A0), check_movxi),
    Case("DMOV uses architectural loc+1", (0xA53A,), check_dmov),
    Case("MOVAD uses architectural loc+1", (0xA711,), check_movad),
    Case("MOVDL uses architectural loc+2", (0xA60C,), check_movdl),
    Case("MOVD32 uses architectural mem+2", (0xE223, 0x0321), check_movd32),
    Case("XMACD uses architectural loc+1", (0xA43F, 0xFACE), check_xmacd),
    Case("loc16 *XAR4++ advances one word", (0x9284,), check_xar_postincrement16),
    Case("loc32 *XAR4++ advances two words", (0x0684,), check_xar_postincrement32),
    Case("MOVB *XAR4++ advances one word", (0xC684,), check_xar_postincrement8),
    Case("loc16 *--XAR4 decrements before loading", (0x928C,), check_xar_predecrement16),
    Case("loc32 *--XAR4 decrements by two before loading", (0x068C,), check_xar_predecrement32),
    Case("loc16 *SP++ uses old SP and one-word stride", (0x92BD,), check_sp_postincrement16),
    Case("loc32 *SP++ uses old SP and two-word stride", (0x06BD,), check_sp_postincrement32),
    Case("loc16 *--SP decrements before loading", (0x92BE,), check_sp_predecrement16),
    Case("loc32 *--SP decrements by two before loading", (0x06BE,), check_sp_predecrement32),
    Case(
        "MOVB immediate byte index maps offset 3 to word +1",
        (0xC6DC,),
        check_movb_indexed_immediate_load,
    ),
    Case(
        "MOVB AR0 byte index is branch-free and word-scaled",
        (0xC694,),
        check_movb_indexed_ar0_load,
    ),
    Case(
        "MOVB immediate byte store preserves the neighboring byte",
        (0x3CDC,),
        check_movb_indexed_immediate_store,
    ),
    Case(
        "MOVB AR0 byte store is branch-free read-modify-write",
        (0x3C94,),
        check_movb_indexed_ar0_store,
    ),
    Case("loc32 *0++ uses AR0 rather than loc width", (0x06BB,), check_ar0_modifier32),
    Case("loc32 *0-- uses AR0 rather than loc width", (0x06BC,), check_ar0_decrement32),
    Case("loc16 C2xLP *++ updates the old ARP-selected XAR", (0x92B9,), check_c2x_postincrement16),
    Case("loc16 C2xLP *-- decrements the old ARP-selected XAR", (0x92BA,), check_c2x_postdecrement16),
    Case("loc32 C2xLP *++ uses two-word stride", (0x06B9,), check_c2x_postincrement32),
    Case("loc32 C2xLP *-- uses two-word stride", (0x06BA,), check_c2x_postdecrement32),
    Case("MOVB C2xLP *++ advances one word", (0xC6B9,), check_c2x_postincrement8),
    Case("C2xLP *ARP2 loads through old ARP before selecting ARP2", (0x92B2,), check_c2x_arp_selection16),
    Case("loc32 *BR0++ updates only the low 16 bits", (0x06AE,), check_bitreverse_increment),
    Case("loc32 *BR0-- updates only the low 16 bits", (0x06AF,), check_bitreverse_decrement),
    Case("loc16 circular update is branch-free", (0x92BF,), check_circular16),
    Case("loc32 circular update is branch-free", (0x06BF,), check_circular32),
    Case(
        "AMODE=1 common loc32 postincrement keeps two-word stride",
        (0x561E, 0x0684),
        check_xar_postincrement32,
    ),
    Case(
        "AMODE=1 circular loc32 updates XAR1 index by two",
        (0x561E, 0x06BF),
        check_amode1_circular32,
    ),
    Case(
        "AMODE=1 circular loc16 updates XAR1 index by one",
        (0x561E, 0x92BF),
        check_amode1_circular16,
    ),
    Case(
        "AMODE=1 circular MOVB accesses one word and advances XAR1 by one",
        (0x561E, 0xC6BF),
        check_amode1_circular16,
    ),
    Case("SETC AMODE selects 7-bit direct addressing", (0x561E, 0x9240), check_amode1_direct),
    Case(
        "SETC AMODE selects 7-bit direct addressing for loc32",
        (0x561E, 0x0640),
        check_amode1_direct32,
    ),
    Case(
        "CLRC AMODE restores C28x stack decoding",
        (0x561E, 0x9240, 0x5616, 0x9243),
        check_amode_clear_restores_stack,
    ),
    Case("SETC PAGE0 selects page-zero direct addressing", (0x3B40, 0x9243), check_page0_direct),
    Case(
        "SETC PAGE0 selects page-zero direct addressing for loc32",
        (0x3B40, 0x0643),
        check_page0_direct32,
    ),
    Case(
        "CLRC PAGE0 restores stack addressing",
        (0x3B40, 0x9243, 0x2940, 0x9243),
        check_amode_clear_restores_stack,
    ),
    Case(
        "AMODE=1 *++,ARPn updates old XAR then ARP",
        (0x561E, 0x92C2),
        check_amode1_arp_postincrement,
    ),
    Case(
        "AMODE=1 loc32 *++,ARPn uses two-word stride",
        (0x561E, 0x06C2),
        check_amode1_arp_postincrement32,
    ),
    Case(
        "AMODE=1 loc16 *--,ARP2 decrements old XAR before selecting ARP2",
        (0x561E, 0x92CA),
        check_amode1_arp_postdecrement16,
    ),
    Case(
        "AMODE=1 loc32 *--,ARP3 uses two-word stride",
        (0x561E, 0x06CB),
        check_amode1_arp_postdecrement32,
    ),
    Case(
        "AMODE=1 loc32 *0++,ARP3 uses AR0 and old XAR",
        (0x561E, 0x06D3),
        check_amode1_arp_ar0_increment32,
    ),
    Case(
        "AMODE=1 loc32 *0--,ARP3 uses inverse AR0 update",
        (0x561E, 0x06DB),
        check_amode1_arp_ar0_decrement32,
    ),
    Case(
        "AMODE=1 loc32 *BR0++,ARP3 preserves upper XAR before ARP update",
        (0x561E, 0x06E3),
        check_amode1_arp_bitreverse_increment32,
    ),
    Case(
        "AMODE=1 loc32 *BR0--,ARP3 preserves upper XAR before ARP update",
        (0x561E, 0x06EB),
        check_amode1_arp_bitreverse_decrement32,
    ),
    Case(
        "DMOV address-only postincrement uses one-word stride",
        (0xA584,),
        check_xar_postincrement16,
    ),
    Case(
        "MOVDL address-only postincrement uses two-word stride",
        (0xA684,),
        check_xar_postincrement32,
    ),
    Case(
        "DMOV address-only predecrement uses one-word stride",
        (0xA58C,),
        check_xar_predecrement16,
    ),
    Case(
        "MOVDL address-only predecrement uses two-word stride",
        (0xA68C,),
        check_xar_predecrement32,
    ),
    Case("SUBL models V, signed OVC, and OVM branch-free", (0x11AC,), check_signed_acc_status),
    Case("ADDCL includes carry in signed status", (0x5640, 0x00A6), check_addcl_status),
    Case("ADDCU includes carry in signed status", (0x0CAC,), check_addcu_status),
    Case("SUBBL preserves full-width inverse borrow", (0x5654, 0x00A6), check_subbl_status),
    Case("SBBU preserves full-width inverse borrow", (0x1DAC,), check_sbbu_status),
    Case("ADDUL ACC counts unsigned carry in OVCU", (0x5653, 0x00A6), check_addul_acc),
    Case("ADDUL P counts unsigned carry in OVCU", (0x5657, 0x00A6), check_addul_p),
    Case("SUBUL ACC counts unsigned borrow in OVCU", (0x5655, 0x00A6), check_subul_acc),
    Case("SUBUL P counts unsigned borrow in OVCU", (0x565D, 0x00A6), check_subul_p),
    Case("CMPL uses infinite-precision N and unsigned C", (0x0FA6,), check_cmpl_infinite_precision),
    Case(
        "compiler signed CMPL/SB LT sequence branches from N",
        (0x0FA6, 0x6403),
        check_cmpl_signed_branch,
    ),
    Case(
        "compiler unsigned CMPL/SB HI sequence branches from C and Z",
        (0x0FA6, 0x6603),
        check_cmpl_unsigned_branch,
    ),
    Case("DIVF32 conditions inputs and models result/LUF/LVF", (0xE274, 0x0058), check_divf32),
    Case(
        "DIVF32 snapshots an aliased numerator before writeback",
        (0xE274, 0x0009),
        check_divf32_aliased_numerator,
    ),
    Case("MAXF32||MOV32 snapshots aliased source", (0xE69C, 0x0088), check_max_snapshot),
    Case("PUSH ST0 encodes decoded PM and six-bit OVC", (0x7618,), check_push_st0_encoding),
    Case("POP ST0 decodes PM and sign-extends OVC", (0x7613,), check_pop_st0_decoding),
    Case("B OV snapshots then clears V", (0xFFEB, 0x0001), check_branch_v_clear),
    Case("BF NOV snapshots then clears V", (0x56CA, 0x0001), check_branch_v_clear),
    Case("SB OV snapshots then clears V", (0x6B02,), check_branch_v_clear),
    Case("B UNC is an unconditional branch", (0xFFEF, 0x0001), check_unconditional_direct_branch),
    Case("BF UNC is an unconditional branch", (0x56CF, 0x0001), check_unconditional_direct_branch),
    Case("SB UNC is an unconditional branch", (0x6F02,), check_unconditional_direct_branch),
    Case("conditional MOVB OV snapshots then clears V", (0x56BB, 0x0511), check_branch_v_clear),
    Case("XRETC OV snapshots then clears V", (0x56FB,), check_branch_v_clear),
    Case("LB *XAR7 masks its target to 22 code-address bits", (0x7620,), check_lb_xar7_target),
    Case("LC *XAR7 masks its target to 22 code-address bits", (0x7604,), check_lc_xar7_target),
    Case("MOVL ACC,ACC refreshes N and Z", (0x1EA9,), check_movl_acc_self_flags),
    Case("MOVL ACC,P refreshes N and Z", (0xA9A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XT refreshes N and Z", (0xABA9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR0 refreshes N and Z", (0x3AA9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR1 refreshes N and Z", (0xB2A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR2 refreshes N and Z", (0xAAA9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR3 refreshes N and Z", (0xA2A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR4 refreshes N and Z", (0xA8A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR5 refreshes N and Z", (0xA0A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR6 refreshes N and Z", (0xC2A9,), check_movl_register_to_acc_flags),
    Case("MOVL ACC,XAR7 refreshes N and Z", (0xC3A9,), check_movl_register_to_acc_flags),
)


def main() -> int:
    failures: list[str] = []
    for case in CASES:
        try:
            case.check(_translate(case.words))
        except Exception as exc:  # Keep the full suite running to report all regressions.
            failures.append(f"FAIL {case.name}: {exc}")
        else:
            print(f"PASS {case.name}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"SEMANTIC_TESTS={len(CASES)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
