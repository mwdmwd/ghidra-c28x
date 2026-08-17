#!/usr/bin/env python3
"""Focused semantic regressions for high-value C28x P-Code behavior.

These tests inspect P-Code rather than instruction text.  Most assertions protect
structure, data dependencies, update order, and effective-address side effects;
a small integer-only evaluator also executes boundary vectors for selected
register-form arithmetic constructors.  It is not a hardware emulator.
"""

from __future__ import annotations

import argparse
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


def _translate_div32(words: Iterable[int]) -> list:
    """Translate an analyzer-proved full-width SUBCUL division schedule."""
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("subcul_div32", 1)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_pm_store_noshift(words: Iterable[int]) -> list:
    """Translate an analyzer-proved decoded-PM-zero MOV loc16,P."""
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("pm_store_noshift", 1)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_lsrl_count(words: Iterable[int], count: int) -> list:
    """Translate LSRL selected by an exact nonzero T(4:0) proof."""
    assert 0 < count <= 31
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("lsrl_t_count", count)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_asr64_pair_phase(words: Iterable[int], phase: int) -> list:
    """Translate one phase of an analyzer-proven adjacent ASR64 #16 pair."""
    assert phase in (0, 1, 2)
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("asr64_pair_phase", phase)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_ovm_zero(words: Iterable[int]) -> list:
    """Translate arithmetic selected by a finite proof that OVM is zero."""
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("ovm_zero", 1)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_switch_canonical(words: Iterable[int]) -> list:
    """Translate an instruction selected by a complete switch proof."""
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    ctx.setVariableDefault("switch_canonical", 1)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in ctx.translate(data).ops if op.opcode != OpCode.IMARK]


def _translate_at(words: Iterable[int], base_address: int) -> list:
    """Translate a schedule at an explicit byte-domain program address."""
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    data = b"".join(struct.pack("<H", word) for word in words)
    return [
        op for op in ctx.translate(data, base_address=base_address).ops
        if op.opcode != OpCode.IMARK
    ]


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
        elif opcode == OpCode.INT_DIV:
            if args[1] == 0:
                raise AssertionError("canonical unsigned division by zero")
            result = args[0] // args[1]
        elif opcode == OpCode.INT_REM:
            if args[1] == 0:
                raise AssertionError("canonical unsigned remainder by zero")
            result = args[0] % args[1]
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
        elif opcode == OpCode.INT_DIV:
            if args[1] == 0:
                raise AssertionError("canonical unsigned division by zero")
            result = args[0] // args[1]
        elif opcode == OpCode.INT_REM:
            if args[1] == 0:
                raise AssertionError("canonical unsigned remainder by zero")
            result = args[0] % args[1]
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


def _execute_tmu_pcode(ops: list, initial: dict[str, int]) -> dict[str, int]:
    """Execute the finite P-Code subset used by focused TMU constructors.

    Unlike the integer-only harness, this supports forward intra-instruction
    branches and the floating-point operations used by the retained TMU
    regressions.  It remains a local eventual-state harness, not a cycle-
    accurate C28x or TMU emulator.
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
            raise AssertionError(f"register {name} is absent from TMU P-Code")
        write(node, value)

    pc = 0
    steps = 0
    while pc < len(ops):
        steps += 1
        if steps > 1000:
            raise AssertionError("TMU P-Code exceeded execution step limit")
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
            raise AssertionError(f"unsupported side-effect TMU P-Code op {opcode.name}")

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
        elif opcode == OpCode.INT_CARRY:
            result = int(args[0] + args[1] > mask(op.inputs[0].size))
        elif opcode == OpCode.FLOAT_EQUAL:
            result = int(_float32_from_bits(args[0]) == _float32_from_bits(args[1]))
        elif opcode == OpCode.FLOAT_LESS:
            result = int(_float32_from_bits(args[0]) < _float32_from_bits(args[1]))
        elif opcode == OpCode.FLOAT_LESSEQUAL:
            result = int(_float32_from_bits(args[0]) <= _float32_from_bits(args[1]))
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
        elif opcode == OpCode.FLOAT_MULT:
            result = _float32_to_bits(
                _float32_from_bits(args[0]) * _float32_from_bits(args[1])
            )
        elif opcode == OpCode.FLOAT_ADD:
            result = _float32_to_bits(
                _float32_from_bits(args[0]) + _float32_from_bits(args[1])
            )
        elif opcode == OpCode.FLOAT_SUB:
            result = _float32_to_bits(
                _float32_from_bits(args[0]) - _float32_from_bits(args[1])
            )
        elif opcode == OpCode.FLOAT_SQRT:
            operand = _float32_from_bits(args[0])
            result = _float32_to_bits(math.sqrt(operand))
        elif opcode == OpCode.FLOAT_TRUNC:
            result = math.trunc(_float32_from_bits(args[0]))
        elif opcode == OpCode.FLOAT_INT2FLOAT:
            result = _float32_to_bits(float(signed(args[0], op.inputs[0].size)))
        elif opcode == OpCode.CALLOTHER:
            assert len(args) == 2, f"unexpected TMU CALLOTHER arity: {len(args)}"
            fraction_bits = args[1] & 0xFFFFFFFF
            magnitude = fraction_bits & 0x7FFFFFFF
            if magnitude == 0:
                result = 0x3F800000
            elif magnitude in (0x3E800000, 0x3F400000):
                # The manual's cardinal-value table specifies positive zero.
                result = 0x00000000
            elif magnitude == 0x3F000000:
                result = 0xBF800000
            else:
                fraction = _float32_from_bits(fraction_bits)
                result = _float32_to_bits(math.cos(fraction * (2.0 * math.pi)))
        else:
            raise AssertionError(f"unsupported TMU P-Code op {opcode.name}")
        write(op.output, result)
        pc += 1

    return {name: read(node) for name, node in registers.items()}


def _f32(value: float) -> int:
    return _float32_to_bits(value)


def check_divf32(ops: list) -> None:
    _no_internal_cfg(ops)
    divides = [op for op in ops if op.opcode == OpCode.FLOAT_DIV]
    assert len(divides) == 1, f"DIVF32 must emit one FLOAT_DIV, got {len(divides)}"
    divide = divides[0]
    first_write = _find_index(ops, lambda op: _reg(op.output) == "R0H", "DIVF32 result write")
    assert any(
        index < first_write and any(_reg(value) == "R3H" for value in op.inputs)
        for index, op in enumerate(ops)
    ), "DIVF32 must read its numerator before destination writeback"
    assert any(
        index < first_write and any(_reg(value) == "R1H" for value in op.inputs)
        for index, op in enumerate(ops)
    ), "DIVF32 must read its denominator before destination writeback"

    stf_flags = {"STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"}
    flag_reads = {
        _reg(value)
        for op in ops
        for value in op.inputs
        if _reg(value) in stf_flags
    }
    assert flag_reads <= {"STF_LU", "STF_LV"}, (
        f"DIVF32 may read only its sticky destination flags: {flag_reads}"
    )
    flag_writes = [op for op in ops if _reg(op.output) in stf_flags]
    written = {_reg(op.output) for op in flag_writes}
    assert written == {"STF_LU", "STF_LV"}, f"unexpected DIVF32 STF writes: {written}"

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
        actual = _execute_tmu_pcode(
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


def check_div2pif32(ops: list) -> None:
    _no_internal_cfg(ops)
    multiplies = [op for op in ops if op.opcode == OpCode.FLOAT_MULT]
    assert len(multiplies) == 1, (
        f"DIV2PIF32 must emit one FLOAT_MULT, got {len(multiplies)}"
    )
    multiply = multiplies[0]
    source_inputs = [
        value for value in multiply.inputs if _depends_on_register(ops, value, "R0H")
    ]
    assert len(source_inputs) == 1 and source_inputs[0].space.name == "unique", (
        "DIV2PIF32 must snapshot its aliased R0H source"
    )
    constant_inputs = [
        value for value in multiply.inputs if _resolves_to_constant(ops, value, 0x3E22F983)
    ]
    assert len(constant_inputs) == 1, "DIV2PIF32 must use exact 0x3E22F983"
    assert any(_reg(op.output) == "R0H" for op in ops), "DIV2PIF32 must write R0H"

    stf_flags = {"STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"}
    flag_reads = {
        _reg(value)
        for op in ops
        for value in op.inputs
        if _reg(value) in stf_flags
    }
    assert flag_reads <= {"STF_LU"}, (
        f"DIV2PIF32 may read only its sticky destination flag: {flag_reads}"
    )
    flag_writes = [op for op in ops if _reg(op.output) in stf_flags]
    assert {_reg(op.output) for op in flag_writes} == {"STF_LU"}, (
        f"unexpected DIV2PIF32 STF writes: {flag_writes}"
    )

    scale = _float32_from_bits(0x3E22F983)

    def product_bits(operand: int) -> int:
        return _f32(_float32_from_bits(operand) * scale)

    def run(
        operand: int,
        expected_result: int,
        expected_lu: int,
        description: str,
        *,
        initial_lu: int = 0,
    ) -> None:
        actual = _execute_tmu_pcode(
            ops,
            {
                "R0H": operand,
                "STF_LU": initial_lu,
            },
        )
        expected = {"R0H": expected_result, "STF_LU": expected_lu}
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"

    run(_f32(1.0), product_bits(_f32(1.0)), 0, "ordinary positive conversion")
    run(_f32(-2.0), product_bits(_f32(-2.0)), 0, "ordinary negative conversion")
    run(
        _f32(6.0),
        product_bits(_f32(6.0)),
        1,
        "ordinary conversion preserves sticky LUF",
        initial_lu=1,
    )
    run(0x00000000, 0x00000000, 0, "positive zero")
    run(0x80000000, 0x00000000, 0, "negative zero is positive zero")
    run(0x00000001, 0x00000000, 0, "positive denormal is positive zero")
    run(0x80000001, 0x00000000, 0, "negative denormal is positive zero")
    run(0x7F800000, 0x7F800000, 0, "positive infinity")
    run(0xFF800000, 0xFF800000, 0, "negative infinity")
    run(0x7FC00001, 0x7F800000, 0, "positive NaN is positive infinity")
    run(0xFFC00001, 0xFF800000, 0, "negative NaN is negative infinity")
    run(0x00800000, 0x00000000, 1, "positive underflow flushes to zero")
    run(0x80800000, 0x00000000, 1, "negative underflow flushes to positive zero")


def check_cospuf32(ops: list) -> None:
    _no_internal_cfg(ops)
    userops = [op for op in ops if op.opcode == OpCode.CALLOTHER]
    assert len(userops) == 1, f"COSPUF32 must emit one cosine userop, got {len(userops)}"
    cosine = userops[0]
    assert cosine.output is not None and cosine.output.space.name == "unique"
    assert len(cosine.inputs) == 2 and _is_const(cosine.inputs[0], 3), (
        "COSPUF32 must call the declared cospu_f32 userop"
    )
    assert cosine.inputs[1].space.name == "unique"
    assert _depends_on_register(ops, cosine.inputs[1], "R0H"), (
        "COSPUF32 core must depend on the incoming aliased source"
    )

    truncates = [op for op in ops if op.opcode == OpCode.FLOAT_TRUNC]
    conversions = [op for op in ops if op.opcode == OpCode.FLOAT_INT2FLOAT]
    fractions = [op for op in ops if op.opcode == OpCode.FLOAT_SUB]
    assert len(truncates) == len(conversions) == len(fractions) == 1, (
        "COSPUF32 must form fraction(x) with trunc/int2float/sub"
    )
    assert _key(fractions[0].output) == _key(cosine.inputs[1])
    assert any(
        op.opcode == OpCode.INT_LESSEQUAL
        and any(_is_const(v, 0x2F000000) for v in op.inputs)
        for op in ops
    ), "COSPUF32 must implement the inclusive 2^-33 lower check"
    assert any(
        op.opcode == OpCode.INT_LESSEQUAL
        and any(_is_const(v, 0x4A800000) for v in op.inputs)
        for op in ops
    ), "COSPUF32 must implement the inclusive 2^22 upper check"
    assert any(_reg(op.output) == "R0H" for op in ops), (
        "COSPUF32 must commit the range-selected result"
    )

    stf_flags = {"STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"}
    flag_accesses = [
        (_reg(op.output), {_reg(value) for value in op.inputs})
        for op in ops
        if _reg(op.output) in stf_flags
        or any(_reg(value) in stf_flags for value in op.inputs)
    ]
    assert not flag_accesses, f"COSPUF32 must not access STF flags: {flag_accesses}"

    def run(operand: int, expected_result: int, description: str) -> None:
        actual = _execute_tmu_pcode(ops, {"R0H": operand})
        assert actual["R0H"] == expected_result, (
            f"{description}: actual=0x{actual['R0H']:08x} "
            f"expected=0x{expected_result:08x}"
        )

    run(0x00000000, 0x3F800000, "positive zero")
    run(0x80000000, 0x3F800000, "negative zero is positive zero")
    run(0x00000001, 0x3F800000, "positive denormal is positive zero")
    run(0x80000001, 0x3F800000, "negative denormal is positive zero")
    run(0x7F800000, 0x3F800000, "positive infinity is too big")
    run(0xFF800000, 0x3F800000, "negative infinity is too big")
    run(0x7FC00001, 0x3F800000, "positive NaN is positive infinity")
    run(0xFFC00001, 0x3F800000, "negative NaN is negative infinity")
    run(0x2F000000, 0x3F800000, "positive 2^-33 lower boundary")
    run(0xAF000000, 0x3F800000, "negative 2^-33 lower boundary")
    run(0x4A800000, 0x3F800000, "positive 2^22 upper boundary")
    run(0xCA800000, 0x3F800000, "negative 2^22 upper boundary")
    run(0x4A7FFFFF, 0x00000000, "largest in-range value uses fraction 0.75")
    run(_f32(0.25), 0x00000000, "quarter turn")
    run(_f32(-0.25), 0x00000000, "negative quarter turn")
    run(_f32(0.5), 0xBF800000, "half turn")
    run(_f32(-1.5), 0xBF800000, "negative periodic half turn")
    run(_f32(0.125), _f32(math.sqrt(0.5)), "ordinary eighth turn")


def check_sqrtf32(ops: list) -> None:
    _no_internal_cfg(ops)
    roots = [op for op in ops if op.opcode == OpCode.FLOAT_SQRT]
    assert len(roots) == 1, f"SQRTF32 must emit one FLOAT_SQRT, got {len(roots)}"
    root = roots[0]
    assert root.inputs[0].space.name == "unique", "SQRTF32 must snapshot its aliased source"
    assert _depends_on_register(ops, root.inputs[0], "R0H"), (
        "SQRTF32 root operand must depend on the incoming R0H"
    )
    assert any(_reg(op.output) == "R0H" for op in ops), "SQRTF32 must write R0H"

    stf_flags = {"STF_TF", "STF_ZI", "STF_NI", "STF_ZF", "STF_NF", "STF_LU", "STF_LV"}
    flag_reads = {
        _reg(value)
        for op in ops
        for value in op.inputs
        if _reg(value) in stf_flags
    }
    assert flag_reads <= {"STF_LV"}, (
        f"SQRTF32 may read only its sticky destination flag: {flag_reads}"
    )
    flag_writes = [op for op in ops if _reg(op.output) in stf_flags]
    assert {_reg(op.output) for op in flag_writes} == {"STF_LV"}, (
        f"unexpected SQRTF32 STF writes: {flag_writes}"
    )

    def run(
        operand: int,
        expected_result: int,
        expected_lv: int,
        description: str,
        *,
        initial_lv: int = 0,
    ) -> None:
        actual = _execute_tmu_pcode(
            ops,
            {
                "R0H": operand,
                "STF_LV": initial_lv,
            },
        )
        expected = {"R0H": expected_result, "STF_LV": expected_lv}
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"

    run(_f32(9.0), _f32(3.0), 0, "ordinary square root")
    run(
        _f32(2.0),
        _f32(math.sqrt(2.0)),
        1,
        "ordinary square root preserves sticky LVF",
        initial_lv=1,
    )
    run(0x00000000, 0x00000000, 0, "positive zero")
    run(0x80000000, 0x00000000, 0, "negative zero is positive zero")
    run(0x00000001, 0x00000000, 0, "positive denormal is positive zero")
    run(0x80000001, 0x00000000, 0, "negative denormal is positive zero")
    run(_f32(-4.0), 0x00000000, 1, "negative finite input returns zero")
    run(0xFF800000, 0x00000000, 1, "negative infinity returns zero")
    run(0x7F800000, 0x7F800000, 1, "positive infinity returns infinity")
    run(0x7FC00001, 0x7F800000, 1, "positive NaN is positive infinity")
    run(0xFFC00001, 0x00000000, 1, "negative NaN is negative infinity")


def check_divf32_aliased_numerator(ops: list) -> None:
    _no_internal_cfg(ops)
    divides = [op for op in ops if op.opcode == OpCode.FLOAT_DIV]
    assert len(divides) == 1, f"aliased DIVF32 must emit one FLOAT_DIV, got {len(divides)}"
    divide = divides[0]
    first_write = _find_index(ops, lambda op: _reg(op.output) == "R1H", "aliased DIVF32 result write")
    assert any(
        index < first_write and any(_reg(value) == "R1H" for value in op.inputs)
        for index, op in enumerate(ops)
    ), "aliased DIVF32 must snapshot its numerator before writeback"
    assert any(
        index < first_write and any(_reg(value) == "R0H" for value in op.inputs)
        for index, op in enumerate(ops)
    ), "aliased DIVF32 must snapshot its denominator before writeback"
    actual = _execute_tmu_pcode(
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


def _mov_acc_mext_expected(value: int, sxm: int, shift: int) -> dict[str, int]:
    value &= 0xFFFF
    extended = value
    if sxm and value & 0x8000:
        extended |= 0xFFFF0000
    result = (extended << shift) & 0xFFFFFFFF
    return {
        "ACC": result,
        "AL": result & 0xFFFF,
        "N": (result >> 31) & 1,
        "Z": int(result == 0),
    }


def _mov_acc_writes(ops: list):
    acc_write = _find(
        ops, lambda op: _reg(op.output) == "ACC", "complete MOV ACC destination write"
    )
    al_write = _find(
        ops, lambda op: _reg(op.output) == "AL", "explicit MOV ACC low-half write"
    )
    assert ops.index(acc_write) < ops.index(al_write), (acc_write, al_write)
    assert any(_depends_on_register(ops, value, "SXM") for value in acc_write.inputs), (
        "complete MOV ACC result must retain SXM dependence"
    )
    assert not _depends_on_register(ops, al_write.inputs[0], "SXM"), (
        "exact low half must not depend on SXM"
    )
    for flag in ("N", "Z"):
        flag_write = _find(
            ops, lambda op, flag=flag: _reg(op.output) == flag, f"MOV ACC {flag} write"
        )
        assert ops.index(al_write) < ops.index(flag_write)
        assert any(
            _depends_on_register(ops, value, "ACC") for value in flag_write.inputs
        ), f"MOV ACC {flag} must be computed from the complete result"
    return acc_write, al_write


def _check_mov_acc_mext_register(ops: list, shift: int, source: str = "AR6") -> None:
    _no_internal_cfg(ops)
    acc_write, al_write = _mov_acc_writes(ops)
    snapshots = [
        op
        for op in ops
        if op.opcode == OpCode.COPY
        and op.output is not None
        and op.output.space.name == "unique"
        and op.inputs
        and _reg(op.inputs[0]) == source
    ]
    assert len(snapshots) == 1, f"expected one {source} snapshot, got {len(snapshots)}"
    snapshot = snapshots[0]
    assert ops.index(snapshot) < ops.index(acc_write)
    assert _depends_on_varnode(ops, acc_write.inputs[0], snapshot.output)
    assert _depends_on_varnode(ops, al_write.inputs[0], snapshot.output)

    for value in (0x0000, 0x7FFF, 0x8000, 0xFFFF):
        for sxm in (0, 1):
            initial = {source: value, "SXM": sxm}
            expected = _mov_acc_mext_expected(value, sxm, shift)
            actual = _execute_integer_pcode(ops, initial)
            for name, wanted in expected.items():
                got = actual.get(name)
                assert got == wanted, (
                    f"MOV ACC,{source} << {shift}, value=0x{value:04x}, SXM={sxm}: "
                    f"{name}=0x{got:x} expected 0x{wanted:x}"
                )
            assert (actual["ACC"] >> 16) == (expected["ACC"] >> 16), (
                "AH overlap mismatch", value, sxm, shift, actual, expected
            )


def check_mov_acc_mext_shift0(ops: list) -> None:
    _check_mov_acc_mext_register(ops, 0)


def check_mov_acc_mext_shift1(ops: list) -> None:
    _check_mov_acc_mext_register(ops, 1)


def check_mov_acc_mext_shift8(ops: list) -> None:
    _check_mov_acc_mext_register(ops, 8)


def check_mov_acc_mext_shift15(ops: list) -> None:
    _check_mov_acc_mext_register(ops, 15)


def check_mov_acc_mext_alias_al(ops: list) -> None:
    _check_mov_acc_mext_register(ops, 8, "AL")
    snapshot = _find(
        ops,
        lambda op: op.opcode == OpCode.COPY
        and op.output is not None
        and op.output.space.name == "unique"
        and op.inputs
        and _reg(op.inputs[0]) == "AL",
        "old AL snapshot",
    )
    first_acc_overlap = _find_index(
        ops,
        lambda op: op.output is not None and _reg(op.output) in {"ACC", "AL"},
        "first ACC/AL write",
    )
    assert ops.index(snapshot) < first_acc_overlap, (
        "aliased AL source must be snapshotted before either overlapping destination write"
    )


def _check_mov_acc_mext_memory(ops: list, *, expect_xar6_update: bool = False) -> None:
    _no_internal_cfg(ops)
    acc_write, al_write = _mov_acc_writes(ops)
    loads = [op for op in ops if op.opcode == OpCode.LOAD and op.output.size == 2]
    assert len(loads) == 1, f"one architectural loc16 operand emitted {len(loads)} LOADs"
    load = loads[0]
    snapshots = [
        op
        for op in ops
        if op.opcode == OpCode.COPY
        and op.output is not None
        and op.output.space.name == "unique"
        and op.inputs
        and _key(op.inputs[0]) == _key(load.output)
    ]
    assert len(snapshots) == 1, f"memory source needs one reusable snapshot, got {len(snapshots)}"
    snapshot = snapshots[0]
    assert ops.index(load) < ops.index(snapshot) < ops.index(acc_write)
    assert _depends_on_varnode(ops, acc_write.inputs[0], snapshot.output)
    assert _depends_on_varnode(ops, al_write.inputs[0], snapshot.output)
    xar_writes = [op for op in ops if _reg(op.output) == "XAR6"]
    if expect_xar6_update:
        assert len(xar_writes) == 1, f"postincrement source updated XAR6 {len(xar_writes)} times"
        address_snapshots = [
            op
            for op in ops
            if op.opcode == OpCode.COPY
            and op.output is not None
            and op.output.space.name == "unique"
            and op.inputs
            and _reg(op.inputs[0]) == "XAR6"
            and _depends_on_varnode(ops, load.inputs[1], op.output)
        ]
        assert len(address_snapshots) == 1, (
            "postincrement must snapshot the old XAR6 once for the LOAD address"
        )
        assert ops.index(address_snapshots[0]) < ops.index(xar_writes[0])
        assert ops.index(address_snapshots[0]) < ops.index(load)
    else:
        assert not xar_writes, f"non-updating memory source unexpectedly changed XAR6: {xar_writes}"


def check_mov_acc_mext_memory(ops: list) -> None:
    _check_mov_acc_mext_memory(ops)


def check_mov_acc_mext_memory_postincrement(ops: list) -> None:
    _check_mov_acc_mext_memory(ops, expect_xar6_update=True)


def check_mov_acc_mext_dynamic(ops: list) -> None:
    _no_internal_cfg(ops)
    acc_write, al_write = _mov_acc_writes(ops)
    assert any(_depends_on_register(ops, value, "T") for value in acc_write.inputs)
    assert any(_depends_on_register(ops, value, "T") for value in al_write.inputs)
    snapshots = [
        op
        for op in ops
        if op.opcode == OpCode.COPY
        and op.output is not None
        and op.output.space.name == "unique"
        and op.inputs
        and _reg(op.inputs[0]) == "AR6"
    ]
    assert len(snapshots) == 1
    for shift in (0, 1, 8, 15):
        for value in (0x7FFF, 0x8000, 0xFFFF):
            for sxm in (0, 1):
                expected = _mov_acc_mext_expected(value, sxm, shift)
                actual = _execute_integer_pcode(
                    ops, {"AR6": value, "T": shift, "SXM": sxm}
                )
                for name, wanted in expected.items():
                    assert actual.get(name) == wanted, (shift, value, sxm, name, actual, expected)


def check_mov_acc_mext_setc_sxm(ops: list) -> None:
    _no_internal_cfg(ops)
    actual = _execute_integer_pcode(ops, {"AR6": 0x8000, "SXM": 0})
    expected = _mov_acc_mext_expected(0x8000, 1, 8)
    for name, wanted in {**expected, "SXM": 1}.items():
        assert actual.get(name) == wanted, (name, actual, expected)


def check_mov_acc_mext_clrc_sxm(ops: list) -> None:
    _no_internal_cfg(ops)
    actual = _execute_integer_pcode(ops, {"AR6": 0x8000, "SXM": 1})
    expected = _mov_acc_mext_expected(0x8000, 0, 8)
    for name, wanted in {**expected, "SXM": 0}.items():
        assert actual.get(name) == wanted, (name, actual, expected)



def check_abs_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    assert not any(_reg(op.output) == "TC" for op in ops), "ABS must not modify TC"
    vectors = (
        ({"ACC": 7, "OVM": 0, "V": 1, "C": 1}, {"ACC": 7, "V": 1, "C": 0, "N": 0, "Z": 0}, "positive preserves sticky V"),
        ({"ACC": 0, "OVM": 0, "V": 0, "C": 1}, {"ACC": 0, "V": 0, "C": 0, "N": 0, "Z": 1}, "zero"),
        ({"ACC": 0xFFFFFFF9, "OVM": 0, "V": 0, "C": 1}, {"ACC": 7, "V": 0, "C": 0, "N": 0, "Z": 0}, "ordinary negative"),
        ({"ACC": 0x80000000, "OVM": 0, "V": 0, "C": 1}, {"ACC": 0x80000000, "V": 1, "C": 0, "N": 1, "Z": 0}, "minimum wraps with OVM clear"),
        ({"ACC": 0x80000000, "OVM": 1, "V": 0, "C": 1}, {"ACC": 0x7FFFFFFF, "V": 1, "C": 0, "N": 0, "Z": 0}, "minimum saturates with OVM set"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_abstc_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 5, "OVM": 0, "V": 1, "C": 1, "TC": 1}, {"ACC": 5, "V": 1, "C": 0, "TC": 1, "N": 0, "Z": 0}, "positive leaves TC"),
        ({"ACC": 0xFFFFFFFB, "OVM": 0, "V": 0, "C": 1, "TC": 0}, {"ACC": 5, "V": 0, "C": 0, "TC": 1, "N": 0, "Z": 0}, "negative toggles TC"),
        ({"ACC": 0x80000000, "OVM": 0, "V": 0, "C": 1, "TC": 1}, {"ACC": 0x80000000, "V": 1, "C": 0, "TC": 0, "N": 1, "Z": 0}, "minimum wraps and toggles"),
        ({"ACC": 0x80000000, "OVM": 1, "V": 0, "C": 1, "TC": 0}, {"ACC": 0x7FFFFFFF, "V": 1, "C": 0, "TC": 1, "N": 0, "Z": 0}, "minimum saturates and toggles"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_neg_acc_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 5, "OVM": 0, "V": 1, "C": 1}, {"ACC": 0xFFFFFFFB, "V": 1, "C": 0, "N": 1, "Z": 0}, "ordinary negate"),
        ({"ACC": 0, "OVM": 0, "V": 0, "C": 0}, {"ACC": 0, "V": 0, "C": 1, "N": 0, "Z": 1}, "zero sets carry"),
        ({"ACC": 0x80000000, "OVM": 0, "V": 0, "C": 1}, {"ACC": 0x80000000, "V": 1, "C": 0, "N": 1, "Z": 0}, "minimum wraps"),
        ({"ACC": 0x80000000, "OVM": 1, "V": 0, "C": 1}, {"ACC": 0x7FFFFFFF, "V": 1, "C": 0, "N": 0, "Z": 0}, "minimum saturates"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_neg_ax_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    target = next((name for name in ("AL", "AH") if any(_reg(op.output) == name for op in ops)), None)
    assert target is not None, "NEG AX must write AL or AH"
    vectors = (
        ({target: 1, "V": 1, "C": 1}, {target: 0xFFFF, "V": 1, "C": 0, "N": 1, "Z": 0}, "ordinary 16-bit negate"),
        ({target: 0, "V": 0, "C": 0}, {target: 0, "V": 0, "C": 1, "N": 0, "Z": 1}, "16-bit zero"),
        ({target: 0x8000, "V": 0, "C": 1}, {target: 0x8000, "V": 1, "C": 0, "N": 1, "Z": 0}, "16-bit minimum"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_neg64_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0, "P": 1, "OVM": 0, "V": 1, "C": 1}, {"ACC": 0xFFFFFFFF, "P": 0xFFFFFFFF, "V": 1, "C": 0, "N": 1, "Z": 0}, "ordinary 64-bit negate"),
        ({"ACC": 0, "P": 0, "OVM": 0, "V": 0, "C": 0}, {"ACC": 0, "P": 0, "V": 0, "C": 1, "N": 0, "Z": 1}, "64-bit zero"),
        ({"ACC": 0x80000000, "P": 0, "OVM": 0, "V": 0, "C": 1}, {"ACC": 0x80000000, "P": 0, "V": 1, "C": 0, "N": 1, "Z": 0}, "64-bit minimum wraps"),
        ({"ACC": 0x80000000, "P": 0, "OVM": 1, "V": 0, "C": 1}, {"ACC": 0x7FFFFFFF, "P": 0xFFFFFFFF, "V": 1, "C": 0, "N": 0, "Z": 0}, "64-bit minimum saturates"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_negtc_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x80000001, "TC": 0, "OVM": 1, "V": 1, "C": 1}, {"ACC": 0x80000001, "TC": 0, "V": 1, "C": 1, "N": 1, "Z": 0}, "inactive preserves ACC C and V"),
        ({"ACC": 5, "TC": 1, "OVM": 0, "V": 1, "C": 1}, {"ACC": 0xFFFFFFFB, "TC": 1, "V": 1, "C": 0, "N": 1, "Z": 0}, "active ordinary negate"),
        ({"ACC": 0, "TC": 1, "OVM": 0, "V": 0, "C": 0}, {"ACC": 0, "TC": 1, "V": 0, "C": 1, "N": 0, "Z": 1}, "active zero"),
        ({"ACC": 0x80000000, "TC": 1, "OVM": 0, "V": 0, "C": 1}, {"ACC": 0x80000000, "TC": 1, "V": 1, "C": 0, "N": 1, "Z": 0}, "active minimum wraps"),
        ({"ACC": 0x80000000, "TC": 1, "OVM": 1, "V": 0, "C": 1}, {"ACC": 0x7FFFFFFF, "TC": 1, "V": 1, "C": 0, "N": 0, "Z": 0}, "active minimum saturates"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_lsrl_t_generic_state(ops: list) -> None:
    # Unknown T must retain the architectural count-zero split.
    branches = [op.opcode for op in ops if op.opcode in (OpCode.BRANCH, OpCode.CBRANCH)]
    assert branches == [OpCode.CBRANCH, OpCode.BRANCH], branches
    vectors = (
        ({"ACC": 0x80000001, "T": 0, "C": 1},
         {"ACC": 0x80000001, "C": 0, "N": 1, "Z": 0},
         "zero count"),
        ({"ACC": 0x80000001, "T": 32, "C": 1},
         {"ACC": 0x80000001, "C": 0, "N": 1, "Z": 0},
         "width count masks to zero"),
        ({"ACC": 0x80000001, "T": 1, "C": 0},
         {"ACC": 0x40000000, "C": 1, "N": 0, "Z": 0},
         "one-bit runtime count"),
    )
    for initial, expected, description in vectors:
        actual = _execute_tmu_pcode(ops, initial)
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"


def check_lsrl_t_proved_counts(_: list) -> None:
    vectors = (
        (1, {"ACC": 0x80000001, "C": 0},
         {"ACC": 0x40000000, "C": 1, "N": 0, "Z": 0},
         "count one"),
        (31, {"ACC": 0x80000000, "C": 0},
         {"ACC": 1, "C": 0, "N": 0, "Z": 0},
         "width minus one"),
        (31, {"ACC": 0x40000000, "C": 0},
         {"ACC": 0, "C": 1, "N": 0, "Z": 1},
         "largest legal count carry and zero"),
    )
    for count, initial, expected, description in vectors:
        ops = _translate_lsrl_count((0x5622,), count)
        _no_internal_cfg(ops)
        touched = {
            _reg(node)
            for op in ops
            for node in (*op.inputs, op.output)
            if node is not None and _reg(node) is not None
        }
        assert "T" not in touched, f"proved count {count} still reads T: {touched}"
        _assert_execution(ops, initial, expected, description)


def check_asr64_immediate_standalone(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x00000001, "P": 0x80018000, "C": 0},
         {"ACC": 0x00000000, "P": 0x00018001, "C": 1, "N": 0, "Z": 0},
         "positive value and final carry"),
        ({"ACC": 0xFFFFFFFF, "P": 0x00000000, "C": 0},
         {"ACC": 0xFFFFFFFF, "P": 0xFFFF0000, "C": 0, "N": 1, "Z": 0},
         "negative sign extension"),
        ({"ACC": 0x00000000, "P": 0x00000000, "C": 1},
         {"ACC": 0, "P": 0, "C": 0, "N": 0, "Z": 1},
         "zero"),
    )
    for initial, expected, description in vectors:
        actual = _execute_tmu_pcode(ops, initial)
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"


def check_asr64_pair_first_phase(_: list) -> None:
    ops = _translate_asr64_pair_phase((0x568F,), 1)
    assert ops == [], f"first paired ASR64 must be inert, got {ops}"


def check_asr64_pair_second_phase(_: list) -> None:
    ops = _translate_asr64_pair_phase((0x568F,), 2)
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x00000000, "P": 0x80000000, "C": 0},
         {"ACC": 0, "P": 0, "C": 1, "N": 0, "Z": 1},
         "zero extension with carry from original P bit 31"),
        ({"ACC": 0x00000001, "P": 0x00000000, "C": 1},
         {"ACC": 0, "P": 1, "C": 0, "N": 0, "Z": 0},
         "positive sign extension"),
        ({"ACC": 0x80000000, "P": 0x7FFFFFFF, "C": 0},
         {"ACC": 0xFFFFFFFF, "P": 0x80000000, "C": 0, "N": 1, "Z": 0},
         "negative minimum"),
        ({"ACC": 0xFFFFFFFF, "P": 0xFFFFFFFF, "C": 0},
         {"ACC": 0xFFFFFFFF, "P": 0xFFFFFFFF, "C": 1, "N": 1, "Z": 0},
         "all ones snapshots aliased sources"),
    )
    for initial, expected, description in vectors:
        actual = _execute_tmu_pcode(ops, initial)
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"


def check_lsl64_t_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x80000000, "P": 1, "T": 0, "C": 1}, {"ACC": 0x80000000, "P": 1, "C": 0, "N": 1, "Z": 0}, "zero shift clears carry"),
        ({"ACC": 0x80000000, "P": 1, "T": 1, "C": 0}, {"ACC": 0, "P": 2, "C": 1, "N": 0, "Z": 0}, "one-bit shift"),
        ({"ACC": 0, "P": 2, "T": 63, "C": 0}, {"ACC": 0, "P": 0, "C": 1, "N": 0, "Z": 1}, "maximum shift captures bit one"),
        ({"ACC": 0, "P": 1, "T": 63, "C": 1}, {"ACC": 0x80000000, "P": 0, "C": 0, "N": 1, "Z": 0}, "maximum shift retains low bit as sign"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_sfr_immediate_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x80000001, "SXM": 1, "C": 1}, {"ACC": 0xFC000000, "C": 0, "N": 1, "Z": 0}, "arithmetic right shift"),
        ({"ACC": 0x80000001, "SXM": 0, "C": 1}, {"ACC": 0x04000000, "C": 0, "N": 0, "Z": 0}, "logical right shift"),
        ({"ACC": 0x10, "SXM": 0, "C": 0}, {"ACC": 0, "C": 1, "N": 0, "Z": 1}, "last shifted bit becomes carry"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_sfr_t_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    vectors = (
        ({"ACC": 0x80000001, "T": 0, "SXM": 1, "C": 1}, {"ACC": 0x80000001, "C": 0, "N": 1, "Z": 0}, "zero shift clears carry and refreshes flags"),
        ({"ACC": 0x80000001, "T": 1, "SXM": 1, "C": 0}, {"ACC": 0xC0000000, "C": 1, "N": 1, "Z": 0}, "arithmetic variable shift"),
        ({"ACC": 0x00008000, "T": 15, "SXM": 0, "C": 0}, {"ACC": 1, "C": 0, "N": 0, "Z": 0}, "maximum logical variable shift"),
        ({"ACC": 0x00004000, "T": 15, "SXM": 0, "C": 0}, {"ACC": 0, "C": 1, "N": 0, "Z": 1}, "maximum variable shift carry"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_cmpf32_branch_free(ops: list) -> None:
    _no_internal_cfg(ops)
    writes = {_reg(op.output) for op in ops if _reg(op.output) is not None}
    assert writes & {"STF_ZF", "STF_NF"} == {"STF_ZF", "STF_NF"}
    assert not (writes & {"STF_LV", "STF_LU", "STF_ZI", "STF_NI", "STF_TF"})

    vectors = (
        (_f32(2.0), _f32(2.0), 1, 0, "ordinary equal"),
        (_f32(-2.0), _f32(1.0), 0, 1, "ordinary less"),
        (_f32(3.0), _f32(-1.0), 0, 0, "ordinary greater"),
        (0x80000000, 0x00000000, 1, 0, "negative zero equals positive zero"),
        (0x80000001, 0x00000000, 1, 0, "negative denormal equals positive zero"),
        (0x7FC00001, 0x7F800000, 1, 0, "positive NaN equals positive infinity"),
        (0xFFC00001, 0x7F800000, 1, 0, "negative NaN also becomes positive infinity"),
        (_f32(1.0), 0x7FC00001, 0, 1, "normal compares less than conditioned NaN"),
    )
    for lhs, rhs, zf, nf, description in vectors:
        actual = _execute_tmu_pcode(
            ops,
            {"R0H": lhs, "R1H": rhs, "STF_ZF": 0, "STF_NF": 0},
        )
        assert actual["STF_ZF"] == zf and actual["STF_NF"] == nf, (
            f"{description}: actual ZF/NF={actual['STF_ZF']}/{actual['STF_NF']} "
            f"expected={zf}/{nf}"
        )


def check_movst0_all_eventual_state(ops: list) -> None:
    _no_internal_cfg(ops)
    initial = {
        "V": 0, "N": 0, "Z": 0, "C": 0, "TC": 0,
        "STF_LV": 1, "STF_LU": 0, "STF_NF": 1, "STF_NI": 0,
        "STF_ZF": 0, "STF_ZI": 1, "STF_TF": 1,
    }
    expected = {
        "V": 1, "N": 1, "Z": 1, "C": 1, "TC": 1,
        "STF_LV": 0, "STF_LU": 0,
        "STF_NF": 1, "STF_NI": 0, "STF_ZF": 0, "STF_ZI": 1, "STF_TF": 1,
    }
    _assert_execution(ops, initial, expected, "all MOVST0 selections")


def check_movst0_lvf_selective(ops: list) -> None:
    _no_internal_cfg(ops)
    initial = {
        "V": 1, "N": 1, "Z": 1, "C": 1, "TC": 1,
        "STF_LV": 0, "STF_LU": 1, "STF_NF": 0, "STF_NI": 0,
        "STF_ZF": 0, "STF_ZI": 0, "STF_TF": 0,
    }
    expected = {
        "V": 0, "N": 1, "Z": 1, "C": 1, "TC": 1,
        "STF_LV": 0, "STF_LU": 1,
    }
    _assert_execution(ops, initial, expected, "selected LVF clears V and only LVF")


def check_movst0_ci_selective(ops: list) -> None:
    _no_internal_cfg(ops)
    for tf, expected_c in ((0, 0), (1, 1)):
        initial = {
            "V": 1, "N": 1, "Z": 1, "C": 1 - tf, "TC": 1,
            "STF_LV": 1, "STF_LU": 1, "STF_NF": 1, "STF_NI": 1,
            "STF_ZF": 1, "STF_ZI": 1, "STF_TF": tf,
        }
        expected = {
            "V": 1, "N": 1, "Z": 1, "C": expected_c, "TC": 1,
            "STF_LV": 1, "STF_LU": 1,
        }
        _assert_execution(ops, initial, expected, f"CI maps TF={tf} to C")


def check_movst0_tf_selective(ops: list) -> None:
    _no_internal_cfg(ops)
    for tf, expected_tc in ((0, 0), (1, 1)):
        initial = {
            "V": 1, "N": 1, "Z": 1, "C": 1, "TC": 1 - tf,
            "STF_LV": 1, "STF_LU": 1, "STF_NF": 1, "STF_NI": 1,
            "STF_ZF": 1, "STF_ZI": 1, "STF_TF": tf,
        }
        expected = {
            "V": 1, "N": 1, "Z": 1, "C": 1, "TC": expected_tc,
            "STF_LV": 1, "STF_LU": 1,
        }
        _assert_execution(ops, initial, expected, f"TF maps TF={tf} to TC")


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
            lambda op: op.opcode == OpCode.COPY
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


def _no_nonstandard_arithmetic_widths(ops: list) -> None:
    assert not any(
        (op.output is not None and op.output.size in (3, 5))
        or any(value.size in (3, 5) for value in op.inputs)
        for op in ops
    ), "targeted arithmetic must use only ordinary-width or one-bit varnodes"


def check_signed_acc_status(ops: list) -> None:
    _no_internal_cfg(ops)
    _no_nonstandard_arithmetic_widths(ops)
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
        and op.output.size == 4
        and op.inputs
        and _reg(op.inputs[0]) == "C",
        "ordinary-width carry-in extension",
    )
    carries = [op for op in ops if op.opcode == OpCode.INT_CARRY]
    signed_overflows = [op for op in ops if op.opcode == OpCode.INT_SCARRY]
    assert len(carries) == 2, "carry-in addition must combine both stage carries"
    assert len(signed_overflows) == 2, "carry-in addition must combine both stage overflows"
    c_write = _find(ops, lambda op: _reg(op.output) == "C", "eventual carry write")
    assert c_write.opcode == OpCode.BOOL_OR
    assert {_key(value) for value in c_write.inputs} == {_key(op.output) for op in carries}
    overflow = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_NOTEQUAL
        and {_key(value) for value in op.inputs} == {_key(op.output) for op in signed_overflows},
        "XOR-equivalent eventual signed overflow",
    )
    assert any(
        op.opcode == OpCode.INT_ADD
        and op.output.size == 4
        and _key(carry_extend.output) in {_key(value) for value in op.inputs}
        for op in ops
    ), "carry-in must participate in the wrapped 32-bit result"
    assert _key(_find(ops, lambda op: _reg(op.output) == "V", "sticky V").inputs[1]) == _key(overflow.output)


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
        and op.output.size == 4
        and op.inputs
        and _key(op.inputs[0]) == _key(borrow.output),
        "ordinary-width borrow extension",
    )
    borrows = [op for op in ops if op.opcode == OpCode.INT_LESS]
    signed_overflows = [op for op in ops if op.opcode == OpCode.INT_SBORROW]
    assert len(borrows) == 2, "borrow-in subtraction must combine both stage borrows"
    assert len(signed_overflows) == 2, "borrow-in subtraction must combine both stage overflows"
    c_write = _find(ops, lambda op: _reg(op.output) == "C", "eventual no-borrow write")
    assert c_write.opcode == OpCode.BOOL_NEGATE
    borrow_or = _find(
        ops,
        lambda op: op.opcode == OpCode.BOOL_OR
        and {_key(value) for value in op.inputs} == {_key(op.output) for op in borrows},
        "combined unsigned borrow",
    )
    assert _key(c_write.inputs[0]) == _key(borrow_or.output)
    overflow = _find(
        ops,
        lambda op: op.opcode == OpCode.INT_NOTEQUAL
        and {_key(value) for value in op.inputs} == {_key(op.output) for op in signed_overflows},
        "XOR-equivalent eventual signed overflow",
    )
    assert any(
        op.opcode == OpCode.INT_SUB
        and op.output.size == 4
        and _key(borrow_extend.output) in {_key(value) for value in op.inputs}
        for op in ops
    ), "borrow-in must participate in the wrapped 32-bit result"
    assert _key(_find(ops, lambda op: _reg(op.output) == "V", "sticky V").inputs[1]) == _key(overflow.output)


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
    _no_nonstandard_arithmetic_widths(ops)
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


def check_add_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    for initial, expected, description in (
        ({"ACC": 1, "AR6": 0xFFFF, "SXM": 1, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
         "ADD sign-extends the 16-bit source under SXM"),
        ({"ACC": 1, "AR6": 0xFFFF, "SXM": 0, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 0x10000, "C": 0, "V": 0, "OVC": 0, "N": 0, "Z": 0},
         "ADD zero-extends the 16-bit source when SXM is clear"),
    ):
        _assert_execution(ops, initial, expected, description)


def check_sub_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    for initial, expected, description in (
        ({"ACC": 0, "AR6": 0xFFFF, "SXM": 1, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 1, "C": 0, "V": 0, "OVC": 0, "N": 0, "Z": 0},
         "SUB sign-extends the 16-bit source under SXM"),
        ({"ACC": 0, "AR6": 0xFFFF, "SXM": 0, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 0xFFFF0001, "C": 0, "V": 0, "OVC": 0, "N": 1, "Z": 0},
         "SUB zero-extends the 16-bit source when SXM is clear"),
    ):
        _assert_execution(ops, initial, expected, description)


def check_addl_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    for initial, expected, description in (
        ({"ACC": 0xFFFFFFFF, "XAR6": 1, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1}, "ADDL carry and equality boundary"),
        ({"ACC": 0x7FFFFFFF, "XAR6": 1, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
         {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0}, "ADDL positive overflow"),
    ):
        _assert_execution(ops, initial, expected, description)


def check_addl_alias_safe(ops: list) -> None:
    check_signed_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0x40000000, "V": 0, "OVC": 0, "OVM": 0},
        {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
        "ADDL snapshots an aliased ACC source before writeback",
    )


def check_addcl_alias_safe(ops: list) -> None:
    check_signed_carry_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0x7FFFFFFF, "C": 1, "V": 0, "OVC": 0, "OVM": 0},
        {"ACC": 0xFFFFFFFF, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
        "ADDCL snapshots aliased ACC and includes incoming carry",
    )


def check_addl_pm_proved_ovm_zero(_: list) -> None:
    selected = _translate_ovm_zero((0x10AC,))
    generic = _translate((0x10AC,))
    _no_internal_cfg(selected)
    _no_nonstandard_arithmetic_widths(selected)

    touched = {
        _reg(node)
        for op in selected
        for node in (*op.inputs, op.output)
        if node is not None and _reg(node) is not None
    }
    assert {"ACC", "P", "PM"} <= touched, (
        f"proved OVM=0 ADDL ACC,P << PM lost architectural inputs: {touched}"
    )
    assert "OVM" not in touched, (
        f"proved OVM=0 ADDL ACC,P << PM still references OVM: {touched}"
    )
    assert not any(
        any(_is_const(value, constant) for value in op.inputs)
        for op in selected
        for constant in (0x7FFFFFFF, 0x80000000)
    ), "proved OVM=0 ADDL ACC,P << PM retained saturation constants"

    acc_write = _find(
        selected, lambda op: _reg(op.output) == "ACC", "selected ADDL ACC write"
    )
    assert any(_depends_on_register(selected, value, "P") for value in acc_write.inputs), (
        "selected ADDL result no longer depends on P"
    )
    assert any(_depends_on_register(selected, value, "PM") for value in acc_write.inputs), (
        "selected ADDL result no longer depends on PM"
    )
    left_shifts = [op for op in selected if op.opcode == OpCode.INT_LEFT]
    right_shifts = [op for op in selected if op.opcode == OpCode.INT_SRIGHT]
    assert left_shifts and right_shifts, (
        "selected ADDL must retain both logical-left and arithmetic-right PM paths"
    )
    assert any(
        _depends_on_register(selected, op.inputs[0], "P")
        and _depends_on_register(selected, op.inputs[1], "PM")
        for op in left_shifts
    ), "selected ADDL logical-left shift lost P/PM dependency"
    assert any(
        _depends_on_register(selected, op.inputs[0], "P")
        and _depends_on_register(selected, op.inputs[1], "PM")
        for op in right_shifts
    ), "selected ADDL arithmetic-right shift lost P/PM dependency"

    for register in ("ACC", "C", "V", "OVC", "N", "Z"):
        _find(
            selected,
            lambda op, register=register: _reg(op.output) == register,
            f"selected ADDL {register} write",
        )
    assert any(
        op.opcode == OpCode.INT_CARRY and _depends_on_register(selected, op.inputs[1], "P")
        for op in selected
    ), "selected ADDL lost wrapped-add carry"
    assert any(
        op.opcode == OpCode.INT_SCARRY and _depends_on_register(selected, op.inputs[1], "P")
        for op in selected
    ), "selected ADDL lost signed overflow"
    sticky_v = _find(
        selected,
        lambda op: op.opcode == OpCode.BOOL_OR and _reg(op.output) == "V",
        "selected sticky V update",
    )
    assert any(_reg(value) == "V" for value in sticky_v.inputs), (
        "selected ADDL V is no longer sticky"
    )
    ovc_write = _find(
        selected, lambda op: _reg(op.output) == "OVC", "selected signed OVC update"
    )
    assert ovc_write.opcode == OpCode.INT_OR
    assert any(
        op.opcode == OpCode.INT_AND and any(_is_const(value, 0x3F) for value in op.inputs)
        for op in selected
    ), "selected ADDL OVC update must wrap as a signed six-bit counter"

    vectors = (
        (
            {"ACC": 1, "P": 2, "PM": 1, "V": 1, "OVC": 7},
            {"ACC": 5, "C": 0, "V": 1, "OVC": 7, "N": 0, "Z": 0},
            "selected ADDL logical-left PM shift and sticky V",
        ),
        (
            {"ACC": 0xFFFFFFFF, "P": 1, "PM": 0, "V": 0, "OVC": 0},
            {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
            "selected ADDL zero PM shift with carry and zero",
        ),
        (
            {"ACC": 1, "P": 0xFFFFFFFE, "PM": 0xFF, "V": 0, "OVC": 0},
            {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
            "selected ADDL arithmetic-right negative PM shift",
        ),
        (
            {"ACC": 0x7FFFFFFF, "P": 1, "PM": 1, "V": 0, "OVC": 0},
            {"ACC": 0x80000001, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
            "selected ADDL positive overflow increments OVC",
        ),
        (
            {"ACC": 0x7FFFFFFF, "P": 1, "PM": 1, "V": 0, "OVC": 0x1F},
            {"ACC": 0x80000001, "C": 0, "V": 1, "OVC": 0xE0, "N": 1, "Z": 0},
            "selected ADDL positive OVC wrap 31 to -32",
        ),
        (
            {"ACC": 0x80000000, "P": 0xFFFFFFFE, "PM": 0xFF,
             "V": 0, "OVC": 0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0xFF, "N": 0, "Z": 0},
            "selected ADDL negative overflow decrements OVC",
        ),
        (
            {"ACC": 0x80000000, "P": 0xFFFFFFFE, "PM": 0xFF,
             "V": 0, "OVC": 0xE0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0x1F, "N": 0, "Z": 0},
            "selected ADDL negative OVC wrap -32 to 31",
        ),
    )
    compared_registers = ("ACC", "C", "V", "OVC", "N", "Z")
    for initial, expected, description in vectors:
        _assert_execution(selected, initial, expected, description)
        generic_initial = dict(initial)
        generic_initial["OVM"] = 0
        selected_state = _execute_integer_pcode(selected, initial)
        generic_state = _execute_integer_pcode(generic, generic_initial)
        mismatches = {
            register: (selected_state[register], generic_state[register])
            for register in compared_registers
            if selected_state[register] != generic_state[register]
        }
        assert not mismatches, f"{description} differs from generic OVM=0: {mismatches}"

    _assert_execution(
        generic,
        {"ACC": 0x7FFFFFFF, "P": 1, "PM": 1, "V": 0, "OVC": 7, "OVM": 1},
        {"ACC": 0x7FFFFFFF, "C": 0, "V": 1, "OVC": 7, "N": 0, "Z": 0},
        "generic ADDL ACC,P << PM retains OVM positive saturation",
    )


def check_addcl_proved_ovm_zero(_: list) -> None:
    selected = _translate_ovm_zero((0x5640, 0x00A6))
    generic = _translate((0x5640, 0x00A6))
    _no_internal_cfg(selected)
    _no_nonstandard_arithmetic_widths(selected)

    touched = {
        _reg(node)
        for op in selected
        for node in (*op.inputs, op.output)
        if node is not None and _reg(node) is not None
    }
    assert "OVM" not in touched, f"proved OVM=0 ADDCL still references OVM: {touched}"
    assert not any(
        any(_is_const(value, constant) for value in op.inputs)
        for op in selected
        for constant in (0x7FFFFFFF, 0x80000000)
    ), "proved OVM=0 ADDCL retained saturation constants"

    carry_extend = _find(
        selected,
        lambda op: op.opcode == OpCode.INT_ZEXT
        and op.output.size == 4
        and op.inputs
        and _reg(op.inputs[0]) == "C",
        "selected ADDCL incoming carry snapshot",
    )
    carries = [op for op in selected if op.opcode == OpCode.INT_CARRY]
    overflows = [op for op in selected if op.opcode == OpCode.INT_SCARRY]
    assert len(carries) == 2 and len(overflows) == 2, (
        "selected ADDCL must retain both addition stages"
    )
    c_write = _find(selected, lambda op: _reg(op.output) == "C", "selected C write")
    assert c_write.opcode == OpCode.BOOL_OR
    assert {_key(value) for value in c_write.inputs} == {
        _key(op.output) for op in carries
    }
    eventual_overflow = _find(
        selected,
        lambda op: op.opcode == OpCode.INT_NOTEQUAL
        and {_key(value) for value in op.inputs} == {
            _key(op.output) for op in overflows
        },
        "selected complete three-input signed overflow",
    )
    assert any(
        op.opcode == OpCode.INT_ADD
        and op.output.size == 4
        and _key(carry_extend.output) in {_key(value) for value in op.inputs}
        for op in selected
    ), "selected ADDCL omitted carry-in from wrapped ACC"
    assert _key(
        _find(selected, lambda op: _reg(op.output) == "V", "selected sticky V").inputs[1]
    ) == _key(eventual_overflow.output)
    for register in ("ACC", "C", "V", "OVC", "N", "Z"):
        _find(selected, lambda op, register=register: _reg(op.output) == register,
              f"selected ADDCL {register} write")
    assert any(
        op.opcode == OpCode.INT_AND and any(_is_const(value, 0x3F) for value in op.inputs)
        for op in selected
    ), "selected ADDCL OVC update must wrap as a signed six-bit counter"

    vectors = (
        (
            {"ACC": 1, "XAR6": 2, "C": 1, "V": 1, "OVC": 7},
            {"ACC": 4, "C": 0, "V": 1, "OVC": 7, "N": 0, "Z": 0},
            "selected ADDCL no overflow with carry-in and sticky V",
        ),
        (
            {"ACC": 0xFFFFFFFF, "XAR6": 0, "C": 1, "V": 0, "OVC": 0},
            {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
            "selected ADDCL second-stage carry-out and zero",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 0xFFFFFFFF, "C": 1,
             "V": 0, "OVC": 5},
            {"ACC": 0x80000000, "C": 1, "V": 0, "OVC": 5,
             "N": 1, "Z": 0},
            "selected ADDCL cancels two staged signed overflows",
        ),
        (
            {"ACC": 0x7FFFFFFF, "XAR6": 0, "C": 1, "V": 0, "OVC": 0},
            {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
            "selected ADDCL positive overflow increments OVC",
        ),
        (
            {"ACC": 0x7FFFFFFF, "XAR6": 0, "C": 1, "V": 0, "OVC": 0x1F},
            {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 0xE0, "N": 1, "Z": 0},
            "selected ADDCL positive OVC wrap 31 to -32",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0xFF, "N": 0, "Z": 0},
            "selected ADDCL negative overflow decrements OVC",
        ),
        (
            {"ACC": 0x80000000, "XAR6": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0xE0},
            {"ACC": 0x7FFFFFFF, "C": 1, "V": 1, "OVC": 0x1F, "N": 0, "Z": 0},
            "selected ADDCL negative OVC wrap -32 to 31",
        ),
    )
    compared_registers = ("ACC", "C", "V", "OVC", "N", "Z")
    for initial, expected, description in vectors:
        _assert_execution(selected, initial, expected, description)
        generic_initial = dict(initial)
        generic_initial["OVM"] = 0
        selected_state = _execute_integer_pcode(selected, initial)
        generic_state = _execute_integer_pcode(generic, generic_initial)
        mismatches = {
            register: (selected_state[register], generic_state[register])
            for register in compared_registers
            if selected_state[register] != generic_state[register]
        }
        assert not mismatches, f"{description} differs from generic OVM=0: {mismatches}"

    selected_alias = _translate_ovm_zero((0x5640, 0x00A9))
    generic_alias = _translate((0x5640, 0x00A9))
    alias_initial = {"ACC": 0x7FFFFFFF, "C": 1, "V": 0, "OVC": 0}
    alias_expected = {
        "ACC": 0xFFFFFFFF, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0
    }
    _assert_execution(
        selected_alias, alias_initial, alias_expected,
        "selected ADDCL snapshots an aliased ACC source",
    )
    generic_alias_initial = dict(alias_initial)
    generic_alias_initial["OVM"] = 0
    selected_alias_state = _execute_integer_pcode(selected_alias, alias_initial)
    generic_alias_state = _execute_integer_pcode(generic_alias, generic_alias_initial)
    assert all(
        selected_alias_state[register] == generic_alias_state[register]
        for register in compared_registers
    ), "selected aliased ADDCL differs from generic OVM=0"


def check_subbl_alias_safe(ops: list) -> None:
    check_signed_borrow_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0x12345678, "C": 0, "V": 0, "OVC": 0, "OVM": 0},
        {"ACC": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0, "N": 1, "Z": 0},
        "SUBBL snapshots aliased ACC before subtracting inverse carry",
    )


def check_addb_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0x7FFFFFFF, "V": 0, "OVC": 0, "OVM": 1},
        {"ACC": 0x7FFFFFFF, "C": 0, "V": 1, "OVC": 0, "N": 0, "Z": 0},
        "ADDB OVM saturation",
    )


def check_subb_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0, "V": 0, "OVC": 0, "OVM": 0},
        {"ACC": 0xFFFFFFFF, "C": 0, "V": 0, "OVC": 0, "N": 1, "Z": 0},
        "SUBB borrow boundary",
    )


def check_subb_switch_canonical(_: list) -> None:
    ops = _translate_switch_canonical((0x1901,))
    _no_internal_cfg(ops)
    assert any(op.opcode == OpCode.INT_SUB and _reg(op.output) == "ACC" for op in ops)
    touched = {
        _reg(node)
        for op in ops
        for node in (*op.inputs, op.output)
        if node is not None and _reg(node) is not None
    }
    assert "OVM" not in touched and "OVC" not in touched and "V" not in touched, touched
    actual = _execute_integer_pcode(
        ops,
        {"ACC": 3, "C": 0},
    )
    assert actual["ACC"] == 2 and actual["C"] == 1
    assert actual["N"] == 0 and actual["Z"] == 0


def check_addu_standard_width(ops: list) -> None:
    check_signed_acc_status(ops)
    _assert_execution(
        ops,
        {"ACC": 0x7FFFFFFF, "AR6": 1, "V": 0, "OVC": 0, "OVM": 0},
        {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
        "ADDU zero-extension and signed overflow",
    )


def check_addu_proved_ovm_zero(_: list) -> None:
    ops = _translate_ovm_zero((0x0DA6,))
    _no_internal_cfg(ops)
    _no_nonstandard_arithmetic_widths(ops)
    touched = {
        _reg(node)
        for op in ops
        for node in (*op.inputs, op.output)
        if node is not None and _reg(node) is not None
    }
    assert "OVM" not in touched, f"proved OVM=0 ADDU still references OVM: {touched}"
    assert not any(
        op.opcode == OpCode.INT_XOR and any(_is_const(value, 0x7FFFFFFF) for value in op.inputs)
        for op in ops
    ), "proved OVM=0 ADDU retained saturation-value construction"
    _find(ops, lambda op: _reg(op.output) == "OVC", "signed OVC update")
    _find(ops, lambda op: _reg(op.output) == "V", "sticky V update")
    vectors = (
        ({"ACC": 0xFFFFFFFF, "AR6": 1, "V": 0, "OVC": 0},
         {"ACC": 0, "C": 1, "V": 0, "OVC": 0, "N": 0, "Z": 1},
         "unsigned carry without signed overflow"),
        ({"ACC": 0x7FFFFFFF, "AR6": 1, "V": 0, "OVC": 0},
         {"ACC": 0x80000000, "C": 0, "V": 1, "OVC": 1, "N": 1, "Z": 0},
         "positive overflow increments OVC"),
        ({"ACC": 0x80000000, "AR6": 0xFFFF, "V": 1, "OVC": 0},
         {"ACC": 0x8000FFFF, "C": 0, "V": 1, "OVC": 0, "N": 1, "Z": 0},
         "zero-extended source and sticky V"),
    )
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_addul_acc(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="ACC")
    _check_addul_execution(ops, destination="ACC")


def check_addul_p(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="P")
    _check_addul_execution(ops, destination="P")


def check_subul_acc(ops: list) -> None:
    _check_unsigned_ovcu(ops, destination="ACC")
    _check_subul_execution(ops, destination="ACC")


def _check_subc_no_uint5(ops: list, divisor_register: str) -> None:
    assert not any(
        (op.output is not None and op.output.size == 5)
        or any(value.size == 5 for value in op.inputs)
        for op in ops
    ), "SUBCU(L) must not expose a five-byte temporary"

    _no_internal_cfg(ops)
    c_write = _find(ops, lambda op: _reg(op.output) == "C", "SUBCU(L) no-borrow flag")
    assert c_write.opcode == OpCode.COPY and len(c_write.inputs) == 1
    no_borrow = _definition_for(_unique_definitions(ops), c_write.inputs[0])
    assert no_borrow is not None and no_borrow.opcode == OpCode.INT_OR, (
        "C must combine the shift carry with the unsigned low-word comparison"
    )
    assert any(_depends_on_register(ops, value, "ACC") for value in no_borrow.inputs), (
        "SUBCU(L) C must depend on the incoming ACC value"
    )
    assert any(
        _depends_on_register(ops, value, divisor_register) for value in no_borrow.inputs
    ), "SUBCU(L) C must depend on the divisor comparison"
    _find(
        ops,
        lambda op: op.opcode == OpCode.INT_CARRY
        and len(op.inputs) == 2
        and all(_depends_on_register(ops, value, "ACC") for value in op.inputs),
        "ACC shift carry for the 33rd dividend bit",
    )
    assert not any(_reg(op.output) in {"V", "OVC"} for op in ops), (
        "SUBCU(L) must not modify V or OVC"
    )


def check_subcu(ops: list) -> None:
    _check_subc_no_uint5(ops, "AR6")
    vectors = (
        (
            {"ACC": 0x00008000, "AR6": 1, "C": 0, "N": 1, "Z": 1},
            {"ACC": 1, "C": 1, "N": 0, "Z": 0},
            "SUBCU exact equality subtracts and emits quotient bit one",
        ),
        (
            {"ACC": 0x00007FFF, "AR6": 1, "C": 1, "N": 1, "Z": 1},
            {"ACC": 0x0000FFFE, "C": 0, "N": 0, "Z": 0},
            "SUBCU borrow keeps the shifted dividend fragment",
        ),
        (
            {"ACC": 0x80000000, "AR6": 0xFFFF, "C": 0, "N": 1, "Z": 1},
            {"ACC": 0x00010001, "C": 1, "N": 0, "Z": 0},
            "SUBCU honors the 33rd shift bit as an unconditional no-borrow",
        ),
        (
            {"ACC": 0, "AR6": 1, "C": 1, "N": 1, "Z": 0},
            {"ACC": 0, "C": 0, "N": 0, "Z": 1},
            "SUBCU final N and Z reflect ACC while V and OVC remain untouched",
        ),
    )
    for initial, expected, description in vectors:
        actual = _execute_tmu_pcode(ops, initial)
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"

    for numerator, denominator in (
        (0, 123),
        (1, 1),
        (10, 5),
        (5, 3),
        (0xFFFF, 0xFFFF),
        (0xFFFF, 1),
    ):
        state = {
            "ACC": numerator,
            "AR6": denominator,
            "C": 0,
            "N": 0,
            "Z": 0,
        }
        for _ in range(16):
            state = _execute_tmu_pcode(ops, state)
        quotient = state["ACC"] & 0xFFFF
        remainder = state["ACC"] >> 16
        assert (quotient, remainder) == divmod(numerator, denominator), (
            "SUBCU restoring division failed for "
            f"{numerator}/{denominator}: quotient={quotient} remainder={remainder}"
        )


def check_subcul(ops: list) -> None:
    _check_subc_no_uint5(ops, "XAR6")
    vectors = (
        (
            {"ACC": 0, "P": 0x80000000, "XAR6": 1, "C": 0, "N": 1, "Z": 0},
            {"ACC": 0, "P": 1, "C": 1, "N": 0, "Z": 1},
            "SUBCUL exact equality subtracts and emits quotient bit one",
        ),
        (
            {"ACC": 0, "P": 0, "XAR6": 1, "C": 1, "N": 1, "Z": 0},
            {"ACC": 0, "P": 0, "C": 0, "N": 0, "Z": 1},
            "SUBCUL borrow shifts ACC:P without setting the quotient bit",
        ),
        (
            {"ACC": 0x80000000, "P": 0, "XAR6": 0xFFFFFFFF, "C": 0, "N": 1, "Z": 1},
            {"ACC": 1, "P": 1, "C": 1, "N": 0, "Z": 0},
            "SUBCUL honors the 33rd shift bit as an unconditional no-borrow",
        ),
        (
            {"ACC": 1, "P": 0, "XAR6": 1, "C": 0, "N": 1, "Z": 1},
            {"ACC": 1, "P": 1, "C": 1, "N": 0, "Z": 0},
            "SUBCUL low-word no-borrow subtracts the divisor",
        ),
    )
    for initial, expected, description in vectors:
        actual = _execute_tmu_pcode(ops, initial)
        mismatches = {
            name: (actual.get(name), value)
            for name, value in expected.items()
            if actual.get(name) != value
        }
        assert not mismatches, f"{description}: actual/expected {mismatches}"

    for numerator, denominator in (
        (0, 123),
        (1, 1),
        (10, 5),
        (5, 3),
        (0xFFFFFFFF, 0xFFFFFFFF),
        (0xFFFFFFFF, 1),
    ):
        state = {
            "ACC": 0,
            "P": numerator,
            "XAR6": denominator,
            "C": 0,
            "N": 0,
            "Z": 0,
        }
        for _ in range(32):
            state = _execute_tmu_pcode(ops, state)
        assert (state["P"], state["ACC"]) == divmod(numerator, denominator), (
            "SUBCUL restoring division failed for "
            f"{numerator}/{denominator}: quotient={state['P']} remainder={state['ACC']}"
        )



def check_subcul_div32_canonical(_: list) -> None:
    # RPT #31 followed by SUBCUL ACC,XAR6.  The analyzer-only context selects
    # a one-shot quotient/remainder summary and final repeat-counter state.
    ops = _translate_div32((0xF61F, 0x5617, 0x00A6))
    opcodes = [op.opcode for op in ops]
    assert opcodes.count(OpCode.INT_DIV) == 1, opcodes
    assert opcodes.count(OpCode.INT_REM) == 1, opcodes
    _no_internal_cfg(ops)

    written = {_reg(op.output) for op in ops if op.output is not None}
    for register in ("P", "ACC", "C", "N", "Z", "RPTC"):
        assert register in written, (register, written)
    assert "V" not in written and "OVC" not in written, written

    vectors = (
        (0x00000000, 1),
        (0x00000001, 1),
        (0x00000009, 10),
        (0x0000000A, 10),
        (0x0000000B, 10),
        (0x80000000, 3),
        (0xFFFFFFFF, 10),
        (0xFFFFFFFF, 0xFFFFFFFF),
    )
    for dividend, divisor in vectors:
        state = _execute_integer_pcode(
            ops,
            {
                "P": dividend,
                "ACC": 0,
                "XAR6": divisor,
                "C": 0,
                "N": 0,
                "Z": 0,
                "RPTC": 0xBEEF,
            },
        )
        quotient, remainder = divmod(dividend, divisor)
        assert state["P"] == quotient, (dividend, divisor, state)
        assert state["ACC"] == remainder, (dividend, divisor, state)
        assert state["C"] == (quotient & 1), (dividend, divisor, state)
        assert state["N"] == ((remainder >> 31) & 1), (dividend, divisor, state)
        assert state["Z"] == int(remainder == 0), (dividend, divisor, state)
        assert state["RPTC"] == 0, (dividend, divisor, state)

    ordinary = _translate((0xF61F, 0x5617, 0x00A6))
    ordinary_opcodes = [op.opcode for op in ordinary]
    assert OpCode.INT_DIV not in ordinary_opcodes and OpCode.INT_REM not in ordinary_opcodes
    assert OpCode.CBRANCH in ordinary_opcodes and OpCode.BRANCH in ordinary_opcodes

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


def _check_standard_compare(
    ops: list,
    left_register: str,
    right_register: str | None,
    vectors: tuple,
) -> None:
    _no_internal_cfg(ops)
    _no_nonstandard_arithmetic_widths(ops)
    n_write = _find(ops, lambda op: _reg(op.output) == "N", "infinite-precision N update")
    z_write = _find(ops, lambda op: _reg(op.output) == "Z", "compare equality update")
    c_write = _find(ops, lambda op: _reg(op.output) == "C", "unsigned no-borrow update")
    assert n_write.opcode == OpCode.INT_SLESS
    assert z_write.opcode == OpCode.INT_EQUAL
    assert c_write.opcode == OpCode.INT_LESSEQUAL
    assert _depends_on_register(ops, n_write.inputs[0], left_register)
    assert _depends_on_register(ops, z_write.inputs[0], left_register)
    assert _depends_on_register(ops, c_write.inputs[1], left_register)
    if right_register is not None:
        assert _depends_on_register(ops, n_write.inputs[1], right_register)
        assert _depends_on_register(ops, z_write.inputs[1], right_register)
        assert _depends_on_register(ops, c_write.inputs[0], right_register)
    assert not any(_reg(op.output) == "V" for op in ops), "compare must leave sticky V unchanged"
    for initial, expected, description in vectors:
        _assert_execution(ops, initial, expected, description)


def check_cmp_infinite_precision(ops: list) -> None:
    _check_standard_compare(
        ops,
        "AL",
        "AR6",
        (
            ({"AL": 0x8000, "AR6": 1}, {"N": 1, "Z": 0, "C": 1},
             "CMP signed-negative result can still be unsigned no-borrow"),
            ({"AL": 0, "AR6": 0xFFFF}, {"N": 0, "Z": 0, "C": 0},
             "CMP signed-positive result can still borrow unsigned"),
            ({"AL": 0x1234, "AR6": 0x1234}, {"N": 0, "Z": 1, "C": 1},
             "CMP equality"),
            ({"AL": 0x7FFF, "AR6": 0x8000}, {"N": 0, "Z": 0, "C": 0},
             "CMP signed high boundary differs from unsigned ordering"),
        ),
    )


def check_cmp_immediate_infinite_precision(ops: list) -> None:
    _check_standard_compare(
        ops,
        "AR6",
        None,
        (
            ({"AR6": 0xFFFF}, {"N": 1, "Z": 0, "C": 1},
             "CMP immediate signed-negative left with unsigned no-borrow"),
            ({"AR6": 0}, {"N": 1, "Z": 0, "C": 0},
             "CMP immediate ordinary borrow"),
            ({"AR6": 1}, {"N": 0, "Z": 1, "C": 1}, "CMP immediate equality"),
            ({"AR6": 0x7FFF}, {"N": 0, "Z": 0, "C": 1},
             "CMP immediate signed high boundary"),
        ),
    )


def check_cmpb_infinite_precision(ops: list) -> None:
    _check_standard_compare(
        ops,
        "AL",
        None,
        (
            ({"AL": 0x00FF}, {"N": 0, "Z": 1, "C": 1}, "CMPB equality"),
            ({"AL": 0}, {"N": 1, "Z": 0, "C": 0}, "CMPB unsigned low boundary"),
            ({"AL": 0x8000}, {"N": 1, "Z": 0, "C": 1},
             "CMPB signed-negative AL still has unsigned no-borrow"),
            ({"AL": 0x7FFF}, {"N": 0, "Z": 0, "C": 1}, "CMPB signed high boundary"),
        ),
    )


def check_cmpl_infinite_precision(ops: list) -> None:
    _check_standard_compare(
        ops,
        "ACC",
        "XAR6",
        (
            ({"ACC": 0x80000000, "XAR6": 1}, {"N": 1, "Z": 0, "C": 1},
             "CMPL infinite-precision signed negative with unsigned no-borrow"),
            ({"ACC": 0, "XAR6": 0xFFFFFFFF}, {"N": 0, "Z": 0, "C": 0},
             "CMPL signed positive result with unsigned borrow"),
            ({"ACC": 0x12345678, "XAR6": 0x12345678}, {"N": 0, "Z": 1, "C": 1},
             "CMPL equality"),
            ({"ACC": 0x7FFFFFFF, "XAR6": 0x80000000}, {"N": 0, "Z": 0, "C": 0},
             "CMPL signed high boundary differs from unsigned ordering"),
        ),
    )


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


def check_mov_p_generic_pmshift(ops: list) -> None:
    """Unproved MOV loc16,P must retain the complete architectural PM shift."""
    assert any(
        _reg(node) == "PM"
        for op in ops
        for node in (*op.inputs, op.output)
        if node is not None
    ), "ordinary MOV loc16,P must read decoded PM"
    assert any(op.opcode == OpCode.INT_LEFT for op in ops), (
        "ordinary MOV loc16,P lost its left-shift path"
    )
    assert any(op.opcode == OpCode.INT_SRIGHT for op in ops), (
        "ordinary MOV loc16,P lost its arithmetic-right path"
    )

    vectors = (
        (0, 0x89ABCDEF, 0xCDEF),
        (1, 0x89ABCDEF, 0x9BDE),
        (-1, 0x89ABCDEF, 0xE6F7),
    )
    for pm_value, product, expected in vectors:
        actual = _execute_integer_pcode(
            ops,
            {"PM": pm_value & 0xFF, "P": product, "AR0": 0x1234},
        )
        assert actual["AR0"] == expected, (pm_value, product, actual)


def check_mov_p_proved_noshift(_: list) -> None:
    """The context-selected form is exactly a low-half copy, including aliasing."""
    ops = _translate_pm_store_noshift((0x3FAA,))  # MOV PH,P
    assert not any(
        _reg(node) == "PM"
        for op in ops
        for node in (*op.inputs, op.output)
        if node is not None
    ), "proved no-shift MOV loc16,P still references PM"
    forbidden = {OpCode.INT_LEFT, OpCode.INT_RIGHT, OpCode.INT_SRIGHT, OpCode.INT_SLESS}
    assert not any(op.opcode in forbidden for op in ops), (
        "proved no-shift MOV loc16,P retained shift/sign P-Code"
    )
    assert any(_reg(op.output) == "PH" for op in ops), (
        "proved no-shift alias fixture must write PH"
    )
    assert any(any(_reg(node) == "PL" for node in op.inputs) for op in ops), (
        "proved no-shift alias fixture must read the old low product half"
    )
    actual = _execute_integer_pcode(
        ops,
        {"PL": 0xCDEF, "PH": 0x1234},
    )
    assert actual["PH"] == 0xCDEF, actual
    assert actual["PL"] == 0xCDEF, actual


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



def _execute_call_state(
    ops: list,
    initial: dict[str, int],
    memory: dict[int, int] | None = None,
) -> tuple[dict[str, int], dict[int, int], list[int]]:
    """Execute the finite register/memory subset used by call/return P-Code.

    C28x LOAD/STORE pointers are word indices in a wordsize=2 RAM space.  The
    memory dictionary is byte-addressed internally so 32-bit push/pop order is
    tested exactly rather than inferred from decompiler text.
    """
    cells: dict[tuple[str, int], int] = {}
    registers: dict[str, object] = {}
    mem = dict(memory or {})
    flows: list[int] = []

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
            value |= cells.get((node.space.name, node.offset + index), 0) << (8 * index)
        return value

    def write(node, value: int) -> None:
        value &= mask(node.size)
        for index in range(node.size):
            cells[(node.space.name, node.offset + index)] = (value >> (8 * index)) & 0xFF

    def load(word: int, size: int) -> int:
        byte = word * 2
        return sum(mem.get(byte + i, 0) << (8 * i) for i in range(size))

    def store(word: int, size: int, value: int) -> None:
        byte = word * 2
        for i in range(size):
            mem[byte + i] = (value >> (8 * i)) & 0xFF

    passthrough = {name: value for name, value in initial.items() if name not in registers}
    for name, value in initial.items():
        node = registers.get(name)
        if node is not None:
            write(node, value)

    for op in ops:
        args = [read(node) for node in op.inputs]
        code = op.opcode
        if code == OpCode.STORE:
            store(args[1], op.inputs[2].size, args[2])
            continue
        if code == OpCode.LOAD:
            write(op.output, load(args[1], op.output.size))
            continue
        if code in (OpCode.CALL, OpCode.CALLIND, OpCode.RETURN):
            flows.append(args[0])
            continue
        if op.output is None:
            raise AssertionError(f"unsupported call P-Code side effect {code.name}")
        if code in (OpCode.COPY, OpCode.INT_ZEXT):
            result = args[0]
        elif code == OpCode.INT_SEXT:
            result = signed(args[0], op.inputs[0].size)
        elif code == OpCode.INT_ADD:
            result = args[0] + args[1]
        elif code == OpCode.INT_SUB:
            result = args[0] - args[1]
        elif code == OpCode.INT_AND:
            result = args[0] & args[1]
        elif code == OpCode.INT_OR:
            result = args[0] | args[1]
        elif code == OpCode.INT_EQUAL:
            result = int(args[0] == args[1])
        elif code == OpCode.INT_SLESS:
            result = int(signed(args[0], op.inputs[0].size) <
                         signed(args[1], op.inputs[1].size))
        elif code == OpCode.SUBPIECE:
            result = args[0] >> (8 * args[1])
        else:
            raise AssertionError(f"unsupported call P-Code op {code.name}")
        write(op.output, result)

    final = dict(passthrough)
    final.update({name: read(node) for name, node in registers.items()})
    return (final, mem, flows)


def _memory_value(memory: dict[int, int], word: int, size: int) -> int:
    byte = word * 2
    return sum(memory.get(byte + i, 0) << (8 * i) for i in range(size))



def check_add_sp_large_frame(ops: list) -> None:
    assert not any(op.opcode == OpCode.INT_ZEXT for op in ops), \
        "large ADD SP must not reintroduce a 16-to-32-bit stack ZEXT"
    adds = [op for op in ops if op.opcode == OpCode.INT_ADD and _reg(op.output) == "SP"]
    assert len(adds) == 1, "ADD SP must commit one pointer-width delta"
    assert adds[0].output.size == 4 and all(node.size == 4 for node in adds[0].inputs), \
        "ADD SP carrier arithmetic must remain four bytes"
    assert all(node.size not in (3, 5) for op in ops for node in
               ([op.output] if op.output is not None else []) + list(op.inputs))
    state, _memory, _flow = _execute_call_state(ops, {"SP": 0x400, "N": 1, "Z": 1})
    assert state["SP"] == 0x60C and state["SP16"] == 0x60C
    assert state["N"] == 0 and state["Z"] == 0


def check_add_sp_large_negative_frame(ops: list) -> None:
    state, _memory, _flow = _execute_call_state(ops, {"SP": 0x800, "N": 1, "Z": 1})
    assert state["SP"] == 0x5F4 and state["SP16"] == 0x5F4
    assert state["N"] == 0 and state["Z"] == 0

def check_lcr_nested_state(_ops: list) -> None:
    first = _translate_at((0x7641, 0x7010), 0x200)
    second = _translate_at((0x7641, 0x7020), 0x300)
    ret = _translate_at((0x0006,), 0x400)
    state = {"SP": 0x400, "RPC": 0x111111}
    state, memory, flow1 = _execute_call_state(first, state)
    first_link = state["RPC"]
    assert state["SP"] == 0x402 and _memory_value(memory, 0x400, 4) == 0x111111
    state, memory, flow2 = _execute_call_state(second, state, memory)
    second_link = state["RPC"]
    assert state["SP"] == 0x404 and _memory_value(memory, 0x402, 4) == first_link
    state, memory, returns = _execute_call_state(ret, state, memory)
    assert returns == [second_link] and state["RPC"] == first_link and state["SP"] == 0x402
    state, memory, returns = _execute_call_state(ret, state, memory)
    assert returns == [first_link] and state["RPC"] == 0x111111 and state["SP"] == 0x400
    assert len(flow1) == len(flow2) == 1


def check_lcr_indirect_state(ops: list) -> None:
    assert any(op.opcode == OpCode.INT_AND and any(_is_const(v, 0x3FFFFF) for v in op.inputs)
               for op in ops), "indirect LCR must mask XAR0 to 22 bits"
    state, memory, flow = _execute_call_state(
        ops, {"SP": 0x500, "RPC": 0x123456, "XAR0": 0xFFC23456}
    )
    assert flow == [0x023456] and state["SP"] == 0x502 and state["RPC"] != 0x123456
    assert _memory_value(memory, 0x500, 4) == 0x123456


def check_lc_direct_state(ops: list) -> None:
    state, memory, flow = _execute_call_state(ops, {"SP": 0x600, "RPC": 0x234567})
    assert len(flow) == 1 and state["SP"] == 0x602 and state["RPC"] == 0x234567
    assert _memory_value(memory, 0x600, 4) != 0


def check_lret_state(ops: list) -> None:
    memory: dict[int, int] = {}
    value = 0x345678
    for i in range(4): memory[0x700 * 2 + i] = (value >> (8 * i)) & 0xFF
    state, _memory, flow = _execute_call_state(ops, {"SP": 0x702, "RPC": 0x111111}, memory)
    assert flow == [value] and state["SP"] == 0x700 and state["RPC"] == 0x111111


def check_lretr_state(ops: list) -> None:
    memory: dict[int, int] = {}
    older = 0x123456
    for i in range(4): memory[0x800 * 2 + i] = (older >> (8 * i)) & 0xFF
    current = 0x234567
    state, _memory, flow = _execute_call_state(ops, {"SP": 0x802, "RPC": current}, memory)
    assert flow == [current] and state["SP"] == 0x800 and state["RPC"] == older


def check_iret_stack_release(ops: list) -> None:
    sp_subs = [
        op for op in ops
        if op.opcode == OpCode.INT_SUB and _reg(op.output) == "SP"
    ]
    assert sum(any(_is_const(v, 2) for v in op.inputs) for op in sp_subs) == 7
    assert sum(any(_is_const(v, 1) for v in op.inputs) for op in sp_subs) == 1
    assert sum(op.opcode == OpCode.RETURN for op in ops) == 1


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
    Case("status mode: MOV ACC,AR6 shift 0 exposes exact low half", (0x85A6,), check_mov_acc_mext_shift0),
    Case("status mode: MOV ACC,AR6 shift 1 exposes exact low half", (0x5603, 0x01A6), check_mov_acc_mext_shift1),
    Case("status mode: MOV ACC,AR6 shift 8 exposes exact low half", (0x5603, 0x08A6), check_mov_acc_mext_shift8),
    Case("status mode: MOV ACC,AR6 shift 15 exposes exact low half", (0x5603, 0x0FA6), check_mov_acc_mext_shift15),
    Case("status mode: MOV ACC,AL snapshots an overlapping source", (0x5603, 0x08A9), check_mov_acc_mext_alias_al),
    Case("status mode: MOV ACC,memory shift 0 performs one LOAD", (0x85C6,), check_mov_acc_mext_memory),
    Case("status mode: MOV ACC,memory shift 1 performs one LOAD", (0x5603, 0x01C6), check_mov_acc_mext_memory),
    Case("status mode: MOV ACC,memory shift 8 performs one LOAD", (0x5603, 0x08C6), check_mov_acc_mext_memory),
    Case("status mode: MOV ACC,memory shift 15 performs one LOAD", (0x5603, 0x0FC6), check_mov_acc_mext_memory),
    Case("status mode: MOV ACC,*XAR6++ performs one LOAD and one update", (0x5603, 0x0886), check_mov_acc_mext_memory_postincrement),
    Case("status mode: MOV ACC,AR6 dynamic T remains exact", (0x5606, 0x00A6), check_mov_acc_mext_dynamic),
    Case("status mode: SETC SXM changes full MOV ACC result", (0x3B01, 0x5603, 0x08A6), check_mov_acc_mext_setc_sxm),
    Case("status mode: CLRC SXM changes full MOV ACC result", (0x2901, 0x5603, 0x08A6), check_mov_acc_mext_clrc_sxm),
    Case("SUBL models V, signed OVC, and OVM branch-free", (0x11AC,), check_signed_acc_status),
    Case("ADD uses ordinary widths and preserves SXM", (0x81A6,), check_add_standard_width),
    Case("SUB uses ordinary widths and preserves SXM", (0xAEA6,), check_sub_standard_width),
    Case("ADDL uses ordinary widths with exact signed status", (0x07A6,), check_addl_standard_width),
    Case("ADDL snapshots an aliased ACC source", (0x07A9,), check_addl_alias_safe),
    Case("ADDB uses ordinary widths with OVM saturation", (0x0901,), check_addb_standard_width),
    Case("SUBB uses ordinary widths with exact no-borrow", (0x1901,), check_subb_standard_width),
    Case("proved switch SUBB uses bounded no-borrow arithmetic", (0x1901,), check_subb_switch_canonical),
    Case("ADDU uses ordinary widths with zero-extended source", (0x0DA6,), check_addu_standard_width),
    Case("status mode: proved OVM-zero ADDU omits only saturation", (0x0DA6,), check_addu_proved_ovm_zero),
    Case(
        "status mode: proved OVM-zero ADDL ACC,P << PM preserves dynamic shift and signed status",
        (0x10AC,),
        check_addl_pm_proved_ovm_zero,
    ),
    Case(
        "status mode: proved OVM-zero ADDCL preserves carry and signed status",
        (0x5640, 0x00A6),
        check_addcl_proved_ovm_zero,
    ),
    Case("ADDCL includes carry in signed status", (0x5640, 0x00A6), check_addcl_status),
    Case("ADDCL snapshots an aliased ACC source", (0x5640, 0x00A9), check_addcl_alias_safe),
    Case("ADDCU includes carry in signed status", (0x0CAC,), check_addcu_status),
    Case("SUBBL preserves full-width inverse borrow", (0x5654, 0x00A6), check_subbl_status),
    Case("SUBBL snapshots an aliased ACC source", (0x5654, 0x00A9), check_subbl_alias_safe),
    Case("SBBU preserves full-width inverse borrow", (0x1DAC,), check_sbbu_status),
    Case("ADDUL ACC counts unsigned carry in OVCU", (0x5653, 0x00A6), check_addul_acc),
    Case("ADDUL P counts unsigned carry in OVCU", (0x5657, 0x00A6), check_addul_p),
    Case("SUBUL ACC counts unsigned borrow in OVCU", (0x5655, 0x00A6), check_subul_acc),
    Case("SUBUL P counts unsigned borrow in OVCU", (0x565D, 0x00A6), check_subul_p),
    Case("SUBCU models the unsigned 33-bit no-borrow step without uint5", (0x1FA6,), check_subcu),
    Case("SUBCUL models the unsigned 33-bit no-borrow step without uint5", (0x5617, 0x00A6), check_subcul),
    Case(
        "proved RPT #31 SUBCUL exposes unsigned quotient and remainder",
        (0xF61F, 0x5617, 0x00A6),
        check_subcul_div32_canonical,
    ),
    Case("CMP uses signed ordering for infinite-precision N", (0x54A6,), check_cmp_infinite_precision),
    Case("CMP immediate uses signed ordering and unsigned no-borrow", (0x1BA6, 0x0001), check_cmp_immediate_infinite_precision),
    Case("CMPB uses signed ordering and unsigned no-borrow", (0x52FF,), check_cmpb_infinite_precision),
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
    Case("ABS is branch-free and preserves complete eventual state", (0xFF56,), check_abs_eventual_state),
    Case("ABSTC is branch-free and toggles TC from the original sign", (0x565F,), check_abstc_eventual_state),
    Case("NEG ACC is branch-free with sticky V and OVM saturation", (0xFF54,), check_neg_acc_eventual_state),
    Case("NEG AL is branch-free with 16-bit minimum behavior", (0xFF5C,), check_neg_ax_eventual_state),
    Case("NEG AH is branch-free with 16-bit minimum behavior", (0xFF5D,), check_neg_ax_eventual_state),
    Case("NEG64 is branch-free with complete eventual state", (0x5658,), check_neg64_eventual_state),
    Case("NEGTC is branch-free and preserves inactive C", (0x5632,), check_negtc_eventual_state),
    Case("LSRL ACC,T retains exact unknown and masked-zero semantics", (0x5622,), check_lsrl_t_generic_state),
    Case("proved LSRL ACC,T uses direct exact nonzero shifts", (0x5622,), check_lsrl_t_proved_counts),
    Case("paired ASR64 control retains standalone #16 semantics", (0x568f,), check_asr64_immediate_standalone),
    Case("paired ASR64 first phase is semantically inert", (0x568f,), check_asr64_pair_first_phase),
    Case("paired ASR64 second phase publishes exact net shift by 32", (0x568f,), check_asr64_pair_second_phase),
    Case("LSL64 ACC:P,T is branch-free for zero and maximum shifts", (0x5652,), check_lsl64_t_eventual_state),
    Case("SFR ACC,#5 is branch-free with SXM and carry", (0xFF44,), check_sfr_immediate_eventual_state),
    Case("SFR ACC,T is branch-free for zero and maximum shifts", (0xFF51,), check_sfr_t_eventual_state),
    Case("CMPF32 conditions special values without internal CFG", (0xE694, 0x0008), check_cmpf32_branch_free),
    Case("MOVST0 all flags commits selected eventual state", (0xADFF,), check_movst0_all_eventual_state),
    Case("MOVST0 LVF preserves unselected state", (0xAD01,), check_movst0_lvf_selective),
    Case("MOVST0 CI maps TF to C without internal CFG", (0xAD40,), check_movst0_ci_selective),
    Case("MOVST0 TF maps TF to TC without internal CFG", (0xAD80,), check_movst0_tf_selective),
    Case("DIVF32 conditions inputs and models result/LUF/LVF", (0xE274, 0x0058), check_divf32),
    Case("SQRTF32 conditions input and models result/LVF", (0xE277, 0x0000), check_sqrtf32),
    Case("DIV2PIF32 uses exact scale and models result/LUF", (0xE271, 0x0000), check_div2pif32),
    Case("COSPUF32 applies range conditions and computes periodic cosine", (0xE279, 0x0000), check_cospuf32),
    Case(
        "DIVF32 snapshots an aliased numerator before writeback",
        (0xE274, 0x0009),
        check_divf32_aliased_numerator,
    ),
    Case("MAXF32||MOV32 snapshots aliased source", (0xE69C, 0x0088), check_max_snapshot),
    Case(
        "ordinary MOV loc16,P retains generic PM shift semantics",
        (0x3FA0,),
        check_mov_p_generic_pmshift,
    ),
    Case(
        "proved decoded-PM-zero MOV loc16,P is an alias-safe low-half copy",
        (0x3FAA,),
        check_mov_p_proved_noshift,
    ),
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
    Case("ADD SP large positive frame uses pointer-width carrier", (0x08AD, 0x020C), check_add_sp_large_frame),
    Case("ADD SP large negative frame uses pointer-width carrier", (0x08AD, 0xFDF4), check_add_sp_large_negative_frame),
    Case("LCR direct preserves nested RPC/SP state", (0x7641, 0x7010), check_lcr_nested_state),
    Case("LCR indirect masks its target and saves RPC", (0x3E60,), check_lcr_indirect_state),
    Case("LC direct uses the stack without changing RPC", (0x0081, 0x700F), check_lc_direct_state),
    Case("LRET pops a direct-call return without changing RPC", (0x7614,), check_lret_state),
    Case("LRETR returns through current RPC then restores the older RPC", (0x0006,), check_lretr_state),
    Case("IRET releases seven context pairs and the alignment word", (0x7602,), check_iret_stack_release),
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
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--status-mode-only",
        action="store_true",
        help="run only the focused SXM/OVM status-mode semantic cases",
    )
    parser.add_argument(
        "--shift-idiom-only",
        action="store_true",
        help="run only the focused proved-shift semantic cases",
    )
    args = parser.parse_args()

    selected = CASES
    if args.status_mode_only:
        selected = tuple(
            case
            for case in CASES
            if case.name.startswith("status mode:")
            or case.name in {
                "ADD uses ordinary widths and preserves SXM",
                "SUB uses ordinary widths and preserves SXM",
                "ADDU uses ordinary widths with zero-extended source",
                "ordinary MOV loc16,P retains generic PM shift semantics",
                "proved decoded-PM-zero MOV loc16,P is an alias-safe low-half copy",
            }
        )
    elif args.shift_idiom_only:
        selected = tuple(
            case
            for case in CASES
            if case.name in {
                "LSRL ACC,T retains exact unknown and masked-zero semantics",
                "proved LSRL ACC,T uses direct exact nonzero shifts",
            }
            or case.name.startswith("paired ASR64")
        )

    failures: list[str] = []
    for case in selected:
        try:
            case.check(_translate(case.words))
        except Exception as exc:  # Keep the full suite running to report all regressions.
            failures.append(f"FAIL {case.name}: {exc}")
        else:
            print(f"PASS {case.name}")

    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1

    print(f"SEMANTIC_TESTS={len(selected)}")
    print("INTERNAL_CFG_VECTOR_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
