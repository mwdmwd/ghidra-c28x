#!/usr/bin/env python3
"""Executable regressions for C28x repeated program-space transfer shadows.

The C28x RPT wrapper normally re-enters one instruction's P-Code.  PREAD,
PWRITE, XPREAD, and XPWRITE are architecturally different: on a repeated
transfer, the program-space pointer is copied to an instruction-local shadow
which advances once per transfer while XAR7 or AL remains architectural state.
This test executes the finite P-Code subset used by those schedules and checks
both final state and the loop's structural data dependencies.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Iterable

from pypcode import Context, OpCode


def _translate(words: Iterable[int], *, base_address: int = 0) -> list:
    ctx = Context("tms320c28:LE:32:default")
    ctx.setVariableDefault("ctx_objmode", 1)
    ctx.setVariableDefault("ctx_amode", 0)
    ctx.setVariableDefault("ctx_page0", 0)
    data = b"".join(struct.pack("<H", word) for word in words)
    return list(ctx.translate(data, base_address=base_address).ops)


def _reg(node) -> str | None:
    if node is None or node.space.name != "register":
        return None
    return node.getRegisterName()


def _same(left, right) -> bool:
    return (
        left.space.name == right.space.name
        and left.offset == right.offset
        and left.size == right.size
    )


def _is_const(node, value: int) -> bool:
    return node.space.name == "const" and node.offset == value


def _mask(size: int) -> int:
    return (1 << (size * 8)) - 1


def _signed(value: int, size: int) -> int:
    sign = 1 << (size * 8 - 1)
    value &= _mask(size)
    return value - (1 << (size * 8)) if value & sign else value


@dataclass
class Trace:
    cells: dict[tuple[str, int], int]
    registers: dict[str, object]
    memory: dict[int, int]
    loads: list[tuple[int, int, int, int]]
    stores: list[tuple[int, int, int, int]]
    steps: int

    def read(self, node) -> int:
        if node.space.name == "const":
            return node.offset & _mask(node.size)
        return sum(
            self.cells.get((node.space.name, node.offset + index), 0) << (8 * index)
            for index in range(node.size)
        )

    def register(self, name: str) -> int:
        node = self.registers.get(name)
        if node is None:
            raise AssertionError(f"register {name} was absent from translated P-Code")
        return self.read(node)

    def word(self, address: int) -> int:
        byte = address * 2
        return self.memory.get(byte, 0) | (self.memory.get(byte + 1, 0) << 8)


def _execute(
    ops: list,
    initial_registers: dict[str, int],
    initial_words: dict[int, int] | None = None,
) -> Trace:
    """Execute the finite integer/memory/control-flow subset in these fixtures."""

    cells: dict[tuple[str, int], int] = {}
    registers: dict[str, object] = {}
    memory: dict[int, int] = {}
    loads: list[tuple[int, int, int, int]] = []
    stores: list[tuple[int, int, int, int]] = []

    for op in ops:
        for node in (*op.inputs, op.output):
            name = _reg(node)
            if name is not None:
                registers.setdefault(name, node)

    def read(node) -> int:
        if node.space.name == "const":
            return node.offset & _mask(node.size)
        return sum(
            cells.get((node.space.name, node.offset + index), 0) << (8 * index)
            for index in range(node.size)
        )

    def write(node, value: int) -> None:
        value &= _mask(node.size)
        for index in range(node.size):
            cells[(node.space.name, node.offset + index)] = (
                value >> (8 * index)
            ) & 0xFF

    def load(word: int, size: int) -> int:
        byte = word * 2
        return sum(memory.get(byte + index, 0) << (8 * index) for index in range(size))

    def store(word: int, size: int, value: int) -> None:
        byte = word * 2
        for index in range(size):
            memory[byte + index] = (value >> (8 * index)) & 0xFF

    for word, value in (initial_words or {}).items():
        store(word, 2, value)

    for name, value in initial_registers.items():
        node = registers.get(name)
        if node is None:
            raise AssertionError(f"initial register {name} absent from translated P-Code")
        write(node, value)

    # External RPT loop branches use byte-domain instruction addresses.  Map
    # every IMARK start and the final instruction end to executable P-Code.
    address_to_pc: dict[int, int] = {}
    for index, op in enumerate(ops):
        if op.opcode == OpCode.IMARK:
            mark = op.inputs[0]
            address_to_pc[mark.offset] = index + 1
            address_to_pc[mark.offset + mark.size] = index + 1
    if ops:
        final_marks = [op.inputs[0] for op in ops if op.opcode == OpCode.IMARK]
        if final_marks:
            final = final_marks[-1]
            address_to_pc[final.offset + final.size] = len(ops)

    pc = 0
    steps = 0
    while pc < len(ops):
        steps += 1
        if steps > 200_000:
            raise AssertionError("repeat-transfer P-Code exceeded execution step limit")

        op = ops[pc]
        code = op.opcode
        if code == OpCode.IMARK:
            pc += 1
            continue

        if code in (OpCode.BRANCH, OpCode.CBRANCH):
            take = True
            if code == OpCode.CBRANCH:
                take = bool(read(op.inputs[1]))
            if not take:
                pc += 1
                continue

            target = op.inputs[0]
            if target.space.name == "const":
                pc += _signed(target.offset, target.size)
            elif target.space.name == "ram":
                try:
                    pc = address_to_pc[target.offset]
                except KeyError as exc:
                    raise AssertionError(
                        f"unmapped external P-Code branch target 0x{target.offset:x}"
                    ) from exc
            else:
                raise AssertionError(
                    f"unsupported branch target space {target.space.name}"
                )
            continue

        args = [read(node) for node in op.inputs]
        if code == OpCode.LOAD:
            pointer = args[1]
            value = load(pointer, op.output.size)
            loads.append((pc, pointer, op.output.size, value))
            write(op.output, value)
            pc += 1
            continue
        if code == OpCode.STORE:
            pointer = args[1]
            value = args[2]
            stores.append((pc, pointer, op.inputs[2].size, value))
            store(pointer, op.inputs[2].size, value)
            pc += 1
            continue
        if op.output is None:
            raise AssertionError(f"unsupported side-effect P-Code op {code.name}")

        if code in (OpCode.COPY, OpCode.INT_ZEXT):
            result = args[0]
        elif code == OpCode.INT_SEXT:
            result = _signed(args[0], op.inputs[0].size)
        elif code == OpCode.INT_ADD:
            result = args[0] + args[1]
        elif code == OpCode.INT_SUB:
            result = args[0] - args[1]
        elif code == OpCode.INT_MULT:
            result = args[0] * args[1]
        elif code == OpCode.INT_AND:
            result = args[0] & args[1]
        elif code == OpCode.INT_OR:
            result = args[0] | args[1]
        elif code == OpCode.INT_XOR:
            result = args[0] ^ args[1]
        elif code == OpCode.INT_NEGATE:
            result = ~args[0]
        elif code == OpCode.INT_2COMP:
            result = -args[0]
        elif code == OpCode.INT_LEFT:
            result = args[0] << args[1]
        elif code == OpCode.INT_RIGHT:
            result = args[0] >> args[1]
        elif code == OpCode.INT_SRIGHT:
            result = _signed(args[0], op.inputs[0].size) >> args[1]
        elif code == OpCode.INT_EQUAL:
            result = int(args[0] == args[1])
        elif code == OpCode.INT_NOTEQUAL:
            result = int(args[0] != args[1])
        elif code == OpCode.INT_LESS:
            result = int(args[0] < args[1])
        elif code == OpCode.INT_LESSEQUAL:
            result = int(args[0] <= args[1])
        elif code == OpCode.INT_SLESS:
            result = int(
                _signed(args[0], op.inputs[0].size)
                < _signed(args[1], op.inputs[1].size)
            )
        elif code == OpCode.INT_SLESSEQUAL:
            result = int(
                _signed(args[0], op.inputs[0].size)
                <= _signed(args[1], op.inputs[1].size)
            )
        elif code == OpCode.BOOL_AND:
            result = int(bool(args[0]) and bool(args[1]))
        elif code == OpCode.BOOL_OR:
            result = int(bool(args[0]) or bool(args[1]))
        elif code == OpCode.BOOL_XOR:
            result = int(bool(args[0]) ^ bool(args[1]))
        elif code == OpCode.BOOL_NEGATE:
            result = int(not bool(args[0]))
        elif code == OpCode.SUBPIECE:
            result = args[0] >> (args[1] * 8)
        elif code == OpCode.PIECE:
            result = (args[0] << (op.inputs[1].size * 8)) | args[1]
        else:
            raise AssertionError(f"unsupported repeat-transfer P-Code op {code.name}")
        write(op.output, result)
        pc += 1

    return Trace(cells, registers, memory, loads, stores, steps)


def _instruction_ops(ops: list, ordinal: int = 1) -> tuple[int, int]:
    marks = [index for index, op in enumerate(ops) if op.opcode == OpCode.IMARK]
    if ordinal >= len(marks):
        raise AssertionError(f"missing instruction ordinal {ordinal}")
    start = marks[ordinal] + 1
    end = marks[ordinal + 1] if ordinal + 1 < len(marks) else len(ops)
    return start, end


@dataclass(frozen=True)
class ShadowShape:
    node: object
    program_op_index: int
    loop_target_index: int


def _check_shadow_shape(
    ops: list,
    *,
    program_opcode: OpCode,
    architectural_pointer: str | None,
) -> ShadowShape:
    """Prove one repeated transfer has an internal, advancing unique shadow."""

    start, end = _instruction_ops(ops)
    segment = list(enumerate(ops[start:end], start=start))

    backwards = []
    for index, op in segment:
        if op.opcode != OpCode.BRANCH or op.inputs[0].space.name != "const":
            continue
        delta = _signed(op.inputs[0].offset, op.inputs[0].size)
        if delta < 0:
            backwards.append((index, index + delta))
    assert len(backwards) == 1, f"expected one internal repeat back-edge, got {backwards}"
    branch_index, loop_target = backwards[0]
    assert start <= loop_target < branch_index
    assert not any(
        op.opcode in (OpCode.BRANCH, OpCode.CBRANCH)
        and op.inputs[0].space.name == "ram"
        for _, op in segment
    ), "transfer repeat must not rebuild the instruction through an external branch"

    program_ops = [
        (index, op)
        for index, op in segment
        if op.opcode == program_opcode
        and op.inputs[1].space.name == "unique"
        and op.inputs[1].size == 4
    ]
    assert len(program_ops) == 1, (
        f"expected one shadow-addressed {program_opcode.name}, got {program_ops}"
    )
    program_index, program_op = program_ops[0]
    shadow = program_op.inputs[1]

    increments = [
        (index, op)
        for index, op in segment
        if op.opcode == OpCode.INT_ADD
        and op.output is not None
        and _same(op.output, shadow)
        and any(_same(node, shadow) for node in op.inputs)
        and any(_is_const(node, 1) for node in op.inputs)
    ]
    assert len(increments) == 1, f"shadow needs one +1 progression, got {increments}"
    assert program_index < increments[0][0] < branch_index

    definitions = [
        (index, op)
        for index, op in segment
        if op.output is not None and _same(op.output, shadow)
    ]
    initializers = [(index, op) for index, op in definitions if index < loop_target]
    assert len(initializers) == 1, (
        f"shadow must be initialized once before the loop, got {initializers}"
    )
    assert loop_target <= program_index, "program access must lie inside repeat loop"

    if architectural_pointer is not None:
        init = initializers[0][1]
        assert any(
            _reg(node) == architectural_pointer
            or (
                node.space.name == "unique"
                and any(
                    prior.output is not None
                    and _same(prior.output, node)
                    and any(_reg(source) == architectural_pointer for source in prior.inputs)
                    for _, prior in segment
                    if prior.opcode in (OpCode.COPY, OpCode.INT_ZEXT)
                )
            )
            for node in init.inputs
        ), f"shadow initializer must depend on {architectural_pointer}"

    return ShadowShape(shadow, program_index, loop_target)


def _assert_words(trace: Trace, start: int, expected: list[int]) -> None:
    actual = [trace.word(start + index) for index in range(len(expected))]
    assert actual == expected, (
        f"memory mismatch at 0x{start:x}: expected {expected!r}, got {actual!r}"
    )


def _program_events(trace: Trace, op_index: int, *, store: bool) -> list[tuple[int, int]]:
    events = trace.stores if store else trace.loads
    return [(address, value) for index, address, size, value in events if index == op_index and size == 2]


def _rpt(count: int) -> int:
    assert 0 <= count <= 0xFF
    return 0xF600 | count


def _ascending(start: int, count: int) -> dict[int, int]:
    return {start + index: (0x1100 + 0x31 * index) & 0xFFFF for index in range(count)}


def test_pread_counts_and_locations() -> int:
    vectors = 0
    for count in (0, 1, 4):
        iterations = count + 1
        source = 0x1200
        destination = 0x2200
        source_words = _ascending(source, iterations)
        ops = _translate((_rpt(count), 0x2484))
        shape = _check_shadow_shape(
            ops, program_opcode=OpCode.LOAD, architectural_pointer="XAR7"
        )
        trace = _execute(
            ops,
            {"XAR4": destination, "XAR7": source, "RPTC": 0xFFFF},
            source_words,
        )
        expected = [source_words[source + index] for index in range(iterations)]
        _assert_words(trace, destination, expected)
        assert trace.register("XAR4") == destination + iterations
        assert trace.register("XAR7") == source
        assert trace.register("RPTC") == 0
        assert trace.read(shape.node) == source + iterations
        assert _program_events(trace, shape.program_op_index, store=False) == [
            (source + index, expected[index]) for index in range(iterations)
        ]
        vectors += 1

    # Non-postincrement loc16 must still execute once per transfer: the last
    # program word wins at one fixed data-memory destination.
    count = 3
    iterations = count + 1
    source = 0x1300
    source_words = _ascending(source, iterations)
    ops = _translate((_rpt(count), 0x2420))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.LOAD, architectural_pointer="XAR7"
    )
    trace = _execute(ops, {"XAR7": source, "RPTC": 0x1234}, source_words)
    assert trace.word(0x20) == source_words[source + iterations - 1]
    assert trace.register("XAR7") == source
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == source + iterations
    assert [address for address, _ in _program_events(trace, shape.program_op_index, store=False)] == [
        source + index for index in range(iterations)
    ]
    vectors += 1

    # Alias-shaped destination: loc16 predecrements architectural XAR7, while
    # the program read continues upward through the original shadow.
    source = 0x3102
    words = {
        source: 0xA111,
        source + 1: 0xB222,
        source - 1: 0xDEAD,
        source - 2: 0xBEEF,
    }
    ops = _translate((_rpt(1), 0x248F))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.LOAD, architectural_pointer="XAR7"
    )
    trace = _execute(ops, {"XAR7": source, "RPTC": 9}, words)
    assert trace.word(source - 1) == 0xA111
    assert trace.word(source - 2) == 0xB222
    assert trace.register("XAR7") == source - 2
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == source + 2
    vectors += 1

    # The unique shadow must die with the instruction.  A following ordinary
    # PREAD observes unchanged XAR7, not the exhausted shadow.
    source = 0x1400
    destination = 0x2400
    words = {source: 0x1111, source + 1: 0x2222}
    ops = _translate((_rpt(1), 0x2484, 0x2421))
    trace = _execute(
        ops,
        {"XAR4": destination, "XAR7": source, "RPTC": 7},
        words,
    )
    _assert_words(trace, destination, [0x1111, 0x2222])
    assert trace.word(0x21) == 0x1111
    assert trace.register("XAR7") == source
    vectors += 1
    return vectors


def test_pwrite_and_alias() -> int:
    vectors = 0
    source = 0x2500
    destination = 0x3500
    count = 4
    iterations = count + 1
    source_words = _ascending(source, iterations)
    ops = _translate((_rpt(count), 0x2684))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.STORE, architectural_pointer="XAR7"
    )
    trace = _execute(
        ops,
        {"XAR4": source, "XAR7": destination, "RPTC": 0xFFFF},
        source_words,
    )
    expected = [source_words[source + index] for index in range(iterations)]
    _assert_words(trace, destination, expected)
    assert trace.register("XAR4") == source + iterations
    assert trace.register("XAR7") == destination
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == destination + iterations
    assert _program_events(trace, shape.program_op_index, store=True) == [
        (destination + index, expected[index]) for index in range(iterations)
    ]
    vectors += 1

    # Alias-shaped source: architectural XAR7 walks downward through loc16;
    # the hidden program destination walks upward from the original value.
    destination = 0x3602
    words = {destination - 1: 0xC333, destination - 2: 0xD444}
    ops = _translate((_rpt(1), 0x268F))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.STORE, architectural_pointer="XAR7"
    )
    trace = _execute(ops, {"XAR7": destination, "RPTC": 5}, words)
    assert trace.word(destination) == 0xC333
    assert trace.word(destination + 1) == 0xD444
    assert trace.register("XAR7") == destination - 2
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == destination + 2
    vectors += 1
    return vectors


def test_xpread_forms() -> int:
    vectors = 0

    # Immediate high-page source.
    source = 0x3F1234
    destination = 0x2700
    words = _ascending(source, 3)
    ops = _translate((_rpt(2), 0xAC84, 0x1234))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.LOAD, architectural_pointer=None
    )
    trace = _execute(ops, {"XAR4": destination, "RPTC": 6}, words)
    _assert_words(trace, destination, [words[source + index] for index in range(3)])
    assert trace.register("XAR4") == destination + 3
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == source + 3
    vectors += 1

    # AL source remains architectural state for a non-aliasing destination.
    al = 0x0200
    source = 0x3F0000 | al
    destination = 0x2800
    words = _ascending(source, 3)
    ops = _translate((_rpt(2), 0x563C, 0x0084))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.LOAD, architectural_pointer="AL"
    )
    trace = _execute(
        ops,
        {"AL": al, "XAR4": destination, "RPTC": 0xABCD},
        words,
    )
    _assert_words(trace, destination, [words[source + index] for index in range(3)])
    assert trace.register("AL") == al
    assert trace.register("XAR4") == destination + 3
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == source + 3
    vectors += 1

    # Alias-shaped @AL destination proves that the program pointer was copied
    # before the first result overwrote AL.  Final N/Z come from the last word.
    al = 0x0300
    source = 0x3F0000 | al
    words = {source: 0x1111, source + 1: 0x8001, 0x3F1111: 0x7777}
    ops = _translate((_rpt(1), 0x563C, 0x00A9))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.LOAD, architectural_pointer="AL"
    )
    trace = _execute(
        ops,
        {"AL": al, "N": 0, "Z": 1},
        words,
    )
    assert trace.register("AL") == 0x8001
    assert trace.register("N") == 1 and trace.register("Z") == 0
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == source + 2
    assert [address for address, _ in _program_events(trace, shape.program_op_index, store=False)] == [
        source,
        source + 1,
    ]
    vectors += 1
    return vectors


def test_xpwrite_forms() -> int:
    vectors = 0

    al = 0x0400
    destination = 0x3F0000 | al
    source = 0x2900
    source_words = _ascending(source, 3)
    ops = _translate((_rpt(2), 0x563D, 0x0084))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.STORE, architectural_pointer="AL"
    )
    trace = _execute(
        ops,
        {"AL": al, "XAR4": source, "RPTC": 0xFFFF},
        source_words,
    )
    _assert_words(
        trace, destination, [source_words[source + index] for index in range(3)]
    )
    assert trace.register("AL") == al
    assert trace.register("XAR4") == source + 3
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == destination + 3
    vectors += 1

    # AL can also be the loc16 source.  Program-side progression must not
    # modify it, so the same source value is written to both destinations.
    al = 0x0500
    destination = 0x3F0000 | al
    ops = _translate((_rpt(1), 0x563D, 0x00A9))
    shape = _check_shadow_shape(
        ops, program_opcode=OpCode.STORE, architectural_pointer="AL"
    )
    trace = _execute(ops, {"AL": al, "RPTC": 3})
    _assert_words(trace, destination, [al, al])
    assert trace.register("AL") == al
    assert trace.register("RPTC") == 0
    assert trace.read(shape.node) == destination + 2
    vectors += 1
    return vectors


def test_ordinary_transfers() -> int:
    vectors = 0

    # One ordinary vector for every documented family/form guards the
    # non-repeat path while the specialized RPT constructors evolve.
    source = 0x1600
    destination = 0x2600
    ops = _translate((0x2484,))
    assert not any(_reg(op.output) == "RPTC" for op in ops)
    trace = _execute(
        ops,
        {"XAR4": destination, "XAR7": source},
        {source: 0x1234},
    )
    assert trace.word(destination) == 0x1234
    assert trace.register("XAR4") == destination + 1
    assert trace.register("XAR7") == source
    vectors += 1

    source = 0x2610
    destination = 0x3610
    ops = _translate((0x2684,))
    assert not any(_reg(op.output) == "RPTC" for op in ops)
    trace = _execute(
        ops,
        {"XAR4": source, "XAR7": destination},
        {source: 0x2345},
    )
    assert trace.word(destination) == 0x2345
    assert trace.register("XAR4") == source + 1
    assert trace.register("XAR7") == destination
    vectors += 1

    source = 0x3F1234
    destination = 0x2620
    ops = _translate((0xAC84, 0x1234))
    assert not any(_reg(op.output) == "RPTC" for op in ops)
    trace = _execute(
        ops,
        {"XAR4": destination},
        {source: 0x3456},
    )
    assert trace.word(destination) == 0x3456
    assert trace.register("XAR4") == destination + 1
    vectors += 1

    al = 0x0600
    source = 0x3F0000 | al
    destination = 0x2630
    ops = _translate((0x563C, 0x0084))
    assert not any(_reg(op.output) == "RPTC" for op in ops)
    trace = _execute(
        ops,
        {"AL": al, "XAR4": destination},
        {source: 0x4567},
    )
    assert trace.word(destination) == 0x4567
    assert trace.register("AL") == al
    assert trace.register("XAR4") == destination + 1
    vectors += 1

    al = 0x0700
    destination = 0x3F0000 | al
    source = 0x2640
    ops = _translate((0x563D, 0x0084))
    assert not any(_reg(op.output) == "RPTC" for op in ops)
    trace = _execute(
        ops,
        {"AL": al, "XAR4": source},
        {source: 0x5678},
    )
    assert trace.word(destination) == 0x5678
    assert trace.register("AL") == al
    assert trace.register("XAR4") == source + 1
    vectors += 1
    return vectors


def test_ordinary_repeated_near_miss() -> int:
    """Keep unrelated repeated instructions on the generic RPT wrapper."""

    count = 4
    iterations = count + 1
    raw = (_rpt(count), 0x2B84)
    destination = 0x4200
    initial = {
        destination + index: 0xA000 + index for index in range(iterations)
    }
    ops = _translate(raw)
    second_start, second_end = _instruction_ops(ops)
    segment = ops[second_start:second_end]
    assert not any(
        op.output is not None
        and op.output.space.name == "unique"
        and any(_reg(node) in ("XAR7", "AL") for node in op.inputs)
        for op in segment
    ), "ordinary repeated MOV must not acquire a program-transfer shadow"
    assert any(
        op.opcode == OpCode.BRANCH and op.inputs[0].space.name == "ram"
        for op in segment
    ), "ordinary repeated MOV should remain on the generic RPT path"
    trace = _execute(
        ops,
        {"XAR4": destination, "RPTC": 0xFFFF},
        initial,
    )
    _assert_words(trace, destination, [0] * iterations)
    assert trace.register("XAR4") == destination + iterations
    assert trace.register("RPTC") == 0
    zero_stores = [event for event in trace.stores if event[2] == 2 and event[3] == 0]
    assert len(zero_stores) == iterations, (
        f"expected {iterations} zero stores, got {len(zero_stores)}"
    )
    return 1


def main() -> int:
    tests = (
        ("PREAD RPT counts, fixed loc16, aliases, and shadow lifetime", test_pread_counts_and_locations),
        ("PWRITE source progression and XAR7 alias priority", test_pwrite_and_alias),
        ("XPREAD immediate, AL, and AL-destination alias forms", test_xpread_forms),
        ("XPWRITE AL destination and AL-source alias forms", test_xpwrite_forms),
        ("ordinary PREAD/PWRITE/XPREAD/XPWRITE controls", test_ordinary_transfers),
        ("unrelated repeated-MOV near miss", test_ordinary_repeated_near_miss),
    )

    vectors = 0
    for name, test in tests:
        count = test()
        vectors += count
        print(f"PASS {name} ({count} vectors)")

    print(f"REPEAT_TRANSFER_VECTORS={vectors}")
    print("REPEAT_TRANSFER_STRUCTURAL_PCODE=PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
