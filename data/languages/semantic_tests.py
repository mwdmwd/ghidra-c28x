#!/usr/bin/env python3
"""Focused semantic regressions for high-value C28x P-Code behavior.

These tests inspect P-Code rather than instruction text. Assertions protect
control-flow ordering, parallel source snapshotting, status updates, and
effective-address side effects.
"""

from __future__ import annotations

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
    Case("MAXF32||MOV32 snapshots aliased source", (0xE69C, 0x0088), check_max_snapshot),
    Case("PUSH ST0 encodes decoded PM and six-bit OVC", (0x7618,), check_push_st0_encoding),
    Case("POP ST0 decodes PM and sign-extends OVC", (0x7613,), check_pop_st0_decoding),
    Case("B OV snapshots then clears V", (0xFFEB, 0x0001), check_branch_v_clear),
    Case("BF NOV snapshots then clears V", (0x56CA, 0x0001), check_branch_v_clear),
    Case("SB OV snapshots then clears V", (0x6B02,), check_branch_v_clear),
    Case("conditional MOVB OV snapshots then clears V", (0x56BB, 0x0511), check_branch_v_clear),
    Case("XRETC OV snapshots then clears V", (0x56FB,), check_branch_v_clear),
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
