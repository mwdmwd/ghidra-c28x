#!/usr/bin/env python3
"""Focused semantic regressions for high-value C28x P-Code behavior.

These tests intentionally inspect P-Code structure rather than instruction text.
They protect control-flow ordering, parallel source snapshotting, status updates,
and effective-address side effects.
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


_CTX = Context("tms320c28:LE:32:default")
_CTX.setVariableDefault("ctx_objmode", 1)


def _translate(words: Iterable[int]) -> list:
    data = b"".join(struct.pack("<H", word) for word in words)
    return [op for op in _CTX.translate(data).ops if op.opcode != OpCode.IMARK]


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
