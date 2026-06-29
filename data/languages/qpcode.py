#!/usr/bin/env python3
"""Read hex words from stdin, translate to P-Code via pypcode, print result."""

import struct
import sys

from pypcode import Context, OpCode

ctx = Context("tms320c28:LE:32:default")
ctx.setVariableDefault("ctx_objmode", 1)


def _fmt(v):
    name = v.space.name
    off = v.offset
    sz = v.size
    if name == "const":
        return f"#{off:#x}"
    if name == "register":
        reg = v.getRegisterName()
        return reg if reg else f"reg[{off:#x}:{sz}]"
    if name == "unique":
        return f"tmp[{off:#x}:{sz}]"
    return f"{name}[{off:#x}:{sz}]"


data = b"".join(struct.pack("<H", int(w, 16)) for line in sys.stdin for w in line.split() if w)

if not data:
    sys.exit(0)

dx = ctx.disassemble(data)
ins_map = {ins.addr.offset: ins for ins in dx.instructions}

tx = ctx.translate(data)

cur_ins = None
for op in tx.ops:
    if op.opcode == OpCode.IMARK:
        byte_off = op.inputs[0].offset
        cur_ins = ins_map.get(byte_off)
        if cur_ins:
            ib = bytearray(data[cur_ins.addr.offset : cur_ins.addr.offset + cur_ins.length])
            for i in range(0, len(ib), 2):
                ib[i], ib[i + 1] = ib[i + 1], ib[i]
            words = ib.hex(" ", 2).split()
            wo = cur_ins.addr.offset // 2
            print(f"{wo:08x}   {words[0]}   {cur_ins.mnem.upper():13}{cur_ins.body}")
        else:
            print(f"  ; (unknown @ byte {byte_off:#x})")
        continue

    out = op.output
    ins = op.inputs
    out_str = _fmt(out) if out else None
    ins_str = ", ".join(_fmt(v) for v in ins)

    if out_str:
        print(f"           {out_str} = {op.opcode.name}({ins_str})")
    else:
        print(f"           {op.opcode.name}({ins_str})")
