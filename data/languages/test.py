#!/usr/bin/env python3
from pypcode import Context, PcodePrettyPrinter

ctx = Context("tms320c28:LE:32:default")

dx = ctx.disassemble(b"\x01\x00\x56\xff\x5f\x56\x1a\xff\x34\x12")
for ins in dx.instructions:
    print(f"{ins.addr.offset:#x}/{ins.length}: {ins.mnem} {ins.body}")
