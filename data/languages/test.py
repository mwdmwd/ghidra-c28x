#!/usr/bin/env python3
from pypcode import Context, PcodePrettyPrinter

ctx = Context("tms320c28:LE:32:default")

dx = ctx.disassemble(b"\x01\x00\x56\xff\x5f\x56\x1a\xff\x34\x12\x23\x56\xab\x00\xab\x81\xab\x85\x04\x56\xa1\x09\x21\x94\x21\x95\x21\x72\x21\x73")
for ins in dx.instructions:
    print(f"{ins.addr.offset:#x}/{ins.length}: {ins.mnem} {ins.body}")
