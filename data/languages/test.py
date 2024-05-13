#!/usr/bin/env python3
import re

from pypcode import Context, PcodePrettyPrinter

ctx = Context("tms320c28:LE:32:default")

with open("test.bin", "rb") as f:
    t = f.read()

SHIFT = re.compile(r"((?:<<|>>)\s*#)(0x[0-9a-fA-F]+)")


def dehex_shifts(b):
    return SHIFT.sub(lambda m: m.group(1) + str(int(m.group(2), 16)), b)


dx = ctx.disassemble(t)
for ins in dx.instructions:
    ib = bytearray(t[ins.addr.offset : ins.addr.offset + ins.length])
    for i in range(0, len(ib), 2):
        ib[i], ib[i + 1] = ib[i + 1], ib[i]

    words = ib.hex(" ", 2).split()
    # print(f"{ins.addr.offset:#x}/{ins.length}: {words[0]} {ins.mnem} {ins.body}")
    wordOffset = ins.addr.offset // 2
    print(f"{wordOffset:08x}   {words[0]}   {ins.mnem.upper():13}{ins.body}")
    for i, word in enumerate(words[1:], start=1):
        print(f"{wordOffset + i:08x}   {word}")
