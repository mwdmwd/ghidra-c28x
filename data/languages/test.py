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
    mnem = ins.mnem.upper()
    body = ins.body
    if mnem in (
        "B",
        "BANZ",
        "BF",
        "SB",
        "SBF",
    ):
        args = [a.strip() for a in body.split(",")]
        for i, arg in enumerate(args):
            try:
                args[i] = str(int(arg, 0) - wordOffset)
            except Exception as e:
                pass
        body = ", ".join(args)
    print(f"{wordOffset:08x}   {words[0]}   {mnem:13}{body}")
    for i, word in enumerate(words[1:], start=1):
        print(f"{wordOffset + i:08x}   {word}")
