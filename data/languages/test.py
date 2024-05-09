#!/usr/bin/env python3
from pypcode import Context, PcodePrettyPrinter

ctx = Context("tms320c28:LE:32:default")

t = b"\x01\x00\x56\xff\x5f\x56\x1a\xff\x34\x12\x23\x56\xab\x00\xab\x81\xab\x85\x04\x56\xa1\x09\x21\x94\x21\x95\x21\x72\x21\x73"
with open("test.bin", "wb") as f:
    f.write(t)

dx = ctx.disassemble(t)
for ins in dx.instructions:
    ib = bytearray(t[ins.addr.offset : ins.addr.offset + ins.length])
    for i in range(0, len(ib), 2):
        ib[i], ib[i + 1] = ib[i + 1], ib[i]

    words = ib.hex(" ", 2).split()
    #print(f"{ins.addr.offset:#x}/{ins.length}: {words[0]} {ins.mnem} {ins.body}")
    wordOffset = ins.addr.offset // 2
    print(f"{wordOffset:08x}   {words[0]}   {ins.mnem.upper():13}{ins.body}")
    for i, word in enumerate(words[1:], start=1):
        print(f"{wordOffset + i:08x}   {word}")
