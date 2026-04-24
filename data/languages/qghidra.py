#!/usr/bin/env python3
"""Read hex words from stdin, disassemble with Ghidra/pypcode, print result."""

import sys
import struct
from pypcode import Context

ctx = Context("tms320c28:LE:32:default")

data = b"".join(struct.pack("<H", int(w, 16)) for line in sys.stdin for w in line.split() if w)

if not data:
    sys.exit(0)

dx = ctx.disassemble(data)
for ins in dx.instructions:
    ib = bytearray(data[ins.addr.offset : ins.addr.offset + ins.length])
    for i in range(0, len(ib), 2):
        ib[i], ib[i + 1] = ib[i + 1], ib[i]
    words = ib.hex(" ", 2).split()
    wo = ins.addr.offset // 2
    print(f"{wo:08x}   {words[0]}   {ins.mnem.upper():13}{ins.body}")
    for i, word in enumerate(words[1:], start=1):
        print(f"{wo+i:08x}   {word}")
