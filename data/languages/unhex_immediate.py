#!/usr/bin/env python3
import sys
import re


HEX_IMMEDIATE = re.compile(r"#(0x[0-9a-fA-F]+)")
HEX_IMMEDIATE_COMMA = re.compile(r", (0x[0-9a-fA-F]+)")

for line in sys.stdin:
    line = HEX_IMMEDIATE.sub(lambda hi: "#" + str(int(hi.group()[1:], 16)), line)
    line = HEX_IMMEDIATE_COMMA.sub(lambda hi: ", " + str(int(hi.group()[2:], 16)), line)
    print(line, end="")
