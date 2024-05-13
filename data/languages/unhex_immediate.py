#!/usr/bin/env python3
import sys
import re


HEX_IMMEDIATE = re.compile(r"#(0x[0-9a-fA-F]+)")

for line in sys.stdin:
    print(HEX_IMMEDIATE.sub(lambda hi: "#" + str(int(hi.group()[1:], 16)), line), end="")
