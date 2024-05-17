#!/usr/bin/env python3
import sys
import re

# Everything except after @ signs
HEX_IMMEDIATE_ALL = re.compile(r"(?<!@)0x[0-9a-fA-F]+")

for line in sys.stdin:
    line = HEX_IMMEDIATE_ALL.sub(lambda hi: str(int(hi.group(), 16)), line)
    print(line, end="")
