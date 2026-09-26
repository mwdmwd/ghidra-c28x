#!/usr/bin/env python3
"""SPRU430F pp.187/199/244/385: loc updates win XAR7 write conflicts.

Section 5.9 defines the independent program address and the 1/2-word stride.
IMACL's p.199 'by 1' conflicts with that explicit 32-bit addressing rule and
with its example walking int32 arrays; use the two-word stride of section 5.9.
"""
from core_arithmetic_test import execute, signed


def check_dual_mac():
    initial = {"XAR7": 0x2404, "XAR6": 0x2804, "ARP": 7, "AR0": 0,
               "ACC": 0, "P": 0, "PM": 0, "OVM": 0, "OVC": 0, "V": 0}
    memory = {address: (address * 3 + 7) & 0xFFFF
              for address in range(0x2400, 0x2810)}
    for opcode, width in ((0x5607, 1), (0x564B, 2), (0x564D, 2), (0x564F, 2)):
        # (loc, AMODE, data address, final data-side XAR7, data-side modifies XAR7)
        modes = ((0x8F, 0, 0x2404 - width, 0x2404 - width, True),
                 (0x87, 0, 0x2404, 0x2404 + width, True),
                 (0xC7, 0, 0x2404, 0x2404, False),
                 (0x86, 0, 0x2804, 0x2404, False),
                 (0xB9, 0, 0x2404, 0x2404 + width, True),
                 (0xBA, 0, 0x2404, 0x2404 - width, True),
                 (0xBB, 0, 0x2404, 0x2404, True),
                 (0xBC, 0, 0x2404, 0x2404, True),
                 (0xAE, 0, 0x2404, 0x2404, True),
                 (0xAF, 0, 0x2404, 0x2404, True),
                 (0xC2, 1, 0x2404, 0x2404 + width, True),
                 (0xCA, 1, 0x2404, 0x2404 - width, True),
                 (0xD2, 1, 0x2404, 0x2404, True),
                 (0xDA, 1, 0x2404, 0x2404, True),
                 (0xE2, 1, 0x2404, 0x2404, True),
                 (0xEA, 1, 0x2404, 0x2404, True))
        for post in (False, True):
            for loc, amode, data_address, data_xar7, conflict in modes:
                words = ((0x561E,) if amode else ()) + (
                    opcode, (0x8700 if post else 0xC700) | loc)
                trace, _ops = execute(words, initial, memory)
                final_xar7 = data_xar7 + (width if post and not conflict else 0)
                assert trace.register("XAR7") == final_xar7, (words, hex(trace.register("XAR7")), hex(final_xar7))
                assert [(load[1], load[2]) for load in trace.loads] == [
                    (data_address, width * 2), (0x2404, width * 2)], words
                a, b = (sum(memory[address + i] << (16 * i) for i in range(width))
                        for address in (data_address, 0x2404))
                if opcode == 0x5607:
                    expected_p = signed(a, 16) * signed(b, 16)
                elif opcode == 0x564B:
                    expected_p = signed(a & 0xFFFF, 16) * signed(b & 0xFFFF, 16)
                    assert trace.register("ACC") == (signed(a >> 16, 16) * signed(b >> 16, 16)) & 0xFFFFFFFF
                else:
                    expected_p = signed(a) * signed(b)
                    if opcode == 0x564F:
                        expected_p >>= 32
                assert trace.register("P") == expected_p & 0xFFFFFFFF, words
                assert not trace.stores, words
        # Repeated independent array walks retain the instruction-width stride.
        trace, _ops = execute((0xF602, opcode, 0x8786), initial, memory)
        assert trace.register("XAR7") == 0x2404 + 3 * width, opcode
        assert trace.register("XAR6") == 0x2804 + 3 * width, opcode
        assert [(load[1], load[2]) for load in trace.loads] == [
            (base + i * width, width * 2) for i in range(3) for base in (0x2804, 0x2404)], opcode
        # Legacy updates through another ARP must still permit program ++.
        # Materialize XAR6 so the finite executor can seed its indirect alias.
        for amode, loc in ((0, 0xBB), (1, 0xD2)):
            words = (0x7680, 0x2804) + ((0x561E,) if amode else ()) + (opcode, 0x8700 | loc)
            trace, _ops = execute(words, dict(initial, ARP=6), memory)
            assert trace.register("XAR7") == 0x2404 + width, words
            assert trace.register("XAR6") == 0x2804, words
            assert [load[1] for load in trace.loads] == [0x2804, 0x2404], words
        # Priority applies independently on every repeated execution.
        trace, _ops = execute((0xF602, opcode, 0x878F), dict(initial, XAR7=0x2410), memory)
        assert trace.register("XAR7") == 0x2410 - 3 * width, opcode
        assert [load[1] for load in trace.loads] == [
            address for i in range(3)
            for address in (0x2410 - (i + 1) * width, 0x2410 - i * width)], opcode


if __name__ == "__main__":
    check_dual_mac()
    print("DUAL_MAC_VECTORS=144")
