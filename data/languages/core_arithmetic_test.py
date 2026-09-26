#!/usr/bin/env python3
"""Manual-based C28x arithmetic/status boundary regressions (SPRU430F).

Use unbounded Python arithmetic for expected values and the finite shared
P-Code executor for the module. This is not a hardware simulator.
"""
from __future__ import annotations

from itertools import product

from repeat_transfer_test import _execute, _reg, _translate


def execute(words, initial, memory=None):
    ops = _translate(words)
    return run(ops, initial, memory), ops


def run(ops, initial, memory=None):
    present = {_reg(node) for op in ops for node in (*op.inputs, op.output)}
    return _execute(ops, {k: v for k, v in initial.items() if k in present}, memory)


def state(trace, initial, names):
    return {name: trace.register(name) if name in trace.registers else initial[name]
            for name in names}


def signed(value, width=32):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def check_mov_pm():
    # Table 2-3 and p.275: all eight PM encodings, including AMODE's 101 case.
    for source, opcode in (("AL", 0x5638), ("AH", 0x5639)):
        for amode, raw, p in product((0, 1), range(8), (0, 0x12345678, 0x81234567)):
            initial = {source: 0xA5F8 | raw, "PM": 0xFE, "AMODE": amode, "P": p}
            trace, ops = execute((opcode, 0x3FA0), initial)
            shift = (1, 0, -1, -2, -3, 4 if amode else -4, -5, -6)[raw]
            shifted = p << shift if shift >= 0 else signed(p) >> -shift
            expected = {"PM": shift & 0xFF, "AR0": shifted & 0xFFFF, source: initial[source]}
            assert state(trace, initial, expected) == expected, (source, amode, raw, hex(p))
            writes = {_reg(op.output) for op in ops if op.output is not None}
            assert writes - {None} == {"PM", "AR0"}, writes


def check_maxcul():
    # p.247: N/Z describe the preceding high-word MAXL. V is sticky and is
    # set here only when equal high words require replacing the low word.
    values = (0, 1, 2, 0x80000000, 0xFFFFFFFF)
    for n, z in ((0, 0), (0, 1), (1, 0)):
        for p, source, v in product(values, values, (0, 1)):
            initial = {"N": n, "Z": z, "V": v, "P": p, "XAR4": source}
            trace, ops = execute((0x5651, 0x00A4), initial)
            expected_p = source if n else (max(p, source) if z else p)
            expected = {"P": expected_p, "V": v | int(z and p < source), "N": n, "Z": z}
            assert state(trace, initial, expected) == expected, (initial, expected)
            writes = {_reg(op.output) for op in ops if op.output is not None}
            assert writes - {None} == {"P", "V"}, writes


def check_loc32_flags():
    # pp.142/430/432: unsigned carry/no-borrow and sticky signed overflow.
    values = (0, 1, 2, 0x7FFFFFFF, 0x80000000, 0x80000001, 0xFFFFFFFE, 0xFFFFFFFF)
    for opcode in (0x5601, 0x5641, 0x5649):
        for loc, destination in ((0xA4, "XAR4"), (0xA9, "ACC"), (0x84, "memory")):
            ops = _translate((opcode, loc))
            for value, acc, c, v in product(values, values, (0, 1), (0, 1)):
                if destination == "ACC":
                    value = acc
                initial = {"ACC": acc, "C": c, "V": v, "N": 1, "Z": 1,
                           "XAR4": 0x2400 if destination == "memory" else value}
                memory = {0x2400: value & 0xFFFF, 0x2401: value >> 16, 0x2402: 0xBEEF}
                trace = run(ops, initial, memory)
                left, right = (acc, value) if opcode == 0x5649 else (value, acc)
                subtract = opcode != 0x5601
                total = left - right if subtract else left + right
                stotal = signed(left) - signed(right) if subtract else signed(left) + signed(right)
                result = total & 0xFFFFFFFF
                expected = {"C": int(left >= right) if subtract else int(total > 0xFFFFFFFF),
                            "V": v | int(not -0x80000000 <= stotal < 0x80000000),
                            "N": result >> 31, "Z": int(result == 0)}
                assert state(trace, initial, expected) == expected, (opcode, loc, initial, expected)
                actual = (trace.word(0x2400) | (trace.word(0x2401) << 16)
                          if destination == "memory" else trace.register(destination))
                assert actual == result, (opcode, loc, initial, hex(actual), hex(result))
                if destination != "ACC":
                    assert trace.register("ACC") == acc
                if destination == "memory":
                    assert len(trace.loads) == len(trace.stores) == 1
                    assert trace.register("XAR4") == 0x2402
                    assert trace.word(0x2402) == 0xBEEF


def check_movu_ovc():
    # p.314: expose exactly six unsigned bits; refresh N/Z for AX destinations.
    for loc, destination in ((0xA9, "AL"), (0xA8, "AH"), (0xA0, "AR0"), (0x84, "memory")):
        ops = _translate((0x5628, loc))
        for ovc, n, z in product(range(256), (0, 1), (0, 1)):
            initial = {"OVC": ovc, "N": n, "Z": z, "XAR4": 0x2400}
            if destination != "memory":
                initial[destination] = 0xA5A5
            trace = run(ops, initial, {0x2400: 0xABCD, 0x2401: 0x1234})
            value = trace.word(0x2400) if destination == "memory" else trace.register(destination)
            assert value == ovc & 0x3F, (loc, ovc, value)
            ax = destination in ("AL", "AH")
            expected = {"OVC": ovc, "N": 0 if ax else n,
                        "Z": int(value == 0) if ax else z}
            assert state(trace, initial, expected) == expected, (loc, initial, expected)
            assert not trace.loads
            if destination == "memory":
                assert len(trace.stores) == 1
                assert trace.register("XAR4") == 0x2401
                assert trace.word(0x2401) == 0x1234
    trace, _ops = execute((0x5655, 0x00A4, 0x5628, 0x00A0),
                          {"ACC": 0, "XAR4": 1, "OVC": 0, "V": 0})
    assert trace.register("AR0") == 63, "reachable unsigned borrow must store six bits"


def check_integer_mac_flags():
    # pp.199-200/205-206: add/subtract unsigned old P, independently of PM
    # and OVM. The new signed product is shifted only when stored into P.
    arithmetic = ((0, 1), (0, 0), (0xFFFFFFFF, 1), (0x7FFFFFFF, 1),
                  (0x80000000, 1), (0x80000000, 0xFFFFFFFF),
                  (0x7FFFFFFF, 0xFFFFFFFF), (1, 0xFFFFFFFF))
    for words, subtract in (((0x5643, 0x00A4), True),
                            ((0x564D, 0xC7A4), False),
                            ((0x564D, 0x87A4), False)):
        ops = _translate(words)
        for (acc, p), (a, b), shift, ovc, v, ovm in product(
                arithmetic, ((3, 5), (-7, 9), (-0x80000000, -1)),
                (-6, 0, 1, 4), (-32, -1, 0, 31), (0, 1), (0, 1)):
            initial = {"ACC": acc, "P": p, "XAR4": a & 0xFFFFFFFF,
                       "XT": b & 0xFFFFFFFF, "XAR7": 0x2400,
                       "C": acc & 1, "V": v, "N": 1, "Z": 1,
                       "OVC": ovc & 0xFF, "OVM": ovm, "PM": shift & 0xFF}
            memory = {0x2400: b & 0xFFFF, 0x2401: (b >> 16) & 0xFFFF}
            trace = run(ops, initial, memory)
            total = acc - p if subtract else acc + p
            signed_total = signed(acc) - signed(p) if subtract else signed(acc) + signed(p)
            result = total & 0xFFFFFFFF
            event = int(acc < p) if subtract else int(total > 0xFFFFFFFF)
            counter = (ovc - event if subtract else ovc + event) & 0x3F
            shifted_product = (a * b) << shift if shift >= 0 else (a * b) >> -shift
            expected = {"ACC": result, "P": shifted_product & 0xFFFFFFFF,
                        "C": 1 - event if subtract else event,
                        "V": v | int(not -0x80000000 <= signed_total < 0x80000000),
                        "N": result >> 31, "Z": int(result == 0),
                        "OVC": signed(counter, 6) & 0xFF, "OVM": ovm}
            assert state(trace, initial, expected) == expected, (words, initial, expected)
        touched = {_reg(node) for op in ops for node in (*op.inputs, op.output)}
        assert "OVM" not in touched, "unsigned product accumulation must not use OVM"


if __name__ == "__main__":
    check_mov_pm()
    print("MOV_PM_VECTORS=96")
    check_maxcul()
    print("MAXCUL_VECTORS=150")
    check_integer_mac_flags()
    print("INTEGER_MAC_FLAG_VECTORS=4608")
    check_movu_ovc()
    print("MOVU_OVC_VECTORS=4097")
    check_loc32_flags()
    print("LOC32_FLAG_VECTORS=2304")
