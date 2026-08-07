#!/usr/bin/env python3
"""Deterministic source generator for the compiler-guided switch zoo."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GeneratedSwitch:
    source_name: str
    entry: str
    source: str


_HEADER = """typedef unsigned int zoo_u16;
typedef int zoo_s16;
typedef unsigned long zoo_u32;
typedef long zoo_s32;

"""


def generated_switches() -> dict[str, GeneratedSwitch]:
    """Return all named generated switch probes in stable matrix order."""

    return {
        "switch_u16_dense_zero": GeneratedSwitch(
            "switch_u16_dense_zero.c",
            "zoo_switch_u16_dense_zero",
            _HEADER
            + """void zoo_switch_u16_dense_zero(volatile zoo_u16 *out,
                                   zoo_u16 selector, zoo_u16 value)
{
    switch (selector) {
    case 0: out[0] = value; break;
    case 1: out[3] = value; break;
    case 2: out[1] = value; break;
    case 3: out[7] = value; break;
    case 4: out[2] = value; break;
    case 5: out[11] = value; break;
    case 6: out[4] = value; break;
    case 7: out[13] = value; break;
    case 8: out[5] = value; break;
    case 9: out[17] = value; break;
    case 10: out[6] = value; break;
    case 11: out[19] = value; break;
    default: break;
    }
}
""",
        ),
        "switch_s16_boundary": GeneratedSwitch(
            "switch_s16_boundary.c",
            "zoo_switch_s16_boundary",
            _HEADER
            + """void zoo_switch_s16_boundary(volatile zoo_u16 *out,
                                  zoo_s16 selector, zoo_u16 value)
{
    switch (selector) {
    case -32768: out[0] = value; break;
    case -32767: out[3] = value; break;
    case -32766: out[1] = value; break;
    case -32765: out[7] = value; break;
    case -32764: out[2] = value; break;
    case -32763: out[11] = value; break;
    case -32762: out[4] = value; break;
    case -32761: out[13] = value; break;
    case -32760: out[5] = value; break;
    case -32759: out[17] = value; break;
    case -32758: out[6] = value; break;
    case -32757: out[19] = value; break;
    default: break;
    }
}
""",
        ),
        "switch_u32_holes_shared": GeneratedSwitch(
            "switch_u32_holes_shared.c",
            "zoo_switch_u32_holes_shared",
            _HEADER
            + """void zoo_switch_u32_holes_shared(volatile zoo_u16 *out,
                                      zoo_u32 selector, zoo_u16 value)
{
    switch (selector) {
    case 0x100ul:
    case 0x103ul: out[0] = value; break;
    case 0x101ul: out[3] = value; break;
    case 0x104ul: out[1] = value; break;
    case 0x105ul:
    case 0x108ul: out[7] = value; break;
    case 0x106ul: out[2] = value; break;
    case 0x109ul: out[11] = value; break;
    case 0x10aul: out[4] = value; break;
    case 0x10cul: out[13] = value; break;
    case 0x10dul: out[5] = value; break;
    case 0x10ful: out[17] = value; break;
    default: out[19] = (zoo_u16)(value ^ 0x55aau); break;
    }
}
""",
        ),
        "switch_s32_cross_zero": GeneratedSwitch(
            "switch_s32_cross_zero.c",
            "zoo_switch_s32_cross_zero",
            _HEADER
            + """void zoo_switch_s32_cross_zero(volatile zoo_u16 *out,
                                    zoo_s32 selector, zoo_u16 value)
{
    switch (selector) {
    case -6l: out[0] = value; break;
    case -5l: out[3] = value; break;
    case -4l: out[1] = value; break;
    case -3l: out[7] = value; break;
    case -2l: out[2] = value; break;
    case -1l: out[11] = value; break;
    case 0l: out[4] = value; break;
    case 1l: out[13] = value; break;
    case 2l: out[5] = value; break;
    case 3l: out[17] = value; break;
    case 4l: out[6] = value; break;
    case 5l: out[19] = value; break;
    default: break;
    }
}
""",
        ),
        "switch_u16_fallthrough": GeneratedSwitch(
            "switch_u16_fallthrough.c",
            "zoo_switch_u16_fallthrough",
            _HEADER
            + """zoo_u16 zoo_switch_u16_fallthrough(volatile zoo_u16 *out,
                                       zoo_u16 selector, zoo_u16 value)
{
    zoo_u16 result = 0u;
    switch (selector) {
    case 20: result += 1u; /* fall through */
    case 21: out[0] = value; result += 2u; break;
    case 22:
    case 23: out[1] = value; return 7u;
    case 24: result = 3u; break;
    case 25: out[2] = value; result = 4u; break;
    case 26: result += 5u; /* fall through */
    case 27: out[3] = value; result += 6u; break;
    case 28: out[4] = value; result = 8u; break;
    case 29: out[5] = value; result = 9u; break;
    case 30: out[6] = value; result = 10u; break;
    case 31: out[7] = value; result = 11u; break;
    default: return 0xffffu;
    }
    return result;
}
""",
        ),
        "switch_sequential_nested": GeneratedSwitch(
            "switch_sequential_nested.c",
            "zoo_switch_sequential_nested",
            _HEADER
            + """zoo_u16 zoo_switch_sequential_nested(volatile zoo_u16 *out,
                                          zoo_u16 a, zoo_u16 b,
                                          zoo_u16 value)
{
    zoo_u16 result = 0u;
    switch (a) {
    case 40: result = 1u; break;
    case 41: result = 2u; break;
    case 42: result = 3u; break;
    case 43: result = 4u; break;
    case 44: result = 5u; break;
    case 45: result = 6u; break;
    case 46: result = 7u; break;
    case 47: result = 8u; break;
    case 48: result = 9u; break;
    case 49: result = 10u; break;
    case 50: result = 11u; break;
    case 51: result = 12u; break;
    default: result = 13u; break;
    }

    switch (b) {
    case 60: out[0] = value; break;
    case 61: out[1] = value; break;
    case 62: out[2] = value; break;
    case 63: out[3] = value; break;
    case 64: out[4] = value; break;
    case 65: out[5] = value; break;
    case 66: out[6] = value; break;
    case 67: out[7] = value; break;
    case 68: out[8] = value; break;
    case 69: out[9] = value; break;
    case 70: out[10] = value; break;
    case 71: out[11] = value; break;
    default:
        switch ((zoo_u16)(a & 3u)) {
        case 0: result += 20u; break;
        case 1: result += 21u; break;
        case 2: result += 22u; break;
        default: result += 23u; break;
        }
        break;
    }
    return result;
}
""",
        ),
    }
