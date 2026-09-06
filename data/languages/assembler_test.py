#!/usr/bin/env python3
"""Exercise split imm22 and FPU imm16 operands through the Ghidra assembler.

Opcode words are from SPRU430F's LB, LC, LCR, FFC, and MOVL XARn,#22bit instruction tables.
FPU opcode words and field layouts are from SPRUEO2B's immediate instruction tables.
"""

import argparse
from pathlib import Path
import struct


FORMS = (
    ("lb {value}", 0x0040),
    ("lc {value}", 0x0080),
    ("lcr {value}", 0x7640),
    ("ffc XAR7,{value}", 0x00C0),
    ("movl XAR0,#{value}", 0x8D00),
    ("movl XAR1,#{value}", 0x8D40),
    ("movl XAR2,#{value}", 0x8D80),
    ("movl XAR3,#{value}", 0x8DC0),
    ("movl XAR4,#{value}", 0x8F00),
    ("movl XAR5,#{value}", 0x8F40),
    ("movl XAR6,#{value}", 0x7680),
    ("movl XAR7,#{value}", 0x76C0),
)

# Mnemonic, first opcode word, number of immediate bits in the second word.
FPU_FORMS = (
    ("addf32", 0xE880, 10),
    ("mpyf32", 0xE840, 10),
    ("subf32", 0xE8C0, 10),
    ("cmpf32", 0xE810, 13),
    ("maxf32", 0xE820, 13),
    ("minf32", 0xE830, 13),
    ("moviz", 0xE800, 13),
    ("movxi", 0xE808, 13),
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ghidra-install", type=Path, default=Path("/opt/ghidra"))
    args = parser.parse_args()

    from pyghidra.launcher import DeferredPyGhidraLauncher

    launcher = DeferredPyGhidraLauncher(install_dir=args.ghidra_install)
    launcher.add_vmargs("-Xmx2G")
    launcher.start()

    from ghidra import GhidraApplicationLayout
    from ghidra.app.plugin.assembler import Assemblers, AssemblySemanticException
    from ghidra.framework import Application, ApplicationConfiguration
    from ghidra.program.model.lang import LanguageID
    from ghidra.program.util import DefaultLanguageService
    from java.io import File

    config = ApplicationConfiguration()
    config.setInitializeLogging(False)
    Application.initializeApplication(
        GhidraApplicationLayout(File(str(args.ghidra_install.resolve()))), config
    )
    language = DefaultLanguageService.getLanguageService().getLanguage(
        LanguageID("tms320c28:LE:32:default")
    )
    assembler = Assemblers.getAssembler(language)
    # Every individual operand bit, the word boundary, asymmetric halves, and
    # every high-six-bit combination. Hex and decimal syntax must both work.
    values = sorted({
        0, 0xFFFF, 0x10000, 0x10001, 0x123456, 0x2AAAAA, 0x155555, 0x3FFFFF,
        *(1 << bit for bit in range(22)),
        *((high << 16) | 0xA55A for high in range(64)),
    })
    positive = negative = 0
    # These are absolute word-address operands, independent of the assembly PC.
    for pc in (0x100, 0x234560):
        address = language.getDefaultSpace().getAddress(pc)
        for template, opcode in FORMS:
            for value in values:
                expected = struct.pack("<HH", opcode | (value >> 16), value & 0xFFFF)
                for literal in (hex(value), str(value)):
                    line = template.format(value=literal)
                    actual = bytes(int(b) & 0xFF for b in assembler.assembleLine(address, line))
                    assert actual == expected, (pc, line, actual.hex(), expected.hex())
                    positive += 1
            for literal in ("-1", "0x400000", "0x412345", "0xffffffff"):
                line = template.format(value=literal)
                try:
                    assembler.assembleLine(address, line)
                except AssemblySemanticException:
                    negative += 1
                else:
                    raise AssertionError(f"Out-of-range operand accepted: {line}")
    print(f"ASSEMBLER_IMM22 PASS positive={positive} negative={negative}")

    positive = negative = 0
    address = language.getDefaultSpace().getAddress(0x100)
    for mnemonic, opcode, low_bits in FPU_FORMS:
        values = sorted({
            0, 0xFFFF, 0xA55A, 0x5AA5, 0x3F80, 0xBF80, 0x7F80,
            (1 << low_bits) - 1, 1 << low_bits, (1 << low_bits) + 1,
            *(1 << bit for bit in range(16)),
            *((high << low_bits) | 0x155 for high in range(1 << (16 - low_bits))),
        })
        for dest in range(8):
            for source in range(8 if low_bits == 10 else 1):
                template = f"{mnemonic} R{dest}H,#{{value}}"
                if low_bits == 10:
                    template += f",R{source}H"
                for value in values:
                    expected = struct.pack(
                        "<HH", opcode | (value >> low_bits),
                        ((value & ((1 << low_bits) - 1)) << (16 - low_bits))
                        | (source << 3) | dest,
                    )
                    for literal in (hex(value), str(value)):
                        line = template.format(value=literal)
                        actual = bytes(int(b) & 0xFF for b in assembler.assembleLine(address, line))
                        assert actual == expected, (line, actual.hex(), expected.hex())
                        positive += 1
                for literal in ("-1", "0x10000", "0x1a55a", "0xffffffff"):
                    line = template.format(value=literal)
                    try:
                        assembler.assembleLine(address, line)
                    except AssemblySemanticException:
                        negative += 1
                    else:
                        raise AssertionError(f"Out-of-range operand accepted: {line}")
    print(f"ASSEMBLER_FPU_IMM16 PASS positive={positive} negative={negative}")


if __name__ == "__main__":
    main()
