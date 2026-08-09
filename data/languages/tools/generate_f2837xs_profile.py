#!/usr/bin/env python3
"""Generate the checked F2837xS-compatible Ghidra device profile.

The generator consumes the redistributable C2000Ware subset supplied by the
operator.  Register names, descriptions, offsets, bit fields, and peripheral
base addresses are derived from TI's SysConfig metadata; only the mapping from
register families to device instances and the non-MMIO memory segmentation is
curated here.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

PROFILE_VERSION = 1


def parse_int(text: str) -> int:
    cleaned = re.sub(r"[uUlL]+$", "", text.strip())
    try:
        return int(cleaned, 0)
    except ValueError:
        # A few generated SysConfig offsets retain a C macro name followed by
        # the resolved literal.  Use the final literal and reject strings with
        # no numeric evidence.
        values = re.findall(r"0x[0-9A-Fa-f]+|\d+", cleaned)
        if not values:
            raise
        return int(values[-1], 0)


def extract_array(text: str, declaration_re: str) -> str:
    m = re.search(declaration_re, text)
    if not m:
        raise ValueError(f"array declaration not found: {declaration_re}")
    start = text.find("[", m.start())
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        c = text[i]
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return text[start + 1 : i]
    raise ValueError("unterminated array")


def top_level_objects(array_body: str) -> Iterable[str]:
    depth = 0
    start = None
    in_string = False
    escape = False
    for i, c in enumerate(array_body):
        if in_string:
            if escape:
                escape = False
            elif c == "\\":
                escape = True
            elif c == '"':
                in_string = False
            continue
        if c == '"':
            in_string = True
        elif c == "{":
            if depth == 0:
                start = i
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0 and start is not None:
                yield array_body[start : i + 1]
                start = None
    if depth != 0:
        raise ValueError("unbalanced object array")


def field(block: str, key: str, required: bool = True) -> str | None:
    m = re.search(rf"\b{re.escape(key)}\s*:\s*\"([^\"]*)\"", block)
    if m:
        return m.group(1)
    if required:
        raise ValueError(f"missing {key} in {block[:120]!r}")
    return None


@dataclass(frozen=True)
class Register:
    name: str
    description: str
    offset: int
    width_bits: int
    fields: tuple[dict, ...]


def parse_registers(path: Path) -> list[Register]:
    text = path.read_text(encoding="utf-8")
    body = extract_array(text, r"let\s+\w+Registers\s*=\s*\[")
    result: list[Register] = []
    for block in top_level_objects(body):
        name = field(block, "name")
        offset_s = field(block, "offset")
        # Parameterised CLB PUSH/PULL pseudo-registers are not concrete labels.
        if "(" in name or offset_s is None or "(" in offset_s:
            continue
        description = field(block, "description", required=False) or ""
        bits: list[dict] = []
        bm = re.search(r"\bbits\s*:\s*\[", block)
        if bm:
            bits_body = extract_array(block[bm.start() :], r"\bbits\s*:\s*\[")
            for bit in top_level_objects(bits_body):
                try:
                    bits.append(
                        {
                            "name": field(bit, "name"),
                            "description": field(bit, "description", required=False) or "",
                            "size": parse_int(field(bit, "size")),
                            "shift": parse_int(field(bit, "shift")),
                            "mask": parse_int(field(bit, "mask")),
                        }
                    )
                except ValueError:
                    # Ignore malformed metadata entries rather than inventing them.
                    continue
        top = max((b["shift"] + b["size"] for b in bits), default=16)
        width = 32 if top > 16 else 16
        result.append(Register(name, description, parse_int(offset_s), width, tuple(bits)))
    if not result:
        raise ValueError(f"no registers parsed from {path}")
    return result


def parse_memory_map(path: Path) -> tuple[dict[str, int], dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    body = extract_array(text, r"let\s+DeviceMemoryMap\s*=\s*\[")
    bases: dict[str, int] = {}
    display: dict[str, str] = {}
    for block in top_level_objects(body):
        name = field(block, "name")
        bases[name] = parse_int(field(block, "baseAddress"))
        display[name] = field(block, "displayName", required=False) or name
    return bases, display


def add_instance(
    out: list[dict], namespace: str, base_name: str, base: int, registers: Iterable[Register]
) -> None:
    for r in registers:
        out.append(
            {
                "namespace": namespace,
                "baseSymbol": base_name,
                "name": r.name,
                "address": base + r.offset,
                "widthBits": r.width_bits,
                "description": r.description,
                "fields": list(r.fields),
            }
        )


def select(regs: list[Register], pred: Callable[[Register], bool]) -> list[Register]:
    return [r for r in regs if pred(r)]


def build_registers(root: Path, bases: dict[str, int]) -> list[dict]:
    js = root / "sysconfig-registers"
    parsed = {
        p.stem.removeprefix("f2837xs_").removesuffix("_registers"): parse_registers(p)
        for p in sorted(js.glob("f2837xs_*_registers.js"))
    }
    out: list[dict] = []

    simple: dict[str, list[str]] = {
        "asysctl": ["ANALOGSUBSYS_BASE"],
        "can": ["CANA_BASE", "CANB_BASE"],
        "cmpss": [f"CMPSS{i}_BASE" for i in range(1, 9)],
        "cputimer": [f"CPUTIMER{i}_BASE" for i in range(3)],
        "dac": [f"DAC{x}_BASE" for x in "ABC"],
        "ecap": [f"ECAP{i}_BASE" for i in range(1, 7)],
        "emif": ["EMIF1_BASE", "EMIF2_BASE"],
        "epwm": [f"EPWM{i}_BASE" for i in range(1, 13)],
        "eqep": [f"EQEP{i}_BASE" for i in range(1, 4)],
        "i2c": ["I2CA_BASE", "I2CB_BASE"],
        "mcbsp": ["MCBSPA_BASE", "MCBSPB_BASE"],
        "nmi": ["NMI_BASE"],
        "sci": [f"SCI{x}_BASE" for x in "ABCD"],
        "sdfm": ["SDFM1_BASE", "SDFM2_BASE"],
        "spi": [f"SPI{x}_BASE" for x in "ABC"],
        "upp": ["UPP_BASE"],
    }
    for module, base_names in simple.items():
        for base_name in base_names:
            add_instance(out, base_name.removesuffix("_BASE"), base_name, bases[base_name], parsed[module])

    # ADC control and result spaces share one metadata array but have distinct bases.
    adc_result = select(parsed["adc"], lambda r: bool(re.fullmatch(r"(?:RESULT\d+|PPB\dRESULT)", r.name)))
    adc_control = select(parsed["adc"], lambda r: r not in adc_result)
    for x in "ABCD":
        add_instance(out, f"ADC{x}", f"ADC{x}_BASE", bases[f"ADC{x}_BASE"], adc_control)
        add_instance(out, f"ADC{x}RESULT", f"ADC{x}RESULT_BASE", bases[f"ADC{x}RESULT_BASE"], adc_result)

    # CLA core registers and the separate software-interrupt block.
    cla_soft = select(parsed["cla"], lambda r: r.name.startswith("SOFTINT"))
    cla_core = select(parsed["cla"], lambda r: r not in cla_soft)
    add_instance(out, "CLA1", "CLA1_BASE", bases["CLA1_BASE"], cla_core)
    add_instance(out, "CLA1_SOFTINT", "CLA1_SOFTINT_BASE", bases["CLA1_SOFTINT_BASE"], cla_soft)

    # DMA controller registers precede the channel MODE register in the TI array.
    dma_global_names = {"CTRL", "DEBUGCTRL", "PRIORITYCTRL1", "PRIORITYSTAT"}
    dma_global = select(parsed["dma"], lambda r: r.name in dma_global_names)
    dma_channel = select(parsed["dma"], lambda r: r.name not in dma_global_names)
    add_instance(out, "DMA", "DMA_BASE", bases["DMA_BASE"], dma_global)
    for i in range(1, 7):
        add_instance(out, f"DMA_CH{i}", f"DMA_CH{i}_BASE", bases[f"DMA_CH{i}_BASE"], dma_channel)

    # GPIO configuration and data banks are separately based.
    gpio_data = select(parsed["gpio"], lambda r: bool(re.fullmatch(r"GP[A-F](?:DAT|SET|CLEAR|TOGGLE)", r.name)))
    gpio_ctrl = select(parsed["gpio"], lambda r: r not in gpio_data)
    add_instance(out, "GPIOCTRL", "GPIOCTRL_BASE", bases["GPIOCTRL_BASE"], gpio_ctrl)
    add_instance(out, "GPIODATA", "GPIODATA_BASE", bases["GPIODATA_BASE"], gpio_data)

    # Memory configuration metadata concatenates six independently based register groups.
    memcfg_groups = {
        "MEMCFG": lambda n: n.startswith(("DX", "LSX", "GSX", "MSGX")),
        "EMIF1CONFIG": lambda n: n.startswith("EMIF1"),
        "EMIF2CONFIG": lambda n: n.startswith("EMIF2"),
        "ACCESSPROTECTION": lambda n: n.startswith(("NMAV", "NMCPU", "NMDMA", "NMCLA", "MAV", "MCPU", "MDMA")),
        "MEMORYERROR": lambda n: n.startswith(("UC", "CERR", "CEINT")),
        "ROMWAITSTATE": lambda n: n == "ROMWAITSTATE",
        "ROMPREFETCH": lambda n: n == "ROMPREFETCH",
    }
    for ns, pred in memcfg_groups.items():
        base_name = ns + "_BASE"
        add_instance(out, ns, base_name, bases[base_name], select(parsed["memcfg"], lambda r, p=pred: p(r.name)))

    # System-control metadata concatenates DEVCFG, CLKCFG, CPUSYS, WD,
    # DMACLASRCSEL, and SYNCSOC register groups.
    sys_groups = {
        "DEVCFG": lambda n: bool(re.fullmatch(r"(?:PARTID[HL]|REVID|DC\d+|PERCNF1|FUSEERR|SOFTPRES\d+|SYSDBGCTL)", n)),
        "CLKCFG": lambda n: n.startswith(("CLKCFG", "CLKSRC", "SYSPLL", "AUXPLL", "SYSCLK", "AUXCLK", "PERCLK", "XCLK", "LOSPCP", "MCDCR", "X1CNT")),
        "CPUSYS": lambda n: n.startswith(("CPUSYS", "HIB", "IORESTORE", "PIEVERR", "PCLKCR", "SECMSEL", "LPMCR", "GPIOLPM", "TMR2", "RESC")),
        "WD": lambda n: n in {"SCSR", "WDCNTR", "WDKEY", "WDCR", "WDWCR"},
        "DMACLASRCSEL": lambda n: n.startswith(("CLA1TASKSRC", "DMACHSRC")),
        "SYNCSOC": lambda n: n in {"SYNCSELECT", "ADCSOCOUTSELECT", "SYNCSOCLOCK"},
    }
    for ns, pred in sys_groups.items():
        base_name = ns + "_BASE"
        add_instance(out, ns, base_name, bases[base_name], select(parsed["sysctl"], lambda r, p=pred: p(r.name)))

    # Flash control and ECC have independent bases.  The pump semaphore is a
    # single register at its own absolute base.
    flash_ctrl = select(parsed["flash"], lambda r: r.name in {"FRDCNTL", "FBAC", "FBFALLBACK", "FBPRDY", "FPAC1", "FMSTAT", "FRD_INTF_CTRL"})
    flash_ecc = select(parsed["flash"], lambda r: r.name not in {x.name for x in flash_ctrl} and r.name != "PUMPREQUEST")
    for bank in (0, 1):
        add_instance(out, f"FLASH{bank}CTRL", f"FLASH{bank}CTRL_BASE", bases[f"FLASH{bank}CTRL_BASE"], flash_ctrl)
        add_instance(out, f"FLASH{bank}ECC", f"FLASH{bank}ECC_BASE", bases[f"FLASH{bank}ECC_BASE"], flash_ecc)
    add_instance(out, "FLASHPUMPSEMAPHORE", "FLASHPUMPSEMAPHORE_BASE", bases["FLASHPUMPSEMAPHORE_BASE"], select(parsed["flash"], lambda r: r.name == "PUMPREQUEST"))

    # DCSM OTP and live register windows.
    dcsm = parsed["dcsm"]
    dcsm_maps = {
        "DCSM_Z1OTP": lambda n: n.startswith("Z1OTP_"),
        "DCSM_Z2OTP": lambda n: n.startswith("Z2OTP_"),
        "DCSM_Z1": lambda n: n.startswith("Z1_") and not n.startswith("Z1OTP_"),
        "DCSM_Z2": lambda n: n.startswith("Z2_") and not n.startswith("Z2OTP_"),
        "DCSMCOMMON": lambda n: n in {"FLSEM", "SECTSTAT", "RAMSTAT"},
    }
    for ns, pred in dcsm_maps.items():
        base_name = ns + "_BASE"
        add_instance(out, ns, base_name, bases[base_name], select(dcsm, lambda r, p=pred: p(r.name)))

    # XBAR metadata presently describes the shared flag/clear window only.
    add_instance(out, "XBAR", "XBAR_BASE", bases["XBAR_BASE"], parsed["xbar"])

    # CLB metadata contains three register subspaces per tile; split by the
    # reset of offsets in the source ordering.
    clb = parsed["clb"]
    logic_cfg = clb[:29]
    logic_ctl = clb[29:51]
    for i in range(1, 5):
        add_instance(out, f"CLB{i}_LOGICCFG", f"CLB{i}_LOGICCFG_BASE", bases[f"CLB{i}_LOGICCFG_BASE"], logic_cfg)
        add_instance(out, f"CLB{i}_LOGICCTL", f"CLB{i}_LOGICCTL_BASE", bases[f"CLB{i}_LOGICCTL_BASE"], logic_ctl)

    out.sort(key=lambda r: (r["address"], r["namespace"], r["name"]))
    return out


def block(name: str, start: int, words: int, kind: str, r: bool, w: bool, x: bool, volatile: bool, source: str) -> dict:
    return {
        "name": name,
        "start": start,
        "words": words,
        "kind": kind,
        "read": r,
        "write": w,
        "execute": x,
        "volatile": volatile,
        "source": source,
    }


def build_blocks() -> list[dict]:
    linker = "TI C2000Ware F2837xS linker command files"
    memmap = "TI F2837xS hw_memmap.h / f2837xs_memmap.js"
    rommap = "TI C2000Ware 3.02 F2837xS Rev-B Boot ROM and CLA data-ROM linker maps"
    blocks: list[dict] = [
        block("RAM_M0", 0x0000, 0x0400, "ram", True, True, False, False, linker),
        block("RAM_M1", 0x0400, 0x0400, "ram", True, True, False, False, linker),
        block("ADC_RESULT_REGS", 0x0B00, 0x0080, "peripheral", True, True, False, True, memmap),
        block("CPU_TIMER_REGS", 0x0C00, 0x0020, "peripheral", True, True, False, True, memmap),
        block("PIE_CONTROL", 0x0CE0, 0x0020, "peripheral", True, True, False, True, memmap),
        block("PIE_VECTOR_RAM", 0x0D00, 0x0100, "ram", True, True, False, False, linker),
        block("DMA_REGS", 0x1000, 0x00E0, "peripheral", True, True, False, True, memmap),
        block("CLA1_REGS", 0x1400, 0x0080, "peripheral", True, True, False, True, memmap),
        block("CLA1_TO_CPU_MSG_RAM", 0x1480, 0x0080, "ram", True, True, False, False, linker),
        block("CPU_TO_CLA1_MSG_RAM", 0x1500, 0x0080, "ram", True, True, False, False, linker),
        block("CLB_REGS", 0x3000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("EPWM_REGS", 0x4000, 0x0C00, "peripheral", True, True, False, True, memmap),
        block("CAPTURE_ANALOG_REGS", 0x5000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("SERIAL_UPP_REGS", 0x6000, 0x0400, "peripheral", True, True, False, True, memmap),
        block("UPP_TX_MSG_RAM", 0x6C00, 0x0200, "peripheral_ram", True, True, False, True, memmap),
        block("UPP_RX_MSG_RAM", 0x6E00, 0x0200, "peripheral_ram", True, True, False, True, memmap),
        block("SYSTEM_IO_REGS", 0x7000, 0x1000, "peripheral", True, True, False, True, memmap),
    ]
    for i in range(6):
        blocks.append(block(f"RAM_LS{i}", 0x8000 + i * 0x800, 0x800, "ram", True, True, False, False, linker))
    blocks += [
        block("RAM_D0", 0xB000, 0x0800, "ram", True, True, False, False, linker),
        block("RAM_D1", 0xB800, 0x0800, "ram", True, True, False, False, linker),
    ]
    for i in range(16):
        blocks.append(block(f"RAM_GS{i}", 0xC000 + i * 0x1000, 0x1000, "ram", True, True, False, False, linker))
    blocks += [
        block("USB_REGS", 0x40000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("EMIF1_REGS", 0x47000, 0x0800, "peripheral", True, True, False, True, memmap),
        block("EMIF2_REGS", 0x47800, 0x0800, "peripheral", True, True, False, True, memmap),
        block("CANA_REGS", 0x48000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("CANA_MESSAGE_RAM", 0x49000, 0x0800, "peripheral_ram", True, True, False, True, memmap),
        block("CANB_REGS", 0x4A000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("CANB_MESSAGE_RAM", 0x4B000, 0x0800, "peripheral_ram", True, True, False, True, memmap),
        block("FLASH_PUMP_SEMAPHORE", 0x50024, 0x0002, "peripheral", True, True, False, True, memmap),
        block("SYSTEM_CONTROL_REGS", 0x5D000, 0x0400, "peripheral", True, True, False, True, memmap),
        block("ROM_PREFETCH_REGS", 0x5E600, 0x0020, "peripheral", True, True, False, True, memmap),
        block("DCSM_MEMCFG_FLASH_REGS", 0x5F000, 0x1000, "peripheral", True, True, False, True, memmap),
        block("OTP_CALIBRATION_UID", 0x70000, 0x0400, "otp", True, False, True, False, "TI F2837xS OTP/UID map"),
        block("DCSM_Z1_OTP", 0x78000, 0x0200, "otp", True, False, False, False, linker),
        block("DCSM_Z2_OTP", 0x78200, 0x0200, "otp", True, False, False, False, linker),
        block("FLASH_BANK0", 0x80000, 0x40000, "flash", True, False, True, False, linker),
        block("FLASH_BANK1", 0xC0000, 0x40000, "flash", True, False, True, False, "F2837x-compatible second-bank window; derivative-dependent"),
        block("SECURE_ROM", 0x3F0000, 0x8000, "rom", True, False, True, False, rommap),
        block("BOOT_ROM", 0x3F8000, 0x7FC0, "rom", True, False, True, False, rommap),
        block("CPU_RESET_VECTORS", 0x3FFFC0, 0x0040, "rom", True, False, True, False, rommap),
        block("CLA_DATA_ROM", 0x1001000, 0x1000, "rom_data", True, False, False, False, rommap),
    ]
    blocks.sort(key=lambda b: b["start"])
    # Ensure the curated blocks never overlap; this is a generator bug, not a
    # runtime condition to paper over.
    for a, b in zip(blocks, blocks[1:]):
        if a["start"] + a["words"] > b["start"]:
            raise ValueError(f"overlapping profile blocks: {a['name']} and {b['name']}")
    return blocks


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    h.update(path.read_bytes())
    return h.hexdigest()


def checked_end(start: int, words: int, what: str) -> int:
    if start < 0 or words <= 0:
        raise ValueError(f"invalid range for {what}: start={start:#x} words={words:#x}")
    end = start + words
    if end <= start:
        raise ValueError(f"overflowing range for {what}: start={start:#x} words={words:#x}")
    return end


def containing_region(profile: dict, start: int, words: int) -> str | None:
    end = checked_end(start, words, "profile range")
    for b in profile["blocks"]:
        block_end = checked_end(b["start"], b["words"], f"block {b['name']}")
        if start >= b["start"] and end <= block_end:
            return b["name"]
    return None


def validate_profile(profile: dict) -> None:
    if profile["addressUnitBytes"] != 2:
        raise ValueError("F2837xS-compatible profile must use two-byte addressable units")

    blocks = sorted(profile["blocks"], key=lambda b: (b["start"], b["name"]))
    names: set[str] = set()
    previous: dict | None = None
    for b in blocks:
        if b["name"] in names:
            raise ValueError(f"duplicate block name: {b['name']}")
        names.add(b["name"])
        end = checked_end(b["start"], b["words"], f"block {b['name']}")
        if previous is not None:
            previous_end = previous["start"] + previous["words"]
            if previous_end > b["start"]:
                raise ValueError(f"overlapping profile blocks: {previous['name']} and {b['name']}")
        previous = b

    base_names: set[str] = set()
    for label in profile["baseLabels"]:
        name = label["symbol"]
        if name in base_names:
            raise ValueError(f"duplicate base symbol: {name}")
        base_names.add(name)
        if containing_region(profile, label["address"], 1) is None:
            raise ValueError(f"base label is outside mapped profile memory: {name} at {label['address']:#x}")

    register_names: set[tuple[str, str]] = set()
    spans: list[tuple[int, int, str]] = []
    for r in profile["registers"]:
        key = (r["namespace"], r["name"])
        if key in register_names:
            raise ValueError(f"duplicate register symbol: {key[0]}::{key[1]}")
        register_names.add(key)
        width = r["widthBits"]
        if width not in (16, 32):
            raise ValueError(f"unsupported register width {width}: {key[0]}::{key[1]}")
        words = width // 16
        end = checked_end(r["address"], words, f"register {key[0]}::{key[1]}")
        if containing_region(profile, r["address"], words) is None:
            raise ValueError(f"register is outside mapped profile memory: {key[0]}::{key[1]}")
        for f in r.get("fields", []):
            size = f["size"]
            shift = f["shift"]
            mask = f["mask"]
            if size <= 0 or shift < 0 or shift + size > width:
                raise ValueError(f"invalid bit field {key[0]}::{key[1]}::{f['name']}")
            expected_mask = ((1 << size) - 1) << shift
            if mask != expected_mask:
                raise ValueError(
                    f"metadata mask mismatch for {key[0]}::{key[1]}::{f['name']}: "
                    f"mask={mask:#x} expected={expected_mask:#x}"
                )
        spans.append((r["address"], end, f"{key[0]}::{key[1]}"))

    spans.sort()
    for index, a in enumerate(spans):
        for b in spans[index + 1 :]:
            if b[0] >= a[1]:
                break
            if (a[0], a[1]) != (b[0], b[1]):
                raise ValueError(f"partially overlapping register spans: {a[2]} and {b[2]}")

def input_provenance(root: Path) -> tuple[dict[str, str], str]:
    files = sorted((root / "sysconfig-registers").glob("f2837xs_*_registers.js"))
    files.append(root / "sysconfig-registers" / "f2837xs_memmap.js")
    unique = sorted(set(files))
    hashes = {str(path.relative_to(root)): sha256(path) for path in unique}
    aggregate = hashlib.sha256()
    for name, digest in hashes.items():
        aggregate.update(name.encode("utf-8"))
        aggregate.update(b"\0")
        aggregate.update(digest.encode("ascii"))
        aggregate.update(b"\n")
    return hashes, aggregate.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--inputs", type=Path, required=True, help="c2000ware-f2837xs subset")
    ap.add_argument("--output", type=Path, required=True)
    args = ap.parse_args()
    root = args.inputs.resolve()
    memmap_file = root / "sysconfig-registers" / "f2837xs_memmap.js"
    bases, display = parse_memory_map(memmap_file)
    registers = build_registers(root, bases)
    base_labels = [
        {"name": name.removesuffix("_BASE"), "symbol": name, "address": address, "displayName": display[name]}
        for name, address in sorted(bases.items(), key=lambda item: (item[1], item[0]))
    ]
    profile = {
        "schema": "tms320c28-device-profile",
        "version": PROFILE_VERSION,
        "profileName": "F2837xS-compatible",
        "addressUnitBytes": 2,
        "blocks": build_blocks(),
        "baseLabels": base_labels,
        "registers": registers,
        "romEvidence": {
            "default": "uninitialized map only",
            "tiGoldenIsOptional": True,
            "rawDumpSupported": True,
            "warning": "Do not substitute a TI golden ROM for bytes from the analyzed device.",
        },
        "provenance": {
            "memoryMapSha256": sha256(memmap_file),
            "subsetLicense": "TI BSD-3-Clause terms in device_profiles/UPSTREAM_LICENSE.md",
            "generatedBy": "tools/generate_f2837xs_profile.py",
        },
    }
    input_hashes, aggregate_hash = input_provenance(root)
    profile["provenance"]["inputFilesSha256"] = input_hashes
    profile["provenance"]["inputsAggregateSha256"] = aggregate_hash
    validate_profile(profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"PROFILE_BLOCKS={len(profile['blocks'])}")
    print(f"PROFILE_BASE_LABELS={len(base_labels)}")
    print(f"PROFILE_REGISTERS={len(registers)}")
    print(f"PROFILE_OUTPUT={args.output}")


if __name__ == "__main__":
    main()
