#!/usr/bin/env python3
"""Build and audit TI EABI incoming/outgoing stack-argument fixtures."""
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

COMMON = ("--float_support=fpu32", "--abi=eabi")
FUNCTIONS = (
    "stack_reuse_ffc",
    "stack_lcr_helper",
    "stack_leaf_noarg",
    "stack_nonleaf_noarg",
    "stack_noarg_lcr",
    "stack_noarg_ffc",
    "stack_noarg_div",
    "stack_mixed_helper",
    "stack_mixed_caller",
    "stack_incoming_live",
    "stack_conditional_noarg",
    "stack_escape_helper",
    "stack_escape_local",
    "stack_fixture_entry",
    "stack_ffc_helper",
    "__c28xabi_divl",
)
LABEL_RE = re.compile(r"^[0-9a-fA-F]+\s{2,}([^\s].*):\s*$")


def run(cmd: list[str], cwd: Path, out: Path | None = None) -> None:
    if out is None:
        process = subprocess.run(cmd, cwd=cwd, check=False)
    else:
        with out.open("w", encoding="utf-8") as stream:
            process = subprocess.run(
                cmd, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False
            )
    if process.returncode:
        if out is not None and out.exists():
            sys.stderr.write(out.read_text(errors="replace"))
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(cmd)}"
        )


def prototypes(tree: ET.ElementTree) -> dict[str, ET.Element]:
    nodes = list(tree.findall("./default_proto/prototype"))
    nodes.extend(tree.findall("./prototype"))
    return {node.get("name", ""): node for node in nodes}


def one_stack_addr(proto: ET.Element) -> str:
    addresses = proto.findall('./input/pentry/addr[@space="stack"]')
    if len(addresses) != 1:
        raise RuntimeError(
            f"{proto.get('name')} expected one stack input range, got {len(addresses)}"
        )
    return addresses[0].get("offset", "")


def return_registers(proto: ET.Element) -> list[str]:
    return [
        register.get("name", "")
        for register in proto.findall("./returnaddress/register")
    ]


def check_cspec(root: Path) -> None:
    tree = ET.parse(root / "tms320c28.cspec")
    stack = tree.find("./stackpointer")
    if stack is None or stack.get("register") != "SP" or stack.get("growth") != "positive":
        raise RuntimeError("compiler spec must use positive-growing SP")

    by_name = prototypes(tree)
    expected = {
        "__stdcall": ("0x1fffffe08", ["RPC"], True),
        "__lc": ("0x1fffffe08", [], True),
        "__ffc": ("0x1fffffe0c", ["XAR7"], False),
    }
    for name, (stack_addr, returns, has_uponreturn) in expected.items():
        proto = by_name.get(name)
        if proto is None:
            raise RuntimeError(f"missing compiler prototype {name}")
        if proto.get("stackshift") != "0" or proto.get("extrapop") != "0":
            raise RuntimeError(f"{name} must have zero completed-call stack movement")
        actual_addr = one_stack_addr(proto)
        if actual_addr.lower() != stack_addr:
            raise RuntimeError(
                f"{name} stack range expected {stack_addr}, got {actual_addr}"
            )
        if return_registers(proto) != returns:
            raise RuntimeError(
                f"{name} return state expected {returns}, got {return_registers(proto)}"
            )
        uponreturn = proto.findall('./pcode[@inject="uponreturn"]')
        if bool(uponreturn) != has_uponreturn:
            raise RuntimeError(
                f"{name} upon-return injection mismatch: {len(uponreturn)}"
            )

    print("STACK_ARGUMENT_CSPEC_POSITIVE_SP=PASS")
    print("STACK_ARGUMENT_CSPEC_LCR_LC_BOUNDARY=0x1fffffe08")
    print("STACK_ARGUMENT_CSPEC_FFC_BOUNDARY=0x1fffffe0c")
    print("STACK_ARGUMENT_CSPEC_CALL_MECHANISMS=3")


def function_blocks(text: str) -> dict[str, str]:
    lines = text.splitlines()
    starts: list[tuple[int, str]] = []
    expected = set(FUNCTIONS)
    for index, line in enumerate(lines):
        match = LABEL_RE.match(line)
        if match is None:
            continue
        label = match.group(1)
        if label in expected:
            starts.append((index, label))
    found = {name for _, name in starts}
    missing = expected - found
    if missing:
        raise RuntimeError(f"disassembly lost function labels: {sorted(missing)}")

    result: dict[str, str] = {}
    for position, (start, name) in enumerate(starts):
        end = starts[position + 1][0] if position + 1 < len(starts) else len(lines)
        result[name] = "\n".join(lines[start:end])
    return result


def require(block: str, markers: tuple[str, ...], context: str) -> None:
    missing = [marker for marker in markers if marker not in block]
    if missing:
        raise RuntimeError(f"{context} lost {missing}:\n{block}")


def require_absent(block: str, markers: tuple[str, ...], context: str) -> None:
    found = [marker for marker in markers if marker in block]
    if found:
        raise RuntimeError(f"{context} unexpectedly contains {found}:\n{block}")


def require_count(block: str, marker: str, count: int, context: str) -> None:
    actual = block.count(marker)
    if actual != count:
        raise RuntimeError(
            f"{context} expected {count} occurrences of {marker!r}, got {actual}:\n{block}"
        )


def check_frame(block: str, words: int, context: str) -> None:
    require(
        block,
        (f"ADDB         SP, #{words}", f"SUBB         SP, #{words}"),
        context,
    )


def check_disassembly(listing: Path, optimization: str) -> None:
    text = listing.read_text(errors="replace")
    blocks = function_blocks(text)

    lcr = blocks["stack_noarg_lcr"]
    check_frame(lcr, 4, f"{optimization} noarg LCR frame")
    require(
        lcr,
        (
            "MOV          AL, #0x3344",
            "MOV          AH, #0x1122",
            "MOVL         *-SP[2], ACC",
            "*-SP[4]",
        ),
        f"{optimization} noarg LCR local/outgoing evidence",
    )
    require_count(lcr, "LCR          ", 1, f"{optimization} noarg LCR")

    ffc = blocks["stack_noarg_ffc"]
    check_frame(ffc, 4, f"{optimization} noarg FFC frame")
    require(
        ffc,
        ("MOVB         ACC, #10", "MOVL         *-SP[2], ACC", "*-SP[4]"),
        f"{optimization} noarg FFC local/outgoing evidence",
    )
    require_count(ffc, "FFC          ", 1, f"{optimization} noarg FFC")
    require_absent(ffc, ("LCR          ",), f"{optimization} noarg FFC mechanism")

    reuse = blocks["stack_reuse_ffc"]
    check_frame(reuse, 2, f"{optimization} reused FFC slot frame")
    require(
        reuse,
        ("MOVB         ACC, #10", "MOVB         ACC, #37", "*-SP[2]"),
        f"{optimization} reused FFC constants",
    )
    require_count(reuse, "FFC          ", 2, f"{optimization} reused FFC calls")
    if reuse.count("MOVL         *-SP[2], ACC") != 2:
        raise RuntimeError(
            f"{optimization} FFC calls did not reuse the same outgoing slot:\n{reuse}"
        )

    division = blocks["stack_noarg_div"]
    check_frame(division, 2, f"{optimization} division caller frame")
    require(
        division,
        ("MOVB         ACC, #10", "MOVL         *-SP[2], ACC", "FFC          "),
        f"{optimization} division outgoing divisor",
    )
    require_count(division, "FFC          ", 1, f"{optimization} division call")

    incoming = blocks["stack_incoming_live"]
    expected_frame = 2 if optimization == "O0" else 4
    check_frame(incoming, expected_frame, f"{optimization} incoming-live frame")
    require(
        incoming,
        ("MOVB         ACC, #5", "MOVL         *-SP[2], ACC", "LCR          "),
        f"{optimization} incoming-live outgoing slot",
    )
    if optimization == "O0":
        require(incoming, ("ADDL         ACC, *-SP[6]",), "O0 true incoming stack read")
    else:
        require(
            incoming,
            ("MOVL         XAR7, *-SP[8]", "MOVL         *-SP[4], XAR7",
             "ADDL         ACC, *-SP[4]"),
            "O2 incoming stack preservation across nested call",
        )

    mixed = blocks["stack_mixed_caller"]
    check_frame(mixed, 8, f"{optimization} mixed caller frame")
    require(
        mixed,
        (
            "MOV          *-SP[1], #0x3333",
            "MOV          *-SP[2], #0x4444",
            "MOVL         XAR4, #0x003801",
            "MOVL         XAR5, #0x003802",
            "MOVL         *-SP[4], XAR6",
            "MOV          *-SP[5], #0",
            "MOV          *-SP[6], #0",
            "MOVL         *-SP[8], ACC",
            "MOVB         XAR6, #0x06",
            "MOVB         ACC, #7",
            "MOV          PL, #0x0003",
        ),
        f"{optimization} mixed AL/AH/ACC:P/XAR4/XAR5/stack schedule",
    )
    require_count(mixed, "LCR          ", 1, f"{optimization} mixed caller")

    conditional = blocks["stack_conditional_noarg"]
    check_frame(conditional, 4, f"{optimization} conditional frame")
    require(
        conditional,
        ("*-SP[4]", "MOVL         *-SP[2], ACC", "SB           ", "LCR          "),
        f"{optimization} conditional call/no-call rejoin",
    )
    require_count(conditional, "LCR          ", 1, f"{optimization} conditional call")

    escaped = blocks["stack_escape_local"]
    check_frame(escaped, 2, f"{optimization} escaped-local frame")
    require(
        escaped,
        ("MOVZ         AR4, SP", "SUBB         XAR4, #2", "MOVB         ACC, #13",
         "LCR          ", "*-SP[2]"),
        f"{optimization} escaped local alias",
    )

    leaf = blocks["stack_leaf_noarg"]
    require_absent(
        leaf,
        ("ADDB         SP", "SUBB         SP", "LCR          ", "FFC          "),
        f"{optimization} leaf control",
    )
    require(leaf, ("LRETR",), f"{optimization} leaf return")

    nonleaf = blocks["stack_nonleaf_noarg"]
    check_frame(nonleaf, 2, f"{optimization} non-leaf control frame")
    require_count(nonleaf, "LCR          ", 2, f"{optimization} non-leaf calls")
    require(nonleaf, ("MOVL         *-SP[2], ACC",), f"{optimization} non-leaf outgoing slot")

    ffc_helper = blocks["stack_ffc_helper"]
    require(
        ffc_helper,
        ("ADDL         ACC, *-SP[2]", "LB           *XAR7"),
        f"{optimization} FFC helper",
    )
    require_absent(
        ffc_helper,
        ("LRETR", "ADDB         SP", "SUBB         SP"),
        f"{optimization} FFC helper mechanism",
    )

    div_helper = blocks["__c28xabi_divl"]
    require(
        div_helper,
        (
            "MOVL         ACC, *-SP[2]",
            "MOVL         *-SP[2], ACC",
            "RPT          #31",
            "SUBCUL       ACC, *-SP[2]",
            "LB           *XAR7",
        ),
        f"{optimization} FFC division helper schedule",
    )
    require_absent(div_helper, ("LRETR",), f"{optimization} FFC division return")

    print(f"STACK_ARGUMENT_DISASSEMBLY_{optimization}=PASS")
    print(f"STACK_ARGUMENT_DISASSEMBLY_LOCAL_OUTGOING_{optimization}=PASS")
    print(f"STACK_ARGUMENT_DISASSEMBLY_INCOMING_LIVE_{optimization}=PASS")
    print(f"STACK_ARGUMENT_DISASSEMBLY_MIXED_{optimization}=PASS")
    print(f"STACK_ARGUMENT_DISASSEMBLY_FFC_{optimization}=PASS")


def build(
    root: Path, out: Path, cc: Path, dis: Path, stripper: Path
) -> list[Path]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)

    ffc_obj = out / "stack_argument_ffc.obj"
    run(
        [
            str(cc),
            *COMMON,
            "--compile_only",
            f"--output_file={ffc_obj}",
            str(root / "stack_argument_ffc.asm"),
        ],
        root,
    )

    subjects: list[Path] = []
    for optimization in ("O0", "O2"):
        lower = optimization.lower()
        c_obj = out / f"stack_argument_{lower}.obj"
        linked = out / f"stack_argument_{lower}.linked.out"
        run(
            [
                str(cc),
                *COMMON,
                "--c11",
                f"-{optimization}",
                "--symdebug:none",
                "--compile_only",
                f"--output_file={c_obj}",
                str(root / "stack_argument_test.c"),
            ],
            root,
        )
        run(
            [
                str(cc),
                *COMMON,
                "--run_linker",
                "--entry_point=stack_fixture_entry",
                f"--output_file={linked}",
                str(c_obj),
                str(ffc_obj),
                str(root / "stack_argument_test.cmd"),
            ],
            root,
        )
        # Keep global fixture symbols while removing debug and compiler-local
        # metadata, matching the stripped firmware conditions under test.
        run([str(stripper), str(linked)], root)
        listing = out / f"stack_argument_{lower}.dis.txt"
        run([str(dis), str(linked)], root, listing)
        check_disassembly(listing, optimization)
        subjects.append(linked)

    print("STACK_ARGUMENT_LINKED_STRIPPED_PROGRAMS=2")
    return subjects


def headless(root: Path, work: Path, ghidra: Path, subject: Path, index: int) -> str:
    run_dir = work / f"{index}-{subject.stem}"
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        root / "StackArgumentTest.java", run_dir / "scripts" / "StackArgumentTest.java"
    )

    cmd = [
        "timeout",
        "--signal=TERM",
        "--kill-after=5s",
        "180s",
        str(ghidra),
        str(run_dir / "project"),
        "stack-argument-test",
        "-import",
        str(subject),
        "-processor",
        "tms320c28:LE:32:default",
        "-cspec",
        "default",
        "-scriptPath",
        str(run_dir / "scripts"),
        "-postScript",
        str(run_dir / "scripts" / "StackArgumentTest.java"),
        "-log",
        str(run_dir / "ghidra.log"),
        "-scriptlog",
        str(run_dir / "script.log"),
        "-analysisTimeoutPerFile",
        "120",
        "-overwrite",
        "-deleteProject",
    ]
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(run_dir / "home"),
            "XDG_CONFIG_HOME": str(run_dir / "config"),
            "GHIDRA_HEADLESS_JAVA_OPTIONS":
                f"-Dapplication.tempdir={run_dir / 'tmp'} "
                f"-Dapplication.cachedir={run_dir / 'cache'} "
                f"-Djava.io.tmpdir={run_dir / 'tmp'}",
        }
    )
    console = run_dir / "console.log"
    with console.open("w", encoding="utf-8") as stream:
        process = subprocess.run(
            cmd, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False
        )
    script = (
        (run_dir / "script.log").read_text(errors="replace")
        if (run_dir / "script.log").exists()
        else ""
    )
    if process.returncode or script.count("STACK_ARGUMENT_PROGRAM_PASS=") != 1:
        sys.stderr.write(console.read_text(errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless failed for {subject.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines()
        if "STACK_ARGUMENT_" in line
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cl2000", type=Path, required=True)
    parser.add_argument("--dis2000", type=Path, required=True)
    parser.add_argument("--strip2000", type=Path, required=True)
    parser.add_argument("--ghidra-headless", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    check_cspec(root)
    subjects = build(
        root,
        args.build.resolve(),
        args.cl2000.resolve(),
        args.dis2000.resolve(),
        args.strip2000.resolve(),
    )
    shutil.rmtree(args.work.resolve(), ignore_errors=True)
    args.work.resolve().mkdir(parents=True)
    for index, subject in enumerate(subjects, 1):
        print(
            headless(
                root,
                args.work.resolve(),
                args.ghidra_headless.resolve(),
                subject,
                index,
            )
        )
    print(f"STACK_ARGUMENT_GHIDRA_PROGRAMS={len(subjects)}")
    print("STACK_ARGUMENT_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
