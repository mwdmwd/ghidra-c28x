#!/usr/bin/env python3
"""Build and audit focused TI EABI call/return and scalar-register fixtures."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

COMMON = ("--float_support=fpu32", "--abi=eabi")


def run(cmd: list[str], cwd: Path, out: Path | None = None) -> None:
    if out is None:
        process = subprocess.run(cmd, cwd=cwd, check=False)
    else:
        with out.open("w", encoding="utf-8") as stream:
            process = subprocess.run(
                cmd, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT, check=False
            )
    if process.returncode:
        if out and out.exists():
            sys.stderr.write(out.read_text(errors="replace"))
        raise RuntimeError(
            f"command failed ({process.returncode}): {' '.join(cmd)}"
        )


def pentry_registers(parent: ET.Element) -> list[tuple[dict[str, str], str]]:
    result: list[tuple[dict[str, str], str]] = []
    for entry in parent.findall("./pentry"):
        register = entry.find("./register")
        if register is not None:
            result.append((dict(entry.attrib), register.get("name", "")))
    return result


def check_cspec(root: Path) -> None:
    tree = ET.parse(root / "tms320c28.cspec")
    protos = list(tree.findall("./default_proto/prototype")) + list(
        tree.findall("./prototype")
    )
    by_name = {proto.get("name"): proto for proto in protos}

    for name in ("__stdcall", "__lc", "__ffc"):
        proto = by_name.get(name)
        if proto is None:
            raise RuntimeError(f"missing compiler prototype {name}")

        input_node = proto.find("./input")
        output_node = proto.find("./output")
        if input_node is None or output_node is None:
            raise RuntimeError(f"incomplete compiler prototype {name}")

        input_entries = pentry_registers(input_node)
        registers = [register for _, register in input_entries]
        expected_scalar = [
            ({"minsize": "1", "maxsize": "2", "storage": "class4"}, "AL"),
            ({"minsize": "1", "maxsize": "2", "storage": "class4"}, "AH"),
            ({"minsize": "3", "maxsize": "4", "storage": "class4"}, "ACC"),
        ]
        if input_entries[:3] != expected_scalar:
            raise RuntimeError(
                f"{name} scalar overlap entries must be AL, AH, then containing ACC; "
                f"got {input_entries[:3]}"
            )
        for attrs, register in input_entries[:3]:
            if "extension" in attrs:
                raise RuntimeError(
                    f"{name} {register} must not assert sign/zero extension"
                )

        for register in ("XAR4", "XAR5"):
            if registers.count(register) != 2:
                raise RuntimeError(
                    f"{name} must expose {register} once as a pointer pool and once "
                    f"as a general fallback, got {registers.count(register)}"
                )

        rules: set[tuple[str, str, str, str]] = set()
        for rule in input_node.findall("./rule"):
            datatype = rule.find("./datatype")
            if datatype is None:
                continue
            action = next(
                (child for child in rule if child.tag != "datatype"), None
            )
            if action is None:
                continue
            rules.add(
                (
                    datatype.get("name", ""),
                    datatype.get("minsize", ""),
                    datatype.get("maxsize", ""),
                    action.tag + ":" + action.get("storage", ""),
                )
            )
            if action.tag == "join" and action.get("stackspill") != "false":
                raise RuntimeError(f"{name} 16-bit class must not spill through ACC")
        required_rules = {
            ("int", "1", "2", "join:class4"),
            ("uint", "1", "2", "join:class4"),
            ("int", "3", "4", "consume:class4"),
            ("uint", "3", "4", "consume:class4"),
        }
        if not required_rules.issubset(rules):
            raise RuntimeError(f"{name} missing scalar allocation rules: {rules}")

        output_entries = pentry_registers(output_node)
        output_by_register = {
            register: attrs for attrs, register in output_entries
        }
        if output_by_register.get("AL") != {"minsize": "1", "maxsize": "2"}:
            raise RuntimeError(f"{name} 16-bit output must be AL only")
        if output_by_register.get("ACC") != {"minsize": "3", "maxsize": "4"}:
            raise RuntimeError(f"{name} 32-bit output must be ACC")
        if "P" not in output_by_register:
            raise RuntimeError(f"{name} output resources must include P")
        joined = output_node.find(
            './pentry[@minsize="8"][@maxsize="8"]/addr[@space="join"]'
        )
        if joined is None or joined.get("piece1") != "ACC" or joined.get("piece2") != "P":
            raise RuntimeError(
                f"{name} 64-bit output must join ACC high then P low"
            )

    print("RPC_ABI_GENERAL_REGISTER_FALLBACKS=PASS")
    print("RPC_ABI_SCALAR_OVERLAP_MODEL=PASS")
    print("RPC_ABI_ACC_P_OUTPUT_JOIN=PASS")


def build(
    root: Path, out: Path, cc: Path, dis: Path, stripper: Path
) -> list[Path]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subjects: list[Path] = []
    rts = root / "tools/ti-cgt/lib/rts2800_fpu32_eabi.lib"
    if not rts.is_file():
        raise RuntimeError(f"missing TI EABI RTS library: {rts}")

    for opt in ("o0", "o2"):
        obj = out / f"rpc_abi_{opt}.obj"
        linked = out / f"rpc_abi_{opt}.linked.out"
        run(
            [
                str(cc),
                *COMMON,
                "--c11",
                f"-{opt.upper()}",
                "--symdebug:none",
                "--compile_only",
                f"--output_file={obj}",
                str(root / "rpc_abi_test.c"),
            ],
            root,
        )
        run(
            [
                str(cc),
                *COMMON,
                "--run_linker",
                "--entry_point=rpc_fixture_entry",
                f"--output_file={linked}",
                str(obj),
                str(root / "rpc_abi_test.cmd"),
                str(rts),
            ],
            root,
        )
        # Plain strip removes debug and local compiler metadata while retaining
        # the global fixture/helper symbols used by the focused Ghidra audit.
        run([str(stripper), str(linked)], root)
        listing = out / f"rpc_abi_{opt}.dis.txt"
        run([str(dis), str(linked)], root, listing)
        text = listing.read_text(errors="replace")
        for marker in (
            "LCR",
            "LRETR",
            "rpc_stack_args",
            "rpc_stack_caller",
            "rpc_branch_rejoin",
            "rpc_void_a",
            "rpc_void_b",
            "rpc_void_c",
            "rpc_one_s16",
            "rpc_one_u16",
            "rpc_four_s16",
            "rpc_one_s32",
            "rpc_id_s64",
            "rpc_two_s64",
            "rpc_mixed_s64",
            "rpc_div_s64",
            "rpc_div_u64",
            "rpc_calls16",
            "rpc_calls64",
            "rpc_scalar_fixture_entry",
            "__c28xabi_divll",
            "__c28xabi_divull",
        ):
            if marker not in text:
                raise RuntimeError(f"{opt} disassembly lost {marker}")
        if "LCR          *XAR" not in text:
            raise RuntimeError(f"{opt} lost indirect LCR")
        if "MOV          *-SP[1], AL" not in text:
            raise RuntimeError(f"{opt} one-argument 16-bit callee did not save AL")
        for constant in ("#0x6", "#0x1", "#0xa", "#0x0"):
            if f"MOVB         AL, {constant}" not in text:
                raise RuntimeError(f"{opt} lost AL-only call constant {constant}")
        if "MOVB         AH, #0x2" not in text or "MOVB         XAR4, #0x3" not in text:
            raise RuntimeError(f"{opt} lost AL/AH/XAR4/XAR5 four-scalar schedule")
        subjects.append(linked)

    obj = out / "rpc_flow_validation.obj"
    linked = out / "rpc_flow_validation.linked.out"
    run(
        [str(cc), *COMMON, "--compile_only", f"--output_file={obj}",
         str(root / "rpc_flow_validation.asm")],
        root,
    )
    run(
        [str(cc), *COMMON, "--run_linker", "--entry_point=rpc_flow_entry",
         f"--output_file={linked}", str(obj), str(root / "rpc_flow_validation.cmd")],
        root,
    )
    run([str(stripper), str(linked)], root)
    listing = out / "rpc_flow_validation.dis.txt"
    run([str(dis), str(linked)], root, listing)
    text = listing.read_text(errors="replace")
    for marker in (
        "LC           *XAR7",
        "LCR          *XAR0",
        "LRET",
        "LRETE",
        "LRETR",
        "IRET",
    ):
        if marker not in text:
            raise RuntimeError(f"flow disassembly lost {marker}")
    subjects.append(linked)
    print("RPC_ABI_DISASSEMBLY_SCALAR_FIXTURES=PASS")
    return subjects


def headless(root: Path, work: Path, ghidra: Path, subject: Path, index: int) -> str:
    run_dir = work / f"{index}-{subject.stem}"
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "RpcAbiTest.java", run_dir / "scripts" / "RpcAbiTest.java")
    cmd = [
        "timeout",
        "--signal=TERM",
        "--kill-after=5s",
        "180s",
        str(ghidra),
        str(run_dir / "project"),
        "rpc-abi-test",
        "-import",
        str(subject),
        "-processor",
        "tms320c28:LE:32:default",
        "-cspec",
        "default",
        "-scriptPath",
        str(run_dir / "scripts"),
        "-postScript",
        str(run_dir / "scripts" / "RpcAbiTest.java"),
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
    with (run_dir / "console.log").open("w", encoding="utf-8") as stream:
        process = subprocess.run(
            cmd, cwd=root, env=env, stdout=stream, stderr=subprocess.STDOUT, check=False
        )
    script = (
        (run_dir / "script.log").read_text(errors="replace")
        if (run_dir / "script.log").exists()
        else ""
    )
    if process.returncode or script.count("RPC_ABI_PROGRAM_PASS=") != 1:
        sys.stderr.write((run_dir / "console.log").read_text(errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless failed for {subject.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines()
        if "RPC_ABI_" in line
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
        root, args.build.resolve(), args.cl2000.resolve(), args.dis2000.resolve(),
        args.strip2000.resolve()
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
    print(f"RPC_ABI_GHIDRA_PROGRAMS={len(subjects)}")
    print("RPC_ABI_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
