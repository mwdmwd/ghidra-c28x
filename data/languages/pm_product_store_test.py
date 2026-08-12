#!/usr/bin/env python3
"""Build and audit proved no-shift MOV loc16,P fixtures."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

COMMON = ("--float_support=fpu32", "--abi=eabi")
COMPILER_FUNCTIONS = (
    "pm_plain_quotient_store",
    "pm_store_after_call",
    "pm_store_after_unequal_calls",
)
MANUAL_FUNCTIONS = (
    "pm_boundary_store",
    "pm_explicit_zero",
    "pm_explicit_zero_rejoin",
    "pm_explicit_zero_after_dynamic",
    "pm_after_completed_call",
    "pm_after_unequal_calls",
    "pm_near_positive_shift",
    "pm_near_negative_shift",
    "pm_near_dynamic_pm",
    "pm_near_dynamic_st0",
    "pm_near_conflicting_paths",
    "pm_near_alternate_ingress",
    "pm_near_undominated_zero_loop",
    "pm_near_raw101_c28",
    "pm_near_raw101_c2x",
)


@dataclass(frozen=True)
class Subject:
    path: Path
    kind: str
    addresses: dict[str, str]


def symbol_addresses(disassembly: str, names: tuple[str, ...]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in names:
        match = re.search(
            rf"^([0-9a-fA-F]+)\s+{re.escape(name)}:\s*$",
            disassembly, re.MULTILINE,
        )
        if match is None:
            raise RuntimeError(f"disassembly lost symbol {name}")
        result[name] = match.group(1).lower()
    return result


def run(command: list[str], cwd: Path, output: Path | None = None) -> None:
    if output is None:
        completed = subprocess.run(command, cwd=cwd, check=False)
    else:
        with output.open("w", encoding="utf-8") as stream:
            completed = subprocess.run(
                command, cwd=cwd, stdout=stream, stderr=subprocess.STDOUT,
                check=False,
            )
    if completed.returncode:
        if output is not None and output.exists():
            sys.stderr.write(output.read_text(encoding="utf-8", errors="replace"))
        raise RuntimeError(
            f"command failed ({completed.returncode}): {' '.join(command)}"
        )


def function_text(disassembly: str, name: str) -> str:
    marker = re.search(rf"^[0-9a-fA-F]+\s+{re.escape(name)}:\s*$", disassembly,
                       re.MULTILINE)
    if marker is None:
        raise RuntimeError(f"disassembly lost function {name}")
    next_symbol = re.search(r"^[0-9a-fA-F]+\s+pm_[A-Za-z0-9_]+:\s*$",
                            disassembly[marker.end():], re.MULTILINE)
    end = marker.end() + next_symbol.start() if next_symbol else len(disassembly)
    return disassembly[marker.start():end]


def build(root: Path, out: Path, compiler: Path, disassembler: Path, stripper: Path) -> list[Subject]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subjects: list[Subject] = []
    for optimization in ("o0", "o2"):
        obj = out / f"pm_product_store_{optimization}.obj"
        linked = out / f"pm_product_store_{optimization}.out"
        run([
            str(compiler), *COMMON, "--c11", f"-{optimization.upper()}",
            "--symdebug:none", "--compile_only", f"--output_file={obj}",
            str(root / "pm_product_store_test.c"),
        ], root)
        run([
            str(compiler), *COMMON, "--run_linker",
            "--entry_point=pm_product_store_entry", f"--output_file={linked}",
            str(obj), str(root / "pm_product_store_test.cmd"),
        ], root)
        listing = out / f"pm_product_store_{optimization}.dis.txt"
        run([str(disassembler), str(linked)], root, listing)
        text = listing.read_text(encoding="utf-8", errors="replace")
        for name in COMPILER_FUNCTIONS:
            body = function_text(text, name)
            if len(re.findall(r"\bMOV\s+[^\n,]+, P\s*$", body, re.MULTILINE)) != 1:
                raise RuntimeError(
                    f"{optimization} {name} lost its single MOV loc16,P"
                )
        if text.count("SUBCUL") != 3 or text.count("RPT          #31") != 3:
            raise RuntimeError(
                f"{optimization} compiler fixture lost three quotient schedules"
            )
        plain = function_text(text, "pm_plain_quotient_store")
        after = function_text(text, "pm_store_after_call")
        rejoin = function_text(text, "pm_store_after_unequal_calls")
        if "LCR" in plain or after.count("LCR") < 1 or rejoin.count("LCR") < 3:
            raise RuntimeError(
                f"{optimization} compiler fixture lost plain/call/rejoin coverage"
            )
        if "SB" not in rejoin:
            raise RuntimeError(f"{optimization} unequal-call fixture lost its branch")
        addresses = symbol_addresses(text, COMPILER_FUNCTIONS)
        run([str(stripper), "--postlink", str(linked)], root)
        subjects.append(Subject(linked, "compiler", addresses))

    obj = out / "pm_product_store_validation.obj"
    linked = out / "pm_product_store_validation.out"
    run([
        str(compiler), *COMMON, "--compile_only", f"--output_file={obj}",
        str(root / "pm_product_store_validation.asm"),
    ], root)
    run([
        str(compiler), *COMMON, "--run_linker",
        "--entry_point=pm_validation_entry", f"--output_file={linked}",
        str(obj), str(root / "pm_product_store_validation.cmd"),
    ], root)
    listing = out / "pm_product_store_validation.dis.txt"
    run([str(disassembler), str(linked)], root, listing)
    text = listing.read_text(encoding="utf-8", errors="replace")
    for name in MANUAL_FUNCTIONS:
        if name not in text:
            raise RuntimeError(f"validation disassembly lost {name}")
    if text.count("MOV          AR0, P") != len(MANUAL_FUNCTIONS):
        raise RuntimeError("validation fixture must contain fifteen MOV AR0,P sites")
    if text.count("ff6d   SPM          #-4") != 2:
        raise RuntimeError("validation fixture lost the two raw-PM-101 encodings")
    validation_names = MANUAL_FUNCTIONS + (
        "pm_stale_store", "pm_stale_nonmov", "pm_after_completed_call",
        "pm_after_unequal_calls", "pm_near_raw101_c28",
        "pm_near_raw101_c2x", "pm_alternate_target",
    )
    addresses = symbol_addresses(text, tuple(dict.fromkeys(validation_names)))
    run([str(stripper), "--postlink", str(linked)], root)
    subjects.append(Subject(linked, "validation", addresses))
    return subjects


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=10)


def headless(root: Path, work: Path, ghidra: Path, subject: Subject,
             index: int, timeout_seconds: int) -> str:
    run_dir = work / f"{index}-{subject.path.stem}"
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "PmProductStoreTest.java", run_dir / "scripts")
    is_validation = subject.kind == "validation"
    if is_validation:
        shutil.copy2(root / "PmProductStoreSeedStale.java", run_dir / "scripts")

    script_log = run_dir / "script.log"
    console_log = run_dir / "console.log"
    command = [
        str(ghidra), str(run_dir / "project"), "pm-product-store-test",
        "-import", str(subject.path),
        "-processor", "tms320c28:LE:32:default", "-cspec", "default",
        "-scriptPath", str(run_dir / "scripts"),
    ]
    address_args = [f"{name}={address}" for name, address in subject.addresses.items()]
    if is_validation:
        command.extend([
            "-preScript", str(run_dir / "scripts" / "PmProductStoreSeedStale.java"),
            *address_args,
        ])
    command.extend([
        "-postScript", str(run_dir / "scripts" / "PmProductStoreTest.java"),
        subject.kind, *address_args,
        "-log", str(run_dir / "ghidra.log"),
        "-scriptlog", str(script_log),
        "-analysisTimeoutPerFile", "90", "-overwrite", "-deleteProject",
    ])
    env = os.environ.copy()
    env.update({
        "HOME": str(run_dir / "home"),
        "XDG_CONFIG_HOME": str(run_dir / "config"),
        "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join((
            f"-Dapplication.tempdir={run_dir / 'tmp'}",
            f"-Dapplication.cachedir={run_dir / 'cache'}",
            f"-Djava.io.tmpdir={run_dir / 'tmp'}",
        )),
    })
    with console_log.open("wb") as output:
        process = subprocess.Popen(
            command, cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        passed = False
        while time.monotonic() < deadline:
            if script_log.exists():
                script = script_log.read_text(encoding="utf-8", errors="replace")
                if script.count("PM_PROGRAM_PASS=") == 1:
                    passed = True
                    break
            if process.poll() is not None:
                break
            time.sleep(0.5)
        if passed:
            time.sleep(0.5)
        terminate_group(process)

    script = script_log.read_text(encoding="utf-8", errors="replace") \
        if script_log.exists() else ""
    if not passed or script.count("PM_PROGRAM_PASS=") != 1:
        sys.stderr.write(console_log.read_text(encoding="utf-8", errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless PM test failed for {subject.path.name}")
    if "ERROR" in script or "Exception" in script or "AssertionError" in script:
        sys.stderr.write(script)
        raise RuntimeError(f"PM script logged an error for {subject.path.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines() if "PM_" in line
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
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    root = args.root.resolve()
    subjects = build(
        root, args.build.resolve(), args.cl2000.resolve(),
        args.dis2000.resolve(), args.strip2000.resolve(),
    )
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for index, subject in enumerate(subjects, 1):
        print(headless(
            root, work, args.ghidra_headless.resolve(), subject, index, args.timeout
        ))
    print(f"PM_GHIDRA_PROGRAMS={len(subjects)}")
    print("PM_PRODUCT_STORE_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
