#!/usr/bin/env python3
"""Build and audit proved constant-T and paired-shift fixtures."""

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
    "shift_t_div2", "shift_t_div4",
    "shift_sign_extend_value", "shift_sign_extend_multiply",
    "shift_add_sign_extended_product", "shift_t_compiler_entry",
)
PAIR_COMPILER_FUNCTIONS = (
    "shift_sign_extend_value", "shift_sign_extend_multiply",
    "shift_add_sign_extended_product",
)
MANUAL_FUNCTIONS = (
    "shift_t_direct_one", "shift_t_direct_max", "shift_t_direct_sixteen",
    "shift_t_equal_merge", "shift_t_redefined_after_clobber",
    "shift_t_near_call_clobber", "shift_t_near_conflicting_merge",
    "shift_t_near_zero", "shift_t_near_masked_zero", "shift_t_near_dynamic",
    "shift_t_near_partial_write", "shift_t_near_value_clobber",
    "shift_t_near_alternate_ingress", "shift_t_alternate_source",
    "shift_t_contract_callee",
    "shift_pair_direct", "shift_pair_after_impy",
    "shift_pair_near_standalone", "shift_pair_near_first_count",
    "shift_pair_near_second_count", "shift_pair_near_separated",
    "shift_pair_near_second_ingress", "shift_pair_second_ingress_source",
    "shift_pair_near_first_ingress", "shift_pair_first_ingress_source",
    "shift_pair_near_flag_observer", "shift_pair_near_conflicting_rejoin",
    "shift_validation_entry",
)
VALIDATION_LABELS = (
    "shift_t_stale_zero", "shift_t_stale_nonshift", "shift_t_alternate_target",
    "shift_pair_alternate_second", "shift_pair_alternate_first",
    "shift_pair_stale_first", "shift_pair_stale_second",
)


@dataclass(frozen=True)
class Subject:
    path: Path
    kind: str
    addresses: dict[str, str]


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


def function_text(disassembly: str, name: str) -> str:
    marker = re.search(
        rf"^[0-9a-fA-F]+\s+{re.escape(name)}:\s*$", disassembly, re.MULTILINE,
    )
    if marker is None:
        raise RuntimeError(f"disassembly lost function {name}")
    next_symbol = re.search(
        r"^[0-9a-fA-F]+\s+shift_[A-Za-z0-9_]+:\s*$",
        disassembly[marker.end():], re.MULTILINE,
    )
    end = marker.end() + next_symbol.start() if next_symbol else len(disassembly)
    return disassembly[marker.start():end]


def build(root: Path, out: Path, compiler: Path, disassembler: Path,
          stripper: Path) -> list[Subject]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subjects: list[Subject] = []

    for optimization in ("o0", "o2"):
        obj = out / f"shift_idiom_{optimization}.obj"
        linked = out / f"shift_idiom_{optimization}.out"
        run([
            str(compiler), *COMMON, "--c11", f"-{optimization.upper()}",
            "--symdebug:none", "--compile_only", f"--output_file={obj}",
            str(root / "shift_idiom_test.c"),
        ], root)
        run([
            str(compiler), *COMMON, "--run_linker",
            "--entry_point=shift_t_compiler_entry", f"--output_file={linked}",
            str(obj), str(root / "shift_idiom_test.cmd"),
        ], root)
        listing = out / f"shift_idiom_{optimization}.dis.txt"
        run([str(disassembler), str(linked)], root, listing)
        text = listing.read_text(encoding="utf-8", errors="replace")
        expected = {"shift_t_div2": 0x1f, "shift_t_div4": 0x1e}
        for name, count in expected.items():
            body = function_text(text, name)
            if body.count("LSRL         ACC, T") != 1:
                raise RuntimeError(f"{optimization} {name} lost its single LSRL ACC,T")
            immediate = re.search(
                r"MOV\s+T, #0x([0-9a-fA-F]{4})", body,
            )
            if immediate is None or int(immediate.group(1), 16) != count:
                raise RuntimeError(
                    f"{optimization} {name} lost MOV T,#{count:#x}"
                )
        for name in PAIR_COMPILER_FUNCTIONS:
            body = function_text(text, name)
            if body.count("ASR64        ACC:P, 16") != 2:
                raise RuntimeError(
                    f"{optimization} {name} lost adjacent ASR64 #16 pair"
                )
            if "ASR64        ACC:P, 16\n" not in body:
                raise RuntimeError(f"{optimization} {name} pair text changed")
        addresses = symbol_addresses(text, COMPILER_FUNCTIONS)
        run([str(stripper), "--postlink", str(linked)], root)
        subjects.append(Subject(linked, "compiler", addresses))

    obj = out / "shift_idiom_validation.obj"
    linked = out / "shift_idiom_validation.out"
    run([
        str(compiler), *COMMON, "--compile_only", f"--output_file={obj}",
        str(root / "shift_idiom_validation.asm"),
    ], root)
    run([
        str(compiler), *COMMON, "--run_linker",
        "--entry_point=shift_validation_entry", f"--output_file={linked}",
        str(obj), str(root / "shift_idiom_validation.cmd"),
    ], root)
    listing = out / "shift_idiom_validation.dis.txt"
    run([str(disassembler), str(linked)], root, listing)
    text = listing.read_text(encoding="utf-8", errors="replace")
    for name in MANUAL_FUNCTIONS + VALIDATION_LABELS:
        if not re.search(rf"^[0-9a-fA-F]+\s+{re.escape(name)}:\s*$",
                         text, re.MULTILINE):
            raise RuntimeError(f"validation disassembly lost {name}")
    if text.count("LSRL         ACC, T") != 13:
        raise RuntimeError("validation fixture must contain thirteen LSRL ACC,T sites")
    if text.count("ASR64        ACC:P, 16") != 17 or \
            text.count("ASR64        ACC:P, 15") != 2:
        raise RuntimeError("validation fixture lost its nineteen ASR64 sites")
    addresses = symbol_addresses(
        text, tuple(dict.fromkeys(MANUAL_FUNCTIONS + VALIDATION_LABELS)),
    )
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
    shutil.copy2(root / "ShiftIdiomTest.java", run_dir / "scripts")
    is_validation = subject.kind == "validation"
    if is_validation:
        shutil.copy2(root / "ShiftIdiomSeedStale.java", run_dir / "scripts")

    script_log = run_dir / "script.log"
    console_log = run_dir / "console.log"
    command = [
        str(ghidra), str(run_dir / "project"), "shift-idiom-test",
        "-import", str(subject.path),
        "-processor", "tms320c28:LE:32:default", "-cspec", "default",
        "-scriptPath", str(run_dir / "scripts"),
    ]
    address_args = [f"{name}={address}" for name, address in subject.addresses.items()]
    if is_validation:
        command.extend([
            "-preScript", str(run_dir / "scripts" / "ShiftIdiomSeedStale.java"),
            *address_args,
        ])
    command.extend([
        "-postScript", str(run_dir / "scripts" / "ShiftIdiomTest.java"),
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
                if script.count("SHIFT_PROGRAM_PASS=") == 1:
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
    if not passed or script.count("SHIFT_PROGRAM_PASS=") != 1:
        sys.stderr.write(console_log.read_text(encoding="utf-8", errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless shift test failed for {subject.path.name}")
    if "ERROR" in script or "Exception" in script or "AssertionError" in script:
        sys.stderr.write(script)
        raise RuntimeError(f"shift script logged an error for {subject.path.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines() if "SHIFT_" in line
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
    output = []
    for index, subject in enumerate(subjects, 1):
        markers = headless(
            root, work, args.ghidra_headless.resolve(), subject,
            index, args.timeout,
        )
        output.append(markers)
        print(markers)
    aggregate = "\n".join(output)
    required = {
        "SHIFT_COMPILER_DIRECT_SITES=2": 2,
        "SHIFT_COMPILER_UNREACHABLE_BLOCKS=0": 2,
        "SHIFT_MANUAL_DIRECT_SITES=5": 1,
        "SHIFT_MANUAL_NEAR_MISSES=8": 1,
        "SHIFT_PAIR_COMPILER_PAIRS=3": 2,
        "SHIFT_PAIR_SIGN_EXTENSION_DECOMPILATIONS=3": 2,
        "SHIFT_PAIR_MANUAL_PAIRS=2": 1,
        "SHIFT_PAIR_MANUAL_NEAR_MISSES=8": 1,
        "SHIFT_STALE_CONTEXT_REVOKED=2": 1,
        "SHIFT_PAIR_STALE_CONTEXT_REVOKED=2": 1,
    }
    for marker, count in required.items():
        actual = aggregate.count(marker)
        if actual != count:
            raise RuntimeError(f"expected {count} occurrences of {marker}, got {actual}")
    print(f"SHIFT_GHIDRA_PROGRAMS={len(subjects)}")
    print("SHIFT_IDIOM_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
