#!/usr/bin/env python3
"""Build and audit proved full-width RPT/SUBCUL division fixtures."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import time

COMMON = ("--float_support=fpu32", "--abi=eabi")


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


def build(root: Path, out: Path, compiler: Path, disassembler: Path) -> list[Path]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subjects: list[Path] = []
    for optimization in ("o0", "o2"):
        obj = out / f"division_idiom_{optimization}.obj"
        linked = out / f"division_idiom_{optimization}.out"
        run([
            str(compiler), *COMMON, "--c11", f"-{optimization.upper()}",
            "--symdebug:none", "--compile_only", f"--output_file={obj}",
            str(root / "division_idiom_test.c"),
        ], root)
        run([
            str(compiler), *COMMON, "--run_linker",
            "--entry_point=division_idiom_entry", f"--output_file={linked}",
            str(obj), str(root / "division_idiom_test.cmd"),
        ], root)
        listing = out / f"division_idiom_{optimization}.dis.txt"
        run([str(disassembler), str(linked)], root, listing)
        text = listing.read_text(encoding="utf-8", errors="replace")
        if text.count("SUBCUL") != 5 or text.count("RPT          #31") != 5:
            raise RuntimeError(
                f"{optimization} compiler fixture lost five full-width divisions"
            )
        for marker in (
            "div32_const10", "mod32_const10", "div32_variable_nonzero",
            "divmod32_variable_nonzero",
        ):
            if marker not in text:
                raise RuntimeError(f"{optimization} disassembly lost {marker}")
        subjects.append(linked)

    obj = out / "division_validation.obj"
    linked = out / "division_validation.out"
    run([
        str(compiler), *COMMON, "--compile_only", f"--output_file={obj}",
        str(root / "division_validation.asm"),
    ], root)
    run([
        str(compiler), *COMMON, "--run_linker",
        "--entry_point=division_validation_entry", f"--output_file={linked}",
        str(obj), str(root / "division_validation.cmd"),
    ], root)
    listing = out / "division_validation.dis.txt"
    run([str(disassembler), str(linked)], root, listing)
    text = listing.read_text(encoding="utf-8", errors="replace")
    if text.count("SUBCUL") != 11:
        raise RuntimeError("validation fixture must contain eleven SUBCUL sites")
    for marker in (
        "division_positive_const", "division_positive_variable",
        "division_near_repeat_count", "division_near_initial_acc",
        "division_near_zero_divisor", "division_near_unknown_divisor",
        "division_near_mutated_divisor", "division_near_memory_alias",
        "division_near_intervening_flow", "division_near_alternate_ingress",
        "division_near_missing_dividend",
    ):
        if marker not in text:
            raise RuntimeError(f"validation disassembly lost {marker}")
    subjects.append(linked)
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


def headless(root: Path, work: Path, ghidra: Path, subject: Path,
             index: int, timeout_seconds: int) -> str:
    run_dir = work / f"{index}-{subject.stem}"
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "DivisionIdiomTest.java", run_dir / "scripts")

    script_log = run_dir / "script.log"
    console_log = run_dir / "console.log"
    command = [
        str(ghidra), str(run_dir / "project"), "division-idiom-test",
        "-import", str(subject),
        "-processor", "tms320c28:LE:32:default", "-cspec", "default",
        "-scriptPath", str(run_dir / "scripts"),
        "-postScript", str(run_dir / "scripts" / "DivisionIdiomTest.java"),
        "-log", str(run_dir / "ghidra.log"),
        "-scriptlog", str(script_log),
        "-analysisTimeoutPerFile", "90", "-overwrite", "-deleteProject",
    ]
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
                if script.count("DIVISION_PROGRAM_PASS=") == 1:
                    passed = True
                    break
            if process.poll() is not None:
                break
            time.sleep(0.5)
        if passed:
            # Some Ghidra builds keep a non-daemon analysis thread alive after
            # the final script marker.  The isolated project has already served
            # its purpose; terminate the complete process group deterministically.
            time.sleep(0.5)
        terminate_group(process)

    script = script_log.read_text(encoding="utf-8", errors="replace") \
        if script_log.exists() else ""
    if not passed or script.count("DIVISION_PROGRAM_PASS=") != 1:
        sys.stderr.write(console_log.read_text(encoding="utf-8", errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless division test failed for {subject.name}")
    if "ERROR" in script or "Exception" in script or "AssertionError" in script:
        sys.stderr.write(script)
        raise RuntimeError(f"division script logged an error for {subject.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines() if "DIVISION_" in line
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--cl2000", type=Path, required=True)
    parser.add_argument("--dis2000", type=Path, required=True)
    parser.add_argument("--ghidra-headless", type=Path, required=True)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=180)
    args = parser.parse_args()

    root = args.root.resolve()
    subjects = build(
        root, args.build.resolve(), args.cl2000.resolve(), args.dis2000.resolve()
    )
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for index, subject in enumerate(subjects, 1):
        print(headless(
            root, work, args.ghidra_headless.resolve(), subject, index, args.timeout
        ))
    print(f"DIVISION_GHIDRA_PROGRAMS={len(subjects)}")
    print("DIVISION_IDIOM_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
