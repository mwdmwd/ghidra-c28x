#!/usr/bin/env python3
"""Build and audit finite typed code-pointer target discovery."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import re
import shutil
import signal
import subprocess
import sys
import time

COMMON = ("--float_support=fpu32", "--abi=eabi")

SYMBOLS = (
    # Typed destinations and initialized support values.
    "cp_struct_root", "cp_struct_callback",
    "cp_slot_standalone", "cp_slot_initialized",
    "cp_slot_repeat_first", "cp_slot_repeat_second",
    "cp_slot_propagated", "cp_slot_existing", "cp_slot_equal_merge",
    "cp_slot_scalar", "cp_slot_object_pointer", "cp_slot_zero",
    "cp_slot_all_ones", "cp_slot_uninitialized", "cp_slot_nonexec",
    "cp_slot_invalid", "cp_slot_interior", "cp_slot_partial",
    "cp_slot_dynamic", "cp_slot_clobber", "cp_slot_conflict",
    "cp_slot_call", "cp_slot_alternate", "cp_slot_composed",
    "cp_data_object", "cp_all_ones_value",
    # Positive and negative store sites.
    "cp_store_standalone_site", "cp_store_struct_site",
    "cp_store_initialized_site", "cp_store_repeat_first_site",
    "cp_store_repeat_second_site", "cp_store_propagated_site",
    "cp_store_existing_site", "cp_store_equal_merge_site",
    "cp_near_scalar_site", "cp_near_object_pointer_site",
    "cp_near_zero_site", "cp_near_all_ones_site",
    "cp_near_uninitialized_site", "cp_near_nonexec_site",
    "cp_near_invalid_site", "cp_near_interior_site",
    "cp_near_partial_store_site", "cp_near_dynamic_site",
    "cp_near_clobber_site", "cp_near_conflict_site",
    "cp_near_call_site", "cp_near_alternate_site",
    "cp_near_composed_site",
    # Target/function boundaries used by the regression.
    "cp_runtime_target", "cp_static_target", "cp_existing_target",
    "cp_other_target", "cp_scalar_lookalike_target",
    "cp_object_lookalike_target", "cp_interior_container",
    "cp_interior_target", "cp_invalid_target", "cp_near_all_ones",
)


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


def symbol_addresses(disassembly: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in SYMBOLS:
        match = re.search(
            rf"^([0-9a-fA-F]+)\s+{re.escape(name)}:\s*$",
            disassembly, re.MULTILINE,
        )
        if match is None:
            raise RuntimeError(f"validation disassembly lost symbol {name}")
        result[name] = match.group(1).lower()
    return result


def build(root: Path, out: Path, compiler: Path, disassembler: Path,
          stripper: Path) -> tuple[Path, dict[str, str]]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    obj = out / "code_pointer_validation.obj"
    linked = out / "code_pointer_validation.out"
    listing = out / "code_pointer_validation.dis.txt"
    run([
        str(compiler), *COMMON, "--compile_only", f"--output_file={obj}",
        str(root / "code_pointer_validation.asm"),
    ], root)
    run([
        str(compiler), *COMMON, "--run_linker",
        "--entry_point=cp_validation_entry", f"--output_file={linked}",
        str(obj), str(root / "code_pointer_validation.cmd"),
    ], root)
    run([str(disassembler), str(linked)], root, listing)
    text = listing.read_text(encoding="utf-8", errors="replace")
    addresses = symbol_addresses(text)
    if text.count("MOVL         @") < 22:
        raise RuntimeError("validation fixture lost full-width direct stores")
    if "MOV          @" not in text:
        raise RuntimeError("validation fixture lost partial-width store")
    run([str(stripper), "--postlink", str(linked)], root)
    return linked, addresses


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
             addresses: dict[str, str], timeout_seconds: int) -> str:
    shutil.rmtree(work, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (work / name).mkdir(parents=True, exist_ok=True)
    for script in ("CodePointerTestSetup.java", "CodePointerTest.java"):
        shutil.copy2(root / script, work / "scripts" / script)

    address_args = [f"{name}={addresses[name]}" for name in SYMBOLS]
    script_log = work / "script.log"
    console_log = work / "console.log"
    command = [
        str(ghidra), str(work / "project"), "code-pointer-test",
        "-import", str(subject),
        "-processor", "tms320c28:LE:32:default", "-cspec", "default",
        "-scriptPath", str(work / "scripts"),
        "-preScript", str(work / "scripts" / "CodePointerTestSetup.java"),
        *address_args,
        "-postScript", str(work / "scripts" / "CodePointerTest.java"),
        *address_args,
        "-log", str(work / "ghidra.log"),
        "-scriptlog", str(script_log),
        "-analysisTimeoutPerFile", "120", "-overwrite", "-deleteProject",
    ]
    env = os.environ.copy()
    env.update({
        "HOME": str(work / "home"),
        "XDG_CONFIG_HOME": str(work / "config"),
        "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join((
            f"-Dapplication.tempdir={work / 'tmp'}",
            f"-Dapplication.cachedir={work / 'cache'}",
            f"-Djava.io.tmpdir={work / 'tmp'}",
        )),
    })
    with console_log.open("wb") as output:
        process = subprocess.Popen(
            command, cwd=root, env=env, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                break
            if script_log.exists() and \
                    script_log.read_text(encoding="utf-8", errors="replace").count(
                        "CODE_POINTER_TEST_PASS=all") == 1:
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    terminate_group(process)
                break
            time.sleep(0.25)
        else:
            terminate_group(process)
            raise RuntimeError(f"headless code-pointer test timed out after {timeout_seconds}s")

    if process.returncode:
        console = console_log.read_text(encoding="utf-8", errors="replace")
        script = script_log.read_text(encoding="utf-8", errors="replace") \
            if script_log.exists() else ""
        raise RuntimeError(
            f"headless code-pointer test failed ({process.returncode})\n"
            f"{console[-16000:]}\n{script[-16000:]}"
        )
    script = script_log.read_text(encoding="utf-8", errors="replace")
    if script.count("CODE_POINTER_TEST_PASS=all") != 1:
        console = console_log.read_text(encoding="utf-8", errors="replace")
        raise RuntimeError(
            "headless code-pointer regression did not emit exactly one pass marker\n" +
            console[-16000:] + "\n" + script[-16000:]
        )
    return "\n".join(
        line for line in script.splitlines()
        if "CODE_POINTER_" in line
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
    parser.add_argument("--timeout", type=int, default=240)
    args = parser.parse_args()

    root = args.root.resolve()
    subject, addresses = build(
        root, args.build.resolve(), args.cl2000.resolve(),
        args.dis2000.resolve(), args.strip2000.resolve(),
    )
    markers = headless(
        root, args.work.resolve(), args.ghidra_headless.resolve(), subject,
        addresses, args.timeout,
    )
    print(markers)
    required = (
        "CODE_POINTER_ACCEPTED_STORES=8",
        "CODE_POINTER_REJECTED_STORES=15",
        "CODE_POINTER_IDEMPOTENT_RERUNS=2",
        "CODE_POINTER_MARKER_REVOCATION=1",
        "CODE_POINTER_CALL_EDGES_FABRICATED=0",
        "CODE_POINTER_TEST_PASS=all",
    )
    for marker in required:
        if markers.count(marker) != 1:
            raise RuntimeError(f"expected one {marker}, got {markers.count(marker)}")
    print("CODE_POINTER_GHIDRA_PROGRAMS=1")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
