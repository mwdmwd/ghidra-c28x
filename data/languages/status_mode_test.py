#!/usr/bin/env python3
"""Build and audit SXM low-half plus finite OVM arithmetic fixtures."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

COMMON = ("--float_support=fpu32", "--abi=eabi")
COMPILER_NAMES = (
    "status_consume16",
    "status_low_combine_store",
    "status_low_combine_pass",
    "status_low_shift_store",
    "status_low_shift_pass",
    "status_low_shift15_store",
    "status_full_unsigned",
    "status_full_signed",
    "status_full_signed_shift0",
    "status_full_unsigned_shift15",
    "status_full_signed_shift15",
    "status_mul6_signed",
    "status_low_volatile",
    "status_full_volatile",
    "status_callee",
    "status_unequal_calls",
    "status_post_known_indirect",
    "status_post_call_sum",
    "status_post_call_integer",
    "status_post_ambiguous_indirect",
    "status_nested_direct",
    "status_mode_entry",
)
VALIDATION_NAMES = (
    "status_validation_entry",
    "status_manual_callee",
    "status_ovm_set_add",
    "status_ovm_set_call_add",
    "status_ovm_clear_add",
    "status_ovm_conflict_rejoin",
    "status_ovm_ambiguous_call",
    "status_lc_positive",
    "status_lc_target",
    "status_lc_wrong_model",
    "status_lcr_target",
    "status_ffc_positive",
    "status_ffc_target",
    "status_ffc_wrong_model",
    "status_ffc_wrong_target",
    "status_non_c_entry",
    "status_alternate_ingress",
    "status_alternate_source",
    "status_alternate_addu",
    "status_sxm_unknown_full",
    "status_unproved_entry",
    "status_stale_function",
    "status_stale_addu",
    "status_stale_nonaddu",
    "status_addcl_boundary_zero",
    "status_addcl_setc_sxm_preserve",
    "status_addcl_clrc_sxm_preserve",
    "status_addcl_setc_multibit_preserve",
    "status_addcl_clrc_multibit_preserve",
    "status_addcl_setc_includes_ovm",
    "status_addcl_clrc_includes_ovm",
    "status_addcl_conflict_rejoin",
    "status_addcl_ambiguous_call",
    "status_addcl_st0_write",
    "status_addcl_alternate_ingress",
    "status_addcl_alternate_source",
    "status_addcl_alternate_site",
    "status_addcl_unproved_entry",
    "status_stale_addcl_function",
    "status_stale_addcl",
    "status_addl_pm_boundary_zero",
    "status_addl_pm_explicit_clear",
    "status_addl_pm_setc_sxm_preserve",
    "status_addl_pm_clrc_sxm_preserve",
    "status_addl_pm_setc_multibit_preserve",
    "status_addl_pm_clrc_multibit_preserve",
    "status_addl_pm_setc_ovm",
    "status_addl_pm_conflict_rejoin",
    "status_addl_pm_ambiguous_call",
    "status_addl_pm_st0_write",
    "status_addl_pm_alternate_ingress",
    "status_addl_pm_alternate_source",
    "status_addl_pm_alternate_site",
    "status_addl_pm_unproved_entry",
    "status_stale_addl_pm_function",
    "status_stale_addl_pm",
    "status_stale_addl_loc32_function",
    "status_stale_addl_loc32",
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
                command,
                cwd=cwd,
                stdout=stream,
                stderr=subprocess.STDOUT,
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
            disassembly,
            re.MULTILINE,
        )
        if match is None:
            raise RuntimeError(f"disassembly lost symbol {name}")
        result[name] = match.group(1).lower()
    return result


def function_text(disassembly: str, name: str) -> str:
    marker = re.search(
        rf"^[0-9a-fA-F]+\s+{re.escape(name)}:\s*$", disassembly, re.MULTILINE
    )
    if marker is None:
        raise RuntimeError(f"disassembly lost function {name}")
    next_symbol = re.search(
        r"^[0-9a-fA-F]+\s+status_[A-Za-z0-9_]+:\s*$",
        disassembly[marker.end() :],
        re.MULTILINE,
    )
    end = marker.end() + next_symbol.start() if next_symbol else len(disassembly)
    return disassembly[marker.start() : end]


def require_pattern(body: str, pattern: str, where: str) -> None:
    if re.search(pattern, body, re.MULTILINE) is None:
        raise RuntimeError(f"{where} lost pattern {pattern!r}\n{body}")


def check_cspec(root: Path) -> None:
    path = root / "tms320c28.cspec"
    tree = ET.parse(path)
    root_node = tree.getroot()
    tracked = root_node.findall("./context_data/tracked_set/set")
    entries = {(node.get("name"), node.get("val")) for node in tracked}
    required = {("PM", "0"), ("OVM", "0"), ("PAGE0", "0")}
    if entries != required:
        raise RuntimeError(f"TI C entry context changed unexpectedly: {entries}")
    if any(name == "SXM" for name, _ in entries):
        raise RuntimeError("SXM must not have a presumed TI C boundary value")

    prototypes = root_node.findall(".//prototype")
    by_name = {node.get("name"): node for node in prototypes}
    for name in ("__stdcall", "__lc", "__ffc"):
        prototype = by_name.get(name)
        if prototype is None:
            raise RuntimeError(f"missing {name} prototype")
        killed = {node.get("name") for node in prototype.findall("./killedbycall/register")}
        if not {"ST0", "ST1"}.issubset(killed):
            raise RuntimeError(f"{name} no longer kills complete ST0/ST1")

    default_body = " ".join(
        "".join(node.itertext())
        for node in by_name["__stdcall"].findall('./pcode[@inject="uponreturn"]/body')
    )
    lc_body = " ".join(
        "".join(node.itertext())
        for node in by_name["__lc"].findall('./pcode[@inject="uponreturn"]/body')
    )
    ffc_body = " ".join(
        "".join(node.itertext())
        for node in by_name["__ffc"].findall('./pcode[@inject="uponreturn"]/body')
    )
    if "SP = SP - 2" not in default_body or "RPC = *:4 SP" not in default_body:
        raise RuntimeError("default completed-call RPC/stack injection changed")
    if "SP = SP - 2" not in lc_body or "RPC" in lc_body:
        raise RuntimeError("LC completed-call stack injection changed")
    if ffc_body.strip():
        raise RuntimeError("FFC unexpectedly gained an upon-return stack injection")
    if "OVM" in default_body + lc_body + ffc_body:
        raise RuntimeError("OVM must not be globally forced by completed-call injection")

    print("STATUS_MODE_CSPEC_ENTRY_PM_OVM_PAGE0=PASS")
    print("STATUS_MODE_CSPEC_SXM_UNPRESUMED=PASS")
    print("STATUS_MODE_CSPEC_CALL_STACK_RPC_PRESERVED=PASS")


def build(
    root: Path, out: Path, compiler: Path, disassembler: Path, stripper: Path
) -> list[Subject]:
    shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True)
    subjects: list[Subject] = []

    for optimization in ("o0", "o2"):
        obj = out / f"status_mode_{optimization}.obj"
        linked = out / f"status_mode_{optimization}.out"
        run(
            [
                str(compiler),
                *COMMON,
                "--c11",
                f"-{optimization.upper()}",
                "--symdebug:none",
                "--compile_only",
                f"--output_file={obj}",
                str(root / "status_mode_test.c"),
            ],
            root,
        )
        run(
            [
                str(compiler),
                *COMMON,
                "--run_linker",
                "--entry_point=status_mode_entry",
                f"--output_file={linked}",
                str(obj),
                str(root / "status_mode_test.cmd"),
            ],
            root,
        )
        listing = out / f"status_mode_{optimization}.dis.txt"
        run([str(disassembler), str(linked)], root, listing)
        text = listing.read_text(encoding="utf-8", errors="replace")
        addresses = symbol_addresses(text, COMPILER_NAMES)

        for name in ("status_low_combine_store", "status_low_combine_pass"):
            body = function_text(text, name)
            require_pattern(body, r"\bMOV\s+ACC, .*<< 8", f"{optimization} {name}")
            require_pattern(body, r"\bADD\s+AL,", f"{optimization} {name}")
        for name in ("status_low_shift_store", "status_low_shift_pass"):
            require_pattern(
                function_text(text, name), r"\bMOV\s+ACC, .*<< 1", f"{optimization} {name}"
            )
        require_pattern(
            function_text(text, "status_low_shift15_store"),
            r"\bMOV\s+ACC, .*<< 15",
            f"{optimization} status_low_shift15_store",
        )

        full_modes = {
            "status_full_unsigned": "CLRC",
            "status_full_signed": "SETC",
            "status_full_signed_shift0": "SETC",
            "status_full_unsigned_shift15": "CLRC",
            "status_full_signed_shift15": "SETC",
        }
        for name, mode in full_modes.items():
            body = function_text(text, name)
            require_pattern(body, rf"\b{mode}\s+SXM", f"{optimization} {name}")
            require_pattern(body, r"\bMOV\s+ACC, AL", f"{optimization} {name}")

        mul6 = function_text(text, "status_mul6_signed")
        if len(re.findall(r"\bADDL\s+ACC,\s*P\s*<<\s*PM", mul6)) != 1:
            raise RuntimeError(
                f"{optimization} status_mul6_signed lost exact ADDL ACC,P << PM"
            )
        require_pattern(mul6, r"\bMOVL\s+P,\s*ACC", f"{optimization} mul6")
        require_pattern(mul6, r"\bSPM\s+#1", f"{optimization} mul6")
        require_pattern(mul6, r"\bLSL\s+ACC,\s*2", f"{optimization} mul6")

        require_pattern(
            function_text(text, "status_low_volatile"),
            r"\bMOV\s+ACC, @[^\n]+<< 8",
            f"{optimization} low volatile",
        )
        full_volatile = function_text(text, "status_full_volatile")
        require_pattern(full_volatile, r"\bCLRC\s+SXM", f"{optimization} full volatile")
        require_pattern(full_volatile, r"\bMOV\s+ACC, @[^\n]+<< 8", f"{optimization} full volatile")

        for name in (
            "status_post_call_sum",
            "status_post_call_integer",
            "status_unequal_calls",
            "status_nested_direct",
            "status_post_known_indirect",
            "status_post_ambiguous_indirect",
        ):
            body = function_text(text, name)
            if body.count("ADDU") != 1:
                raise RuntimeError(f"{optimization} {name} lost its single ADDU")
        unequal = function_text(text, "status_unequal_calls")
        if unequal.count("LCR") < 2 or "SB" not in unequal:
            raise RuntimeError(f"{optimization} unequal-call fixture lost branch/calls")
        for name in ("status_post_known_indirect", "status_post_ambiguous_indirect"):
            require_pattern(
                function_text(text, name), r"LCR\s+\*XAR7", f"{optimization} {name}"
            )

        # Strip all invocation evidence before Ghidra import; addresses above
        # are the only metadata passed to the focused scripts.
        run([str(stripper), "--postlink", str(linked)], root)
        subjects.append(Subject(linked, "compiler", addresses))

    obj = out / "status_mode_validation.obj"
    linked = out / "status_mode_validation.out"
    run(
        [
            str(compiler),
            *COMMON,
            "--compile_only",
            f"--output_file={obj}",
            str(root / "status_mode_validation.asm"),
        ],
        root,
    )
    run(
        [
            str(compiler),
            *COMMON,
            "--run_linker",
            "--entry_point=status_validation_entry",
            f"--output_file={linked}",
            str(obj),
            str(root / "status_mode_validation.cmd"),
        ],
        root,
    )
    listing = out / "status_mode_validation.dis.txt"
    run([str(disassembler), str(linked)], root, listing)
    text = listing.read_text(encoding="utf-8", errors="replace")
    addresses = symbol_addresses(text, VALIDATION_NAMES)
    if text.count("ADDU         ACC, AR6") != 13:
        raise RuntimeError("validation fixture lost its thirteen ADDU sites")
    if text.count("ADDCL        ACC, XAR6") != 13:
        raise RuntimeError("validation fixture lost its thirteen ADDCL sites")
    if len(re.findall(r"\bADDL\s+ACC,\s*P\s*<<\s*PM", text)) != 13:
        raise RuntimeError(
            "validation fixture lost its thirteen exact ADDL ACC,P << PM sites"
        )
    if re.search(
        r"^[0-9a-fA-F]+\s+status_stale_addl_loc32:\s*$"
        r"[\s\S]*?\bADDL\s+ACC,\s*XAR6",
        text,
        re.MULTILINE,
    ) is None:
        raise RuntimeError("validation fixture lost stale non-candidate ADDL loc32")
    for marker in (
        "SETC         OVM",
        "CLRC         OVM",
        "SETC         SXM|TC",
        "CLRC         SXM|TC",
        "SETC         SXM|OVM",
        "CLRC         SXM|OVM",
        "LCR          *XAR7",
        "LC           0x",
        "FFC          XAR7",
        "POP          ST0",
        "MOV          ACC, AR6 << 8",
    ):
        if marker not in text:
            raise RuntimeError(f"validation disassembly lost {marker}")
    run([str(stripper), "--postlink", str(linked)], root)
    subjects.append(Subject(linked, "validation", addresses))

    print("STATUS_MODE_COMPILER_OPT_LEVELS=2")
    print("STATUS_MODE_COMPILER_IMMEDIATE_SHIFTS=0,1,8,15")
    print("STATUS_MODE_COMPILER_ADDL_PM_SITES=1")
    print("STATUS_MODE_VALIDATION_ADDU_SITES=13")
    print("STATUS_MODE_VALIDATION_ADDCL_SITES=13")
    print("STATUS_MODE_VALIDATION_ADDL_PM_SITES=13")
    return subjects


def headless(
    root: Path,
    work: Path,
    ghidra: Path,
    subject: Subject,
    index: int,
    timeout_seconds: int,
) -> str:
    run_dir = work / f"{index}-{subject.path.stem}"
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    shutil.copy2(root / "StatusModeTest.java", run_dir / "scripts")
    if subject.kind == "validation":
        shutil.copy2(root / "StatusModeSeedStale.java", run_dir / "scripts")

    script_log = run_dir / "script.log"
    console_log = run_dir / "console.log"
    command = [
        "timeout",
        "--signal=TERM",
        "--kill-after=5s",
        f"{timeout_seconds}s",
        str(ghidra),
        str(run_dir / "project"),
        "status-mode-test",
        "-import",
        str(subject.path),
        "-processor",
        "tms320c28:LE:32:default",
        "-cspec",
        "default",
        "-scriptPath",
        str(run_dir / "scripts"),
    ]
    address_args = [f"{name}={address}" for name, address in subject.addresses.items()]
    if subject.kind == "validation":
        command.extend(
            [
                "-preScript",
                str(run_dir / "scripts" / "StatusModeSeedStale.java"),
                *address_args,
            ]
        )
    command.extend(
        [
            "-postScript",
            str(run_dir / "scripts" / "StatusModeTest.java"),
            subject.kind,
            *address_args,
            "-log",
            str(run_dir / "ghidra.log"),
            "-scriptlog",
            str(script_log),
            "-analysisTimeoutPerFile",
            "120",
            "-overwrite",
            "-deleteProject",
        ]
    )
    env = os.environ.copy()
    env.update(
        {
            "HOME": str(run_dir / "home"),
            "XDG_CONFIG_HOME": str(run_dir / "config"),
            "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join(
                (
                    f"-Dapplication.tempdir={run_dir / 'tmp'}",
                    f"-Dapplication.cachedir={run_dir / 'cache'}",
                    f"-Djava.io.tmpdir={run_dir / 'tmp'}",
                )
            ),
        }
    )
    with console_log.open("w", encoding="utf-8") as output:
        process = subprocess.run(
            command,
            cwd=root,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            check=False,
        )

    script = (
        script_log.read_text(encoding="utf-8", errors="replace")
        if script_log.exists()
        else ""
    )
    if process.returncode or script.count("STATUS_MODE_PROGRAM_PASS=") != 1:
        sys.stderr.write(console_log.read_text(encoding="utf-8", errors="replace"))
        sys.stderr.write(script)
        raise RuntimeError(f"headless status-mode test failed for {subject.path.name}")
    if "AssertionError" in script or "Exception" in script or " ERROR " in script:
        sys.stderr.write(script)
        raise RuntimeError(f"status-mode script logged an error for {subject.path.name}")
    return "\n".join(
        line.split("> ", 1)[-1].strip()
        for line in script.splitlines()
        if "STATUS_MODE_" in line
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
    check_cspec(root)
    subjects = build(
        root,
        args.build.resolve(),
        args.cl2000.resolve(),
        args.dis2000.resolve(),
        args.strip2000.resolve(),
    )
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)
    for index, subject in enumerate(subjects, 1):
        print(
            headless(
                root,
                work,
                args.ghidra_headless.resolve(),
                subject,
                index,
                args.timeout,
            )
        )
    print(f"STATUS_MODE_GHIDRA_PROGRAMS={len(subjects)}")
    print("STATUS_MODE_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
