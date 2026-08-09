#!/usr/bin/env python3
"""Deterministic headless regression for the C28x device profile and ROM importer."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from typing import Iterable

FIRMWARE_BASE = 0x1000
FIRMWARE_WORDS = 0x200


def put_word(image: bytearray, word_address: int, value: int) -> None:
    index = (word_address - FIRMWARE_BASE) * 2
    if index < 0 or index + 2 > len(image):
        raise ValueError(f"word 0x{word_address:x} is outside fixture")
    image[index] = value & 0xFF
    image[index + 1] = (value >> 8) & 0xFF


def fixture_image() -> bytearray:
    image = bytearray(FIRMWARE_WORDS * 2)
    # Explicit executable copy: NOP; LRETR.
    put_word(image, 0x1040, 0x7700)
    put_word(image, 0x1041, 0x0006)

    # Signed-length .cinit table with both destination encodings.
    put_word(image, 0x1080, 3)
    put_word(image, 0x1081, 0x2020)
    put_word(image, 0x1082, 0x1111)
    put_word(image, 0x1083, 0x2222)
    put_word(image, 0x1084, 0x3333)
    put_word(image, 0x1085, 0xFFFE)  # -2 => 32-bit destination
    put_word(image, 0x1086, 0x2030)
    put_word(image, 0x1087, 0x0000)
    put_word(image, 0x1088, 0x4444)
    put_word(image, 0x1089, 0x5555)
    put_word(image, 0x108A, 0)
    return image


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def base_profile() -> dict:
    return {
        "schema": "tms320c28-device-profile",
        "version": 1,
        "profileName": "Synthetic-profile-test",
        "addressUnitBytes": 2,
        "blocks": [
            {
                "name": "TEST_FLASH",
                "start": 0x1000,
                "words": 0x200,
                "kind": "flash",
                "read": True,
                "write": False,
                "execute": True,
                "volatile": False,
                "source": "synthetic profile test",
            },
            {
                "name": "TEST_RAM",
                "start": 0x2000,
                "words": 0x100,
                "kind": "ram",
                "read": True,
                "write": True,
                "execute": False,
                "volatile": False,
                "source": "synthetic profile test",
            },
            {
                "name": "TEST_PERIPH",
                "start": 0x3000,
                "words": 0x40,
                "kind": "peripheral",
                "read": True,
                "write": True,
                "execute": False,
                "volatile": True,
                "source": "synthetic profile test",
            },
            {
                "name": "TEST_ROM",
                "start": 0x4000,
                "words": 0x40,
                "kind": "rom",
                "read": True,
                "write": False,
                "execute": True,
                "volatile": False,
                "source": "synthetic profile test",
            },
        ],
        "baseLabels": [
            {
                "symbol": "TEST_PERIPH_BASE",
                "displayName": "Synthetic peripheral",
                "address": 0x3000,
            }
        ],
        "registers": [
            {
                "namespace": "TESTPERIPH",
                "name": "REG16",
                "address": 0x3004,
                "widthBits": 16,
                "description": "Synthetic 16-bit register",
                "fields": [
                    {"name": "ENABLE", "shift": 0, "size": 1, "description": "Enable"}
                ],
            },
            {
                "namespace": "TESTPERIPH",
                "name": "REG32",
                "address": 0x3006,
                "widthBits": 32,
                "description": "Synthetic 32-bit register",
                "fields": [
                    {"name": "VALUE", "shift": 0, "size": 16, "description": "Value"}
                ],
            },
        ],
        "romEvidence": {
            "default": "uninitialized",
            "rawDumpSupported": True,
            "tiGoldenIsOptional": True,
            "warning": "synthetic test",
        },
        "provenance": {"generatedBy": "profile_tests.py"},
    }


def base_workspace(image_hash: str) -> dict:
    return {
        "schema": "tms320c28-firmware-workspace",
        "version": 1,
        "workspaceName": "Synthetic-workspace-test",
        "deviceProfile": "Synthetic-profile-test",
        "firmware": {
            "blockName": "TEST_FLASH_IMAGE",
            "wordBase": FIRMWARE_BASE,
            "byteLength": FIRMWARE_WORDS * 2,
            "sha256": image_hash,
            "read": True,
            "write": False,
            "execute": True,
        },
        "copyRecovery": {
            "cinit": {
                "table": 0x1080,
                "maxRecords": 8,
                "maxWordsPerRecord": 16,
                "allowedDestinationRanges": [{"start": 0x2000, "words": 0x100}],
                "evidence": "synthetic signed-length cinit parser",
            },
            "explicit": [
                {
                    "name": "TEST_CODE",
                    "source": 0x1040,
                    "destination": 0x2040,
                    "words": 2,
                    "executable": True,
                    "evidence": "synthetic explicit ascending copy",
                }
            ],
        },
        "analysisSeeds": {"disassembly": [0x2040], "functions": [0x2040]},
    }


def write_case(
    directory: Path, image: bytearray, profile: dict, workspace: dict
) -> tuple[Path, Path, Path]:
    directory.mkdir(parents=True, exist_ok=True)
    image_path = directory / "fixture.bin"
    profile_path = directory / "profile.json"
    workspace_path = directory / "workspace.json"
    image_path.write_bytes(image)
    profile_path.write_text(json.dumps(profile, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    workspace_path.write_text(
        json.dumps(workspace, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return image_path, profile_path, workspace_path


def run_headless(
    *,
    ghidra: Path,
    script_path: Path,
    run_dir: Path,
    image_path: Path,
    scripts: list[tuple[str, list[str]]],
    timeout: int = 75,
) -> tuple[int, str, str]:
    shutil.rmtree(run_dir, ignore_errors=True)
    for name in ("home", "config", "project", "tmp", "cache"):
        (run_dir / name).mkdir(parents=True, exist_ok=True)
    console = run_dir / "console.log"
    script_log = run_dir / "script.log"
    ghidra_log = run_dir / "ghidra.log"
    isolated_scripts = run_dir / "scripts"
    isolated_scripts.mkdir(parents=True, exist_ok=True)
    for source in script_path.glob("*.java"):
        shutil.copy2(source, isolated_scripts / source.name)

    command = [
        str(ghidra),
        str(run_dir / "project"),
        "profile-test",
        "-import",
        str(image_path),
        "-loader",
        "BinaryLoader",
        "-loader-baseAddr",
        hex(FIRMWARE_BASE),
        "-loader-blockName",
        "PROFILE_TEST_IMPORT",
        "-processor",
        "tms320c28:LE:32:default",
        "-cspec",
        "default",
        "-noanalysis",
        "-scriptPath",
        str(isolated_scripts),
    ]
    for script, args in scripts:
        command.extend(["-postScript", script, *args])
    command.extend(
        [
            "-log",
            str(ghidra_log),
            "-scriptlog",
            str(script_log),
            "-overwrite",
            "-deleteProject",
        ]
    )
    # Some Ghidra development builds leave a non-daemon helper thread alive
    # after a deliberately failing post-script.  Bound the whole process tree
    # externally so negative tests remain deterministic.
    command = [
        "timeout", "--signal=TERM", "--kill-after=5s", f"{timeout}s", *command
    ]

    env = os.environ.copy()
    env.update(
        {
            "HOME": str(run_dir / "home"),
            "XDG_CONFIG_HOME": str(run_dir / "config"),
            "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join(
                [
                    f"-Dapplication.tempdir={run_dir / 'tmp'}",
                    f"-Dapplication.cachedir={run_dir / 'cache'}",
                    f"-Djava.io.tmpdir={run_dir / 'tmp'}",
                ]
            ),
        }
    )
    try:
        with console.open("w", encoding="utf-8") as console_stream:
            completed = subprocess.run(
                command,
                stdout=console_stream,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL,
                text=True,
                env=env,
                timeout=timeout + 15,
                check=False,
            )
        returncode = completed.returncode
    except subprocess.TimeoutExpired:
        with console.open("a", encoding="utf-8") as console_stream:
            console_stream.write("\nPROFILE_TEST_HARNESS_ERROR=headless timeout\n")
        returncode = 124
    output = console.read_text(encoding="utf-8", errors="replace")
    script_output = ""
    if script_log.exists():
        script_output = script_log.read_text(encoding="utf-8", errors="replace")
    combined = output + ("\n" + script_output if script_output else "")
    return returncode, combined, script_output


def marker_values(output: str, marker: str) -> list[int]:
    return [int(value) for value in re.findall(rf"{re.escape(marker)}=(\d+)", output)]


def require(condition: bool, message: str, output: str | None = None) -> None:
    if condition:
        return
    if output:
        sys.stderr.write(output[-16000:])
    raise RuntimeError(message)


def expect_workspace_failure(
    *,
    name: str,
    ghidra: Path,
    script_path: Path,
    work: Path,
    image: bytearray,
    profile: dict,
    workspace: dict,
    prefix: str = "DEVICE_PROFILE_ERROR:",
    before: list[tuple[str, list[str]]] | None = None,
    after: list[tuple[str, list[str]]] | None = None,
) -> None:
    case_dir = work / "cases" / name
    image_path, profile_path, workspace_path = write_case(
        case_dir, image, profile, workspace
    )
    scripts = list(before or [])
    scripts.append(
        (
            "TMS320C28DeviceProfile.java",
            [
                f"profile={profile_path}",
                f"workspace={workspace_path}",
                "strictFirmware=true",
                "recoverCopies=true",
                "seedAnalysis=false",
                "applyRegisterTypes=true",
            ],
        )
    )
    scripts.extend(after or [])
    _, output, _ = run_headless(
        ghidra=ghidra,
        script_path=script_path,
        run_dir=work / "runs" / name,
        image_path=image_path,
        scripts=scripts,
    )
    require(prefix in output, f"negative {name} did not report {prefix}", output)
    require("FIRMWARE_WORKSPACE_PASS=" not in output,
        f"negative {name} unexpectedly passed", output)
    print(f"PROFILE_TEST_NEGATIVE_PASS={name}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ghidra-headless", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    ghidra = args.ghidra_headless.resolve()
    work = args.work.resolve()
    scripts = root / "ghidra_scripts"
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    image = fixture_image()
    profile = base_profile()
    workspace = base_workspace(sha256(image))
    positive_dir = work / "cases" / "positive"
    image_path, profile_path, workspace_path = write_case(
        positive_dir, image, profile, workspace
    )
    rom_path = positive_dir / "rom.bin"
    rom_bytes = bytes([0x5A, 0xA5, 0x34, 0x12, 0xEF, 0xBE, 0xFE, 0xCA])
    rom_path.write_bytes(rom_bytes)
    rom_hash = sha256(rom_bytes)
    profile_args = [
        f"profile={profile_path}",
        f"workspace={workspace_path}",
        "strictFirmware=true",
        "recoverCopies=true",
        "seedAnalysis=true",
        "applyRegisterTypes=true",
        "verboseCopies=false",
    ]
    rom_args = [
        f"path={rom_path}",
        "base=0x4010",
        "expectedWords=4",
        f"sha256={rom_hash}",
        "provenance=synthetic-profile-test-rom",
        "execute=true",
    ]
    _, output, marker_output = run_headless(
        ghidra=ghidra,
        script_path=scripts,
        run_dir=work / "runs" / "positive",
        image_path=image_path,
        scripts=[
            ("TMS320C28DeviceProfile.java", profile_args),
            ("TMS320C28DeviceProfile.java", profile_args),
            ("TMS320C28ImportRomEvidence.java", rom_args),
            ("TMS320C28ImportRomEvidence.java", rom_args),
            ("TMS320C28ProfileTest.java", ["mode=positive"]),
        ],
    )
    require(marker_output.count("DEVICE_PROFILE_PASS=Synthetic-profile-test") == 2,
        "positive profile was not applied twice", output)
    require(marker_output.count("FIRMWARE_WORKSPACE_PASS=Synthetic-workspace-test") == 2,
        "positive firmware workspace was not applied twice", output)
    created = marker_values(marker_output, "DEVICE_PROFILE_BLOCKS_CREATED")
    require(len(created) == 2 and created[0] > 0 and created[1] == 0,
        f"profile idempotence block counts are wrong: {created}", output)
    reused_labels = marker_values(marker_output, "DEVICE_PROFILE_LABELS_REUSED")
    require(len(reused_labels) == 2 and reused_labels[1] > reused_labels[0],
        f"profile symbols were not reused on the second pass: {reused_labels}", output)
    require(marker_output.count("ROM_EVIDENCE_PASS=") == 2,
        "positive ROM evidence was not applied twice", output)
    rom_initialized = marker_values(marker_output, "ROM_EVIDENCE_BLOCKS_INITIALIZED")
    require(len(rom_initialized) == 2 and rom_initialized[0] > 0 and rom_initialized[1] == 0,
        f"ROM idempotence initialized counts are wrong: {rom_initialized}", output)
    require("PROFILE_TEST_PASS=positive" in marker_output, "positive validator did not pass", output)
    print("PROFILE_TEST_IDEMPOTENCE=PASS")
    print("ROM_EVIDENCE_IDEMPOTENCE=PASS")

    negatives = 0

    wrong_hash = copy.deepcopy(workspace)
    wrong_hash["firmware"]["sha256"] = "00" * 32
    expect_workspace_failure(name="wrong-firmware-hash", ghidra=ghidra, script_path=scripts,
        work=work, image=image, profile=profile, workspace=wrong_hash)
    negatives += 1

    escaped_image = bytearray(image)
    put_word(escaped_image, 0x1081, 0x2200)
    escaped = base_workspace(sha256(escaped_image))
    expect_workspace_failure(name="cinit-destination-escape", ghidra=ghidra,
        script_path=scripts, work=work, image=escaped_image, profile=profile,
        workspace=escaped)
    negatives += 1

    missing_terminator = copy.deepcopy(workspace)
    missing_terminator["copyRecovery"]["cinit"]["maxRecords"] = 2
    expect_workspace_failure(name="cinit-missing-terminator", ghidra=ghidra,
        script_path=scripts, work=work, image=image, profile=profile,
        workspace=missing_terminator)
    negatives += 1

    overlap_image = bytearray(image)
    put_word(overlap_image, 0x1086, 0x2021)
    overlap_workspace = base_workspace(sha256(overlap_image))
    expect_workspace_failure(name="cinit-destination-overlap", ghidra=ghidra,
        script_path=scripts, work=work, image=overlap_image, profile=profile,
        workspace=overlap_workspace)
    negatives += 1

    self_overlap_image = bytearray(image)
    put_word(self_overlap_image, 0x1081, 0x1082)
    self_overlap_workspace = base_workspace(sha256(self_overlap_image))
    self_overlap_workspace["copyRecovery"]["cinit"]["allowedDestinationRanges"] = [
        {"start": 0x1000, "words": 0x200}
    ]
    expect_workspace_failure(name="cinit-source-destination-overlap", ghidra=ghidra,
        script_path=scripts, work=work, image=self_overlap_image, profile=profile,
        workspace=self_overlap_workspace)
    negatives += 1

    explicit_overlap = copy.deepcopy(workspace)
    explicit_overlap["copyRecovery"]["explicit"][0]["destination"] = 0x1040
    expect_workspace_failure(name="explicit-source-destination-overlap", ghidra=ghidra,
        script_path=scripts, work=work, image=image, profile=profile,
        workspace=explicit_overlap)
    negatives += 1

    uninitialized_source = copy.deepcopy(workspace)
    uninitialized_source["copyRecovery"]["explicit"][0]["source"] = 0x4000
    expect_workspace_failure(name="explicit-uninitialized-source", ghidra=ghidra,
        script_path=scripts, work=work, image=image, profile=profile,
        workspace=uninitialized_source)
    negatives += 1

    expect_workspace_failure(name="incompatible-initialized-destination", ghidra=ghidra,
        script_path=scripts, work=work, image=image, profile=profile,
        workspace=workspace,
        before=[("TMS320C28ProfileTestSetup.java", ["mode=incompatibleCopyDestination"])])
    negatives += 1

    # ROM overlap rejection is exercised after a successful profile-only mapping.
    rom_negative_dir = work / "cases" / "rom-overlap"
    rom_image_path, rom_profile_path, _ = write_case(
        rom_negative_dir, image, profile, workspace
    )
    rom_negative_path = rom_negative_dir / "rom.bin"
    rom_negative_path.write_bytes(rom_bytes)
    _, rom_output, _ = run_headless(
        ghidra=ghidra,
        script_path=scripts,
        run_dir=work / "runs" / "rom-overlap",
        image_path=rom_image_path,
        scripts=[
            (
                "TMS320C28DeviceProfile.java",
                [
                    f"profile={rom_profile_path}",
                    "applyRegisterTypes=false",
                ],
            ),
            ("TMS320C28ProfileTestSetup.java", ["mode=incompatibleRom"]),
            ("TMS320C28ImportRomEvidence.java", rom_args),
        ],
    )
    require("ROM_EVIDENCE_ERROR: incompatible initialized ROM overlap" in rom_output,
        "ROM overlap negative was not rejected", rom_output)
    require("ROM_EVIDENCE_PASS=" not in rom_output,
        "ROM overlap negative unexpectedly passed", rom_output)
    print("ROM_EVIDENCE_OVERLAP_REJECTION=PASS")

    print(f"PROFILE_TEST_NEGATIVES={negatives}")
    print("PROFILE_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep Make output compact but actionable
        print(f"PROFILE_TEST_HARNESS_ERROR={exc}", file=sys.stderr)
        raise
