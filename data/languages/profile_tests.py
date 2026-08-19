#!/usr/bin/env python3
"""Deterministic headless regression for the C28x device profile and ROM importer."""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
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

ACCESS_VIEW_NEGATIVES = {
    "out-of-block": "outside parent peripheral block",
    "incompatible-overlap": "overlaps incompatible register span",
    "duplicate-name": "duplicate access-view symbol",
    "duplicate-lane": "duplicate physical access view for logical lane",
    "invalid-logical-range": "logical range outside parent",
    "unsupported-logical-width": "unsupported access-view logical width",
    "unsupported-storage-width": "unsupported access-view storage width",
    "unsupported-lane": "unsupported CAN access-view lane",
    "address-mismatch": "CAN access-view address mismatch",
    "name-mismatch": "CAN access-view name mismatch",
    "missing-parent": "missing access-view parent",
    "unsupported-parent": "unsupported access-view parent",
    "base-mismatch": "access-view base mismatch",
    "field-mapping-mismatch": "access-view field mapping mismatch",
}


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
            },
            {
                "symbol": "CANA_BASE",
                "displayName": "Synthetic CAN byte-peripheral window",
                "address": 0x3020,
            },
        ],
        "registers": [
            {
                "namespace": "TESTPERIPH",
                "name": "REG16",
                "address": 0x3004,
                "widthBits": 16,
                "description": "Synthetic 16-bit register",
                "fields": [
                    {
                        "name": "ENABLE",
                        "shift": 0,
                        "size": 1,
                        "mask": 0x1,
                        "description": "Enable",
                    }
                ],
            },
            {
                "namespace": "TESTPERIPH",
                "name": "REG32",
                "address": 0x3006,
                "widthBits": 32,
                "description": "Synthetic 32-bit register",
                "fields": [
                    {
                        "name": "VALUE",
                        "shift": 0,
                        "size": 16,
                        "mask": 0xFFFF,
                        "description": "Value",
                    }
                ],
            },
            {
                "namespace": "CANA",
                "baseSymbol": "CANA_BASE",
                "name": "IF1ARB",
                "address": 0x3020,
                "widthBits": 32,
                "description": "Synthetic IF1 arbitration register",
                "fields": [
                    {
                        "name": "ID",
                        "shift": 0,
                        "size": 29,
                        "mask": 0x1FFFFFFF,
                        "description": "Message identifier",
                    },
                    {
                        "name": "DIR",
                        "shift": 29,
                        "size": 1,
                        "mask": 0x20000000,
                        "description": "Message direction",
                    },
                    {
                        "name": "XTD",
                        "shift": 30,
                        "size": 1,
                        "mask": 0x40000000,
                        "description": "Extended identifier",
                    },
                    {
                        "name": "MSGVAL",
                        "shift": 31,
                        "size": 1,
                        "mask": 0x80000000,
                        "description": "Message valid",
                    },
                ],
            },
            {
                "namespace": "CANA",
                "baseSymbol": "CANA_BASE",
                "name": "FOLLOWING16",
                "address": 0x3024,
                "widthBits": 16,
                "description": "Synthetic following register",
                "fields": [
                    {
                        "name": "READY",
                        "shift": 0,
                        "size": 1,
                        "mask": 0x1,
                        "description": "Ready",
                    }
                ],
            },
        ],
        "accessViews": [
            {
                "namespace": "CANA",
                "baseSymbol": "CANA_BASE",
                "name": "IF1ARB_BYTE2",
                "address": 0x3022,
                "physicalStorageWidthBits": 16,
                "parentRegister": "IF1ARB",
                "logicalBitOffset": 16,
                "logicalWidthBits": 8,
                "description": (
                    "C28x byte-peripheral physical access view of "
                    "Synthetic IF1 arbitration register"
                ),
                "fieldOverlaps": [
                    {
                        "name": "ID",
                        "description": "Message identifier",
                        "parentShift": 0,
                        "parentSize": 29,
                        "overlapLogicalBitOffset": 16,
                        "overlapWidthBits": 8,
                        "crossesByteBoundary": True,
                    }
                ],
            },
            {
                "namespace": "CANA",
                "baseSymbol": "CANA_BASE",
                "name": "IF1ARB_BYTE3",
                "address": 0x3023,
                "physicalStorageWidthBits": 16,
                "parentRegister": "IF1ARB",
                "logicalBitOffset": 24,
                "logicalWidthBits": 8,
                "description": (
                    "C28x byte-peripheral physical access view of "
                    "Synthetic IF1 arbitration register"
                ),
                "fieldOverlaps": [
                    {
                        "name": "ID",
                        "description": "Message identifier",
                        "parentShift": 0,
                        "parentSize": 29,
                        "overlapLogicalBitOffset": 24,
                        "overlapWidthBits": 5,
                        "crossesByteBoundary": True,
                    },
                    {
                        "name": "DIR",
                        "description": "Message direction",
                        "parentShift": 29,
                        "parentSize": 1,
                        "overlapLogicalBitOffset": 29,
                        "overlapWidthBits": 1,
                        "crossesByteBoundary": False,
                    },
                    {
                        "name": "XTD",
                        "description": "Extended identifier",
                        "parentShift": 30,
                        "parentSize": 1,
                        "overlapLogicalBitOffset": 30,
                        "overlapWidthBits": 1,
                        "crossesByteBoundary": False,
                    },
                    {
                        "name": "MSGVAL",
                        "description": "Message valid",
                        "parentShift": 31,
                        "parentSize": 1,
                        "overlapLogicalBitOffset": 31,
                        "overlapWidthBits": 1,
                        "crossesByteBoundary": False,
                    },
                ],
            },
        ],
        "codeVectors": [
            {
                "namespace": "TESTVECT",
                "baseSymbol": "TEST_VECTOR_BASE",
                "name": "SYNTH_VECTOR0",
                "address": 0x2080,
                "widthBits": 32,
                "description": "Synthetic code-vector slot 0",
            },
            {
                "namespace": "TESTVECT",
                "baseSymbol": "TEST_VECTOR_BASE",
                "name": "SYNTH_VECTOR1",
                "address": 0x2082,
                "widthBits": 32,
                "description": "Synthetic code-vector slot 1",
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


def load_profile_generator(root: Path):
    path = root / "tools" / "generate_f2837xs_profile.py"
    spec = importlib.util.spec_from_file_location("generate_f2837xs_profile_test", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load profile generator: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def expect_generator_failure(module, profile: dict, expected: str, name: str) -> None:
    try:
        module.validate_profile(profile)
    except ValueError as exc:
        require(expected in str(exc),
            f"generator negative {name} reported {exc!s}, expected {expected!r}")
        print(f"PROFILE_GENERATOR_NEGATIVE_PASS={name}")
        return
    raise RuntimeError(f"generator negative {name} unexpectedly passed")


def mutate_access_view_profile(name: str) -> dict:
    profile = base_profile()
    views = profile["accessViews"]
    parent = next(
        register for register in profile["registers"]
        if register["namespace"] == "CANA" and register["name"] == "IF1ARB"
    )

    if name == "out-of-block":
        parent["address"] = 0x303E
        views[0]["address"] = 0x3040
        views[1]["address"] = 0x3041
    elif name == "incompatible-overlap":
        profile["registers"].append(
            {
                "namespace": "TESTPERIPH",
                "baseSymbol": "TEST_PERIPH_BASE",
                "name": "OVERLAPPING32",
                "address": 0x3022,
                "widthBits": 32,
                "description": "Incompatible access-view overlap",
                "fields": [],
            }
        )
    elif name == "duplicate-name":
        views[1]["name"] = views[0]["name"]
    elif name == "duplicate-lane":
        duplicate = copy.deepcopy(views[0])
        duplicate["name"] = "IF1ARB_BYTE2_ALIAS"
        views.append(duplicate)
    elif name == "invalid-logical-range":
        views[0]["logicalBitOffset"] = 31
    elif name == "unsupported-logical-width":
        views[0]["logicalWidthBits"] = 4
    elif name == "unsupported-storage-width":
        views[0]["physicalStorageWidthBits"] = 32
    elif name == "unsupported-lane":
        views[0]["logicalBitOffset"] = 8
        views[0]["name"] = "IF1ARB_BYTE1"
        views[0]["address"] = 0x3021
        views[0]["fieldOverlaps"] = [
            {
                "name": "ID",
                "description": "Message identifier",
                "parentShift": 0,
                "parentSize": 29,
                "overlapLogicalBitOffset": 8,
                "overlapWidthBits": 8,
                "crossesByteBoundary": True,
            }
        ]
    elif name == "address-mismatch":
        views[0]["address"] += 1
    elif name == "name-mismatch":
        views[0]["name"] = "IF1ARB_UPPER2"
    elif name == "missing-parent":
        views[0]["parentRegister"] = "MISSING"
    elif name == "unsupported-parent":
        views[0]["parentRegister"] = "FOLLOWING16"
        views[0]["name"] = "FOLLOWING16_BYTE2"
        views[0]["address"] = 0x3026
    elif name == "base-mismatch":
        views[0]["baseSymbol"] = "TEST_PERIPH_BASE"
    elif name == "field-mapping-mismatch":
        views[0]["fieldOverlaps"] = []
    else:
        raise ValueError(f"unknown access-view mutation: {name}")
    return profile


def run_generator_access_view_tests(root: Path) -> int:
    module = load_profile_generator(root)
    profile = base_profile()
    generated = module.build_can_access_views(profile["registers"])
    require(generated == profile["accessViews"],
        "generator helper did not reproduce the synthetic CAN views")
    module.validate_profile(profile)
    require([view["name"] for view in generated] ==
        ["IF1ARB_BYTE2", "IF1ARB_BYTE3"],
        "generator access-view names are not deterministic")
    require([view["address"] for view in generated] == [0x3022, 0x3023],
        "generator access-view addresses do not follow the C28x CAN rule")

    for name, expected in ACCESS_VIEW_NEGATIVES.items():
        expect_generator_failure(module, mutate_access_view_profile(name), expected, name)

    print("PROFILE_GENERATOR_ACCESS_VIEWS=2")
    print(f"PROFILE_GENERATOR_NEGATIVES={len(ACCESS_VIEW_NEGATIVES)}")
    print("PROFILE_GENERATOR_TEST_PASS=all")
    return len(ACCESS_VIEW_NEGATIVES)


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


def expect_access_view_profile_failure(
    *,
    name: str,
    expected: str,
    ghidra: Path,
    script_path: Path,
    work: Path,
    image: bytearray,
) -> None:
    case_dir = work / "cases" / f"access-view-{name}"
    profile = mutate_access_view_profile(name)
    workspace = base_workspace(sha256(image))
    image_path, profile_path, _ = write_case(case_dir, image, profile, workspace)
    _, output, _ = run_headless(
        ghidra=ghidra,
        script_path=script_path,
        run_dir=work / "runs" / f"access-view-{name}",
        image_path=image_path,
        scripts=[
            (
                "TMS320C28DeviceProfile.java",
                [
                    f"profile={profile_path}",
                    "applyRegisterTypes=true",
                ],
            )
        ],
        timeout=45,
    )
    require("DEVICE_PROFILE_ERROR:" in output and expected in output,
        f"access-view negative {name} did not report {expected!r}", output)
    require("DEVICE_PROFILE_BEGIN=" not in output,
        f"access-view negative {name} began partial profile application", output)
    require("DEVICE_PROFILE_BLOCKS_CREATED=" not in output,
        f"access-view negative {name} emitted post-application state", output)
    require("DEVICE_PROFILE_PASS=" not in output,
        f"access-view negative {name} unexpectedly passed", output)
    print(f"PROFILE_TEST_ACCESS_VIEW_NEGATIVE_PASS={name}")


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

    generator_negatives = run_generator_access_view_tests(root)

    image = fixture_image()
    profile = base_profile()
    workspace = base_workspace(sha256(image))

    for name, expected in ACCESS_VIEW_NEGATIVES.items():
        expect_access_view_profile_failure(
            name=name,
            expected=expected,
            ghidra=ghidra,
            script_path=scripts,
            work=work,
            image=image,
        )
    print(f"PROFILE_TEST_ACCESS_VIEW_NEGATIVES={len(ACCESS_VIEW_NEGATIVES)}")

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
    vector_created = marker_values(marker_output, "DEVICE_PROFILE_CODE_VECTOR_DATA_CREATED")
    require(vector_created == [2, 0],
        f"code-vector creation was not idempotent: {vector_created}", output)
    vector_skipped = marker_values(marker_output, "DEVICE_PROFILE_CODE_VECTOR_DATA_SKIPPED")
    require(vector_skipped == [0, 2],
        f"code-vector reuse metrics are wrong: {vector_skipped}", output)
    access_created = marker_values(
        marker_output, "DEVICE_PROFILE_ACCESS_VIEW_DATA_CREATED")
    require(access_created == [2, 0],
        f"access-view creation was not idempotent: {access_created}", output)
    access_skipped = marker_values(
        marker_output, "DEVICE_PROFILE_ACCESS_VIEW_DATA_SKIPPED")
    require(access_skipped == [0, 2],
        f"access-view reuse metrics are wrong: {access_skipped}", output)
    require(marker_output.count("ROM_EVIDENCE_PASS=") == 2,
        "positive ROM evidence was not applied twice", output)
    rom_initialized = marker_values(marker_output, "ROM_EVIDENCE_BLOCKS_INITIALIZED")
    require(len(rom_initialized) == 2 and rom_initialized[0] > 0 and rom_initialized[1] == 0,
        f"ROM idempotence initialized counts are wrong: {rom_initialized}", output)
    require("PROFILE_TEST_PASS=positive" in marker_output, "positive validator did not pass", output)
    print("PROFILE_TEST_IDEMPOTENCE=PASS")
    print("PROFILE_TEST_ACCESS_VIEWS=2")
    print("PROFILE_TEST_ACCESS_VIEW_IDEMPOTENCE=PASS")
    print("PROFILE_TEST_CODE_VECTORS=2")
    print("ROM_EVIDENCE_IDEMPOTENCE=PASS")

    conflict_dir = work / "cases" / "access-view-user-conflict"
    conflict_image_path, conflict_profile_path, _ = write_case(
        conflict_dir, image, profile, workspace
    )
    conflict_args = [
        f"profile={conflict_profile_path}",
        "applyRegisterTypes=true",
    ]
    _, conflict_output, conflict_markers = run_headless(
        ghidra=ghidra,
        script_path=scripts,
        run_dir=work / "runs" / "access-view-user-conflict",
        image_path=conflict_image_path,
        scripts=[
            ("TMS320C28ProfileTestSetup.java", ["mode=accessViewConflict"]),
            ("TMS320C28DeviceProfile.java", conflict_args),
            ("TMS320C28DeviceProfile.java", conflict_args),
            ("TMS320C28ProfileTest.java", ["mode=user-conflict"]),
        ],
    )
    require(conflict_markers.count("PROFILE_TEST_SETUP_PASS=accessViewConflict") == 1,
        "access-view conflict setup did not run exactly once", conflict_output)
    require(conflict_markers.count("DEVICE_PROFILE_PASS=Synthetic-profile-test") == 2,
        "access-view conflict profile was not applied twice", conflict_output)
    conflict_created = marker_values(
        conflict_markers, "DEVICE_PROFILE_ACCESS_VIEW_DATA_CREATED")
    require(conflict_created == [1, 0],
        f"access-view conflict creation counts are wrong: {conflict_created}",
        conflict_output)
    conflict_skipped = marker_values(
        conflict_markers, "DEVICE_PROFILE_ACCESS_VIEW_DATA_SKIPPED")
    require(conflict_skipped == [1, 2],
        f"access-view conflict skip counts are wrong: {conflict_skipped}",
        conflict_output)
    require(conflict_markers.count("PROFILE_TEST_PASS=user-conflict") == 1,
        "access-view conflict preservation validator did not pass exactly once",
        conflict_output)
    print("PROFILE_TEST_ACCESS_VIEW_USER_PRESERVATION=PASS")
    print("PROFILE_TEST_ACCESS_VIEW_CONFLICT_IDEMPOTENCE=PASS")

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
    print(f"PROFILE_TEST_GENERATOR_NEGATIVES={generator_negatives}")
    print("PROFILE_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # keep Make output compact but actionable
        print(f"PROFILE_TEST_HARNESS_ERROR={exc}", file=sys.stderr)
        raise
