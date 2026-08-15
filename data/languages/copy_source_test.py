#!/usr/bin/env python3
"""Deterministic fresh-project test for explicit inert copy-source cleanup."""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

FIRMWARE_BASE = 0x1000
FIRMWARE_WORDS = 0x300
SOURCE = 0x1040
DESTINATION = 0x2040
AUX_SOURCE = 0x3000
COPY_WORDS = 0x10

CASES: tuple[str, ...] = (
    "positive",
    "policy-absent",
    "unknown-policy",
    "empty",
    "overflow",
    "overlap",
    "unmapped-source",
    "uninitialized-source",
    "unmapped-destination",
    "incompatible-destination",
    "function-entry",
    "function-body",
    "external-entry",
    "external-call",
    "external-jump",
    "external-conditional",
    "external-fallthrough",
    "disassembly-seed",
    "function-seed",
    "source-executable-destination",
    "isolation-boundary",
)

EXPECTED_SKIP_REASON = {
    "unknown-policy": "unknown-value-retire",
    "function-entry": "function-entry",
    "function-body": "function-body",
    "external-entry": "external-entry-point",
    "external-call": "external-flow-ingress",
    "external-jump": "external-flow-ingress",
    "external-conditional": "external-flow-ingress",
    "external-fallthrough": "external-fallthrough-ingress",
    "disassembly-seed": "analysis-seed",
    "function-seed": "analysis-seed",
    "source-executable-destination": "executable-copy-destination",
    "isolation-boundary": "isolation-boundary-code-unit",
}


def put_word(image: bytearray, word_address: int, value: int) -> None:
    index = (word_address - FIRMWARE_BASE) * 2
    if index < 0 or index + 2 > len(image):
        raise ValueError(f"word 0x{word_address:x} is outside fixture")
    image[index] = value & 0xFF
    image[index + 1] = (value >> 8) & 0xFF


def fixture_image() -> bytes:
    # NOP is a convenient one-word instruction.  Add bounded returns so every
    # deliberate disassembly island terminates inside fixture-owned storage.
    image = bytearray(FIRMWARE_WORDS * 2)
    for word in range(FIRMWARE_BASE, FIRMWARE_BASE + FIRMWARE_WORDS):
        put_word(image, word, 0x7700)
    for word in (
        0x1013, 0x1023, 0x1033, SOURCE + COPY_WORDS - 1,
        0x1063, 0x1103, 0x112F,
    ):
        put_word(image, word, 0x0006)  # LRETR
    return bytes(image)


def profile() -> dict:
    return {
        "schema": "tms320c28-device-profile",
        "version": 1,
        "profileName": "Synthetic-copy-source-test",
        "addressUnitBytes": 2,
        "blocks": [
            {
                "name": "COPY_FLASH",
                "start": FIRMWARE_BASE,
                "words": FIRMWARE_WORDS,
                "kind": "flash",
                "read": True,
                "write": False,
                "execute": True,
                "volatile": False,
                "source": "synthetic copy-source fixture",
            },
            {
                "name": "COPY_LIVE_RAM",
                "start": 0x2000,
                "words": 0x100,
                "kind": "ram",
                "read": True,
                "write": True,
                "execute": True,
                "volatile": False,
                "source": "synthetic copy-source fixture",
            },
            {
                "name": "COPY_AUX_RAM",
                "start": AUX_SOURCE,
                "words": 0x100,
                "kind": "ram",
                "read": True,
                "write": True,
                "execute": True,
                "volatile": False,
                "source": "synthetic copy-source fixture",
            },
        ],
        "baseLabels": [],
        "registers": [],
        "codeVectors": [],
        "provenance": {"generatedBy": "copy_source_test.py"},
    }


def explicit_copy(
    *,
    name: str = "TEST_LIVE_COPY",
    source: int = SOURCE,
    destination: int = DESTINATION,
    words: int = COPY_WORDS,
    executable: bool = True,
    disposition: object = ...,
) -> dict:
    record: dict[str, object] = {
        "name": name,
        "source": source,
        "destination": destination,
        "words": words,
        "executable": executable,
        "evidence": "synthetic exact ascending copy evidence",
    }
    if disposition is not ...:
        record["sourceDisposition"] = disposition
    return record


def workspace(image_hash: str, records: list[dict], *, seeds: dict | None = None) -> dict:
    result = {
        "schema": "tms320c28-firmware-workspace",
        "version": 1,
        "workspaceName": "synthetic-copy-source-test",
        "deviceProfile": "Synthetic-copy-source-test",
        "firmware": {
            "blockName": "COPY_FLASH_IMAGE",
            "wordBase": FIRMWARE_BASE,
            "byteLength": FIRMWARE_WORDS * 2,
            "sha256": image_hash,
            "read": True,
            "write": False,
            "execute": True,
        },
        "copyRecovery": {"explicit": records},
        "analysisSeeds": seeds or {
            "disassembly": [DESTINATION],
            "functions": [DESTINATION],
        },
    }
    return result


def case_workspaces(mode: str, image_hash: str) -> tuple[dict, dict, dict, int]:
    baseline = workspace(image_hash, [explicit_copy()])
    absent = copy.deepcopy(baseline)
    test = copy.deepcopy(baseline)
    source_under_audit = SOURCE

    record = test["copyRecovery"]["explicit"][0]
    record["sourceDisposition"] = "inert-storage"

    if mode == "policy-absent":
        test = copy.deepcopy(absent)
    elif mode == "unknown-policy":
        record["sourceDisposition"] = "retire"
    elif mode == "empty":
        record["words"] = 0
    elif mode == "overflow":
        record["source"] = 0x7FFFFFFFFFFFFFFF
        record["words"] = 2
    elif mode == "overlap":
        record["destination"] = SOURCE + 4
    elif mode == "unmapped-source":
        record["source"] = 0x5000
    elif mode == "uninitialized-source":
        record["source"] = AUX_SOURCE
    elif mode == "unmapped-destination":
        record["destination"] = 0x5000
    elif mode == "disassembly-seed":
        test["analysisSeeds"]["disassembly"].append(SOURCE)
    elif mode == "function-seed":
        test["analysisSeeds"]["functions"].append(SOURCE)
    elif mode == "source-executable-destination":
        prep = explicit_copy(
            name="PREP_EXECUTABLE_SOURCE",
            source=0x1120,
            destination=AUX_SOURCE,
            words=COPY_WORDS,
            executable=True,
        )
        live = explicit_copy(
            source=AUX_SOURCE,
            destination=DESTINATION,
            disposition=...,
        )
        baseline = workspace(image_hash, [prep, live])
        absent = copy.deepcopy(baseline)
        live_policy = copy.deepcopy(live)
        live_policy["sourceDisposition"] = "inert-storage"
        test = workspace(image_hash, [copy.deepcopy(prep), live_policy])
        source_under_audit = AUX_SOURCE
    # All remaining proof near-misses are installed by the Java fixture.
    return baseline, test, absent, source_under_audit


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_case(
    *, root: Path, ghidra: Path, work: Path, mode: str, image: bytes,
    profile_value: dict, baseline: dict, test: dict, absent: dict,
    source_under_audit: int,
) -> str:
    case = work / "cases" / mode
    run = work / "runs" / mode
    shutil.rmtree(case, ignore_errors=True)
    shutil.rmtree(run, ignore_errors=True)
    case.mkdir(parents=True)
    for name in ("home", "config", "project", "tmp", "cache", "scripts"):
        (run / name).mkdir(parents=True, exist_ok=True)

    image_path = case / "fixture.bin"
    profile_path = case / "profile.json"
    baseline_path = case / "baseline.json"
    test_path = case / "test.json"
    absent_path = case / "absent.json"
    image_path.write_bytes(image)
    write_json(profile_path, profile_value)
    write_json(baseline_path, baseline)
    write_json(test_path, test)
    write_json(absent_path, absent)

    for script in ("TMS320C28DeviceProfile.java", "TMS320C28CopySourceTest.java"):
        shutil.copy2(root / "ghidra_scripts" / script, run / "scripts" / script)

    script_args = [
        f"mode={mode}",
        f"profile={profile_path}",
        f"baseline={baseline_path}",
        f"workspace={test_path}",
        f"absent={absent_path}",
        f"source=0x{source_under_audit:x}",
    ]
    script_log = run / "script.log"
    console_log = run / "console.log"
    command = [
        str(ghidra), str(run / "project"), "copy-source-test",
        "-import", str(image_path),
        "-loader", "BinaryLoader",
        "-loader-baseAddr", hex(FIRMWARE_BASE),
        "-loader-blockName", "COPY_SOURCE_IMPORT",
        "-processor", "tms320c28:LE:32:default", "-cspec", "default",
        "-noanalysis",
        "-scriptPath", str(run / "scripts"),
        "-postScript", str(run / "scripts" / "TMS320C28CopySourceTest.java"),
        *script_args,
        "-log", str(run / "ghidra.log"),
        "-scriptlog", str(script_log),
        "-analysisTimeoutPerFile", "120",
        "-overwrite", "-deleteProject",
    ]
    env = os.environ.copy()
    env.update({
        "HOME": str(run / "home"),
        "XDG_CONFIG_HOME": str(run / "config"),
        "GHIDRA_HEADLESS_JAVA_OPTIONS": " ".join((
            f"-Dapplication.tempdir={run / 'tmp'}",
            f"-Dapplication.cachedir={run / 'cache'}",
            f"-Djava.io.tmpdir={run / 'tmp'}",
        )),
    })
    with console_log.open("w", encoding="utf-8") as output:
        completed = subprocess.run(
            command, cwd=root, env=env, stdout=output,
            stderr=subprocess.STDOUT, check=False, timeout=180,
        )
    console = console_log.read_text(encoding="utf-8", errors="replace")
    script = script_log.read_text(encoding="utf-8", errors="replace") \
        if script_log.exists() else ""
    if completed.returncode:
        raise RuntimeError(
            f"copy-source case {mode} failed ({completed.returncode})\n"
            f"{console[-18000:]}\n{script[-18000:]}"
        )
    marker = f"COPY_SOURCE_CASE_PASS={mode}"
    if script.count(marker) != 1:
        raise RuntimeError(
            f"copy-source case {mode} emitted {script.count(marker)} pass markers\n"
            f"{console[-18000:]}\n{script[-18000:]}"
        )

    cleanup_lines = [line for line in script.splitlines()
                     if "FIRMWARE_WORKSPACE_SOURCE_CLEANUP=" in line]
    if mode == "positive":
        if not any(":APPLIED:inert-storage:" in line for line in cleanup_lines):
            raise RuntimeError("positive case did not apply inert source cleanup")
    elif mode == "policy-absent":
        if cleanup_lines:
            raise RuntimeError(f"policy-absent case emitted cleanup markers: {cleanup_lines}")
    elif mode in EXPECTED_SKIP_REASON:
        reason = EXPECTED_SKIP_REASON[mode]
        if not any(f":SKIPPED:{reason}" in line for line in cleanup_lines):
            raise RuntimeError(
                f"{mode} did not emit deterministic skip reason {reason}: {cleanup_lines}"
            )
    else:
        if any(":APPLIED:" in line for line in cleanup_lines):
            raise RuntimeError(f"fatal case {mode} partially applied source cleanup")

    return marker


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--ghidra-headless", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--case", choices=CASES)
    args = parser.parse_args()

    root = args.root.resolve()
    ghidra = args.ghidra_headless.resolve()
    work = args.work.resolve()
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True)

    image = fixture_image()
    image_hash = hashlib.sha256(image).hexdigest()
    profile_value = profile()
    selected = (args.case,) if args.case else CASES
    for mode in selected:
        baseline, test, absent, source_under_audit = case_workspaces(mode, image_hash)
        marker = run_case(
            root=root, ghidra=ghidra, work=work, mode=mode, image=image,
            profile_value=profile_value, baseline=baseline, test=test,
            absent=absent, source_under_audit=source_under_audit,
        )
        print(marker)
    print(f"COPY_SOURCE_GHIDRA_PROGRAMS={len(selected)}")
    print("COPY_SOURCE_TEST_PASS=all")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.TimeoutExpired as error:
        print(f"COPY_SOURCE_TEST_ERROR=timeout: {error}", file=sys.stderr)
        raise
