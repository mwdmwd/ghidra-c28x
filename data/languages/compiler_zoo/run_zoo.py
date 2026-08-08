#!/usr/bin/env python3
"""Build and classify the bounded TI CL2000 compiler-output zoo.

The checked-in C and generator are the corpus definition.  All objects, linked
images, disassemblies, fingerprints, and Ghidra input lists are generated into
an ignored build directory and are deliberately not source artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from generate_switches import GeneratedSwitch, generated_switches


INSTRUCTION_RE = re.compile(
    r"^\s*[0-9a-fA-F]{8}\s+[0-9a-fA-F]{4}\s+"
    r"(?:\|\|)?([A-Za-z][A-Za-z0-9.]*)\s*(.*?)\s*$"
)
SPACE_RE = re.compile(r"\s+")


@dataclass(frozen=True)
class BuildSpec:
    build_id: str
    family: str
    kind: str
    source: Path
    source_variant: dict[str, Any]
    entry: str
    model: str
    optimization: int
    opt_for_speed: int | None
    defines: dict[str, int]
    extra_flags: tuple[str, ...]
    expected: dict[str, int]
    ghidra_selected: bool


def run(command: list[str], *, cwd: Path) -> str:
    process = subprocess.run(
        command,
        cwd=cwd,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if process.returncode != 0:
        rendered = " ".join(command)
        raise RuntimeError(
            f"command failed ({process.returncode}): {rendered}\n{process.stdout}"
        )
    return process.stdout


def parse_instructions(disassembly: str) -> list[tuple[str, str]]:
    instructions: list[tuple[str, str]] = []
    for line in disassembly.splitlines():
        match = INSTRUCTION_RE.match(line)
        if match is None:
            continue
        mnemonic = match.group(1).upper()
        # Data words use the pseudo mnemonic '.word', which intentionally does
        # not match the leading-letter expression above.
        operands = SPACE_RE.sub(" ", match.group(2).strip())
        instructions.append((mnemonic, operands))
    return instructions


def schedule_text(instructions: list[tuple[str, str]]) -> str:
    return "\n".join(
        mnemonic if not operands else f"{mnemonic} {operands}"
        for mnemonic, operands in instructions
    )


def observed_properties(instructions: list[tuple[str, str]]) -> dict[str, int]:
    counts = Counter(mnemonic for mnemonic, _ in instructions)
    native_table_load = sum(
        1
        for mnemonic, operands in instructions
        if mnemonic == "MOVL"
        and re.match(r"^XAR7,\s*\*.*XAR7", operands, re.IGNORECASE)
    )
    observed: dict[str, int] = dict(sorted(counts.items()))
    observed["native_table_load"] = native_table_load
    return observed


def validate_expectations(
    build_id: str, expected: dict[str, int], observed: dict[str, int]
) -> None:
    failures: list[str] = []
    for key, value in expected.items():
        if key.endswith("_min"):
            actual_key = key[:-4]
            actual = observed.get(actual_key, 0)
            if actual < value:
                failures.append(f"{actual_key}={actual}, expected >= {value}")
        else:
            actual = observed.get(key, 0)
            if actual != value:
                failures.append(f"{key}={actual}, expected {value}")
    if failures:
        raise AssertionError(f"{build_id}: " + "; ".join(failures))


def build_id_for(
    family: str, model: str, optimization: int, speed: int | None
) -> str:
    result = f"{family}_{model}_o{optimization}"
    if speed is not None:
        result += f"_speed{speed}"
    return result


def expand_specs(
    manifest: dict[str, Any],
    zoo_dir: Path,
    generated_dir: Path,
) -> list[BuildSpec]:
    generated = generated_switches()
    selected = set(manifest["ghidra_selection"])
    specs: list[BuildSpec] = []

    for group in manifest["groups"]:
        family = group["family"]
        source_variant: dict[str, Any]
        if group.get("generated", False):
            generated_switch: GeneratedSwitch = generated[family]
            source = generated_dir / generated_switch.source_name
            source.write_text(generated_switch.source)
            entry = generated_switch.entry
            source_variant = {
                "generator": "generate_switches.py",
                "generated_family": family,
            }
        else:
            source = zoo_dir / group["source"]
            entry = group["entry"]
            source_variant = {"source": group["source"]}

        defines = {
            str(key): int(value) for key, value in group.get("defines", {}).items()
        }
        extra_flags = tuple(str(flag) for flag in group.get("extra_flags", []))
        if defines:
            source_variant["defines"] = defines
        if extra_flags:
            source_variant["extra_flags"] = list(extra_flags)

        for model in group["models"]:
            expected = {
                str(key): int(value)
                for key, value in group["expect"][model].items()
            }
            for optimization in group["optimizations"]:
                for speed in group["opt_for_speed"]:
                    build_id = build_id_for(
                        family, model, int(optimization), speed
                    )
                    specs.append(
                        BuildSpec(
                            build_id=build_id,
                            family=family,
                            kind=group["kind"],
                            source=source,
                            source_variant=source_variant,
                            entry=entry,
                            model=model,
                            optimization=int(optimization),
                            opt_for_speed=speed,
                            defines=defines,
                            extra_flags=extra_flags,
                            expected=expected,
                            ghidra_selected=build_id in selected,
                        )
                    )

    known = {spec.build_id for spec in specs}
    unknown = selected - known
    if unknown:
        raise ValueError(f"unknown ghidra_selection entries: {sorted(unknown)}")
    return specs


def compiler_flags(common: list[str], spec: BuildSpec) -> list[str]:
    flags = list(common)
    flags.extend(spec.extra_flags)
    flags.append(f"-O{spec.optimization}")
    if spec.model == "unified":
        flags.append("--unified_memory")
    elif spec.model != "default":
        raise ValueError(f"unsupported memory model {spec.model}")
    if spec.opt_for_speed is not None:
        flags.append(f"--opt_for_speed={spec.opt_for_speed}")
    for key, value in sorted(spec.defines.items()):
        flags.append(f"--define={key}={value}")
    return flags


def write_markdown(matrix: dict[str, Any], output: Path) -> None:
    lines = [
        "# Generated CL2000 zoo matrix",
        "",
        f"Compiler revision: `{matrix['compiler_revision']}`  ",
        "Generation uses no randomness.  ",
        f"Builds: **{matrix['summary']['builds']}**; Ghidra-selected: "
        f"**{matrix['summary']['ghidra_selected']}**; schedule groups: "
        f"**{matrix['summary']['schedule_groups']}**.",
        "",
        "| Build | Family | Model | Opt | Speed | PREAD | LB | Native load | Schedule | Ghidra |",
        "|---|---|---:|---:|---:|---:|---:|---:|---|---:|",
    ]
    for build in matrix["builds"]:
        observed = build["observed"]
        speed = "-" if build["opt_for_speed"] is None else str(build["opt_for_speed"])
        lines.append(
            "| {id} | {family} | {model} | O{opt} | {speed} | {pread} | {lb} | "
            "{native} | `{schedule}` | {ghidra} |".format(
                id=build["id"],
                family=build["family"],
                model=build["model"],
                opt=build["optimization"],
                speed=speed,
                pread=observed.get("PREAD", 0),
                lb=observed.get("LB", 0),
                native=observed.get("native_table_load", 0),
                schedule=build["schedule_sha256"][:12],
                ghidra="yes" if build["ghidra_selected"] else "no",
            )
        )

    lines.extend(["", "## Option sets that collapsed to the same schedule", ""])
    duplicates = [
        group for group in matrix["schedule_groups"] if len(group["members"]) > 1
    ]
    if not duplicates:
        lines.append("No duplicate instruction schedules were observed.")
    else:
        for group in duplicates:
            lines.append(
                f"- `{group['schedule_sha256'][:12]}`: "
                + ", ".join(f"`{item}`" for item in group["members"])
            )

    output.write_text("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    parser.add_argument(
        "--manifest", type=Path, default=Path(__file__).with_name("manifest.json")
    )
    parser.add_argument("--out", type=Path, default=Path("compiler-zoo-build"))
    parser.add_argument("--cl2000", required=True)
    parser.add_argument("--dis2000", required=True)
    parser.add_argument("--strip2000", required=True)
    args = parser.parse_args()

    root = args.root.resolve()
    manifest_path = args.manifest.resolve()
    out = args.out if args.out.is_absolute() else root / args.out
    out = out.resolve()
    zoo_dir = root / "compiler_zoo"
    link_command = zoo_dir / "zoo_link.cmd"

    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != 1:
        raise ValueError("unsupported compiler zoo manifest schema")

    if out.exists():
        shutil.rmtree(out)
    generated_dir = out / "generated"
    objects_dir = out / "objects"
    linked_dir = out / "linked"
    stripped_dir = out / "stripped"
    disassembly_dir = out / "disassembly"
    for directory in (
        generated_dir,
        objects_dir,
        linked_dir,
        stripped_dir,
        disassembly_dir,
    ):
        directory.mkdir(parents=True, exist_ok=True)

    specs = expand_specs(manifest, zoo_dir, generated_dir)
    common_flags = [str(flag) for flag in manifest["common_flags"]]
    compiler_revision = run([args.cl2000, "--compiler_revision"], cwd=root).strip()
    expected_match = re.search(r"\b\d+\.\d+\.\d+\b", str(manifest["compiler"]))
    if expected_match is None:
        raise ValueError("manifest compiler field does not contain a numeric revision")
    expected_revision = expected_match.group(0)
    if compiler_revision != expected_revision:
        raise RuntimeError(
            f"unexpected cl2000 revision {compiler_revision!r}; "
            f"expected {expected_revision!r}"
        )

    builds: list[dict[str, Any]] = []
    schedule_members: dict[str, list[str]] = defaultdict(list)
    ghidra_inputs: list[str] = []

    for index, spec in enumerate(specs, start=1):
        flags = compiler_flags(common_flags, spec)
        obj = objects_dir / f"{spec.build_id}.obj"
        linked = linked_dir / f"{spec.build_id}.linked.out"
        stripped = stripped_dir / f"{spec.build_id}.out"
        stripped_new = stripped.with_suffix(stripped.suffix + ".new")
        object_disassembly = disassembly_dir / f"{spec.build_id}.obj.txt"
        stripped_disassembly = disassembly_dir / f"{spec.build_id}.out.txt"

        compile_command = [
            args.cl2000,
            *flags,
            "--compile_only",
            f"--output_file={obj}",
            str(spec.source),
        ]
        run(compile_command, cwd=root)

        link_command_line = [
            args.cl2000,
            "--float_support=fpu32",
            "--abi=eabi",
            "--run_linker",
            f"--entry_point={spec.entry}",
            f"--output_file={linked}",
            str(obj),
            str(link_command),
        ]
        run(link_command_line, cwd=root)
        run(
            [args.strip2000, "--postlink", f"--outfile={stripped_new}", str(linked)],
            cwd=root,
        )
        stripped_new.replace(stripped)

        obj_text = run([args.dis2000, str(obj)], cwd=root)
        out_text = run([args.dis2000, str(stripped)], cwd=root)
        object_disassembly.write_text(obj_text)
        stripped_disassembly.write_text(out_text)

        instructions = parse_instructions(obj_text)
        if not instructions:
            raise AssertionError(f"{spec.build_id}: dis2000 produced no instructions")
        schedule = schedule_text(instructions)
        schedule_sha256 = hashlib.sha256(schedule.encode()).hexdigest()
        observed = observed_properties(instructions)
        validate_expectations(spec.build_id, spec.expected, observed)
        schedule_members[schedule_sha256].append(spec.build_id)

        if spec.ghidra_selected:
            ghidra_inputs.append(str(stripped.relative_to(root)))

        builds.append(
            {
                "id": spec.build_id,
                "family": spec.family,
                "kind": spec.kind,
                "source_variant": spec.source_variant,
                "entry": spec.entry,
                "model": spec.model,
                "optimization": spec.optimization,
                "opt_for_speed": spec.opt_for_speed,
                "flags": flags,
                "linked": True,
                "postlink_stripped": True,
                "expected": spec.expected,
                "observed": observed,
                "instruction_count": len(instructions),
                "schedule_sha256": schedule_sha256,
                "ghidra_selected": spec.ghidra_selected,
                "artifacts": {
                    "object": str(obj.relative_to(root)),
                    "linked": str(linked.relative_to(root)),
                    "stripped": str(stripped.relative_to(root)),
                    "object_disassembly": str(object_disassembly.relative_to(root)),
                    "stripped_disassembly": str(stripped_disassembly.relative_to(root)),
                },
            }
        )
        print(f"ZOO_BUILD {index:02d}/{len(specs):02d} {spec.build_id}")

    groups = [
        {"schedule_sha256": digest, "members": members}
        for digest, members in sorted(schedule_members.items())
    ]
    matrix = {
        "schema": 1,
        "randomness": "none",
        "compiler_expected": manifest["compiler"],
        "compiler_revision": compiler_revision,
        "manifest": str(manifest_path.relative_to(root)),
        "builds": builds,
        "schedule_groups": groups,
        "summary": {
            "builds": len(builds),
            "ghidra_selected": len(ghidra_inputs),
            "schedule_groups": len(groups),
            "duplicate_schedule_groups": sum(
                1 for group in groups if len(group["members"]) > 1
            ),
        },
    }

    (out / "matrix.json").write_text(
        json.dumps(matrix, indent=2, sort_keys=True) + "\n"
    )
    write_markdown(matrix, out / "matrix.md")
    (out / "ghidra-inputs.txt").write_text("\n".join(ghidra_inputs) + "\n")

    print(f"ZOO_COMPILER_REVISION={compiler_revision}")
    print(f"ZOO_BUILDS={len(builds)}")
    print(f"ZOO_GHIDRA_INPUTS={len(ghidra_inputs)}")
    print(f"ZOO_SCHEDULE_GROUPS={len(groups)}")
    print(
        "ZOO_DUPLICATE_SCHEDULE_GROUPS="
        f"{matrix['summary']['duplicate_schedule_groups']}"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AssertionError, OSError, RuntimeError, ValueError) as error:
        print(f"compiler zoo failed: {error}", file=sys.stderr)
        raise SystemExit(1)
