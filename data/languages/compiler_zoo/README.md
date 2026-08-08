# TI CL2000 compiler zoo

This directory is a small, deterministic corpus for testing the compiler-to-Ghidra pipeline rather than arbitrary instruction bytes. It keeps the reviewable inputs and expectations in Git; generated objects, linked images, post-link-stripped images, disassemblies, and Ghidra projects live under ignored build directories.

## Entry points

```sh
make zoo-build
make zoo-test
```

`make zoo-build` reads `manifest.json`, generates the parameterized switch sources, and invokes the bundled TI `cl2000`, `dis2000`, and `strip2000` tools. Each option set receives a distinct object name. Every subject is linked and passed through `strip2000 --postlink`; that step resolves jump-table metadata and removes compiler-local symbols that would otherwise distort Ghidra function discovery. The target writes:

- `compiler-zoo-build/matrix.json` — exact source variant, flags, structural expectations, observed instruction counts, artifact form, and normalized schedule fingerprint for every build;
- `compiler-zoo-build/matrix.md` — a review-oriented table and duplicate-schedule groups;
- `compiler-zoo-build/ghidra-inputs.txt` — the bounded subset imported by the integration test;
- generated source, objects, linked and stripped images, and `dis2000` listings in corresponding subdirectories.

`make zoo-test` imports the selected stripped images into a fresh headless Ghidra project and runs `ZooTest.java`. The assertions cover computed references, distinct switch destinations, function-body reachability, original case values and defaults, conservative rejection of unsupported switch forms, loop/control-flow structure, byte and 64-bit data flow, direct-call/stack ABI patterns, common FPU32 instructions, repeated integer division, and the forward-compatible TMU decode gap.

## Corpus organization

- `manifest.json` is the option matrix and structural contract.
- `generate_switches.py` contains named, deterministic switch families.
- `switch_saved32.c` is the minimized source for the saved-XAR7 32-bit selector form.
- `control_flow.c`, `data_flow.c`, `abi_calls.c`, `fpu32.c`,
  `integer_division.c`, and `tmu_division.c` are compact hand-written source
  families with defined C behavior. The TMU family deliberately remains a
  known-gap subject until `DIVF32` is implemented by the language module.
- `run_zoo.py` is the bounded driver. It validates the compiler revision, emitted instruction properties, and duplicate schedules.
- `zoo_link.cmd` supplies the fixed link layout used for every subject.

There is no random generation and therefore no seed. Expanding the corpus should add a named source family or explicit generator parameters and corresponding structural expectations, not a large Cartesian product. When multiple option sets emit the same normalized schedule, the generated matrix records the collapse rather than counting it as independent instruction-shape coverage.

## Evidence limits

TI compiler and disassembler output establish emitted idioms, encodings, aliases, and ABI conventions. They are not execution oracles for flags or runtime behavior. Any SLEIGH change prompted by the zoo still requires the complete instruction description and focused P-Code regression. The module has no TI ELF relocation handler, so linked, self-contained, post-link-stripped subjects are preferred over conclusions drawn from unresolved relocatable objects.
