# Workspace setup

After importing a program with the correct processor and image base, run this
before auto-analysis:

```text
TMS320C28DeviceProfile.java profile=/absolute/path/device_profiles/f2837xs-compatible.json
```

`TMS320C28DeviceProfile.java` creates the memory map, peripheral labels, and
register types, and is safe to rerun. If a separately maintained image
workspace exists, add `workspace=/absolute/path/workspace.json` to validate the
image and recover its proved copies/seeds.

Only when a matching device ROM dump is available, load it after the profile
and before analysis:

```text
TMS320C28ImportRomEvidence.java path=/absolute/path/rom.bin base=0x... expectedWords=0x... sha256=... provenance=... execute=true
```

`TMS320C28ImportRomEvidence.java` verifies and materializes that dump; never use
a reference ROM as device truth. All JSON addresses and script `base` values
are C28x word addresses. Run auto-analysis last.
