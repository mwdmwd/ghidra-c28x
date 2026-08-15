# Workspace setup

After importing a program with the correct processor and image base, run this
before auto-analysis:

```text
TMS320C28DeviceProfile.java profile=/absolute/path/device_profiles/f2837xs-compatible.json
```

`TMS320C28DeviceProfile.java` creates the memory map, peripheral labels,
register types, and exact pointer-to-function data for authoritative PIE vector
slots, and is safe to rerun. The profile declares slot identities and types,
never firmware handler values. If a separately maintained image
workspace exists, add `workspace=/absolute/path/workspace.json` to validate the
image and recover its proved copies/seeds.

Only when a matching device ROM dump is available, load it after the profile
and before analysis:

```text
TMS320C28ImportRomEvidence.java path=/absolute/path/rom.bin base=0x... expectedWords=0x... sha256=... provenance=... execute=true
```

`TMS320C28ImportRomEvidence.java` verifies and materializes that dump.
All JSON addresses and script `base` values are C28x word addresses.
Run auto-analysis last.

## Regenerating the profile

Use TI's public `c2000ware-core-sdk` at commit `e5698c666d9ff587940d249213cbbb328a3bcd66`: https://github.com/TexasInstruments/c2000ware-core-sdk

```sh
sdk_root=/path/to/c2000ware-core-sdk
subset_dir=$(mktemp -d)
install -d "$subset_dir/sysconfig-registers" "$subset_dir/device-headers"
cp "$sdk_root"/driverlib/.meta/device_driverlib_peripherals/f2837xs_{memmap,*_registers}.js \
  "$subset_dir/sysconfig-registers/"
cp "$sdk_root"/device_support/f2837xs/headers/include/F2837xS_pie{ctrl,vect}.h \
  "$subset_dir/device-headers/"
make profile-generate-check C2000WARE_F2837XS_SUBSET="$subset_dir"
```


A headers-only operator subset is also accepted for deterministic PIE
supplement regeneration when the checked profile already carries the complete
SysConfig-derived map. It must contain exactly the same
`device-headers/F2837xS_piectrl.h` and `F2837xS_pievect.h`; the generator hashes
those inputs and byte-compares the complete output.
