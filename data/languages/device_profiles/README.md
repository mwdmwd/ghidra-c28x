# Workspace setup

After importing a program with the correct processor and image base, run this
before auto-analysis:

```text
TMS320C28DeviceProfile.java profile=/absolute/path/device_profiles/f2837xs-compatible.json
```

`TMS320C28DeviceProfile.java` creates the memory map, peripheral labels,
register types, generated CAN byte-peripheral access views, and exact
pointer-to-function data for authoritative PIE vector slots, and is safe to
rerun. The profile declares slot identities and types, never firmware handler
values. If a separately maintained image
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

## CAN byte-peripheral access views

The checked profile preserves every logical 32-bit CAN IF register as a
four-byte `dword` and adds two non-overlapping physical access views for its
upper lanes.  `<REGISTER>_BYTE2` and `<REGISTER>_BYTE3` identify logical bits
16-23 and 24-31 at displayed C28x word offsets `+2` and `+3`.  Each view uses a
two-byte Ghidra data unit, one word in this two-byte-addressed language.  The
profile carries 28 such views for CANA and 28 for CANB; no rule is inferred for
16-bit CAN registers or another peripheral family.

`accessViews` metadata records the parent, logical range, physical storage, and
the TI fields represented by each lane.  The applicator validates the complete
collection before mapping any profile state.  It preserves incompatible code,
data, and user symbols rather than clearing them, emits deterministic created/
skipped counters, and is semantically idempotent.


## Explicit inert copy sources

An individual record under `copyRecovery.explicit` may opt into source
retirement with exactly:

```json
{
  "name": "RAM_RUN_SECTION",
  "source": 65536,
  "destination": 8192,
  "words": 256,
  "executable": true,
  "sourceDisposition": "inert-storage",
  "evidence": "workspace-owned exact copy proof"
}
```

The field is optional.  Its absence preserves ordinary copy recovery, and the
only accepted value is the exact string `inert-storage`.  The option is
record-local: it is never inferred from equal bytes, an executable destination,
`.cinit`, or another copy record.

Destination materialization still runs first.  Source cleanup then requires the
complete explicit record, positive bounded initialized non-overlapping ranges,
full source/destination byte equality, matching destination execute permission,
one isolatable initialized source block, no function entry or intersecting
function body, no external entry point, no workspace analysis seed, no flow
reference or fall-through from outside the exact source span, no conflicting
executable-copy destination, and no code/data unit crossing an isolation
boundary.  A failed premise emits a deterministic source-cleanup diagnostic and
does not revoke otherwise valid destination recovery.

A proved source is split out exactly, retains its bytes and initialized/read/
write/volatile state, loses only execute permission, and has decoded
instructions plus their outgoing references cleared in one transaction.
Defined data, user/evidence labels and namespaces, listing comments, bookmarks,
and external non-flow references are retained.  The exact block receives a
workspace-owned provenance marker, so reapplying the same workspace is
idempotent and later auto-analysis cannot decode it again.

This transformation is monotonic.  Removing the field later does not
implicitly restore execute permission or deleted analysis state; automatic
restoration would require original split ownership, permissions, and listing
state that the workspace does not claim to reconstruct.

Run the finite migration and near-miss corpus whenever this contract changes:

```sh
make copy-source-test
```

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
