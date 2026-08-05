
TIBIN ?= /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
SLEIGH ?= /opt/ghidra/support/sleigh
PYTHON ?= python3
AS := $(TIBIN)cl2000
ASFLAGS := --float_support=fpu32
DIS := $(TIBIN)dis2000
DISFLAGS ?=
HEX := $(TIBIN)hex2000
CFLAGS ?= $(ASFLAGS) --abi=eabi --c11 -O2 --symdebug:none
GHIDRA_HEADLESS ?= /opt/ghidra/support/analyzeHeadless
GHIDRA_DECOMP_DIR := ghidra-decomp
DECOMPILE_SOURCE ?= abi_test.c
DECOMPILE_OBJECT ?= abi_test.obj
DECOMPILE_NAME ?= $(basename $(notdir $(DECOMPILE_OBJECT)))
DECOMPILE_FUNCTIONS ?=
# -l lists conflicting patterns as errors because context-only ^instruction
# patterns (used for RPT semantics) inherently conflict with every regular instruction
# in SLEIGH's conflict checker, even though they resolve correctly at runtime by specificity
# Use make CONFLICTS=1 to re-enable for hunting real encoding overlaps
SLEIGH_REPORT_CONFLICTS :=

ifdef CONFLICTS
SLEIGH_REPORT_CONFLICTS := -l
endif

ifdef V
SLEIGH_GREP := 2>&1 | (grep -v '^INFO\|^openjdk\|^OpenJDK\|Compiling' || :)
Q :=
else
SLEIGH_GREP := 2>&1 | (grep -v '^INFO\|^openjdk\|^OpenJDK\|Compiling\|WARN.*NOP\|WARN.*-n\|WARN.*Truncation' || :)
Q := @
endif

SHELL := /usr/bin/env bash
.SHELLFLAGS := -o pipefail -c

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec $(wildcard tms320c28*.sinc) tms320c28.slaspec
	$(Q)$(SLEIGH) $(SLEIGH_REPORT_CONFLICTS) -u -t -c tms320c28.slaspec $(SLEIGH_GREP) # -f unused fields

test.obj: test.asm
	$(Q)$(AS) $(ASFLAGS) $<

$(DECOMPILE_OBJECT): $(DECOMPILE_SOURCE) Makefile
	$(Q)$(AS) $(CFLAGS) --compile_only --output_file=$@ $<

test.bin: test.obj
	@$(HEX) $< --binary -o $@ 2>&1 | (grep -v '^Translating\|text ==>' || :)

.PHONY: dis
dis: test.obj
# movl rd, *--sp -> pop is dubious as it is implemented with != which bloats the sla to hell
	$(DIS) $(DISFLAGS) $< | tail -n+5 \
	| perl -0777 -pe 's/\n\s+\|\|/ || /g' \
	| sed -E -e 's/(<<|>>)\s+([0-9]+)/\1 #\2/g' \
	-e 's/ADDL      ACC/ADDL         ACC/g' \
	-e 's/MOVL      ACC/MOVL         ACC/g' \
	-e 's/\|\|\s+/|| /g' \
	-e 's/\s+\|\|/ ||/g' \
	-e 's/\|\|([A-Z])/\1/g' \
	-e 's/MOVL         ([A-Z0-9]+), \*--SP/POP          \1/g' \
	-e 's/MOVL         \*SP\+\+, ([A-Z0-9]+)/PUSH         \1/g' \
	-e 's/SUBL      ACC/SUBL         ACC/' \
	-e 's/XRETC        UNC/XRET         /g' \
	-e 's/BANZ         (.*),/BANZ         \1, /g' \
	-e 's/MOVIZ        R([0-9]+)/MOVIZ        R\1H/g' \
	-e 's/SWAPF        R([0-9]+),\s+R([0-9]+)/SWAPF        R\1H, R\2H/g' \
	-e 's/ZERO         R([0-9]+)/ZERO         R\1H/g' \
	-e 's/RPTB([[:space:]]+)#[$$][+]/RPTB         /g' \
	-e 's/  +/ /g' \
	| ./unhex_immediate.py

.PHONY: test
test: tms320c28.sla test.bin
	$(PYTHON) ./test.py | sed -E 's/  +/ /g' | ./unhex_immediate.py

# Full visual diff
.PHONY: diff
diff: tms320c28.sla test.bin
	diff --side-by-side --left-column <(make --silent dis) <(make --silent test)

# Quiet diff (no output if identical)
.PHONY: qdiff
qdiff: tms320c28.sla test.bin
	$(Q)diff -u <(make --silent dis) <(make --silent test)

# Disassemble hex words from stdin with Ghidra, to assembly
.PHONY: qghidra
qghidra: tms320c28.sla
	$(Q)$(PYTHON) qghidra.py

# Disassemble hex words from stdin with Ghidra, to P-Code
.PHONY: qpcode
qpcode: tms320c28.sla
	$(Q)$(PYTHON) qpcode.py

# Focused P-Code semantic regressions for compiler-critical instructions.
.PHONY: semantic-test
semantic-test: tms320c28.sla semantic_tests.py
	$(Q)$(PYTHON) semantic_tests.py

# Assemble instructions from stdin, print along with hex words
.PHONY: qasm
qasm:
	@rm -f quick.asm quick.obj
	@echo '    .text' > quick.asm
	@echo '    .newblock' >> quick.asm
	@echo '    .asmfunc' >> quick.asm
	@sed 's/^/  /' >> quick.asm
	$(Q)$(AS) $(ASFLAGS) quick.asm
	$(Q)$(DIS) $(DISFLAGS) quick.obj | grep . | grep -v Disassembly\ of
	@rm -f quick.asm quick.obj

# Compile a C sample with cl2000, import it into Ghidra, and decompile selected functions.
# DECOMPILE_FUNCTIONS is a space-separated list; Decompile.java uses its ABI defaults when empty.
# Set an isolated environment to avoid using any user Ghidra settings.
.PHONY: decompile
decompile: tms320c28.sla $(DECOMPILE_OBJECT) Decompile.java
	@mkdir -p $(GHIDRA_DECOMP_DIR)/home $(GHIDRA_DECOMP_DIR)/config $(GHIDRA_DECOMP_DIR)/project $(GHIDRA_DECOMP_DIR)/tmp $(GHIDRA_DECOMP_DIR)/cache
	$(Q)HOME=$$PWD/$(GHIDRA_DECOMP_DIR)/home XDG_CONFIG_HOME=$$PWD/$(GHIDRA_DECOMP_DIR)/config \
		GHIDRA_HEADLESS_JAVA_OPTIONS="-Dapplication.tempdir=$$PWD/$(GHIDRA_DECOMP_DIR)/tmp -Dapplication.cachedir=$$PWD/$(GHIDRA_DECOMP_DIR)/cache -Djava.io.tmpdir=$$PWD/$(GHIDRA_DECOMP_DIR)/tmp" \
		$(GHIDRA_HEADLESS) $$PWD/$(GHIDRA_DECOMP_DIR)/project $(DECOMPILE_NAME) \
		-import $(DECOMPILE_OBJECT) -processor tms320c28:LE:32:default -cspec default \
		-scriptPath $$PWD -postScript Decompile.java $(DECOMPILE_FUNCTIONS) \
		-log $$PWD/$(GHIDRA_DECOMP_DIR)/ghidra.log \
		-scriptlog $$PWD/$(GHIDRA_DECOMP_DIR)/script.log \
		-analysisTimeoutPerFile 60 -overwrite -deleteProject

.PHONY: clean
clean:
	@rm -rf $(GHIDRA_DECOMP_DIR)
	@rm -f tms320c28.sla test.obj test.bin abi_test.obj quick.asm quick.obj
