TIBIN := /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
AS := $(TIBIN)cl2000
ASFLAGS := --float_support=fpu32
DIS := $(TIBIN)dis2000
DISFLAGS ?=
HEX := $(TIBIN)hex2000
# -l lists conflicting patterns as errors because context-only ^instruction
# patterns (used for RPT semantics) inherently conflict with every regular instruction
# in SLEIGH's conflict checker, even though they resolve correctly at runtime by specificity
# Use make CONFLICTS=1 to re-enable for hunting real encoding overlaps
SLEIGH_REPORT_CONFLICTS :=

ifdef CONFLICTS
SLEIGH_REPORT_CONFLICTS := -l
endif

SLEIGH_GREP ?=

SHELL := /usr/bin/env bash
.SHELLFLAGS := -o pipefail -c

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec $(wildcard tms320c28*.sinc) tms320c28.slaspec
	/opt/ghidra/support/sleigh $(SLEIGH_REPORT_CONFLICTS) -u -t -c -a $$PWD $(SLEIGH_GREP) # -f unused fields

test.obj: test.asm
	$(AS) $(ASFLAGS) $<

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
	./test.py | sed -E 's/  +/ /g' | ./unhex_immediate.py

.PHONY: diff
diff: tms320c28.sla test.bin
	diff --side-by-side --left-column <(make --silent dis) <(make --silent test)

.PHONY: qdiff
qdiff: SLEIGH_GREP := 2>&1 | (grep -v '^INFO\|^openjdk\|^OpenJDK\|Compiling\|WARN.*NOP\|WARN.*-n\|WARN.*Truncation' || :)
qdiff: tms320c28.sla test.bin
	@diff -u <(make --silent dis) <(make --silent test)

.PHONY: qghidra
qghidra: tms320c28.sla
	@python3 qghidra.py

.PHONY: qasm
qasm:
	@rm -f quick.asm quick.obj
	@echo '    .text' > quick.asm
	@echo '    .newblock' >> quick.asm
	@echo '    .asmfunc' >> quick.asm
	@sed 's/^/  /' >> quick.asm
	@$(AS) $(ASFLAGS) quick.asm
	@$(DIS) $(DISFLAGS) quick.obj | grep . | grep -v Disassembly\ of
	@rm -f quick.asm quick.obj

.PHONY: clean
clean:
	rm -f tms320c28.sla test.obj test.bin quick.asm quick.obj
