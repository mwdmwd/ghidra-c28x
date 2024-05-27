TIBIN := /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
AS := $(TIBIN)cl2000
DIS := $(TIBIN)dis2000
DISFLAGS ?=
HEX := $(TIBIN)hex2000
SLEIGH_REPORT_CONFLICTS := -l

ifdef PERMISSIVE
SLEIGH_REPORT_CONFLICTS :=
endif

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec tms320c28.sinc tms320c28.slaspec
	/opt/ghidra/support/sleigh $(SLEIGH_REPORT_CONFLICTS) -u -t -c -o -a $$PWD # -f unused fields

test.obj: test.asm
	$(AS) $<

test.bin: test.obj
	$(HEX) $< --binary -o $@

.PHONY: dis
dis: test.obj
# movl rd, *--sp -> pop is dubious as it is implemented with != which bloats the sla to hell
# TODO no support for parallel
	$(DIS) $(DISFLAGS) $< | tail -n+5 | sed -E -e 's/(<<|>>)\s+([0-9]+)/\1 #\2/g' -e 's/ADDL      ACC/ADDL         ACC/g' -e 's/MOVL      ACC/MOVL         ACC/g' \
	-e 's/MOVL         ([A-Z0-9]+), \*--SP/POP          \1/g' -e 's/MOVL         \*SP\+\+, ([A-Z0-9]+)/PUSH         \1/g' \
	-e 's/\|\|/  /g' \
	| ./unhex_immediate.py

.PHONY: test
test: tms320c28.sla test.bin
	./test.py | ./unhex_immediate.py

.PHONY: diff
diff: tms320c28.sla test.bin
	diff --side-by-side --left-column <(make --silent dis) <(make --silent test)