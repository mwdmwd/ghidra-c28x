TIBIN := /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
AS := $(TIBIN)cl2000
DIS := $(TIBIN)dis2000
HEX := $(TIBIN)hex2000

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec tms320c28.sinc tms320c28.slaspec
	/opt/ghidra/support/sleigh -a $$PWD

test.obj: test.asm
	$(AS) $<

test.bin: test.obj
	$(HEX) $< --binary -o $@

.PHONY: dis
dis: test.obj
	$(DIS) $< | tail -n+5 | sed -E 's/(<<|>>)\s+([0-9]+)/\1 #\2/g'

.PHONY: test
test: tms320c28.sla test.bin
	./test.py

.PHONY: diff
diff: tms320c28.sla test.bin
	diff -u <(make --silent dis) <(make --silent test)