TIBIN := /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
AS := $(TIBIN)cl2000
DIS := $(TIBIN)dis2000

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec tms320c28.sinc tms320c28.slaspec
	/opt/ghidra/support/sleigh -a $$PWD

test.obj: test.asm
	$(AS) $<

.PHONY: dis
dis: test.obj
	$(DIS) $<

.PHONY: test
test: tms320c28.sla
	./test.py
