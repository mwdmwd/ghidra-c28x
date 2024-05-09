TIBIN := /home/user/re/inverter/tms320/ti-cgt-c2000_22.6.1.LTS/bin/
ASFLAGS := asm2000 --buffer_diagnostics --suppress_asm_extension --parser_opts 49 --abi=coffabi --cla_background_task=off --float_operations_allowed=all --fp_mode=strict --mem_model:code=flat --mem_model:data=large --printf_support=full --version=28 --size_speed_goal=low_risk_size -D_OPTIMIZE_FOR_SPACE --c89 --symdebug:dwarf --keep_unneeded_types=false --advice:performance=all --buffer_diagnostics
AS := $(TIBIN)asm2000 $(ASFLAGS)

tms320c28.sla: tms320c28.cspec tms320c28.ldefs tms320c28.opinion tms320c28.pspec tms320c28.sinc tms320c28.slaspec
	/opt/ghidra/support/sleigh -a $$PWD

test.obj: test.asm
	$(AS) $< -o $@

.PHONY: test
test: tms320c28.sla
	./test.py
