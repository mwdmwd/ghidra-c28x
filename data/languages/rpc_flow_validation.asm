    .sect ".text"
    .global rpc_flow_entry, lc_direct_target, lcr_direct_target
    .global lc_indirect_target, lcr_indirect_target, lrete_target, iret_target
    .asmfunc
rpc_flow_entry:
    LC lc_direct_target
    LCR lcr_direct_target
    MOVL XAR7,#lc_indirect_target
    LC *XAR7
    MOVL XAR0,#lcr_indirect_target
    LCR *XAR0
    LCR lrete_target
    LCR iret_target
    LRETR
    .endasmfunc
    .asmfunc
lc_direct_target: LRET
    .endasmfunc
    .asmfunc
lcr_direct_target: LRETR
    .endasmfunc
    .asmfunc
lc_indirect_target: LRET
    .endasmfunc
    .asmfunc
lcr_indirect_target: LRETR
    .endasmfunc
    .asmfunc
lrete_target: LRETE
    .endasmfunc
    .asmfunc
iret_target: IRET
    .endasmfunc
