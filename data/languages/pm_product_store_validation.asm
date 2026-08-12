    .text
    .global pm_validation_entry
    .global pm_boundary_store
    .global pm_explicit_zero
    .global pm_explicit_zero_rejoin
    .global pm_explicit_zero_after_dynamic
    .global pm_after_completed_call
    .global pm_after_unequal_calls
    .global pm_contract_callee
    .global pm_near_positive_shift
    .global pm_near_negative_shift
    .global pm_near_dynamic_pm
    .global pm_near_dynamic_st0
    .global pm_near_conflicting_paths
    .global pm_near_alternate_ingress
    .global pm_near_undominated_zero_loop
    .global pm_alternate_source
    .global pm_near_raw101_c28
    .global pm_near_raw101_c2x
    .global pm_stale_store
    .global pm_stale_nonmov

; A call-reached function entry is a documented TI C run-time boundary.  The
; deliberately tagged NOP lets the regression prove stale context is removed
; from non-MOV instructions without changing its bytes or display.
pm_boundary_store:
    .asmfunc
pm_stale_nonmov:
    NOP
    MOV     AR0,P
    LRETR
    .endasmfunc

; A dominating explicit decoded PM=0 definition selects the direct low-half
; product store.
pm_explicit_zero:
    .asmfunc
    SPM     #0
    MOV     AR0,P
    LRETR
    .endasmfunc

; Both predecessor paths define the same effective PM value before the merge.
pm_explicit_zero_rejoin:
    .asmfunc
    CMPB    AL,#0
    SB      pm_zero_short,NEQ
    SPM     #0
    B       pm_zero_join,UNC
pm_zero_short:
    SPM     #0
pm_zero_join:
    MOV     AR0,P
    LRETR
    .endasmfunc

; A dynamic PM write is invalid until a later dominating exact definition.
pm_explicit_zero_after_dynamic:
    .asmfunc
    MOV     PM,AL
    SPM     #0
    MOV     AR0,P
    LRETR
    .endasmfunc

; A completed call returns with raw PM=1, represented by decoded PM=0.  Start
; from a conflicting value so the positive depends on the return contract.
pm_after_completed_call:
    .asmfunc
    SPM     #1
    LCR     pm_contract_callee
    MOV     AR0,P
    LRETR
    .endasmfunc

; One arm completes one call and the other completes three.  Every predecessor
; reaches the store with decoded PM=0 despite the unequal call counts.
pm_after_unequal_calls:
    .asmfunc
    SPM     #-1
    CMPB    AL,#0
    SB      pm_one_call,NEQ
    LCR     pm_contract_callee
    LCR     pm_contract_callee
    LCR     pm_contract_callee
    B       pm_calls_join,UNC
pm_one_call:
    LCR     pm_contract_callee
pm_calls_join:
    MOV     AR0,P
    LRETR
    .endasmfunc

pm_contract_callee:
    .asmfunc
    SPM     #0
    LRETR
    .endasmfunc

; Nonzero left shift: stale direct-form context is preseeded specifically on
; this MOV and must be revoked by the analyzer.
pm_near_positive_shift:
    .asmfunc
    SPM     #1
pm_stale_store:
    MOV     AR0,P
    LRETR
    .endasmfunc

; Negative shift remains on generic pmshift().
pm_near_negative_shift:
    .asmfunc
    SPM     #-1
    MOV     AR0,P
    LRETR
    .endasmfunc

; Runtime PM value cannot prove a direct store.
pm_near_dynamic_pm:
    .asmfunc
    MOV     PM,AL
    MOV     AR0,P
    LRETR
    .endasmfunc

; POP ST0 dynamically restores PM together with the other status fields.
pm_near_dynamic_st0:
    .asmfunc
    POP     ST0
    MOV     AR0,P
    LRETR
    .endasmfunc

; Conflicting exact predecessor values do not agree at the merge.
pm_near_conflicting_paths:
    .asmfunc
    CMPB    AL,#0
    SB      pm_conflict_nonzero,NEQ
    SPM     #0
    B       pm_conflict_join,UNC
pm_conflict_nonzero:
    SPM     #1
pm_conflict_join:
    MOV     AR0,P
    LRETR
    .endasmfunc

; A separate function jumps past the explicit zero definition and directly to
; the store, so the nominal function has exterior/alternate ingress.
pm_near_alternate_ingress:
    .asmfunc
    SPM     #0
pm_alternate_target:
    MOV     AR0,P
    LRETR
    .endasmfunc

pm_alternate_source:
    .asmfunc
    B       pm_alternate_target,UNC
    .endasmfunc

; This function has no documented call boundary.  The explicit zero lies after
; the store and reaches the entry only through a backedge, so it does not
; dominate the store's first execution and must not bootstrap a proof.
pm_near_undominated_zero_loop:
    .asmfunc
    MOV     AR0,P
    SPM     #0
    B       pm_near_undominated_zero_loop,UNC
    .endasmfunc

; Raw PM=101 is never no-shift: it is right four in C28x mode ...
pm_near_raw101_c28:
    .asmfunc
    CLRC    AMODE
    SPM     #-4
    MOV     AR0,P
    LRETR
    .endasmfunc

; ... and the same raw bits mean left four in AMODE=1.  The TI assembler spells
; the raw encoding as #-4, while the context-sensitive Ghidra decode is #4.
pm_near_raw101_c2x:
    .asmfunc
    SETC    AMODE
    SPM     #-4
    MOV     AR0,P
    CLRC    AMODE
    LRETR
    .endasmfunc

pm_validation_entry:
    .asmfunc
    LCR     pm_boundary_store
    LCR     pm_explicit_zero
    LCR     pm_explicit_zero_rejoin
    LCR     pm_explicit_zero_after_dynamic
    LCR     pm_after_completed_call
    LCR     pm_after_unequal_calls
    LCR     pm_near_positive_shift
    LCR     pm_near_negative_shift
    LCR     pm_near_dynamic_pm
    LCR     pm_near_dynamic_st0
    LCR     pm_near_conflicting_paths
    LCR     pm_near_alternate_ingress
    LCR     pm_alternate_source
    LCR     pm_near_raw101_c28
    LCR     pm_near_raw101_c2x
    LRETR
    .endasmfunc
