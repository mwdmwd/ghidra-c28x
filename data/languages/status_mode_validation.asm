    .sect ".text"
    .global status_validation_entry
    .global status_unproved_entry
    .global status_stale_addu
    .global status_stale_nonaddu
    .global status_non_c_entry
    .global status_manual_callee
    .global status_ovm_set_add
    .global status_ovm_set_call_add
    .global status_ovm_clear_add
    .global status_ovm_conflict_rejoin
    .global status_ovm_ambiguous_call
    .global status_lc_positive
    .global status_lc_wrong_model
    .global status_ffc_positive
    .global status_ffc_wrong_model
    .global status_alternate_ingress
    .global status_alternate_source
    .global status_alternate_addu
    .global status_sxm_unknown_full
    .global status_stale_function

    .asmfunc
status_validation_entry:
    LCR       #status_manual_callee
    LCR       #status_ovm_set_add
    LCR       #status_ovm_set_call_add
    LCR       #status_ovm_clear_add
    LCR       #status_ovm_conflict_rejoin
    LCR       #status_ovm_ambiguous_call
    LCR       #status_lc_positive
    LCR       #status_lc_wrong_model
    LCR       #status_ffc_positive
    LCR       #status_ffc_wrong_model
    LCR       #status_non_c_entry
    LCR       #status_alternate_ingress
    LCR       #status_alternate_source
    LCR       #status_sxm_unknown_full
    LRETR
    .endasmfunc

    .asmfunc
status_manual_callee:
    MOVB      AL, #1
    LRETR
    .endasmfunc

    .asmfunc
status_ovm_set_add:
    SETC      OVM
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ovm_set_call_add:
    SETC      OVM
    LCR       #status_manual_callee
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ovm_clear_add:
    SETC      OVM
    CLRC      OVM
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ovm_conflict_rejoin:
    CMPB      AL, #0
    SB        status_ovm_clear_arm, EQ
    SETC      OVM
    SB        status_ovm_conflict_join, UNC
status_ovm_clear_arm:
    CLRC      OVM
status_ovm_conflict_join:
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ovm_ambiguous_call:
    LCR       *XAR7
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_lc_positive:
    LC        status_lc_target
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_lc_target:
    MOVB      AL, #2
    LRET
    .endasmfunc

    .asmfunc
status_lc_wrong_model:
    LC        status_lcr_target
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_lcr_target:
    MOVB      AL, #3
    LRETR
    .endasmfunc

    .asmfunc
status_ffc_positive:
    FFC       XAR7, status_ffc_target
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ffc_target:
    MOVB      AL, #4
    LB        *XAR7
    .endasmfunc

    .asmfunc
status_ffc_wrong_model:
    FFC       XAR7, status_ffc_wrong_target
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_ffc_wrong_target:
    MOVL      XAR7, #status_lcr_target
    LB        *XAR7
    .endasmfunc

    ; Called through LCR initially.  The Java regression test changes this
    ; function to __lc and reruns the proof to verify mismatched/non-C
    ; prototype revocation.
    .asmfunc
status_non_c_entry:
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    ; A separate function branches into the interior, invalidating the C-entry
    ; fact at the joined ADDU despite the ordinary LCR call to the entry.
    .asmfunc
status_alternate_ingress:
    MOVB      AL, #5
status_alternate_inner:
    MOVL      ACC, XAR4
status_alternate_addu:
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    .asmfunc
status_alternate_source:
    LB        status_alternate_inner
    .endasmfunc

    ; SXM has no TI C boundary value.  A full-width consumer must therefore
    ; retain the architectural mode dependence even at an ordinary C entry.
    .asmfunc
status_sxm_unknown_full:
    MOV       ACC, AR6 << #8
    LRETR
    .endasmfunc

    ; No call reaches this function.  Its ADDU must remain architectural.
    .asmfunc
status_unproved_entry:
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    ; Deliberately stale contexts are seeded before analysis and must be revoked.
    .asmfunc
status_stale_function:
    MOVL      ACC, XAR4
status_stale_addu:
    ADDU      ACC, AR6
status_stale_nonaddu:
    NOP
    LRETR
    .endasmfunc
    .end
