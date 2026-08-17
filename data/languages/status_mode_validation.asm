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
    .global status_addcl_boundary_zero
    .global status_addcl_setc_sxm_preserve
    .global status_addcl_clrc_sxm_preserve
    .global status_addcl_setc_multibit_preserve
    .global status_addcl_clrc_multibit_preserve
    .global status_addcl_setc_includes_ovm
    .global status_addcl_clrc_includes_ovm
    .global status_addcl_conflict_rejoin
    .global status_addcl_ambiguous_call
    .global status_addcl_st0_write
    .global status_addcl_alternate_ingress
    .global status_addcl_alternate_source
    .global status_addcl_alternate_site
    .global status_addcl_unproved_entry
    .global status_stale_addcl_function
    .global status_stale_addcl
    .global status_addl_pm_boundary_zero
    .global status_addl_pm_explicit_clear
    .global status_addl_pm_setc_sxm_preserve
    .global status_addl_pm_clrc_sxm_preserve
    .global status_addl_pm_setc_multibit_preserve
    .global status_addl_pm_clrc_multibit_preserve
    .global status_addl_pm_setc_ovm
    .global status_addl_pm_conflict_rejoin
    .global status_addl_pm_ambiguous_call
    .global status_addl_pm_st0_write
    .global status_addl_pm_alternate_ingress
    .global status_addl_pm_alternate_source
    .global status_addl_pm_alternate_site
    .global status_addl_pm_unproved_entry
    .global status_stale_addl_pm_function
    .global status_stale_addl_pm
    .global status_stale_addl_loc32_function
    .global status_stale_addl_loc32

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
    LCR       #status_addcl_boundary_zero
    LCR       #status_addcl_setc_sxm_preserve
    LCR       #status_addcl_clrc_sxm_preserve
    LCR       #status_addcl_setc_multibit_preserve
    LCR       #status_addcl_clrc_multibit_preserve
    LCR       #status_addcl_setc_includes_ovm
    LCR       #status_addcl_clrc_includes_ovm
    LCR       #status_addcl_conflict_rejoin
    LCR       #status_addcl_ambiguous_call
    LCR       #status_addcl_st0_write
    LCR       #status_addcl_alternate_ingress
    LCR       #status_addcl_alternate_source
    LCR       #status_addl_pm_boundary_zero
    LCR       #status_addl_pm_explicit_clear
    LCR       #status_addl_pm_setc_sxm_preserve
    LCR       #status_addl_pm_clrc_sxm_preserve
    LCR       #status_addl_pm_setc_multibit_preserve
    LCR       #status_addl_pm_clrc_multibit_preserve
    LCR       #status_addl_pm_setc_ovm
    LCR       #status_addl_pm_conflict_rejoin
    LCR       #status_addl_pm_ambiguous_call
    LCR       #status_addl_pm_st0_write
    LCR       #status_addl_pm_alternate_ingress
    LCR       #status_addl_pm_alternate_source
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

    ; An ordinary TI C boundary establishes OVM=0 without assuming a global
    ; architectural reset state.  This is the simplest exact ADDCL consumer.
    .asmfunc
status_addcl_boundary_zero:
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; Mode mask bit 0 is SXM.  These exact single-bit masks must preserve the
    ; incoming OVM=0 fact rather than being mistaken for an OVM write.
    .asmfunc
status_addcl_setc_sxm_preserve:
    SETC      SXM
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_clrc_sxm_preserve:
    CLRC      SXM
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; 0x05 selects SXM and TC, but not bit 1 (OVM).  Both exact multi-bit
    ; SETC and CLRC therefore preserve the incoming OVM state.
    .asmfunc
status_addcl_setc_multibit_preserve:
    SETC      #5
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_clrc_multibit_preserve:
    CLRC      #5
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; 0x03 selects both SXM and OVM.  SETC makes OVM one and must retain the
    ; generic saturating ADDCL; CLRC makes OVM zero and selects the exact form.
    .asmfunc
status_addcl_setc_includes_ovm:
    SETC      #3
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_clrc_includes_ovm:
    SETC      OVM
    CLRC      #3
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_conflict_rejoin:
    CMPB      AL, #0
    SB        status_addcl_clear_arm, EQ
    SETC      OVM
    SB        status_addcl_conflict_join, UNC
status_addcl_clear_arm:
    CLRC      OVM
status_addcl_conflict_join:
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_ambiguous_call:
    LCR       *XAR7
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; A dynamic ST0 restore writes OVM among the other status fields.  It is
    ; intentionally not treated like a preserving exact SETC/CLRC mask.
    .asmfunc
status_addcl_st0_write:
    POP       ST0
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; An interior branch from a different function invalidates the otherwise
    ; ordinary C boundary fact at this exact ADDCL site.
    .asmfunc
status_addcl_alternate_ingress:
    MOVB      AL, #6
status_addcl_alternate_inner:
    MOVL      ACC, XAR4
status_addcl_alternate_site:
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    .asmfunc
status_addcl_alternate_source:
    LB        status_addcl_alternate_inner
    .endasmfunc

    ; The exact one-word 0x10ac ADDL uses P and decoded signed PM as dynamic
    ; architectural inputs.  Only the pre-existing OVM proof selects it.
    .asmfunc
status_addl_pm_boundary_zero:
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    ; An explicit clear is a local OVM=0 origin for the exact shifted-P ADDL.
    .asmfunc
status_addl_pm_explicit_clear:
    SETC      OVM
    CLRC      OVM
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    ; Exact SETC/CLRC masks that omit OVM preserve the incoming C-boundary zero.
    .asmfunc
status_addl_pm_setc_sxm_preserve:
    SETC      SXM
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_clrc_sxm_preserve:
    CLRC      SXM
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_setc_multibit_preserve:
    SETC      #5
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_clrc_multibit_preserve:
    CLRC      #5
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    ; SETC OVM, a conflicting join, an unresolved call, and a dynamic ST0 write
    ; each leave the exact ADDL on its generic architectural constructor.
    .asmfunc
status_addl_pm_setc_ovm:
    SETC      OVM
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_conflict_rejoin:
    CMPB      AL, #0
    SB        status_addl_pm_clear_arm, EQ
    SETC      OVM
    SB        status_addl_pm_conflict_join, UNC
status_addl_pm_clear_arm:
    CLRC      OVM
status_addl_pm_conflict_join:
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_ambiguous_call:
    LCR       *XAR7
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_st0_write:
    POP       ST0
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    ; A branch from another function reaches the interior and invalidates the
    ; otherwise ordinary C-entry fact at this exact shifted-P ADDL.
    .asmfunc
status_addl_pm_alternate_ingress:
    MOVL      P, XAR5
    SPM       #1
status_addl_pm_alternate_inner:
    MOVL      ACC, XAR4
status_addl_pm_alternate_site:
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_addl_pm_alternate_source:
    LB        status_addl_pm_alternate_inner
    .endasmfunc

    ; No call reaches this function.  Its ADDU must remain architectural.
    .asmfunc
status_unproved_entry:
    MOVL      ACC, XAR4
    ADDU      ACC, AR6
    LRETR
    .endasmfunc

    ; No call reaches this function.  Its ADDCL must remain architectural.
    .asmfunc
status_addcl_unproved_entry:
    MOVL      ACC, XAR4
    ADDCL     ACC, XAR6
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

    .asmfunc
status_stale_addcl_function:
    MOVL      ACC, XAR4
status_stale_addcl:
    ADDCL     ACC, XAR6
    LRETR
    .endasmfunc

    ; No call reaches this exact shifted-P ADDL function.
    .asmfunc
status_addl_pm_unproved_entry:
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    ; Deliberately stale exact and non-candidate ADDL contexts are seeded before
    ; analysis.  Both must be revoked and redisassembled generically.
    .asmfunc
status_stale_addl_pm_function:
    MOVL      P, XAR5
    SPM       #1
    MOVL      ACC, XAR4
status_stale_addl_pm:
    ADDL      ACC, P << PM
    SPM       #0
    LRETR
    .endasmfunc

    .asmfunc
status_stale_addl_loc32_function:
    MOVL      ACC, XAR4
status_stale_addl_loc32:
    ADDL      ACC, XAR6
    LRETR
    .endasmfunc
    .end
