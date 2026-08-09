    .sect ".text"
    .global ffc_validation_entry
    .asmfunc
ffc_validation_entry:
    FFC       XAR7, ffc_valid
    FFC       XAR7, ffc_valid
    FFC       XAR7, near_clobber
    FFC       XAR7, near_mixed
    LCR       #near_mixed
    FFC       XAR7, near_ingress
    LCR       #near_ingress_source
    FFC       XAR7, near_flow
    LCR       #near_fallthrough_prefix
    FFC       XAR7, near_fallthrough
    LCR       #ordinary_indirect
    LRETR
    .endasmfunc

    ; Minimized linked reproduction of the live signed-division helper.  FFC
    ; defines XAR7 as its return register; none of these operations touches it.
    .asmfunc
ffc_valid:
    CLRC      TC
    CLRC      OVM
    ABSTC     ACC
    MOVL      P, ACC
    MOVL      ACC, *-SP[2]
    ABSTC     ACC
    MOVL      *-SP[2], ACC
    MOVB      ACC, #0
    RPT       #31
 || SUBCUL    ACC, *-SP[2]
    MOVL      ACC, P
    NEGTC     ACC
    CLRC      TC
    LB        *XAR7
    .endasmfunc

    ; Near miss: the helper destroys the FFC return register before LB.
    .asmfunc
near_clobber:
    MOVL      XAR7, #ordinary_target
    LB        *XAR7
    .endasmfunc

    ; Near miss: the same entry has both FFC and ordinary LCR callers.
    .asmfunc
near_mixed:
    MOVB      AL, #2
    LB        *XAR7
    .endasmfunc

    ; Near miss: a separate function jumps into the middle of the helper.
    .asmfunc
near_ingress:
    MOVB      AL, #3
near_ingress_inner:
    CLRC      TC
    LB        *XAR7
    .endasmfunc

    .asmfunc
near_ingress_source:
    LB        near_ingress_inner
    .endasmfunc

    ; Near miss: provenance is interrupted by explicit control flow.
    .asmfunc
near_flow:
    SB        near_flow_cont, UNC
near_flow_cont:
    LB        *XAR7
    .endasmfunc

    ; Near miss: decoded code falls through into the nominal FFC destination.
    .asmfunc
near_fallthrough_prefix:
    MOVB      AL, #4
near_fallthrough:
    CLRC      TC
    LB        *XAR7
    .endasmfunc

    ; Ordinary indirect branch: no FFC provenance and no return semantics.
    .asmfunc
ordinary_indirect:
    MOVL      XAR7, #ordinary_target
    LB        *XAR7
    .endasmfunc
ordinary_target:
    LRETR
