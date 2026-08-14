    .sect ".ffc"
    .global stack_ffc_helper
    .global __c28xabi_divl

    ; FFC/XAR7 leaf: first 32-bit stack argument is architectural *-SP[2].
    .asmfunc
stack_ffc_helper:
    ADDL      ACC, *-SP[2]
    LB        *XAR7
    .endasmfunc

    ; Minimized TI signed-division helper schedule.  It preserves XAR7 and
    ; returns through LB *XAR7, so the existing finite FFC analyzer can prove
    ; this distinct call mechanism without a helper-name special case.
    .asmfunc
__c28xabi_divl:
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
