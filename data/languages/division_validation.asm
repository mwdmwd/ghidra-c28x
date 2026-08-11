    .text
    .global division_validation_entry
    .global division_positive_const
    .global division_positive_variable
    .global division_near_repeat_count
    .global division_near_initial_acc
    .global division_near_zero_divisor
    .global division_near_unknown_divisor
    .global division_near_mutated_divisor
    .global division_near_memory_alias
    .global division_near_intervening_flow
    .global division_near_alternate_ingress
    .global division_near_missing_dividend
    .global division_alternate_source

; Manual-backed positive: exactly 32 restoring steps, ACC=0, P=dividend,
; register divisor copied from a nonzero constant.
division_positive_const:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    MOVL    ACC,P
    LRETR
    .endasmfunc

; Variable nonzero divisor: ORB forces bit zero regardless of the input.
division_positive_variable:
    .asmfunc
    MOVL    P,ACC
    MOVL    ACC,*-SP[4]
    ORB     AL,#1
    MOVL    XAR6,ACC
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    MOVL    ACC,P
    LRETR
    .endasmfunc

; Wrong repeat count: only 31 executions.
division_near_repeat_count:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    ACC,#0
    RPT     #30
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; Last ACC definition is nonzero rather than the required zero remainder seed.
division_near_initial_acc:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    ACC,#1
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; Proved zero divisor must never select INT_DIV/INT_REM.
division_near_zero_divisor:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#0
    MOVL    XAR6,ACC
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; Runtime divisor with no dominating nonzero proof.
division_near_unknown_divisor:
    .asmfunc
    MOVL    P,ACC
    MOVL    XAR6,*-SP[4]
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; A partial AR6 write invalidates the earlier full-width divisor snapshot.
division_near_mutated_divisor:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    AR6,#11
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; Memory loc32 is deliberately rejected because intervening aliases cannot be
; disproved by the finite register-only matcher.
division_near_memory_alias:
    .asmfunc
    MOVL    P,ACC
    MOVL    XAR6,#0x3800
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,*XAR6
    LRETR
    .endasmfunc

; Explicit control flow inside the proof slice, even when it targets the next
; instruction, is not a straight-line restoring-division idiom.
division_near_intervening_flow:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    B       division_intervening_target,UNC
division_intervening_target:
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

; The branch from another entry provides alternate ingress after the snapshots.
division_near_alternate_ingress:
    .asmfunc
    MOVL    P,ACC
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    ACC,#0
division_alternate_target:
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

division_alternate_source:
    .asmfunc
    B       division_alternate_target,UNC
    .endasmfunc

; P has no local 32-bit dividend snapshot.
division_near_missing_dividend:
    .asmfunc
    MOVB    ACC,#10
    MOVL    XAR6,ACC
    MOVB    ACC,#0
    RPT     #31
    ||SUBCUL ACC,XAR6
    LRETR
    .endasmfunc

division_validation_entry:
    .asmfunc
    LCR     division_positive_const
    LCR     division_positive_variable
    LCR     division_near_repeat_count
    LCR     division_near_initial_acc
    LCR     division_near_zero_divisor
    LCR     division_near_unknown_divisor
    LCR     division_near_mutated_divisor
    LCR     division_near_memory_alias
    LCR     division_near_intervening_flow
    LCR     division_near_alternate_ingress
    LCR     division_near_missing_dividend
    LRETR
    .endasmfunc
