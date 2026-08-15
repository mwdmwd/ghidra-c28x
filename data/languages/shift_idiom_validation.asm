    .text
    .global shift_validation_entry
    .global shift_t_direct_one
    .global shift_t_direct_max
    .global shift_t_direct_sixteen
    .global shift_t_equal_merge
    .global shift_t_redefined_after_clobber
    .global shift_t_near_call_clobber
    .global shift_t_near_conflicting_merge
    .global shift_t_near_zero
    .global shift_t_near_masked_zero
    .global shift_t_near_dynamic
    .global shift_t_near_partial_write
    .global shift_t_near_value_clobber
    .global shift_t_near_alternate_ingress
    .global shift_t_alternate_source
    .global shift_t_contract_callee
    .global shift_t_stale_zero
    .global shift_t_stale_nonshift
    .global shift_t_alternate_target

; Exact nonzero definitions select branch-free LSRL semantics.
shift_t_direct_one:
    .asmfunc
shift_t_stale_nonshift:
    NOP
    MOV     T,#1
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_direct_max:
    .asmfunc
    MOV     T,#31
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_direct_sixteen:
    .asmfunc
    MOV     T,#16
    LSRL    ACC,T
    LRETR
    .endasmfunc

; The full constants differ, but both effective T(4:0) values are one.
shift_t_equal_merge:
    .asmfunc
    CMPB    AL,#0
    SB      shift_t_equal_high,NEQ
    MOV     T,#1
    B       shift_t_equal_join,UNC
shift_t_equal_high:
    MOV     T,#33
shift_t_equal_join:
    LSRL    ACC,T
    LRETR
    .endasmfunc

; A later exact full definition may establish a new value after a clobber.
shift_t_redefined_after_clobber:
    .asmfunc
    MOV     T,#1
    MOV     T,AR4
    MOV     T,#7
    LSRL    ACC,T
    LRETR
    .endasmfunc

; T/XT are not preserved by an ordinary call, so this remains generic.
shift_t_near_call_clobber:
    .asmfunc
    MOV     T,#1
    LCR     shift_t_contract_callee
    LSRL    ACC,T
    LRETR
    .endasmfunc

; Conflicting effective predecessor values do not prove a count.
shift_t_near_conflicting_merge:
    .asmfunc
    CMPB    AL,#0
    SB      shift_t_conflict_two,NEQ
    MOV     T,#1
    B       shift_t_conflict_join,UNC
shift_t_conflict_two:
    MOV     T,#2
shift_t_conflict_join:
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_near_zero:
    .asmfunc
    MOV     T,#0
shift_t_stale_zero:
    LSRL    ACC,T
    LRETR
    .endasmfunc

; Width 32 is masked to zero by the documented T(4:0) count.
shift_t_near_masked_zero:
    .asmfunc
    MOV     T,#32
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_near_dynamic:
    .asmfunc
    MOV     T,AR4
    LSRL    ACC,T
    LRETR
    .endasmfunc

; MOVX TL writes/sign-extends the complete XT register, including T.
shift_t_near_partial_write:
    .asmfunc
    MOV     T,#1
    MOVX    TL,AR4
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_near_value_clobber:
    .asmfunc
    MOV     T,#1
    MOV     T,AR4
    LSRL    ACC,T
    LRETR
    .endasmfunc

; A separate function enters directly at the shift, bypassing its definition.
shift_t_near_alternate_ingress:
    .asmfunc
    MOV     T,#1
shift_t_alternate_target:
    LSRL    ACC,T
    LRETR
    .endasmfunc

shift_t_alternate_source:
    .asmfunc
    B       shift_t_alternate_target,UNC
    .endasmfunc

shift_t_contract_callee:
    .asmfunc
    MOV     T,#9
    LRETR
    .endasmfunc

shift_validation_entry:
    .asmfunc
    LCR     shift_t_direct_one
    LCR     shift_t_direct_max
    LCR     shift_t_direct_sixteen
    LCR     shift_t_equal_merge
    LCR     shift_t_redefined_after_clobber
    LCR     shift_t_near_call_clobber
    LCR     shift_t_near_conflicting_merge
    LCR     shift_t_near_zero
    LCR     shift_t_near_masked_zero
    LCR     shift_t_near_dynamic
    LCR     shift_t_near_partial_write
    LCR     shift_t_near_value_clobber
    LCR     shift_t_near_alternate_ingress
    LCR     shift_t_alternate_source
    LRETR
    .endasmfunc
