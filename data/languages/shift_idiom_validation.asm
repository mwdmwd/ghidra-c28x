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
    .global shift_pair_direct
    .global shift_pair_after_impy
    .global shift_pair_near_standalone
    .global shift_pair_near_first_count
    .global shift_pair_near_second_count
    .global shift_pair_near_separated
    .global shift_pair_near_second_ingress
    .global shift_pair_second_ingress_source
    .global shift_pair_near_first_ingress
    .global shift_pair_first_ingress_source
    .global shift_pair_near_flag_observer
    .global shift_pair_near_conflicting_rejoin
    .global shift_pair_alternate_second
    .global shift_pair_alternate_first
    .global shift_pair_stale_first
    .global shift_pair_stale_second

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


; Adjacent immediate #16,#16 is an exact net arithmetic shift by 32.
shift_pair_direct:
    .asmfunc
    ASR64   ACC:P,#16
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

; A normal straight-line producer may precede the pair.
shift_pair_after_impy:
    .asmfunc
    IMPYL   ACC,XT,ACC
    ASR64   ACC:P,#16
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

shift_pair_near_standalone:
    .asmfunc
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

shift_pair_near_first_count:
    .asmfunc
    ASR64   ACC:P,#15
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

shift_pair_near_second_count:
    .asmfunc
shift_pair_stale_first:
    ASR64   ACC:P,#16
shift_pair_stale_second:
    ASR64   ACC:P,#15
    LRETR
    .endasmfunc

shift_pair_near_separated:
    .asmfunc
    ASR64   ACC:P,#16
    NOP
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

; A second function can enter the second instruction directly.
shift_pair_near_second_ingress:
    .asmfunc
    ASR64   ACC:P,#16
shift_pair_alternate_second:
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

shift_pair_second_ingress_source:
    .asmfunc
    B       shift_pair_alternate_second,UNC
    .endasmfunc

; A non-call branch to a function entry is not an ordinary call ingress.
shift_pair_near_first_ingress:
    .asmfunc
shift_pair_alternate_first:
    ASR64   ACC:P,#16
    ASR64   ACC:P,#16
    LRETR
    .endasmfunc

shift_pair_first_ingress_source:
    .asmfunc
    B       shift_pair_alternate_first,UNC
    .endasmfunc

; An observer between the shifts prevents the bounded pair form.
shift_pair_near_flag_observer:
    .asmfunc
    ASR64   ACC:P,#16
    SB      shift_pair_flag_done,C
    ASR64   ACC:P,#16
shift_pair_flag_done:
    LRETR
    .endasmfunc

; Two predecessor paths enter the first #16 instruction.
shift_pair_near_conflicting_rejoin:
    .asmfunc
    CMPB    AL,#0
    SB      shift_pair_rejoin_high,NEQ
    NOP
    B       shift_pair_rejoin_join,UNC
shift_pair_rejoin_high:
    NOP
shift_pair_rejoin_join:
    ASR64   ACC:P,#16
    ASR64   ACC:P,#16
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
    LCR     shift_pair_direct
    LCR     shift_pair_after_impy
    LCR     shift_pair_near_standalone
    LCR     shift_pair_near_first_count
    LCR     shift_pair_near_second_count
    LCR     shift_pair_near_separated
    LCR     shift_pair_near_second_ingress
    LCR     shift_pair_second_ingress_source
    LCR     shift_pair_near_first_ingress
    LCR     shift_pair_first_ingress_source
    LCR     shift_pair_near_flag_observer
    LCR     shift_pair_near_conflicting_rejoin
    LRETR
    .endasmfunc
