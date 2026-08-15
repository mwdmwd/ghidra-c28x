    .sect ".cpdata"
    .align 2

    .global cp_struct_root
    .global cp_struct_callback
    .global cp_slot_standalone
    .global cp_slot_initialized
    .global cp_slot_repeat_first
    .global cp_slot_repeat_second
    .global cp_slot_propagated
    .global cp_slot_existing
    .global cp_slot_equal_merge
    .global cp_slot_scalar
    .global cp_slot_object_pointer
    .global cp_slot_zero
    .global cp_slot_all_ones
    .global cp_slot_uninitialized
    .global cp_slot_nonexec
    .global cp_slot_invalid
    .global cp_slot_interior
    .global cp_slot_partial
    .global cp_slot_dynamic
    .global cp_slot_clobber
    .global cp_slot_conflict
    .global cp_slot_call
    .global cp_slot_alternate
    .global cp_slot_composed
    .global cp_data_object
    .global cp_all_ones_value

cp_struct_root:
    .word   0x1357
cp_struct_callback:
    .long   0

cp_slot_standalone:       .long 0
cp_slot_initialized:      .long cp_static_target
cp_slot_repeat_first:     .long 0
cp_slot_repeat_second:    .long 0
cp_slot_propagated:       .long 0
cp_slot_existing:         .long 0
cp_slot_equal_merge:      .long 0
cp_slot_scalar:           .long 0
cp_slot_object_pointer:   .long cp_data_object
cp_slot_zero:             .long 0
cp_slot_all_ones:         .long 0
cp_slot_uninitialized:    .long 0
cp_slot_nonexec:          .long 0
cp_slot_invalid:          .long 0
cp_slot_interior:         .long 0
cp_slot_partial:          .long 0
cp_slot_dynamic:          .long 0
cp_slot_clobber:          .long 0
cp_slot_conflict:         .long 0
cp_slot_call:             .long 0
cp_slot_alternate:        .long 0
cp_slot_composed:         .long 0
cp_data_object:           .word 0x55aa
    .align 2
cp_all_ones_value:        .long 0xffffffff

    .sect ".text"
    .global cp_validation_entry
    .global cp_store_standalone
    .global cp_store_struct
    .global cp_store_initialized_replacement
    .global cp_store_repeat
    .global cp_store_propagated
    .global cp_store_existing
    .global cp_store_equal_merge
    .global cp_near_scalar
    .global cp_near_object_pointer
    .global cp_near_zero
    .global cp_near_all_ones
    .global cp_near_uninitialized
    .global cp_near_nonexec
    .global cp_near_invalid
    .global cp_near_interior
    .global cp_near_partial_store
    .global cp_near_dynamic
    .global cp_near_clobber
    .global cp_near_conflicting_merge
    .global cp_near_call
    .global cp_near_alternate_ingress
    .global cp_alternate_ingress_source
    .global cp_near_composed
    .global cp_clobber_helper
    .global cp_runtime_target
    .global cp_static_target
    .global cp_existing_target
    .global cp_other_target
    .global cp_scalar_lookalike_target
    .global cp_object_lookalike_target
    .global cp_interior_container
    .global cp_interior_target
    .global cp_invalid_target

    .global cp_store_standalone_site
    .global cp_store_struct_site
    .global cp_store_initialized_site
    .global cp_store_repeat_first_site
    .global cp_store_repeat_second_site
    .global cp_store_propagated_site
    .global cp_store_existing_site
    .global cp_store_equal_merge_site
    .global cp_near_scalar_site
    .global cp_near_object_pointer_site
    .global cp_near_zero_site
    .global cp_near_all_ones_site
    .global cp_near_uninitialized_site
    .global cp_near_nonexec_site
    .global cp_near_invalid_site
    .global cp_near_interior_site
    .global cp_near_partial_store_site
    .global cp_near_dynamic_site
    .global cp_near_clobber_site
    .global cp_near_conflict_site
    .global cp_near_call_site
    .global cp_near_alternate_site
    .global cp_near_composed_site

cp_store_standalone:
    .asmfunc
    MOVW    DP,#cp_slot_standalone
    MOVL    XAR4,#cp_runtime_target
cp_store_standalone_site:
    MOVL    @cp_slot_standalone,XAR4
    LRETR
    .endasmfunc

cp_store_struct:
    .asmfunc
    MOVW    DP,#cp_struct_callback
    MOVL    XAR4,#cp_runtime_target
cp_store_struct_site:
    MOVL    @cp_struct_callback,XAR4
    LRETR
    .endasmfunc

cp_store_initialized_replacement:
    .asmfunc
    MOVW    DP,#cp_slot_initialized
    MOVL    XAR4,#cp_runtime_target
cp_store_initialized_site:
    MOVL    @cp_slot_initialized,XAR4
    LRETR
    .endasmfunc

cp_store_repeat:
    .asmfunc
    MOVL    XAR4,#cp_runtime_target
    MOVW    DP,#cp_slot_repeat_first
cp_store_repeat_first_site:
    MOVL    @cp_slot_repeat_first,XAR4
    MOVW    DP,#cp_slot_repeat_second
cp_store_repeat_second_site:
    MOVL    @cp_slot_repeat_second,XAR4
    LRETR
    .endasmfunc

cp_store_propagated:
    .asmfunc
    MOVW    DP,#cp_slot_propagated
    MOVL    XAR5,#cp_runtime_target
    MOVL    XAR4,XAR5
cp_store_propagated_site:
    MOVL    @cp_slot_propagated,XAR4
    LRETR
    .endasmfunc

cp_store_existing:
    .asmfunc
    MOVW    DP,#cp_slot_existing
    MOVL    XAR4,#cp_existing_target
cp_store_existing_site:
    MOVL    @cp_slot_existing,XAR4
    LRETR
    .endasmfunc

cp_store_equal_merge:
    .asmfunc
    MOVW    DP,#cp_slot_equal_merge
    CMPB    AL,#0
    SB      cp_equal_high,NEQ
    MOVL    XAR4,#cp_runtime_target
    B       cp_equal_join,UNC
cp_equal_high:
    MOVL    XAR4,#cp_runtime_target
cp_equal_join:
cp_store_equal_merge_site:
    MOVL    @cp_slot_equal_merge,XAR4
    LRETR
    .endasmfunc

cp_near_scalar:
    .asmfunc
    MOVW    DP,#cp_slot_scalar
    MOVL    XAR4,#cp_scalar_lookalike_target
cp_near_scalar_site:
    MOVL    @cp_slot_scalar,XAR4
    LRETR
    .endasmfunc

cp_near_object_pointer:
    .asmfunc
    MOVW    DP,#cp_slot_object_pointer
    MOVL    XAR4,#cp_object_lookalike_target
cp_near_object_pointer_site:
    MOVL    @cp_slot_object_pointer,XAR4
    LRETR
    .endasmfunc

cp_near_zero:
    .asmfunc
    MOVW    DP,#cp_slot_zero
    MOVL    XAR4,#0
cp_near_zero_site:
    MOVL    @cp_slot_zero,XAR4
    LRETR
    .endasmfunc

; Construct the exact full-width all-ones runtime value through two partial
; accumulator writes.  The typed destination alone must not authorize it.
cp_near_all_ones:
    .asmfunc
    MOVW    DP,#cp_slot_all_ones
    MOV     AH,#0xffff
    MOV     AL,#0xffff
    MOVL    XAR4,ACC
cp_near_all_ones_site:
    MOVL    @cp_slot_all_ones,XAR4
    LRETR
    .endasmfunc

cp_near_uninitialized:
    .asmfunc
    MOVW    DP,#cp_slot_uninitialized
    MOVL    XAR4,#0x4000
cp_near_uninitialized_site:
    MOVL    @cp_slot_uninitialized,XAR4
    LRETR
    .endasmfunc

cp_near_nonexec:
    .asmfunc
    MOVW    DP,#cp_slot_nonexec
    MOVL    XAR4,#cp_data_object
cp_near_nonexec_site:
    MOVL    @cp_slot_nonexec,XAR4
    LRETR
    .endasmfunc

cp_near_invalid:
    .asmfunc
    MOVW    DP,#cp_slot_invalid
    MOVL    XAR4,#cp_invalid_target
cp_near_invalid_site:
    MOVL    @cp_slot_invalid,XAR4
    LRETR
    .endasmfunc

cp_near_interior:
    .asmfunc
    MOVW    DP,#cp_slot_interior
    MOVL    XAR4,#cp_interior_target
cp_near_interior_site:
    MOVL    @cp_slot_interior,XAR4
    LRETR
    .endasmfunc

cp_near_partial_store:
    .asmfunc
    MOVW    DP,#cp_slot_partial
    MOVL    XAR4,#cp_runtime_target
cp_near_partial_store_site:
    MOV     @cp_slot_partial,AR4
    LRETR
    .endasmfunc

cp_near_dynamic:
    .asmfunc
    MOVW    DP,#cp_slot_dynamic
cp_near_dynamic_site:
    MOVL    @cp_slot_dynamic,XAR4
    LRETR
    .endasmfunc

cp_near_clobber:
    .asmfunc
    MOVW    DP,#cp_slot_clobber
    MOVL    XAR4,#cp_runtime_target
    MOV     AR4,AL
cp_near_clobber_site:
    MOVL    @cp_slot_clobber,XAR4
    LRETR
    .endasmfunc

cp_near_conflicting_merge:
    .asmfunc
    MOVW    DP,#cp_slot_conflict
    CMPB    AL,#0
    SB      cp_conflict_other,NEQ
    MOVL    XAR4,#cp_runtime_target
    B       cp_conflict_join,UNC
cp_conflict_other:
    MOVL    XAR4,#cp_other_target
cp_conflict_join:
cp_near_conflict_site:
    MOVL    @cp_slot_conflict,XAR4
    LRETR
    .endasmfunc

cp_near_call:
    .asmfunc
    MOVL    XAR4,#cp_runtime_target
    LCR     cp_clobber_helper
    MOVW    DP,#cp_slot_call
cp_near_call_site:
    MOVL    @cp_slot_call,XAR4
    LRETR
    .endasmfunc

cp_near_alternate_ingress:
    .asmfunc
    MOVL    XAR4,#cp_runtime_target
cp_alternate_ingress_join:
    MOVW    DP,#cp_slot_alternate
cp_near_alternate_site:
    MOVL    @cp_slot_alternate,XAR4
    LRETR
    .endasmfunc

cp_alternate_ingress_source:
    .asmfunc
    B       cp_alternate_ingress_join,UNC
    .endasmfunc

cp_near_composed:
    .asmfunc
    MOVW    DP,#cp_slot_composed
    MOVL    XAR4,#cp_runtime_target
    ADDB    XAR4,#1
cp_near_composed_site:
    MOVL    @cp_slot_composed,XAR4
    LRETR
    .endasmfunc

cp_clobber_helper:
    .asmfunc
    MOVL    XAR4,#cp_other_target
    LRETR
    .endasmfunc

cp_runtime_target:
    .asmfunc
    MOVB    AL,#0x11
    LRETR
    .endasmfunc

cp_static_target:
    .asmfunc
    MOVB    AL,#0x22
    LRETR
    .endasmfunc

cp_existing_target:
    .asmfunc
    MOVB    AL,#0x33
    LRETR
    .endasmfunc

cp_other_target:
    .asmfunc
    MOVB    AL,#0x44
    LRETR
    .endasmfunc

cp_scalar_lookalike_target:
    .asmfunc
    MOVB    AL,#0x77
    LRETR
    .endasmfunc

cp_object_lookalike_target:
    .asmfunc
    MOVB    AL,#0x88
    LRETR
    .endasmfunc

cp_interior_container:
    .asmfunc
    MOVB    AL,#0x55
cp_interior_target:
    MOVB    AH,#0x66
    LRETR
    .endasmfunc

; 0x0000 is deliberately invalid in the checked C28x language.
cp_invalid_target:
    .word   0x0000
    .word   0x0000

cp_validation_entry:
    .asmfunc
    LCR     cp_store_standalone
    LCR     cp_store_struct
    LCR     cp_store_initialized_replacement
    LCR     cp_store_repeat
    LCR     cp_store_propagated
    LCR     cp_store_existing
    LCR     cp_store_equal_merge
    LCR     cp_near_scalar
    LCR     cp_near_object_pointer
    LCR     cp_near_zero
    LCR     cp_near_all_ones
    LCR     cp_near_uninitialized
    LCR     cp_near_nonexec
    LCR     cp_near_invalid
    LCR     cp_near_interior
    LCR     cp_near_partial_store
    LCR     cp_near_dynamic
    LCR     cp_near_clobber
    LCR     cp_near_conflicting_merge
    LCR     cp_near_call
    LCR     cp_near_alternate_ingress
    LCR     cp_alternate_ingress_source
    LCR     cp_near_composed
    LRETR
    .endasmfunc
