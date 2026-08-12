    .sect ".text"
    .global switch_saved_validation_entry
    .asmfunc
switch_saved_validation_entry:
    LCR       #saved_global_valid
    LCR       #saved_stack_valid
    LCR       #saved_subb_valid
    LCR       #near_save_source
    LCR       #near_reload_slot
    LCR       #near_partial_overwrite
    LCR       #near_compare_register
    LCR       #near_guard_condition
    LCR       #near_flag_change
    LCR       #near_alternate_ingress
    LCR       #near_interior_ingress
    LCR       #near_global_clrc
    LCR       #near_wrong_source
    LCR       #near_wrong_scale
    LCR       #near_table_base
    LCR       #near_writable_table
    LCR       #near_short_table
    LCR       #near_high_target
    LCR       #near_nonexec_target
    LCR       #near_called_target
    LCR       #near_stack_setc
    LCR       #near_subb_guard_imm
    LCR       #near_subb_tail_imm
    LCR       #near_subb_bound
    LCR       #near_subb_reload
    LCR       #near_subb_unsafe_range
    LCR       #near_alternate_ingress_source
    LCR       #near_interior_ingress_source
    LCR       #called_table_target
    LRETR
    .endasmfunc

    .asmfunc
saved_global_valid:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
saved_global_valid_ingress:
    .word     0xffef
    .word     saved_global_valid_dispatch-saved_global_valid_ingress
saved_global_valid_dispatch:
    CMPB      AL, #3
    MOVZ      AR6, @global_saved_selector
    SB        saved_global_valid_default, HI
    MOVL      XAR7, #saved_global_valid_table
    SETC      SXM
    MOVL      ACC, XAR7
saved_global_valid_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
saved_global_valid_branch:
    LB        *XAR7
saved_global_valid_default:
    MOVB      AL, #0xff
    LRETR
saved_global_valid_case0:
    MOVB      AL, #16
    LRETR
saved_global_valid_case1:
    MOVB      AL, #17
    LRETR
saved_global_valid_case2:
    MOVB      AL, #18
    LRETR
saved_global_valid_case3:
    MOVB      AL, #19
    LRETR
    .endasmfunc

    .asmfunc
saved_stack_valid:
    MOV       *-SP[1], AL
saved_stack_valid_ingress:
    .word     0xffef
    .word     saved_stack_valid_dispatch-saved_stack_valid_ingress
saved_stack_valid_dispatch:
    CMPB      AL, #3
    MOVZ      AR6, *-SP[1]
    SB        saved_stack_valid_default, HI
    MOVL      XAR7, #saved_stack_valid_table
    CLRC      SXM
    MOVL      ACC, XAR7
saved_stack_valid_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
saved_stack_valid_branch:
    LB        *XAR7
saved_stack_valid_default:
    MOVB      AL, #0xff
    LRETR
saved_stack_valid_case0:
    MOVB      AL, #0x20
    LRETR
saved_stack_valid_case1:
    MOVB      AL, #0x21
    LRETR
saved_stack_valid_case2:
    MOVB      AL, #0x22
    LRETR
saved_stack_valid_case3:
    MOVB      AL, #0x23
    LRETR
    .endasmfunc
    .asmfunc
saved_subb_valid:
    MOVL      XAR7, @state_selector
    MOVB      XAR6, #3
    MOVL      ACC, XAR7
saved_subb_valid_guard_subb:
    SUBB      ACC, #1
    CMPL      ACC, XAR6
    SB        saved_subb_valid_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #saved_subb_valid_table
    LSL       ACC, #1
saved_subb_valid_tail_subb:
    SUBB      ACC, #2
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
saved_subb_valid_branch:
    LB        *XAR7
saved_subb_valid_default:
    MOVB      AL, #0xff
    LRETR
saved_subb_valid_case0:
    MOVB      AL, #49
    LRETR
saved_subb_valid_case1:
    MOVB      AL, #50
    LRETR
saved_subb_valid_case2:
    MOVB      AL, #51
    LRETR
saved_subb_valid_case3:
    MOVB      AL, #52
    LRETR
    .endasmfunc

    .asmfunc
near_save_source:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AH
near_save_source_ingress:
    .word     0xffef
    .word     near_save_source_dispatch-near_save_source_ingress
near_save_source_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_save_source_default, HI
    MOVL      XAR7, #near_save_source_table
    SETC      SXM
    MOVL      ACC, XAR7
near_save_source_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_save_source_branch:
    LB        *XAR7
near_save_source_default:
    MOVB      AL, #0xff
    LRETR
near_save_source_case0:
    MOVB      AL, #64
    LRETR
near_save_source_case1:
    MOVB      AL, #65
    LRETR
near_save_source_case2:
    MOVB      AL, #66
    LRETR
    .endasmfunc

    .asmfunc
near_reload_slot:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_reload_slot_ingress:
    .word     0xffef
    .word     near_reload_slot_dispatch-near_reload_slot_ingress
near_reload_slot_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector_alt
    SB        near_reload_slot_default, HI
    MOVL      XAR7, #near_reload_slot_table
    SETC      SXM
    MOVL      ACC, XAR7
near_reload_slot_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_reload_slot_branch:
    LB        *XAR7
near_reload_slot_default:
    MOVB      AL, #0xff
    LRETR
near_reload_slot_case0:
    MOVB      AL, #68
    LRETR
near_reload_slot_case1:
    MOVB      AL, #69
    LRETR
near_reload_slot_case2:
    MOVB      AL, #70
    LRETR
    .endasmfunc

    .asmfunc
near_partial_overwrite:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
    MOVB      @global_saved_selector, AH.LSB
near_partial_overwrite_ingress:
    .word     0xffef
    .word     near_partial_overwrite_dispatch-near_partial_overwrite_ingress
near_partial_overwrite_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_partial_overwrite_default, HI
    MOVL      XAR7, #near_partial_overwrite_table
    SETC      SXM
    MOVL      ACC, XAR7
near_partial_overwrite_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_partial_overwrite_branch:
    LB        *XAR7
near_partial_overwrite_default:
    MOVB      AL, #0xff
    LRETR
near_partial_overwrite_case0:
    MOVB      AL, #72
    LRETR
near_partial_overwrite_case1:
    MOVB      AL, #73
    LRETR
near_partial_overwrite_case2:
    MOVB      AL, #74
    LRETR
    .endasmfunc

    .asmfunc
near_compare_register:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_compare_register_ingress:
    .word     0xffef
    .word     near_compare_register_dispatch-near_compare_register_ingress
near_compare_register_dispatch:
    CMPB      AH, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_compare_register_default, HI
    MOVL      XAR7, #near_compare_register_table
    SETC      SXM
    MOVL      ACC, XAR7
near_compare_register_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_compare_register_branch:
    LB        *XAR7
near_compare_register_default:
    MOVB      AL, #0xff
    LRETR
near_compare_register_case0:
    MOVB      AL, #76
    LRETR
near_compare_register_case1:
    MOVB      AL, #77
    LRETR
near_compare_register_case2:
    MOVB      AL, #78
    LRETR
    .endasmfunc

    .asmfunc
near_guard_condition:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_guard_condition_ingress:
    .word     0xffef
    .word     near_guard_condition_dispatch-near_guard_condition_ingress
near_guard_condition_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_guard_condition_default, GEQ
    MOVL      XAR7, #near_guard_condition_table
    SETC      SXM
    MOVL      ACC, XAR7
near_guard_condition_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_guard_condition_branch:
    LB        *XAR7
near_guard_condition_default:
    MOVB      AL, #0xff
    LRETR
near_guard_condition_case0:
    MOVB      AL, #80
    LRETR
near_guard_condition_case1:
    MOVB      AL, #81
    LRETR
near_guard_condition_case2:
    MOVB      AL, #82
    LRETR
    .endasmfunc

    .asmfunc
near_flag_change:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_flag_change_ingress:
    .word     0xffef
    .word     near_flag_change_dispatch-near_flag_change_ingress
near_flag_change_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    ADDB      AL, #0
    SB        near_flag_change_default, HI
    MOVL      XAR7, #near_flag_change_table
    SETC      SXM
    MOVL      ACC, XAR7
near_flag_change_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_flag_change_branch:
    LB        *XAR7
near_flag_change_default:
    MOVB      AL, #0xff
    LRETR
near_flag_change_case0:
    MOVB      AL, #84
    LRETR
near_flag_change_case1:
    MOVB      AL, #85
    LRETR
near_flag_change_case2:
    MOVB      AL, #86
    LRETR
    .endasmfunc

    .asmfunc
near_alternate_ingress:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_alternate_ingress_ingress:
    .word     0xffef
    .word     near_alternate_ingress_dispatch-near_alternate_ingress_ingress
near_alternate_ingress_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_alternate_ingress_default, HI
    MOVL      XAR7, #near_alternate_ingress_table
    SETC      SXM
    MOVL      ACC, XAR7
near_alternate_ingress_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_alternate_ingress_branch:
    LB        *XAR7
near_alternate_ingress_default:
    MOVB      AL, #0xff
    LRETR
near_alternate_ingress_case0:
    MOVB      AL, #88
    LRETR
near_alternate_ingress_case1:
    MOVB      AL, #89
    LRETR
near_alternate_ingress_case2:
    MOVB      AL, #90
    LRETR
    .endasmfunc

    .asmfunc
near_interior_ingress:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_interior_ingress_ingress:
    .word     0xffef
    .word     near_interior_ingress_dispatch-near_interior_ingress_ingress
near_interior_ingress_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_interior_ingress_default, HI
    MOVL      XAR7, #near_interior_ingress_table
    SETC      SXM
    MOVL      ACC, XAR7
near_interior_ingress_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_interior_ingress_branch:
    LB        *XAR7
near_interior_ingress_default:
    MOVB      AL, #0xff
    LRETR
near_interior_ingress_case0:
    MOVB      AL, #92
    LRETR
near_interior_ingress_case1:
    MOVB      AL, #93
    LRETR
near_interior_ingress_case2:
    MOVB      AL, #94
    LRETR
    .endasmfunc

    .asmfunc
near_global_clrc:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_global_clrc_ingress:
    .word     0xffef
    .word     near_global_clrc_dispatch-near_global_clrc_ingress
near_global_clrc_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_global_clrc_default, HI
    MOVL      XAR7, #near_global_clrc_table
    CLRC      SXM
    MOVL      ACC, XAR7
near_global_clrc_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_global_clrc_branch:
    LB        *XAR7
near_global_clrc_default:
    MOVB      AL, #0xff
    LRETR
near_global_clrc_case0:
    MOVB      AL, #96
    LRETR
near_global_clrc_case1:
    MOVB      AL, #97
    LRETR
near_global_clrc_case2:
    MOVB      AL, #98
    LRETR
    .endasmfunc

    .asmfunc
near_wrong_source:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_wrong_source_ingress:
    .word     0xffef
    .word     near_wrong_source_dispatch-near_wrong_source_ingress
near_wrong_source_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_wrong_source_default, HI
    MOVL      XAR7, #near_wrong_source_table
    SETC      SXM
    MOVL      ACC, XAR7
near_wrong_source_add:
    ADD       ACC, AR5 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_wrong_source_branch:
    LB        *XAR7
near_wrong_source_default:
    MOVB      AL, #0xff
    LRETR
near_wrong_source_case0:
    MOVB      AL, #100
    LRETR
near_wrong_source_case1:
    MOVB      AL, #101
    LRETR
near_wrong_source_case2:
    MOVB      AL, #102
    LRETR
    .endasmfunc

    .asmfunc
near_wrong_scale:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_wrong_scale_ingress:
    .word     0xffef
    .word     near_wrong_scale_dispatch-near_wrong_scale_ingress
near_wrong_scale_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_wrong_scale_default, HI
    MOVL      XAR7, #near_wrong_scale_table
    SETC      SXM
    MOVL      ACC, XAR7
near_wrong_scale_add:
    ADD       ACC, AR6 << #2
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_wrong_scale_branch:
    LB        *XAR7
near_wrong_scale_default:
    MOVB      AL, #0xff
    LRETR
near_wrong_scale_case0:
    MOVB      AL, #104
    LRETR
near_wrong_scale_case1:
    MOVB      AL, #105
    LRETR
near_wrong_scale_case2:
    MOVB      AL, #106
    LRETR
    .endasmfunc

    .asmfunc
near_table_base:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_table_base_ingress:
    .word     0xffef
    .word     near_table_base_dispatch-near_table_base_ingress
near_table_base_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_table_base_default, HI
    MOVL      XAR7, #near_table_base_table+1
    SETC      SXM
    MOVL      ACC, XAR7
near_table_base_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_table_base_branch:
    LB        *XAR7
near_table_base_default:
    MOVB      AL, #0xff
    LRETR
near_table_base_case0:
    MOVB      AL, #108
    LRETR
near_table_base_case1:
    MOVB      AL, #109
    LRETR
near_table_base_case2:
    MOVB      AL, #110
    LRETR
    .endasmfunc

    .asmfunc
near_writable_table:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_writable_table_ingress:
    .word     0xffef
    .word     near_writable_table_dispatch-near_writable_table_ingress
near_writable_table_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_writable_table_default, HI
    MOVL      XAR7, #near_writable_table_table
    SETC      SXM
    MOVL      ACC, XAR7
near_writable_table_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_writable_table_branch:
    LB        *XAR7
near_writable_table_default:
    MOVB      AL, #0xff
    LRETR
near_writable_table_case0:
    MOVB      AL, #112
    LRETR
near_writable_table_case1:
    MOVB      AL, #113
    LRETR
near_writable_table_case2:
    MOVB      AL, #114
    LRETR
    .endasmfunc

    .asmfunc
near_short_table:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_short_table_ingress:
    .word     0xffef
    .word     near_short_table_dispatch-near_short_table_ingress
near_short_table_dispatch:
    CMPB      AL, #3
    MOVZ      AR6, @global_saved_selector
    SB        near_short_table_default, HI
    MOVL      XAR7, #near_short_table_table
    SETC      SXM
    MOVL      ACC, XAR7
near_short_table_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_short_table_branch:
    LB        *XAR7
near_short_table_default:
    MOVB      AL, #0xff
    LRETR
near_short_table_case0:
    MOVB      AL, #116
    LRETR
near_short_table_case1:
    MOVB      AL, #117
    LRETR
near_short_table_case2:
    MOVB      AL, #118
    LRETR
near_short_table_case3:
    MOVB      AL, #119
    LRETR
    .endasmfunc

    .asmfunc
near_high_target:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_high_target_ingress:
    .word     0xffef
    .word     near_high_target_dispatch-near_high_target_ingress
near_high_target_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_high_target_default, HI
    MOVL      XAR7, #near_high_target_table
    SETC      SXM
    MOVL      ACC, XAR7
near_high_target_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_high_target_branch:
    LB        *XAR7
near_high_target_default:
    MOVB      AL, #0xff
    LRETR
near_high_target_case0:
    MOVB      AL, #120
    LRETR
near_high_target_case1:
    MOVB      AL, #121
    LRETR
near_high_target_case2:
    MOVB      AL, #122
    LRETR
    .endasmfunc

    .asmfunc
near_nonexec_target:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_nonexec_target_ingress:
    .word     0xffef
    .word     near_nonexec_target_dispatch-near_nonexec_target_ingress
near_nonexec_target_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_nonexec_target_default, HI
    MOVL      XAR7, #near_nonexec_target_table
    SETC      SXM
    MOVL      ACC, XAR7
near_nonexec_target_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_nonexec_target_branch:
    LB        *XAR7
near_nonexec_target_default:
    MOVB      AL, #0xff
    LRETR
near_nonexec_target_case0:
    MOVB      AL, #124
    LRETR
near_nonexec_target_case1:
    MOVB      AL, #125
    LRETR
near_nonexec_target_case2:
    MOVB      AL, #126
    LRETR
    .endasmfunc

    .asmfunc
near_called_target:
    MOV       AL, @global_selector
    MOV       @global_saved_selector, AL
near_called_target_ingress:
    .word     0xffef
    .word     near_called_target_dispatch-near_called_target_ingress
near_called_target_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, @global_saved_selector
    SB        near_called_target_default, HI
    MOVL      XAR7, #near_called_target_table
    SETC      SXM
    MOVL      ACC, XAR7
near_called_target_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_called_target_branch:
    LB        *XAR7
near_called_target_default:
    MOVB      AL, #0xff
    LRETR
near_called_target_case0:
    MOVB      AL, #128
    LRETR
near_called_target_case1:
    MOVB      AL, #129
    LRETR
near_called_target_case2:
    MOVB      AL, #130
    LRETR
    .endasmfunc

    .asmfunc
near_stack_setc:
    MOV       *-SP[1], AL
near_stack_setc_ingress:
    .word     0xffef
    .word     near_stack_setc_dispatch-near_stack_setc_ingress
near_stack_setc_dispatch:
    CMPB      AL, #2
    MOVZ      AR6, *-SP[1]
    SB        near_stack_setc_default, HI
    MOVL      XAR7, #near_stack_setc_table
    SETC      SXM
    MOVL      ACC, XAR7
near_stack_setc_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_stack_setc_branch:
    LB        *XAR7
near_stack_setc_default:
    MOVB      AL, #0xff
    LRETR
near_stack_setc_case0:
    MOVB      AL, #132
    LRETR
near_stack_setc_case1:
    MOVB      AL, #133
    LRETR
near_stack_setc_case2:
    MOVB      AL, #134
    LRETR
    .endasmfunc

    .asmfunc
near_subb_guard_imm:
    MOVL      XAR7, @state_selector
    MOVB      XAR6, #2
    MOVL      ACC, XAR7
near_subb_guard_imm_guard_subb:
    SUBB      ACC, #2
    CMPL      ACC, XAR6
    SB        near_subb_guard_imm_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #near_subb_guard_imm_table
    LSL       ACC, #1
near_subb_guard_imm_tail_subb:
    SUBB      ACC, #2
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_subb_guard_imm_branch:
    LB        *XAR7
near_subb_guard_imm_default:
    MOVB      AL, #0xff
    LRETR
near_subb_guard_imm_case0:
    MOVB      AL, #144
    LRETR
near_subb_guard_imm_case1:
    MOVB      AL, #145
    LRETR
near_subb_guard_imm_case2:
    MOVB      AL, #146
    LRETR
    .endasmfunc

    .asmfunc
near_subb_tail_imm:
    MOVL      XAR7, @state_selector
    MOVB      XAR6, #2
    MOVL      ACC, XAR7
near_subb_tail_imm_guard_subb:
    SUBB      ACC, #1
    CMPL      ACC, XAR6
    SB        near_subb_tail_imm_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #near_subb_tail_imm_table
    LSL       ACC, #1
near_subb_tail_imm_tail_subb:
    SUBB      ACC, #4
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_subb_tail_imm_branch:
    LB        *XAR7
near_subb_tail_imm_default:
    MOVB      AL, #0xff
    LRETR
near_subb_tail_imm_case0:
    MOVB      AL, #148
    LRETR
near_subb_tail_imm_case1:
    MOVB      AL, #149
    LRETR
near_subb_tail_imm_case2:
    MOVB      AL, #150
    LRETR
    .endasmfunc

    .asmfunc
near_subb_bound:
    MOVL      XAR7, @state_selector
    MOVB      XAR6, #0
    MOVL      ACC, XAR7
near_subb_bound_guard_subb:
    SUBB      ACC, #1
    CMPL      ACC, XAR6
    SB        near_subb_bound_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #near_subb_bound_table
    LSL       ACC, #1
near_subb_bound_tail_subb:
    SUBB      ACC, #2
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_subb_bound_branch:
    LB        *XAR7
near_subb_bound_default:
    MOVB      AL, #0xff
    LRETR
near_subb_bound_case0:
    MOVB      AL, #152
    LRETR
near_subb_bound_case1:
    MOVB      AL, #153
    LRETR
near_subb_bound_case2:
    MOVB      AL, #154
    LRETR
    .endasmfunc

    .asmfunc
near_subb_reload:
    MOVL      XAR7, @state_selector
    MOVB      XAR6, #2
    MOVL      ACC, XAR7
near_subb_reload_guard_subb:
    SUBB      ACC, #1
    CMPL      ACC, XAR6
    SB        near_subb_reload_default, HI
    MOVL      ACC, P
    MOVL      XAR7, #near_subb_reload_table
    LSL       ACC, #1
near_subb_reload_tail_subb:
    SUBB      ACC, #2
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_subb_reload_branch:
    LB        *XAR7
near_subb_reload_default:
    MOVB      AL, #0xff
    LRETR
near_subb_reload_case0:
    MOVB      AL, #156
    LRETR
near_subb_reload_case1:
    MOVB      AL, #157
    LRETR
near_subb_reload_case2:
    MOVB      AL, #158
    LRETR
    .endasmfunc

    .asmfunc
near_subb_unsafe_range:
    MOVL      XAR7, @state_selector
    MOVL      XAR6, @unsafe_bound
    MOVL      ACC, XAR7
near_subb_unsafe_range_guard_subb:
    SUBB      ACC, #1
    CMPL      ACC, XAR6
    SB        near_subb_unsafe_range_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #near_subb_unsafe_range_table
    LSL       ACC, #1
near_subb_unsafe_range_tail_subb:
    SUBB      ACC, #2
    ADDL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
near_subb_unsafe_range_branch:
    LB        *XAR7
near_subb_unsafe_range_default:
    MOVB      AL, #0xff
    LRETR
near_subb_unsafe_range_case0:
    MOVB      AL, #160
    LRETR
near_subb_unsafe_range_case1:
    MOVB      AL, #161
    LRETR
near_subb_unsafe_range_case2:
    MOVB      AL, #162
    LRETR
    .endasmfunc

    .asmfunc
near_alternate_ingress_source:
near_alternate_ingress_source_ingress:
    .word     0xffef
    .word     near_alternate_ingress_dispatch-near_alternate_ingress_source_ingress
    .endasmfunc

    .asmfunc
near_interior_ingress_source:
near_interior_ingress_source_ingress:
    .word     0xffef
    .word     near_interior_ingress_add-near_interior_ingress_source_ingress
    .endasmfunc

    .asmfunc
called_table_target:
    MOVB      AL, #0xee
    LRETR
    .endasmfunc

    .sect ".switch"
saved_global_valid_table:
    .long     saved_global_valid_case0
    .long     saved_global_valid_case1
    .long     saved_global_valid_case2
    .long     saved_global_valid_case3
saved_stack_valid_table:
    .long     saved_stack_valid_case0
    .long     saved_stack_valid_case1
    .long     saved_stack_valid_case2
    .long     saved_stack_valid_case3
saved_subb_valid_table:
    .long     saved_subb_valid_case0
    .long     saved_subb_valid_case1
    .long     saved_subb_valid_case2
    .long     saved_subb_valid_case3
near_save_source_table:
    .long     near_save_source_case0
    .long     near_save_source_case1
    .long     near_save_source_case2
near_reload_slot_table:
    .long     near_reload_slot_case0
    .long     near_reload_slot_case1
    .long     near_reload_slot_case2
near_partial_overwrite_table:
    .long     near_partial_overwrite_case0
    .long     near_partial_overwrite_case1
    .long     near_partial_overwrite_case2
near_compare_register_table:
    .long     near_compare_register_case0
    .long     near_compare_register_case1
    .long     near_compare_register_case2
near_guard_condition_table:
    .long     near_guard_condition_case0
    .long     near_guard_condition_case1
    .long     near_guard_condition_case2
near_flag_change_table:
    .long     near_flag_change_case0
    .long     near_flag_change_case1
    .long     near_flag_change_case2
near_alternate_ingress_table:
    .long     near_alternate_ingress_case0
    .long     near_alternate_ingress_case1
    .long     near_alternate_ingress_case2
near_interior_ingress_table:
    .long     near_interior_ingress_case0
    .long     near_interior_ingress_case1
    .long     near_interior_ingress_case2
near_global_clrc_table:
    .long     near_global_clrc_case0
    .long     near_global_clrc_case1
    .long     near_global_clrc_case2
near_wrong_source_table:
    .long     near_wrong_source_case0
    .long     near_wrong_source_case1
    .long     near_wrong_source_case2
near_wrong_scale_table:
    .long     near_wrong_scale_case0
    .long     near_wrong_scale_case1
    .long     near_wrong_scale_case2
near_table_base_table:
    .long     near_table_base_case0
    .long     near_table_base_case1
    .long     near_table_base_case2
near_high_target_table:
    .long     0x00400000
    .long     near_high_target_case1
    .long     near_high_target_case2
near_nonexec_target_table:
    .long     nonexec_target
    .long     near_nonexec_target_case1
    .long     near_nonexec_target_case2
near_called_target_table:
    .long     called_table_target
    .long     near_called_target_case1
    .long     near_called_target_case2
near_stack_setc_table:
    .long     near_stack_setc_case0
    .long     near_stack_setc_case1
    .long     near_stack_setc_case2
near_subb_guard_imm_table:
    .long     near_subb_guard_imm_case0
    .long     near_subb_guard_imm_case1
    .long     near_subb_guard_imm_case2
near_subb_tail_imm_table:
    .long     near_subb_tail_imm_case0
    .long     near_subb_tail_imm_case1
    .long     near_subb_tail_imm_case2
near_subb_bound_table:
    .long     near_subb_bound_case0
    .long     near_subb_bound_case1
    .long     near_subb_bound_case2
near_subb_reload_table:
    .long     near_subb_reload_case0
    .long     near_subb_reload_case1
    .long     near_subb_reload_case2
near_subb_unsafe_range_table:
    .long     near_subb_unsafe_range_case0
    .long     near_subb_unsafe_range_case1
    .long     near_subb_unsafe_range_case2

    .sect ".short_switch"
near_short_table_table:
    .long     near_short_table_case0
    .long     near_short_table_case1
    .long     near_short_table_case2

    .sect ".data"
global_selector:
    .word     0
global_saved_selector:
    .word     0
global_saved_selector_alt:
    .word     0
state_selector:
    .long     1
nonexec_target:
    .long     0
unsafe_bound:
    .long     0xffffffff
near_writable_table_table:
    .long     near_writable_table_case0
    .long     near_writable_table_case1
    .long     near_writable_table_case2
