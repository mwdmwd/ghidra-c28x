    .sect ".text"
    .global switch_ar6_validation_entry
    .asmfunc
switch_ar6_validation_entry:
    LCR       #ar6_valid
    LCR       #near_producer
    LCR       #near_copy
    LCR       #near_compare
    LCR       #near_count
    LCR       #near_guard
    LCR       #near_table
    LCR       #near_setc
    LCR       #near_basecopy
    LCR       #near_add_source
    LCR       #near_add_shift
    LCR       #near_copyback
    LCR       #near_load_offset
    LCR       #near_ingress
    LCR       #near_ingress_source
    LRETR
    .endasmfunc

    .asmfunc
ar6_valid:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        ar6_valid_default, HI
    MOVL      XAR7, #ar6_valid_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
ar6_valid_default:
    MOVB      AL, #0xff
    LRETR
ar6_valid_case0:
    MOVB      AL, #16
    LRETR
ar6_valid_case1:
    MOVB      AL, #17
    LRETR
ar6_valid_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_producer:
    MOV       AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_producer_default, HI
    MOVL      XAR7, #near_producer_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_producer_default:
    MOVB      AL, #0xff
    LRETR
near_producer_case0:
    MOVB      AL, #16
    LRETR
near_producer_case1:
    MOVB      AL, #17
    LRETR
near_producer_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_copy:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR5
    CMPB      AL, #2
    SB        near_copy_default, HI
    MOVL      XAR7, #near_copy_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_copy_default:
    MOVB      AL, #0xff
    LRETR
near_copy_case0:
    MOVB      AL, #16
    LRETR
near_copy_case1:
    MOVB      AL, #17
    LRETR
near_copy_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_compare:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AH, #2
    SB        near_compare_default, HI
    MOVL      XAR7, #near_compare_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_compare_default:
    MOVB      AL, #0xff
    LRETR
near_compare_case0:
    MOVB      AL, #16
    LRETR
near_compare_case1:
    MOVB      AL, #17
    LRETR
near_compare_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_count:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #0
    SB        near_count_default, HI
    MOVL      XAR7, #near_count_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_count_default:
    MOVB      AL, #0xff
    LRETR
near_count_case0:
    MOVB      AL, #16
    LRETR
    .endasmfunc

    .asmfunc
near_guard:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_guard_default, GEQ
    MOVL      XAR7, #near_guard_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_guard_default:
    MOVB      AL, #0xff
    LRETR
near_guard_case0:
    MOVB      AL, #16
    LRETR
near_guard_case1:
    MOVB      AL, #17
    LRETR
near_guard_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_table:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_table_default, HI
    MOVL      XAR7, XAR4
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_table_default:
    MOVB      AL, #0xff
    LRETR
near_table_case0:
    MOVB      AL, #16
    LRETR
near_table_case1:
    MOVB      AL, #17
    LRETR
near_table_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_setc:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_setc_default, HI
    MOVL      XAR7, #near_setc_table
    CLRC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_setc_default:
    MOVB      AL, #0xff
    LRETR
near_setc_case0:
    MOVB      AL, #16
    LRETR
near_setc_case1:
    MOVB      AL, #17
    LRETR
near_setc_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_basecopy:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_basecopy_default, HI
    MOVL      XAR7, #near_basecopy_table
    SETC      SXM
    MOVL      ACC, XAR6
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_basecopy_default:
    MOVB      AL, #0xff
    LRETR
near_basecopy_case0:
    MOVB      AL, #16
    LRETR
near_basecopy_case1:
    MOVB      AL, #17
    LRETR
near_basecopy_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_add_source:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_add_source_default, HI
    MOVL      XAR7, #near_add_source_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR5 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_add_source_default:
    MOVB      AL, #0xff
    LRETR
near_add_source_case0:
    MOVB      AL, #16
    LRETR
near_add_source_case1:
    MOVB      AL, #17
    LRETR
near_add_source_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_add_shift:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_add_shift_default, HI
    MOVL      XAR7, #near_add_shift_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #2
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_add_shift_default:
    MOVB      AL, #0xff
    LRETR
near_add_shift_case0:
    MOVB      AL, #16
    LRETR
near_add_shift_case1:
    MOVB      AL, #17
    LRETR
near_add_shift_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_copyback:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_copyback_default, HI
    MOVL      XAR7, #near_copyback_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR6, ACC
    MOVL      XAR7, XAR6
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_copyback_default:
    MOVB      AL, #0xff
    LRETR
near_copyback_case0:
    MOVB      AL, #16
    LRETR
near_copyback_case1:
    MOVB      AL, #17
    LRETR
near_copyback_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_load_offset:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_load_offset_default, HI
    MOVL      XAR7, #near_load_offset_table
    SETC      SXM
    MOVL      ACC, XAR7
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[2]
    LB        *XAR7
near_load_offset_default:
    MOVB      AL, #0xff
    LRETR
near_load_offset_case0:
    MOVB      AL, #16
    LRETR
near_load_offset_case1:
    MOVB      AL, #17
    LRETR
near_load_offset_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_ingress:
    MOVZ      AR6, @ar6_selector
    MOV       AL, AR6
    CMPB      AL, #2
    SB        near_ingress_default, HI
    MOVL      XAR7, #near_ingress_table
    SETC      SXM
    MOVL      ACC, XAR7
near_ingress_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
    LB        *XAR7
near_ingress_default:
    MOVB      AL, #0xff
    LRETR
near_ingress_case0:
    MOVB      AL, #16
    LRETR
near_ingress_case1:
    MOVB      AL, #17
    LRETR
near_ingress_case2:
    MOVB      AL, #18
    LRETR
    .endasmfunc

    .asmfunc
near_ingress_source:
    SB        near_ingress_add, UNC
    .endasmfunc

    .sect ".switch"
ar6_valid_table:
    .long     ar6_valid_case0
    .long     ar6_valid_case1
    .long     ar6_valid_case2
near_producer_table:
    .long     near_producer_case0
    .long     near_producer_case1
    .long     near_producer_case2
near_copy_table:
    .long     near_copy_case0
    .long     near_copy_case1
    .long     near_copy_case2
near_compare_table:
    .long     near_compare_case0
    .long     near_compare_case1
    .long     near_compare_case2
near_count_table:
    .long     near_count_case0
near_guard_table:
    .long     near_guard_case0
    .long     near_guard_case1
    .long     near_guard_case2
near_table_table:
    .long     near_table_case0
    .long     near_table_case1
    .long     near_table_case2
near_setc_table:
    .long     near_setc_case0
    .long     near_setc_case1
    .long     near_setc_case2
near_basecopy_table:
    .long     near_basecopy_case0
    .long     near_basecopy_case1
    .long     near_basecopy_case2
near_add_source_table:
    .long     near_add_source_case0
    .long     near_add_source_case1
    .long     near_add_source_case2
near_add_shift_table:
    .long     near_add_shift_case0
    .long     near_add_shift_case1
    .long     near_add_shift_case2
near_copyback_table:
    .long     near_copyback_case0
    .long     near_copyback_case1
    .long     near_copyback_case2
near_load_offset_table:
    .long     near_load_offset_case0
    .long     near_load_offset_case1
    .long     near_load_offset_case2
near_ingress_table:
    .long     near_ingress_case0
    .long     near_ingress_case1
    .long     near_ingress_case2

    .sect ".data"
ar6_selector:
    .word 0
