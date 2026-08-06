    .sect ".text"
    .global switch_validation_entry
    .asmfunc
switch_validation_entry:
    LCR       #compact_valid
    LCR       #malformed_bounds
    LCR       #inconsistent_arithmetic
    LCR       #high_target_bits
    LCR       #writable_table
    LCR       #ordinary_indirect
    LCR       #function_pointer_dispatch
    LCR       #function_pointer_target0
    LCR       #function_pointer_target1
    LCR       #saved_selector_valid
    LRETR
    .endasmfunc

    .asmfunc
compact_valid:
    MOV       AH, AL
    SUB       AL, #0x120
    CMPB      AL, #3
    B         compact_valid_dispatch, LOS
    LRETR
compact_valid_dispatch:
    MOVL      XAR7, #compact_valid_table
    MOV       ACC, AH << #1
    SUB       ACC, #0x240
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
compact_valid_case0:
    MOVB      AL, #0x11
    LRETR
compact_valid_case1:
    MOVB      AL, #0x23
    LRETR
compact_valid_case2:
    MOVB      AL, #0x35
    LRETR
compact_valid_case3:
    MOVB      AL, #0x47
    LRETR
    .endasmfunc

    .asmfunc
malformed_bounds:
    MOV       AH, AL
    SUB       AL, #0x130
    CMPB      AL, #0
    B         malformed_bounds_dispatch, LOS
    LRETR
malformed_bounds_dispatch:
    MOVL      XAR7, #malformed_bounds_table
    MOV       ACC, AH << #1
    SUB       ACC, #0x260
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
malformed_bounds_case0:
    LRETR
malformed_bounds_case1:
    LRETR
malformed_bounds_case2:
    LRETR
    .endasmfunc

    .asmfunc
inconsistent_arithmetic:
    MOV       AH, AL
    SUB       AL, #0x140
    CMPB      AL, #2
    B         inconsistent_arithmetic_dispatch, LOS
    LRETR
inconsistent_arithmetic_dispatch:
    MOVL      XAR7, #inconsistent_arithmetic_table
    MOV       ACC, AH << #1
    SUB       ACC, #0x282 ; expected 2 * 0x140 = 0x280
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
inconsistent_arithmetic_case0:
    LRETR
inconsistent_arithmetic_case1:
    LRETR
inconsistent_arithmetic_case2:
    LRETR
    .endasmfunc

    .asmfunc
high_target_bits:
    MOV       AH, AL
    SUB       AL, #0x150
    CMPB      AL, #2
    B         high_target_bits_dispatch, LOS
    LRETR
high_target_bits_dispatch:
    MOVL      XAR7, #high_target_bits_table
    MOV       ACC, AH << #1
    SUB       ACC, #0x2a0
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
high_target_bits_case0:
    LRETR
high_target_bits_case1:
    LRETR
high_target_bits_case2:
    LRETR
    .endasmfunc

    .asmfunc
writable_table:
    MOV       AH, AL
    SUB       AL, #0x160
    CMPB      AL, #2
    B         writable_table_dispatch, LOS
    LRETR
writable_table_dispatch:
    MOVL      XAR7, #writable_table_data
    MOV       ACC, AH << #1
    SUB       ACC, #0x2c0
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
writable_table_case0:
    LRETR
writable_table_case1:
    LRETR
writable_table_case2:
    LRETR
    .endasmfunc

    .asmfunc
ordinary_indirect:
    MOVL      XAR7, XAR4
    MOVL      XAR7, *XAR7
    LB        *XAR7
    .endasmfunc


    .asmfunc
function_pointer_dispatch:
    MOV       AH, AL
    SUB       AL, #0x170
    CMPB      AL, #2
    B         function_pointer_dispatch_body, LOS
    LRETR
function_pointer_dispatch_body:
    MOVL      XAR7, #function_pointer_table
    MOV       ACC, AH << #1
    SUB       ACC, #0x2e0
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
    .endasmfunc

    .asmfunc
function_pointer_target0:
    MOVB      AL, #0x71
    LRETR
    .endasmfunc

    .asmfunc
function_pointer_target1:
    MOVB      AL, #0x72
    LRETR
    .endasmfunc

    .asmfunc
function_pointer_target2:
    MOVB      AL, #0x73
    LRETR
    .endasmfunc

    ; Mirrors a TI firmware schedule that preserves a 32-bit selector in XAR7
    ; across two unsigned ranges, then scales and adjusts ACC for native tables.
    ; The first dispatch immediately follows an unconditional default branch.
    .asmfunc
saved_selector_valid:
    LCR       #function_pointer_target2
    MOVB      XAR6, #3
    MOVL      XAR7, ACC
    SUB       ACC, #0xc0 << #1       ; low case 0x180
    CMPL      ACC, XAR6
    SB        saved_selector_dispatch0, LOS
    MOVB      XAR6, #2
    MOVL      ACC, XAR7
    SUB       ACC, #0x19 << #4       ; low case 0x190
    CMPL      ACC, XAR6
    SB        saved_selector_dispatch1, LOS
    SB        saved_selector_default, UNC
saved_selector_dispatch0:
    MOVL      ACC, XAR7
    MOVL      XAR7, #saved_selector_table0
    LSL       ACC, #1
    SUB       ACC, #0xc0 << #2       ; two-word entries, low case 0x180
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
saved_selector_dispatch1:
    MOVL      ACC, XAR7
    MOVL      XAR7, #saved_selector_table1
    LSL       ACC, #1
    SUB       ACC, #0x19 << #5       ; two-word entries, low case 0x190
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
saved_selector_default:
    LRETR
saved_selector_case0:
    MOVB      AL, #0x81
    LRETR
saved_selector_case1:
    MOVB      AL, #0x82
    LRETR
saved_selector_case2:
    MOVB      AL, #0x83
    LRETR
saved_selector_case3:
    MOVB      AL, #0x84
    LRETR
saved_selector_case4:
    MOVB      AL, #0x91
    LRETR
saved_selector_case5:
    MOVB      AL, #0x92
    LRETR
saved_selector_case6:
    MOVB      AL, #0x93
    LRETR
    .endasmfunc

    .sect ".switch"
compact_valid_table:
    .long compact_valid_case0
    .long compact_valid_case1
    .long compact_valid_case2
    .long compact_valid_case3
malformed_bounds_table:
    .long malformed_bounds_case0
    .long malformed_bounds_case1
    .long malformed_bounds_case2
inconsistent_arithmetic_table:
    .long inconsistent_arithmetic_case0
    .long inconsistent_arithmetic_case1
    .long inconsistent_arithmetic_case2
function_pointer_table:
    .long function_pointer_target0
    .long function_pointer_target1
    .long function_pointer_target2
high_target_bits_table:
    .long high_target_bits_case0 + 0x400000
    .long high_target_bits_case1 + 0x400000
    .long high_target_bits_case2 + 0x400000
saved_selector_table0:
    .long saved_selector_case0
    .long saved_selector_case1
    .long saved_selector_case2
    .long saved_selector_case3
saved_selector_table1:
    .long saved_selector_case4
    .long saved_selector_case5
    .long saved_selector_case6

    .sect ".data"
writable_table_data:
    .long writable_table_case0
    .long writable_table_case1
    .long writable_table_case2
