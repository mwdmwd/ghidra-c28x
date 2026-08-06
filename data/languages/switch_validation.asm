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
    LCR       #function_pointer_target2
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

    .sect ".data"
writable_table_data:
    .long writable_table_case0
    .long writable_table_case1
    .long writable_table_case2
