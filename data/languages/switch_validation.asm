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
    LCR       #validation_tail
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

    ; Keep this extension after the original .text/.switch corpus so the
    ; established negative-fixture addresses remain stable.
    .sect ".extra"
    .asmfunc
validation_tail:
    LCR       #saved_selector_valid
    LCR       #saved_p_valid
    SB        saved_hi_valid, UNC
    .endasmfunc

    ; Mirrors the real-firmware schedule at 0x8e1ec: subtract the low case,
    ; branch to default on HI, and fall through on the bounded unsigned range.
    ; P preserves the original 32-bit selector using the unshifted MOVL forms.
    .asmfunc
saved_p_valid:
    MOVB      XAR7, #0x1b
    MOVL      P, ACC
    SUB       ACC, #1 << #9          ; low case 0x200
    CMPL      ACC, XAR7
    SB        saved_p_default, HI
    MOVL      ACC, P
    MOVL      XAR7, #saved_p_table
    LSL       ACC, #1
    SUB       ACC, #1 << #10         ; two-word entries, low case 0x200
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
saved_p_default:
    LRETR
saved_p_case00:
    MOVB      AL, #0x00
    LRETR
saved_p_case01:
    MOVB      AL, #0x01
    LRETR
saved_p_case02:
    MOVB      AL, #0x02
    LRETR
saved_p_case03:
    MOVB      AL, #0x03
    LRETR
saved_p_case04:
    MOVB      AL, #0x04
    LRETR
saved_p_case05:
    MOVB      AL, #0x05
    LRETR
saved_p_case06:
    MOVB      AL, #0x06
    LRETR
saved_p_case07:
    MOVB      AL, #0x07
    LRETR
saved_p_case08:
    MOVB      AL, #0x08
    LRETR
saved_p_case09:
    MOVB      AL, #0x09
    LRETR
saved_p_case10:
    MOVB      AL, #0x0a
    LRETR
saved_p_case11:
    MOVB      AL, #0x0b
    LRETR
saved_p_case12:
    MOVB      AL, #0x0c
    LRETR
saved_p_case13:
    MOVB      AL, #0x0d
    LRETR
saved_p_case14:
    MOVB      AL, #0x0e
    LRETR
saved_p_case15:
    MOVB      AL, #0x0f
    LRETR
saved_p_case16:
    MOVB      AL, #0x10
    LRETR
saved_p_case17:
    MOVB      AL, #0x11
    LRETR
saved_p_case22:
    MOVB      AL, #0x16
    LRETR
saved_p_case23:
    MOVB      AL, #0x17
    LRETR
saved_p_case24:
    MOVB      AL, #0x18
    LRETR
saved_p_case25:
    MOVB      AL, #0x19
    LRETR
saved_p_case26:
    MOVB      AL, #0x1a
    LRETR
saved_p_case27:
    MOVB      AL, #0x1b
    LRETR
    .endasmfunc

    ; Standalone 32-bit switches from cl2000 22.6.1 use this XAR7-saved
    ; sibling of the P-saved firmware form, with the same inverted HI guard.
    .asmfunc
saved_hi_valid:
    MOVB      XAR6, #0x02
    MOVL      XAR7, ACC
    SUB       ACC, #0x110 << #1       ; low case 0x220
    CMPL      ACC, XAR6
    SB        saved_hi_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #saved_hi_table
    LSL       ACC, #1
    SUB       ACC, #0x110 << #2       ; two-word entries, low case 0x220
    ADDL      XAR7, ACC
    MOVL      XAR7, *XAR7
    LB        *XAR7
saved_hi_default:
    LRETR
saved_hi_case0:
    MOVB      AL, #0x21
    LRETR
saved_hi_case1:
    MOVB      AL, #0x22
    LRETR
saved_hi_case2:
    MOVB      AL, #0x23
    LRETR
    .endasmfunc

    .sect ".extra_switch"
saved_p_table:
    .long saved_p_case00
    .long saved_p_case01
    .long saved_p_case02
    .long saved_p_case03
    .long saved_p_case04
    .long saved_p_case05
    .long saved_p_case06
    .long saved_p_case07
    .long saved_p_case08
    .long saved_p_case09
    .long saved_p_case10
    .long saved_p_case11
    .long saved_p_case12
    .long saved_p_case13
    .long saved_p_case14
    .long saved_p_case15
    .long saved_p_case16
    .long saved_p_case17
    .long saved_p_default
    .long saved_p_default
    .long saved_p_default
    .long saved_p_default
    .long saved_p_case22
    .long saved_p_case23
    .long saved_p_case24
    .long saved_p_case25
    .long saved_p_case26
    .long saved_p_case27
saved_hi_table:
    .long saved_hi_case0
    .long saved_hi_case1
    .long saved_hi_case2

    .sect ".data"
writable_table_data:
    .long writable_table_case0
    .long writable_table_case1
    .long writable_table_case2
