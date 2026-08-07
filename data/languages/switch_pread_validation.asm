    .sect ".text"
    .global switch_pread_validation_entry
    .asmfunc
switch_pread_validation_entry:
    LCR       #pread_increment_by_two
    LCR       #pread_swapped_halves
    LRETR
    .endasmfunc

    ; Near miss 1: the program-space halfword address advances by two rather
    ; than one between the low and high target reads.
    .asmfunc
pread_increment_by_two:
    MOVB      XAR6, #3
    MOVL      XAR7, ACC
    SUB       ACC, #0x11 << #5       ; selector - 0x220
    CMPL      ACC, XAR6
    SB        pread_increment_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #pread_increment_table
    LSL       ACC, #1
    SUB       ACC, #0x11 << #6       ; two-word entries, low case 0x220
    ADDL      XAR7, ACC
    PREAD     AL, *XAR7
    ADDB      XAR7, #2                ; invalid: must advance exactly one word
    PREAD     AH, *XAR7
    MOVL      XAR7, ACC
    LB        *XAR7
pread_increment_default:
    LRETR
pread_increment_case0:
    MOVB      AL, #0x11
    LRETR
pread_increment_case1:
    MOVB      AL, #0x12
    LRETR
pread_increment_case2:
    MOVB      AL, #0x13
    LRETR
pread_increment_case3:
    MOVB      AL, #0x14
    LRETR
    .endasmfunc

    ; Near miss 2: the table words are read into the opposite accumulator
    ; halves.  The same bytes are touched, but the 32-bit target is not the
    ; validated little-endian PREAD construction.
    .asmfunc
pread_swapped_halves:
    MOVB      XAR6, #3
    MOVL      XAR7, ACC
    SUB       ACC, #0x12 << #5       ; selector - 0x240
    CMPL      ACC, XAR6
    SB        pread_swapped_default, HI
    MOVL      ACC, XAR7
    MOVL      XAR7, #pread_swapped_table
    LSL       ACC, #1
    SUB       ACC, #0x12 << #6       ; two-word entries, low case 0x240
    ADDL      XAR7, ACC
    PREAD     AH, *XAR7               ; invalid: high half is read first
    ADDB      XAR7, #1
    PREAD     AL, *XAR7               ; invalid: low half is read second
    MOVL      XAR7, ACC
    LB        *XAR7
pread_swapped_default:
    LRETR
pread_swapped_case0:
    MOVB      AL, #0x21
    LRETR
pread_swapped_case1:
    MOVB      AL, #0x22
    LRETR
pread_swapped_case2:
    MOVB      AL, #0x23
    LRETR
pread_swapped_case3:
    MOVB      AL, #0x24
    LRETR
    .endasmfunc

    .sect ".switch"
pread_increment_table:
    .long pread_increment_case0
    .long pread_increment_case1
    .long pread_increment_case2
    .long pread_increment_case3
pread_swapped_table:
    .long pread_swapped_case0
    .long pread_swapped_case1
    .long pread_swapped_case2
    .long pread_swapped_case3
