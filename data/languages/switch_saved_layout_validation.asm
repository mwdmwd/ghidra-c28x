    .sect ".text"
    .global switch_saved_layout_validation_entry
    .asmfunc
switch_saved_layout_validation_entry:
    LCR       #saved_layout_global_valid
    LCR       #saved_layout_stack_valid
    LRETR
    .endasmfunc

    .asmfunc
saved_layout_global_valid:
    MOV       AL, @layout_global_selector
    MOVW      DP, #layout_global_saved_selector
    MOV       @layout_global_saved_selector, AL
saved_layout_global_valid_ingress:
    .word     0xffef
    .word     saved_layout_global_valid_dispatch-saved_layout_global_valid_ingress

; These targets deliberately occupy the skipped interval between the one
; ingress branch and the dispatcher, matching the firmware's non-adjacent
; saved-selector schedule.
saved_layout_global_valid_case0:
    MOVB      AL, #0x10
    LRETR
saved_layout_global_valid_case1:
    MOVB      AL, #0x11
    LRETR
saved_layout_global_valid_case2:
    MOVB      AL, #0x12
    LRETR
saved_layout_global_valid_case3:
    MOVB      AL, #0x13
    LRETR

saved_layout_global_valid_dispatch:
    CMPB      AL, #3
    MOVZ      AR6, @layout_global_saved_selector
    SB        saved_layout_global_valid_default, HI
    MOVL      XAR7, #saved_layout_global_valid_table
    SETC      SXM
    MOVL      ACC, XAR7
saved_layout_global_valid_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
saved_layout_global_valid_branch:
    LB        *XAR7
saved_layout_global_valid_default:
    MOVB      AL, #0xff
    LRETR
    .endasmfunc

    .asmfunc
saved_layout_stack_valid:
    ADDB      SP, #2
    MOV       *-SP[1], AL
saved_layout_stack_valid_ingress:
    .word     0xffef
    .word     saved_layout_stack_valid_dispatch-saved_layout_stack_valid_ingress

saved_layout_stack_valid_case0:
    MOVB      AL, #0x20
    SUBB      SP, #2
    LRETR
saved_layout_stack_valid_case1:
    MOVB      AL, #0x21
    SUBB      SP, #2
    LRETR
saved_layout_stack_valid_case2:
    MOVB      AL, #0x22
    SUBB      SP, #2
    LRETR
saved_layout_stack_valid_case3:
    MOVB      AL, #0x23
    SUBB      SP, #2
    LRETR

saved_layout_stack_valid_dispatch:
    CMPB      AL, #3
    MOVZ      AR6, *-SP[1]
    SB        saved_layout_stack_valid_default, HI
    MOVL      XAR7, #saved_layout_stack_valid_table
    CLRC      SXM
    MOVL      ACC, XAR7
saved_layout_stack_valid_add:
    ADD       ACC, AR6 << #1
    MOVL      XAR7, ACC
    MOVL      XAR7, *+XAR7[0]
saved_layout_stack_valid_branch:
    LB        *XAR7
saved_layout_stack_valid_default:
    MOVB      AL, #0xff
    SUBB      SP, #2
    LRETR
    .endasmfunc

    .sect ".switch"
saved_layout_global_valid_table:
    .long     saved_layout_global_valid_case0
    .long     saved_layout_global_valid_case1
    .long     saved_layout_global_valid_case2
    .long     saved_layout_global_valid_case3
saved_layout_stack_valid_table:
    .long     saved_layout_stack_valid_case0
    .long     saved_layout_stack_valid_case1
    .long     saved_layout_stack_valid_case2
    .long     saved_layout_stack_valid_case3

    .sect ".data"
layout_global_selector:
    .word     0
layout_global_saved_selector:
    .word     0
