MEMORY { PROG : origin = 0x18000, length = 0x4000
         DATA : origin = 0x03000, length = 0x0800 }
SECTIONS { .text : > PROG .const : > PROG .cinit : > PROG
           .bss : > DATA .data : > DATA .stack : > DATA .sysmem : > DATA }
