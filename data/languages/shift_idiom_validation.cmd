MEMORY { PROG : origin = 0x22000, length = 0x3000
         DATA : origin = 0x05800, length = 0x0800 }
SECTIONS { .text : > PROG .const : > PROG .cinit : > PROG
           .bss : > DATA .data : > DATA .stack : > DATA .sysmem : > DATA }
