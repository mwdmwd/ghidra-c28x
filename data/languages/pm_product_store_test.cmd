MEMORY { PROG : origin = 0x1d000, length = 0x3000
         DATA : origin = 0x04000, length = 0x0800 }
SECTIONS { .text : > PROG .const : > PROG .cinit : > PROG
           .bss : > DATA .data : > DATA .stack : > DATA .sysmem : > DATA }
