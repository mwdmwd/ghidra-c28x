MEMORY { PROG : origin = 0x17000, length = 0x1000
         DATA : origin = 0x03400, length = 0x0200 }
SECTIONS { .text : > PROG .data : > DATA .stack : > DATA }
