MEMORY
{
    PROG : origin = 0x1D000, length = 0x5000
    DATA : origin = 0x04000, length = 0x2000
}
SECTIONS
{
    .text   : > PROG
    .const  : > PROG
    .cinit  : > PROG
    .bss    : > DATA
    .data   : > DATA
    .stack  : > DATA
    .sysmem : > DATA
}
