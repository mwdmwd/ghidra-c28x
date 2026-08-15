MEMORY
{
    DATA : origin = 0x02000, length = 0x0800
    PROG : origin = 0x03000, length = 0x1000
}
SECTIONS
{
    .text   : > PROG
    .cpdata : > DATA
    .data   : > DATA
    .bss    : > DATA
    .stack  : > DATA
}
