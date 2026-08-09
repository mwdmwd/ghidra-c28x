MEMORY
{
    PROG : origin = 0x15000, length = 0x2000
    DATA : origin = 0x02200, length = 0x0100
}
SECTIONS
{
    .text   : > PROG
    .switch : > PROG
    .data   : > DATA
}
