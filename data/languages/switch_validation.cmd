MEMORY
{
    PROG : origin = 0x13000, length = 0x1000
    DATA : origin = 0x02000, length = 0x0100
}
SECTIONS
{
    .text   : > PROG
    .switch : > PROG
    .extra  : > PROG
    .extra_switch : > PROG
    .data   : > DATA
}
