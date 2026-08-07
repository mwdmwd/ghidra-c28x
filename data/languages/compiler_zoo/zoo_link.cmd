MEMORY
{
    PROG : origin = 0x18000, length = 0x2000
}
SECTIONS
{
    .text   : > PROG
    .switch : > PROG
}
