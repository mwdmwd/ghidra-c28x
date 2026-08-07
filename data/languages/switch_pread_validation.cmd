MEMORY
{
    PROG : origin = 0x14000, length = 0x1000
}
SECTIONS
{
    .text   : > PROG
    .switch : > PROG
}
