MEMORY
{
    PROG : origin = 0x10000, length = 0x1000
}

SECTIONS
{
    .text : > PROG
    .switch : > PROG
}
