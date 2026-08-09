MEMORY
{
    PROG : origin = 0x16000, length = 0x2000
    DATA : origin = 0x02300, length = 0x0100
}
SECTIONS
{
    .text : > PROG
    .data : > DATA
}
