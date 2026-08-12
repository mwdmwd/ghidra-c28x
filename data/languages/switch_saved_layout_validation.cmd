MEMORY
{
    PROG  : origin = 0x18000, length = 0x1000
    DATA  : origin = 0x02400, length = 0x0100
}
SECTIONS
{
    .text            : > PROG
    .switch          : > PROG
    .data            : > DATA
}
