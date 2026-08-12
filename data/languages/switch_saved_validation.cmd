MEMORY
{
    PROG  : origin = 0x17000, length = 0x7000
    DATA  : origin = 0x02300, length = 0x0200
    SHORT : origin = 0x1f000, length = 0x0006
}
SECTIONS
{
    .text            : > PROG
    .switch          : > PROG
    .data            : > DATA
    .short_switch    : > SHORT
}
