typedef unsigned int zoo_u16;
typedef unsigned long zoo_u32;

/*
 * Defined-behavior probes for the RPT || SUBCU(L) schedules seen repeatedly
 * in firmware.  Ghidra currently exposes the instructions' exact 33-bit
 * subtract temporary as uint5 in decompiled C, obscuring these ordinary
 * quotient/remainder operations.
 */
zoo_u32 zoo_integer_division(zoo_u32 numerator32,
                             zoo_u32 denominator32,
                             zoo_u16 numerator16,
                             zoo_u16 denominator16,
                             volatile zoo_u32 *remainder32,
                             volatile zoo_u16 *quotient16)
{
    zoo_u32 quotient32;

    if (denominator32 == 0ul) {
        *remainder32 = numerator32;
        quotient32 = 0ul;
    }
    else {
        quotient32 = numerator32 / denominator32;
        *remainder32 = numerator32 % denominator32;
    }

    if (denominator16 == 0u) {
        *quotient16 = 0u;
    }
    else {
        *quotient16 = numerator16 / denominator16;
    }

    return quotient32 + (zoo_u32)*quotient16;
}
