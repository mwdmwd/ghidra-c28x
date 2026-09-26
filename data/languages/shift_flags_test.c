/* Variable counts stay in range. TI cl2000 uses arithmetic right shifts for
 * signed values, and unsigned left shifts are defined modulo 2^32.
 */
int probe_asr_immediate(int value)
{
    return value >> 5;
}

int probe_asr_variable(int value, unsigned int count)
{
    return value >> (count & 15);
}

unsigned long probe_lsll(unsigned long value, unsigned int count)
{
    return value << (count & 31);
}
