#pragma FUNC_CANNOT_INLINE(shift_t_div2)
#pragma FUNC_CANNOT_INLINE(shift_t_div4)

long shift_t_div2(long value)
{
    return value / 2;
}

long shift_t_div4(long value)
{
    return value / 4;
}

long shift_t_compiler_entry(long value)
{
    return shift_t_div2(value) + shift_t_div4(value);
}
