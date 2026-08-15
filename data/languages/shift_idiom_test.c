#pragma FUNC_CANNOT_INLINE(shift_t_div2)
#pragma FUNC_CANNOT_INLINE(shift_t_div4)
#pragma FUNC_CANNOT_INLINE(shift_sign_extend_value)
#pragma FUNC_CANNOT_INLINE(shift_sign_extend_multiply)
#pragma FUNC_CANNOT_INLINE(shift_add_sign_extended_product)

long shift_t_div2(long value)
{
    return value / 2;
}

long shift_t_div4(long value)
{
    return value / 4;
}

long long shift_sign_extend_value(long value)
{
    return (long long)value;
}

long long shift_sign_extend_multiply(long left, long right)
{
    long product = left * right;
    return (long long)product;
}

long long shift_add_sign_extended_product(
    long long total, long left, long right)
{
    long product = left * right;
    return total + (long long)product;
}

volatile long shift_t_sink;

long long shift_t_compiler_entry(long value)
{
    shift_t_sink = shift_t_div2(value);
    shift_t_sink += shift_t_div4(value);
    long long result = shift_sign_extend_value(value);
    result += shift_sign_extend_multiply(value, value + 1);
    return shift_add_sign_extended_product(result, value, value - 1);
}
