typedef unsigned long u32;

volatile u32 division_idiom_sink;

#pragma FUNC_CANNOT_INLINE(div32_const10)
u32 div32_const10(u32 dividend)
{
    return dividend / 10UL;
}

#pragma FUNC_CANNOT_INLINE(mod32_const10)
u32 mod32_const10(u32 dividend)
{
    return dividend % 10UL;
}

/* ORing one bit gives the analyzer a local, data-independent nonzero proof. */
#pragma FUNC_CANNOT_INLINE(div32_variable_nonzero)
u32 div32_variable_nonzero(u32 dividend, u32 divisor)
{
    divisor |= 1UL;
    return dividend / divisor;
}

#pragma FUNC_CANNOT_INLINE(divmod32_variable_nonzero)
u32 divmod32_variable_nonzero(u32 dividend, u32 divisor, volatile u32 *remainder)
{
    divisor |= 1UL;
    *remainder = dividend % divisor;
    return dividend / divisor;
}

#pragma FUNC_CANNOT_INLINE(division_idiom_entry)
u32 division_idiom_entry(u32 dividend, u32 divisor)
{
    u32 remainder;
    u32 result = div32_const10(dividend) + mod32_const10(dividend);
    result += div32_variable_nonzero(dividend, divisor);
    result += divmod32_variable_nonzero(dividend, divisor, &remainder);
    division_idiom_sink = remainder;
    return result;
}
