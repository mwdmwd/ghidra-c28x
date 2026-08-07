typedef unsigned int zoo_u16;
typedef unsigned long zoo_u32;

typedef struct {
    zoo_u16 lo;
    zoo_u16 hi;
    zoo_u32 total;
} zoo_pair;

#pragma FUNC_CANNOT_INLINE(zoo_abi_helper)
zoo_u32 zoo_abi_helper(zoo_u32 base, zoo_u16 delta, zoo_pair *pair)
{
    pair->lo = delta;
    pair->hi = (zoo_u16)(delta ^ 0x55aau);
    pair->total = base + (zoo_u32)pair->lo + (zoo_u32)pair->hi;
    return pair->total ^ 0x12345678ul;
}

/* A direct call, mixed-width arguments, a stack-resident structure, and a
 * returned 32-bit value. */
zoo_u32 zoo_abi_calls(zoo_u16 value, zoo_u32 base, volatile zoo_u32 *out)
{
    zoo_pair pair;
    zoo_u32 result = zoo_abi_helper(base, (zoo_u16)(value + 3u), &pair);
    *out = result + pair.total;
    return pair.total;
}
