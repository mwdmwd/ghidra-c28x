typedef signed int rpc_s16;
typedef unsigned int rpc_u16;
typedef signed long rpc_s32;
typedef unsigned long rpc_u32;
typedef signed long long rpc_s64;
typedef unsigned long long rpc_u64;

typedef long (*rpc_binary_fn)(long, long);

volatile long rpc_branch_sink;
volatile rpc_s16 rpc_scalar_sink_s16;
volatile rpc_u16 rpc_scalar_sink_u16;
volatile rpc_s32 rpc_scalar_sink_s32;
volatile rpc_u32 rpc_scalar_sink_u32;
volatile rpc_s64 rpc_scalar_sink_s64;
volatile rpc_u64 rpc_scalar_sink_u64;

#pragma FUNC_CANNOT_INLINE(rpc_void_a)
void rpc_void_a(long value) { rpc_branch_sink += value; }
#pragma FUNC_CANNOT_INLINE(rpc_void_b)
void rpc_void_b(long value) { rpc_branch_sink ^= value; }
#pragma FUNC_CANNOT_INLINE(rpc_void_c)
void rpc_void_c(long value) { rpc_branch_sink -= value; }
#pragma FUNC_CANNOT_INLINE(rpc_leaf)
long rpc_leaf(long value) { return value + 3L; }
#pragma FUNC_CANNOT_INLINE(rpc_multi_return)
long rpc_multi_return(long value) {
    if (value < 0L) return -value;
    if (value == 0L) return 17L;
    return value + 5L;
}
#pragma FUNC_CANNOT_INLINE(rpc_nested_inner)
long rpc_nested_inner(long value) { return rpc_leaf(value) + 1L; }
#pragma FUNC_CANNOT_INLINE(rpc_nested_outer)
long rpc_nested_outer(long value) {
    long first = rpc_nested_inner(value);
    long second = rpc_leaf(value + 2L);
    return first + second;
}
#pragma FUNC_CANNOT_INLINE(rpc_indirect_target)
long rpc_indirect_target(long left, long right) { return left - right; }
#pragma FUNC_CANNOT_INLINE(rpc_indirect_call)
long rpc_indirect_call(rpc_binary_fn fn, long left, long right) {
    return fn(left, right) + 9L;
}
#pragma FUNC_CANNOT_INLINE(rpc_stack_args)
long rpc_stack_args(long a0,long a1,long a2,long a3,long a4,
                    long a5,long a6,long a7,long a8,long a9) {
    return a0+a1+a2+a3+a4+a5+a6+a7+a8+a9;
}
#pragma FUNC_CANNOT_INLINE(rpc_stack_caller)
long rpc_stack_caller(long seed) {
    return rpc_stack_args(seed,seed+1L,seed+2L,seed+3L,seed+4L,
                          seed+5L,seed+6L,seed+7L,seed+8L,seed+9L);
}

/*
 * The two arms deliberately complete different numbers of ordinary LCR calls
 * before joining.  The volatile local forces a real stack slot and the final
 * expression reads late stack arguments after the join.  This is the compact
 * form of the firmware failure where a duplicate completed-call stack shift
 * made SP path-dependent.
 */
#pragma FUNC_CANNOT_INLINE(rpc_branch_rejoin)
long rpc_branch_rejoin(long choose,long a1,long a2,long a3,long a4,
                       long a5,long a6,long a7,long a8,long a9) {
    volatile long local = a1 + a6;
    if (choose != 0L) {
        rpc_void_a(local + a7);
    }
    else {
        rpc_void_a(local + a7);
        rpc_void_b(a8);
        rpc_void_c(a9);
    }
    local += a8;
    return local + a9;
}
#pragma FUNC_CANNOT_INLINE(rpc_preserve_older)
long rpc_preserve_older(long value) {
    long before = rpc_leaf(value);
    long nested = rpc_nested_inner(before);
    return before + nested + rpc_multi_return(value - 4L);
}

/*
 * Scalar-register subjects.  The one-argument callees force a direct 16-bit
 * save from AL; no operation reads AH as an extension of the incoming value.
 */
#pragma FUNC_CANNOT_INLINE(rpc_one_s16)
rpc_s16 rpc_one_s16(rpc_s16 value) {
    volatile rpc_s16 saved = value;
    return (rpc_s16)((rpc_s32)saved + 1L);
}

#pragma FUNC_CANNOT_INLINE(rpc_one_u16)
rpc_u16 rpc_one_u16(rpc_u16 value) {
    volatile rpc_u16 saved = value;
    return (rpc_u16)((rpc_u32)saved + 1UL);
}

#pragma FUNC_CANNOT_INLINE(rpc_four_s16)
rpc_s16 rpc_four_s16(rpc_s16 a, rpc_s16 b, rpc_s16 c, rpc_s16 d) {
    rpc_s32 total = (rpc_s32)a + 3L * (rpc_s32)b +
                    5L * (rpc_s32)c + 7L * (rpc_s32)d;
    return (rpc_s16)total;
}

#pragma FUNC_CANNOT_INLINE(rpc_one_s32)
rpc_s32 rpc_one_s32(rpc_s32 value) {
    rpc_scalar_sink_s32 = value;
    return value ^ 0x12345678L;
}

#pragma FUNC_CANNOT_INLINE(rpc_id_s64)
rpc_s64 rpc_id_s64(rpc_s64 value) { return value; }

#pragma FUNC_CANNOT_INLINE(rpc_arith_s64)
rpc_s64 rpc_arith_s64(rpc_s64 value) {
    return (rpc_s64)((rpc_u64)value + 0x1122334455667788ULL);
}

#pragma FUNC_CANNOT_INLINE(rpc_arith_u64)
rpc_u64 rpc_arith_u64(rpc_u64 value) {
    return value + 0x8877665544332211ULL;
}

#pragma FUNC_CANNOT_INLINE(rpc_two_s64)
rpc_s64 rpc_two_s64(rpc_s64 first, rpc_s64 second) {
    return first ^ second;
}

#pragma FUNC_CANNOT_INLINE(rpc_two_u64)
rpc_u64 rpc_two_u64(rpc_u64 first, rpc_u64 second) {
    return first + second;
}

/* Exact SPRU514Z mixed-order example: stack, ACC:P, XAR5, XAR4. */
#pragma FUNC_CANNOT_INLINE(rpc_mixed_s64)
rpc_s64 rpc_mixed_s64(rpc_s32 a, rpc_s64 b, rpc_s16 c, rpc_s16 *d) {
    rpc_u64 total = (rpc_u64)b + (rpc_u64)(rpc_s64)a +
                    (rpc_u64)(rpc_s64)c + (rpc_u64)(rpc_s64)*d;
    return (rpc_s64)total;
}

#pragma FUNC_CANNOT_INLINE(rpc_div_s64)
rpc_s64 rpc_div_s64(rpc_s64 dividend, rpc_s64 divisor) {
    const rpc_s64 minimum = -9223372036854775807LL - 1LL;
    if (divisor == 0LL) return 0LL;
    if (dividend == minimum && divisor == -1LL) return minimum;
    return dividend / divisor;
}

#pragma FUNC_CANNOT_INLINE(rpc_div_u64)
rpc_u64 rpc_div_u64(rpc_u64 dividend, rpc_u64 divisor) {
    return divisor == 0ULL ? 0ULL : dividend / divisor;
}

#pragma FUNC_CANNOT_INLINE(rpc_calls16)
rpc_s16 rpc_calls16(rpc_s16 choose) {
    volatile rpc_s16 branch_choice = choose;
    rpc_s16 total = rpc_one_s16(6);
    total = (rpc_s16)(total + rpc_one_s16(1));
    total = (rpc_s16)(total + rpc_one_s16(10));
    total = (rpc_s16)(total + rpc_one_s16(0));
    total = (rpc_s16)(total + rpc_one_s16(-7));
    total = (rpc_s16)(total + (rpc_s16)rpc_one_u16(0xfff0U));

    /* Constant AL loads leave unrelated AH state stale at the call sites. */
    if (branch_choice != 0) {
        rpc_scalar_sink_u16 = 0x55aaU;
        total = (rpc_s16)(total + rpc_four_s16(1, 2, 3, 4));
    }
    else {
        rpc_scalar_sink_u16 = 0xaa55U;
        total = (rpc_s16)(total + rpc_one_s16(rpc_four_s16(5, 6, 7, 8)));
    }
    rpc_scalar_sink_s16 = total;
    return (rpc_s16)(total + (rpc_s16)rpc_scalar_sink_u16);
}

#pragma FUNC_CANNOT_INLINE(rpc_calls64)
rpc_s64 rpc_calls64(rpc_s64 x, rpc_s64 y, rpc_s16 c, rpc_s16 *pointer) {
    rpc_s64 identity = rpc_id_s64(x);
    rpc_s64 signed_value = rpc_arith_s64(identity);
    rpc_u64 unsigned_value = rpc_arith_u64((rpc_u64)y);
    rpc_s64 pair_signed = rpc_two_s64(signed_value, y);
    rpc_u64 pair_unsigned = rpc_two_u64(unsigned_value, (rpc_u64)x);
    rpc_s64 mixed = rpc_mixed_s64(0x12345678L, pair_signed, c, pointer);
    rpc_s64 signed_quotient = rpc_div_s64(mixed, y | 1LL);
    rpc_u64 unsigned_quotient = rpc_div_u64(pair_unsigned, ((rpc_u64)y) | 1ULL);
    rpc_scalar_sink_s64 = signed_quotient;
    rpc_scalar_sink_u64 = unsigned_quotient;
    rpc_scalar_sink_u32 = (rpc_u32)rpc_one_s32((rpc_s32)c);
    return (rpc_s64)((rpc_u64)signed_quotient + unsigned_quotient +
                     (rpc_u64)rpc_scalar_sink_u32);
}

#pragma FUNC_CANNOT_INLINE(rpc_scalar_fixture_entry)
rpc_s64 rpc_scalar_fixture_entry(rpc_s16 choose) {
    rpc_s16 pointed = -11;
    rpc_s16 narrow = rpc_calls16(choose);
    return rpc_calls64(0x1122334455667788LL,
                       -0x0102030405060708LL,
                       narrow, &pointed);
}

#pragma FUNC_CANNOT_INLINE(rpc_fixture_entry)
long rpc_fixture_entry(long value) {
    long direct = rpc_nested_outer(value);
    long indirect = rpc_indirect_call(rpc_indirect_target, value+20L, value);
    long stack = rpc_stack_caller(value);
    long branch = rpc_branch_rejoin(value & 1L,value+1L,value+2L,value+3L,
                                    value+4L,value+5L,value+6L,value+7L,
                                    value+8L,value+9L);
    rpc_s64 scalar = rpc_scalar_fixture_entry((rpc_s16)value);
    rpc_s32 scalar_fold = (rpc_s32)((rpc_u64)scalar ^ ((rpc_u64)scalar >> 32));
    return direct + indirect + stack + branch + rpc_preserve_older(value) + scalar_fold;
}
