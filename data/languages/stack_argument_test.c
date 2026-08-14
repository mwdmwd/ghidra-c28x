typedef signed int stack_s16;
typedef unsigned int stack_u16;
typedef signed long stack_s32;
typedef unsigned long stack_u32;
typedef signed long long stack_s64;
typedef unsigned long long stack_u64;
typedef stack_s16 *stack_p16;

volatile stack_s32 stack_input;
volatile stack_s16 stack_flag;
volatile stack_s16 stack_pointer_a;
volatile stack_s16 stack_pointer_b;
volatile stack_s32 stack_sink32;
volatile stack_s64 stack_sink64;

#pragma FUNC_CANNOT_INLINE(stack_lcr_helper)
stack_s32 stack_lcr_helper(stack_s32 left, stack_s32 right) {
    return left + right;
}

/*
 * The second 32-bit argument is the first stack-passed argument.  The local
 * and the outgoing argument block share one positive-growing TI frame.
 */
#pragma FUNC_CANNOT_INLINE(stack_noarg_lcr)
stack_s32 stack_noarg_lcr(void) {
    volatile stack_s32 local = 7L;
    return stack_lcr_helper(stack_input, 0x11223344L) + local;
}

#pragma FAST_FUNC_CALL(stack_ffc_helper)
extern stack_s32 stack_ffc_helper(stack_s32 left, stack_s32 right);

#pragma FAST_FUNC_CALL(__c28xabi_divl)
extern stack_s32 __c28xabi_divl(stack_s32 dividend, stack_s32 divisor);

/* FFC does not push RPC, so *-SP[2] is its first 32-bit stack argument. */
#pragma FUNC_CANNOT_INLINE(stack_noarg_ffc)
stack_s32 stack_noarg_ffc(void) {
    volatile stack_s32 local = 3L;
    return stack_ffc_helper(stack_input, 10L) + local;
}

/* Two completed calls deliberately reuse the same outgoing slot. */
#pragma FUNC_CANNOT_INLINE(stack_reuse_ffc)
stack_s32 stack_reuse_ffc(void) {
    stack_s32 first = stack_ffc_helper(stack_input, 10L);
    stack_s32 second = stack_ffc_helper(stack_input, 37L);
    return first + second;
}

/* Compiler-emitted form matching the firmware's fast signed-division helper. */
#pragma FUNC_CANNOT_INLINE(stack_noarg_div)
stack_s32 stack_noarg_div(void) {
    return __c28xabi_divl(stack_input, 10L);
}

/*
 * The incoming second argument lives below the caller's RPC save.  It must
 * remain a real input while this function allocates an outgoing stack slot.
 */
#pragma FUNC_CANNOT_INLINE(stack_incoming_live)
stack_s32 stack_incoming_live(stack_s32 first, volatile stack_s32 second) {
    stack_s32 nested = stack_lcr_helper(first, 5L);
    return second + nested;
}

/*
 * ACC:P consumes the overlapping ACC/AL/AH integer class, the two pointers
 * consume XAR4/XAR5, and the remaining 16-, 32-, and 64-bit values enter the
 * aligned stack area.
 */
#pragma FUNC_CANNOT_INLINE(stack_mixed_helper)
stack_s64 stack_mixed_helper(stack_s64 wide, stack_p16 first_pointer,
                             stack_p16 second_pointer, stack_s16 narrow_a,
                             stack_s16 narrow_b, stack_s32 scalar,
                             stack_s64 stacked_wide) {
    stack_sink32 = scalar + (stack_s32)narrow_a + (stack_s32)narrow_b +
                   (stack_s32)*first_pointer + (stack_s32)*second_pointer;
    (void)stacked_wide;
    return wide;
}

#pragma FUNC_CANNOT_INLINE(stack_mixed_caller)
stack_s64 stack_mixed_caller(void) {
    stack_pointer_a = 0x1111;
    stack_pointer_b = 0x2222;
    return stack_mixed_helper(3LL, (stack_p16)&stack_pointer_a,
                              (stack_p16)&stack_pointer_b,
                              0x3333, 0x4444, 6L, 7LL);
}

#pragma FUNC_CANNOT_INLINE(stack_escape_helper)
void stack_escape_helper(stack_s32 *pointer, stack_s32 addend) {
    *pointer += addend;
}

#pragma FUNC_CANNOT_INLINE(stack_escape_local)
stack_s32 stack_escape_local(void) {
    stack_s32 local = stack_input;
    stack_escape_helper(&local, 13L);
    return local;
}

/* One predecessor has a nested call and the other reaches the join directly. */
#pragma FUNC_CANNOT_INLINE(stack_conditional_noarg)
stack_s32 stack_conditional_noarg(void) {
    volatile stack_s32 local = stack_input;
    if (stack_flag != 0) {
        local = stack_lcr_helper(local, 11L);
    }
    return local + 3L;
}

#pragma FUNC_CANNOT_INLINE(stack_leaf_noarg)
stack_s32 stack_leaf_noarg(void) {
    return stack_input + 1L;
}

#pragma FUNC_CANNOT_INLINE(stack_nonleaf_noarg)
stack_s32 stack_nonleaf_noarg(void) {
    return stack_leaf_noarg() + stack_lcr_helper(stack_input, 17L);
}

#pragma FUNC_CANNOT_INLINE(stack_fixture_entry)
stack_s32 stack_fixture_entry(stack_s32 first, stack_s32 second) {
    stack_s64 mixed = stack_mixed_caller();
    stack_s32 total = stack_noarg_lcr() + stack_noarg_ffc() +
                      stack_reuse_ffc() + stack_noarg_div() +
                      stack_incoming_live(first, second) +
                      stack_escape_local() + stack_conditional_noarg() +
                      stack_leaf_noarg() + stack_nonleaf_noarg();
    stack_sink64 = mixed;
    stack_sink32 = total;
    return total + (stack_s32)mixed;
}
