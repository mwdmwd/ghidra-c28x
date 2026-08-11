typedef long (*rpc_binary_fn)(long, long);
volatile long rpc_branch_sink;

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
#pragma FUNC_CANNOT_INLINE(rpc_fixture_entry)
long rpc_fixture_entry(long value) {
    long direct = rpc_nested_outer(value);
    long indirect = rpc_indirect_call(rpc_indirect_target, value+20L, value);
    long stack = rpc_stack_caller(value);
    long branch = rpc_branch_rejoin(value & 1L,value+1L,value+2L,value+3L,
                                    value+4L,value+5L,value+6L,value+7L,
                                    value+8L,value+9L);
    return direct + indirect + stack + branch + rpc_preserve_older(value);
}
