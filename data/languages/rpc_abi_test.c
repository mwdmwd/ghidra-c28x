typedef long (*rpc_binary_fn)(long, long);
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
    return direct + indirect + stack + rpc_preserve_older(value);
}
