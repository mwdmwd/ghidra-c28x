typedef unsigned int zoo_u16;
typedef unsigned long zoo_u32;
typedef unsigned long long zoo_u64;

typedef struct {
    zoo_u16 first;
    zoo_u16 third;
    zoo_u32 total;
} zoo_record;

/* Byte intrinsics, word/longword indexing, a small local structure, and an
 * unsigned 64-bit carry/borrow chain.  All arithmetic has defined wraparound. */
zoo_u32 zoo_data_flow(volatile zoo_u16 *words, volatile zoo_u32 *longs,
                      zoo_u16 byte_index, volatile zoo_u64 *wide)
{
    zoo_record record;
    zoo_u16 index = (zoo_u16)(byte_index & 7u);
    zoo_u16 byte_value = (zoo_u16)__byte((int *)words, index);
    zoo_u64 wide_value;

    __byte((int *)words, (zoo_u16)(index ^ 1u)) =
        (zoo_u16)(byte_value ^ 0x5au);

    record.first = words[1];
    record.third = words[3];
    record.total = longs[1];
    longs[2] = record.total + (zoo_u32)record.first + (zoo_u32)record.third;

    wide_value = *wide;
    wide_value += (zoo_u64)longs[0];
    wide_value -= (zoo_u64)record.third;
    *wide = wide_value;

    return longs[2] + (zoo_u32)wide_value;
}
