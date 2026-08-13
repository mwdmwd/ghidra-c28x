typedef unsigned short c28_u16;
typedef signed short c28_s16;
typedef unsigned long c28_u32;
typedef signed long c28_s32;
typedef void (*status_call_t)(void);

#define NOINLINE __attribute__((noinline))

volatile c28_u16 status_mmio_word;
volatile c28_u16 status_sink16;
volatile c28_u32 status_sink32;
c28_u16 status_table[128];
c28_u16 status_fixture_input[2];
c28_u16 status_fixture_output;

NOINLINE void status_consume16(c28_u16 value)
{
    status_sink16 = value;
}

NOINLINE void status_low_combine_store(const c28_u16 *input, c28_u16 *output)
{
    *output = (c28_u16)((input[1] << 8) + input[0]);
}

NOINLINE void status_low_combine_pass(const c28_u16 *input)
{
    status_consume16((c28_u16)((input[1] << 8) + input[0]));
}

NOINLINE void status_low_shift_store(const c28_u16 *input)
{
    status_sink16 = (c28_u16)(input[0] << 1);
}

NOINLINE void status_low_shift_pass(const c28_u16 *input)
{
    status_consume16((c28_u16)(input[0] << 1));
}

NOINLINE void status_low_shift15_store(const c28_u16 *input)
{
    status_sink16 = (c28_u16)(input[0] << 15);
}

NOINLINE c28_u32 status_full_unsigned(c28_u16 value)
{
    return ((c28_u32)value) << 8;
}

NOINLINE c28_s32 status_full_signed(c28_s16 value)
{
    return ((c28_s32)value) << 8;
}

NOINLINE c28_s32 status_full_signed_shift0(c28_s16 value)
{
    return ((c28_s32)value) << 0;
}

NOINLINE c28_u32 status_full_unsigned_shift15(c28_u16 value)
{
    return ((c28_u32)value) << 15;
}

NOINLINE c28_s32 status_full_signed_shift15(c28_s16 value)
{
    return ((c28_s32)value) << 15;
}

NOINLINE void status_low_volatile(void)
{
    status_sink16 = (c28_u16)(status_mmio_word << 8);
}

NOINLINE c28_u32 status_full_volatile(void)
{
    return ((c28_u32)status_mmio_word) << 8;
}

NOINLINE void status_callee(void)
{
    status_sink16++;
}

NOINLINE c28_u16 *status_post_call_sum(c28_u16 index)
{
    status_callee();
    return status_table + index;
}

NOINLINE c28_u32 status_post_call_integer(c28_u16 index)
{
    status_callee();
    return 0x10000UL + index;
}

NOINLINE c28_u16 *status_unequal_calls(c28_u16 index, c28_u16 select)
{
    if (select) {
        status_callee();
    }
    else {
        status_callee();
        status_callee();
    }
    return status_table + index;
}

NOINLINE void status_nested_callee(void)
{
    status_callee();
}

NOINLINE c28_u16 *status_nested_direct(c28_u16 index)
{
    status_nested_callee();
    return status_table + index;
}

status_call_t status_known_call = status_callee;

NOINLINE c28_u16 *status_post_known_indirect(c28_u16 index)
{
    status_known_call();
    return status_table + index;
}

NOINLINE c28_u16 *status_post_ambiguous_indirect(status_call_t call, c28_u16 index)
{
    call();
    return status_table + index;
}

void status_mode_entry(void)
{
    status_low_combine_store(status_fixture_input, &status_fixture_output);
    status_low_combine_pass(status_fixture_input);
    status_low_shift_store(status_fixture_input);
    status_low_shift_pass(status_fixture_input);
    status_low_shift15_store(status_fixture_input);
    status_sink32 = status_full_unsigned(status_fixture_output);
    status_sink32 = (c28_u32)status_full_signed((c28_s16)status_fixture_output);
    status_sink32 = (c28_u32)status_full_signed_shift0((c28_s16)status_fixture_output);
    status_sink32 = status_full_unsigned_shift15(status_fixture_output);
    status_sink32 = (c28_u32)status_full_signed_shift15((c28_s16)status_fixture_output);
    status_low_volatile();
    status_sink32 = status_full_volatile();
    status_sink32 = (c28_u32)status_post_call_sum(status_fixture_output);
    status_sink32 = status_post_call_integer(status_fixture_output);
    status_sink32 = (c28_u32)status_unequal_calls(status_fixture_output, status_sink16);
    status_sink32 = (c28_u32)status_nested_direct(status_fixture_output);
    status_sink32 = (c28_u32)status_post_known_indirect(status_fixture_output);
    status_sink32 = (c28_u32)status_post_ambiguous_indirect(status_known_call, status_fixture_output);
}
