typedef unsigned long uint32_t;
typedef unsigned short uint16_t;

volatile uint16_t pm_store_sink;
volatile uint32_t pm_call_sink;

#pragma FUNC_CANNOT_INLINE(pm_leaf)
void pm_leaf(uint32_t value)
{
    pm_call_sink += value;
}

#pragma FUNC_CANNOT_INLINE(pm_plain_quotient_store)
void pm_plain_quotient_store(uint32_t value)
{
    pm_store_sink = (uint16_t)(value / 10UL);
}

#pragma FUNC_CANNOT_INLINE(pm_store_after_call)
void pm_store_after_call(uint32_t value)
{
    uint32_t quotient = value / 10UL;
    pm_leaf(value);
    pm_store_sink = (uint16_t)quotient;
}

#pragma FUNC_CANNOT_INLINE(pm_store_after_unequal_calls)
void pm_store_after_unequal_calls(uint32_t value, uint16_t choose_short_arm)
{
    uint32_t quotient = value / 10UL;

    if (choose_short_arm != 0U) {
        pm_leaf(value);
    }
    else {
        pm_leaf(value);
        pm_leaf(value + 1UL);
        pm_leaf(value + 2UL);
    }
    pm_store_sink = (uint16_t)quotient;
}

void pm_product_store_entry(uint32_t value, uint16_t choose_short_arm)
{
    pm_plain_quotient_store(value);
    pm_store_after_call(value);
    pm_store_after_unequal_calls(value, choose_short_arm);
}
