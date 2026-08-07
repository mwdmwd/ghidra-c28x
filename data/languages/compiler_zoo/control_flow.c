typedef unsigned int zoo_u16;
typedef int zoo_s16;
typedef unsigned long zoo_u32;
typedef long zoo_s32;

/* Comparisons, boolean materialization, short circuiting, forward exits,
 * and both forward and reverse loops in one bounded, self-contained probe. */
zoo_u16 zoo_control_flow(const volatile zoo_u16 *values, zoo_u16 count,
                         zoo_s32 bias, zoo_u32 limit)
{
    zoo_u32 sum = 0ul;
    zoo_u16 i = 0u;

    if (values == (const volatile zoo_u16 *)0) {
        return 0xffffu;
    }

    while ((i < count) && (i < 8u)) {
        zoo_u16 value = values[i];
        if (((value & 1u) != 0u) && (bias < 0l)) {
            sum += (zoo_u32)value;
        }
        else if ((value == 0u) || (sum > limit)) {
            break;
        }
        else {
            sum += (zoo_u32)(zoo_u16)(value ^ i);
        }
        ++i;
    }

    while (i != 0u) {
        --i;
        if (values[i] == 0x55aau) {
            return (zoo_u16)(sum + (zoo_u32)i);
        }
    }

    if (sum > 0xfffful) {
        return 0xffffu;
    }
    return (zoo_u16)sum;
}
