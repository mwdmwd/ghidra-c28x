typedef unsigned int zoo_u16;

/* Common FPU32 multiply/add, compare, store, conversion, and bounded-loop
 * idioms.  NaN and range checks keep the final C conversion defined. */
zoo_u16 zoo_fpu32(volatile float *dst, const volatile float *src,
                  zoo_u16 count, float scale, float limit)
{
    float sum = 0.0f;
    zoo_u16 i = 0u;

    while ((i < count) && (i < 8u)) {
        float value = src[i] * scale + 0.5f;
        dst[i] = value;
        if (value > limit) {
            break;
        }
        sum += value;
        ++i;
    }

    if (sum != sum) {
        return 0u;
    }
    if (sum < 0.0f) {
        sum = -sum;
    }
    if (sum > 65535.0f) {
        return 65535u;
    }
    return (zoo_u16)sum;
}
