typedef unsigned int zoo_u16;

/*
 * A minimized, defined-behavior source for the TMU DIVF32 opcode found at
 * four sites in firmware.bin.  The manifest supplies --tmu_support=tmu0 and
 * --fp_mode=relaxed; without those options CL2000 uses a run-time helper.
 */
float zoo_tmu_division(float numerator, float denominator,
                       volatile float *result)
{
    float quotient;

    if (denominator == 0.0f) {
        *result = numerator;
        return numerator;
    }

    quotient = numerator / denominator;
    *result = quotient;
    return quotient + (float)(zoo_u16)(quotient > 1.0f);
}
