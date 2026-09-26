/* TI compiler MACF32 schedules. Build at -O0 and
 * -O2 --fp_mode=relaxed --unified_memory;
 * inspect dis2000 beside the decompilation because reassociation may split
 * the dot product across accumulator pairs.
 */
float probe_dot4(const float *a, const float *b)
{
    float sum = 0.0f;
    unsigned int i;
    #pragma UNROLL(4)
    for (i = 0; i < 4; ++i)
        sum += a[i] * b[i];
    return sum;
}

float probe_dot32(const float *a, const float *b)
{
    float sum = 0.0f;
    unsigned int i;
    for (i = 0; i < 32; ++i)
        sum += a[i] * b[i];
    return sum;
}
