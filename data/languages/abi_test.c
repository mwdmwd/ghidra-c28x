typedef struct {
    float sum;
    long count;
} abi_pair;

float abi_dot4(float a, float b, float c, float d)
{
    return (a * b) + (c * d);
}

long abi_scale_sum(float *dst, const float *src, long n, float scale)
{
    long i;
    float acc = 0.0f;

    for (i = 0; i < n; ++i) {
        float v = src[i] * scale;
        dst[i] = v;
        acc += v;
    }

    return (long)acc + n;
}

abi_pair abi_make_pair(float value, long count)
{
    abi_pair out;

    out.sum = value + (float)count;
    out.count = count + 1;

    return out;
}
