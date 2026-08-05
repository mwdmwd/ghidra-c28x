typedef unsigned int u16;

float probe_fload(const float *p)
{
    return *p;
}

float probe_fscale(float value, float scale)
{
    return value * scale;
}

float probe_fload_scale(const float *p, float scale)
{
    return *p * scale;
}

float probe_fsum2(const float *p, float scale)
{
    return p[0] * scale + p[1] * scale;
}

float probe_floop_noscale(const float *p, u16 n)
{
    u16 i;
    float sum = 0.0f;
    for (i = 0u; i < n; ++i) {
        sum += p[i];
    }
    return sum;
}

float probe_floop_scale(const float *p, u16 n, float scale)
{
    u16 i;
    float sum = 0.0f;
    for (i = 0u; i < n; ++i) {
        sum += p[i] * scale;
    }
    return sum;
}
