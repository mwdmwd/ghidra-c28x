/*
 * Defined-behavior TMU0 probes for the three directly reached firmware
 * instructions retained by the semantic audit.  CL2000 documents __sqrtf and
 * __cos as intrinsic entry points; the manifest supplies --tmu_support=tmu0
 * and --fp_mode=relaxed so these lower to native TMU instructions rather than
 * run-time calls.
 */
extern float __sqrtf(float);
extern float __cos(float);

float zoo_tmu_math(float x, volatile float *result)
{
    float root = __sqrtf(x);
    float cosine = __cos(x);

    result[0] = root;
    result[1] = cosine;
    return root + cosine;
}
