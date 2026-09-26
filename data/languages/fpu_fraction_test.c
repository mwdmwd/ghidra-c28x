/* TI FPU32 intrinsic probes for FRACF32 (SPRUEO2B p. 61).
 * Decompile at -O0 and -O2 with separate object names.
 */
float probe_fraction(float value)
{
    return __fracf32(value);
}

float probe_fraction_large(void)
{
    return __fracf32(2147483648.0f);
}

float probe_fraction_negative_large(void)
{
    return __fracf32(-2147483648.0f);
}

float probe_fraction_control(void)
{
    return __fracf32(19.625f);
}
