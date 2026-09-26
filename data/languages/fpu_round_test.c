/* TI FPU32 intrinsics and ordinary unsigned casts; instruction semantics:
 * SPRUEO2B pp. 56/59 and SPRUHS1C pp. 54/56/57.
 *
 * Compile at -O0 and -O2 with distinct DECOMPILE_OBJECT names, then use
 * make decompile DECOMPILE_SOURCE=fpu_round_test.c with these six names
 * in DECOMPILE_FUNCTIONS. The compiler supplies the required delay slots.
 */
int probe_f32toi16r(float value)
{
    return __f32toi16r(value);
}

unsigned int probe_f32toui16r(float value)
{
    return __f32toui16r(value);
}

int probe_f32toi16r_example(void)
{
    return __f32toi16r(-1.7f);
}

unsigned int probe_f32toui16r_example(void)
{
    return __f32toui16r(10.8f);
}

unsigned int probe_f32toui16(float value)
{
    /* Use representable inputs for this C probe; P-Code vectors separately
     * exercise the instruction's saturation outside the C conversion range.
     */
    return (unsigned int)value;
}

unsigned int probe_f32toui16_control(void)
{
    return (unsigned int)65534.75f;
}
