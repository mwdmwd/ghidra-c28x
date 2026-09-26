/* TI FPU32 intrinsics: SPRU514Z, Table 7-7; instruction semantics:
 * SPRUEO2B pp. 56/59 and SPRUHS1C pp. 54/57.
 *
 * Compile at -O0 and -O2 with distinct DECOMPILE_OBJECT names, then use
 * make decompile DECOMPILE_SOURCE=fpu_round_test.c with these four names
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
