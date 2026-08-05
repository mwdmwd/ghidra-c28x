typedef unsigned int u16;
typedef int s16;
typedef unsigned long u32;
typedef long s32;
typedef unsigned long long u64;
typedef long long s64;

typedef struct {
    u16 lo;
    u16 hi;
    u32 total;
} probe_record;

u16 probe_u16_mix(u16 a, u16 b, u16 shift)
{
    shift &= 15u;
    return (u16)((u16)(a + b) ^ (u16)(a << shift) ^ (u16)(b >> ((16u - shift) & 15u)));
}

s32 probe_s16_widen(s16 a, s16 b)
{
    return (s32)a + (s32)b - ((s32)a >> 3);
}

u32 probe_u32_mix(u32 a, u32 b, u16 shift)
{
    shift &= 31u;
    return (a + b) ^ (a << shift) ^ (b >> ((32u - shift) & 31u));
}

u32 probe_mul_u16(u16 a, u16 b)
{
    return (u32)a * (u32)b;
}

u32 probe_mul_u32(u32 a, u32 b)
{
    return a * b;
}

s16 probe_cmp_s16(s16 a, s16 b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}

u16 probe_cmp_u16(u16 a, u16 b)
{
    if (a < b) return 1u;
    if (a == b) return 2u;
    return 3u;
}

s16 probe_cmp_s32(s32 a, s32 b)
{
    if (a <= b) return 7;
    return 9;
}

u16 probe_cmp_u32(u32 a, u32 b)
{
    if (a >= b) return 11u;
    return 13u;
}

s16 probe_cmp_s32_boundaries(s32 value)
{
    if (value == (-2147483647L - 1L)) return -2;
    if (value < -1L) return -1;
    if (value == 0L) return 0;
    if (value >= 2147483647L) return 2;
    return 1;
}

u16 probe_cmp_u32_boundaries(u32 value)
{
    if (value == 0UL) return 0u;
    if (value < 0x80000000UL) return 1u;
    if (value == 0xffffffffUL) return 3u;
    return 2u;
}

u64 probe_add_u64(u64 a, u64 b)
{
    return a + b;
}

u64 probe_sub_u64(u64 a, u64 b)
{
    return a - b;
}

u64 probe_add_u64_mem(const u64 *a, const u64 *b)
{
    return *a + *b;
}

u64 probe_sub_u64_mem(const u64 *a, const u64 *b)
{
    return *a - *b;
}

u32 probe_sum_u16(const u16 *p, u16 n)
{
    u16 i;
    u32 sum = 0u;
    for (i = 0u; i < n; ++i) {
        sum += p[i];
    }
    return sum;
}

u32 probe_sum_u32(const u32 *p, u16 n)
{
    u16 i;
    u32 sum = 0u;
    for (i = 0u; i < n; ++i) {
        sum += p[i];
    }
    return sum;
}

u32 probe_sum_reverse_u16(const u16 *end, u16 n)
{
    u32 sum = 0u;
    while (n != 0u) {
        --end;
        sum += *end;
        --n;
    }
    return sum;
}

u32 probe_sum_reverse_u32(const u32 *end, u16 n)
{
    u32 sum = 0u;
    while (n != 0u) {
        --end;
        sum += *end;
        --n;
    }
    return sum;
}

u16 probe_byte_read(const u16 *base, u16 byte_index)
{
    return (u16)__byte((int *)base, byte_index);
}

void probe_byte_write(u16 *base, u16 byte_index, u16 value)
{
    __byte((int *)base, byte_index) = value;
}

void probe_copy_u16(u16 *dst, const u16 *src, u16 n)
{
    u16 i;
    for (i = 0u; i < n; ++i) {
        dst[i] = src[i];
    }
}

void probe_copy_u32(u32 *dst, const u32 *src, u16 n)
{
    u16 i;
    for (i = 0u; i < n; ++i) {
        dst[i] = src[i];
    }
}

void probe_stride_u16(u16 *dst, const u16 *src, u16 n)
{
    u32 i;
    for (i = 0u; i < (u32)n; ++i) {
        dst[i * 2u] = src[i * 3u];
    }
}

u32 probe_counted_down(const u16 *p, u16 n)
{
    u32 sum = 0u;
    while (n != 0u) {
        sum += *p++;
        --n;
    }
    return sum;
}

u32 probe_pointer_end(const u32 *first, const u32 *last)
{
    u32 sum = 0u;
    while (first != last) {
        sum += *first++;
    }
    return sum;
}

u32 probe_stack_locals(u16 a, u16 b, u16 c)
{
    u16 v[4];
    v[0] = a;
    v[1] = b;
    v[2] = c;
    v[3] = (u16)(a ^ b ^ c);
    return (u32)v[0] + (u32)v[1] + (u32)v[2] + (u32)v[3];
}

probe_record probe_make_record(u16 a, u16 b)
{
    probe_record r;
    r.lo = a;
    r.hi = b;
    r.total = (u32)a + (u32)b;
    return r;
}

u32 probe_record_sum(probe_record r)
{
    return (u32)r.lo + (u32)r.hi + r.total;
}

float probe_float_arith(float a, float b, float c)
{
    return (a * b) + c - (a * c);
}

float probe_float_loop(const float *p, u16 n, float scale)
{
    u16 i;
    float sum = 0.0f;
    for (i = 0u; i < n; ++i) {
        sum += p[i] * scale;
    }
    return sum;
}

float probe_s16_to_float(s16 value)
{
    return (float)value;
}

float probe_u16_to_float(u16 value)
{
    return (float)value;
}

float probe_s32_to_float(s32 value)
{
    return (float)value;
}

float probe_u32_to_float(u32 value)
{
    return (float)value;
}

s16 probe_float_to_s16(float value)
{
    if (value != value) value = 0.0f;
    if (value > 32767.0f) value = 32767.0f;
    if (value < -32768.0f) value = -32768.0f;
    return (s16)value;
}

u16 probe_float_to_u16(float value)
{
    if (value != value) value = 0.0f;
    if (value > 65535.0f) value = 65535.0f;
    if (value < 0.0f) value = 0.0f;
    return (u16)value;
}

#pragma FUNC_CANNOT_INLINE(probe_callee)
u32 probe_callee(u32 a, u16 b)
{
    return a + (u32)b + 0x1234u;
}

u32 probe_call(u32 a, u16 b)
{
    return probe_callee(a ^ 0x55aa55aaUL, (u16)(b + 3u));
}
