typedef unsigned int zoo_u16;
typedef unsigned long zoo_u32;

#ifndef ZOO_SWITCH_CASES
#define ZOO_SWITCH_CASES 12
#endif

/*
 * Minimal cl2000 22.6.1.LTS probe for the default-memory saved-XAR7
 * program-read dispatch.  Twelve dense 32-bit cases are the smallest
 * table form observed in the bounded density sweep (eleven uses compares).
 */
void switch_pread32_probe(volatile zoo_u16 *out, zoo_u32 selector, zoo_u16 value)
{
    switch (selector) {
    case 0x220ul: out[0] = value; break;
    case 0x221ul: out[3] = value; break;
    case 0x222ul: out[1] = value; break;
    case 0x223ul: out[7] = value; break;
    case 0x224ul: out[2] = value; break;
    case 0x225ul: out[11] = value; break;
    case 0x226ul: out[4] = value; break;
    case 0x227ul: out[13] = value; break;
    case 0x228ul: out[5] = value; break;
    case 0x229ul: out[17] = value; break;
    case 0x22aul: out[6] = value; break;
#if ZOO_SWITCH_CASES >= 12
    case 0x22bul: out[19] = value; break;
#endif
    default: break;
    }
}
