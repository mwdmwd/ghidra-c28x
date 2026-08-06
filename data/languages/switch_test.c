typedef unsigned int u16;

/*
 * Keep the stores deliberately non-linear so the compiler cannot replace the
 * switch with arithmetic.  The two dense ranges mirror a real TI-generated
 * dispatch shape and should become adjacent 22- and 14-entry .switch tables.
 */
void switch_probe(volatile u16 *out, u16 selector, u16 value)
{
    switch (selector) {
    case 0x1ae: out[0x00] = value; break;
    case 0x1af: out[0x03] = value; break;
    case 0x1b0: out[0x01] = value; break;
    case 0x1b1: out[0x07] = value; break;
    case 0x1b2: out[0x02] = value; break;
    case 0x1b3: out[0x0b] = value; break;
    case 0x1b4: out[0x04] = value; break;
    case 0x1b5: out[0x0d] = value; break;
    case 0x1b6: out[0x05] = value; break;
    case 0x1b7: out[0x11] = value; break;
    case 0x1b8: out[0x06] = value; break;
    case 0x1b9: out[0x13] = value; break;
    case 0x1ba: out[0x08] = value; break;
    case 0x1bb: out[0x17] = value; break;
    case 0x1bc: out[0x09] = value; break;
    case 0x1bd: out[0x1d] = value; break;
    case 0x1be: out[0x0a] = value; break;
    case 0x1bf: out[0x1f] = value; break;
    case 0x1c0: out[0x0c] = value; break;
    case 0x1c1: out[0x25] = value; break;
    case 0x1c2: out[0x0e] = value; break;
    case 0x1c3: out[0x29] = value; break;
    case 0x1e0: out[0x32] = value; break;
    case 0x1e1: out[0x35] = value; break;
    case 0x1e2: out[0x33] = value; break;
    case 0x1e3: out[0x39] = value; break;
    case 0x1e4: out[0x34] = value; break;
    case 0x1e5: out[0x3b] = value; break;
    case 0x1e6: out[0x36] = value; break;
    case 0x1e7: out[0x3d] = value; break;
    case 0x1e8: out[0x37] = value; break;
    case 0x1e9: out[0x3f] = value; break;
    case 0x1ea: out[0x38] = value; break;
    case 0x1eb: out[0x3a] = value; break;
    case 0x1ec: out[0x3c] = value; break;
    case 0x1ed: out[0x3e] = value; break;
    default: break;
    }
}
