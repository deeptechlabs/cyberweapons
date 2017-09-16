/* des3_port.c 95/11/11 08:40:10 EST */

#include "des3.h"

static void deskey(unsigned char *, short, unsigned long *);
static void cookey(unsigned long *, unsigned long *);

static unsigned short bytebit[8] = {
    0200, 0100, 040, 020, 010, 04, 02, 01 };

static unsigned long bigbyte[24] = {
    0x800000L, 0x400000L, 0x200000L, 0x100000L,
    0x80000L,  0x40000L,  0x20000L,  0x10000L,
    0x8000L,   0x4000L,   0x2000L,   0x1000L,
    0x800L,    0x400L,    0x200L,    0x100L,
    0x80L,     0x40L,     0x20L,     0x10L,
    0x8L,      0x4L,      0x2L,      0x1L    };

/* Use the key schedule specified in the Standard (ANSI X3.92-1981). */

static unsigned char pc1[56] = {
    56, 48, 40, 32, 24, 16,  8,   0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26,  18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,   6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28,  20, 12,  4, 27, 19, 11,  3 };

static unsigned char totrot[16] = {
    1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 };

static unsigned char pc2[48] = {
    13, 16, 10, 23,  0,  4,   2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7,  15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54,  29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52,  45, 41, 49, 35, 28, 31 };

static void deskey(unsigned char *key, short edf, unsigned long *out) {
    int i, j, l;
    unsigned char *pp0, *pp2, *ep, *pcp, *pep, pc1m[56], pcr[56];
    unsigned long *kp0, *bbp, kn[32];

    for ( j = 0, pp0 = pc1m; j < 56; j++ ) {
        i = (l = pc1[j]) & 07;
        *pp0++ = (key[l >> 3] & bytebit[i]) ? 1 : 0;
        }
    pep = &pc1m[28];
    for( i = 0; i < 16; i++ ) {
        pp0 = pcr;
        pp2 = ep = pp0 + 28;
        pcp = &pc1m[totrot[i]];
        while( pp0 < ep ) {    
            if( pcp < pep ) {
                *pp0++ = *pcp;
                *pp2++ = pcp[28];
                }
            else {
                *pp0++ = pcp[-28];
                *pp2++ = *pcp;
                }
            pcp++;
            }
        kp0 = &kn[ ((edf == DE1) ? (15 - i) : i) << 1 ];
        *kp0 = kp0[1] = 0L;
        bbp = bigbyte;
        pp0 = pc2;
        ep = pp0 + 24;
        while( pp0 < ep ) {
            if( pcr[*pp0] ) *kp0 |= *bbp;
            if( pcr[pp0[24]] ) kp0[1] |= *bbp;
            pp0++;
            bbp++;
            }
        }
    cookey(kn, out);
    return;
    }

static void cookey(unsigned long *raw1, unsigned long *cook) {
    unsigned long *raw0, *ep;

    ep = &cook[32];
    while( cook < ep ) {
        raw0 = raw1++;
        *cook     = (*raw0 & 0x00fc0000L) << 6;
        *cook    |= (*raw0 & 0x00000fc0L) << 10;
        *cook    |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++  |= (*raw1 & 0x00000fc0L) >> 6;
        *cook     = (*raw0 & 0x0003f000L) << 12;
        *cook    |= (*raw0 & 0x0000003fL) << 16;
        *cook    |= (*raw1 & 0x0003f000L) >> 4;
        *cook++  |= (*raw1++ & 0x0000003fL);
        }
    return;
    }

void des2key(unsigned char hexkey[16], short mode,
                unsigned long keyout[96]) {
    unsigned long *cp, *ep, *dp;
    short revmod;

    revmod = (mode == EN0) ? DE1 : EN0;
    deskey(&hexkey[8], revmod, &keyout[32]);
    deskey(hexkey, mode, keyout);
    cp = keyout;
    ep = &keyout[32];
    dp = &keyout[64];
    while( cp < ep ) *dp++ = *cp++;
    return;
    }
    
#ifdef DES3
void des3key(unsigned char hexkey[24], short mode,
                unsigned long keyout[96]) {
    unsigned char *first, *third;
    short revmod;

    if( mode == EN0 ) {
        revmod = DE1;
        first = hexkey;
        third = &hexkey[16];
        }
    else {
        revmod = EN0;
        first = &hexkey[16];
        third = hexkey;
        }
    deskey(first, mode, keyout);
    deskey(&hexkey[8], revmod, &keyout[32]);
    deskey(third, mode, &keyout[64]);
    return;
    }
#endif

static unsigned long SP1[64] = {
    0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
    0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
    0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
    0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
    0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
    0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
    0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
    0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
    0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
    0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
    0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
    0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
    0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
    0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
    0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L };

static unsigned long SP2[64] = {
    0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
    0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
    0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
    0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
    0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
    0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
    0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
    0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
    0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
    0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
    0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
    0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
    0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
    0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
    0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
    0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L };

static unsigned long SP3[64] = {
    0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
    0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
    0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
    0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
    0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
    0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
    0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
    0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
    0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
    0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
    0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
    0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
    0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
    0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
    0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
    0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L };

static unsigned long SP4[64] = {
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
    0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
    0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
    0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
    0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
    0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
    0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
    0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
    0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
    0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
    0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
    0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
    0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L };

static unsigned long SP5[64] = {
    0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
    0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
    0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
    0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
    0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
    0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
    0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
    0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
    0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
    0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
    0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
    0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
    0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
    0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
    0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
    0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L };

static unsigned long SP6[64] = {
    0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
    0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
    0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
    0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
    0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
    0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
    0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
    0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
    0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
    0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
    0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
    0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
    0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
    0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
    0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L };

static unsigned long SP7[64] = {
    0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
    0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
    0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
    0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
    0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
    0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
    0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
    0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
    0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
    0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
    0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
    0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
    0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
    0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
    0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
    0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L };

static unsigned long SP8[64] = {
    0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
    0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
    0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
    0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
    0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
    0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
    0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
    0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
    0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
    0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
    0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
    0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
    0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
    0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
    0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
    0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L };

static unsigned short Padd = 0x0123;    /* 68030 TC5 allignment */

void des3(unsigned char inblock[8], unsigned char outblock[8],
            unsigned long keys[96]) {
    unsigned long fval, work, right, leftt;
    int round, iterate;
    
    leftt   = ((unsigned long)inblock[0] << 24)
            | ((unsigned long)inblock[1] << 16)
            | ((unsigned long)inblock[2] << 8)
            |  (unsigned long)inblock[3];
    right   = ((unsigned long)inblock[4] << 24)
            | ((unsigned long)inblock[5] << 16)
            | ((unsigned long)inblock[6] << 8)
            |  (unsigned long)inblock[7];
    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL;
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL;
    iterate = 1;
    goto Des0;
    while( iterate < 3 ) {
        work = right;
        right = leftt;
        leftt = work;
        iterate++;
Des0:    
        for( round = 0; round < 8; round++ ) {
            work  = ((right << 28) | (right >> 4)) ^ *keys++;
            fval  = SP7[ work        & 0x3fL];
            fval |= SP5[(work >>  8) & 0x3fL];
            fval |= SP3[(work >> 16) & 0x3fL];
            fval |= SP1[(work >> 24) & 0x3fL];
            work  = right ^ *keys++;
            fval |= SP8[ work        & 0x3fL];
            fval |= SP6[(work >>  8) & 0x3fL];
            fval |= SP4[(work >> 16) & 0x3fL];
            fval |= SP2[(work >> 24) & 0x3fL];
            leftt ^= fval;
            work  = ((leftt << 28) | (leftt >> 4)) ^ *keys++;
            fval  = SP7[ work        & 0x3fL];
            fval |= SP5[(work >>  8) & 0x3fL];
            fval |= SP3[(work >> 16) & 0x3fL];
            fval |= SP1[(work >> 24) & 0x3fL];
            work  = leftt ^ *keys++;
            fval |= SP8[ work        & 0x3fL];
            fval |= SP6[(work >>  8) & 0x3fL];
            fval |= SP4[(work >> 16) & 0x3fL];
            fval |= SP2[(work >> 24) & 0x3fL];
            right ^= fval;
            }
        }
    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333L;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL;
    leftt ^= work;
    right ^= (work << 4);
    outblock[0] = (unsigned char)(right >> 24) & 0xFF;
    outblock[1] = (unsigned char)(right >> 16) & 0xFF;
    outblock[2] = (unsigned char)(right >>  8) & 0xFF;
    outblock[3] = (unsigned char)(right      ) & 0xFF;
    outblock[4] = (unsigned char)(leftt >> 24) & 0xFF;
    outblock[5] = (unsigned char)(leftt >> 16) & 0xFF;
    outblock[6] = (unsigned char)(leftt >>  8) & 0xFF;
    outblock[7] = (unsigned char)(leftt      ) & 0xFF;
    return;
    }

/* Validation triples -
 *
 * Double-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210
 * Plain  : 0123 4567 89ab cde7
 * Cipher : 7f1d 0a77 826b 8aff
 *
 * Triple-length key, single-length plaintext -
 * Key    : 0123 4567 89ab cdef fedc ba98 7654 3210 89ab cdef 0123 4567
 * Plain  : 0123 4567 89ab cde7
 * Cipher : de0b 7c06 ae5e 0ed5
 */
/***** end of des3_port.c ***** Graven Imagery ***********************/
