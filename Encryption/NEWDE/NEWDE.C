/* NEWDE (V5) - 
 *
 * A portable, public domain, version of StuffIt's NewDE algorithm.
 * Written with Symantec's THINK (Lightspeed) C and Vantage V1.6 by
 * Richard Outerbridge.
 *
 * Copyright 1988,1989,1990,1991 by Richard Outerbridge.
 * (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1991.
 */

#include "newde.h"

/* Internal functions that no one else needs to know about */

static void ffunc(unsigned long *, unsigned long *);
static void scrunch(unsigned char *, unsigned long *);
static void unscrun(unsigned long *, unsigned char *);

/* The internal (active) key registers */

static unsigned long KnL[16] = { 0L };
static unsigned char Df_Key[8] = {
	0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef };

/* Use the 64-bit "KSX" key schedule (Cryptologia, Volume 10,
 * Number 3, July 1986, pp. 152-154.)
 */

void keyload(key, edf)
unsigned char *key;
int edf;
{
	register int i;
	register unsigned long *tofill;
	unsigned long mkr[16];

	for( i = 0; i < 16; i++ ) {
		mkr[i++] = (*key >> 4) & 0x0f;
		mkr[i] = (*key++) & 0x0f;
		}
	for( i = 0; i < 16; i++ ) {
		if( edf == DE1 ) tofill = &KnL[(15-i) << 1];
		else tofill = &KnL[i << 1];
/* 7 */ *tofill    = ((mkr[(i+13)&0x0f]<<2) | (mkr[ i         ]>>2));
/* 5 */ *tofill   |= ((mkr[(i+ 6)&0x0f]<<2) | (mkr[(i+11)&0x0f]>>2)) <<8;
/* 3 */ *tofill   |= ((mkr[(i+10)&0x0f]<<2) | (mkr[(i+ 3)&0x0f]>>2)) <<16;
/* 1 */ *tofill++ |= ((mkr[(i+ 1)&0x0f]<<2) | (mkr[(i+ 8)&0x0f]>>2)) <<24;
/* 8 */ *tofill   = (((mkr[ i         ]<<4) |  mkr[(i+ 9)&0x0f]) &0x3fL);
/* 6 */ *tofill  |= (((mkr[(i+11)&0x0f]<<4) |  mkr[(i+ 2)&0x0f]) &0x3fL) <<8;
/* 4 */ *tofill  |= (((mkr[(i+ 3)&0x0f]<<4) |  mkr[(i+14)&0x0f]) &0x3fL) <<16;
/* 2 */ *tofill  |= (((mkr[(i+ 8)&0x0f]<<4) |  mkr[(i+ 5)&0x0f]) &0x3fL) <<24;
		}
	return;
	}

/* Externally-accessible key management functions */

void cpkey(into)
register unsigned long *into;
{
	register unsigned long *from, *endp;

	from = KnL, endp = &KnL[32];
	while( from < endp ) *into++ = *from++;
	return;
	}

void usekey(from)
register unsigned long *from;
{
	register unsigned long *to, *endp;

	to = KnL, endp = &KnL[32];
	while( to < endp ) *to++ = *from++;
	return;
	}

/* The principal external function interfaces */

void newde(inblock, outblock)
unsigned char *inblock, *outblock;
{
	register unsigned long *work;
	unsigned long buff[2];

	work = buff;
	scrunch(inblock, work);
	ffunc(work, KnL);
	unscrun(work, outblock);
	return;
	}

/* Portable data packing and unpacking */

static void scrunch(outof, into)
register unsigned char *outof;
register unsigned long *into;
{
	*into    = (*outof++ & 0xffL) << 24;
	*into   |= (*outof++ & 0xffL) << 16;
	*into   |= (*outof++ & 0xffL) << 8;
	*into++ |= (*outof++ & 0xffL);
	*into    = (*outof++ & 0xffL) << 24;
	*into   |= (*outof++ & 0xffL) << 16;
	*into   |= (*outof++ & 0xffL) << 8;
	*into   |= (*outof   & 0xffL);
	return;
	}

static void unscrun(outof, into)
register unsigned long *outof;
register unsigned char *into;
{
	*into++ = (unsigned char) ((*outof >> 24) & 0xffL);
	*into++ = (unsigned char) ((*outof >> 16) & 0xffL);
	*into++ = (unsigned char) ((*outof >>  8) & 0xffL);
	*into++ = (unsigned char) ( *outof++      & 0xffL);
	*into++ = (unsigned char) ((*outof >> 24) & 0xffL);
	*into++ = (unsigned char) ((*outof >> 16) & 0xffL);
	*into++ = (unsigned char) ((*outof >>  8) & 0xffL);
	*into   = (unsigned char) ( *outof        & 0xffL);
	return;
	}

/* The combined pre-computed Substitution and Permutation boxes */

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

/* The central bit-crunching f-function */

static void ffunc(block, keys)
register unsigned long *block, *keys;
{
	register unsigned long fval, work, right, leftt;
	register int round;

	leftt = ((block[0] << 1) | ((block[0] >> 31) & 1L)) & 0xffffffffL;
	right = ((block[1] << 1) | ((block[1] >> 31) & 1L)) & 0xffffffffL;
	for( round = 0; round < 8; round++ ) {
		work  = ((right << 28) | (right >> 4)) ^ *keys++;
		fval  = SP7[  work	  & 0x3fL ];
		fval |= SP5[ (work >>  8) & 0x3fL ];
		fval |= SP3[ (work >> 16) & 0x3fL ];
		fval |= SP1[ (work >> 24) & 0x3fL ];
		work  = right ^ *keys++;
		fval |= SP8[  work	  & 0x3fL ];
		fval |= SP6[ (work >>  8) & 0x3fL ];
		fval |= SP4[ (work >> 16) & 0x3fL ];
		fval |= SP2[ (work >> 24) & 0x3fL ];
		leftt ^= fval;
		work  = ((leftt << 28) | (leftt >> 4)) ^ *keys++;
		fval  = SP7[  work	  & 0x3fL ];
		fval |= SP5[ (work >>  8) & 0x3fL ];
		fval |= SP3[ (work >> 16) & 0x3fL ];
		fval |= SP1[ (work >> 24) & 0x3fL ];
		work  = leftt ^ *keys++;
		fval |= SP8[  work	  & 0x3fL ];
		fval |= SP6[ (work >>  8) & 0x3fL ];
		fval |= SP4[ (work >> 16) & 0x3fL ];
		fval |= SP2[ (work >> 24) & 0x3fL ];
		right ^= fval;
		}
	*block++ = (right << 31) | (right >> 1);
	*block   = (leftt << 31) | (leftt >> 1);
	return;
	}

/* Key-hashing functions, ASCII to hex */

void makekey(aptr, kptr)
register char *aptr;		    /* NULL-terminated  */
register unsigned char *kptr;	 /* unsigned char[8] */
{
	register unsigned char *store;
	register int first, i;
	unsigned long savek[32];

	cpkey(savek);
	keyload(Df_Key, EN0);
	for( i = 0; i < 8; i++ ) kptr[i] = Df_Key[i];
	first = 1;
	while( (*aptr != '\0')  || first ) {
		store = kptr;
		for( i = 0; i < 8 && (*aptr != '\0'); i++ ) {
			*store++ ^= *aptr & 0x7f;
			*aptr++ = '\0';
			}
		newde(kptr, kptr);
		first = 0;
		}
	usekey(savek);
	return;
	}

/* Validation sets:
 *
 * Single-length key, single-length plaintext -
 * Key    : 01 23 45 67 89 ab cd ef
 * Plain  : 01 23 45 67 89 ab cd e7
 * NewDE  : de 3c 8f e8 72 15 93 ab
 *
 * Single-length complementation characteristics -
 * E(k)[0] = {E(k*F)[F]}*F = {E(k*A)[5]}*5 = {E(k*5)[A]}*A
 * 
 * newde V5.05 rwo 9109.13 08:00 Graven Imagery
 ********************************************************************/
