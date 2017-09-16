/*
 * This is version 1.2 of CryptoLib
 *
 * The authors of this software are Jack Lacy, Don Mitchell and Matt Blaze
 *              Copyright (c) 1991, 1992, 1993, 1994, 1995 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * NOTE:
 * Some of the algorithms in cryptolib may be covered by patents.
 * It is the responsibility of the user to ensure that any required
 * licenses are obtained.
 *
 *
 * SOME PARTS OF CRYPTOLIB MAY BE RESTRICTED UNDER UNITED STATES EXPORT
 * REGULATIONS.
 *
 *
 * THIS SOFTWARE IS BEING PROVIDED "AS IS", WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTY.  IN PARTICULAR, NEITHER THE AUTHORS NOR AT&T MAKE ANY
 * REPRESENTATION OR WARRANTY OF ANY KIND CONCERNING THE MERCHANTABILITY
 * OF THIS SOFTWARE OR ITS FITNESS FOR ANY PARTICULAR PURPOSE.
 */

/*
 * Secure Hash Standard
 * proposed NIST SHS
 * coded for byte strings: number of bits is a multiple of 8
 *
 * Copyright (c) 1992 AT&T Bell Laboratories
 * Coded by Jim Reeds 5 Feb 1992
 * Enhanced by Jack Lacy 1993
 */

/*
 * unsigned long shs(char *s, int n);
 *
 * input:  
 *                s character array to be hashed
 *                n length of s in BYTES
 * output:
 *                return value: address of 5 unsigned longs holding hash
 *
 * machine dependencies:
 *                assumes a char is 8 bits
 */

/*
 * passes test on:
 *                gauss (vax)
 *                3k (cray)
 *                slepian (MIPS)
 *                bird (sparcstation II)
 */

#include "libcrypt.h"

static long nbits;
static unsigned long *h;
static unsigned long *w;

static void packl P((unsigned long));
static void pack P((unsigned char, unsigned char, unsigned char, unsigned char));
static void shs1 P((void));
static void opack P((unsigned char));

#define MASK        (unsigned long)0xffffffffUL        /* in case more than 32 bits per long */

/*
 * stick one byte into the current block; process the block when full
 */
#ifdef K_AND_R
static void opack(c)
  unsigned char c;
#else
static void opack(unsigned char c)
#endif
{
	long n32, nd32, shiftbits;
	unsigned long x, mask, y;
	
	nd32 = nbits/32;
	n32 = nbits & 0x1f;
	shiftbits = 24 - n32;
	
	x = (unsigned long)c;
	x <<= shiftbits;
	mask = (unsigned long)0xff;
	mask <<= shiftbits;
	
	mask = ~mask;
	y = w[nd32];
	y = (y & mask) + x;
	w[nd32] = y;
	
	nbits += 8;
	if(nbits==512){
		nbits = 0;
		shs1();
	}
}

#ifdef K_AND_R
  static void pack(c0, c1, c2, c3)
  unsigned char c0, c1, c2, c3;
#else
static void pack(unsigned char c0, unsigned char c1, unsigned char c2, unsigned char c3)
#endif
{
	int nd32;
	unsigned long *wp;
	
	wp = w;
	
	nd32 = (int)(nbits / 32); 
	
	wp[nd32] = (Ulong)c0;
	wp[nd32] = (Ulong)((wp[nd32] << 8) | c1);
	wp[nd32] = (Ulong)((wp[nd32] << 8) | c2);
	wp[nd32] = (Ulong)((wp[nd32] << 8) | c3);
	
	nbits += 32;
	if(nbits==512){
		nbits = 0;
		shs1();
	}
}

/*
 * stick a 4 byte number into the current block
 */
#ifdef K_AND_R
static void
packl(x)
  unsigned long x;
#else
  static void packl(unsigned long x)
#endif
{
	pack((unsigned char)(x>>24), (unsigned char)(x>>16),
	     (unsigned char)(x>>8), (unsigned char)(x>>0));
}

/*
 * process one block
 */
static void
shs1()
{
	unsigned long *wp;
	unsigned long temp;
	unsigned long A, B, C, D, E;
	int t;
	
#define S(n,x) (Ulong)(((x) << (n)) | ((MASK & (x)) >> (32 - (n))))
	
	wp = w;
	t = 8;
	do {
		wp[16] = S(1, (Ulong)(wp[13]^wp[8]^wp[2]^wp[0]));
		wp[17] = S(1, (Ulong)(wp[14]^wp[9]^wp[3]^wp[1]));
		wp[18] = S(1, (Ulong)(wp[15]^wp[10]^wp[4]^wp[2]));
		wp[19] = S(1, (Ulong)(wp[16]^wp[11]^wp[5]^wp[3]));
		wp[20] = S(1, (Ulong)(wp[17]^wp[12]^wp[6]^wp[4]));
		wp[21] = S(1, (Ulong)(wp[18]^wp[13]^wp[7]^wp[5]));
		wp[22] = S(1, (Ulong)(wp[19]^wp[14]^wp[8]^wp[6]));
		wp[23] = S(1, (Ulong)(wp[20]^wp[15]^wp[9]^wp[7]));
		wp += 8;
		t--;
	} while (t > 0);
	
	A = h[0];
	B = h[1];
	C = h[2];
	D = h[3];
	E = h[4];
	
	t = 0;
	while (t<20) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0x5a827999UL + ((B&C)|(D&~B));
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<40) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0x6ed9eba1UL + (B^C^D);
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<60) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0x8f1bbcdcUL + ((B&C)|(B&D)|(C&D));
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<80) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0xca62c1d6UL + (B^C^D);
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	h[0] = MASK&(h[0] + A);
	h[1] = MASK&(h[1] + B);
	h[2] = MASK&(h[2] + C);
	h[3] = MASK&(h[3] + D);
	h[4] = MASK&(h[4] + E);
}
/*
#define CHARSTOLONG(wp,s,i) {*wp++ = (Ulong)((((Ulong)(s[i])&0xff)<<24)|(((Ulong)(s[i+1])&0xff)<<16)|(((Ulong)(s[i+2])&0xff)<<8)|(Ulong)(s[i+3]&0xff));}
*/
#define CHARSTOLONG(wp,s,i) {*wp = (Ulong)s[i];\
			     *wp = (Ulong)((*wp << 8) | s[i+1]); \
			     *wp = (Ulong)((*wp << 8) | s[i+2]); \
			     *wp = (Ulong)((*wp << 8) | s[i+3]); \
			      wp++;}


#ifdef K_AND_R
_TYPE( void )
shsInit(mdContext)
  SHS_CTX *mdContext;
#else
_TYPE( void ) shsInit(SHS_CTX *mdContext)
#endif
{
	int i;
	
	for (i=0; i<80; i++)
		mdContext->w[i] = 0;
	nbits = 0;
	mdContext->h[0] = (unsigned long)0x67452301UL;
	mdContext->h[1] = (unsigned long)0xefcdab89UL;
	mdContext->h[2] = (unsigned long)0x98badcfeUL;
	mdContext->h[3] = (unsigned long)0x10325476UL;
	mdContext->h[4] = (unsigned long)0xc3d2e1f0UL;
	mdContext->totalLength = 0;
}


#ifdef K_AND_R
_TYPE( void )
shsUpdate(mdContext, s, n)
  SHS_CTX *mdContext;
  unsigned char *s;
  unsigned long n;
#else
_TYPE( void ) shsUpdate(SHS_CTX *mdContext,
			unsigned char *s,
			unsigned long n)
#endif
{
	unsigned char *sp;
	register unsigned long *wp;
	long nn = n;
	long i;
	
	sp = s;
	w = mdContext->w;
	h = mdContext->h;
	mdContext->totalLength += n;
	
	n = n/(Ulong)64;
	wp = w;
	
	while(n>0){
		CHARSTOLONG(wp,sp,0);
		CHARSTOLONG(wp,sp,4);
		CHARSTOLONG(wp,sp,8);
		CHARSTOLONG(wp,sp,12);
		CHARSTOLONG(wp,sp,16);
		CHARSTOLONG(wp,sp,20);
		CHARSTOLONG(wp,sp,24);
		CHARSTOLONG(wp,sp,28);
		CHARSTOLONG(wp,sp,32);
		CHARSTOLONG(wp,sp,36);
		CHARSTOLONG(wp,sp,40);
		CHARSTOLONG(wp,sp,44);
		CHARSTOLONG(wp,sp,48);
		CHARSTOLONG(wp,sp,52);
		CHARSTOLONG(wp,sp,56);
		CHARSTOLONG(wp,sp,60);
		n--;
		wp = w;
		sp += 64;
		shs1();
	}
	i=nn%64;
	while(i>3) {
		pack(sp[3], sp[2], sp[1], sp[0]);
		sp += 4;
		i -= 4;
	}
	while (i) {
		opack((unsigned char)*sp++);
		i--;
	}
}

#ifdef K_AND_R
_TYPE( void )
shsFinal(mdContext)
  SHS_CTX *mdContext;
#else
_TYPE( void ) shsFinal(SHS_CTX *mdContext)
#endif
{
	long nn = mdContext->totalLength;
	w = mdContext->w;
	h = mdContext->h;
	
	opack(128);
	while(nbits != 448)opack(0);
	packl((unsigned long)(nn>>29));
	packl((unsigned long)(nn<<3));
	
	if(nbits != 0)handle_exception(CRITICAL, "shsFinal(): nbits != 0\n");
}

#ifdef K_AND_R
_TYPE( unsigned long * )
shs(s, n)
  unsigned char *s;
  unsigned long n;
#else
_TYPE( unsigned long * ) shs(unsigned char *s,
			     unsigned long n)
#endif
{
	SHS_CTX mdContext;
	unsigned long *digest;
	
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(5*sizeof(unsigned long));
	digest = (unsigned long *)GlobalLock(handle);
#else
	digest = (unsigned long *)clib_malloc(5*sizeof(unsigned long));
#endif
	shsInit(&mdContext);
	shsUpdate(&mdContext, s, n);
	shsFinal(&mdContext);
	
	digest[0] = mdContext.h[0];
	digest[1] = mdContext.h[1];
	digest[2] = mdContext.h[2];
	digest[3] = mdContext.h[3];
	digest[4] = mdContext.h[4];

	return digest;
}


#ifdef K_AND_R
_TYPE( unsigned long * )
fShsDigest(in)
  FILE *in;
#else
_TYPE( unsigned long * ) fShsDigest(FILE *in)
#endif
{
	SHS_CTX mdContext;
	unsigned char buffer[1024];
	long length, total;
	unsigned long *digest;

#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(5*sizeof(unsigned long));
	digest = (unsigned long *)GlobalLock(handle);
#else
	digest = (unsigned long *)clib_malloc(5*sizeof(unsigned long));
#endif
	
	clib_memzero(buffer, 1024);

	total = 0;
	shsInit(&mdContext);
	while ((length = fread(buffer, 1, 1024, in)) != 0) {
		total += length;
		shsUpdate(&mdContext, buffer, length);
	}
	shsFinal(&mdContext);
	clib_memzero(buffer, 1024);

	digest[0] = mdContext.h[0];
	digest[1] = mdContext.h[1];
	digest[2] = mdContext.h[2];
	digest[3] = mdContext.h[3];
	digest[4] = mdContext.h[4];

	return digest;
}
