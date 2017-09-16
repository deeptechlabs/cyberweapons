/*
 * The authors of this software are Jim Reeds and Jack Lacy
 *              Copyright (c) 1992, 1994 by AT&T.
 * Permission to use, copy, and modify this software without fee
 * is hereby granted, provided that this entire notice is included in
 * all copies of any software which is or includes a copy or
 * modification of this software and in all copies of the supporting
 * documentation for such software.
 *
 * This software may be subject to United States export controls.
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
 * Copyright (c) 1992, 1994 AT&T Bell Laboratories
 * Coded by Jim Reeds 5 Feb 1992
 * Enhanced by Jack Lacy 1993, 1994
 */

/*
 * unsigned char * shs(char *s, int n);
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

#include <sys/types.h>
#include <stdio.h>

typedef struct {
    long totalLength;
    unsigned long h[5];
    unsigned long w[80];
} SHS_CTX;

unsigned char *shs();
#ifdef SOLARIS2X
#define bzero(b, l)             memset(b, 0, l)
#define bcopy(s, d, l)          memcpy(d, s, l)
#define bcmp(s, d, l)           (memcmp(s, d, l)? 1 : 0)
#endif

static long nbits;
static unsigned long *h;
static unsigned long *w;
static void shs1();
/*
static void packl (unsigned long);
static void pack (unsigned char, unsigned char, unsigned char, unsigned char);
static void shs1(void);
static void opack(unsigned char);
*/

#define MASK        (unsigned long)0xffffffffL        /* in case more than 32 
bits per long */

/*
 * stick one byte into the current block; process the block when full
 */
static void opack(c)
  unsigned char c;
{
	int n32, nd32, shiftbits;
	register unsigned long x, mask, y;
	
	nd32 = (int)(nbits >> 5);  /* nbits/32 */
	n32 = (int)(nbits & 0x1f); /* nbits%32 */
	shiftbits = 24-n32;
	
	x = (unsigned long)(c<<shiftbits);
	mask = (unsigned long)(0xff << shiftbits);
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

static void pack(c0, c1, c2, c3)
  unsigned char c0, c1, c2, c3;
{
	int nd32;
	
	nd32 = (int)(nbits >> 5);
	w[nd32] = (u_long)(((u_long)c0<<24) | ((u_long)c1<<16) | ((u_long)c2<<8) | 
(u_long)c3);
	
	nbits += 32;
	if(nbits==512){
		nbits = 0;
		shs1();
	}
}

/*
 * stick a 4 byte number into the current block
 */
static void
packl(x)
  unsigned long x;
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
	
#define S(n,x) (u_long)(((x)<<(n))|((MASK&(x))>>(32-(n))))
	
	wp = w;
	t = 8;
	do {
		wp[16] = S(1, (u_long)(wp[13]^wp[8]^wp[2]^wp[0]));
		wp[17] = S(1, (u_long)(wp[14]^wp[9]^wp[3]^wp[1]));
		wp[18] = S(1, (u_long)(wp[15]^wp[10]^wp[4]^wp[2]));
		wp[19] = S(1, (u_long)(wp[16]^wp[11]^wp[5]^wp[3]));
		wp[20] = S(1, (u_long)(wp[17]^wp[12]^wp[6]^wp[4]));
		wp[21] = S(1, (u_long)(wp[18]^wp[13]^wp[7]^wp[5]));
		wp[22] = S(1, (u_long)(wp[19]^wp[14]^wp[8]^wp[6]));
		wp[23] = S(1, (u_long)(wp[20]^wp[15]^wp[9]^wp[7]));
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
		temp += (unsigned long)0x5a827999L + ((B&C)|(D&~B));
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<40) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0x6ed9eba1L + (B^C^D);
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<60) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0x8f1bbcdcL + ((B&C)|(B&D)|(C&D));
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	while (t<80) {
		temp = S(5,A) + E + w[t++];
		temp += (unsigned long)0xca62c1d6L + (B^C^D);
		E = D; D = C; C = S(30,B); B = A; A = temp;
	}
	h[0] = MASK&(h[0] + A);
	h[1] = MASK&(h[1] + B);
	h[2] = MASK&(h[2] + C);
	h[3] = MASK&(h[3] + D);
	h[4] = MASK&(h[4] + E);
}

#define CHARSTOLONG(wp,s,i) {*wp++ = (u_long)((((u_long)(s[i])&0xff)<<24)|(((u_
long)(s[i+1])&0xff)<<16)|(((u_long)(s[i+2])&0xff)<<8)|(u_long)(s[i+3]&0xff));}


void
shsInit(mdContext)
  SHS_CTX *mdContext;
{
	nbits = 0;
	mdContext->h[0] = (unsigned long)0x67452301L;
	mdContext->h[1] = (unsigned long)0xefcdab89L;
	mdContext->h[2] = (unsigned long)0x98badcfeL;
	mdContext->h[3] = (unsigned long)0x10325476L;
	mdContext->h[4] = (unsigned long)0xc3d2e1f0L;
	mdContext->totalLength = 0;
}


void
shsUpdate(mdContext, s, n)
  SHS_CTX *mdContext;
  unsigned char *s;
  unsigned int n;
{
	register unsigned long *wp;
	long nn = n;
	long i;
	
	w = mdContext->w;
	h = mdContext->h;
	mdContext->totalLength += n;
	
	nbits = 0;
	n = n/(u_long)64;
	wp = w;
	
	while(n>0){
		CHARSTOLONG(wp,s,0);
		CHARSTOLONG(wp,s,4);
		CHARSTOLONG(wp,s,8);
		CHARSTOLONG(wp,s,12);
		CHARSTOLONG(wp,s,16);
		CHARSTOLONG(wp,s,20);
		CHARSTOLONG(wp,s,24);
		CHARSTOLONG(wp,s,28);
		CHARSTOLONG(wp,s,32);
		CHARSTOLONG(wp,s,36);
		CHARSTOLONG(wp,s,40);
		CHARSTOLONG(wp,s,44);
		CHARSTOLONG(wp,s,48);
		CHARSTOLONG(wp,s,52);
		CHARSTOLONG(wp,s,56);
		CHARSTOLONG(wp,s,60);
		n--;
		wp = w;
		s = (s + 64);
		shs1();
	}
	i=nn%64;
	while(i>3) {
		CHARSTOLONG(wp,s,0);
		s = (s + 4);
		nbits += (u_long)32;
		i -= 4;
	}
	while (i) {
		opack((unsigned char)*s++);
		i--;
	}
}

void
shsFinal(mdContext)
  SHS_CTX *mdContext;
{
	long nn = mdContext->totalLength;
	w = mdContext->w;
	h = mdContext->h;
	
	opack(128);
	while(nbits != 448)opack(0);
	packl((unsigned long)(nn>>29));
	packl((unsigned long)(nn<<3));
	
	/* if(nbits != 0)
	   handle_exception(CRITICAL,"shsFinal(): nbits != 0\n");*/
}

unsigned char *
shs(s, n)
  unsigned char *s;
  long n;
{
        SHS_CTX *mdContext;
	static SHS_CTX mdC;
	static unsigned char ret[20];
	int i;
	
	mdContext = &mdC;

	shsInit(mdContext);
	shsUpdate(mdContext, s, n);
	shsFinal(mdContext);
	for (i=0; i<5; i++) {
		ret[i*4] = (mdContext->h[i]>>24)&0xff;
		ret[i*4+1] = (mdContext->h[i]>>16)&0xff;
		ret[i*4+2] = (mdContext->h[i]>>8)&0xff;
		ret[i*4+3] = (mdContext->h[i])&0xff;
	}
        
	return ret;
}

/*int fread(char *, int, int, FILE *);*/

unsigned long *
fShsDigest(in)
  FILE *in;
{
	SHS_CTX *mdContext;
	SHS_CTX mdC;
	unsigned char buffer[1024];
	long length, total;

	mdContext = &mdC;
	
	bzero(buffer, 1024);

	total = 0;
	shsInit(mdContext);
	while ((length = fread(buffer, 1, 1024, in)) != 0) {
		total += length;
		shsUpdate(mdContext, buffer, length);
	}
	shsFinal(mdContext);

	return mdContext->h;
}



