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
 *        CryptoLib Bignum Utilities
 *        coded by Jack Lacy December, 1991
 *
 *        Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"
#include <string.h>

static void ctox P((unsigned char *, int, unsigned char *));

extern int msb_table8[256];

_TYPE( int ) bigNumsAllocated = 0;


Ulong zero_data[1] = {0};
Ulong one_data[1] = {1};
Ulong two_data[1] = {2};
#ifdef DLLEXPORT
Bignum bigzero = {POS, 1, 1, (HGLOBAL)0, (HGLOBAL)0, zero_data};
Bignum bigone = {POS, 1, 1, (HGLOBAL)0, (HGLOBAL)0, one_data};
Bignum bigtwo = {POS, 1, 1, (HGLOBAL)0, (HGLOBAL)0, two_data};
#else
Bignum bigzero = {POS, 1, 1, zero_data};
Bignum bigone = {POS, 1, 1, one_data};
Bignum bigtwo = {POS, 1, 1, two_data};
#endif
_TYPE( BigInt ) zero = &bigzero;
_TYPE( BigInt ) one = &bigone;
_TYPE( BigInt ) two = &bigtwo;

#ifdef DLLEXPORT
#ifdef K_AND_R
_TYPE( BigInt  )
itobig(i)
  Ulong i;
#else
_TYPE( BigInt  ) itobig(Ulong i)
#endif
{
	Bignum *big;
	HGLOBAL bighandle;
	
	bighandle = clib_malloc(sizeof(Bignum));
	if (bighandle == (HGLOBAL)NULL)
		handle_exception(CRITICAL, "clib_malloc returned NULL 1\n");

	big = (Bignum *)GlobalLock(bighandle);
	if (big == NULL)
		handle_exception(CRITICAL, "clib_malloc return NULL 2\n");
	big->bighandle = bighandle;
	
	big->numhandle = clib_malloc(sizeof(Ulong));
	if (big->numhandle == (HGLOBAL)NULL)
		handle_exception(CRITICAL, "clib_malloc returned NULL 3\n");
	
	big->num = (Ulong *)GlobalLock(big->numhandle);
	if (big->num == NULL)
		handle_exception(CRITICAL, "itobig: memory error\n");
	big->num[0] = (Ulong)i;
	big->space = 1;
	big->length = 1;
	big->sign = POS;
	
	bigNumsAllocated++;
	return big;
}

#else

#ifdef K_AND_R
_TYPE( BigInt  )
itobig(i)
  Ulong i;
#else
_TYPE( BigInt  ) itobig(Ulong i)
#endif
{
	BigInt big;
	
	big = (BigInt)clib_malloc(sizeof(Bignum));
	
	NUM(big) = (BigData)clib_malloc(sizeof(Ulong));
	NUM(big)[0] = (Ulong)i;
	SPACE(big) = 1;
	LENGTH(big) = 1;
	SIGN(big) = POS;
	
	bigNumsAllocated++;
	return big;
}
#endif


#ifdef K_AND_R
_TYPE( void )
freeBignum(a)
  BigInt a;
#else
_TYPE( void ) freeBignum(BigInt a)
#endif
{
	int i;
	
	i = (int)SPACE(a);

	while (--i >= 0)
		NUM(a)[i] = 0;
#ifdef DLLEXPORT
	GlobalUnlock(NHNDLE(a));
	GlobalUnlock(BHNDLE(a));
	clib_free(NHNDLE(a));
	clib_free(BHNDLE(a));

#else
	clib_free((unsigned char *)NUM(a));
	clib_free((unsigned char *)a);
#endif
	bigNumsAllocated--;
}

#define BITS(a) (((LENGTH(a) - 1) * UlongBits) + msb((Ulong)NUM(a)[LENGTH(a)-1]))
/* return number of bits in BigInt */
#ifdef K_AND_R
_TYPE( int )
bigBits(a)
  BigInt a;
#else
_TYPE( int ) bigBits(BigInt a)
#endif
{
	return (int)BITS(a);
}

#ifdef K_AND_R
_TYPE( int )
bigBytes(a)
  BigInt a;
#else
_TYPE( int ) bigBytes(BigInt a)
#endif
{
	return (int)(LENGTH(a)*sizeof(Ulong));
}

#ifdef K_AND_R
_TYPE( Sign )
bigTest(a)
  BigInt a;
#else
_TYPE( Sign ) bigTest(BigInt a)
#endif
{
	return SIGN(a);
}

#ifdef K_AND_R
_TYPE( int )
msb(a)
  Ulong a;
#else
_TYPE( int ) msb(Ulong a)
#endif
{
	register Ushort ahi, alo;
	
	if (a & (unsigned long)0x80000000)
		return 32;
	
	ahi = (Ushort)(a >> 16);
	alo = (Ushort)(a & 0xFFFF);
	
	if (ahi) {
		alo = ahi & (Ushort)0xFF;
		ahi = (Ushort)(ahi >> 8);
		if (ahi)
			return (24 + msb_table8[ahi]);
		else
			return (16 + msb_table8[alo]);
	}
	else {
		ahi = (Ushort)(alo >> 8);
		alo = (Ushort)(alo & 0xFF);
		if (ahi)
			return (8 + msb_table8[ahi]);
		else
			return (msb_table8[alo]);
	}
}

#ifdef K_AND_R
_TYPE( int )
old_msb(a)
  Ulong a;
#else
_TYPE( int ) old_msb(Ulong a)
#endif
{
	int i;
	
	i = 1;
	while (a >> 1) {
		a >>= 1;
		i++;
	}
	return i;
}


#ifdef K_AND_R
_TYPE( Boolean )
even(b)
  BigInt b;
#else
_TYPE( Boolean ) even(BigInt b)
#endif
{
	return EVEN(b);
}

#ifdef K_AND_R
_TYPE( Boolean )
odd(b)
  BigInt b;
#else
_TYPE( Boolean ) odd(BigInt b)
#endif
{
	return ODD(b);
}


#ifdef K_AND_R
_TYPE( void )
bufToBig(buf, len, big)
  unsigned char *buf;
  int len;
  BigInt big;
#else
_TYPE( void ) bufToBig(unsigned char *buf,
		       int len,
		       BigInt big)
#endif
{
	register unsigned char *cp;
	register int i;
	register BigData bp;
	register Ulong m;
	Ulong newlen;
	
	cp = buf;
	newlen = len/sizeof(Ulong);
	if (len %sizeof(Ulong))
		newlen++;
	GUARANTEE(big, (int)newlen);
	LENGTH(big) = (int)newlen;
	bp = NUM(big);
	i = (int)LENGTH(big);
	
	while (i > 1) {
		m = ((Ulong)cp[3]<<24)|((Ulong)cp[2]<<16)|((Ulong)cp[1]<<8)|((Ulong)cp[0]);
		cp += sizeof(Ulong);
		*bp++ = m;
		i--;
	};
	m = 0;
	i = 0;
	switch(len%sizeof(Ulong)) {
	    case 0:
		m |= ((Ulong)*cp++ << i);
		i += 8;
	    case 3:
		m |= ((Ulong)*cp++ << i);
		i += 8;
	    case 2:
		m |= ((Ulong)*cp++ << i);
		i += 8;
	    case 1:
		m |= ((Ulong)*cp++ << i);
		break;
	}
	
	*bp = m;
	
	trim(big);
}

#ifdef K_AND_R
_TYPE( void )
bigToBuf(big, bufsize, buf)
  BigInt big;
  int bufsize;
  unsigned char *buf;
#else
_TYPE( void ) bigToBuf(BigInt big,
		       int bufsize,
		       unsigned char *buf)
#endif
{
	register BigData bp;
	register Ulong ss;
	register int i;
	unsigned char *nbp;
	
	if (LENGTH(big)*sizeof(Ulong) > (unsigned)bufsize) {
		handle_exception(CRITICAL, "BigToBuf: Buffer is too small.\n");
	}
	
	for (i=bufsize-1; i>=0; i--)
		buf[i] = 0;
	
	bp = NUM(big);
	nbp = buf;
	for (i = 0; i < (int)LENGTH(big); i++) {
		ss = *bp++;
		*nbp++ = (unsigned char)(ss & 0xff);
		*nbp++ = (unsigned char)((ss >> 8) & 0xff);
		*nbp++ = (unsigned char)((ss >> 16) & 0xff);
		*nbp++ = (unsigned char)((ss >> 24) & 0xff);
	}
}

#ifdef K_AND_R
_TYPE( void )
RSA_bufToBig(buf, len, big)
  unsigned char *buf;
  Ulong len;
  BigInt big;
#else
_TYPE( void ) RSA_bufToBig(unsigned char *buf,
			   int len,
			   BigInt big)
#endif
{
	register unsigned char *cp;
	register int i;
	register BigData bp;
	register Ulong m;
	Ulong newlen;
	
	cp = buf;
	newlen = len/4;
	if (len %4)
		newlen++;
	GUARANTEE(big, (int)newlen);
	LENGTH(big) = (int)newlen;
	bp = NUM(big) + LENGTH(big) - 1;
	i = (int)LENGTH(big);
	
	while (i > 0) {
		m = 0;
		m = ((*cp++ & 0xff) << 24);
		m |= ((*cp++ & 0xff) << 16);
		m |= ((*cp++ & 0xff) << 8);
		m |= ((*cp++ & 0xff) << 0);
		*bp-- = m;
		i--;
	};
	trim(big);
}

#ifdef K_AND_R
_TYPE( void )
RSA_bigToBuf(big, bufsize, buf)
  BigInt big;
  int bufsize;
  unsigned char *buf;
#else
_TYPE( void ) RSA_bigToBuf(BigInt big,
			   int bufsize,
			   unsigned char *buf)
#endif
{
	register BigData bp;
	register Ulong ss;
	register int i;
	unsigned char *nbp;
	
	if (LENGTH(big)*4 > bufsize) {
		handle_exception(CRITICAL, "RSAbigToBuf: buffer too small.\n");
	}
	
	for (i=bufsize-1; i>=0; i--)
		buf[i] = 0;
	
	bp = NUM(big);
	nbp = buf + bufsize - 1;
	for (i = 0; i < (int)LENGTH(big); i++) {
		ss = *bp++;
		*nbp-- = (unsigned char)(ss & 0xff);
		*nbp-- = (unsigned char)((ss >> 8) & 0xff);
		*nbp-- = (unsigned char)((ss >> 16) & 0xff);
		*nbp-- = (unsigned char)((ss >> 24) & 0xff);
	}
}

static int trans_c2x[103] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
	0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
};


#ifdef K_AND_R
_TYPE( BigInt )
atobig(a)
  char *a;
#else
_TYPE( BigInt ) atobig(char *a)
#endif
{
	BigInt big;
	register unsigned char *c;
	register int i;
	int size;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
	
	i = strlen(a);
	size = (i+1)/2;
#ifdef DLLEXPORT
	handle = clib_malloc(size);
	c = (unsigned char *)GlobalLock(handle);
#else
	c = (unsigned char *)clib_malloc(size);
#endif
	ctox((unsigned char *)a, size, c);
	big = bigInit(0);
	bufToBig(c, size, big);
	SIGN(big) = POS;
#ifdef DLLEXPORT
	GlobalUnlock(handle);
	clib_free(handle);
#else
	clib_free((unsigned char *)c);
#endif
	return big;
}

#ifdef K_AND_R
static void
ctox(a, size, c)
  unsigned char *a, *c;
  int size;
#else
  static void ctox(unsigned char *a, int size, unsigned char *c)
#endif
{
	register unsigned char *p;
	register int c1, c2, i;
	
	p = c;
	i = size-1;
	if (strlen((char *)a)%2) {
		p[i] = (unsigned char)(trans_c2x[*a++]);
		--i;
	}

	while(i>=0) {
		c1 = trans_c2x[*a++];
		c2 = trans_c2x[*a++];
		p[i] = (unsigned char)(((c1 << 4) | c2) & 0xff);
		i--;
	}
}

