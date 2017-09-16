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
 * 32 bit multiplication macros 32x32 bit multiplication into
 * 64 bit result.  The asm macros work only with gcc.
 * If gcc is not used or if your architecture is not covered here,
 * the slower Karatsuba method at the end of this file is used.
 * If you want to add the correct GNU macro for your architecture,
 * that'd be great!  Thanks to the GNU folks for their very nice
 * inline asm extension tools and to SUN for the 32 bit multiplication
 * method for sparc2s.
 */

#if defined (__GNUC__) && !defined (NO_ASM)

/* sparc 32 bit multiplication */
#if defined (__sparc__) /* for sparc 2 */
#if defined (__sparc10__) /* for sparc 10, 20 */

#define lmul32(hp, lp, x, y) \
  __asm__ ("umul %2,%3,%1
        rd %%y,%0"					\
	: "=r" ((unsigned long)(hp)), "=r" ((unsigned long)(lp))\
	: "r" ((unsigned long)(x)), "r" ((unsigned long)(y)))

#else

/* sparc lacking integer multiplication instructions. */

#define lmul32(hp, lp, x, y) \
__asm__("
	mov	%3, %%y
	andcc	%%g0,%%g0,%%g1
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%2,%%g1;	mulscc	%%g1,%2,%%g1;
	mulscc	%%g1,%%g0,%%g1
	tst	%2
	bge	1f
	nop
	add	%%g1, %3, %%g1
1:
	rd	%%y,%1
	andcc	%%g1, %%g1, %0" \
	: "=r" ((unsigned long)(hp)), "=r" ((unsigned long)(lp))\
	: "%rI" ((unsigned long)(x)), "r" ((unsigned long)(y))	\
	: "%g1", "%g2")

#endif
#endif

/* MIPS 32 bit multiplication */
#if defined (__mips__)
#define lmul32(hp, lp, x, y) \
  __asm__ ("multu %2,%3
	mflo %0
	mfhi %1"							\
	: "=r" ((unsigned long)(hp)), "=r" ((unsigned long)(lp))\
	: "r" ((unsigned long)(x)), "r" ((unsigned long)(y)))
#endif

/* x86 32 bit multiplication */
#if defined (__i386__) || defined (__i486__)
#define lmul32(hp, lp, x, y) \
  __asm__ ("mull %3"							\
	: "=a" ((unsigned long)(lp)), "=d" ((unsigned long)(hp))\
	: "%0" ((unsigned long)(x)), "rm" ((unsigned long)(y)))
#endif /* __i386__ */

#endif /* __GNUC__ */

/* If this machine has no inline assembler, use C macros.  */

#if !defined (lmul32)
/* Lacy implementation of Karatsuba 32x32 bit mult 5/26/93 */
#define lmul32(hp, lp, a, b)						\
    do {								\
        unsigned long __pmidh, __pmidl;					\
        unsigned long __ahi, __bhi, __alo, __blo;			\
	long __carry;							\
									\
	__ahi = ((a) >> 16);						\
	__alo = (a) & 0xFFFF;						\
	__bhi = ((b) >> 16);						\
	__blo = (b) & 0xFFFF;						\
									\
	(hp) = __ahi * __bhi;						\
	(lp) = __alo * __blo;						\
	__ahi -= __alo;							\
	__blo -= __bhi;							\
	__pmidh = __ahi * __blo;					\
	__carry = (__pmidh)?-((__ahi ^ __blo) & 0x10000):0;		\
									\
	__pmidh += (hp);						\
	__carry += (__pmidh < (hp))?0x10000:0;				\
	__pmidh += (lp);						\
	__carry += (__pmidh < (lp))?0x10000:0;				\
	__pmidl = __pmidh << 16;					\
	__pmidh >>= 16;							\
									\
	(lp) += __pmidl;						\
	__carry += ((lp) < __pmidl);					\
									\
	(hp) += __carry + __pmidh;					\
    } while (0)

#endif

