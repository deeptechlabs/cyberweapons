/* 
 * if you want to make RSAREF faster this is often a good place to
 * do it. In particular a bit of assembler for the platform of your choice
 * would be very helpful. 
 * this file defines the macro umul_ppmm(hp,lp,m1,m2) which multiplies
 *  two NN_DIGIT_BITS size unsigned integers m1 and m2, and places the
 *  high part of the product in hp, and the low part in lp.
 * 
 * this file is NOT part of the original RSAREF distribution. It is an
 * attempt to collect many of the platform specific optimisations in one
 * place 
 */

#ifdef __GNUC__

#if defined(sparc) || defined(_IBMR2)
/* use faster multiplication routines provided by GNU C 
   need gcc 2.x for this. IBMR2 is RS6000 */
#define umul_ppmm(hp,lp,m1,m2) \
	{ \
		union { \
			unsigned long long x64; \
			unsigned long x32[2]; \
		} aaxx; \
		aaxx.x64 = (unsigned long long) (m1) * (unsigned long long) (m2); \
		hp = aaxx.x32[0]; lp = aaxx.x32[1]; \
	}
		
#endif
/* sparc || _IBMR2 */

#if defined(vax)
/* untested -- who still has one? This will work for i386, but see below */
#define umul_ppmm(hp,lp,m1,m2) \
	{ \
		union { \
			unsigned long long x64; \
			unsigned long x32[2]; \
		} aaxx; \
		aaxx.x64 = (unsigned long long) (m1) * (unsigned long long) (m2); \
		hp = aaxx.x32[1]; lp = aaxx.x32[0]; \
	}
#endif
/* vax */

#if defined(__i386__) || defined(__i486__)
/* We don't really make use of this */
#define umul_ppmm(hp,lp,m1,m2) \
	asm("movl %2, %%eax; mull %3; movl %%eax, %0; movl %%edx, %1" \
	:"=g" (lp), "=g" (hp) : "g" (m1), "g" (m2) : "eax", "edx")
#endif
/* i386 || i486 */

#endif
/* __GNUC__ */

/* 
 * just inline the usual approach if it hasn't been defined above. On
 * some platform/compiler combinations just forcing the compiler to inline
 * this gives a performance improvement.
 */

#ifndef umul_ppmm
#define umul_ppmm(hp,lp,m1,m2) \
{ \
  NN_DIGIT t, u; \
  NN_HALF_DIGIT bHigh, bLow, cHigh, cLow; \
  bHigh = HIGH_HALF (m1); \
  bLow = LOW_HALF (m1); \
  cHigh = HIGH_HALF (m2); \
  cLow = LOW_HALF (m2); \
  lp = (NN_DIGIT)bLow * (NN_DIGIT)cLow; \
  t = (NN_DIGIT)bLow * (NN_DIGIT)cHigh; \
  u = (NN_DIGIT)bHigh * (NN_DIGIT)cLow; \
  hp = (NN_DIGIT)bHigh * (NN_DIGIT)cHigh; \
  if ((t += u) < u) \
    hp += TO_HIGH_HALF (1); \
  u = TO_HIGH_HALF (t); \
  if ((lp += u) < u) \
    hp++; \
  hp += HIGH_HALF (t); \
} 
#endif
/* ifndef umul_ppmm */
