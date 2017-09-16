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
 *  Modular exponentiation using Montgomery reduction and
 *  Addition chaining.
 *  coded by Jack Lacy 11/91.
 *  Copyright (c) 1991 AT&T Bell Laboratories
 */
#include "libcrypt.h"

typedef struct {
#ifdef DLLEXPORT
	HGLOBAL mshandle;
#endif
	BigInt N;
	BigInt R2modN;
	Ulong n0p;
} Mont_set;

/* Struct for Montgomery reduction REDC */

/* Generally no reason to play with this stuff, used exclusively within bigPow */
static Ulong modInverse P((Ulong));
static Mont_set * mont_set P((BigInt));
static BigInt res_form P((BigInt big, Mont_set *ms));
static void freeMs P((Mont_set *));
static void REDC P((BigInt, Mont_set *, BigInt));

static Table *buildAddChainTable P((BigInt,  Mont_set *));
static void print_table P((Table *));
static void bigpow P((BigInt, BigInt, BigInt, BigInt));
static void bigpow2 P((BigInt, BigInt, BigInt, BigInt));
static void bigpow_crt P((BigInt, BigInt, BigInt, BigInt, BigInt));
static void bigmod2 P((BigInt, BigInt));
static Table *buildCoeffTable P((BigInt, Mont_set *, Table *));

extern int bigNumsAllocated;

#ifdef K_AND_R
static Ulong
modInverse(x)
  Ulong x;
#else
static Ulong modInverse(Ulong x)
#endif
{
	register int i;
	Ulong y[UlongBits+1], od, d, xx;
	
	y[1] = 1;
	od = 2;
	for (i=2; i<UlongBits+1; i++) {
		d = od << 1;
		xx = x * y[i-1];
		if (d)
			xx %= d;
		if (xx < od)
			y[i] = y[i-1];
		else
			y[i] = y[i-1] + od;
		od = d;
	}
	
	return y[UlongBits]*UlongMask;
}

#ifdef K_AND_R
static Mont_set *
mont_set(N)
  BigInt N;
#else
static Mont_set * mont_set(BigInt N)
#endif
{
	Mont_set *ms;
	int shiftbits;
	BigInt R2 = bigInit(1);
#ifdef DLLEXPORT
	HGLOBAL mshandle;
	mshandle = clib_malloc(sizeof(Mont_set));
	ms = (Mont_set *)GlobalLock(mshandle);
	ms->mshandle = mshandle;
#else
	ms = (Mont_set *) clib_malloc(sizeof(Mont_set));
#endif
	ms->N = N;
	ms->n0p = modInverse(NUM(N)[0]);
	shiftbits = 32*LENGTH(N);
	bigLeftShift(R2, shiftbits, R2);
	bigLeftShift(R2, shiftbits, R2);
	bigMod(R2, N, R2);
	ms->R2modN = R2;

	return ms;
}

/* Convert a to a*R mod N or
   REDC((a mod N)(R^2 mod N), ms)
 */

#ifdef K_AND_R
static BigInt
res_form(a, ms)
  BigInt a;
  Mont_set *ms;
#else
static BigInt res_form(BigInt a, Mont_set *ms)
#endif
{
	BigInt r;

	r = bigInit(0);
	bigMultiply(a, ms->R2modN, r);
	REDC(r, ms, r);

	return r;

}

/* Special form of redc which reduces arg 1 in place.
   Convert T to T*R^(-1) mod N. See coremult.c.
   */

#ifdef K_AND_R
static void
REDC(T, ms, result)
  BigInt T;
  Mont_set *ms;
  BigInt result;
#else
static void REDC(BigInt T,
		 Mont_set *ms,
		 BigInt result)
#endif
{
	register Ulong n0p, m;
	register BigInt N, t;
	register BigData tp;
	register int i, n;
	int shiftbits;
	
	t = T;
	N = ms->N;
	n0p = ms->n0p;
	
	/* Main loop */
	
	n = (int)LENGTH(N);
	for (i=0; i < n; i++) {
		tp = NUM(t);
		m = tp[i] * n0p;
		Ulong_bigmult(N, m, t, i);
	}
	
	/* divide by R */
	shiftbits = (int)(n * sizeof(Ulong) * CHARBITS);
	bigRightShift(t, shiftbits, result);
	
	if (bigCompare(result, N) > 0)
		bigSubtract(result, N, result);
	
	trim(result);
}

#ifdef K_AND_R
static Table *buildAddChainTable(a, ms)
  BigInt a;
  Mont_set *ms;
#else
static Table *buildAddChainTable(BigInt a,
				 Mont_set *ms)
#endif
{
	register int i;
	Table *tp;
#ifdef DLLEXPORT
	HGLOBAL tphandle;
#endif
	BigInt x, one;
	
#ifdef DLLEXPORT
	tphandle = clib_malloc(sizeof(Table) + sizeof(BigInt)*(16 - 2));
	tp = (Table *)GlobalLock(tphandle);
	tp->tphandle = tphandle;
#else
	tp = (Table *)clib_malloc(sizeof(Table) + sizeof(BigInt)*(16 - 2));
#endif
	tp->length = 16;

	one = bigInit(1);
	tp->t[0] = res_form(one, ms); /* x^0 */
	freeBignum(one);

	x = res_form(a, ms);
	tp->t[1] = bigInit(0);        /* x^1 */
	bigCopy(x, tp->t[1]);

	for (i = 2; i < 16; i++) {        /* x^[2-15] */
		tp->t[i] = bigInit(0);
		bigMultiply(x, tp->t[i-1], tp->t[i]);
		REDC(tp->t[i], ms, tp->t[i]);

	}
	freeBignum(x);
	return tp;
}


#ifdef K_AND_R
static Table *
buildAddChainTable2(a, m)
  BigInt a, m;
#else
  static Table *buildAddChainTable2(BigInt a,
				    BigInt m)
#endif
{
	register int i;
	Table *tp;
#ifdef DLLEXPORT
	HGLOBAL tphandle;
#endif
	
#ifdef DLLEXPORT
	tphandle = clib_malloc(sizeof(Table) + sizeof(BigInt)*(16 - 2));
	tp = (Table *)GlobalLock(tphandle);
	tp->tphandle = tphandle;
#else
	tp = (Table *)clib_malloc(sizeof(Table) + sizeof(BigInt)*(16 - 2));
#endif
	
	tp->length = 16;
	tp->t[0] = bigInit(1);        /* x^0 */
	tp->t[1] = bigInit(0);        /* x^1 */
	bigCopy(a, tp->t[1]);
	for (i = 2; i < 16; i++) {        /* x^[2-15] */
		tp->t[i] = bigInit(0);
		bigMultiply(a, tp->t[i-1], tp->t[i]);
		bigmod2(tp->t[i], m);
	}
	
	return tp;
}


#ifdef K_AND_R
static void
print_table(t)
  Table *t;
#else
  static void print_table(Table *t)
#endif
{
	int i;
	
	for (i = 0; (unsigned)i < t->length; i++) {
		printf("t[%d] = ",i); bigprint(t->t[i]);
	}
}

#ifdef K_AND_R
_TYPE( void )
freeTable(t)
  Table *t;
#else
_TYPE( void ) freeTable(Table *t)
#endif
{
	register int i;
	
	for (i = 0; i < (int)t->length; i++) {
		freeBignum(t->t[i]);
	}
#ifdef DLLEXPORT
	GlobalUnlock(t->tphandle);
	GlobalFree(t->tphandle);
#else
	free((char *)t);
#endif
}

#ifdef K_AND_R
static void freeMs(ms)
  Mont_set *ms;
#else
static void freeMs(Mont_set *ms)
#endif
{
	freeBignum(ms->R2modN);
#ifdef DLLEXPORT
	GlobalUnlock(ms->mshandle);
	GlobalFree(ms->mshandle);
#else
	free((char *)ms);
#endif
}

#define NIBBLE(B,N) (((NUM(B)[(N) >> 3] >> (((N) & 7) << 2)) & 15))
#define NIBSPERCHUNK 8

#ifdef K_AND_R
static void
bigpow(a, exp, modulus, result)
  BigInt a, exp, modulus, result;
#else
  static void bigpow(BigInt a,
		     BigInt exp,
		     BigInt modulus,
		     BigInt result)
#endif
{
	Table *at;
	BigInt d;
	Mont_set *ms;
	register int i, nib;
	
	ms = mont_set(modulus);
	at = buildAddChainTable(a, ms);
	
	for (i = (int)(NIBSPERCHUNK*LENGTH(exp) - 1); i >= 0; --i)
		if (NIBBLE(exp, i))
			break;

        d = bigInit(0);
	bigCopy(at->t[0], result);
	for (;; i--) {
		nib = (int)(NIBBLE(exp, i));
		/* Always do multiply even if nib = 0
		 * to avoid timing attack.
		 */
		bigMultiply(at->t[nib], result, d);
		REDC(d, ms, result);

		if (i == 0)
			break;
		
		bigMultiply(result, result, d);
		REDC(d, ms, result);

		bigMultiply(result, result, d);
		REDC(d, ms, result);

		bigMultiply(result, result, d);
		REDC(d, ms, result);

		bigMultiply(result, result, d);
		REDC(d, ms, result);
	}
	REDC(result, ms, result);

	freeBignum(d);
	freeTable(at);
	freeMs(ms);
}


#ifdef K_AND_R
static void
bigpow2(a, exp, modulus, result)
  BigInt a, exp, modulus, result;
#else
  static void bigpow2(BigInt a,
		      BigInt exp,
		      BigInt modulus,
		      BigInt result)
#endif
{
	Table *at;
	BigInt d;
	register int i, nib;
	
	if (ZERO(a)) {
		reset_big(result, (Ulong)0);
		return;
	}
	else if (ZERO(exp)) {
		reset_big(result, (Ulong)1);
		return;
	}
	at = buildAddChainTable2(a, modulus);
	for (i = (int)(8*LENGTH(exp)-1); i >= 0; --i)
		if (NIBBLE(exp, i))
			break;
	
	d = bigInit(1);
	
	for (;; --i) {
		nib = (int)(NIBBLE(exp, i));
		if (nib) {
			bigMultiply(at->t[nib], d, result);
			bigmod2(result, modulus);
		}
		else
			bigCopy(d, result);
		
		if (i == 0)
			break;
		
		bigMultiply(result, result, d);
		bigmod2(d, modulus);
		
		bigMultiply(d, d, result);
		bigmod2(result, modulus);
		
		bigMultiply(result, result, d);
		bigmod2(d, modulus);
		
		bigMultiply(d, d, result);
		bigmod2(result, modulus);
		
		bigCopy(result, d);
	}
	freeBignum(d);
	freeTable(at);
	
}

#ifdef K_AND_R
static
void bigpow_crt(m, f1, f2, exp, result)
  BigInt m, f1, f2, exp, result;
#else
  static void bigpow_crt(BigInt m,
			 BigInt f1,
			 BigInt f2,
			 BigInt exp,
			 BigInt result)
#endif
{
	BigInt u1, u2, tmp, c12;
	
	u1 = bigInit(0);
	u2 = bigInit(0);
	tmp = bigInit(0);
	c12 = bigInit(0);
	
	/* We assume here that f1 is a power of 2 */
	
	bigCopy(m, u1);
	bigmod2(u1, f1);
	bigMod(m, f2, u2);
	
	bigpow2(u1, exp, f1, u1);
	bigpow(u2, exp, f2, u2);
	
	getInverse(f1, f2, c12);
	crtCombine(u1, u2, f1, f2, c12, result);
	
	if (SIGN(result) == NEG) {
		bigMultiply(f1, f2, tmp);
		negate(result, tmp, result);
	}
	
	freeBignum(u1);
	freeBignum(u2);
	freeBignum(tmp);
	freeBignum(c12);
}


#ifdef K_AND_R
_TYPE( void )
bigPow(m, exp, modulus, result)
  BigInt m, exp, modulus, result;
#else
_TYPE( void ) bigPow(BigInt m,
		     BigInt exp,
		     BigInt modulus,
		     BigInt result)
#endif
{
	BigInt f1, f2, newm;
	int k = 0;
	
	if (ZERO(m)) {
		reset_big(result, (Ulong)0);
		return;
	}
	else if (ZERO(exp)) {
		reset_big(result, (Ulong)1);
		return;
	}

	newm = bigInit(0);
	if (bigCompare(m, modulus) > 0)
		bigMod(m, modulus, newm);
	else
		bigCopy(m, newm);
	
	if (EVEN(modulus)) {
		f1 = bigInit(1);
		f2 = bigInit(0);
		bigCopy(modulus, f2);
		while (EVEN(f2)) {
			bigRightShift(f2, (int)1, f2);
			k++;
		}
		bigLeftShift(f1, k, f1);
		if (!ONE(f2)) {
			bigpow_crt(newm, f1, f2, exp, result);
		}
		else
			bigpow2(newm, exp, f1, result);
		freeBignum(f1);
		freeBignum(f2);
	}
	else {
		bigpow(newm, exp, modulus, result);
	}
	freeBignum(newm);
}


/* Modulus operation for m a power of 2 */
#ifdef K_AND_R
static void
bigmod2(a, m)
  BigInt a, m;
#else
  static void bigmod2(BigInt a,
		      BigInt m)
#endif
{
	Ulong mask;
	
	mask = NUM(m)[LENGTH(m)-1] - 1;
	LENGTH(a) = LENGTH(m);
	NUM(a)[LENGTH(a)-1] &= mask;
	
	while ((NUM(a)[LENGTH(a)-1] == 0) && LENGTH(a) > 1)
		LENGTH(a) -= 1;
}

#ifdef K_AND_R
_TYPE( Table * )
g16_bigpow(a, modulus, explength)
  BigInt a, modulus;
  int explength;
#else
_TYPE( Table * ) g16_bigpow(BigInt a,
			    BigInt modulus,
			    int explength)
#endif
{
	Table *g16_table;
	Mont_set *ms;
	register BigInt c, d;
	register int i;
	
#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(Table)+((unsigned)(sizeof(BigInt)*(explength-2))));
	g16_table = (Table *)GlobalLock(handle);
	g16_table->tphandle = handle;
#else
	g16_table = (Table *)clib_malloc(sizeof(Table)+((unsigned)(sizeof(BigInt)*(explength-2))));
#endif
	g16_table->length = (int)explength;
	for (i=0; i<explength; i++)
		g16_table->t[i] = bigInit(0);	
	
	ms = mont_set(modulus);
	c = res_form(a, ms);
	bigCopy(c, g16_table->t[0]);
	
	i = (int)explength-1;
	for (;; --i) {
		if (i == 0)
			break;
		d = g16_table->t[(int)explength-i];
		
		bigMultiply(c, c, d);
		REDC(d, ms, c);
		
		bigMultiply(c, c, d);
		REDC(d, ms, c);
		
		bigMultiply(c, c, d);
		REDC(d, ms, c);
		
		bigMultiply(c, c, d);
		REDC(d, ms, c);

		bigCopy(c, d); /* c is part of continuing calculation */
		
	}
	
	freeMs(ms);
	freeBignum(c);
	
	return g16_table;
}

#ifdef K_AND_R
static Table *
buildCoeffTable(exp, ms, g16_table)
  BigInt exp;
  Mont_set *ms;
  Table *g16_table;
#else
  static Table *buildCoeffTable(BigInt exp,
				Mont_set *ms,
				Table *g16_table)
#endif
{
	register BigInt tmp1, ms_one;
	BigInt one;
	Table *C;
	register int i, j;
	int numnibs;

#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(Table)+(sizeof(BigInt)*(16-2)));
	C = (Table *)GlobalLock(handle);
	C->tphandle = handle;
#else		
	C = (Table *)clib_malloc(sizeof(Table)+(sizeof(BigInt)*(16-2)));
#endif
	C->length = 16;
	C->t[0] = bigInit(1);
	
	tmp1 = bigInit(0);
	one = bigInit(1);
	ms_one = res_form(one, ms);
	freeBignum(one);
	
	numnibs = 8*LENGTH(exp);
	if (numnibs > (int)g16_table->length)
		handle_exception(CRITICAL, "buildCoeffTable: exponent too long.\n");

	for (j=1; j<16; j++) {
		C->t[j] = bigInit(0);
		bigCopy(ms_one, C->t[j]);
		
		for (i=numnibs-1; i>=0; i--) {
			if (NIBBLE(exp, i) == (unsigned)j) {
				bigMultiply(g16_table->t[i], C->t[j], tmp1);
				REDC(tmp1, ms, C->t[j]);
			}
		}
	}
	freeBignum(ms_one);
	freeBignum(tmp1);
	
	return C;
}


#ifdef K_AND_R
_TYPE( void )
brickell_bigpow(g16_table, exp, modulus, result)
  Table *g16_table;
  BigInt exp, modulus, result;
#else
_TYPE( void ) brickell_bigpow(Table *g16_table,
			      BigInt exp,
			      BigInt modulus,
			      BigInt result)
#endif
{
	Table *C;
	register BigInt d, tmp;
	Mont_set *ms;
	register int i;
	
	ms = mont_set(modulus);
	C = buildCoeffTable(exp, ms, g16_table);
	
	tmp = bigInit(0);
	d = bigInit(0);
	bigCopy(C->t[15], d);
	bigCopy(d, result);
	
	for (i=14; i>0; i--) {
		bigMultiply(C->t[i], d, tmp);
		REDC(tmp, ms, d);
		
		bigMultiply(result, d, tmp);
		REDC(tmp, ms, result);
	}
	REDC(result, ms, result);
	
	freeTable(C);
	freeMs(ms);
	freeBignum(d);
	freeBignum(tmp);
}

#ifdef K_AND_R
_TYPE( void )
bigCube(a, m, result)
  BigInt a, m, result;
#else
_TYPE( void ) bigCube(BigInt a,
		      BigInt m,
		      BigInt result)
#endif
{
	BigInt d;
	
	d = bigInit(0);
	bigMultiply(a, a, d);
	bigMod(d, m, d);
	bigMultiply(d, a, result);
	bigMod(result, m, result);
	
	freeBignum(d);
}


#ifdef K_AND_R
_TYPE( void )
double_bigPow(a1, a2, exp1, exp2, modulus, result)
  BigInt a1, a2, exp1, exp2, modulus, result;
#else
_TYPE( void ) double_bigPow(BigInt a1,
			    BigInt a2,
			    BigInt exp1,
			    BigInt exp2,
			    BigInt modulus,
			    BigInt result)
#endif
{
	Table *at1, *at2;
	BigInt d;
	Mont_set *ms;
	register int i, j, k, nib1, nib2;

	ms = mont_set(modulus);
	at1 = buildAddChainTable(a1, ms);
	at2 = buildAddChainTable(a2, ms);

	for (i = (int)(NIBSPERCHUNK*LENGTH(exp1) - 1); i >= 0; --i)
		if (NIBBLE(exp1, i))
			break;
	
	for (j = (int)(NIBSPERCHUNK*LENGTH(exp2) - 1); j >= 0; --j)
		if (NIBBLE(exp2, j))
			break;
	
	k = (i>=j)? i: j;
	d = bigInit(0);
	bigCopy(at1->t[0], result);

	for (;; --k) {
		nib1 = (k<=i)? (int)(NIBBLE(exp1, k)) : 0;
		nib2 = (k<=j)? (int)(NIBBLE(exp2, k)) : 0;

		if ((nib1 != 0) || (nib2 != 0)) {
			if (nib1) {
				bigMultiply(at1->t[nib1], result, d);
				REDC(d, ms, result);
			}
			if (nib2) {
				bigMultiply(at2->t[nib2], result, d);
				REDC(d, ms, result);
			}
		}
		if (k == 0)
			break;
		
		bigMultiply(result, result, d);
		REDC(d, ms, result);
		
		bigMultiply(result, result, d);
		REDC(d, ms, result);
		
		bigMultiply(result, result, d);
		REDC(d, ms, result);
		
		bigMultiply(result, result, d);
		REDC(d, ms, result);
		
	}
	REDC(result, ms, result);
	
	freeBignum(d);
	freeTable(at1);
	freeTable(at2);
	freeMs(ms);
}


#ifdef K_AND_R
static Table *
double_buildCoeffTable(exp1, exp2, ms, g16_table1, g16_table2)
  BigInt exp1, exp2;
  Mont_set *ms;
  Table *g16_table1, *g16_table2;
#else
  static Table *double_buildCoeffTable(BigInt exp1,
				       BigInt exp2,
				       Mont_set *ms,
				       Table *g16_table1,
				       Table *g16_table2)
#endif
{
	register BigInt tmp1, ms_one;
	BigInt one;
	Table *C;
	int i, j, k;
	int numnibs1, numnibs2, nib1, nib2;

#ifdef DLLEXPORT
	HGLOBAL handle = clib_malloc(sizeof(Table)+(sizeof(BigInt)*(16-2)));
	C = (Table *)GlobalLock(handle);
	C->tphandle = handle;
#else		
	C = (Table *)clib_malloc(sizeof(Table)+(sizeof(BigInt)*(16-2)));
#endif
	C->length = 16;
	C->t[0] = bigInit(1);
	
	tmp1 = bigInit(0);
	one = bigInit(1);
	ms_one = res_form(one, ms);
	freeBignum(one);
	
	numnibs1 = 8*LENGTH(exp1);
	numnibs2 = 8*LENGTH(exp2);

	if (numnibs1 > (int)g16_table1->length)
		handle_exception(CRITICAL, "buildCoeffTable: exponent1 too long.\n");

	if (numnibs2 > (int)g16_table2->length)
		handle_exception(CRITICAL, "buildCoeffTable: exponent2 too long.\n");

	k = (numnibs1 >= numnibs2)? numnibs1: numnibs2;
	for (j=1; j<16; j++) {
		C->t[j] = bigInit(0);
		bigCopy(ms_one, C->t[j]);
		for (i=k-1; i>=0; i--) {
			nib1 = (i<numnibs1)? (int)NIBBLE(exp1, i): 0;
			nib2 = (i<numnibs2)? (int)NIBBLE(exp2, i): 0;
			if (nib1 == j) {
				bigMultiply(g16_table1->t[i], C->t[j], tmp1);
				REDC(tmp1, ms, C->t[j]);
			}
			if (nib2 == j) {
				bigMultiply(g16_table2->t[i], C->t[j], tmp1);
				REDC(tmp1, ms, C->t[j]);
			}
		}
	}
	freeBignum(ms_one);
	freeBignum(tmp1);
	
	return C;
}


#ifdef K_AND_R
_TYPE( void )
double_brickell_bigpow(g16_table1, g16_table2, exp1, exp2, modulus, result)
  Table *g16_table1, *g16_table2;
  BigInt exp1, exp2, modulus, result;
#else
_TYPE( void ) double_brickell_bigpow(Table *g16_table1,
				     Table *g16_table2,
				     BigInt exp1,
				     BigInt exp2,
				     BigInt modulus,
				     BigInt result)
#endif
{
	Table *C;
	register BigInt d, tmp;
	Mont_set *ms;
	register int i;
	
	ms = mont_set(modulus);
	C = double_buildCoeffTable(exp1, exp2, ms, g16_table1, g16_table2);
	
	tmp = bigInit(0);
	d = bigInit(0);
	bigCopy(C->t[15], d);
	bigCopy(d, result);
	
	for (i=14; i>0; i--) {
		bigMultiply(C->t[i], d, tmp);
		REDC(tmp, ms, d);

		bigMultiply(result, d, tmp);
		REDC(tmp, ms, result);
	}
	REDC(result, ms, result);
	
	freeTable(C);
	freeMs(ms);
	freeBignum(d);
	freeBignum(tmp);
}

