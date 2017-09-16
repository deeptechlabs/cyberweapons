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
#ifndef LIBCRYPT_H
#define LIBCRYPT_H


#include <stdio.h>	

/*	#include "ansi.h"	*/
/*	prototyping macro	*/
#undef P
#ifdef K_AND_R
#	define P(a)	()
#else
#	define P(a)	a
#endif
/************************************************************************/

/*	For building dynamic link libraries under windows, windows NT 
 *	using MSVC1.5 or MSVC2.0
 */

#ifdef MSVC15	/* MSVC1.5 support for 16 bit apps */
#define _MSVC15EXPORT _export
#define _MSVC20EXPORT
#define _DLLAPI _export _pascal
#define _TYPE(a) a _MSVC15EXPORT
#define DLLEXPORT 1

#elif MSVC20
#define _MSVC15EXPORT
#define _MSVC20EXPORT _declspec(dllexport)
#define _DLLAPI
#define _TYPE(a) _MSVC20EXPORT a
#define DLLEXPORT 1

#else			/* Default, non-dll.  Use this for Unix or DOS */
#define _MSVC15DEXPORT
#define _MSVC20EXPORT
#define _DLLAPI
#define _TYPE(a) a
#endif

/************************************************************************/


/*	#include "memalloc.h"	*/
/*	If windows or windows NT, use HGLOBAL type memalloc. 		*/

#ifdef DLLEXPORT
#include <windows.h>
_TYPE( HGLOBAL ) clib_malloc(int);
_TYPE( HGLOBAL ) clib_realloc(HGLOBAL, int);
_TYPE( void ) clib_free(HGLOBAL);
#else
_TYPE( long * ) clib_malloc P((int));
_TYPE( long * ) clib_realloc P((unsigned char *oldsrc, int len));
_TYPE( void ) clib_free P((unsigned char *));
#endif
_TYPE( void ) clib_memcpy P((unsigned char *src, unsigned char *dst, int length));
_TYPE( int ) clib_memcmp P((unsigned char *src, unsigned char *dst, int length));
_TYPE( void ) clib_memzero P((unsigned char *src, int len));
/************************************************************************/


/*	#include "bignum.h"	*/

/* The default radix length is 32 bits so that a bignum contains an array of
 * unsigned longs.
 */
typedef unsigned long Ulong;
typedef unsigned short Ushort;
typedef Ulong NumType;
#define UlongBits 32
#define UlongMask (unsigned long)0xFFFFFFFF
typedef long SignedUlong;
typedef Ulong * BigData;

typedef int Boolean;
#define TRUE 1
#define FALSE 0

typedef int Sign;
#define POS 1
#define NEG -1

/* Fundamental bigmath unit */
typedef struct Bignum {
    Sign sign;
    int length; /* length of number (in Ulong units)	*/
    int space; /* storage space (in Ulong units)	*/
#ifdef DLLEXPORT
	HGLOBAL bighandle;
    HGLOBAL numhandle;
#endif
    Ulong *num;
} Bignum;

typedef Bignum * BigInt;
#define NUM(x) ((x)->num)
#define LENGTH(x) ((x)->length)
#define SIGN(x) ((x)->sign)
#define SPACE(x) ((x)->space)

/* GUARANTEE is the principal macro for bigint memory allocation.
 * Space is updated by this macro.  If a bigint shrinks (say as the result
 * of a modular reduction, space need not be freed.  The length will be reduced.
 * If later the reduced number is square (say) then we don't need to realloc the
 * memory.  Look at bigmath.c to get a feel for how this is used.
 */

#ifdef DLLEXPORT

#define NHNDLE(x) ((x)->numhandle)
#define BHNDLE(x) ((x)->bighandle)
#define GUARANTEE(B,S) { \
  if(SPACE(B) < (S)) { \
	 SPACE(B) = (S); \
	 NHNDLE(B) = clib_realloc(NHNDLE(B), (sizeof(Ulong)*(S))); \
	 NUM(B) = (Ulong *)GlobalLock(NHNDLE(B)); \
  } \
}

#else

#define GUARANTEE(B,S) { \
  if((B)->space < (S)) { \
	(B)->space = (S); \
	(B)->num = (BigData)clib_realloc((unsigned char *)NUM(B), (unsigned)(sizeof(Ulong)*SPACE(B))); \
  } \
}

#endif


#define LENGTH_IN_BYTES(N) (((N + (UlongBits-1) / UlongBits) * sizeof(Ulong))
#define EVEN(a) (((NUM(a)[0] & 1) == 0) ? TRUE : FALSE)
#define ODD(a) (((NUM(a)[0] & 1) != 0) ? TRUE : FALSE)
#define CHARBITS 8
/* Some useful predicates. */
#define ZERO(x) ((LENGTH(x) == 1) && (NUM(x)[0] == 0))
#define ONE(x) ((LENGTH(x) == 1) && (NUM(x)[0] == 1))
#define TWO(x) ((LENGTH(x) == 1) && (NUM(x)[0] == 2))

/* All bignums must be initialized by x = bigInit(a), where a is typically 0. */
#define bigInit(x) (itobig((Ulong)(x)))
_TYPE( BigInt ) itobig P((Ulong));

extern _TYPE( int ) bigNumsAllocated;

/* Convert an ascii hex represenation of a number to a BigInt:
 * bigx = atobig("abcd123ef");
 */
_TYPE( BigInt ) atobig P((char *));

/* zeros and frees bignums. */
_TYPE( void ) freeBignum P((BigInt));

/* return the number of bits or bytes in a BigInt */
_TYPE( int ) bigBits P((BigInt));
_TYPE( int ) bigBytes P((BigInt));

/* return the most significant bit position */
_TYPE( int ) msb P((Ulong));

_TYPE( Sign ) bigTest P((BigInt));
_TYPE( Boolean ) even P((BigInt));
_TYPE( Boolean ) odd P((BigInt));

/* Move bigs in and out of buffers.  Binary representation.
 * least significant byte in big -> least significant byte in buffer.
 */
_TYPE( void ) bufToBig P((unsigned char *buf,
			  int buflen,
			  BigInt big));

_TYPE( void ) bigToBuf P((BigInt big,
			  int bufsize,
			  unsigned char *buf));

/* RSAREF form: Move bigs in and out of buffers.  Binary representation.
 * most significant byte in big -> least significant byte in buffer.
 */
_TYPE( void ) RSA_bufToBig P((unsigned char *buf,
			      int buflen,
			      BigInt big));

_TYPE( void ) RSA_bigToBuf P((BigInt big,
			      int bufsize,
			      unsigned char *buf));

extern _TYPE( BigInt ) zero;
extern _TYPE( BigInt ) one;
extern _TYPE( BigInt ) two;
/************************************************************************/


/*	#include "ioutils.h"	*/
typedef int ExceptionType;
#define CRITICAL 1
#define WARNING 0

/* Printing functions: print bigs in hex form. */
_TYPE( void ) bigprint P((BigInt));
_TYPE( void ) fBigPrint P((BigInt, FILE *));
/* Fill a buffer with the hex representation of a BigInt. */
_TYPE( int ) bigsprint P((BigInt, unsigned char *buf));

/* All (known) errors go through this interface. */
_TYPE( void ) handle_exception P((ExceptionType type, char *exception_msg));

/************************************************************************/


/*	#include "bigmath.h"	*/
/* Basic big arithmetic */
/* BE AWARE: the result for multiplication cannot be the same pointer as
 * the multiplier or multiplicand.
 */
_TYPE( void ) bigAdd P((BigInt a, BigInt b, BigInt result));

/* no reason to use bigsub...bigSubtract does the right thing with signs */
void bigsub P((BigInt, BigInt, BigInt));
_TYPE( void ) bigSubtract P((BigInt a,  BigInt b, BigInt result));
_TYPE( void ) bigLeftShift P((BigInt a,	int numbits, BigInt result));
_TYPE( void ) bigRightShift P((BigInt a, int numbits, BigInt result));

/* reset a big to val. space stays constant, length is set to 1 and rest of number is zeroed. */
_TYPE( void ) reset_big P((BigInt a, Ulong val));

/* There's no reason to use either lbigmult or bigsquare as they are called from
 * bigMultiply.
 */
void lbigmult P((BigInt a, BigInt b, BigInt res));
void bigsquare P((BigInt a, BigInt res));

/* bigCompare returns 0 if the two numbers are the same, it returns
 * < 0 if the first number is less than the second and > 0 otherwise.
 */
_TYPE( int ) bigCompare P((BigInt a, BigInt b));
_TYPE( void ) bigMod P((BigInt a, BigInt modulus, BigInt result));
_TYPE( void ) bigDivide P((BigInt a, BigInt divisor, BigInt quotient, BigInt remainder));
_TYPE( void ) bigCopy P((BigInt src, BigInt dst));

/* bitwise boolean operations */
_TYPE( void ) bigAnd P((BigInt a, BigInt b, BigInt result));
_TYPE( void ) bigOr P((BigInt a, BigInt b, BigInt result));
_TYPE( void ) bigXor P((BigInt a, BigInt b, BigInt result));

/* return -a (mod modulus) */
_TYPE( void ) negate P((BigInt a, BigInt modulus, BigInt result));

/* Use Chinese Remainder Thm. to combine a and b corresponding to primes p and q
 * using C12 = inverse of p (mod q).
 */
_TYPE( void ) crtCombine P((BigInt a, BigInt b, BigInt p, BigInt q, BigInt c12, BigInt result));

/* trim leading (most sig) zeros. */
_TYPE( void ) trim P((BigInt));

/************************************************************************/

/*	#include "prime.h"	*/

#define NIST 0		/* p = n*q + 1, q is prime */
#define GORDON 1	/* p is strong in the form discussed by Gordon */
typedef int PrimeType;

/* Set number of tries for Rabin-Miller, Default=5 */
_TYPE( void ) setPrimeTestAttempts P((int));

/* Rabin-Miller + pretest */
_TYPE( Boolean ) primeTest P((BigInt));

/* Returns number of random bytes needed if randomStart is not to be NULL.
 * qlen = 0 for type=GORDON.  Use this for each of the 2 following functions.
 */
_TYPE( int ) randBytesNeededForPrime P((int plen, int qlen, PrimeType type));

/* Not a strong prime -- lengths are in bits.
 * randomStart = NULL ==> use pseudo RNG seeded by truerand.
 * randomStart != NULL, randomStart should be number of bytes desired in p.
 */
_TYPE( void ) getPrime P((int plen, BigInt p, BigInt randomStart));

/* Generate a strong prime p and return subprime q as well
 * randomStart, if not NULL, should be number of bytes in p + number of
 * bytes in q (in each of the next 3 functions.
 */
_TYPE( void ) genStrongPrimeSet P((int plen, BigInt p, int qlen, BigInt q, PrimeType type, BigInt randomStart));

/* GORDON is default */
_TYPE( void ) genStrongPrime P((int plen, BigInt p, BigInt randomStart));

/* Return number of bytes needed for getPrimitiveElement if randomStart != NULL
 */
_TYPE( int ) randBytesNeededForRoot P((int plen));

/* Return primitive element mod p.  q is a factor of p-1 */
_TYPE( void ) getPrimitiveElement P((BigInt el, BigInt p, BigInt q, BigInt randomStart));

/************************************************************************/



/*	#include "fastmult.h"	*/
/* if a == b, squaring optimization is used */
_TYPE( void ) bigMultiply P((BigInt a, BigInt b, BigInt result));

/************************************************************************/


/*	#include "bigpow.h"	*/

typedef struct {
#ifdef DLLEXPORT
	HGLOBAL tphandle;
#endif
	unsigned length;
	BigInt t[2];
} Table;

/* Modular exponentiation a^b mod c (assumes a < c). */
_TYPE( void ) bigPow P((BigInt a, BigInt exponent, BigInt modulus, BigInt result));
_TYPE( void ) double_bigPow P((BigInt a, BigInt b, BigInt exp1, BigInt exp2, BigInt modulus, BigInt result));

/* Modular cube a^3 mod c */
_TYPE( void ) bigCube P((BigInt a, BigInt modulus, BigInt result));

/* When doing a^b mod c for a constant a and c, a table can be created using the following
 * function.  This is useful in El Gamal variants where the base (a) and the modulus are
 * constant in groupd of keys.  This is true of DSA (an El Gamal variant) as well.
 * exp_length = LENGTH(exp)*8  (number of 4 bit nibbles in exponent).  This is also the length
 * of tables created for this purpose.
 */
_TYPE( Table * ) g16_bigpow P((BigInt a, BigInt modulus,
			       int length_of_exponent_in_4_bit_nibbles));

/* bigpow using table: Ernie Brickell's method. */
_TYPE( void ) brickell_bigpow P((Table *table, BigInt exponent,
				 BigInt modulus, BigInt result));

_TYPE( void ) double_brickell_bigpow P((Table *tab1, Table *tab2,
					BigInt exp1, BigInt exp2,
					BigInt modulus, BigInt result));

_TYPE( void ) freeTable P((Table *));

/************************************************************************/


/*	#include "longmult.h"	*/
/* Not part of the cryptoLib interface - low level multiplication routines.
 * Best if these are implemented in assembly.
 */
Ulong LMULT P((Ulong *result, Ulong multiplier, Ulong *multiplicand, int length));
void BUILDDIAG P((Ulong *result, Ulong *src, int length));
void SQUAREINNERLOOP P((Ulong *result, Ulong multiplier,
			Ulong *multiplicand, int start, int finish));
/************************************************************************/


/*	#include "coremult.h"	*/
/* Not part of the cryptoLib interface - low level multiplication routines. */
void Ulong_bigmultN P((Ulong *, Ulong *, Ulong *, int));
void Ulong_bigsquareN P((Ulong *, Ulong *, int));
void bigmultN P((BigData, BigData, BigData, int));
void bigsquareN P((BigData, BigData, int));
void Ulong_bigmult P((BigInt, Ulong, BigInt, int));
/************************************************************************/


/*	#include "euclid.h"	*/
/* Euclid's extended gcd algorithm for solving
 * ax + by = gcd(a, b)
 * Always returns x and y > 0.
 */
_TYPE( void ) extendedGcd P((BigInt a, BigInt b, BigInt x, BigInt y, BigInt gcd));

/* If gcd(a, b) = 1, x = inverse of a (mod b) and y = inverse of b (mod a) */
_TYPE( void ) getInverse P((BigInt a, BigInt b, BigInt inverse_of_a_mod_b ));
_TYPE( BigInt ) gcd P((BigInt a, BigInt b));
/************************************************************************/


/*	#include "truerand.h"	*/
/* Don Mitchell's random number generator based on randomness in clock skew and
 * interrupt arrival times in Unix or Windows NT or 95.
 * To use be sure TRUERAND is defined at compile time for truerand.c and getrand.c.
 * When using MSVC* define NT_TRUERAND.  truerand() won't work under non-preemptive
 * operating systems (DOS, Windows). rand() is used instead.  Beware, rand() is not
 * cyptographically secure.  Also, read the disclaimers at the beginning of the
 * truerand code (unix_truerand.c and nt_truerand.c.
 */
_TYPE( unsigned long ) truerand();
/************************************************************************/
/*	quantization		*/
/* This should be set to whatever the variance in operations with
 * private keys is likely to be.  This value is used in quantized versions
 * of RSASign, RSADecrypt, EGSign, EGDecrypt and DSASign.
 */
#define STD_QUANTUM 50
_TYPE ( int )start_quantize P((int millesecs));
_TYPE ( int )end_quantize();
_TYPE ( int )min_quantum();
/************************************************************************/



/*	#include "fsr_rand.h"	*/
/* Nonlinear feedback shift register pseudorandom number generator based on DES. */
/* Can be seeded with seed_fsr(unsigned char *seed) or (by default) with truerand() */

_TYPE( void ) seed_fsr P((unsigned char *seed, int seedlen));
_TYPE( unsigned long ) fsrRandom P ((void));
/************************************************************************/


/*	#include "desrand.h"	*/
/* 3des in counter mode with random key, output xor'ed with sha of random
 * prefix, suffix and counter
/* Can be seeded with seedDesRandom(unsigned char *seed, int seedlen) with 64 bytes of seed
 * or (by default) with truerand() */

_TYPE( void ) seedDesRandom P((unsigned char *seed, int seedlen));
_TYPE( unsigned long ) desRandom P ((void));
/************************************************************************/


/*	#include "getrand.h"	*/
/* By default, REALLY ==> truerand() and PSEUDO ==> fsrRandom() */
#define REALLY 1
#define PSEUDO 0
typedef int RandType; /* REALLY or PSEUDO */

_TYPE( void ) bigRand P((int numbytes, BigInt big, RandType type));
_TYPE( int ) randomBytes P((unsigned char *buffer, int numbytes, RandType type));

/* Get a uniformly random number between a and b */
_TYPE( void ) getRandBetween P((BigInt a, BigInt b, BigInt result, RandType type, BigInt randomStart));

/* randomize a random BigInt (for use in primes.c currently) */
_TYPE( void ) randomize P((BigInt r));
#define seed_rng seedDesRandom

/************************************************************************/

/*	#include "jacobi.h"	*/
/* calculate the jacobi symbol (a/b) */
_TYPE( int ) bigJacobi P((BigInt a, BigInt b));
_TYPE( int ) jacobi P((int a, int b));

/* Return true if a is a quadratic residue mod p*q where p and q are prime. 
 * bigIsQR is much faster than compositeQuadResidue below; makes use of bigJacobi.
 */
_TYPE( int ) bigIsQR P((BigInt a, BigInt p, BigInt q));
_TYPE( int ) isQR P((int a, int p, int q));
/************************************************************************/
/*	#include "newton.h"	*/
/* Determine whether a BigInt has trivial roots.  Useful for determining
 * whether an RSA modulus is not of the form p^n, where p is a prime and
 * n an integer.
 */

_TYPE( Boolean ) modulus_OK P((BigInt));
_TYPE( Boolean ) hasPthRoot P((BigInt c, int p));

/************************************************************************/

/*	#include "quadres.h"	*/
/* Return true if a is a quadratic residue mod p */
_TYPE( Boolean ) quadResidue P((BigInt a, BigInt p));

/* Return true if a is a quadratic residue mod p*q where p and q are prime. */
_TYPE( Boolean ) compositeQuadResidue P((BigInt a, BigInt p, BigInt q));

/* return the square root of a (mod p) where p is prime. */
_TYPE( void ) squareRoot P((BigInt a, BigInt p, BigInt result));

/* return the 2 linearly independent square roots of a (mod p*q) for p and q prime. */
/* c12 is the inverse of p (mod q) for use in CRT reconstruction. */
/* The other 2 roots are n-root1 and n-root2 */
_TYPE( void ) compositeSquareRoot P((BigInt a, BigInt p,
				     BigInt q, BigInt c12,
				     BigInt root1, BigInt root2));
/************************************************************************/

/*	#include "rabin.h"	*/

/* Rabin's scheme is essentially RSA with 2 as the public exponent.  Care has been
 * taken to avoid the small exponent attack (See Simmons' Contemporary Cryptology).
 * Encryption, Decryption, Signature and Verification work exactly as with RSA.
 * However, since squaring is the encryption process, to decrypt the square root is taken.
 * This yields 4 square roots.  Thus some way to detect which if these is correct is
 * needed.  The message to be encrypted is thus given "structure". From most-sig-byte to least,
 * the format is: [random pad | message | msg_len (4 bytes) | digest (pad | msg | msg_len) ]
 * The digest functions supported are SHS, MD{2, 4, 5}.  The functions below take as arguments
 * the digest type and digest length in bytes.
 */
typedef struct {
	BigInt p, q, c12;
	BigInt modulus;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinPrivateKey;

typedef struct {
	BigInt modulus;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinPublicKey;

typedef struct {
	RabinPublicKey *publicKey;
	RabinPrivateKey *privateKey;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} RabinKeySet;

typedef Bignum RabinSignature;

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForRabinSet P((int modbits));

/* If randomStart is not NULL is should contain the number of bytes required
 * for the modulus.
 */
_TYPE( RabinKeySet *) genRabinKeySet P((int modbits, BigInt randomStart));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForRabinEncrypt P((int modbits));

/* randomStart, if not NULL should contain the number of bytes in the modulus.
 * This is true for both encrypting and signing.
 */
_TYPE( BigInt ) RabinEncrypt P((BigInt message,
				RabinPublicKey *pubkey,
				int digestType,
				int digestLen,
				BigInt randomStart));

_TYPE( BigInt ) RabinDecrypt P((BigInt enc_message,
				RabinPrivateKey *privkey,
				int digestType,
				int digestLen));

/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( BigInt ) quantized_RabinDecrypt P((BigInt enc_message,
					  RabinPrivateKey *privkey,
					  int digestType,
					  int digestLen));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForRabinSign P((int modbits));

_TYPE( RabinSignature * ) RabinSign P((BigInt message,
				       RabinPrivateKey *privkey,
				       int digestType,
				       int digestLen,
				       BigInt randomStart));

/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( RabinSignature * ) quantized_RabinSign P((BigInt message,
						 RabinPrivateKey *privkey,
						 int digestType,
						 int digestLen,
						 BigInt randomStart));

_TYPE( Boolean ) RabinVerify P((BigInt message,
				RabinSignature *sig,
				RabinPublicKey *pubkey,
				int digestType,
				int digestLen));

_TYPE( void ) freeRabinPublicKey P((RabinPublicKey *key));
_TYPE( void ) freeRabinPrivateKey P((RabinPrivateKey *key));
_TYPE( void ) freeRabinKeySet P((RabinKeySet *ks));
_TYPE( void ) freeRabinSignature P((RabinSignature *sig));


/************************************************************************/

/*	#include "des.h"	*/
/* Fundamental DES block_cipher function.  block_cipher assumes a 128 byte expanded key
 * created from the des 64 bit key by key_setup.  decrypting = 0 for encryption and 1 for
 * decryption.  Input blocks are assumed to be 64 bits.
 */
_TYPE( void ) key_setup P((unsigned char key[8], unsigned char expanded_key[128]));
_TYPE( void ) block_cipher P((unsigned char longkey[128], unsigned char text[8],
			      int decrypting));

/* triple_des block_cpiher, takes 3 keys.  Most common form is for key 0 = key 2. */
_TYPE( void ) triple_block_cipher P((unsigned char keys[3][128],
				     unsigned char text[8],
				     int decrypting));
/************************************************************************/


/*	#include "desmodes.h"	*/

#define ECB 10
#define CBC 20
#define OFM 30
#define ECB3 13
#define CBC3 23
#define OFM3 33

typedef int ModeType;

typedef struct {
	ModeType mode;
	unsigned char icv[8];
	unsigned char int_key[128];
	int count;
	Ulong setup;	/* Set to 0xdeadbeef when setupDESState is done */
} DESState;

typedef struct {
	ModeType mode;
	unsigned char icv[8];
	unsigned char int_key[3][128];
	int count;
	Ulong setup;	/* Set to 0xdeadbeef when setupTripleDESState is done */
} TripleDESState;

/* Initialize new DES state.  If the mode is other than ECB, an icv is sent, otherwise
 * icv = NULL.
 */
_TYPE( void ) setupDESState P((DESState *s, unsigned char *key,
			       unsigned char *icv, ModeType mode));

/* Initialize new Triple DES state.  If the mode is other than ECB, an icv is sent, otherwise
 * icv = NULL.
 */
_TYPE( void ) setupTripleDESState P((TripleDESState *s, unsigned char *key[3],
				     unsigned char *icv, ModeType mode));

/* key_crunch crunches a buffer into a 64 bit des key */
_TYPE( void ) key_crunch P((unsigned char buffer[], int buflen, unsigned char key[8]));

/* block [en/de]cryption modes */
_TYPE( void ) blockEncrypt P((unsigned char block[8], DESState *state));
_TYPE( void ) blockDecrypt P((unsigned char block[8], DESState *state));

/* buffer [en/de]cryption modes */
_TYPE( void ) bufferEncrypt  P((unsigned char *buf, int buf_len, DESState *state));
_TYPE( void ) bufferDecrypt  P((unsigned char *buf, int buf_len, DESState *state));

/* block triple [en/de]cryption modes */
_TYPE( void ) block3Encrypt P((unsigned char block[8], TripleDESState *state));
_TYPE( void ) block3Decrypt P((unsigned char block[8], TripleDESState *state));

/* buffer triple [en/de]cryption modes */
_TYPE( void ) buffer3Encrypt P((unsigned char *buf, int buf_len, TripleDESState *state));
_TYPE( void ) buffer3Decrypt P((unsigned char *buf, int buf_len, TripleDESState *state));

/* ECB bignum DES [en/de]cryption */
_TYPE( void ) bignumDesEncrypt P((BigInt, unsigned char key[8]));
_TYPE( void ) bignumDesDecrypt P((BigInt, unsigned char key[8]));

/* CBC bignum DES [en/de]cryption */
_TYPE( void ) bignumCBCDesEncrypt P((BigInt, unsigned char key[8]));
_TYPE( void ) bignumCBCDesDecrypt P((BigInt, unsigned char key[8]));

/*  Cipher feedback mode -- 8 or 64 bit with full expanded key - from key_setup() */
/*  These interfaces are likely to change soon. */

_TYPE( void ) blockEightBitCFMEncrypt P((unsigned char in[8], int len,
					 unsigned char sreg[8], unsigned char key[8]));
_TYPE( void ) blockEightBitCFMDecrypt P((unsigned char in[8], int len,
					 unsigned char sreg[8], unsigned char key[8]));
_TYPE( void ) blockSixtyFourBitCFMEncrypt P((unsigned char in[8], int len,
					     unsigned char sreg[8], unsigned char key[8]));
_TYPE( void ) blockSixtyFourBitCFMDecrypt P((unsigned char in[8], int len,
					     unsigned char sreg[8], unsigned char key[8]));
/************************************************************************/

/* El Gamal Crypto system stuff */
/* p is prime, q is a large prime factor of p-1.  alpha is the base
 * g_table is included as part of the key to enable Brickell exponentiation.
 * If one set {p, q, alpha} is used by "everyone" then this table can be constant.
 * That is, {p, q, alpha, g_table} is public.  The private key is then
 * the exponent (or secret) and the public key is alpha^exponent mod p.
 */
/*	#include "elgamal.h"	*/
typedef struct EGParams {
	BigInt p, q, alpha;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} EGParams;

typedef struct EGPrivateKey {
    BigInt p, q;
    BigInt alpha;
    BigInt publicKey;
    BigInt secret;
    Table *g_table;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} EGPrivateKey;

typedef struct EGPublicKey {
    BigInt p, q;
    BigInt alpha;
    BigInt publicKey;
    Table *g_table, *y_table;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} EGPublicKey;

typedef struct EGKeySet {
    EGPublicKey *publicKey;
    EGPrivateKey *privateKey;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} EGKeySet;

typedef struct EGSignature {
    BigInt r, s;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} EGSignature;

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForEGParams P((int pbits, int qbits));

/* generate global p, q, and alpha.
 * q is a large factor of p-1.
 * alpha is a primitive element mod p.
 * randomStart, if not NULL should contain p bytes + q bytes + alpha (p) bytes
 * or 2*p + q bytes.
 */
_TYPE( EGParams * ) genEGParams P((int pbits, int qbits, BigInt randomStart));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForEGKeySet P((int qbits));

/* generate public and private keys corresponding to params.
 * if a new parameter set is to be used per keyset, set params = NULL
 * and send pbits and qbits.
 * If params is NULL: randomStart (if not NULL) should contain q bytes
 * (for the secret exponent).  If params is not NULL add in what is needed
 * for params.
 */
_TYPE( EGKeySet * ) genEGKeySet P((EGParams *params, int pbits, int qbits, BigInt randomStart));

/* generate private key using seed to seed the random number generator before
 * choosing the random, secret exponent.
 */
_TYPE( EGPrivateKey * ) genEGPrivateKeyWithSeed P((EGParams *params, char *seed, int seedlen));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForEGSign P((int qbits));

/* El Gamal signature
 * randomStart (if not NULL) should contain q bytes (one time per message
 * secret exponent).
 */
_TYPE( EGSignature * ) EGSign P((BigInt big, EGPrivateKey *key, BigInt randomStart));

/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( EGSignature * ) quantized_EGSign P((BigInt big, EGPrivateKey *key, BigInt randomStart));

/* Verify signature of big */
_TYPE( Boolean ) EGVerify P((BigInt big, EGSignature *sig, EGPublicKey *key));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForEGEncrypt P((int qbits));

/* El Gamal encrypt and decrypt functions -- these are not reversible as in RSA 
 * That is, Decrypt(Encrypt(m, pubkey), privkey) is NOT the same as
 * Encrypt(Decrypt(m, privkey), pubkey).  This symmetry doesn't exist with
 * El Gamal.  randomStart (if not NULL) should contain q bytes
 * (one time per message secret exponent).
 */
_TYPE( BigInt ) EGEncrypt P((BigInt message, EGPublicKey *key, BigInt randomStart));
_TYPE( BigInt ) EGDecrypt P((BigInt enc_message, EGPrivateKey *key));
/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( BigInt ) quantized_EGDecrypt P((BigInt enc_message, EGPrivateKey *key));

/* El Gamal Cleanup functions -- be sure to use these! */
_TYPE( void ) freeEGPublicKey P((EGPublicKey *));
_TYPE( void ) freeEGPrivateKey P((EGPrivateKey *));
_TYPE( void ) freeEGKeys P((EGKeySet *));
_TYPE( void ) freeEGSig P((EGSignature *));
_TYPE( void ) freeEGParams P((EGParams *));
/************************************************************************/

/*	dh.h	*/
/* An implementation of Diffie-Hellman key exchange.
 * Generate a DiffieHellmanSet which contains a base, a prime p, a prime factor of p-1,
 * and a table for using Brickell's speedup for exponentiation.
 */
typedef struct {
	int qbits;
	BigInt alpha, p, q;
	Table *alphatab;
#ifdef DLLEXPORT
	HGLOBAL handle;
#endif
} DiffieHellmanSet;

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForDHSet P((int pbits, int qbits));

/* This Set must be agreed upon by the participants in the exchange.
 * randomStart, if not NULL should contain 2*bytes in p + bytes in q.
 */
_TYPE( DiffieHellmanSet * ) GenDiffieHellmanSet P((int pbits,
						   int qbits,
						   BigInt randomStart));

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForDHInit P((int qbits));

/* my_exponent should usually be initialized to 0 unless you want to use a prespecified value.
 * After this function call, my_exponent should be protected (say using BignumDESEncrypt())
 * and my_msg1 sent to the other party in the exchange.
 * randomStart if not NULL should contain bigBytes(myDHset->q) bytes.
 */
_TYPE( void ) DiffieHellmanInit P((DiffieHellmanSet *myDHset,
				   BigInt my_exponent,
				   BigInt my_msg1,
				   BigInt randomStart));

/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( void ) quantized_DiffieHellmanInit P((DiffieHellmanSet *myDHset,
					     BigInt my_exponent,
					     BigInt my_msg1,
					     BigInt randomStart));

/* After receiving the other party's message, recd_msg1, uncover your exponent and proceed.
 * DH_key will contain the full pbits worth of Diffie Hellman key material for you to process
 * as necessary.
 */
_TYPE( void ) DiffieHellmanGenKey P((DiffieHellmanSet *myDHset,
				     BigInt recd_msg1,
				     BigInt my_exponent,
				     BigInt DH_key));

/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( void ) quantized_DiffieHellmanGenKey P((DiffieHellmanSet *myDHset,
					       BigInt recd_msg1,
					       BigInt my_exponent,
					       BigInt DH_key));

_TYPE( void ) freeDiffieHellmanSet P((DiffieHellmanSet *DHset));


/************************************************************************/
/* The digital signature standard doesn't introduce new structures...we reuse the
 * El Gamal structs and parameter generation stuff.
 */
/*	#include "DSA.h"	*/
typedef EGSignature DSASignature;
typedef EGPublicKey DSAPublicKey;
typedef EGPrivateKey DSAPrivateKey;
typedef EGParams DSAParams;
typedef EGKeySet DSAKeySet;

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForDSASign P((int qbits));

/* randomStart (if not NULL) should contain q bytes (bigBytes(key->q))
 */
_TYPE( DSASignature * ) DSASign P((BigInt big, DSAPrivateKey *key, BigInt randomStart));
/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( DSASignature * ) quantized_DSASign P((BigInt big, DSAPrivateKey *key, BigInt randomStart));

_TYPE( Boolean ) DSAVerify P((BigInt big, DSASignature *sig, DSAPublicKey *key));
			    
#define randBytesNeededForDSAParams randBytesNeededForEGParams
#define randBytesNeededForDSAKeySet randBytesNeededForEGKeySet
#define genDSAParams genEGParams
#define genDSAKeySet genEGKeySet

_TYPE( void ) freeDSASig P((DSASignature *));
#define freeDSAPublicKey freeEGPublicKey
#define freeDSAPrivateKey freeEGPrivateKey
#define freeDSAKeys freeEGKeys
#define freeDSAParams freeEGParams
/************************************************************************/

/* RSA Cryptosystem stuff */
/* rsa.c is not included in CryptoLib unless you can convince me that you have
 * a license.  Below is my interface.
 *
 * The private key contains material to enable the Chinese Remainder speedup
 * of decryption (or signing).  For RSA,
 * Decrypt(Encrypt(m, pubkey), privkey) = Encrypt(Decrypt(m, privkey), pubkey) = m
 */
/*	#include "rsa.h"	*/
typedef struct Key_exps {
    BigInt e;
	BigInt d;
#ifdef DLLEXPORT
	HGLOBAL exp_handle;
#endif
} Key_exps;

typedef struct ChineseRemStruct {
	BigInt p, q;    /* SECRET primes */
	BigInt dp, dq;  /* d mod p, d mod q */
	BigInt c12;     /* inverse of p (mod q) */
#ifdef DLLEXPORT
	HGLOBAL crt_handle;
#endif
} ChineseRemStruct;

typedef struct RSAPublicKey {
	BigInt publicExponent;
	BigInt modulus;
#ifdef DLLEXPORT
	HGLOBAL pubkey_handle;
#endif
} RSAPublicKey;

typedef struct RSAPrivateKey {
	BigInt publicExponent;
	BigInt privateExponent;  /* SECRET */
	BigInt modulus;
	ChineseRemStruct *crt;   /* SECRET */
#ifdef DLLEXPORT
	HGLOBAL privkey_handle;
#endif
} RSAPrivateKey;

typedef struct RSAKeySet {
	RSAPublicKey *publicKey;
	RSAPrivateKey *privateKey;
#ifdef DLLEXPORT
	HGLOBAL keyset_handle;
#endif
} RSAKeySet;

typedef Bignum RSASignature;

/* Returns the number of random material to be included in randomStart
 * if it is not to be NULL.
 */
_TYPE( int ) randBytesNeededForRSA P((int nbits, int ebits));

/* generate an RSA key set with modulus length = modbits and
 * public exponent length = explen.  If explen = 2, the public exponent = 3.
 * e may be prespecified.  If not it should be set to NULL.
 * If randomStart is not NULL, it should contain bytes in n + bytes in e.
 */
_TYPE( RSAKeySet * ) genRSAKeySet P((int nbits, int ebits,
				     BigInt e, BigInt randomStart));
/* This function will return an RSA key set with prespecified e, d, p, q.
 */ 
_TYPE( RSAKeySet * ) buildRSAKeySet P((BigInt e, BigInt d, BigInt p, BigInt q));
_TYPE( void ) freeRSAPublicKey P((RSAPublicKey *));
_TYPE( void ) freeRSAPrivateKey P((RSAPrivateKey *));
_TYPE( void ) freeRSAKeys P((RSAKeySet *));
_TYPE( void ) freeRSASig P((RSASignature *));

/* RSA Encryption(m) = m^publicExponent mod modulus */
_TYPE( BigInt ) RSAEncrypt P((BigInt msg, RSAPublicKey *key));

/* RSA Decryption = m^privateExponent mod modulus */
_TYPE( BigInt ) RSADecrypt P((BigInt msg, RSAPrivateKey *key));
/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( BigInt ) quantized_RSADecrypt P((BigInt msg, RSAPrivateKey *key));

/* Signing is just RSADecrypt */
_TYPE( RSASignature * ) RSASign P((BigInt msg, RSAPrivateKey *key));
/* STD_QUANTUM msec quantized to protect against timing attacks */
_TYPE( RSASignature * ) quantized_RSASign P((BigInt msg, RSAPrivateKey *key));

/* Verifying is just RSAEncrypt */
_TYPE( Boolean ) RSAVerify P((BigInt msg, RSASignature *sig, RSAPublicKey *));

/************************************************************************/


/* 4 cryptographic oen-way hash functions md2, md4, md5, SHA */
/* Each works in the same way: initialize structure (you can seed this init process
 * to make the function a keyed hash function, update the structure until all material
 * is hashed, finalize hash.
 */
/*	#include "md4.h"	*/
typedef struct {
  unsigned long i[2];                   /* number of _bits_ handled mod 2^64 */
  unsigned long buf[4];                                    /* scratch buffer */
  unsigned long in[16];
  unsigned char digest[16];     /* actual digest after MD4Final call */
#ifdef DLLEXPORT
	HGLOBAL md4_handle;
#endif	
} MD4_CTX;

_TYPE( void ) MD4Init P((MD4_CTX *mdContext));
_TYPE( void ) MD4Update P((MD4_CTX *mdContext, unsigned char *inBuf, unsigned int inLen));
_TYPE( void ) MD4Final P((MD4_CTX *mdContext));

/************************************************************************/
/*	#include "md5.h"	*/

/* MD5 context. */
typedef struct {
  Ulong state[4];                                           /* state (ABCD) */
  Ulong count[2];                /* number of bits, modulo 2^64 (lsb first) */
  unsigned char buffer[64];                                 /* input buffer */
#ifdef DLLEXPORT
	HGLOBAL md5_handle;
#endif	
} MD5_CTX;

void MD5Init P ((MD5_CTX *));
void MD5Update P ((MD5_CTX *, unsigned char *, unsigned int));
void MD5Final P ((unsigned char [16], MD5_CTX *));

/************************************************************************/

/*	#include "md2.h"	*/
typedef struct {
  unsigned char state[16];                                 /* state */
  unsigned char checksum[16];                           /* checksum */
  unsigned int count;                 /* number of bytes, modulo 16 */
  unsigned char buffer[16];                         /* input buffer */
#ifdef DLLEXPORT
	HGLOBAL md2_handle;
#endif	
} MD2_CTX;

_TYPE( void ) MD2Init P ((MD2_CTX *));
_TYPE( void ) MD2Update P ((MD2_CTX *mdContext, unsigned char *inBuf, unsigned int inLen));
_TYPE( void ) MD2Final P ((unsigned char [16], MD2_CTX *));
/************************************************************************/

/*	#include "shs.h"	*/
/* Secure Hash Standard */

typedef struct SHS_CTX {
    long totalLength;
    unsigned long h[5];
    unsigned long w[80];
#ifdef DLLEXPORT
    HGLOBAL shs_handle;
#endif		
} SHS_CTX;

_TYPE( void ) shsInit P((SHS_CTX *mdContext));
_TYPE( void ) shsUpdate P((SHS_CTX *mdContext, unsigned char *inbuf, unsigned long inLen));
_TYPE( void ) shsFinal P((SHS_CTX *mdContext));
_TYPE( unsigned long * ) shs P((unsigned char *, Ulong));
_TYPE( unsigned long * ) fShsDigest P((FILE *in));

/************************************************************************/

/* This is a simple interface to all of the above hash functions */
#define SHS 1
#define MD5 5
#define MD4 4
#define MD2 3
typedef int DigestType;

/* Return the hash value of file pointed to by fp in BigInt */
_TYPE( void ) fBigMessageDigest P((char *filename, BigInt digest, DigestType type));

/* Return the hash value of buffer pointed to by fp in BigInt */
_TYPE( void ) bigMessageDigest P((unsigned char *buf, int buflen,
				  BigInt digest, DigestType type));

/* same as last function but for dll's */
_TYPE( int ) messageDigest P((unsigned char *message, Ushort messageLength,
			     unsigned char *md, Ushort mdsize,
			     DigestType type));
			    


/************************************************************************/
/*		#include "asn1.h"					*/

/* This stuff is just getting underway and supports the routines in netIface.c */

/*
 *	macros for basic encoding rules
 */

/*#define GETC(S) (octet_counter++, getc(S))*/

#define UNIVERSAL	0x00
#define APPLICATION	0x40
#define CONTEXT		0x80
#define PRIVATE		0xC0

#define PRIMITIVE	0x00
#define CONSTRUCTED	0x20
#define IMPLICIT	PRIMITIVE
#define EXPLICIT	CONSTRUCTED

#define INDEFINITE	(-1L)

#define EOC		0
#define BOOLEAN		1
#define INTEGER		2
#define BITSTRING	3
#define OCTETSTRING	4
#define NULLTYPE	5
#define SEQUENCE	(16 | CONSTRUCTED)
#define SET		(17 | CONSTRUCTED)
#define NUMERICSTRING	18
#define PRINTABLESTRING	19
#define IA5STRING	22
#define UTCTIME		23

/************************************************************************/
/*		#include "fasn1.h"					*/
_TYPE( long ) fgetLength P((FILE *stream));
_TYPE( void ) fputLength P((long length, register FILE *stream));
_TYPE( int ) fgetBoolean P((FILE *stream, int form));
_TYPE( void ) fputBoolean P((int value, register FILE *stream, int form));
_TYPE( long ) fgetInteger P((FILE *stream, int form));
_TYPE( void ) fputInteger P((long value, register FILE *stream, int form));
_TYPE( long ) fgetString P((unsigned char *string, int limit,
			   register FILE *stream, int form));
_TYPE( void ) fputString P((unsigned char *cp, long length,
			   register FILE *stream, int form, int stringtype));
_TYPE( unsigned char *) fgetBitString P((unsigned char *bstring, int limit,
					register FILE *stream, int form));
_TYPE( void ) fputBitString P((unsigned char *bstring, int blength,
			      register FILE *stream,int form));
_TYPE( int ) featDataUnit P((FILE *stream, int form, register tag));
_TYPE( void ) fgetEOC P((FILE *stream, int form));
_TYPE( void ) fputEOC P((FILE *stream));

/************************************************************************/
/*		#include "fnetIface.h"					*/
/* Tools for moving around various structures in asn.1 form.		*/

_TYPE( void ) fputBigInt P((BigInt big, FILE *stream));
_TYPE( BigInt ) fgetBigInt P((FILE *stream));
_TYPE( void ) fputTable P((Table *table, FILE *stream));
_TYPE( Table * ) fgetTable P((FILE *stream));
_TYPE( void ) fputRSAPublicKey P((RSAPublicKey *key, FILE *stream));
_TYPE( RSAPublicKey * ) fgetRSAPublicKey P((FILE *stream));
_TYPE( void ) fputRSAPrivateKey P((RSAPrivateKey *key, FILE *stream));
_TYPE( RSAPrivateKey * ) fgetRSAPrivateKey P((FILE *stream));
_TYPE( void ) fputRSASignature P((RSASignature *sig, FILE *stream));
_TYPE( RSASignature * ) fgetRSASignature P((FILE *stream));
_TYPE( RSAPublicKey * ) nfgetRSAPublicKey P((char *));
_TYPE( RSAPrivateKey * ) nfgetRSAPrivateKey P((char *));
_TYPE( void ) fputEGParams P((EGParams *params, FILE *stream));
_TYPE( EGParams * ) fgetEGParams P((FILE *stream));
_TYPE( void ) fputEGPublicKey P((EGPublicKey *key, FILE *stream));
_TYPE( EGPublicKey * ) fgetEGPublicKey P((FILE *stream));
_TYPE( void ) fputEGPrivateKey P((EGPrivateKey *key, FILE *stream));
_TYPE( EGPrivateKey * ) fgetEGPrivateKey P((FILE *stream));
_TYPE( void ) fputEGSignature P((EGSignature *sig, FILE *stream));
_TYPE( EGSignature * ) fgetEGSignature P((FILE *stream));
_TYPE( void ) fputDSASignature P((DSASignature *sig, FILE *stream));
_TYPE( DSASignature * ) fgetDSASignature P((FILE *stream));

#define fPutDSAParams fPutEGParams
#define fGetDSAParams fGetEGParams
#define fPutDSAPublicKey fPutEGPublicKey
#define fGetDSAPublicKey fGetEGPublicKey
#define fPutDSAPrivateKey fPutEGPrivateKey
#define fGetDSAPrivateKey fGetEGPrivateKey

/************************************************************************/
/*		#include "bufasn1.h"					*/

_TYPE( long ) bufGetLength P((unsigned char **buffer));
_TYPE( void ) bufPutLength P((long length, register unsigned char **buffer));
_TYPE( int ) bufGetBoolean P((unsigned char **buffer, int form));
_TYPE( void ) bufPutBoolean P((int value, register unsigned char **buffer, int form));
_TYPE( long ) bufGetInteger P((unsigned char **buffer, int form));
_TYPE( void ) bufPutInteger P((long value, register unsigned char **buffer, int form));
_TYPE( long ) bufGetString P((unsigned char *string, int limit,
			   register unsigned char **buffer, int form));
_TYPE( void ) bufPutString P((unsigned char *cp, long length,
			   register unsigned char **buffer, int form, int stringtype));
_TYPE( unsigned char *) bufGetBitString P((unsigned char *bstring, int limit,
					register unsigned char **buffer, int form));
_TYPE( void ) bufPutBitString P((unsigned char *bstring, int blength,
			      register unsigned char **buffer,int form));
_TYPE( int ) bufEatDataUnit P((unsigned char **buffer, int form, register tag));
_TYPE( void ) bufGetEOC P((unsigned char **buffer, int form));
_TYPE( void ) bufPutEOC P((unsigned char **buffer));

/************************************************************************/
/*		#include "bufNetIface.h"				*/
/* Tools for moving around various structures in asn.1 form.		*/

_TYPE( void ) bufPutBigInt P((BigInt big, unsigned char **buffer));
_TYPE( BigInt ) bufGetBigInt P((unsigned char **buffer));
_TYPE( void ) bufPutTable P((Table *table, unsigned char **buffer));
_TYPE( Table * ) bufGetTable P((unsigned char **buffer));
_TYPE( void ) bufPutRSAPublicKey P((RSAPublicKey *key, unsigned char **buffer));
_TYPE( RSAPublicKey * ) bufGetRSAPublicKey P((unsigned char **buffer));
_TYPE( void ) bufPutRSAPrivateKey P((RSAPrivateKey *key, unsigned char **buffer));
_TYPE( RSAPrivateKey * ) bufGetRSAPrivateKey P((unsigned char **buffer));
_TYPE( void ) bufPutRSASignature P((RSASignature *sig, unsigned char **buffer));
_TYPE( RSASignature * ) bufGetRSASignature P((unsigned char **buffer));
_TYPE( RSAPublicKey * ) nbufGetRSAPublicKey P((char *));
_TYPE( RSAPrivateKey * ) nbufGetRSAPrivateKey P((char *));
_TYPE( void ) bufPutEGParams P((EGParams *params, unsigned char **buffer));
_TYPE( EGParams * ) bufGetEGParams P((unsigned char **buffer));
_TYPE( void ) bufPutEGPublicKey P((EGPublicKey *key, unsigned char **buffer));
_TYPE( EGPublicKey * ) bufGetEGPublicKey P((unsigned char **buffer));
_TYPE( void ) bufPutEGPrivateKey P((EGPrivateKey *key, unsigned char **buffer));
_TYPE( EGPrivateKey * ) bufGetEGPrivateKey P((unsigned char **buffer));
_TYPE( void ) bufPutEGSignature P((EGSignature *sig, unsigned char **buffer));
_TYPE( EGSignature * ) bufGetEGSignature P((unsigned char **buffer));
_TYPE( void ) bufPutDSASignature P((DSASignature *sig, unsigned char **buffer));
_TYPE( DSASignature * ) bufGetDSASignature P((unsigned char **buffer));

#define bufPutDSAParams bufPutEGParams
#define bufGetDSAParams bufGetEGParams
#define bufPutDSAPublicKey bufPutEGPublicKey
#define bufGetDSAPublicKey bufGetEGPublicKey
#define bufPutDSAPrivateKey bufPutEGPrivateKey
#define bufGetDSAPrivateKey bufGetEGPrivateKey

#endif




