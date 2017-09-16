/****************************************************************************
*																			*
*					cryptlib Prime Number Generation Routines				*
*					  Copyright (various people) 1997-1999					*
*																			*
****************************************************************************/

/* The Usenet Oracle has pondered your question deeply.
   Your question was:

   > O Oracle Most Wise,
   >
   > What is the largest prime number?

   And in response, thus spake the Oracle:

   } This is a question which has stumped some of the best minds in
   } mathematics, but I will explain it so that even you can understand it.
   } The first prime is 2, and the binary representation of 2 is 10.
   } Consider the following series:
   }
   }	Prime	Decimal Representation	Representation in its own base
   }	1st		2						10
   }	2nd		3						10
   }	3rd		5						10
   }	4th		7						10
   }	5th		11						10
   }	6th		13						10
   }	7th		17						10
   }
   } From this demonstration you can see that there is only one prime, and
   } it is ten. Therefore, the largest prime is ten.
													-- The Usenet Oracle */
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"
#if defined( INC_ALL )
  #ifdef __TANDEM
	#include "bnprime.h"
  #else
	#include "bn_prime.h"
  #endif /* __TANDEM */
#else
  #include "bn/bn_prime.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in lib_rand.c */

int getRandomData( BYTE *buffer, const int length );

/****************************************************************************
*																			*
*						Determine Discrete Log Exponent Bits				*
*																			*
****************************************************************************/

/* The following function (provided by Colin Plumb) is used to calculate the
   appropriate size exponent for a given prime size which is required to
   provide equivalent security from small-exponent attacks

   This is based on a paper by Michael Wiener on	| The function defined
   the difficulty of the two attacks, which has		| below (not part of the
   the following table:								| original paper)
													| produces the following
	 Table 1: Subgroup Sizes to Match Field Sizes	| results:
													|
	Size of p	Cost of each attack		Size of q	|	Output	Error
	 (bits)		(instructions or		(bits)		|			(+ is safe)
				 modular multiplies)				|
													|
	   512			9 x 10^17			119			|	137		+18
	   768			6 x 10^21			145			|	153		+8
	  1024			7 x 10^24			165			|	169		+4
	  1280			3 x 10^27			183			|	184		+1
	  1536			7 x 10^29			198			|	198		+0
	  1792			9 x 10^31			212			|	212		+0
	  2048			8 x 10^33			225			|	225		+0
	  2304			5 x 10^35			237			|	237		+0
	  2560			3 x 10^37			249			|	249		+0
	  2816			1 x 10^39			259			|	260		+1
	  3072			3 x 10^40			269			|	270		+1
	  3328			8 x 10^41			279			|	280		+1
	  3584			2 x 10^43			288			|	289		+1
	  3840			4 x 10^44			296			|	297		+1
	  4096			7 x 10^45			305			|	305		+0
	  4352			1 x 10^47			313			|	313		+0
	  4608			2 x 10^48			320			|	321		+1
	  4864			2 x 10^49			328			|	329		+1
	  5120			3 x 10^50			335			|	337		+2

   This function fits a curve to this, which overestimates the size of the
   exponent required, but by a very small amount in the important 1000-4000
   bit range.  It is a quadratic curve up to 3840 bits, and a linear curve
   past that.  They are designed to be C(1) (have the same value and the same
   slope) at the point where they meet */

#define AN		1L		/* a = -AN/AD/65536, the quadratic coefficient */
#define AD		3L
#define M		8L		/* Slope = M/256, i.e. 1/32 where linear starts */
#define TX		3840L	/* X value at the slope point, where linear starts */
#define TY		297L	/* Y value at the slope point, where linear starts */

/* For a slope of M at the point (TX,TY), we only have one degree of freedom
   left in a quadratic curve, so use the coefficient of x^2, namely a, as
   that free parameter.

   y = -AN/AD*((x-TX)/256)^2 + M*(x-TX)/256 + TY
	 = -AN*(x-TX)*(x-TX)/AD/256/256 + M*x/256 - M*TX/256 + TY
	 = -AN*x*x/AD/256/256 + 2*AN*x*TX/AD/256/256 - AN*TX*TX/AD/256/256 \
		+ M*x/256 - M*TX/256 + TY
	 = -AN*(x/256)^2/AD + 2*AN*(TX/256)*(x/256)/AD + M*(x/256) \
		- AN*(TX/256)^2/AD - M*(TX/256) + TY
	 = (AN*(2*TX/256 - x/256) + M*AD)*x/256/AD - (AN*(TX/256)/AD + M)*TX/256 \
		+ TY
	 = (AN*(2*TX/256 - x/256) + M*AD)*x/256/AD \
		- (AN*(TX/256) + M*AD)*TX/256/AD + TY
	 =  ((M*AD + AN*(2*TX/256 - x/256))*x - (AN*(TX/256)+M*AD)*TX)/256/AD + TY
	 =  ((M*AD + AN*(2*TX - x)/256)*x - (AN*(TX/256)+M*AD)*TX)/256/AD + TY
	 =  ((M*AD + AN*(2*TX - x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD + TY
	 =  (((256*M*AD+2*AN*TX-AN*x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD + TY

   Since this is for the range 0...TX, in order to avoid having any
   intermediate results less than 0, we need one final rearrangement, and a
   compiler can easily take the constant-folding from there...

	 =  TY + (((256*M*AD+2*AN*TX-AN*x)/256)*x - (M*AD + AN*TX/256)*TX)/256/AD
	 =  TY - ((M*AD + AN*TX/256)*TX - ((256*M*AD+2*AN*TX-AN*x)/256)*x)/256/AD
*/

int getDLExpSize( const int primeBits )
	{
	long value;	/* Necessary to avoid braindamage on 16-bit compilers */

	/* If it's over TX bits, it's linear */
	if( primeBits > TX )
		value = M * primeBits / 256 - M * TX / 256 + TY;
	else
		/* It's quadratic */
		value = TY - ( ( M * AD + AN * TX / 256 ) * TX - \
					   ( ( 256 * M * AD + AN * 2 * TX - AN * primeBits ) / 256 ) * \
					   primeBits ) / ( AD * 256 );

	return( ( int ) value );
	}

/****************************************************************************
*																			*
*							Generate Non-specific Primes					*
*																			*
****************************************************************************/

/* #include 4k of EAY copyright */

/* The following define is necessary in memory-starved environments.  It
   controls the size of the table used for the sieving */

#if defined( __MSDOS16__ ) && defined( __TURBOC__ )
  #define EIGHT_BIT
#endif /* MSDOS */

/* The number of primes in the sieve (and their values) which result in a
   given number of candidates remaining from 40,000.  Even the first 100
   primes weed out 91% of all the candidates, and after 500 you're only
   removing a handful for each 100 extra primes.

	 Number		   Prime	Candidates left
				  Values	from 40,000
	--------	---------	---------------
	  0- 99		   0- 541		3564
	100-199		 541-1223		3175
	200-299		1223-1987		2969
	300-399		1987-2741		2845
	400-499		2741-3571		2755
	500-599		3571-4409		2688
	600-699		4409-5279		2629
	700-799		5279-6133		2593
	800-899		6133-6997		2555
	900-999		6997-7919		2521 */

/* The number of iterations of Miller-Rabin for an error probbility of
   (1/2)^80, from HAC */

#define getNoPrimeChecks( noBits ) \
	( ( noBits < 150 ) ? 18 : ( noBits < 200 ) ? 15 : \
	  ( noBits < 250 ) ? 12 : ( noBits < 300 ) ? 9 : \
	  ( noBits < 350 ) ? 8 : ( noBits < 400 ) ? 7 : \
	  ( noBits < 500 ) ? 6 : ( noBits < 600 ) ? 5 : \
	  ( noBits < 800 ) ? 4 : ( noBits < 1250 ) ? 3 : 2 )

/* The size of the sieve array - 1 memory page (on most CPU's) = 4K candidate
   values */

#define SIEVE_SIZE				4096

/* When we're doing a sieve of a singleton candidate, we don't run through
   the whole range of sieve values since we run into the law of diminshing
   returns after a certain point.  The following value sieves with every
   prime under 1000 */

#ifdef EIGHT_BIT
  #define FAST_SIEVE_NUMPRIMES	NUMPRIMES
#else
  #define FAST_SIEVE_NUMPRIMES	( 21 * 8 )
#endif /* EIGHT_BIT */

static int witness(BIGNUM* a, BIGNUM* n, BN_CTX* ctx,
		   BN_CTX* ctx2, BN_MONT_CTX* mont);

/* Set up the sieve array for the number.  Every position which contains
   a zero is non-divisible by all of the small primes */

BOOLEAN *initSieve( BOOLEAN *sieveArray, const BIGNUM *candidate )
	{
	int i;

	/* Allocate the array if necessary and clear the sieve */
	if( sieveArray == NULL && \
		( sieveArray = malloc( SIEVE_SIZE * sizeof( BOOLEAN ) ) ) == NULL )
		return( NULL );
	memset( sieveArray, 0, SIEVE_SIZE * sizeof( BOOLEAN ) );

	/* Walk down the list of primes marking the appropriate position in the
	   array as divisible by the prime.  We start at index 1, since the
	   candidate will never be divisible by 2 */
	for( i = 1; i < NUMPRIMES; i++ )
		{
		unsigned int step = primes[ i ];
		int index = ( int ) BN_mod_word( ( BIGNUM * ) candidate, step );

		/* Determine the correct start index for this value */
		if( index & 1 )
			index = ( step - index ) / 2;
		else
			if( index )
				index = ( ( step * 2 ) - index ) / 2;

		/* Mark each multiple of the divisor as being divisible */
		while( index < SIEVE_SIZE )
			{
			sieveArray[ index ] = 1;
			index += step;
			}
		}

	return( sieveArray );
	}

void endSieve( BOOLEAN *sieveArray )
	{
	memset( sieveArray, 0, SIEVE_SIZE * sizeof( BOOLEAN ) );
	free( sieveArray );
	}

/* An LFSR to step through each entry in the sieve array.  This isn't a true
   pseudorandom selection since all it's really doing is going through the
   numbers in a linear order with a different starting point, but it'll do
   for now until the next version of the BN library appears */

#define LFSR_POLYNOMIAL		0x1053
#define LFSR_MASK			0x1000

static int nextEntry( int value )
	{
	/* Get the next value: Multiply by x and reduce by the polynomial */
	value <<= 1;
	if( value & LFSR_MASK )
		value ^= LFSR_POLYNOMIAL;
	return( value );
	}

/* A one-off sieve check for when we're testing a singleton rather than
   running over a range of values */

BOOLEAN primeSieve( const BIGNUM *candidate )
	{
	int i;

	for( i = 1; i < FAST_SIEVE_NUMPRIMES; i++ )
		if( !BN_mod_word( ( BIGNUM * ) candidate, primes[ i ] ) )
			return( FALSE );

	return( TRUE );
	}

/* Do a Miller-Rabin probabilistic primality test */

static int primeProbable( BIGNUM *candidate, const int noChecks,
						  void *callbackArg )
	{
	BN_MONT_CTX *montCTX;
	BN_CTX *bnCTX, *bnCTX2;
	BIGNUM *check;
	int i, status;

	/* Allocate the BN and Montgomery contexts and convert the candidate to
	   its Montgomery form */
	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );
	bnCTX2 = BN_CTX_new();
	montCTX = BN_MONT_CTX_new();
	if( bnCTX2 == NULL || montCTX == NULL || \
		!BN_MONT_CTX_set( montCTX, candidate, bnCTX ) )
		{
		BN_CTX_free( bnCTX );
		if( bnCTX2 != NULL )
			BN_CTX_free( bnCTX2 );
		if( montCTX != NULL )
			BN_MONT_CTX_free( montCTX );
		return( CRYPT_NOMEM );
		}
	check = bnCTX->bn[ bnCTX->tos++ ];

	/* Perform n iterations of Miller-Rabin */
	for( i = 0; i < noChecks; i++ )
		{
		/* Perform the callback.  We do this befor the Miller-Rabin check
		   to ensure that it always gets called at least once for every
		   call to primeProbable() - since the majority of candidates fail
		   the witness() function, it'd almost never get called after
		   witness() is called */
		status = keygenCallback( callbackArg );
		if( cryptStatusError( status ) )
			break;

		/* Instead of using a bignum for the Miller-Rabin check, we use a
		   series of small primes.  The reason for this is that if bases a1
		   and a2 are strong liars for n then their product a1a2 is also very
		   likely to be a strong liar, so using a composite base doesn't give
		   us any great advantage.  In addition an initial test with a=2 is
		   beneficial since most composite numbers will fail Miller-Rabin
		   with a=2, and exponentiation with base 2 is faster than general-
		   purpose exponentiation.  Finally, using small values instead of
		   random bignums is both significantly more efficient and much
		   easier on the RNG.   For these reasons we use the first noChecks
		   small primes as the base instead of using random bignum bases */
		BN_set_word( check, primes[ i ] );
		status = witness( check, candidate, bnCTX, bnCTX2, montCTX );
		if( cryptStatusError( status ) )
			break;
		if( status )
			{
			/* It's not a prime */
			status = FALSE;
			break;
            }
		}

	/* If we made it through all the checks, it's a prime */
	if( i == noChecks )
		status = TRUE;

	/* Free everything */
	bnCTX->tos--;
	BN_MONT_CTX_free( montCTX );
	BN_CTX_free( bnCTX2 );
	BN_CTX_free( bnCTX );

	return( status );
	}

/* Witness function, stolen from original BN code */

static int witness(a,n,ctx,ctx2,mont)
BIGNUM *a;
BIGNUM *n;
BN_CTX *ctx,*ctx2;
BN_MONT_CTX *mont;
    {
	int k,i,ret= -1,good;
    BIGNUM *d,*dd,*tmp,*d1,*d2,*n1;
    BIGNUM *mont_one,*mont_n1,*mont_a;

    d1=ctx->bn[ctx->tos];
    d2=ctx->bn[ctx->tos+1];
    n1=ctx->bn[ctx->tos+2];
    ctx->tos+=3;

    mont_one=ctx2->bn[ctx2->tos];
    mont_n1=ctx2->bn[ctx2->tos+1];
    mont_a=ctx2->bn[ctx2->tos+2];
    ctx2->tos+=3;

    d=d1;
    dd=d2;
    if (!BN_one(d)) goto err;
    if (!BN_sub(n1,n,d)) goto err; /* n1=n-1; */
    k=BN_num_bits(n1);

    if (!BN_to_montgomery(mont_one,BN_value_one(),mont,ctx2)) goto err;
    if (!BN_to_montgomery(mont_n1,n1,mont,ctx2)) goto err;
    if (!BN_to_montgomery(mont_a,a,mont,ctx2)) goto err;

    BN_copy(d,mont_one);
    for (i=k-1; i>=0; i--)
        {
        if (    (BN_cmp(d,mont_one) != 0) &&
            (BN_cmp(d,mont_n1) != 0))
            good=1;
        else
            good=0;

        BN_mod_mul_montgomery(dd,d,d,mont,ctx2);

		if (good && (BN_cmp(dd,mont_one) == 0))
            {
			ret=1;
            goto err;
            }
        if (BN_is_bit_set(n1,i))
            {
            BN_mod_mul_montgomery(d,dd,mont_a,mont,ctx2);
            }
        else
            {
            tmp=d;
            d=dd;
            dd=tmp;
            }
        }
    if (BN_cmp(d,mont_one) == 0)
        i=0;
    else    i=1;
    ret=i;
err:
    ctx->tos-=3;
    ctx2->tos-=3;
	return(ret);
	}

/* Generate a prime.  If exponent != 0, this will also verify that
   gcd( (p - 1)(q - 1), exponent ) = 1, which is required for RSA */

int generateRSAPrime( BIGNUM *candidate, const int noBits,
					  const long exponent, void *callbackArg )
	{
	const int noChecks = getNoPrimeChecks( noBits );
	BOOLEAN *sieveArray = NULL;
	int offset, oldOffset = 0, startPoint, status;

	/* Start with a cryptographically strong odd random number.  We set the
	   two high bits so that pq will end up exactly 2n bits long */
	status = generateBignum( candidate, noBits, 0xC0, 0x1 );
	if( cryptStatusError( status ) )
		return( status );

	do
		{
		/* Set up the sieve array for the number and pick a random starting
		   point */
		sieveArray = initSieve( sieveArray, candidate );
		if( sieveArray == NULL )
			return( CRYPT_NOMEM );
		getRandomData( ( BYTE * ) &startPoint, sizeof( int ) );
		startPoint &= SIEVE_SIZE - 1;

		/* Perform a random-probing search for a prime */
		for( offset = nextEntry( startPoint ); offset != startPoint;
			 offset = nextEntry( offset ) )
			{
			long remainder;

			/* If this candidate is divisible by anything, continue */
			if( sieveArray[ offset ] )
				continue;

			/* Adjust the candidate by the number of nonprimes we've
			   skipped */
			if( offset > oldOffset )
				BN_add_word( candidate, ( offset - oldOffset ) * 2 );
			else
				BN_sub_word( candidate, ( oldOffset - offset ) * 2 );
			oldOffset = offset;

			/* Perform a Fermat test to the base 2 (Fermat = a^p-1 mod p == 1
			   -> a^p mod p == a, for all a), which isn't as reliable as
			   Miller-Rabin but may be quicker if a fast base 2 modexp is
			   available (currently it provides no improvement at all over the
			   use of straight Miller-Rabin).  If a faster version is
			   available, it serves as a convenient filter to weed out most
			   pseudoprimes */
#ifdef USE_FERMAT
			{
			BN_CTX *bnCTX = BN_CTX_new();
			BIGNUM *tmp = BN_new(), *two = BN_new();

			BN_set_word( two, 2 );
			BN_mod_exp( tmp, two, candidate, candidate, bnCTX );
			status = BN_is_word( tmp, 2 );

			BN_clear_free( two );
			BN_clear_free( tmp );
			BN_CTX_free( bnCTX );
			if( !status )
				continue;
			}
#endif /* USE_FERMAT */

			/* Perform the probabalistic test */
			status = primeProbable( candidate, noChecks, callbackArg );
			if( cryptStatusError( status ) )
				break;
			if( !status )
				continue;

			/* If it's not for RSA use, we've found our candidate */
			if( !exponent )
				break;

			/* It's for use with RSA, check the RSA condition that
			   gcd( p - 1, exp ) == 1.  Since exp is a small prime, we can do
			   this efficiently by checking that ( p - 1 ) mod exp != 0 */
			BN_sub_word( candidate, 1 );
			remainder = BN_mod_word( candidate, exponent );
			BN_add_word( candidate, 1 );
			if( remainder )
				break;	/* status = TRUE from above */
			}
		}
	while( status == FALSE );	/* -ve = error, TRUE = success */

	endSieve( sieveArray );
	return( ( status == TRUE ) ? CRYPT_OK : status );
	}

/****************************************************************************
*																			*
*			  					Generate DL Primes							*
*							Copyright Kevin J Bluck 1998					*
*																			*
****************************************************************************/

/* DLP-based PKC's have various requirements for the generated parameters:

	DH: No g (it's fixed at 2) or q
	DSA: p, q, and g of preset lengths (currently p isn't fixed at exactly
		 n * 64 bits because of the way the Lim-Lee algorithm works, it's
		 possible to get this by iterating the multiplication step until the
		 result is exactly n * 64 bits but this doesn't seem worth the
		 effort).
	Elgamal: g small for speed reasons */

/* The maximum number of factors required to generate a prime using the Lim-
   Lee algorithm.  The value 160 is the minimum safe exponent size */

#define MAX_NO_FACTORS	( ( ( CRYPT_MAX_PKCSIZE * 8 ) / 160 ) + 1 )

/* Select a generator g for the prime moduli p and q.  g will be chosen so
   that it is of prime order q, where q divides (p - 1), ie g generates the
   subgroup of order q in the multiplicative group of GF(p).  There are two
   cases for g, one where g is the same size as p (for DSA) and one where g
   is as small as possible (for Elgamal) */

static int findGeneratorForPQ( BIGNUM *p, BIGNUM *q, BIGNUM *g,
							   const BOOLEAN smallG )
	{
	BN_CTX *bnCTX;
	BIGNUM *x, *counter;
	int status = CRYPT_OK;

	/* Allocate the bignums and context */
	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );
	x = BN_new();
	counter = BN_new();
	if( x == NULL || counter == NULL )
		{
		BN_CTX_free( bnCTX );
		if( x != NULL )
			BN_free( x );
		if( counter != NULL )
			BN_free( counter );
		return( CRYPT_NOMEM );
		}

	/* If we're using the values for Elgamal, we want g as small as
	   possible */
	if( smallG )
		{
		for( BN_set_word( g, 3 ); !BN_is_one( x ); BN_add_word( g, 1 ) )
			BN_mod_exp( x, g, q, p, bnCTX );
		}
	else
		{
		/* x = (p - 1) / q */
		BN_sub_word( p, 1 );
		BN_div( x, NULL, p, q, bnCTX );
		BN_add_word( p, 1 );

		/* Starting the count at 3, set g = (counter ^ x) mod p until g != 1 */
		BN_set_word( g, 1 );
		for( BN_set_word( counter, 3 ); BN_is_one( g ); BN_add_word( counter, 1 ) )
			BN_mod_exp( g, counter, x, p, bnCTX );
		}

	/* Clean up */
	BN_clear_free( x );
	BN_clear_free( counter );
	BN_CTX_free( bnCTX );
	return( status );
	}

/* Generate prime numbers for DLP-based PKC's using the Lim-Lee algorithm:
	p = 2 * q * ( prime[1] * ... prime[n] ) + 1;
   Generation of the q and g values is optional, they are ignored if NULL */

int generateDLvalues( BIGNUM *p, const int pBits, BIGNUM *q, int qBits,
					  BIGNUM *g, CRYPT_INFO *cryptInfo )
	{
	const int safeExpSizeBits = getDLExpSize( pBits );
	const int noChecks = getNoPrimeChecks( pBits );
	BIGNUM *products[ MAX_NO_FACTORS ], **primes, *localQ;
	BOOLEAN primeFound = FALSE;
	int indices[ MAX_NO_FACTORS ], index;
	int nPrimes = 0, nAllocatedPrimes, nFactors = 1, factorBits, status;

	int indexMoved	  = 0;

	/* If the caller isn't using q, generate a local value for it with a
	   minimum safe exponent size */
	if( !qBits )
		qBits = safeExpSizeBits;

	/* Determine how many factors we need (it appears that we need an even
	   number of factors, so we reduce it to the next even number) and the
	   size in bits of the factors */
	while( ( pBits - qBits - 1 ) / nFactors  >= safeExpSizeBits )
		nFactors++;
	nFactors = nPrimes = ( nFactors - 1 ) & ~1;
	factorBits = ( ( pBits - qBits ) - 1 ) / nFactors;

	/* When we allocate storage for the primes, we overallocate by a useful
	   amount to save having to reallocate the prime array every time we
	   generate a new one.  The following allocates at least 16 more values
	   than the minimum necessary, rounded up to the nearest multiple of 16.
	   Every time we need more primes after this, we allocate another chunk
	   of 16 values */
	nAllocatedPrimes = ( nPrimes + 32 ) & ~15;

	/* Generate a random prime q and multiply by 2 to form the base for the
	   other factors */
	if( ( localQ = BN_new() ) == NULL )
		return( CRYPT_NOMEM );
	status = generateRSAPrime( localQ, qBits, 0, cryptInfo );
	if( cryptStatusError( status ) )
		{
		BN_clear_free( localQ );
		return( status );
		}
	BN_lshift1( localQ, localQ );

	/* Set up the permutation control arrays */
	status = CRYPT_NOMEM;
	if( ( primes = malloc( nAllocatedPrimes * sizeof( BIGNUM  * ) ) ) == NULL )
		{
		BN_clear_free( localQ );
		return( CRYPT_NOMEM );
		}
	for( index = 0; index < nFactors; index++ )
		if( ( products[ index ] = BN_new() ) == NULL )
			{
			nFactors = index;	/* Remember how far we got */
			goto cleanup;
			}

	/* Generate the first nFactors factors */
	for( index = 0; index < nFactors; index++ )
		{
		if( ( primes[ index ] = BN_new() ) != NULL )
			status = generateRSAPrime( primes[ index ], factorBits, 0,
									   cryptInfo );
		if( cryptStatusError( status ) )
			{
			nPrimes = index;	/* Remember how far we got */
			goto cleanup;
			}
		}

	do
	{
		/* Initialize indices for permutation. We try first the nFactors
		   number of potential factors which are highest in the list, since
		   new primes are always added to the end of the list. */
		indices[nFactors - 1] = nPrimes - 1;
		for (index = nFactors - 2; index >= 0; index--)
			indices[index] = indices[index + 1] - 1;
		BN_mul(products[nFactors - 1], localQ, primes[nPrimes - 1]);
		indexMoved = nFactors - 2;

		/* Test all the currently new possible prime permutations until a
		   prime is found or we run out of permutations. */
		do
		{
			/* Assemble a new candidate prime from the currently indexed
			   random primes */
			for( index = indexMoved; index >= 0; index-- )
				BN_mul( products[ index ], products[ index + 1 ],
						primes[ indices[ index ] ] );
			BN_copy( p, products[ 0 ] );
			BN_add_word( p, 1 );

			/* If the candidate has a good chance of being prime, try a
			   probabalistic test and exit if it succeeds */
			if( primeSieve( p ) )
				{
				status = primeProbable( p, noChecks, cryptInfo );
				if( cryptStatusError( status ) )
					goto cleanup;
				if( status )
					{
					primeFound = TRUE;
					break;
					}
				}

			/* Looping from lowest to highest index, find the lowest index
			   which is not already at the lowest possible point, and move it
			   down one position. */
			for (index = 0; index < nFactors; index++)
				if (indices[index] > index)
				{
					indices[index]--;
					indexMoved = index;
					break;
				}

			/* If we did not change the highest index, take all the indices
			   below the one we moved down, and move them all up so they're
			   packed up as high as they will go. If we moved down the highest
			   index, then we're done with all the permutations, so break the
			   loop to generate another prime and start over.  */
			if ((indexMoved != nFactors - 1) && (index < nFactors))
			{
				for (index = indexMoved - 1; index >= 0; index--)
					indices[index] = indices[index + 1] - 1;
			}
			else
				break;

		} while (indices[nFactors - 1]);

		/* If we haven't found a prime yet, add a new prime to the pool and
		   try again */
		if( !primeFound )
			{
			/* If there's not enough room for the new prime, expand the
			   existing storage */
			status = CRYPT_NOMEM;
			if( nPrimes + 1 > nAllocatedPrimes )
				{
				BIGNUM **newPrimes;

				nAllocatedPrimes += 16;
				newPrimes = malloc( nAllocatedPrimes * sizeof( BIGNUM * ) );
				if( newPrimes == NULL )
					goto cleanup;
				memcpy( newPrimes, primes, nPrimes * sizeof( BIGNUM * ) );
				free( primes );
				primes = newPrimes;
				}

			/* Allocate and generate the new prime */
			if( ( primes[ nPrimes ] = BN_new() ) == NULL )
				goto cleanup;
			nPrimes++;
			status = generateRSAPrime( primes[ nPrimes - 1 ], factorBits, 0,
									   cryptInfo );
			if( cryptStatusError( status ) )
				goto cleanup;
			}
		}
	while( !primeFound );

	/* Recover the original value of q from by dividing by 2 and copy it to
	   the output if necessary */
	BN_rshift1( localQ, localQ );
	if( q != NULL )
		BN_copy( q, localQ );

	/* Find a generator suitable for p and q if necessary */
	if( g != NULL )
		status = findGeneratorForPQ( p, localQ, g, FALSE );

cleanup:

	/* Free the local storage */
	for( index = 0; index < nPrimes; index++ )
		if( primes[ index ] != NULL )
			BN_clear_free( primes[ index ] );
	free( primes );
	for( index = 0; index < nFactors; index++ )
		if( products[ index ] != NULL )
			BN_clear_free( products[ index ] );
	BN_clear_free( localQ );

	return( status );
	}
