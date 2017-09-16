/****************************************************************************
*																			*
*					  cryptlib Elgamal Encryption Routines					*
*						 Copyright Peter Gutmann 1997						*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/* Prototypes for functions in asn1keys.c */

int encodeDLValues( BYTE *buffer, BIGNUM *value1, BIGNUM *value2 );
int decodeDLValues( BYTE *buffer, BIGNUM **value1, BIGNUM **value2 );

/* Prototypes for functions in lib_kg.c */

int generateDLvalues( BIGNUM *p, const int pBits, BIGNUM *q, int qBits,
					  BIGNUM *g, CRYPT_INFO *cryptInfo );

/****************************************************************************
*																			*
*						Predefined Elgamal p and g Parameters				*
*																			*
****************************************************************************/

/* The following values are defined in lib_dh.c and are the shared p values,
   which can be used for discrete-log based PKC's other than DH */

extern const BYTE FAR_BSS prime512[], FAR_BSS prime768[], FAR_BSS prime1024[], 
				  FAR_BSS prime1280[], FAR_BSS prime1536[], 
				  FAR_BSS prime2048[], FAR_BSS prime3072[], 
				  FAR_BSS prime4096[];

/* The structure for storing the Elgamal public values.  Note that unlike DH,
   we can't use a generator of 2 since that would allow an attacker to forge
   signatures as per:

	"Generating ElGamal Signatures Without Knowing the Secret Key", Daniel
	  Bleichenbacher, Advances in Cryptology - EUROCRYPT '96, Springer-Verlag
	  Lecture Notes in Computer Science, Vol.1070 (1996), p.10.

   Apart from that, these values are identical to the DH values */

typedef struct {
	const int baseLen; const BYTE base[ 1 ];
	const int primeLen; const BYTE *prime;
	} EG_PUBLIC_VALUES;

static const EG_PUBLIC_VALUES egPublicValues[] = {
	{ 1, { 0x03 }, 512, prime512  },
	{ 1, { 0x03 }, 768, prime768  },
	{ 1, { 0x03 }, 1024, prime1024 },
	{ 1, { 0x03 }, 1280, prime1280 },
	{ 1, { 0x03 }, 1536, prime1536 },
	{ 1, { 0x03 }, 2048, prime2048 },
	{ 1, { 0x03 }, 3072, prime3072 },
	{ 1, { 0x03 }, 4096, prime4096 },
	{ 0, { 0 }, 0, NULL }
	};

/****************************************************************************
*																			*
*							Elgamal Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Elgamal implementation using a sample key.  Because a lot of the
   high-level encryption routines don't exist yet, we cheat a bit and set up
   a dummy encryption context with just enough information for the following
   code to work */

typedef struct {
	const int pLen; const BYTE *p;
	const int gLen; const BYTE g[ 1 ];
	const int yLen; const BYTE y[ 64 ];
	const int xLen; const BYTE x[ 64 ];
	} ELGAMAL_PRIVKEY;

static const ELGAMAL_PRIVKEY elgamalTestKey = {
	/* p */
	512,
	prime512,
	/* g */
	2,
	{ 0x03 },
	/* y */
	512,
	{ 0x26, 0x26, 0x98, 0x3C, 0x25, 0xD5, 0x80, 0xDA,
	  0x84, 0xA8, 0xA7, 0xFA, 0xF1, 0x68, 0x62, 0xB0,
	  0x01, 0x90, 0x82, 0xBC, 0x3C, 0xDC, 0x78, 0x57,
	  0x62, 0x2C, 0x52, 0x8D, 0x74, 0x08, 0xA4, 0x4C,
	  0xAA, 0x01, 0xF2, 0x89, 0x23, 0xAA, 0xF6, 0x44,
	  0x67, 0xF1, 0x76, 0x54, 0x84, 0xE5, 0xC6, 0xA7,
	  0x01, 0xE7, 0x78, 0x01, 0xFD, 0x5F, 0x10, 0x2B,
	  0xB1, 0x06, 0x2E, 0x9C, 0x63, 0x0B, 0x2B, 0x21 },
	/* x */
	512,
	{ 0xCD, 0x27, 0x3A, 0x8F, 0x3D, 0x8E, 0x14, 0x54,
	  0xFF, 0xB9, 0x3A, 0xB1, 0x11, 0x3C, 0xDF, 0xBD,
	  0x50, 0x78, 0xC4, 0x55, 0x24, 0x5C, 0xAC, 0xF2,
	  0x45, 0x06, 0xE7, 0xBE, 0xAC, 0x7E, 0xD7, 0xCC,
	  0x76, 0x14, 0x9C, 0x84, 0xF4, 0xD6, 0x0C, 0xF7,
	  0x14, 0x40, 0xE5, 0x56, 0xFA, 0xE7, 0xA7, 0x42,
	  0x54, 0x64, 0xDF, 0xE4, 0xD1, 0x92, 0x83, 0x01,
	  0x54, 0x36, 0x37, 0x22, 0xF5, 0x1B, 0xB9, 0x36 }
	};

/* If we're doing a self-test we use the following fixed k (for the
   signature) and kRandom (for the encryption) data rather than a randomly-
   generated value.  The k value is the DSA one from FIPS 186, which seems as
   good as any */

static BYTE kVal[] = {
	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF
	};

static BYTE kRandomVal[] = {
	0x2A, 0x7C, 0x01, 0xFD, 0x62, 0xF7, 0x43, 0x13,
	0x36, 0xFE, 0xE8, 0xF1, 0x68, 0xB2, 0xA2, 0x2F,
	0x76, 0x50, 0xA1, 0x2C, 0x3E, 0x64, 0x8E, 0xFE,
	0x04, 0x58, 0x7F, 0xDE, 0xC2, 0x34, 0xE5, 0x79,
	0xE9, 0x45, 0xB0, 0xDD, 0x5E, 0x56, 0xD7, 0x82,
	0xEF, 0x93, 0xEF, 0x5F, 0xD0, 0x71, 0x8B, 0xA1,
	0x3E, 0xA0, 0x55, 0x6A, 0xB9, 0x6E, 0x72, 0xFE,
	0x17, 0x03, 0x95, 0x50, 0xB7, 0xA1, 0x11, 0xBA
	};

int elgamalInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int elgamalEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int elgamalDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int elgamalSign( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int elgamalSigCheck( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int elgamalSelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	CRYPT_PKCINFO_ELGAMAL *egKey;
	const CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_ELGAMAL, CRYPT_MODE_PKC,
								0, NULL, NULL, 64, 128, 512, 0, 0, 0,
								NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								NULL, NULL, NULL, NULL, CRYPT_ERROR };
	BYTE buffer[ 192 ];
	int status;

	/* Allocate room for the public-key components */
	if( ( egKey = ( CRYPT_PKCINFO_ELGAMAL * ) malloc( sizeof( CRYPT_PKCINFO_ELGAMAL ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the BigNum information and components */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxPKC.param1 = BN_new();
	cryptInfo.ctxPKC.param2 = BN_new();
	cryptInfo.ctxPKC.param3 = BN_new();
	cryptInfo.ctxPKC.param4 = BN_new();
	cryptInitComponents( egKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( egKey->p, elgamalTestKey.p, elgamalTestKey.pLen );
	cryptSetComponent( egKey->g, elgamalTestKey.g, elgamalTestKey.gLen );
	cryptSetComponent( egKey->y, elgamalTestKey.y, elgamalTestKey.yLen );
	cryptSetComponent( egKey->x, elgamalTestKey.x, elgamalTestKey.xLen );
	cryptInfo.capabilityInfo = &capabilityInfo;

	elgamalInitKey( &cryptInfo, egKey, CRYPT_UNUSED );

	/* Perform a test a sig generation/check and test en/decryption */
	memset( buffer, '*', 20 );
	status = elgamalSign( &cryptInfo, buffer, 42 );
	if( !cryptStatusError( status ) )
		{
		memmove( buffer + 20, buffer, status );
		memset( buffer, '*', 20 );
		status = elgamalSigCheck( &cryptInfo, buffer, CRYPT_USE_DEFAULT );
		}
	if( status != CRYPT_OK )
		status = CRYPT_SELFTEST;
	else
		{
#if 0	/* BN_exp() is currently broken */
		memset( buffer, 0, 64 );
		memcpy( buffer, "abcde", 5 );
		if( ( status = elgamalEncrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT ) ) == CRYPT_OK )
			status = elgamalDecrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT );
		if( status != CRYPT_OK || memcmp( buffer, "abcde", 5 ) )
			status = CRYPT_SELFTEST;
#endif /* 0 */
		}

	/* Clean up */
	cryptDestroyComponents( egKey );
	BN_clear_free( cryptInfo.ctxPKC.param1 );
	BN_clear_free( cryptInfo.ctxPKC.param2 );
	BN_clear_free( cryptInfo.ctxPKC.param3 );
	BN_clear_free( cryptInfo.ctxPKC.param4 );
	zeroise( &cryptInfo, sizeof( CRYPT_INFO ) );
	free( egKey );

	return( status );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the Elgamal routines */

/****************************************************************************
*																			*
*						Elgamal Signature/sig.check Routines				*
*																			*
****************************************************************************/

/* Since Elgamal signature generation produces two values and the
   cryptEncrypt() model only provides for passing a byte string in and out
   (or, more specifically, the internal bignum data can't be exported to the
   outside world), we need to encode the resulting data into a flat format.
   This is done by encoding the output as an Elgamal-Sig record:

	Elgamal-Sig ::= SEQUENCE {
		r	INTEGER,
		s	INTEGER
		}

   The input is the 160-bit hash, usually SHA but possibly also RIPEMD-160.

   Signature checking is even uglier, since we need to pass in the hash as
   well as the composite signature (in effect we need to do what
   cryptCheckSignature() does).  We do this by appending the 160-bit hash to
   the composite signature when we call cryptCheckSignature() */

/* The size of the Elgamal signature hash component is 160 bits */

#define ELGAMAL_SIGPART_SIZE	20

/* Sign a single block of data  */

int elgamalSign( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.egParam_p, *g = cryptInfo->ctxPKC.egParam_g;
	BIGNUM *x = cryptInfo->ctxPKC.egParam_x;
	BIGNUM *tmp, *k, *r, *s, *phi_p, *kInv;
	BYTE *bufPtr = buffer;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int status = CRYPT_OK;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value which
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k which avoids
	   having to call generateBignum().  This is a somewhat ugly use of
	   'magic numbers', but it's safe because cryptEncrypt() won't allow any
	   value for noBytes than CRYPT_USE_DEFAULT so there's no way an external
	   caller can pass in a value like this */
	k = BN_new();
	if( noBytes == 42 )
		BN_bin2bn( kVal, ELGAMAL_SIGPART_SIZE, k );
	else
		{
		status = generateBignum( k, bytesToBits( ELGAMAL_SIGPART_SIZE ),
								 0x80, 0 );
		if( cryptStatusError( status ) )
			{
			BN_clear_free( k );
			BN_CTX_free( bnCTX );
			return( status );
			}
		}

	/* Initialise the bignums */
	tmp = BN_new();
	r = BN_new();
	s = BN_new();
	phi_p = BN_new();

	/* Generate phi( p ) and use it to get k, k < p-1 and k relatively prime
	   to p-1.  Since (p-1)/2 is prime, the initial choice for k will be
	   divisible by (p-1)/2 with probability 2/(p-1), so we'll do at most two
	   gcd operations with very high probability.  A k of (p-3)/2 will be
	   chosen with probability 3/(p-1), and all other numbers from 1 to p-1
	   will be chosen with probability 2/(p-1), giving a nearly uniform
	   distribution of exponents */
	BN_copy( phi_p, p );
	BN_sub_word( phi_p, 1 );			/* phi( p ) = p - 1 */
	BN_mod( k, k, phi_p, bnCTX );		/* Reduce k to the correct range */
	BN_gcd( r, k, phi_p, bnCTX );
	while( !BN_is_one( r ) )
		{
		BN_sub_word( k, 1 );
		BN_gcd( r, k, phi_p, bnCTX );
		}

	/* Move the data from the buffer into a bignum */
	BN_bin2bn( bufPtr, ELGAMAL_SIGPART_SIZE, s );

	/* r = g^k mod p */
	BN_mod_exp( r, g, k, p, bnCTX );	/* r = g^k mod p */

	/* s = ( k^-1 * ( hash - x * r ) ) mod phi( p ) */
	kInv = BN_mod_inverse( k, phi_p, bnCTX );/* k = ( k^-1 ) mod phi( p ) */
	BN_mod_mul( tmp, x, r, phi_p, bnCTX );/* tmp = ( x * r ) mod phi( p ) */
	if( BN_cmp( s, tmp ) < 0 )			/* if hash < x * r */
		BN_add( s, s, phi_p );			/*   hash = hash + phi( p ) (fast mod) */
	BN_sub( s, s, tmp );				/* s = hash - x * r */
	BN_mod_mul( s, s, kInv, phi_p, bnCTX );/* s = ( s * k^-1 ) mod phi( p ) */

	/* Encode the result as a DL data block */
	length = encodeDLValues( buffer, r, s );

	/* Destroy sensitive data */
	BN_clear_free( kInv );
	BN_clear_free( tmp );
	BN_clear_free( k );
	BN_clear_free( r );
	BN_clear_free( s );
	BN_clear_free( phi_p );

	BN_CTX_free( bnCTX );

	if( noBytes == CRYPT_USE_DEFAULT )
		length = CRYPT_OK;	/* External calls don't return a length */
	return( ( status == -1 ) ? CRYPT_PKCCRYPT : length );
	}

/* Signature check a single block of data */

int elgamalSigCheck( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.egParam_p, *g = cryptInfo->ctxPKC.egParam_g;
	BIGNUM *y = cryptInfo->ctxPKC.egParam_y;
	BIGNUM *r, *s;
	int	status = CRYPT_OK;

	UNUSED( noBytes );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Decode the values from a DL data block and make sure r and s are
	   valid */
	status = decodeDLValues( buffer + ELGAMAL_SIGPART_SIZE, &r, &s );
	if( cryptStatusError( status ) )
		{
		BN_CTX_free( bnCTX );
		return( status );
		}

	/* Verify that 0 < r < p.  If this check isn't done, an adversary can
	   forge signatures given one existing valid signature for a key */
	if( BN_is_zero( r ) || BN_cmp( r, p ) >= 0 )
		status = CRYPT_BADSIG;
	else
		{
		BIGNUM *hash, *u1, *u2;

		hash = BN_new();
		u1 = BN_new();
		u2 = BN_new();

		BN_bin2bn( buffer, ELGAMAL_SIGPART_SIZE, hash );

		/* u1 = ( y^r * r^s ) mod p */
		BN_mod_exp( y, y, r, p, bnCTX );	/* y' = ( y^r ) mod p */
		BN_mod_exp( r, r, s, p, bnCTX );	/* r' = ( r^s ) mod p */
		BN_mod_mul( u1, y, r, p, bnCTX );	/* u1 = ( y' * r' ) mod p */

		/* u2 = g^hash mod p */
		BN_mod_exp( u2, g, hash, p, bnCTX );

		/* if u1 == u2, signature is good */
		if( BN_cmp( u1, u2 ) && cryptStatusOK( status ) )
			status = CRYPT_BADSIG;

		BN_clear_free( hash );
		BN_clear_free( u2 );
		BN_clear_free( u1 );
		}

	/* Destroy sensitive data */
	BN_clear_free( r );
	BN_clear_free( s );

	BN_CTX_free( bnCTX );

	return( ( status == -1 ) ? CRYPT_PKCCRYPT : status );
	}

/****************************************************************************
*																			*
*						Elgamal En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt a single block of data  */

int elgamalEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.egParam_p, *g = cryptInfo->ctxPKC.egParam_g;
	BIGNUM *y = cryptInfo->ctxPKC.egParam_y;
	BIGNUM *tmp, *k, *r, *s, *phi_p;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int status = CRYPT_OK;

return( CRYPT_ERROR );	/* BN_exp() is broken */

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value which
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k which avoids
	   having to call generateBignum().  This is a somewhat ugly use of
	   'magic numbers', but it's safe because cryptEncrypt() won't allow any
	   value for noBytes than CRYPT_USE_DEFAULT so there's no way an external
	   caller can pass in a value like this */
	k = BN_new();
	if( noBytes == 42 )
		BN_bin2bn( kRandomVal, length, k );
	else
		{
		status = generateBignum( k, length, 0x80, 0 );
		if( cryptStatusError( status ) )
			{
			BN_clear_free( k );
			BN_CTX_free( bnCTX );
			return( status );
			}
		}

	/* Initialise the bignums */
	tmp = BN_new();
	r = BN_new();
	s = BN_new();
	phi_p = BN_new();

	/* Generate phi( p ) and use it to get k, k < p-1 and k relatively prime
	   to p-1.  Since (p-1)/2 is prime, the initial choice for k will be
	   divisible by (p-1)/2 with probability 2/(p-1), so we'll do at most two
	   gcd operations with very high probability.  A k of (p-3)/2 will be
	   chosen with probability 3/(p-1), and all other numbers from 1 to p-1
	   will be chosen with probability 2/(p-1), giving a nearly uniform
	   distribution of exponents */
	BN_copy( phi_p, p );
	BN_sub_word( phi_p, 1 );			/* phi( p ) = p - 1 */
	BN_mod( k, k, phi_p, bnCTX );		/* Reduce k to the correct range */
	BN_gcd( s, k, phi_p, bnCTX );
	while( !BN_is_one( s ) )
		{
		BN_sub_word( k, 1 );
		BN_gcd( s, k, phi_p, bnCTX );
		}

	/* Move the data from the buffer into a bignum */
	BN_bin2bn( buffer, length, tmp );

	/* s = ( y^k * M ) mod p */
	BN_mod_exp( r, y, k, p, bnCTX );	/* y' = y^k mod p */
	BN_mod_mul( s, r, tmp, p, bnCTX );	/* s = y'M mod p */

	/* r = g^k mod p */
	BN_mod_exp( r, g, k, p, bnCTX );

	/* Encode the result as a DL data block */
	length = encodeDLValues( buffer, r, s );

	/* Destroy sensitive data */
	BN_clear_free( tmp );
	BN_clear_free( k );
	BN_clear_free( r );
	BN_clear_free( s );
	BN_clear_free( phi_p );

	BN_CTX_free( bnCTX );

	if( noBytes == CRYPT_USE_DEFAULT )
		length = CRYPT_OK;	/* External calls don't return a length */

	return( ( status == CRYPT_OK ) ? length : CRYPT_PKCCRYPT );
	}

/* Decrypt a single block of data */

int elgamalDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.egParam_p, *x = cryptInfo->ctxPKC.egParam_x;
	BIGNUM *tmp, *r, *s, *dummy;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int status = CRYPT_OK;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Decode the values from a DL data block and make sure r and s are
	   valid */
	status = decodeDLValues( buffer, &r, &s );
	if( cryptStatusError( status ) )
		{
		BN_CTX_free( bnCTX );
		return( status );
		}

	/* Initialize the bignums */
	tmp = BN_new();
	dummy = BN_new();

	/* M = ( s / ( r^x ) ) mod p */
#if 1
	BN_exp( tmp, r, x, bnCTX );				/* M = r^x */
	BN_div( r, dummy, s, tmp, bnCTX );		/* M = s / r^x */
	BN_mod( tmp, r, p, bnCTX );				/* M = ( s / r^x ) mod p */
#else	/* Saves a temporary */
	BN_exp( r, r, x, bnCTX );				/* r' = r^x */
	BN_div( r, dummy, s, r, bnCTX );		/* r'' = s / r' */
	BN_mod( s, r, p, bnCTX );				/* m = r'' mod p */
#endif
#if 0
	/* This may be faster if an inv + mul is faster than a div, especially
	   since we can use a combined modmul, however the current inv uses lots
	   of divs and muls in a loop which probably isn't faster */
	BN_mod_exp( r, r, x, p, bnCTX );		/* r' = r^x */
	tmp = BN_mod_inverse( r, p, bnCTX );	/* r'' = r'^-1 */
	BN_mod_mul( s, s, tmp, p, bnCTX );		/* s = s * r'^-1 mod p */
#endif

	/* Copy the result to the output buffer and destroy sensitive data */
	BN_bn2bin( tmp, buffer );
	BN_clear_free( tmp );
	BN_clear_free( r );
	BN_clear_free( s );
	BN_clear_free( dummy );

	BN_CTX_free( bnCTX );

	if( noBytes == CRYPT_USE_DEFAULT )
		length = CRYPT_OK;	/* External calls don't return a length */

	return( ( status == CRYPT_OK ) ? length : CRYPT_PKCCRYPT );
	}

/****************************************************************************
*																			*
*						Elgamal Key Management Routines						*
*																			*
****************************************************************************/

/* Load Elgamal public/private key components into an encryption context */

int elgamalInitKey( CRYPT_INFO *cryptInfo, const void *key, const int loadType )
	{
	CRYPT_PKCINFO_ELGAMAL *egKey = ( CRYPT_PKCINFO_ELGAMAL * ) key;
	int pBits, gBits, status = CRYPT_OK;

	/* Load the key component from the external representation into the
	   internal BigNums unless we're doing an internal load */
	if( loadType != LOAD_INTERNAL_PUBLIC && loadType != LOAD_INTERNAL_PRIVATE )
		{
		cryptInfo->ctxPKC.isPublicKey = egKey->isPublicKey;

		/* If a key size is given, use the default public values for p and g */
		if( egKey->endianness > CRYPT_COMPONENTS_LITTLENDIAN )
			{
			int index, size = egKey->endianness;

			/* Determine which parameters to use */
			for( index = 0; egPublicValues[ index ].primeLen && \
				 egPublicValues[ index ].primeLen != size; index++ );
			if( !egPublicValues[ index ].primeLen )
				return( CRYPT_BADPARM2 );

			/* Load them into the bignums */
			BN_bin2bn( ( BYTE * ) egPublicValues[ index ].prime,
					   bitsToBytes( size ), cryptInfo->ctxPKC.dhParam_p );
			BN_bin2bn( ( BYTE * ) egPublicValues[ index ].base, 1,
					   cryptInfo->ctxPKC.dhParam_g );
			}
		else
			{
			/* Load the key components into the bignums */
			BN_bin2bn( egKey->p, bitsToBytes( egKey->pLen ),
					   cryptInfo->ctxPKC.egParam_p );
			BN_bin2bn( egKey->g, bitsToBytes( egKey->gLen ),
					   cryptInfo->ctxPKC.egParam_g );
			}
		BN_bin2bn( egKey->y, bitsToBytes( egKey->yLen ),
				   cryptInfo->ctxPKC.egParam_y );
		if( !egKey->isPublicKey )
			BN_bin2bn( egKey->x, bitsToBytes( egKey->xLen ),
					   cryptInfo->ctxPKC.egParam_x );
		}
	cryptInfo->ctxPKC.lastPublicComponent = EG_LAST_PUBLIC;
	cryptInfo->ctxPKC.lastPublicMontCTX = 0;

	/* Make sure the necessary key parameters have been initialised and that
	   the g is within acceptable limits.  This code used to check for g < 3
	   (g = 2 allows signatures to be forged) but this didn't allow PGP 5
	   keys to be loaded (PGP 5 uses Elgamal only for encryption) */
	if( BN_is_zero( cryptInfo->ctxPKC.egParam_p ) || \
		BN_is_zero( cryptInfo->ctxPKC.egParam_g ) || \
/*		BN_cmp_word( cryptInfo->ctxPKC.egParam_g, 2 ) < 0 || \ */
		BN_is_zero( cryptInfo->ctxPKC.egParam_y ) || \
		( !cryptInfo->ctxPKC.isPublicKey && BN_is_zero( cryptInfo->ctxPKC.egParam_x ) ) )
		status = CRYPT_BADPARM2;

	/* Make sure the key paramters are valid: p > 510 (nominally 512 bits),
	   2 <= g <= p-2 (the bitcount is a quick check which works for all but
	   outrageous values of g) */
	pBits = BN_num_bits( cryptInfo->ctxPKC.egParam_p );
	gBits = BN_num_bits( cryptInfo->ctxPKC.egParam_g );
	if( pBits < 510 || gBits < 2 || gBits >= pBits )
		status = CRYPT_BADPARM2;

	/* Set the keysize and generate a key ID for this key */
	cryptInfo->ctxPKC.keySizeBits = BN_num_bits( cryptInfo->ctxPKC.egParam_p );
	if( cryptStatusOK( status ) )
		status = calculateKeyID( CRYPT_ALGO_ELGAMAL, &cryptInfo->ctxPKC,
								 cryptInfo->ctxPKC.keyID );

	return( status );
	}

/****************************************************************************
*																			*
*							Elgamal Key Generation Routines					*
*																			*
****************************************************************************/

/* Turn on this define to use the SKIP (shared DH) constants for p.  This
   allows much faster keygen, but voids your warranty for security */
/* #define USE_SKIP_SHARED_VALUES */

/* Generate an Elgamal key into an encryption context */

int elgamalGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits )
	{
	BN_CTX *bnCTX;
#ifdef USE_SKIP_SHARED_VALUES
	int index;
#endif /* USE_SKIP_SHARED_VALUES */
	int status;

	/* Determine how many bits to give to p */
	cryptInfo->ctxPKC.keySizeBits = keySizeBits;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

#ifdef USE_SKIP_SHARED_VALUES
	/* Determine which parameters to use */
	for( index = 0; egPublicValues[ index ].primeLen && \
		 egPublicValues[ index ].primeLen != keySizeBits;
		 index++ );
	status = ( egPublicValues[ index ].primeLen ) ? CRYPT_OK : CRYPT_ERROR;

	/* Load them into the context */
	if( cryptStatusOK( status ) )
		{
		BN_bin2bn( ( BYTE * ) egPublicValues[ index ].prime,
				   cryptInfo->userKeyLength, cryptInfo->ctxPKC.egParam_p );
		BN_set_word( cryptInfo->ctxPKC.egParam_g,
					 egPublicValues[ index ].base[ 0 ] );
		}
#else
	/*	Generate large prime p and generator g.  We don't care about q */
	status = generateDLvalues( cryptInfo->ctxPKC.egParam_p, keySizeBits, NULL,
							   0, cryptInfo->ctxPKC.egParam_g, cryptInfo );
#endif /* USE_SKIP_SHARED_VALUES */

	/* Generate a random x and check that x < p by clearing the most
	   significant bits in x until x < p.
	   NOTE: Should use the DH x-generation routines, but this isn't done
			 at the moment because Elgamal doesn't work anyway due to bugs in
			 the SSLeay BN code */
	if( cryptStatusOK( status ) )
		status = generateBignum( cryptInfo->ctxPKC.egParam_x, keySizeBits,
								 0xE0, 0 );
	if( cryptStatusOK( status ) )
		{
		int msb;

		for( msb = keySizeBits - 1;
			 BN_cmp( cryptInfo->ctxPKC.egParam_p,
					 cryptInfo->ctxPKC.egParam_x ) <= 0 && msb >= 0; msb-- )
			BN_clear_bit( cryptInfo->ctxPKC.egParam_x, msb );

		/* Calculate y = g^x mod p */
		BN_mod_exp( cryptInfo->ctxPKC.egParam_y, cryptInfo->ctxPKC.egParam_g,
					cryptInfo->ctxPKC.egParam_x, cryptInfo->ctxPKC.egParam_p, bnCTX );
		}

	BN_CTX_free( bnCTX );

	/* Generate a keyID for the new key */
	if( cryptStatusOK( status ) )
		{
		cryptInfo->ctxPKC.isPublicKey = FALSE;
		cryptInfo->ctxPKC.lastPublicComponent = EG_LAST_PUBLIC;
		cryptInfo->ctxPKC.lastPublicMontCTX = 0;
		status = calculateKeyID( CRYPT_ALGO_ELGAMAL, &cryptInfo->ctxPKC,
								 cryptInfo->ctxPKC.keyID );
		}

	return( status );
	}
