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

/****************************************************************************
*																			*
*							Elgamal Self-test Routines						*
*																			*
****************************************************************************/

/* Test the Elgamal implementation using the sample key from FIPS 186.  
   Because a lot of the high-level encryption routines don't exist yet, we 
   cheat a bit and set up a dummy encryption context with just enough 
   information for the following code to work */

typedef struct {
	int pLen; BYTE p[ 64 ];
	int qLen; BYTE q[ 20 ];
	int gLen; BYTE g[ 64 ];
	int xLen; BYTE x[ 20 ];
	int yLen; BYTE y[ 64 ];
	} DLP_PRIVKEY;

static const DLP_PRIVKEY dlpTestKey = {
	/* p */
	512,
	{ 0x8D, 0xF2, 0xA4, 0x94, 0x49, 0x22, 0x76, 0xAA,
	  0x3D, 0x25, 0x75, 0x9B, 0xB0, 0x68, 0x69, 0xCB,
	  0xEA, 0xC0, 0xD8, 0x3A, 0xFB, 0x8D, 0x0C, 0xF7,
	  0xCB, 0xB8, 0x32, 0x4F, 0x0D, 0x78, 0x82, 0xE5,
	  0xD0, 0x76, 0x2F, 0xC5, 0xB7, 0x21, 0x0E, 0xAF,
	  0xC2, 0xE9, 0xAD, 0xAC, 0x32, 0xAB, 0x7A, 0xAC,
	  0x49, 0x69, 0x3D, 0xFB, 0xF8, 0x37, 0x24, 0xC2,
	  0xEC, 0x07, 0x36, 0xEE, 0x31, 0xC8, 0x02, 0x91 },
	/* q */
	160,
	{ 0xC7, 0x73, 0x21, 0x8C, 0x73, 0x7E, 0xC8, 0xEE,
	  0x99, 0x3B, 0x4F, 0x2D, 0xED, 0x30, 0xF4, 0x8E,
	  0xDA, 0xCE, 0x91, 0x5F },
	/* g */
	512,
	{ 0x62, 0x6D, 0x02, 0x78, 0x39, 0xEA, 0x0A, 0x13,
	  0x41, 0x31, 0x63, 0xA5, 0x5B, 0x4C, 0xB5, 0x00,
	  0x29, 0x9D, 0x55, 0x22, 0x95, 0x6C, 0xEF, 0xCB,
	  0x3B, 0xFF, 0x10, 0xF3, 0x99, 0xCE, 0x2C, 0x2E,
	  0x71, 0xCB, 0x9D, 0xE5, 0xFA, 0x24, 0xBA, 0xBF,
	  0x58, 0xE5, 0xB7, 0x95, 0x21, 0x92, 0x5C, 0x9C,
	  0xC4, 0x2E, 0x9F, 0x6F, 0x46, 0x4B, 0x08, 0x8C,
	  0xC5, 0x72, 0xAF, 0x53, 0xE6, 0xD7, 0x88, 0x02 },
	/* y */
	160,
	{ 0x20, 0x70, 0xB3, 0x22, 0x3D, 0xBA, 0x37, 0x2F,
	  0xDE, 0x1C, 0x0F, 0xFC, 0x7B, 0x2E, 0x3B, 0x49,
	  0x8B, 0x26, 0x06, 0x14 },
	/* x */
	512,
	{ 0x19, 0x13, 0x18, 0x71, 0xD7, 0x5B, 0x16, 0x12,
	  0xA8, 0x19, 0xF2, 0x9D, 0x78, 0xD1, 0xB0, 0xD7,
	  0x34, 0x6F, 0x7A, 0xA7, 0x7B, 0xB6, 0x2A, 0x85,
	  0x9B, 0xFD, 0x6C, 0x56, 0x75, 0xDA, 0x9D, 0x21,
	  0x2D, 0x3A, 0x36, 0xEF, 0x16, 0x72, 0xEF, 0x66,
	  0x0B, 0x8C, 0x7C, 0x25, 0x5C, 0xC0, 0xEC, 0x74,
	  0x85, 0x8F, 0xBA, 0x33, 0xF4, 0x4C, 0x06, 0x69,
	  0x96, 0x30, 0xA7, 0x6B, 0x03, 0x0E, 0xE3, 0x33 }
	};

/* If we're doing a self-test we use the following fixed k (for the
   signature) and kRandom (for the encryption) data rather than a randomly-
   generated value.  The k value is the DSA one from FIPS 186, which seems as
   good as any */

static const BYTE kVal[] = {
	0x35, 0x8D, 0xAD, 0x57, 0x14, 0x62, 0x71, 0x0F,
	0x50, 0xE2, 0x54, 0xCF, 0x1A, 0x37, 0x6B, 0x2B,
	0xDE, 0xAA, 0xDF, 0xBF
	};

static const BYTE kRandomVal[] = {
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
	CRYPT_PKCINFO_DLP *egKey;
	static const CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_ELGAMAL, 0, NULL, 
													64, 128, 512, 0 };
	BYTE buffer[ 192 ];
	int status;

	/* Set up the key components */
	if( ( egKey = ( CRYPT_PKCINFO_DLP * ) malloc( sizeof( CRYPT_PKCINFO_DLP ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	cryptInitComponents( egKey, CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( egKey->p, dlpTestKey.p, dlpTestKey.pLen );
	cryptSetComponent( egKey->g, dlpTestKey.g, dlpTestKey.gLen );
	cryptSetComponent( egKey->q, dlpTestKey.q, dlpTestKey.qLen );
	cryptSetComponent( egKey->y, dlpTestKey.y, dlpTestKey.yLen );
	cryptSetComponent( egKey->x, dlpTestKey.x, dlpTestKey.xLen );

	/* Initialise the BigNum information and components */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxPKC.param1 = BN_new();
	cryptInfo.ctxPKC.param2 = BN_new();
	cryptInfo.ctxPKC.param3 = BN_new();
	cryptInfo.ctxPKC.param4 = BN_new();
	cryptInfo.ctxPKC.param5 = BN_new();
	cryptInfo.capabilityInfo = &capabilityInfo;

	elgamalInitKey( &cryptInfo, egKey, CRYPT_UNUSED );

	/* Perform a test a sig generation/check and test en/decryption */
	memset( buffer, '*', 20 );
	status = elgamalSign( &cryptInfo, buffer, -1 );
	if( !cryptStatusError( status ) )
		{
		memmove( buffer + 20, buffer, status );
		memset( buffer, '*', 20 );
		status = elgamalSigCheck( &cryptInfo, buffer, 20 + status );
		}
	if( status != CRYPT_OK )
		status = CRYPT_ERROR;
	else
		{
		memset( buffer, 0, 64 );
		memcpy( buffer, "abcde", 5 );
		status = elgamalEncrypt( &cryptInfo, buffer, -1 );
		if( !cryptStatusError( status ) )
			status = elgamalDecrypt( &cryptInfo, buffer, status );
		if( status != CRYPT_OK || memcmp( buffer, "abcde", 5 ) )
			status = CRYPT_ERROR;
		}

	/* Clean up */
	cryptDestroyComponents( egKey );
	BN_clear_free( cryptInfo.ctxPKC.param1 );
	BN_clear_free( cryptInfo.ctxPKC.param2 );
	BN_clear_free( cryptInfo.ctxPKC.param3 );
	BN_clear_free( cryptInfo.ctxPKC.param4 );
	BN_clear_free( cryptInfo.ctxPKC.param5 );
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
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *g = cryptInfo->ctxPKC.dlpParam_g;
	BIGNUM *x = cryptInfo->ctxPKC.dlpParam_x;
	BIGNUM *tmp, *k, *r, *s, *phi_p, *kInv;
	BYTE *bufPtr = buffer;
	int length, status = CRYPT_OK;

	assert( noBytes == ELGAMAL_SIGPART_SIZE || noBytes == -1 );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value which
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k which avoids
	   having to call generateBignum().  This is a somewhat ugly use of 
	   'magic numbers', but it's safe because cryptEncrypt() won't allow any 
	   such value for noBytes so there's no way an external caller can pass 
	   in a value like this */
	k = BN_new();
	if( noBytes == -1 )
		BN_bin2bn( ( BYTE * ) kVal, ELGAMAL_SIGPART_SIZE, k );
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

	return( ( status == -1 ) ? CRYPT_ERROR_FAILED : length );
	}

/* Signature check a single block of data */

int elgamalSigCheck( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *g = cryptInfo->ctxPKC.dlpParam_g;
	BIGNUM *y = cryptInfo->ctxPKC.dlpParam_y;
	BIGNUM *r, *s;
	int	status;

	UNUSED( noBytes );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

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
		status = CRYPT_ERROR_SIGNATURE;
	else
		{
		BIGNUM *hash, *u1, *u2;

		hash = BN_new();
		u1 = BN_new();
		u2 = BN_new();

		BN_bin2bn( buffer, ELGAMAL_SIGPART_SIZE, hash );

		/* u1 = ( y^r * r^s ) mod p */
		BN_mod_exp( u1, y, r, p, bnCTX );	/* y' = ( y^r ) mod p */
		BN_mod_exp( r, r, s, p, bnCTX );	/* r' = ( r^s ) mod p */
		BN_mod_mul( u1, u1, r, p, bnCTX );	/* u1 = ( y' * r' ) mod p */

		/* u2 = g^hash mod p */
		BN_mod_exp( u2, g, hash, p, bnCTX );

		/* if u1 == u2, signature is good */
		if( BN_cmp( u1, u2 ) && cryptStatusOK( status ) )
			status = CRYPT_ERROR_SIGNATURE;

		BN_clear_free( hash );
		BN_clear_free( u2 );
		BN_clear_free( u1 );
		}

	/* Destroy sensitive data */
	BN_clear_free( r );
	BN_clear_free( s );

	BN_CTX_free( bnCTX );

	return( status );
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
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *g = cryptInfo->ctxPKC.dlpParam_g;
	BIGNUM *y = cryptInfo->ctxPKC.dlpParam_y;
	BIGNUM *tmp, *k, *r, *s, *phi_p;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );

	assert( noBytes == length || noBytes == -1 );

	if( length > ( CRYPT_MAX_PKCSIZE / 2 ) - 10 )
		/* The export key mechanism doesn't currently expect quite this much 
		   data to be returned.  This is just a temporary workaround, we 
		   should really replace the straight PKCS #1 mechanism with a DLP-
		   key-wrap-specific alternative */
		return( CRYPT_ERROR_FAILED );

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Generate the secret random value k.  During the initial self-test
	   the random data pool may not exist yet, and may in fact never exist in
	   a satisfactory condition if there isn't enough randomness present in
	   the system to generate cryptographically strong random numbers.  To
	   bypass this problem, if the caller passes in a noBytes value which
	   can't be passed in via a call to cryptEncrypt() we know it's an
	   internal self-test call and use a fixed bit pattern for k which avoids
	   having to call generateBignum().  This is a somewhat ugly use of 
	   'magic numbers', but it's safe because cryptEncrypt() won't allow any 
	   such value for noBytes so there's no way an external caller can pass 
	   in a value like this */
	k = BN_new();
	if( noBytes == -1 )
		BN_bin2bn( ( BYTE * ) kRandomVal, length, k );
	else
		{
		int status = generateBignum( k, length, 0x80, 0 );
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

	/* Since the output size isn't the same as the input size, we return the
	   new size */
	return( length );
	}

/* Decrypt a single block of data */

int elgamalDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.dlpParam_p;
	BIGNUM *x = cryptInfo->ctxPKC.dlpParam_x;
	BIGNUM *tmp, *r, *s;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int status;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_ERROR_MEMORY );

	/* Decode the values from a DL data block and make sure r and s are
	   valid */
	status = decodeDLValues( buffer, &r, &s );
	if( cryptStatusError( status ) )
		{
		BN_CTX_free( bnCTX );
		return( status );
		}
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */

	/* M = ( s / ( r^x ) ) mod p */
	BN_mod_exp( r, r, x, p, bnCTX );		/* r' = r^x */
	tmp = BN_mod_inverse( r, p, bnCTX );	/* r'' = r'^-1 */
	BN_mod_mul( s, s, tmp, p, bnCTX );		/* s = s * r'^-1 mod p */

	/* Copy the result to the output buffer and destroy sensitive data.  
	   Since the bignum code performs leading-zero truncation, we have to 
	   adjust where we copy the result to in the buffer to take into account 
	   extra zero bytes which aren't extracted from the bignum */
	BN_bn2bin( s, buffer + ( length - BN_num_bytes( s ) ) );
	BN_clear_free( tmp );
	BN_clear_free( r );
	BN_clear_free( s );

	BN_CTX_free( bnCTX );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Elgamal Key Management Routines						*
*																			*
****************************************************************************/

/* Load Elgamal public/private key components into an encryption context */

int elgamalInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	CRYPT_PKCINFO_DLP *egKey = ( CRYPT_PKCINFO_DLP * ) key;
	int status;

	/* Load the key component from the external representation into the
	   internal BigNums unless we're doing an internal load */
	if( keyLength != sizeof( PKCINFO_LOADINTERNAL ) )
		{
		cryptInfo->ctxPKC.isPublicKey = egKey->isPublicKey;

		/* Load the key components into the bignums */
		BN_bin2bn( egKey->p, bitsToBytes( egKey->pLen ),
				   cryptInfo->ctxPKC.dlpParam_p );
		BN_bin2bn( egKey->g, bitsToBytes( egKey->gLen ),
				   cryptInfo->ctxPKC.dlpParam_g );
		BN_bin2bn( egKey->q, bitsToBytes( egKey->qLen ),
				   cryptInfo->ctxPKC.dlpParam_q );
		BN_bin2bn( egKey->y, bitsToBytes( egKey->yLen ),
				   cryptInfo->ctxPKC.dlpParam_y );
		if( !egKey->isPublicKey )
			BN_bin2bn( egKey->x, bitsToBytes( egKey->xLen ),
					   cryptInfo->ctxPKC.dlpParam_x );
		}

	/* Check the parameters and calculate the key ID */
	status = checkDLParams( cryptInfo );
	if( cryptStatusError( status ) )
		return( status );
	cryptInfo->ctxPKC.keySizeBits = BN_num_bits( cryptInfo->ctxPKC.dlpParam_p );
	return( calculateKeyID( cryptInfo ) );
	}

/* Generate an Elgamal key into an encryption context */

int elgamalGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits )
	{
	int status;

	status = generateDLPKey( cryptInfo, keySizeBits, CRYPT_USE_DEFAULT );
	if( cryptStatusError( status ) )
		return( status );
	return( calculateKeyID( cryptInfo ) );
	}
