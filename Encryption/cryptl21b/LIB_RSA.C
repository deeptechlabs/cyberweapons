/****************************************************************************
*																			*
*						cryptlib RSA Encryption Routines					*
*						Copyright Peter Gutmann 1993-1999					*
*																			*
****************************************************************************/

/* I suppose if we all used pure RSA, the Illuminati would blackmail God into
   putting a trapdoor into the laws of mathematics.
														-- Lyle Seaman */
#include <stdlib.h>
#include <string.h>
#include "crypt.h"
#include "cryptctx.h"

/* Prototypes for functions in lib_kg.c */

int generateRSAPrime( BIGNUM *candidate, const int noBits,
					  const long exponent, void *callbackArg );

/****************************************************************************
*																			*
*							RSA Self-test Routines							*
*																			*
****************************************************************************/

/* Test the RSA implementation using a sample key.  Because a lot of the
   high-level encryption routines don't exist yet, we cheat a bit and set
   up a dummy encryption context with just enough information for the
   following code to work */

typedef struct {
	int nLen; BYTE n[ 64 ];
	int eLen; BYTE e[ 1 ];
	int dLen; BYTE d[ 64 ];
	int pLen; BYTE p[ 32 ];
	int qLen; BYTE q[ 32 ];
	int uLen; BYTE u[ 32 ];
	int e1Len; BYTE e1[ 32 ];
	int e2Len; BYTE e2[ 32 ];
	} RSA_PRIVKEY;

static const RSA_PRIVKEY rsaTestKey = {
	/* n */
	512,
	{ 0xE1, 0x95, 0x41, 0x17, 0xB4, 0xCB, 0xDC, 0xD0,
	  0xCB, 0x9B, 0x11, 0x19, 0x9C, 0xED, 0x04, 0x6F,
	  0xBD, 0x70, 0x2D, 0x5C, 0x8A, 0x32, 0xFF, 0x16,
	  0x22, 0x57, 0x30, 0x3B, 0xD4, 0x59, 0x9C, 0x01,
	  0xF0, 0xA3, 0x70, 0xA1, 0x6C, 0x16, 0xAC, 0xCC,
	  0x8C, 0xAD, 0xB0, 0xA0, 0xAF, 0xC7, 0xCC, 0x49,
	  0x4F, 0xD9, 0x5D, 0x32, 0x1C, 0x2A, 0xE8, 0x4E,
	  0x15, 0xE1, 0x26, 0x6C, 0xC4, 0xB8, 0x94, 0xE1 },
	/* e */
	5,
	{ 0x11 },
	/* d */
	509,
	{ 0x13, 0xE7, 0x85, 0xBE, 0x53, 0xB7, 0xA2, 0x8A,
	  0xE4, 0xC9, 0xEA, 0xEB, 0xAB, 0xF6, 0xCB, 0xAF,
	  0x81, 0xA8, 0x04, 0x00, 0xA2, 0xC8, 0x43, 0xAF,
	  0x21, 0x25, 0xCF, 0x8C, 0xCE, 0xF8, 0xD9, 0x0F, 
	  0x10, 0x78, 0x4C, 0x1A, 0x26, 0x5D, 0x90, 0x18,
	  0x79, 0x90, 0x42, 0x83, 0x6E, 0xAE, 0x3E, 0x20, 
	  0x0B, 0x0C, 0x5B, 0x6B, 0x8E, 0x31, 0xE5, 0xCF,
	  0xD6, 0xE0, 0xBB, 0x41, 0xC1, 0xB8, 0x2E, 0x17 },
	/* p */
	256,
	{ 0xED, 0xE4, 0x02, 0x90, 0xA4, 0xA4, 0x98, 0x0D,
	  0x45, 0xA2, 0xF3, 0x96, 0x09, 0xED, 0x7B, 0x40,
	  0xCD, 0xF6, 0x21, 0xCC, 0xC0, 0x1F, 0x83, 0x09,
	  0x56, 0x37, 0x97, 0xFB, 0x05, 0x5B, 0x87, 0xB7 },
	/* q */
	256,
	{ 0xF2, 0xC1, 0x64, 0xE8, 0x69, 0xF8, 0x5E, 0x54, 
	  0x8F, 0xFD, 0x20, 0x8E, 0x6A, 0x23, 0x90, 0xF2,
	  0xAF, 0x57, 0x2F, 0x4D, 0x10, 0x80, 0x8E, 0x11,
	  0x3C, 0x61, 0x44, 0x33, 0x2B, 0xE0, 0x58, 0x27 },
	/* u */
	255,
	{ 0x68, 0x45, 0x00, 0x64, 0x32, 0x9D, 0x09, 0x6E, 
	  0x0A, 0xD3, 0xF3, 0x8A, 0xFE, 0x15, 0x8C, 0x79,
	  0xAD, 0x84, 0x35, 0x05, 0x19, 0x2C, 0x19, 0x51,
	  0xAB, 0x83, 0xC7, 0xE8, 0x5C, 0xAC, 0xAD, 0x7A },
	/* exponent1 */
	256,
	{ 0x99, 0xED, 0xE3, 0x8A, 0xC4, 0xE2, 0xF8, 0xF9,
	  0x87, 0x69, 0x70, 0x70, 0x24, 0x8A, 0x9B, 0x0B,
	  0xD0, 0x90, 0x33, 0xFC, 0xF4, 0xC9, 0x18, 0x8D,
	  0x92, 0x23, 0xF8, 0xED, 0xB8, 0x2C, 0x2A, 0xA3 },
	/* exponent2 */
	256,
	{ 0xB9, 0xA2, 0xF2, 0xCF, 0xD8, 0x90, 0xC0, 0x9B,
	  0x04, 0xB2, 0x82, 0x4E, 0xC9, 0xA2, 0xBA, 0x22,
	  0xFE, 0x8D, 0xF6, 0xFE, 0xB2, 0x44, 0x30, 0x67,
	  0x88, 0x86, 0x9D, 0x90, 0x8A, 0xF6, 0xD9, 0xFF }
	};

int rsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength );
int rsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );
int rsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes );

int rsaSelfTest( void )
	{
	CRYPT_INFO cryptInfo;
	CRYPT_PKCINFO_RSA *rsaKey;
	const CAPABILITY_INFO capabilityInfo = { CRYPT_ALGO_RSA, CRYPT_MODE_PKC,
								0, NULL, NULL, 64, 128, 512, 0, 0, 0,
								NULL, NULL, NULL, NULL, NULL, NULL, NULL,
								NULL, NULL, NULL, NULL, CRYPT_ERROR };
	BYTE buffer[ 64 ];
	int status;

	/* Allocate room for the public-key components */
	if( ( rsaKey = ( CRYPT_PKCINFO_RSA * ) malloc( sizeof( CRYPT_PKCINFO_RSA ) ) ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the BigNum information and components */
	memset( &cryptInfo, 0, sizeof( CRYPT_INFO ) );
	cryptInfo.ctxPKC.param1 = BN_new();
	cryptInfo.ctxPKC.param2 = BN_new();
	cryptInfo.ctxPKC.param3 = BN_new();
	cryptInfo.ctxPKC.param4 = BN_new();
	cryptInfo.ctxPKC.param5 = BN_new();
	cryptInfo.ctxPKC.param6 = BN_new();
	cryptInfo.ctxPKC.param7 = BN_new();
	cryptInfo.ctxPKC.param8 = BN_new();
	cryptInitComponents( rsaKey, CRYPT_COMPONENTS_BIGENDIAN,
						 CRYPT_KEYTYPE_PRIVATE );
	cryptSetComponent( rsaKey->n, rsaTestKey.n, rsaTestKey.nLen );
	cryptSetComponent( rsaKey->e, rsaTestKey.e, rsaTestKey.eLen );
	cryptSetComponent( rsaKey->d, rsaTestKey.d, rsaTestKey.dLen );
	cryptSetComponent( rsaKey->p, rsaTestKey.p, rsaTestKey.pLen );
	cryptSetComponent( rsaKey->q, rsaTestKey.q, rsaTestKey.qLen );
	cryptSetComponent( rsaKey->u, rsaTestKey.u, rsaTestKey.uLen );
	cryptSetComponent( rsaKey->e1, rsaTestKey.e1, rsaTestKey.e1Len );
	cryptSetComponent( rsaKey->e2, rsaTestKey.e2, rsaTestKey.e2Len );
	cryptInfo.capabilityInfo = &capabilityInfo;

	/* Perform the test en/decryption of a block of data */
	memset( buffer, 0, 64 );
	memcpy( buffer, "abcde", 5 );
	rsaInitKey( &cryptInfo, rsaKey, CRYPT_UNUSED );
	if( ( status = rsaEncrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT ) ) == CRYPT_OK )
		status = rsaDecrypt( &cryptInfo, buffer, CRYPT_USE_DEFAULT );
	if( status != CRYPT_OK || memcmp( buffer, "abcde", 5 ) )
		status = CRYPT_SELFTEST;

	/* Clean up */
	cryptDestroyComponents( rsaKey );
	BN_clear_free( cryptInfo.ctxPKC.param1 );
	BN_clear_free( cryptInfo.ctxPKC.param2 );
	BN_clear_free( cryptInfo.ctxPKC.param3 );
	BN_clear_free( cryptInfo.ctxPKC.param4 );
	BN_clear_free( cryptInfo.ctxPKC.param5 );
	BN_clear_free( cryptInfo.ctxPKC.param6 );
	BN_clear_free( cryptInfo.ctxPKC.param7 );
	BN_clear_free( cryptInfo.ctxPKC.param8 );
	if( cryptInfo.ctxPKC.rsaParam_mont_n != NULL )
		BN_MONT_CTX_free( cryptInfo.ctxPKC.rsaParam_mont_n );
	if( cryptInfo.ctxPKC.rsaParam_mont_p != NULL )
		BN_MONT_CTX_free( cryptInfo.ctxPKC.rsaParam_mont_p );
	if( cryptInfo.ctxPKC.rsaParam_mont_q != NULL )
		BN_MONT_CTX_free( cryptInfo.ctxPKC.rsaParam_mont_q );
	zeroise( &cryptInfo, sizeof( CRYPT_INFO ) );
	free( rsaKey );

	return( status );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Adjust p and q if necessary so the CRT decrypt works */

static void fixCRTvalues( CRYPT_INFO *cryptInfo,
						  const BOOLEAN fixPKCSvalues, BN_CTX *bnCTX )
	{
	BIGNUM *tmp;

	/* Make sure that p > q, which is required for the CRT decrypt */
	if( BN_cmp( cryptInfo->ctxPKC.rsaParam_p, cryptInfo->ctxPKC.rsaParam_q ) >= 0 )
		return;

	/* Swap the values p and q and, if necessary, the dependant parameters
	   e1 = d mod (p - 1) and e2 = d mod (q - 1), and recompute
	   u = qInv mod p */
	tmp = cryptInfo->ctxPKC.rsaParam_p;
	cryptInfo->ctxPKC.rsaParam_p = cryptInfo->ctxPKC.rsaParam_q;
	cryptInfo->ctxPKC.rsaParam_q = tmp;
	if( !fixPKCSvalues )
		return;
	tmp = cryptInfo->ctxPKC.rsaParam_exponent1;
	cryptInfo->ctxPKC.rsaParam_exponent1 = cryptInfo->ctxPKC.rsaParam_exponent2;
	cryptInfo->ctxPKC.rsaParam_exponent2 = tmp;
	BN_clear_free( cryptInfo->ctxPKC.rsaParam_u );
	cryptInfo->ctxPKC.rsaParam_u = BN_mod_inverse( cryptInfo->ctxPKC.rsaParam_q,
										cryptInfo->ctxPKC.rsaParam_p, bnCTX );
	}

/* Precompute Montgomery values for public and private components */

static int precomputeMontgomery( CRYPT_INFO *cryptInfo, BN_CTX *bnCTX,
								 const int precomputeType )
	{
	/* If we're doing an internal load of the private components, the public
	   precomputation has already been done */
	if( precomputeType != LOAD_INTERNAL_PRIVATE )
		{
		/* Precompute the public value */
		if( ( cryptInfo->ctxPKC.rsaParam_mont_n = BN_MONT_CTX_new() ) == NULL )
			return( CRYPT_NOMEM );
		BN_MONT_CTX_set( cryptInfo->ctxPKC.rsaParam_mont_n,
						 cryptInfo->ctxPKC.rsaParam_n, bnCTX );
		if( cryptInfo->ctxPKC.isPublicKey )
			return( CRYPT_OK );
		}

	/* Precompute the private values */
	if( ( cryptInfo->ctxPKC.rsaParam_mont_p = BN_MONT_CTX_new() ) == NULL || \
		( cryptInfo->ctxPKC.rsaParam_mont_q = BN_MONT_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );
	BN_MONT_CTX_set( cryptInfo->ctxPKC.rsaParam_mont_p,
					 cryptInfo->ctxPKC.rsaParam_p, bnCTX );
	BN_MONT_CTX_set( cryptInfo->ctxPKC.rsaParam_mont_q,
					 cryptInfo->ctxPKC.rsaParam_q, bnCTX );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Init/Shutdown Routines							*
*																			*
****************************************************************************/

/* Not needed for the RSA routines */

/****************************************************************************
*																			*
*							RSA En/Decryption Routines						*
*																			*
****************************************************************************/

/* Encrypt/signature check a single block of data  */

int rsaEncrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *n;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int status = CRYPT_OK;

	/* The length of the data value is usually determined by the PKC key
	   size, however sometimes we can be passed data which has been zero-
	   padded (for example data coming from an ASN.1 INTEGER in which the
	   high bit is a sign bit) making it longer than the key size, or which
	   has zero high byte(s), making it shorter than the key size.  If this
	   is the case we strip the high byte if it's zero, and set the actual
	   length to the data length of it's less than the key length.  This can
	   only happen if we're called from a internal function, since a call
	   from an external function can only pass CRYPT_USE_DEFAULT as the
	   length */
	if( noBytes != CRYPT_USE_DEFAULT && noBytes != length )
		{
		if( noBytes > length && !*buffer )
			{
			buffer++;
			noBytes--;
			}
		if( noBytes > length )
			return( CRYPT_BADDATA );
		length = noBytes;
		}

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Move the data from the buffer into a bignum, perform the modexp,
	   and move the result back into the buffer */
	n = BN_new();
	BN_bin2bn( buffer, length, n );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */
	BN_mod_exp_mont( n, n, cryptInfo->ctxPKC.rsaParam_e,
					 cryptInfo->ctxPKC.rsaParam_n, bnCTX,
					 cryptInfo->ctxPKC.rsaParam_mont_n );
	length = BN_bn2bin( n, buffer );
	BN_clear_free( n );

	BN_CTX_free( bnCTX );

	if( noBytes == CRYPT_USE_DEFAULT )
		length = CRYPT_OK;	/* External calls don't return a length */
	return( ( status == -1 ) ? CRYPT_PKCCRYPT : length );
	}

/* Use the Chinese Remainder Theorem shortcut for RSA decryption/signature
   generation.  M is the output plaintext message, C is the input ciphertext
   message, d is the secret decryption exponent, p and q are the prime
   factors of n, u is the multiplicative inverse of q, mod p.  n, the common
   modulus, is not used because of the Chinese Remainder Theorem shortcut */

int rsaDecrypt( CRYPT_INFO *cryptInfo, BYTE *buffer, int noBytes )
	{
	BN_CTX *bnCTX;
	BIGNUM *p = cryptInfo->ctxPKC.rsaParam_p;
	BIGNUM *q = cryptInfo->ctxPKC.rsaParam_q;
	BIGNUM *u = cryptInfo->ctxPKC.rsaParam_u;
	BIGNUM *e1 = cryptInfo->ctxPKC.rsaParam_exponent1;
	BIGNUM *e2 = cryptInfo->ctxPKC.rsaParam_exponent2;
	BIGNUM *data, *p2, *q2;
	int length = bitsToBytes( cryptInfo->ctxPKC.keySizeBits ), status = 0;

	/* The length of the data value is usually determined by the PKC key
	   size, however sometimes we can be passed data which has been zero-
	   padded (for example data coming from an ASN.1 INTEGER in which the
	   high bit is a sign bit) making it longer than the key size, or which
	   has zero high byte(s), making it shorter than the key size.  If this
	   is the case we strip the high byte if it's zero, and set the actual
	   length to the data length if it's less than the key length.  This can
	   only happen if we're called from a internal function, since a call
	   from an external function can only pass CRYPT_USE_DEFAULT as the
	   length */
	if( noBytes != CRYPT_USE_DEFAULT && noBytes != length )
		{
		if( noBytes > length && !*buffer )
			{
			buffer++;
			noBytes--;
			}
		if( noBytes > length )
			return( CRYPT_BADDATA );
		length = noBytes;
		}

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Initialise the bignums */
	p2 = BN_new();
	q2 = BN_new();
	data = BN_new();
	BN_bin2bn( buffer, length, data );
	zeroise( buffer, length );	/* Clear buffer while data is in bignum */

	/* Rather than decrypting by computing modexp with full mod n precision,
	   compute a shorter modexp with mod p and mod q precision:
		p2 = ( ( C mod p ) ** exponent1 ) mod p
		q2 = ( ( C mod q ) ** exponent2 ) mod q */
status =
	BN_mod( p2, data, p, bnCTX );		/* p2 = C mod p  */
status =
	BN_mod_exp_mont( p2, p2, e1, p, bnCTX, cryptInfo->ctxPKC.rsaParam_mont_p );
	BN_mod( q2, data, q, bnCTX );		/* q2 = C mod q  */
	BN_mod_exp_mont( q2, q2, e2, q, bnCTX, cryptInfo->ctxPKC.rsaParam_mont_q );

	/* p2 = p2 - q2; if p2 < 0 then p2 = p2 + p */
	BN_sub( p2, p2, q2 );
	if( p2->neg )
		BN_add( p2, p2, p );

	/* M = ( ( ( p2 * u ) mod p ) * q ) + q2 */
	BN_mod_mul( data, p2, u, p, bnCTX );/* data = ( p2 * u ) mod p */
	BN_mul( p2, data, q );				/* p2 = data * q (bn can't reuse data) */
	BN_add( data, p2, q2 );				/* data = p2 + q2 */

	/* Copy the result to the output buffer and destroy sensitive data */
	length = BN_bn2bin( data, buffer );
	BN_clear_free( p2 );
	BN_clear_free( q2 );
	BN_clear_free( data );

	BN_CTX_free( bnCTX );

	if( noBytes == CRYPT_USE_DEFAULT )
		length = CRYPT_OK;	/* External calls don't return a length */
	return( ( status == -1 ) ? CRYPT_PKCCRYPT : length );
	}

/****************************************************************************
*																			*
*							RSA Key Management Routines						*
*																			*
****************************************************************************/

/* Load RSA public/private key components into an encryption context */

int rsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int loadType )
	{
	CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;
	BN_CTX *bnCTX;
	int status = CRYPT_OK;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* Load the key component from the external representation into the
	   internal BigNums unless we're doing an internal load */
	if( loadType != LOAD_INTERNAL_PUBLIC && loadType != LOAD_INTERNAL_PRIVATE )
		{
		cryptInfo->ctxPKC.isPublicKey = rsaKey->isPublicKey;
		BN_bin2bn( rsaKey->n, bitsToBytes( rsaKey->nLen ),
				   cryptInfo->ctxPKC.rsaParam_n );
		BN_bin2bn( rsaKey->e, bitsToBytes( rsaKey->eLen ),
				   cryptInfo->ctxPKC.rsaParam_e );
		if( !rsaKey->isPublicKey )
			{
			BN_bin2bn( rsaKey->d, bitsToBytes( rsaKey->dLen ),
					   cryptInfo->ctxPKC.rsaParam_d );
			BN_bin2bn( rsaKey->p, bitsToBytes( rsaKey->pLen ),
					   cryptInfo->ctxPKC.rsaParam_p );
			BN_bin2bn( rsaKey->q, bitsToBytes( rsaKey->qLen ),
					   cryptInfo->ctxPKC.rsaParam_q );
			BN_bin2bn( rsaKey->u, bitsToBytes( rsaKey->uLen ),
					   cryptInfo->ctxPKC.rsaParam_u );
			BN_bin2bn( rsaKey->e1, bitsToBytes( rsaKey->e1Len ),
					   cryptInfo->ctxPKC.rsaParam_exponent1 );
			BN_bin2bn( rsaKey->e2, bitsToBytes( rsaKey->e2Len ),
					   cryptInfo->ctxPKC.rsaParam_exponent2 );
			}
		}
	cryptInfo->ctxPKC.lastPublicComponent = RSA_LAST_PUBLIC;
	cryptInfo->ctxPKC.lastPublicMontCTX = 1;

	/* Make sure the necessary key parameters have been initialised */
	if( BN_is_zero( cryptInfo->ctxPKC.rsaParam_n ) || \
		BN_is_zero( cryptInfo->ctxPKC.rsaParam_e ) || \
		( !cryptInfo->ctxPKC.isPublicKey && \
		  ( BN_is_zero( cryptInfo->ctxPKC.rsaParam_d ) || \
			BN_is_zero( cryptInfo->ctxPKC.rsaParam_p ) || \
			BN_is_zero( cryptInfo->ctxPKC.rsaParam_q ) || \
			BN_is_zero( cryptInfo->ctxPKC.rsaParam_u ) ) ) )
		status = CRYPT_BADPARM2;

	/* Make sure the key paramters are valid: n > 504 (nominally 512 bits,
	   but some certs contain somewhat shorter keys), e > 2,
	   |p-q| > 128 bits */
	if( BN_num_bits( cryptInfo->ctxPKC.rsaParam_n ) <= 504 || \
		BN_is_word( cryptInfo->ctxPKC.rsaParam_e, 3 ) < 0 )
		status = CRYPT_BADPARM2;
	if( !cryptInfo->ctxPKC.isPublicKey )
		{
		BIGNUM *tmp;

		/* Make sure the two differ by at least 128 bits */
		tmp = BN_new();
		BN_copy( tmp, cryptInfo->ctxPKC.rsaParam_p );
		BN_sub( tmp, tmp, cryptInfo->ctxPKC.rsaParam_q );
		if( BN_num_bits( tmp ) < 128 )
			status = CRYPT_BADPARM2;
		BN_clear_free( tmp );
		}

	/* If we're not using PKCS keys which have exponent1 = d mod ( p - 1 )
	   and exponent2 = d mod ( q - 1 ) precalculated, evaluate them now */
	if( cryptStatusOK( status ) && !cryptInfo->ctxPKC.isPublicKey && \
		BN_is_zero( cryptInfo->ctxPKC.rsaParam_exponent1 ) )
		{
		BIGNUM *d = cryptInfo->ctxPKC.rsaParam_d;
		BIGNUM *exponent1 = cryptInfo->ctxPKC.rsaParam_exponent1;
		BIGNUM *exponent2 = cryptInfo->ctxPKC.rsaParam_exponent2;

		BN_copy( exponent1, cryptInfo->ctxPKC.rsaParam_p );
		BN_sub_word( exponent1, 1 );		/* exponent1 = p - 1 */
		BN_mod( exponent1, d, exponent1, bnCTX );
											/* exponent1 = d mod ( p - 1 ) ) */
		BN_copy( exponent2, cryptInfo->ctxPKC.rsaParam_q );
		BN_sub_word( exponent2, 1 );		/* exponent2 = q - 1 */
		BN_mod( exponent2, d, exponent2, bnCTX );
											/* exponent2 = d mod ( q - 1 ) ) */

		/* Check that everything went OK */
		status = ( status == -1 ) ? CRYPT_BADPARM2 : CRYPT_OK;
		}

	/* Make sure that p and q are set up correctly for the CRT decryption and
	   precompute the Montgomery values */
	if( !cryptInfo->ctxPKC.isPublicKey )
		fixCRTvalues( cryptInfo, TRUE, bnCTX );
	if( cryptStatusOK( status ) )
		status = precomputeMontgomery( cryptInfo, bnCTX, loadType );

	/* Set the keysize and generate a key ID for this key */
	cryptInfo->ctxPKC.keySizeBits = BN_num_bits( cryptInfo->ctxPKC.rsaParam_n );
	if( cryptStatusOK( status ) && loadType != LOAD_INTERNAL_PRIVATE )
		status = calculateKeyID( CRYPT_ALGO_RSA, &cryptInfo->ctxPKC,
								 cryptInfo->ctxPKC.keyID );

	/* Clean up */
	BN_CTX_free( bnCTX );
	return( status );
	}

/****************************************************************************
*																			*
*							RSA Key Generation Routines						*
*																			*
****************************************************************************/

#ifdef ALT_CODE

/* Find a prime.  Returns prime - 1, which saves the caller a few
   operations */

static int findRSAPrimeMinus1( CRYPT_INFO *cryptInfo, BIGNUM *prime,
							   BIGNUM *exp, int primeBits, BN_CTX *context )
	{
	BIGNUM *gcd, *low, *high;
	BIGNUM *localPrime	= NULL;
	int status = CRYPT_OK;

	gcd = BN_new();
	low = BN_new();
	high = BN_new();

	/* Set the low boundary for the prime as 3 * 2^(primeBits - 2) and the
	   high boundary for the prime as 2^primeBits */
	BN_set_word( gcd, 3 );
	BN_lshift( low, gcd, primeBits - 2 );
	BN_add_word( low, 1 );
	BN_set_word( gcd, 1 );
	BN_lshift( high, gcd, primeBits );

	/* Generate a prime such that low < prime < high, and
	   gcd( prime - 1, exp ) = 1.

	   NB: This isn't right since it uses the EAY prime generation model
		   which can completely drain the randomness pool and, in situations
		   where system randomness is used (/dev/random) will stall until it
		   refills.  Compare this with the older bnlib-based code.
		   Unfortunately fixing this involves rewriting a fair bit of
		   bn_prime.c, which the currently enabled code does (the callback
		   model is also different, since the EAY code returns a new bignum
		   rather than a return status) */
	while( !cryptStatusError( status ) )
		{
		localPrime = BN_generate_prime( primeBits, 0, NULL, NULL, cryptInfo );

		BN_sub_word( localPrime, 1 );
		BN_gcd( gcd, localPrime, exp, context );
		if( BN_cmp( low, localPrime ) < 0 && \
			BN_cmp( high, localPrime ) > 0 && \
			BN_is_one( gcd ) )
			break;

		BN_clear_free( localPrime );
		}
	BN_copy( prime, localPrime );

	BN_clear_free( gcd );
	BN_clear_free( low );
	BN_clear_free( high );

	return( status );
	}
#endif /* ALT_CODE */

#if 0	/* Old bnlib-based code */

static int findPrime( CRYPT_INFO *cryptInfo, BIGNUM *prime, BIGNUM *exp,
					  int noBits )
	{
	BIGNUM *gcd, *low, *high;
	int status;

	gcd = BN_new();
	low = BN_new();
	high = BN_new();

	bnSetQ( &low, 3 );
	bnLShift( &low, noBits - 2 );
	bnAddQ( &low, 1 );

	bnSetQ( &high, 1 );
	bnLShift( &high, noBits );

	/* Generate a prime such that 3 * 2^(noBits - 2) < prime < 2^noBits
	   and gcd(prime - 1, exp) = 1.

	   If we fall over the upper limit, we just climb back from the other
	   side! */
	status = generateBignum( prime, noBits, 0xC0, 0x01 );
	while( !cryptStatusError( status ) )
		{
		status = bnPrimeGen( prime, NULL, cryptInfo, 0 );
		if( status < 0 )
			{
			status = ( status == ASYNC_ABORT ) ? CRYPT_INCOMPLETE : CRYPT_NOMEM;
			break;			/* Can only explicitly fail on out-of-mem */
			}
		if( bnCmp( prime, &high ) >= 0 )
			{
			CK( bnCopy( prime, &low ) );
			continue;
			}
		CK( bnSubQ( prime, 1 ) );
		CK( bnGcd( &gcd, prime, exp ) );
		if( bnCmpQ( &gcd, 1 ) == 0 )
			break;

		CK( bnAddQ( prime, 3 ) );
		}

	BN_clear_free( gcd );
	BN_clear_free( low );
	BN_clear_free( high );

	return( status );
	}
#endif /* 0 */

/* Generate an RSA key pair into an encryption context */

int rsaGenerateKey( CRYPT_INFO *cryptInfo, const int keySizeBits )
	{
	BN_CTX *bnCTX;
	BIGNUM *tmp;
	int pBits, qBits, status = CRYPT_OK;

	/* Determine how many bits to give to each of p and q */
	pBits = ( keySizeBits + 1 ) / 2;
	qBits = keySizeBits - pBits;
	cryptInfo->ctxPKC.keySizeBits = pBits + qBits;

	/* Set up assorted status information */
	cryptInfo->ctxPKC.isPublicKey = FALSE;
	cryptInfo->ctxPKC.lastPublicComponent = RSA_LAST_PUBLIC;
	cryptInfo->ctxPKC.lastPublicMontCTX = 1;

	if( ( bnCTX = BN_CTX_new() ) == NULL )
		return( CRYPT_NOMEM );

	/* This version uses F4 as the public exponent e.  The older recommended 3
	   is insecure and recent work indicates that values like 17 (used by PGP)
	   are also insecure against the Hastad attack, it would be better to
	   use 41 or 257 as the exponent.  However these are somewhat slower,
	   it would be necessary to perform timing tests on bnlib to see which of
	   41, 257, and 65537 is the best exponent (from reading the code it
	   should be 41, then 257, then 65537) */
	BN_set_word( cryptInfo->ctxPKC.rsaParam_e, 65537L );

	/* Generate the primes p and q and set them up so the CRT decrypt will
	   work */
#ifdef ALT_CODE
	/* Because we initially need the values (p - 1) and (q - 1), we generate
	   these values and adjust them later to get p and q */
	status = findRSAPrimeMinus1( cryptInfo, cryptInfo->ctxPKC.rsaParam_p,
								 cryptInfo->ctxPKC.rsaParam_e, pBits, bnCTX );
	if( cryptStatusOK( status ) )
		do
			status = findRSAPrimeMinus1( cryptInfo, cryptInfo->ctxPKC.rsaParam_q,
										 cryptInfo->ctxPKC.rsaParam_e, qBits, bnCTX );
		while( cryptStatusOK( status ) && \
			   BN_cmp( cryptInfo->ctxPKC.rsaParam_p, cryptInfo->ctxPKC.rsaParam_q ) == 0 );
#else
	status = generateRSAPrime( cryptInfo->ctxPKC.rsaParam_p, pBits, 65537L,
							   cryptInfo );
	if( cryptStatusOK( status ) )
		status = generateRSAPrime( cryptInfo->ctxPKC.rsaParam_q, qBits, 65537L,
								   cryptInfo );
#endif /* ALT_CODE */
	if( cryptStatusError( status ) )
		{
		BN_CTX_free( bnCTX );
		return( status );
		}
	fixCRTvalues( cryptInfo, FALSE, bnCTX );

	/* If we managed to generate the primes OK, derive everything else from
	   them */
	tmp = BN_new();

	/* Compute d = eInv mod (p - 1)(q - 1), e1 = d mod (p - 1), and
	   e2 = d mod (q - 1) */
	BN_sub_word( cryptInfo->ctxPKC.rsaParam_p, 1 );
	BN_sub_word( cryptInfo->ctxPKC.rsaParam_q, 1 );
	BN_mul( tmp, cryptInfo->ctxPKC.rsaParam_p, cryptInfo->ctxPKC.rsaParam_q );
	BN_clear_free( cryptInfo->ctxPKC.rsaParam_d );
	cryptInfo->ctxPKC.rsaParam_d = BN_mod_inverse( cryptInfo->ctxPKC.rsaParam_e,
												   tmp, bnCTX );
	BN_mod( cryptInfo->ctxPKC.rsaParam_exponent1, cryptInfo->ctxPKC.rsaParam_d,
			cryptInfo->ctxPKC.rsaParam_p, bnCTX );
	BN_mod( cryptInfo->ctxPKC.rsaParam_exponent2, cryptInfo->ctxPKC.rsaParam_d,
			cryptInfo->ctxPKC.rsaParam_q, bnCTX );
	BN_add_word( cryptInfo->ctxPKC.rsaParam_p, 1 );
	BN_add_word( cryptInfo->ctxPKC.rsaParam_q, 1 );

	/* Compute n = pq, and u = qInv mod p */
	BN_mul( cryptInfo->ctxPKC.rsaParam_n, cryptInfo->ctxPKC.rsaParam_p,
			cryptInfo->ctxPKC.rsaParam_q );
	BN_clear_free( cryptInfo->ctxPKC.rsaParam_u );
	cryptInfo->ctxPKC.rsaParam_u = BN_mod_inverse( cryptInfo->ctxPKC.rsaParam_q,
										cryptInfo->ctxPKC.rsaParam_p, bnCTX );

	/* Precompute the Montgomery values */
	status = precomputeMontgomery( cryptInfo, bnCTX, CRYPT_UNUSED );

	BN_clear_free( tmp );
	BN_CTX_free( bnCTX );

	/* Generate a keyID for the new key */
	if( cryptStatusOK( status ) )
		status = calculateKeyID( CRYPT_ALGO_RSA, &cryptInfo->ctxPKC,
								 cryptInfo->ctxPKC.keyID );

#if 0	/* For generating test key data, use cryptAddRandom( "", 0 ); */
{
#include <stdio.h>

BYTE buffer[ CRYPT_MAX_PKCSIZE ];
int length, i;

length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_n, buffer );
printf( "\t/* n */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_n ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_e, buffer );
printf( "\r\n\r\n\t/* e */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_e ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_d, buffer );
printf( "\r\n\r\n\t/* d */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_d ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_p, buffer );
printf( "\r\n\r\n\t/* p */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_p ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_q, buffer );
printf( "\r\n\r\n\t/* q */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_q ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_u, buffer );
printf( "\r\n\r\n\t/* u */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_u ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_exponent1, buffer );
printf( "\r\n\r\n\t/* exponent1 */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_exponent1 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
length = BN_bn2bin( cryptInfo->ctxPKC.rsaParam_exponent2, buffer );
printf( "\r\n\r\n\t/* exponent2 */\r\n\t%d,", BN_num_bits( cryptInfo->ctxPKC.rsaParam_exponent2 ) );
for( i = 0; i < length; i++ )
	{ if( !( i % 8 ) ) printf( "\r\n\t" );
	printf( "0x%02X, ", buffer[ i ] ); }
puts( "\r\n};" );
}
#endif /* 0 */

	return( status );
	}
