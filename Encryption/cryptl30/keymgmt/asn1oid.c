/****************************************************************************
*																			*
*					ASN.1 Object/Algorithm Identifier Routines				*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							Object Identifier Routines						*
*																			*
****************************************************************************/

/* A table mapping OID's to algorithm types.  We take advantage of the fact
   that object identifiers were designed to be handled in the encoded form
   (without any need for decoding) and compare expected OID's with the raw
   encoded form.  Some OID's are for pure algorithms, others are for aWithB
   type combinations (usually encryption + hash), in this case the algorithm
   is the encryption and the subAlgorithm is the hash.

   There are multiple OID's for RSA, the main ones being rsa (which doesn't
   specify an exact data format and is deprecated), rsaEncryption (as per
   PKCS #1, recommended), and rsaSignature (ISO 9796).  We use rsaEncryption
   and its derived forms (eg md5WithRSAEncryption) rather than alternatives
   like md5WithRSA.  There is also an OID for rsaKeyTransport which uses
   PKCS #1 padding but isn't defined by RSADSI.

   There are a great many OIDs for DSA and/or SHA.  We list the less common 
   ones after all the other OIDs so that we always encode the more common 
   form, but can decode many forms (there are even more OIDs for SHA or DSA 
   with common parameters which we don't bother with) */

struct {
	CRYPT_ALGO algorithm;			/* The basic algorithm */
	CRYPT_ALGO subAlgorithm;		/* The algorithm subtype */
	BYTE *oid;						/* The OID for this algorithm */
	} algoIDmap[] = {
	/* RSA and <hash>WithRSA */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x01" ) },
	  /* rsaEncryption (1 2 840 113549 1 1 1) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD2,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x02" ) },
	  /* md2withRSAEncryption (1 2 840 113549 1 1 2) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD4,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x03" ) },
	  /* md4withRSAEncryption (1 2 840 113549 1 1 3) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_MD5,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x04" ) },
	  /* md5withRSAEncryption (1 2 840 113549 1 1 4) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x01\x05" ) },
	  /* sha1withRSAEncryption (1 2 840 113549 1 1 5) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x06\x2B\x24\x03\x03\x01\x01" ) },
	  /* Another rsaSignatureWithsha1 (1 3 36 3 3 1 1) */
	{ CRYPT_ALGO_RSA, CRYPT_ALGO_RIPEMD160,
	  MKOID( "\x06\x06\x2B\x24\x03\x03\x01\x02" ) },
	  /* rsaSignatureWithripemd160 (1 3 36 3 3 1 2) */

	/* DSA and dsaWith<hash> */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x04\x01" ) },
	  /* dsa (1 2 840 10040 4 1) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x0C" ) },
	  /* Peculiar deprecated dsa (1 3 14 3 2 12), but used by CDSA and the
	     German PKI profile */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x04\x03" ) },
	  /* dsaWithSha1 (1 2 840 10040 4 3) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x1B" ) },
	  /* Another dsaWithSHA1 (1 3 14 3 2 27) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x02" ) },
	  /* Yet another dsaWithSHA-1 (2 16 840 1 101 2 1 1 2) */
	{ CRYPT_ALGO_DSA, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x0D" ) },
	  /* When they ran out of valid dsaWithSHA's, they started using invalid
	     ones.  This one is from JDK 1.1 and is actually dsaWithSHA, but it's
		 used as if it were dsaWithSHA-1 (1 3 14 3 2 13) */

	/* Elgamal and elgamalWith<hash> */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01" ) },
	  /* elgamal (1 3 6 1 4 1 3029 1 2 1) */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_SHA,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01\x01" ) },
	  /* elgamalWithSHA-1 (1 3 6 1 4 1 3029 1 2 1 1) */
	{ CRYPT_ALGO_ELGAMAL, CRYPT_ALGO_RIPEMD160,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x97\x55\x01\x02\x01\x02" ) },
	  /* elgamalWithRIPEMD-160 (1 3 6 1 4 1 3029 1 2 1 2) */

	/* DH */
	{ CRYPT_ALGO_DH, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x07\x2A\x86\x48\xCE\x3E\x02\x01" ) },
	  /* dhPublicKey (1 2 840 10046 2 1) */

	/* KEA */
	{ CRYPT_ALGO_KEA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x16" ) },
	  /* keyExchangeAlgorithm (2 16 840 1 101 2 1 1 22) */

	/* Hash algorithms */
	{ CRYPT_ALGO_MD2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02" ) },
	  /* md2 (1 2 840 113549 2 2) */
	{ CRYPT_ALGO_MD4, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x04" ) },
	  /* md4 (1 2 840 113549 2 4) */
	{ CRYPT_ALGO_MD4, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x01" ) },
	  /* Another md4 (0 2 262 1 10 1 3 1) */
	{ CRYPT_ALGO_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05" ) },
	  /* md5 (1 2 840 113549 2 5) */
	{ CRYPT_ALGO_MD5, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x02" ) },
	  /* Another md5 (0 2 262 1 10 1 3 2) */
	{ CRYPT_ALGO_SHA, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x1A" ) },
	  /* sha1 (1 3 14 3 2 26) */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x24\x03\x02\x01" ) },
	  /* ripemd160 (1 3 36 3 2 1) */
	{ CRYPT_ALGO_RIPEMD160, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x08\x02\x82\x06\x01\x0A\x01\x03\x08" ) },
	  /* Another ripemd160 (0 2 262 1 10 1 3 8) */
	{ CRYPT_ALGO_MDC2, CRYPT_ALGO_NONE,
	  MKOID( "\x06\x05\x2B\x24\x03\x02\x05" ) },
	  /* mdc2doubleLength (1 3 36 3 2 5) */

	/* Ciphers */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_ECB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x01" ) },
	  /* blowfishECB (1 3 6 1 4 1 3029 1 1 1) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CBC,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x02" ) },
	  /* blowfishCBC (1 3 6 1 4 1 3029 1 1 2) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_CFB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x03" ) },
	  /* blowfishCFB (1 3 6 1 4 1 3029 1 1 3) */
	{ CRYPT_ALGO_BLOWFISH, CRYPT_MODE_OFB,
	  MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x97\x55\x01\x01\x04" ) },
	  /* blowfishOFB (1 3 6 1 4 1 3029 1 1 4) */
	{ CRYPT_ALGO_CAST, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0A" ) },
	  /* cast5CBC (1 2 840 113533 7 66 10) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x06" ) },
	  /* desECB (1 3 14 3 2 6) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x01" ) },
	  /* Another desECB (0 2 262 1 10 1 2 2 1) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x07" ) },
	  /* desCBC (1 3 14 3 2 7) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x02" ) },
	  /* Another desCBC (0 2 262 1 10 1 2 2 2) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x08" ) },
	  /* desOFB (1 3 14 3 2 8) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x03" ) },
	  /* Another desOFB (0 2 262 1 10 1 2 2 3) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x05\x2B\x0E\x03\x02\x09" ) },
	  /* desCFB (1 3 14 3 2 9) */
	{ CRYPT_ALGO_DES, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x02\x05" ) },
	  /* Another desCFB (0 2 262 1 10 1 2 2 5) */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07" ) },
	  /* des-EDE3-CBC (1 2 840 113549 3 7) */
	{ CRYPT_ALGO_3DES, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x03\x02" ) },
	  /* Another des3CBC (0 2 262 1 10 1 2 3 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x01" ) },
	  /* ideaECB (1 3 6 1 4 1 188 7 1 1 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x01" ) },
	  /* Another ideaECB (1 3 36 3 1 2 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_ECB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x01" ) },
	  /* Yet another ideaECB (0 2 262 1 10 1 2 5 1) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x02" ) },
	  /* ideaCBC (1 3 6 1 4 1 188 7 1 1 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x02" ) },
	  /* Another ideaCBC (1 3 36 3 1 2 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x02" ) },
	  /* Yet another ideaCBC (0 2 262 1 10 1 2 5 2) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x04" ) },
	  /* ideaOFB (1 3 6 1 4 1 188 7 1 1 4) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x03" ) },
	  /* Another ideaOFB (1 3 36 3 1 2 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_OFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x03" ) },
	  /* Yet another ideaOFB (0 2 262 1 10 1 2 5 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x03" ) },
	  /* ideaCFB (1 3 6 1 4 1 188 7 1 1 3) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x06\x2B\x24\x03\x01\x02\x04" ) },
	  /* Another ideaCFB (1 3 36 3 1 2 4) */
	{ CRYPT_ALGO_IDEA, CRYPT_MODE_CFB,
	  MKOID( "\x06\x09\x02\x82\x06\x01\x0A\x01\x02\x05\x05" ) },
	  /* Yet another ideaCFB (0 2 262 1 10 1 2 5 5) */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x02" ) },
	  /* rc2CBC (1 2 840 113549 3 2) */
	{ CRYPT_ALGO_RC2, CRYPT_MODE_ECB,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x03" ) },
	  /* rc2ECB (1 2 840 113549 3 3) */
	{ CRYPT_ALGO_RC4, CRYPT_MODE_OFB,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x04" ) },
	  /* rc4 (1 2 840 113549 3 4) */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x09" ) },
	  /* rC5-CBCPad (1 2 840 113549 3 9) */
	{ CRYPT_ALGO_RC5, CRYPT_MODE_CBC,
	  MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x08" ) },
	  /* rc5CBC (sometimes used interchangeably with the above) (1 2 840 113549 3 8) */
	{ CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC,
	  MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x04" ) },
	  /* fortezzaConfidentialityAlgorithm (2 16 840 1 101 2 1 1 4) */

	{ CRYPT_ALGO_NONE, CRYPT_ALGO_NONE, NULL }
	};

/* Map an OID to an algorithm type.  The subAlgorithm parameter can be
   NULL, in which case we don't return the sub-algorithm, but we return
   an error code if the OID has a sub-algorithm type */

static CRYPT_ALGO oidToAlgorithm( const BYTE *oid, int *subAlgorithm )
	{
	const int oidSize = sizeofOID( oid );
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( sizeofOID( algoIDmap[ i ].oid ) == oidSize && \
			!memcmp( algoIDmap[ i ].oid, oid, oidSize ) )
			{
			if( subAlgorithm != NULL )
				/* Return the sub-algorithm type */
				*subAlgorithm = algoIDmap[ i ].subAlgorithm;
			else
				/* If we're not expecting a sub-algorithm but there's one
				   present, mark it as an error */
				if( algoIDmap[ i ].subAlgorithm != CRYPT_ALGO_NONE )
					return( CRYPT_ERROR );

			return( algoIDmap[ i ].algorithm );
			}

	return( CRYPT_ERROR );
	}

/* Map an algorithm and optional sub-algorithm to an OID */

static BYTE *algorithmToOID( const CRYPT_ALGO algorithm, 
							 const CRYPT_ALGO subAlgorithm )
	{
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( algoIDmap[ i ].algorithm == algorithm && \
			algoIDmap[ i ].subAlgorithm == subAlgorithm )
			return( algoIDmap[ i ].oid );

	assert( NOTREACHED );
	return( NULL );	/* Get rid of compiler warning */
	}

static BYTE *algorithmToOIDcheck( const CRYPT_ALGO algorithm, 
								  const CRYPT_ALGO subAlgorithm )
	{
	int i;

	for( i = 0; algoIDmap[ i ].algorithm != CRYPT_ALGO_NONE; i++ )
		if( algoIDmap[ i ].algorithm == algorithm && \
			algoIDmap[ i ].subAlgorithm == subAlgorithm )
			return( algoIDmap[ i ].oid );

	return( NULL );
	}

int readOID( STREAM *stream, const BYTE *oid )
	{
	BYTE buffer[ 32 ];
	int readDataLength, dummy;

	readDataLength = readRawObject( stream, buffer, &dummy, 32,
									BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( readDataLength ) || \
		memcmp( buffer, oid, sizeofOID( oid ) ) )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	return( readDataLength );
	}

/****************************************************************************
*																			*
*							AlgorithmIdentifier Routines					*
*																			*
****************************************************************************/

/* Because AlgorithmIdentifier's are only defined for a subset of the
   algorithms which cryptlib supports, we have to check that the algorithm
   and mode being used can be represented in encoded data before we try to
   do anything with it */

BOOLEAN checkAlgoID( const CRYPT_ALGO algorithm, const CRYPT_MODE mode )
	{
	return( ( algorithmToOIDcheck( algorithm, mode ) != NULL ) ? TRUE : FALSE );
	}

/* Determine the size of an AlgorithmIdentifier record */

int sizeofAlgoID( const CRYPT_ALGO algorithm )
	{
	return( ( int ) sizeofObject( \
				sizeofOID( algorithmToOID( algorithm, CRYPT_ALGO_NONE ) ) + \
				sizeofNull() ) );
	}

int sizeofAlgoIDex( const CRYPT_ALGO algorithm, const CRYPT_ALGO subAlgorithm,
					const int extraLength )
	{
	return( ( int ) sizeofObject( \
				sizeofOID( algorithmToOID( algorithm, subAlgorithm ) ) + \
				( extraLength ? extraLength : sizeofNull() ) ) );
	}

/* Write an AlgorithmIdentifier record */

int writeAlgoIDex( STREAM *stream, const CRYPT_ALGO algorithm,
				   const CRYPT_ALGO subAlgorithm, const int extraLength )
	{
	BYTE *oid = algorithmToOID( algorithm, subAlgorithm );
	const int oidSize = sizeofOID( oid );

	/* Write the AlgorithmIdentifier field */
	writeSequence( stream, oidSize + \
				   ( extraLength ? extraLength : sizeofNull() ) );
	swrite( stream, oid, oidSize );
	if( !extraLength )
		/* No extra parameters so we need to write a NULL */
		writeNull( stream, DEFAULT_TAG );

	return( sGetStatus( stream ) );
	}

int writeAlgoID( STREAM *stream, const CRYPT_ALGO algorithm  )
	{
	return( writeAlgoIDex( stream, algorithm, CRYPT_ALGO_NONE, 0 ) );
	}

/* Read an AlgorithmIdentifier record */

int readAlgoIDex( STREAM *stream, CRYPT_ALGO *algorithm, 
				  CRYPT_ALGO *subAlgorithm, int *extraLength )
	{
	CRYPT_ALGO cryptAlgo;
	BYTE buffer[ MAX_OID_SIZE ];
	int bufferLength, cryptSubAlgo, length, status;

	/* Clear the result fields */
	*algorithm = CRYPT_ALGO_NONE;
	if( subAlgorithm != NULL )
		*subAlgorithm = CRYPT_ALGO_NONE;
	if( extraLength != NULL )
		*extraLength = 0;

	/* Determine the algorithm information based on the AlgorithmIdentifier
	   field */
	readSequence( stream, &length );
	status = readRawObject( stream, buffer, &bufferLength, MAX_OID_SIZE,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	length -= status;
	if( ( cryptAlgo = oidToAlgorithm( buffer, &cryptSubAlgo ) ) == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTAVAIL );
	*algorithm = cryptAlgo;
	if( subAlgorithm != NULL )
		*subAlgorithm = cryptSubAlgo;

	/* Handle any remaining parameters */
	if( length == sizeofNull() )
		/* Skip the algorithm parameters field */
		readNull( stream );
	else
		/* Tell the caller how much remains to be read */
		if( extraLength != NULL )
			*extraLength = ( int ) length;

	return( sGetStatus( stream ) );
	}

int readAlgoID( STREAM *stream, CRYPT_ALGO *algorithm )
	{
	return( readAlgoIDex( stream, algorithm, NULL, NULL ) );
	}

/* Determine the size of an AlgorithmIdentifier record from an encryption
   context */

int sizeofContextAlgoID( const CRYPT_CONTEXT iCryptContext,
						 const CRYPT_ALGO subAlgorithm )
	{
	int cryptAlgo, status;

	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( sizeofAlgoIDex( cryptAlgo, subAlgorithm, 0 ) );
	}

/* Write an AlgorithmIdentifier record from an encryption context */

int writeContextAlgoID( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const CRYPT_ALGO subAlgorithm )
	{
	int cryptAlgo, status;

	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	return( writeAlgoIDex( stream, cryptAlgo, subAlgorithm, 0 ) );
	}

/* Read an AlgorithmIdentifier record into an encryption context.  This
   currently only works for hash contexts because encryption context OIDs are
   too inconsistent to handle easily */

int readContextAlgoID( STREAM *stream, CRYPT_CONTEXT *iCryptContext )
	{
	CREATEOBJECT_INFO createInfo;
	CRYPT_ALGO cryptAlgo;
	int status;

	/* Read the OID */
	*iCryptContext = CRYPT_ERROR;
	status = readAlgoID( stream, &cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );

	/* Crate the object from it */
	setMessageCreateObjectInfo( &createInfo, cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		*iCryptContext = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*						EncryptionAlgorithmIdentifier Routines				*
*																			*
****************************************************************************/

/* EncryptionAlgorithmIdentifier parameters:

	cast5cbc: RFC 2144
		SEQUENCE {
			iv			OCTET STRING DEFAULT 0,
			keyLen		INTEGER (128)
			}

	blowfishCBC, desCBC, desEDE3-CBC: Blowfish RFC/OIW
		iv				OCTET STRING SIZE (8)

	blowfishCFB, blowfishOFB, desCFB, desOFB: Blowfish RFC/OIW
		SEQUENCE {
			iv			OCTET STRING SIZE (8),
			noBits		INTEGER (64)
			}

	ideaCBC: Ascom Tech
		SEQUENCE {
			iv			OCTET STRING OPTIONAL
			}

	ideaCFB: Ascom Tech
		SEQUENCE {
			r	  [ 0 ]	INTEGER DEFAULT 64,
			k	  [ 1 ]	INTEGER DEFAULT 64,
			j	  [ 2 ]	INTEGER DEFAULT 64,
			iv	  [ 3 ]	OCTET STRING OPTIONAL
			}

	ideaOFB: Ascom Tech
		SEQUENCE {
			j			INTEGER DEFAULT 64,
			iv			OCTET STRING OPTIONAL
			}

	rc2CBC: RFC 2311
		SEQUENCE {
			rc2Param	INTEGER (58),	-- 128 bit key
			iv			OCTET STRING SIZE (8)
			}

	rc4: RFC 2311
		NULL

	rc5: RFC 2040
		SEQUENCE {
			version		INTEGER (16),
			rounds		INTEGER (12),
			blockSize	INTEGER (64),
			iv			OCTET STRING OPTIONAL
			}

	skipjackCBC: SDN.701
		SEQUENCE {
			iv			OCTET STRING
			}

   Because of the haphazard and arbitrary nature of
   EncryptionAlgorithmIdentifier definitions, we can only handle the
   following algorithm/mode combinations:

	Blowfish ECB, CBC, CFB, OFB
	CAST128 CBC
	DES ECB, CBC, CFB, OFB
	3DES CBC
	IDEA ECB, CBC, CFB, OFB
	RC2 ECB, CBC
	RC4
	RC5 CBC
	Skipjack CBC */

#define RC2_KEYSIZE_MAGIC		58	/* Magic value for RC2/128 */

/* Read an EncryptionAlgorithmIdentifier record */

int readCryptAlgoID( STREAM *stream, CRYPT_ALGO *algorithm, CRYPT_MODE *mode, 
					 BYTE *iv, int *ivSize )
	{
	CRYPT_ALGO cryptAlgo;
	BYTE buffer[ MAX_OID_SIZE ];
	int bufferLength, cryptMode, status;

	/* Read the AlgorithmIdentifier header and OID */
	readSequence( stream, NULL );
	status = readRawObject( stream, buffer, &bufferLength, MAX_OID_SIZE, 
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );
	if( ( cryptAlgo = oidToAlgorithm( buffer, &cryptMode ) ) == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTAVAIL );
	*algorithm = cryptAlgo;
	*mode = cryptMode;

	/* Read the algorithm parameters */
	if( cryptAlgo == CRYPT_ALGO_CAST )
		{
		readSequence( stream, NULL );
		status = readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		writeShortInteger( stream, 128, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( cryptAlgo == CRYPT_ALGO_DES || cryptAlgo == CRYPT_ALGO_3DES || \
		cryptAlgo == CRYPT_ALGO_BLOWFISH )
		{
		long value;

		if( cryptMode == CRYPT_MODE_ECB )
			{
			readNull( stream );
			return( sGetStatus( stream ) );
			}
		if( cryptMode == CRYPT_MODE_CBC )
			{
			readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
			return( sGetStatus( stream ) );
			}
		readSequence( stream, NULL );
		readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		readShortInteger( stream, &value );
		if( value != 64 )
			return( CRYPT_ERROR_NOTAVAIL );
		return( sGetStatus( stream ) );
		}
	if( cryptAlgo == CRYPT_ALGO_IDEA )
		{
		int tag;

		if( cryptMode == CRYPT_MODE_ECB )
			{
			readNull( stream );
			return( sGetStatus( stream ) );
			}
		readSequence( stream, NULL );
		tag = peekTag( stream );
		if( cryptMode == CRYPT_MODE_CFB )
			{
			/* Skip the CFB r, k, and j parameters */
			while( tag == MAKE_CTAG( 0 ) || tag == MAKE_CTAG( 1 ) || \
				   tag == MAKE_CTAG( 2 ) )
				{
				long value;

				readShortInteger( stream, &value );
				if( value != 64 )
					return( CRYPT_ERROR_NOTAVAIL );
				}
			if( !checkReadCtag( stream, 3, FALSE ) )
				return( CRYPT_ERROR_BADDATA );
			readOctetStringData( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
			}
		if( cryptMode == CRYPT_MODE_OFB && tag == BER_INTEGER )
			{
			long value;

			/* Skip the OFB j parameter */
			readShortInteger( stream, &value );
			if( value != 64 )
				return( CRYPT_ERROR_NOTAVAIL );
			}
		readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		return( sGetStatus( stream ) );
		}
	if( cryptAlgo == CRYPT_ALGO_RC2 )
		{
		long value;

		readSequence( stream, NULL );
		readShortInteger( stream, &value );
		if( value != RC2_KEYSIZE_MAGIC )
			return( CRYPT_ERROR_NOTAVAIL );
		if( cryptMode == CRYPT_MODE_CBC )
			readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		return( sGetStatus( stream ) );
		}
	if( cryptAlgo == CRYPT_ALGO_RC4 )
		{
		readNull( stream );
		return( sGetStatus( stream ) );
		}
	if( cryptAlgo == CRYPT_ALGO_RC5 )
		{
		long value;

		readSequence( stream, NULL );
		readShortInteger( stream, &value );
		if( value != 16 )						/* Version */
			return( CRYPT_ERROR_NOTAVAIL );
		readShortInteger( stream, &value );
		if( value != 12 )						/* Rounds */
			return( CRYPT_ERROR_NOTAVAIL );
		readShortInteger( stream, &value );
		if( value != 64 )						/* Block size */
			return( CRYPT_ERROR_NOTAVAIL );
		readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		return( sGetStatus( stream ) );
		}
	if( cryptAlgo == CRYPT_ALGO_SKIPJACK )
		{
		readSequence( stream, NULL );
		readOctetString( stream, iv, ivSize, CRYPT_MAX_IVSIZE );
		return( sGetStatus( stream ) );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Write an EncryptionAlgorithmIdentifier record */

int writeContextCryptAlgoID( STREAM *stream, 
							 const CRYPT_CONTEXT iCryptContext )
	{
	BYTE iv[ CRYPT_MAX_IVSIZE ], *oid;
	CRYPT_ALGO algorithm;
	CRYPT_MODE mode;
	int oidSize, ivSize, sizeofIV, status;

	/* Extract the information we need to write the AlgorithmIdentifier */
	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &algorithm, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &mode, CRYPT_CTXINFO_MODE );
	if( cryptStatusOK( status ) && algorithm != CRYPT_ALGO_RC4 && \
		needsIV( mode ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, iv, CRYPT_MAX_IVSIZE );
		status = krnlSendMessage( iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_CTXINFO_IV );
		ivSize = msgData.length;
		sizeofIV = ( int ) sizeofObject( ivSize );
		}
	if( cryptStatusError( status ) )
		return( status );
	if( ( oid = algorithmToOIDcheck( algorithm, ( CRYPT_ALGO ) mode ) ) == NULL )
		{
		/* Some algorithm+mode combinations can't be encoded using the
		   oddball collection of PKCS #7 OIDs, the best we can do is return
		   a CRYPT_ERROR_NOTAVAIL */
		sSetError( stream, CRYPT_ERROR );
		return( CRYPT_ERROR_NOTAVAIL );
		}
	oidSize = sizeofOID( oid );

	/* Write algorithm-specific OID parameters */
	if( algorithm == CRYPT_ALGO_CAST )
		{
		const int paramSize = sizeofIV + sizeofShortInteger( 128 );

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		writeShortInteger( stream, 128, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_DES || algorithm == CRYPT_ALGO_3DES || \
		algorithm == CRYPT_ALGO_BLOWFISH )
		{
		const int paramSize = ( mode == CRYPT_MODE_ECB ) ? sizeofNull() : \
					( mode == CRYPT_MODE_CBC ) ? sizeofIV : \
					( int ) sizeofObject( sizeofIV + sizeofShortInteger( 64 ) );

		writeSequence( stream, oidSize + paramSize );
		swrite( stream, oid, oidSize );
		if( mode == CRYPT_MODE_ECB )
			{
			writeNull( stream, DEFAULT_TAG );
			return( CRYPT_OK );
			}
		if( mode == CRYPT_MODE_CBC )
			{
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
			return( CRYPT_OK );
			}
		writeSequence( stream, sizeofIV + sizeofShortInteger( 64 ) );
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		writeShortInteger( stream, 64, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_IDEA )
		{
		const int paramSize = ( mode == CRYPT_MODE_ECB ) ? \
							  sizeofNull() : ( int ) sizeofObject( sizeofIV );

		writeSequence( stream, oidSize + paramSize );
		swrite( stream, oid, oidSize );
		if( mode == CRYPT_MODE_ECB )
			{
			writeNull( stream, DEFAULT_TAG );
			return( CRYPT_OK );
			}
		writeSequence( stream, sizeofIV );
		writeOctetString( stream, iv, ivSize, \
						  ( mode == CRYPT_MODE_CFB ) ? 3 : DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_RC2 )
		{
		const int paramSize = ( ( mode == CRYPT_MODE_ECB ) ? 0 : sizeofIV ) +
							  sizeofShortInteger( RC2_KEYSIZE_MAGIC );

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		writeShortInteger( stream, RC2_KEYSIZE_MAGIC, DEFAULT_TAG );
		if( mode == CRYPT_MODE_CBC )
			writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_RC4 )
		{
		writeSequence( stream, oidSize + sizeofNull() );
		swrite( stream, oid, oidSize );
		writeNull( stream, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_RC5 )
		{
		const int paramSize = sizeofShortInteger( 16 ) +
					sizeofShortInteger( 12 ) + sizeofShortInteger( 64 ) +
					sizeofIV;

		writeSequence( stream, oidSize + ( int ) sizeofObject( paramSize ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, paramSize );
		writeShortInteger( stream, 16, DEFAULT_TAG );	/* Version */
		writeShortInteger( stream, 12, DEFAULT_TAG );	/* Rounds */
		writeShortInteger( stream, 64, DEFAULT_TAG );	/* Block size */
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		return( CRYPT_OK );
		}
	if( algorithm == CRYPT_ALGO_SKIPJACK )
		{
		writeSequence( stream, oidSize + ( int ) sizeofObject( sizeofIV ) );
		swrite( stream, oid, oidSize );
		writeSequence( stream, sizeofIV );
		writeOctetString( stream, iv, ivSize, DEFAULT_TAG );
		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*							Read/Write CMS Headers							*
*																			*
****************************************************************************/

/* Read and write CMS headers */

int readCMSheader( STREAM *stream, const OID_SELECTION *oidSelection,
				   long *dataSize )
	{
	BOOLEAN isData = FALSE;
	BYTE buffer[ 32 ];
	long value;
	int totalLength, length, oidEntry, status;

	/* Clear return value */
	if( dataSize != NULL )
		*dataSize = 0;

	/* Read the outer SEQUENCE and OID */
	readSequence( stream, &totalLength );
	status = readRawObject( stream, buffer, &length, 32,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );

	/* Try and find the entry for the OID */
	for( oidEntry = 0; oidSelection[ oidEntry ].oid != NULL; oidEntry++ )
		if( length == sizeofOID( oidSelection[ oidEntry ].oid ) && \
			!memcmp( buffer, oidSelection[ oidEntry ].oid, length ) )
			break;
	if( oidSelection[ oidEntry ].oid == NULL )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* If the content type is data, the content is an OCTET STRING rather
	   than a SEQUENCE so we remember the type for later */
	if( length == 11 && !memcmp( buffer, OID_CMS_DATA, 11 ) )
		isData = TRUE;

	/* Some Microsoft software produces an indefinite encoding for a single
	   OID so we have to check for this */
	if( !totalLength && checkEOC( stream ) )
		totalLength = length;

	/* If the content is supplied externally (for example with a detached
	   sig), there won't be any content present */
	if( totalLength == length )
		{
		if( dataSize != NULL )
			*dataSize = 0;
		}
	else
		{
		/* Read the content [0] tag and OCTET STRING/SEQUENCE */
		if( readTag( stream ) != MAKE_CTAG( 0 ) )
			sSetError( stream, CRYPT_ERROR_BADDATA );
		readLength( stream, NULL );
		if( isData )
			{
			const int tag = readTag( stream );

			if( tag != BER_OCTETSTRING && \
				tag != ( BER_OCTETSTRING | BER_CONSTRUCTED ) )
				sSetError( stream, CRYPT_ERROR_BADDATA );
			}
		else
			if( readTag( stream ) != BER_SEQUENCE )
				sSetError( stream, CRYPT_ERROR_BADDATA );
		readLength( stream, &value );
		if( sGetStatus( stream ) != CRYPT_OK )
			return( sGetStatus( stream ) );
		if( dataSize != NULL )
			*dataSize = ( value ) ? value : CRYPT_UNUSED;
		}

	/* If it's not data in an OCTET STRING, check the version number of the
	   content if required */
	if( !isData && oidSelection[ oidEntry ].minVersion != CRYPT_UNUSED )
		{
		readShortInteger( stream, &value );
		if( value < oidSelection[ oidEntry ].minVersion || \
			value > oidSelection[ oidEntry ].maxVersion )
			sSetError( stream, CRYPT_ERROR_BADDATA );
		}

	return( ( sGetStatus( stream ) == CRYPT_OK ) ? \
			oidSelection[ oidEntry ].selection : sGetStatus( stream ) );
	}

void writeCMSheader( STREAM *stream, const BYTE *oid, const long dataSize )
	{
	const BOOLEAN isData = ( sizeofOID( oid ) == 11 && \
					!memcmp( oid, OID_CMS_DATA, 11 ) ) ? TRUE : FALSE;

	/* If a size is given, write the definite form */
	if( dataSize != CRYPT_UNUSED )
		{
		writeSequence( stream, sizeofOID( oid ) + ( ( dataSize ) ? \
					   ( int ) sizeofObject( sizeofObject( dataSize ) ) : 0 ) );
		writeOID( stream, oid );
		if( !dataSize )
			return;	/* No content, exit */
		writeCtag( stream, 0 );
		writeLength( stream, sizeofObject( dataSize ) );
		writeTag( stream, isData ? BER_OCTETSTRING : BER_SEQUENCE );
		writeLength( stream, dataSize );

		return;
		}

	/* No size given, write the indefinite form */
	writeSequenceIndef( stream );
	writeOID( stream, oid );
	writeCtag0Indef( stream );
	if( isData )
		writeOctetStringIndef( stream );
	else
		writeSequenceIndef( stream );
	}

/* Read and write an encryptedContentInfo header.  The inner content may be
   implicitly or explicitly tagged depending on the exact content type */

int sizeofCMSencrHeader( const BYTE *contentOID, const long dataSize,
						 const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int status, cryptInfoSize;

	/* Determine the encoded size of the AlgorithmIdentifier */
	sMemOpen( &nullStream, NULL, 0 );
	status = writeContextCryptAlgoID( &nullStream, iCryptContext );
	cryptInfoSize = ( int ) stell( &nullStream );
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* Calculate encoded size of SEQUENCE + OID + AlgoID + [0] for the
	   definite or indefinite forms */
	if( dataSize != CRYPT_UNUSED )
		return( ( int ) ( sizeofObject( sizeofOID( contentOID ) + \
				cryptInfoSize + sizeofObject( dataSize ) ) - dataSize ) );
	return( 2 + sizeofOID( contentOID ) + cryptInfoSize + 2 );
	}

int readCMSencrHeader( STREAM *stream, const OID_SELECTION *oidSelection,
					   long *dataSize, CRYPT_ALGO *algorithm,
					   CRYPT_MODE *mode, BYTE *iv, int *ivSize )
	{
	BYTE buffer[ 32 ];
	long value;
	int oidEntry, tag, length, status;

	/* Clear the return values */
	*dataSize = 0;
	*algorithm = CRYPT_ALGO_NONE;
	*mode = CRYPT_MODE_NONE;
	*iv = '\0';
	*ivSize = 0;

	/* Read the outer SEQUENCE and OID */
	readSequence( stream, &length );
	status = readRawObject( stream, buffer, &length, 32,
							BER_OBJECT_IDENTIFIER );
	if( cryptStatusError( status ) )
		return( status );

	/* Try and find the entry for the OID */
	for( oidEntry = 0; oidSelection[ oidEntry ].oid != NULL; oidEntry++ )
		if( length == sizeofOID( oidSelection[ oidEntry ].oid ) && \
			!memcmp( buffer, oidSelection[ oidEntry ].oid, length ) )
			break;
	if( oidSelection[ oidEntry ].oid == NULL )
		{
		sSetError( stream, CRYPT_ERROR_BADDATA );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Read the AlgorithmIdentifier.  This can return non-stream-related
	   errors so if there's an error at this point we exit immediately */
	status = readCryptAlgoID( stream, algorithm, mode, iv, ivSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the content [0] tag */
	tag = readTag( stream );
	if( tag != MAKE_CTAG( 0 ) && tag != MAKE_CTAG_PRIMITIVE( 0 ) )
		sSetError( stream, CRYPT_ERROR_BADDATA );
	readLength( stream, &value );
	if( dataSize != NULL )
		*dataSize = ( value ) ? value : CRYPT_UNUSED;

	return( ( sGetStatus( stream ) == CRYPT_OK ) ? \
			oidSelection[ oidEntry ].selection : sGetStatus( stream ) );
	}

int writeCMSencrHeader( STREAM *stream, const BYTE *contentOID,
						const long dataSize,
						const CRYPT_CONTEXT iCryptContext )
	{
	STREAM nullStream;
	int cryptInfoSize, status;

	/* Determine the encoded size of the AlgorithmIdentifier */
	sMemOpen( &nullStream, NULL, 0 );
	status = writeContextCryptAlgoID( &nullStream, iCryptContext );
	cryptInfoSize = ( int ) stell( &nullStream );
	sMemClose( &nullStream );
	if( cryptStatusError( status ) )
		return( status );

	/* If a size is given, write the definite form */
	if( dataSize != CRYPT_UNUSED )
		{
		writeSequence( stream, sizeofOID( contentOID ) + cryptInfoSize + \
					   ( int ) sizeofObject( dataSize ) );
		writeOID( stream, contentOID );
		status = writeContextCryptAlgoID( stream, iCryptContext );
		writeCtagPrimitive( stream, 0 );
		writeLength( stream, dataSize );

		return( status );
		}

	/* No size given, write the indefinite form */
	writeSequenceIndef( stream );
	writeOID( stream, contentOID );
	status = writeContextCryptAlgoID( stream, iCryptContext );
	writeCtag0Indef( stream );

	return( status );
	}
