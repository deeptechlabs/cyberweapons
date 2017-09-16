/****************************************************************************
*																			*
*						ASN.1 Key Encode/Decode Routines					*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "../cryptctx.h"
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "cryptctx.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*						Key Component Read/Write Routines					*
*																			*
****************************************************************************/

/* The DLP algorithms split the key components over the information in the 
   AlgorithmIdentifier and the actual public/private key components, with the
   (p, q, g) set classed as domain parameters and included in the
   AlgorithmIdentifier and y being the actual key.

	params = SEQ {
		p INTEGER,
		q INTEGER,				-- g for DSA
		g INTEGER,				-- q for DSA
		j INTEGER OPTIONAL,		-- X9.42 only
		validationParams [...]	-- X9.42 only
		}

	key = y INTEGER				-- g^x mod p

   For peculiar historical reasons X9.42 reverses the second two parameters
   from FIPS 186 (so it uses p, g, q instead of p, q, g), so when we read/
   write the parameter information we have to switch the order in which we
   read the values if the algorithm isn't DSA */

#define hasReversedParams( cryptAlgo ) \
		( ( cryptAlgo ) == CRYPT_ALGO_DH || \
		  ( cryptAlgo ) == CRYPT_ALGO_ELGAMAL )

/* The format in which to write the key data */

typedef enum { KEYFORMAT_PUBLIC, KEYFORMAT_PRIVATE, KEYFORMAT_CERT } KEYFORMAT_TYPE;

/* When we're writing bignums we can't use the standard ASN.1 sizeof()
   routines, the following macro works out the encoded size */

#define sizeofEncodedBignum( value ) \
	( ( int ) sizeofObject( bitsToBytes( BN_num_bits( value ) ) + \
							BN_high_bit( value ) ) )

/* Read/write a bignum */

static int writeBignum( STREAM *stream, const BIGNUM *value, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	length = BN_bn2bin( ( BIGNUM * ) value, buffer );
	status = writeInteger( stream, buffer, length, tag );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );

	return( status );
	}

static int readBignum( STREAM *stream, BIGNUM *value, const int tag )
	{
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	/* Read the value into a fixed buffer */
	status = readIntegerTag( stream, buffer, &length, CRYPT_MAX_PKCSIZE, 
							 ( tag == DEFAULT_TAG ) ? \
								DEFAULT_TAG : MAKE_CTAG_PRIMITIVE( tag ) );
	if( cryptStatusError( status ) )
		return( status );
	BN_bin2bn( buffer, length, value );
	zeroise( buffer, CRYPT_MAX_PKCSIZE );

	return( CRYPT_OK );
	}

/* Read and write DLP key info with handling for reversed parameters */

static int readDLPparameters( STREAM *stream, PKC_INFO *dlpKey,
							  const BOOLEAN hasReversedParameters )
	{
	/* Read the header and key parameters */
	readSequence( stream, NULL );
	readBignum( stream, dlpKey->dlpParam_p, DEFAULT_TAG );
	if( hasReversedParameters )
		{
		readBignum( stream, dlpKey->dlpParam_g, DEFAULT_TAG );
		readBignum( stream, dlpKey->dlpParam_q, DEFAULT_TAG );
		}
	else
		{
		readBignum( stream, dlpKey->dlpParam_q, DEFAULT_TAG );
		readBignum( stream, dlpKey->dlpParam_g, DEFAULT_TAG );
		}

	return( sGetStatus( stream ) );
	}

static void writeDLPparameters( STREAM *stream, const PKC_INFO *dlpKey,
								const BOOLEAN hasReversedParameters )
	{
	/* Write the identifier and length fields */
	writeSequence( stream, sizeofEncodedBignum( dlpKey->dlpParam_p ) +
						   sizeofEncodedBignum( dlpKey->dlpParam_q ) +
						   sizeofEncodedBignum( dlpKey->dlpParam_g ) );

	/* Write the parameter fields */
	writeBignum( stream, dlpKey->dlpParam_p, DEFAULT_TAG );
	if( hasReversedParameters )
		{
		writeBignum( stream, dlpKey->dlpParam_g, DEFAULT_TAG );
		writeBignum( stream, dlpKey->dlpParam_q, DEFAULT_TAG );
		}
	else
		{
		writeBignum( stream, dlpKey->dlpParam_q, DEFAULT_TAG );
		writeBignum( stream, dlpKey->dlpParam_g, DEFAULT_TAG );
		}
	}

static int readDLPcomponents( STREAM *stream, PKC_INFO *dlpKey,
							  const KEYFORMAT_TYPE formatType )
	{
	/* Set up the general information fields */
	dlpKey->isPublicKey = ( formatType == KEYFORMAT_PUBLIC || \
							formatType == KEYFORMAT_CERT ) ? TRUE : FALSE;

	/* If it's a cert there's a single INTEGER component */
	if( formatType == KEYFORMAT_CERT )
		{
		readBignum( stream, dlpKey->dlpParam_y, DEFAULT_TAG );
		return( sGetStatus( stream ) );
		}

	/* Read the header and key components */
	readSequence( stream, NULL );
	if( formatType == KEYFORMAT_PUBLIC )
		readBignum( stream, dlpKey->dlpParam_y, 0 );
	else
		readBignum( stream, dlpKey->dlpParam_x, 0 );

	return( sGetStatus( stream ) );
	}

static void writeDLPcomponents( STREAM *stream, const PKC_INFO *dlpKey,
								const KEYFORMAT_TYPE formatType )
	{
	/* When we're generating a DH key ID, only p, q, and g are initialised, 
	   so we write a special-case zero y value.  This is a somewhat ugly 
	   side-effect of the odd way in which DH "public keys" work */
	if( BN_is_zero( dlpKey->dlpParam_y ) )
		{
		swrite( stream, "\x02\x00", 2 );
		return;
		}

	/* If it's a cert there's a single INTEGER component */
	if( formatType == KEYFORMAT_CERT )
		{
		writeBignum( stream, dlpKey->dlpParam_y, DEFAULT_TAG );
		return;
		}

	/* Write the header and key components */
	writeSequence( stream, ( formatType == KEYFORMAT_PUBLIC ) ? \
				   sizeofEncodedBignum( dlpKey->dlpParam_y ) : \
				   sizeofEncodedBignum( dlpKey->dlpParam_x ) );
	if( formatType == KEYFORMAT_PUBLIC )
		writeBignum( stream, dlpKey->dlpParam_y, 0 );
	else
		writeBignum( stream, dlpKey->dlpParam_x, 0 );
	}

/* Read and write RSA key info */

static int readRSAcomponents( STREAM *stream, PKC_INFO *rsaKey,
							  const KEYFORMAT_TYPE formatType )
	{
	long value;

	/* Set up the general information fields */
	rsaKey->isPublicKey = ( formatType == KEYFORMAT_PUBLIC || \
							formatType == KEYFORMAT_CERT ) ? TRUE : FALSE;

	/* Read the header and key components */
	readSequence( stream, NULL );
	if( formatType == KEYFORMAT_CERT )
		{
		readBignum( stream, rsaKey->rsaParam_n, DEFAULT_TAG );
		readBignum( stream, rsaKey->rsaParam_e, DEFAULT_TAG );
		return( sGetStatus( stream ) );
		}
	readConstructed( stream, NULL, 0 );
	if( formatType == KEYFORMAT_PUBLIC )
		{
		readBignum( stream, rsaKey->rsaParam_n, DEFAULT_TAG );
		readBignum( stream, rsaKey->rsaParam_e, DEFAULT_TAG );
		}
	else
		{
		readBignum( stream, rsaKey->rsaParam_n, 0 );
		readBignum( stream, rsaKey->rsaParam_e, 1 );
		readBignum( stream, rsaKey->rsaParam_d, 2 );
		readBignum( stream, rsaKey->rsaParam_p, 3 );
		readBignum( stream, rsaKey->rsaParam_q, 4 );
		readBignum( stream, rsaKey->rsaParam_exponent1, 5 );
		readBignum( stream, rsaKey->rsaParam_exponent2, 6 );
		readBignum( stream, rsaKey->rsaParam_u, 7 );
		}
	readShortInteger( stream, &value );

	return( sGetStatus( stream ) );
	}

static void writeRSAcomponents( STREAM *stream, const PKC_INFO *rsaKey,
								const KEYFORMAT_TYPE formatType )
	{
	const int modulusLength = BN_num_bits( rsaKey->rsaParam_n );
	int length;

	/* Determine the size of the public and private fields */
	length = sizeofEncodedBignum( rsaKey->rsaParam_n ) +
			 sizeofEncodedBignum( rsaKey->rsaParam_e );
	if( formatType == KEYFORMAT_PRIVATE )
		length += sizeofEncodedBignum( rsaKey->rsaParam_d ) +
				  sizeofEncodedBignum( rsaKey->rsaParam_p ) +
				  sizeofEncodedBignum( rsaKey->rsaParam_q ) +
				  sizeofEncodedBignum( rsaKey->rsaParam_exponent1 ) +
				  sizeofEncodedBignum( rsaKey->rsaParam_exponent2 ) +
				  sizeofEncodedBignum( rsaKey->rsaParam_u );

	/* Write the the PKC fields */
	if( formatType == KEYFORMAT_CERT )
		{
		writeSequence( stream, length );
		writeBignum( stream, rsaKey->rsaParam_n, DEFAULT_TAG );
		writeBignum( stream, rsaKey->rsaParam_e, DEFAULT_TAG );
		return;
		}
	writeSequence( stream, ( int ) sizeofObject( length ) + \
				   sizeofShortInteger( modulusLength ) );
	writeConstructed( stream, length, 0 );
	if( formatType == KEYFORMAT_PUBLIC )
		{
		writeBignum( stream, rsaKey->rsaParam_n, DEFAULT_TAG );
		writeBignum( stream, rsaKey->rsaParam_e, DEFAULT_TAG );
		}
	else
		{
		writeBignum( stream, rsaKey->rsaParam_n, 0 );
		writeBignum( stream, rsaKey->rsaParam_e, 1 );
		writeBignum( stream, rsaKey->rsaParam_d, 2 );
		writeBignum( stream, rsaKey->rsaParam_p, 3 );
		writeBignum( stream, rsaKey->rsaParam_q, 4 );
		writeBignum( stream, rsaKey->rsaParam_exponent1, 5 );
		writeBignum( stream, rsaKey->rsaParam_exponent2, 6 );
		writeBignum( stream, rsaKey->rsaParam_u, 7 );
		}
	writeShortInteger( stream, modulusLength, DEFAULT_TAG );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Generate a key ID, which is the SHA-1 hash of the SubjectPublicKeyInfo.
   There are about half a dozen incompatible ways of generating X.509
   keyIdentifiers, the following is conformant with the PKIX specification
   ("use whatever you like as long as it's unique"), but differs slightly
   from one common method which hashes the SubjectPublicKey without the
   BIT STRING encapsulation.  The problem with this is that a number of DLP-
   based algorithms use a single integer as the SubjectPublicKey, leading to
   key ID clashes */

static void calculateFlatKeyID( const void *keyInfo, const int keyInfoSize, 
								BYTE *keyID )
	{
	HASHFUNCTION hashFunction;
	int hashSize;

	/* Hash the key info to get the key ID */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( NULL, keyID, ( BYTE * ) keyInfo, keyInfoSize, HASH_ALL );
	}

int calculateKeyID( CRYPT_INFO *cryptInfo )
	{
	int writePublicKey( STREAM *stream, const CRYPT_INFO *cryptInfo );
	STREAM stream;
	BYTE buffer[ ( CRYPT_MAX_PKCSIZE * 2 ) + 50 ];
	const CRYPT_ALGO cryptAlgo = cryptInfo->capabilityInfo->cryptAlgo;
	int status;

	/* If the public key info is present in pre-encoded form, calculate the
	   key ID directly from that */
	if( cryptInfo->ctxPKC.publicKeyInfo != NULL )
		{
		STREAM stream;
		long length;

		calculateFlatKeyID( cryptInfo->ctxPKC.publicKeyInfo, 
							cryptInfo->ctxPKC.publicKeyInfoSize, 
							cryptInfo->ctxPKC.keyID );
		if( cryptAlgo != CRYPT_ALGO_KEA )
			return( CRYPT_OK );
		
		/* If it's a KEA context, we also need to remember the start and 
		   length of the domain parameters and key agreement public value in 
		   the encoded key data */
		sMemConnect( &stream, cryptInfo->ctxPKC.publicKeyInfo, 
					 cryptInfo->ctxPKC.publicKeyInfoSize );
		readSequence( &stream, NULL );
		readSequence( &stream, NULL );
		readUniversal( &stream );
		readTag( &stream );
		readLength( &stream, &length );
		cryptInfo->ctxPKC.domainParamPtr = sMemBufPtr( &stream );
		cryptInfo->ctxPKC.domainParamSize = ( int ) length;
		sSkip( &stream, length );
		readTag( &stream );
		readLength( &stream, &length );
		sgetc( &stream );	/* Skip extra bit count in bitfield */
		cryptInfo->ctxPKC.publicValuePtr = sMemBufPtr( &stream );
		cryptInfo->ctxPKC.publicValueSize = ( int ) length - 1;
		assert( sGetStatus( &stream ) == CRYPT_OK );
		sMemDisconnect( &stream );

		return( CRYPT_OK );
		}

	/* Write the public key fields to a buffer and hash them to get the key
	   ID */
	sMemOpen( &stream, buffer, ( CRYPT_MAX_PKCSIZE * 2 ) + 50 );
	status = writePublicKey( &stream, cryptInfo );
	calculateFlatKeyID( buffer, ( int ) stell( &stream ),
						cryptInfo->ctxPKC.keyID );
	sMemClose( &stream );

	return( status );
	}

/****************************************************************************
*																			*
*						sizeof() methods for ASN.1 Types					*
*																			*
****************************************************************************/

/* Determine the size of the DLP key info */

static int sizeofDLPparameters( const PKC_INFO *dlpKey )
	{
	return( ( int ) sizeofObject( \
			sizeofEncodedBignum( dlpKey->dlpParam_p ) +
			sizeofEncodedBignum( dlpKey->dlpParam_q ) +
			sizeofEncodedBignum( dlpKey->dlpParam_g ) ) );
	}

static int sizeofDLPcomponents( const PKC_INFO *dlpKey,
								const KEYFORMAT_TYPE formatType )
	{
	assert( formatType == KEYFORMAT_CERT );

	return( sizeofEncodedBignum( dlpKey->dlpParam_y ) );
	}

/* Determine the size of the RSA key info */

static int sizeofRSAcomponents( const PKC_INFO *rsaKey,
								const KEYFORMAT_TYPE formatType )
	{
	assert( formatType == KEYFORMAT_CERT );

	return( ( int ) sizeofObject( \
			sizeofEncodedBignum( rsaKey->rsaParam_n ) +
			sizeofEncodedBignum( rsaKey->rsaParam_e ) ) );
	}

/* Determine the size of the payload of a SubjectPublicKeyInfo record (not 
   including the SEQUENCE encapsulation) */

static int sizeofPublicParameters( const CRYPT_ALGO cryptAlgo,
								   const PKC_INFO *pkcInfo )
	{
	if( isDLPAlgorithm( cryptAlgo ) )
		return( sizeofDLPparameters( pkcInfo ) );

	assert( cryptAlgo == CRYPT_ALGO_RSA );
	return( 0 );
	}

static int sizeofPublicComponents( const CRYPT_ALGO cryptAlgo,
								   const PKC_INFO *pkcInfo )
	{
	if( isDLPAlgorithm( cryptAlgo ) )
		return( sizeofDLPcomponents( pkcInfo, KEYFORMAT_CERT ) );

	assert( cryptAlgo == CRYPT_ALGO_RSA );
	return( sizeofRSAcomponents( pkcInfo, KEYFORMAT_CERT ) );
	}

/****************************************************************************
*																			*
*							Read/Write X.509 Key Records					*
*																			*
****************************************************************************/

/* Read a public key from an X.509 SubjectPublicKeyInfo record */

int readPublicKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
				   const READKEY_OPTION_TYPE option )
	{
	CRYPT_ALGO cryptAlgo;
	CREATEOBJECT_INFO createInfo;
	CRYPT_INFO *cryptInfoPtr;
	int extraLength, status;

	assert( option >= READKEY_OPTION_NONE && option < READKEY_OPTION_LAST );

	/* Clear the return value */
	*iCryptContext = CRYPT_ERROR;

	/* Read the SubjectPublicKeyInfo header field and create a context to
	   read the public key information into */
	status = readSequence( stream, NULL );
	if( !cryptStatusError( status ) )
		status = readAlgoIDex( stream, &cryptAlgo, NULL, &extraLength );
	if( !cryptStatusError( status ) )
		{
		setMessageCreateObjectInfo( &createInfo, cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( createInfo.cryptHandle, cryptInfoPtr, 
							  OBJECT_TYPE_CONTEXT );

	/* If there's parameter data present, read it now */
	if( extraLength )
		{
		assert( isDLPAlgorithm( cryptAlgo ) );

		status = readDLPparameters( stream, &cryptInfoPtr->ctxPKC,
									hasReversedParams( cryptAlgo ) );
		}

	/* Read the BITSTRING encapsulation of the public key fields */
	if( !cryptStatusError( status ) && readTag( stream ) != BER_BITSTRING )
		status = CRYPT_ERROR_BADDATA;
	readLength( stream, NULL );
	sgetc( stream );	/* Skip extra bit count in bitfield */
	if( cryptStatusError( status ) )
		{
		unlockResource( cryptInfoPtr );
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* Finally, read the PKC information */
	if( isDLPAlgorithm( cryptAlgo ) )
		status = readDLPcomponents( stream, &cryptInfoPtr->ctxPKC,
									KEYFORMAT_CERT );
	else
		{
		assert( cryptAlgo == CRYPT_ALGO_RSA );

		status = readRSAcomponents( stream, &cryptInfoPtr->ctxPKC,
									KEYFORMAT_CERT );
		}
	unlockResource( cryptInfoPtr );
	if( cryptStatusOK( status ) && option != READKEY_OPTION_DEFERREDLOAD )
		{
		PKCINFO_LOADINTERNAL dummy;
		RESOURCE_DATA msgData;

		/* If everything went OK, perform an internal load which uses the
		   values already present in the context */
		setResourceData( &msgData, &dummy, sizeof( PKCINFO_LOADINTERNAL ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEY_COMPONENTS );
		if( cryptArgError( status ) )
			status = CRYPT_ERROR_BADDATA;	/* Map to a more appropriate code */
		}
	if( cryptStatusError( status ) )
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	else
		*iCryptContext = createInfo.cryptHandle;

	return( status );
	}

/* Write a public key to an X.509 SubjectPublicKeyInfo record */

static int writeSubjectPublicKey( STREAM *stream, const CRYPT_ALGO cryptAlgo,
								  const PKC_INFO *pkcInfo )
	{
	/* Write the PKC information */
	if( isDLPAlgorithm( cryptAlgo ) )
		writeDLPcomponents( stream, pkcInfo, KEYFORMAT_CERT );
	else
		{
		assert( cryptAlgo == CRYPT_ALGO_RSA );

		writeRSAcomponents( stream, pkcInfo, KEYFORMAT_CERT );
		}
	return( sGetStatus( stream ) );
	}

int writePublicKey( STREAM *stream, const CRYPT_INFO *cryptInfoPtr )
	{
	const CRYPT_ALGO cryptAlgo = cryptInfoPtr->capabilityInfo->cryptAlgo;
	const PKC_INFO *pkcInfo = &cryptInfoPtr->ctxPKC;
	const int parameterSize = sizeofPublicParameters( cryptAlgo, pkcInfo );
	const int componentSize = sizeofPublicComponents( cryptAlgo, pkcInfo );
	int totalSize;

	/* Determine the size of the AlgorithmIdentifier record and the
	   BITSTRING-encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + 
				( int ) sizeofObject( componentSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( stream, totalSize );
	writeAlgoIDex( stream, cryptAlgo, CRYPT_ALGO_NONE, parameterSize );

	/* Write the parameter data if necessary */
	if( parameterSize )
		{
		assert( isDLPAlgorithm( cryptAlgo ) );
		
		writeDLPparameters( stream, pkcInfo, hasReversedParams( cryptAlgo ) );
		}

	/* Write the BITSTRING wrapper and the PKC information */
	writeTag( stream, BER_BITSTRING );
	writeLength( stream, componentSize + 1 );	/* +1 for bitstring */
	sputc( stream, 0 );
	return( writeSubjectPublicKey( stream, cryptAlgo, pkcInfo ) );
	}

/****************************************************************************
*																			*
*							Read/Write Private Key Records					*
*																			*
****************************************************************************/

/* Read private key components.  This function assumes that the public
   portion of the context has already been set up */

int readPrivateKey( STREAM *stream, CRYPT_INFO *cryptInfoPtr )
	{
	PKCINFO_LOADINTERNAL dummy;
	RESOURCE_DATA msgData;
	int status;

	/* Read the private key information */
	if( isDLPAlgorithm( cryptInfoPtr->capabilityInfo->cryptAlgo ) )
		status = readDLPcomponents( stream, &cryptInfoPtr->ctxPKC,
									KEYFORMAT_PRIVATE );
	else
		{
		assert( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

		status = readRSAcomponents( stream, &cryptInfoPtr->ctxPKC, 
									KEYFORMAT_PRIVATE );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If everything went OK, perform an internal load which uses the values 
	   already present in the context */
	setResourceData( &msgData, &dummy, sizeof( PKCINFO_LOADINTERNAL ) );
	status = krnlSendMessage( cryptInfoPtr->objectHandle, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
							  CRYPT_CTXINFO_KEY_COMPONENTS );
	if( cryptArgError( status ) )
		status = CRYPT_ERROR_BADDATA;	/* Map to a more appropriate code */

	return( status );
	}

/* Write private key components.  This is just a wrapper for the various
   writeXXXcomponents() functions */

int writePrivateKey( STREAM *stream, const CRYPT_INFO *cryptInfoPtr )
	{
	/* Write the private key information */
	if( isDLPAlgorithm( cryptInfoPtr->capabilityInfo->cryptAlgo ) )
		writeDLPcomponents( stream, &cryptInfoPtr->ctxPKC, KEYFORMAT_PRIVATE );
	else
		{
		assert( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

		writeRSAcomponents( stream, &cryptInfoPtr->ctxPKC, KEYFORMAT_PRIVATE );
		}
	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*							Write Flat Public Key Data						*
*																			*
****************************************************************************/

/* Generate KEA domain parameters from flat-format values */

static int generateDomainParameters( BYTE *domainParameters,
									 const void *p, const int pLength,
									 const void *q, const int qLength,
									 const void *g, const int gLength )
	{
	STREAM stream;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], dataBuffer[ CRYPT_MAX_PKCSIZE * 3 ];
	HASHFUNCTION hashFunction;
	const int pSize = sizeofInteger( p, pLength );
	const int qSize = sizeofInteger( q, qLength );
	const int gSize = sizeofInteger( g, gLength );
	int hashSize, dataSize, i;

	/* Write the parameters to a stream.  The stream length is in case
	   KEA is at some point be extended up to the max.allowed PKC size */
	sMemOpen( &stream, dataBuffer, CRYPT_MAX_PKCSIZE * 3 );
	writeSequence( &stream, pSize + qSize + gSize );
	writeInteger( &stream, p, pLength, DEFAULT_TAG );
	writeInteger( &stream, q, qLength, DEFAULT_TAG );
	writeInteger( &stream, g, gLength, DEFAULT_TAG );
	assert( !cryptStatusError( sGetStatus( &stream ) ) );
	dataSize = ( int ) stell( &stream );
	sMemDisconnect( &stream );

	/* Hash the DSA/KEA parameters and reduce them down to get the domain 
	   identifier */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
	hashFunction( NULL, hash, dataBuffer, dataSize, HASH_ALL );
	zeroise( dataBuffer, CRYPT_MAX_PKCSIZE * 3 );
	hashSize /= 2;	/* Output = hash result folded in half */
	for( i = 0; i < hashSize; i++ )
		domainParameters[ i ] = hash[ i ] ^ hash[ hashSize + i ];

	return( hashSize );
	}

/* If the keys are stored in a crypto device rather than being held in the 
   context, all we have available are the public components in flat format.
   The following code writes flat-format public components in the X.509
   format */

int sizeofFlatPublicKey( const CRYPT_ALGO cryptAlgo, 
						 const void *component1, const int component1Length,
						 const void *component2, const int component2Length,
						 const void *component3, const int component3Length,
						 const void *component4, const int component4Length )
	{
	const int comp1Size = sizeofInteger( component1, component1Length );
	const int comp2Size = sizeofInteger( component2, component2Length );
	const int comp3Size = ( component3 == NULL ) ? 0 : \
						  sizeofInteger( component3, component3Length );
	const int comp4Size = ( component4 == NULL ) ? 0 : \
						  sizeofInteger( component4, component4Length );
	const int parameterSize = ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size + comp3Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				( int) sizeofObject( 10 ) : 0;
	const int componentSize = ( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				component4Length : comp4Size;
	int totalSize;

	assert( cryptAlgo == CRYPT_ALGO_DSA || cryptAlgo == CRYPT_ALGO_KEA || \
			cryptAlgo == CRYPT_ALGO_RSA );

	/* Determine the size of the AlgorithmIdentifier record and the
	   BITSTRING-encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + 
				( int ) sizeofObject( componentSize + 1 );

	return( ( int ) sizeofObject( totalSize ) );
	}

int writeFlatPublicKey( void *buffer, const CRYPT_ALGO cryptAlgo, 
						const void *component1, const int component1Length,
						const void *component2, const int component2Length,
						const void *component3, const int component3Length,
						const void *component4, const int component4Length )
	{
	STREAM stream;
	const int comp1Size = sizeofInteger( component1, component1Length );
	const int comp2Size = sizeofInteger( component2, component2Length );
	const int comp3Size = ( component3 == NULL ) ? 0 : \
						  sizeofInteger( component3, component3Length );
	const int comp4Size = ( component4 == NULL ) ? 0 : \
						  sizeofInteger( component4, component4Length );
	const int parameterSize = ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size + comp3Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				( int) sizeofObject( 10 ) : 0;
	const int componentSize = ( cryptAlgo == CRYPT_ALGO_RSA ) ? \
				( int ) sizeofObject( comp1Size + comp2Size ) : \
							  ( cryptAlgo == CRYPT_ALGO_KEA ) ? \
				component4Length : comp4Size;
	int totalSize, status;

	sMemOpen( &stream, buffer, ( buffer == NULL ) ? 0 : STREAMSIZE_UNKNOWN );

	/* Determine the size of the AlgorithmIdentifier record and the
	   BITSTRING-encapsulated public-key data (the +1 is for the bitstring) */
	totalSize = sizeofAlgoIDex( cryptAlgo, CRYPT_ALGO_NONE, parameterSize ) + 
				( int ) sizeofObject( componentSize + 1 );

	/* Write the SubjectPublicKeyInfo header field */
	writeSequence( &stream, totalSize );
	writeAlgoIDex( &stream, cryptAlgo, CRYPT_ALGO_NONE, parameterSize );

	/* Write the parameter data if necessary */
	if( cryptAlgo == CRYPT_ALGO_DSA )
		{
		writeSequence( &stream, comp1Size + comp2Size + comp3Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
		writeInteger( &stream, component3, component3Length, DEFAULT_TAG );
		}
	if( cryptAlgo == CRYPT_ALGO_KEA )
		{
		BYTE domainParameters[ 10 ];
		const int domainParameterLength = \
					generateDomainParameters( domainParameters, 
											  component1, component1Length,
											  component2, component2Length,
											  component3, component3Length );

		writeOctetString( &stream, domainParameters, domainParameterLength, 
						  DEFAULT_TAG );
		}

	/* Write the BITSTRING wrapper and the PKC information */
	writeTag( &stream, BER_BITSTRING );
	writeLength( &stream, componentSize + 1 );	/* +1 for bitstring */
	sputc( &stream, 0 );
	if( cryptAlgo == CRYPT_ALGO_RSA )
		{
		writeSequence( &stream, comp1Size + comp2Size );
		writeInteger( &stream, component1, component1Length, DEFAULT_TAG );
		writeInteger( &stream, component2, component2Length, DEFAULT_TAG );
		}
	else
		if( cryptAlgo == CRYPT_ALGO_DSA )
			writeInteger( &stream, component4, component4Length, DEFAULT_TAG );
		else
			swrite( &stream, component4, component4Length );

	/* Clean up */
	status = sGetStatus( &stream );
	sMemDisconnect( &stream );
	return( status );
	}

/****************************************************************************
*																			*
*							Read/Write DL Value Record						*
*																			*
****************************************************************************/

/* Unlike the simpler RSA PKC, DL-based PKC's produce a pair of values which
   need to be encoded as ASN.1 records.  The following two functions perform
   this en/decoding */

int encodeDLValues( BYTE *buffer, BIGNUM *value1, BIGNUM *value2 )
	{
	STREAM stream;
	BYTE dataBuffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );

	/* Write the identifier and length fields */
	writeTag( &stream, BER_SEQUENCE );
	writeLength( &stream, sizeofEncodedBignum( value1 ) +
						  sizeofEncodedBignum( value2 ) );

	/* Write the values */
	length = BN_bn2bin( value1, dataBuffer );
	writeInteger( &stream, dataBuffer, length, DEFAULT_TAG );
	length = BN_bn2bin( value2, dataBuffer );
	writeInteger( &stream, dataBuffer, length, DEFAULT_TAG );

	/* Clean up */
	status = ( int ) stell( &stream );
	sMemDisconnect( &stream );
	zeroise( dataBuffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

int decodeDLValues( BYTE *buffer, BIGNUM **value1, BIGNUM **value2 )
	{
	STREAM stream;
	BYTE dataBuffer[ CRYPT_MAX_PKCSIZE ];
	int length, status;

	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );

	/* Read start of parameter sequence fields */
	if( readTag( &stream ) != BER_SEQUENCE )
		{
		sMemDisconnect( &stream );
		return( CRYPT_ERROR_BADDATA );
		}
	readLength( &stream, NULL );	/* Skip SEQ len.*/

	/* Read the DL components from the buffer */
	status = readInteger( &stream, dataBuffer, &length, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_BADDATA );
	*value1 = BN_new();
	BN_bin2bn( dataBuffer, length, *value1 );
	status = readInteger( &stream, dataBuffer, &length, CRYPT_MAX_PKCSIZE );
	if( cryptStatusError( status ) )
		{
		BN_clear_free( *value1 );
		return( CRYPT_ERROR_BADDATA );
		}
	*value2 = BN_new();
	BN_bin2bn( dataBuffer, length, *value2 );

	/* Clean up */
	sMemDisconnect( &stream );
	zeroise( dataBuffer, length );
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Read/Write Ad Hoc-format Key Records				*
*																			*
****************************************************************************/

/* Determine the length of an SSH-format bignum, a signed bignum value with
   the length expressed in bits */

#define sshBignumLength( value ) \
	( BN_num_bits( value ) + bytesToBits( BN_high_bit( value ) ) )

/* Read an SSH public key */

static int readSshBignum( STREAM *stream, BIGNUM *value, 
						  const int minBits, const int maxBits )
	{
	int length;

	/* Read the length and make sure it's within acceptable limits */
	length = ( sgetc( stream ) << 8 ) | sgetc( stream );
	if( length < minBits || length > maxBits )
		return( CRYPT_ERROR_BADDATA );

	/* Read the bignum */
	length = bitsToBytes( length );
	BN_bin2bn( sMemBufPtr( stream ), length, value );
	sSkip( stream, length );

	return( CRYPT_OK );
	}

int readSshPublicKey( STREAM *stream, CRYPT_INFO *cryptInfoPtr )
	{
	PKC_INFO *rsaKey = &cryptInfoPtr->ctxPKC;
	PKCINFO_LOADINTERNAL dummy;
	RESOURCE_DATA msgData;
	int status;

	assert( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );

	/* Read the SSH public key information */
	rsaKey->isPublicKey = TRUE;
	status = readSshBignum( stream, rsaKey->rsaParam_e, 2, 256 );
	if( cryptStatusOK( status ) )
		status = readSshBignum( stream, rsaKey->rsaParam_n, 
								512, bytesToBits( CRYPT_MAX_PKCSIZE ) );
	if( cryptStatusError( status ) )
		return( status );

	/* If everything went OK, perform an internal load which uses the values 
	   already present in the context */
	setResourceData( &msgData, &dummy, sizeof( PKCINFO_LOADINTERNAL ) );
	status = krnlSendMessage( cryptInfoPtr->objectHandle, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_CTXINFO_KEY_COMPONENTS );
	return( cryptArgError( status ) ? CRYPT_ERROR_BADDATA : status );
	}

#if 0
/* Write a public key in one of a number of ad hoc formats */

static int writeSshPublicKey( void *data, const PKC_INFO *rsaKey )
	{
	BYTE *dataPtr = data;
	long length;
	int bnLength;

	length = sshBignumLength( rsaKey->rsaParam_e );
	mputBLong( dataPtr, length );
	if( BN_high_bit( rsaKey->rsaParam_e ) )
		*dataPtr++ = 0;
	bnLength = BN_bn2bin( rsaKey->rsaParam_e, dataPtr );
	dataPtr += bnLength;
	length = sshBignumLength( rsaKey->rsaParam_n );
	mputBLong( dataPtr, length );
	if( BN_high_bit( rsaKey->rsaParam_n ) )
		*dataPtr++ = 0;
	bnLength = BN_bn2bin( rsaKey->rsaParam_n, dataPtr );
	dataPtr += bnLength;

	return( ( int ) ( dataPtr - ( BYTE * ) data ) );
	}

int writeAdhocPublicKey( void *data, const CRYPT_CONTEXT iCryptContext )
	{
	CRYPT_INFO *cryptInfoPtr;
	int status;

	/* Write the key in SSH format */
	getCheckInternalResource( iCryptContext, cryptInfoPtr, OBJECT_TYPE_CONTEXT );
	assert( cryptInfoPtr->capabilityInfo->cryptAlgo == CRYPT_ALGO_RSA );
	status = writeSshPublicKey( data, &cryptInfoPtr->ctxPKC );

	unlockResourceExit( cryptInfoPtr, status );
	}
#endif /* 0 */
