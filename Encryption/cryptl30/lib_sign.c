/****************************************************************************
*																			*
*							cryptlib Signature Routines						*
*						Copyright Peter Gutmann 1993-1999					*
*																			*
****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include "crypt.h"
#ifdef INC_ALL
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
#endif /* Compiler-specific includes */

/* Prototypes for functions in keymgmt/cms.c */

int readSignerInfo( STREAM *stream, CRYPT_ALGO *hashAlgorithm,
					void **iAndSStart, void **attributes, int *attributeSize,
					void **signature );
int writeSignerInfo( STREAM *stream, CRYPT_CERTIFICATE certificate,
					 const CRYPT_ALGO hashAlgorithm,
					 const void *attributes, const int attributeSize,
					 const void *signature, const int signatureSize );

/****************************************************************************
*																			*
*							Low-level Signature Functions 					*
*																			*
****************************************************************************/

/* Create a signature */

static int createSignature( void *signature, int *signatureLength,
							const CRYPT_CONTEXT iSignContext,
							const CRYPT_CONTEXT iHashContext,
							const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO signAlgo, hashAlgo;
	MECHANISM_SIGN_INFO mechanismInfo;
	BYTE hash[ CRYPT_MAX_HASHSIZE ], dataToSign[ CRYPT_MAX_PKCSIZE ];
	int hashSize = 16;	/* Dummy value (non-)used for sig.length checks */
	int length, status;

	/* Extract general information */
	status = krnlSendMessage( iSignContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && signature != NULL )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		if( cryptStatusError( status ) )
			return( status );
		hashSize = msgData.length;
		}

	/* If we're just doing a length check, write dummy data to a null stream
	   and return its length */
	if( signature == NULL )
		{
		STREAM nullStream;

		/* Determine how long the signature will be.  In the case of the DLP-
		   based PKC's it's just an estimate since it can change by up to two 
		   bytes depending on whether the signature values have the high bit 
		   set or not, which requires zero-padding of the ASN.1-encoded 
		   integers.  This is rather nasty because it means we can't tell how 
		   large a signature will be without actually creating it.

		   The 6/10 bytes at the start are for the ASN.1 SEQUENCE and 2 * 
		   INTEGER encoding */
		if( signAlgo == CRYPT_ALGO_DSA )
			length = 6 + ( 2 * ( 20 + 1 ) );	/* 20 = DSA/SHA hash size */
		else
			{
			/* Calculate the eventual signature size */
			setMechanismSignInfo( &mechanismInfo, NULL, 0, hash, hashSize, 
								  hashAlgo, CRYPT_UNUSED, iSignContext );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
									  RESOURCE_IMESSAGE_DEV_SIGN, 
									  &mechanismInfo, MECHANISM_PKCS1 );
			length = mechanismInfo.signatureLength;
			clearMechanismInfo( &mechanismInfo );
			if( cryptStatusError( status ) )
				return( status );
			}

		sMemOpen( &nullStream, NULL, 0 );
		status = writeSignature( &nullStream, iSignContext, hashAlgo, 
								 dataToSign, length, signatureType );
		*signatureLength = ( int ) stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Turn the hash information into a message digest record and find out
	   how much space we need to allocate to it in the signature record (with
	   a slight exception for DLP-based sigs).  There's no need for a length 
	   check as there is for the key export function since even the largest 
	   hash fits easily within the shortest PKC key cryptlib allows */
	if( signAlgo == CRYPT_ALGO_DSA || signAlgo == CRYPT_ALGO_ELGAMAL )
		{
		/* DSA is only defined for hash algorithms with a block size of 160
		   bits */
		if( hashSize != 20 )
			return( CRYPT_ARGERROR_NUM1 );

		/* Sign the data */
		memcpy( dataToSign, hash, hashSize );
		status = length = krnlSendMessage( iSignContext, 
										   RESOURCE_IMESSAGE_CTX_SIGN, 
										   dataToSign, hashSize );
		}
	else
		{
		setMechanismSignInfo( &mechanismInfo, dataToSign, CRYPT_MAX_PKCSIZE,
							  hash, hashSize, hashAlgo, CRYPT_UNUSED,
							  iSignContext );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_SIGN, 
								  &mechanismInfo, MECHANISM_PKCS1 );
		length = mechanismInfo.signatureLength;
		clearMechanismInfo( &mechanismInfo );
		}

	/* Write the signature record to the output and clean up */
	if( !cryptStatusError( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, signature, STREAMSIZE_UNKNOWN );
		status = writeSignature( &stream, iSignContext, hashAlgo, dataToSign, 
								 length, signatureType );
		*signatureLength = ( int ) stell( &stream );
		sMemDisconnect( &stream );
		}

	/* Clean up */
	zeroise( hash, CRYPT_MAX_HASHSIZE );
	zeroise( dataToSign, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/* Check a signature */

static int checkSignature( const void *signature, 
						   const CRYPT_CONTEXT iSigCheckContext,
						   const CRYPT_CONTEXT iHashContext,
						   const SIGNATURE_TYPE signatureType )
	{
	CRYPT_ALGO signAlgo, hashAlgo;
	MECHANISM_SIGN_INFO mechanismInfo;
	QUERY_INFO signatureInfo;
	BYTE hash[ CRYPT_MAX_HASHSIZE ];
	STREAM stream;
	void *signatureData;
	int signatureDataLength, hashSize, status;

	/* Extract general information */
	status = krnlSendMessage( iSigCheckContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &signAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, hash, CRYPT_MAX_HASHSIZE );
		status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
		hashSize = msgData.length;
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read the signature record up to the start of the signature itself */
	memset( &signatureInfo, 0, sizeof( QUERY_INFO ) );
	sMemConnect( &stream, ( void * ) signature, STREAMSIZE_UNKNOWN );
	status = readSignature( &stream, &signatureInfo, signatureType );
	sMemDisconnect( &stream );
	if( cryptStatusOK( status ) )
		{
		/* Make sure we've been given the correct hash algorithm.  CMS
		   specifies the algorithm at the start of the signed data rather than
		   in the signature algorithm OID, so the check is done elsewhere */
		if( signatureType != SIGNATURE_CMS && \
			hashAlgo != signatureInfo.hashAlgo )
			status = CRYPT_ERROR_SIGNATURE;
		}
	if( cryptStatusError( status ) )
		{
		zeroise( &signatureInfo, sizeof( QUERY_INFO ) );
		return( status );
		}

	/* Make sure we've been given the correct key if the signature format
	   supports this type of check */
	if( signatureType == SIGNATURE_CRYPTLIB && \
		krnlSendMessage( iSigCheckContext, RESOURCE_IMESSAGE_COMPARE,
						 signatureInfo.keyID, 
						 RESOURCE_MESSAGE_COMPARE_KEYID ) != CRYPT_OK )
		{
		zeroise( &signatureInfo, sizeof( QUERY_INFO ) );
		return( CRYPT_ERROR_WRONGKEY );
		}
	signatureData = signatureInfo.dataStart;
	signatureDataLength = signatureInfo.dataLength;
	zeroise( &signatureInfo, sizeof( QUERY_INFO ) );

	/* DLP signatures are handled somewhat specially */
	if( signAlgo == CRYPT_ALGO_DSA || signAlgo == CRYPT_ALGO_ELGAMAL )
		{
		BYTE decryptedSignature[ CRYPT_MAX_PKCSIZE ];

		/* DSA and Elgamal are only defined for hash algorithms with a block 
		   size of 160 bits */
		if( hashSize != 20 )
			return( CRYPT_ARGERROR_NUM1 );

		/* Check the signature validity using the encoded signature data and
		   hash */
		memcpy( decryptedSignature, hash, hashSize );
		memcpy( decryptedSignature + hashSize, signatureData, 
				signatureDataLength );
		status = krnlSendMessage( iSigCheckContext, 
								  RESOURCE_IMESSAGE_CTX_SIGCHECK,
								  decryptedSignature, 
								  hashSize + signatureDataLength );
		zeroise( decryptedSignature, CRYPT_MAX_PKCSIZE );	
		}
	else
		{
		setMechanismSignInfo( &mechanismInfo, signatureData, 
							  signatureDataLength, hash, hashSize, hashAlgo, 
							  CRYPT_UNUSED, iSigCheckContext );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_SIGCHECK, 
								  &mechanismInfo, MECHANISM_PKCS1 );
		clearMechanismInfo( &mechanismInfo );
		}

	return( status );
	}

/****************************************************************************
*																			*
*							X.509-style Signature Functions 				*
*																			*
****************************************************************************/

/* Create/check an X.509-style signature.  These work with objects of the
   form:

	signedObject ::= SEQUENCE {
		object				ANY,
		signatureAlgorithm	AlgorithmIdentifier,
		signature			BIT STRING
		}

  The signature checking is somewhat complex since the information needed to
  obtain the key required to check the signature on an object is contained
  inside the object which is being checked.  For this reason we recognise a
  signContext of CRYPT_ERROR to mean that we should check the object without
  trying to check the signature on it.  The idea is that we first call the
  function will a null context pointer to get information on the object, then
  unpack it to find the signers key and load the information into a PKC
  context, then call it a second time to perform the actual check.

  These functions are for internal use only and don't perform the extensive
  parameter checking or support the get-object-size functionality of the more
  general cryptCreate/CheckSignature() functions */

int createX509signature( void *signedObject, int *signedObjectLength,
						 const void *object, const int objectLength,
						 CRYPT_CONTEXT signContext, const CRYPT_ALGO hashAlgo )
	{
	CREATEOBJECT_INFO createInfo;
	STREAM stream;
#if INT_MAX > 32767
	const BOOLEAN largeObject = ( objectLength > 64000 ) ? TRUE : FALSE;
	BYTE *signatureStart = ( BYTE * ) signedObject + \
						   ( ( largeObject ) ? 5 : 4 ) + objectLength;
#else
	BYTE *signatureStart = ( BYTE * ) signedObject + 4 + objectLength;
#endif /* 32-bit ints */
	int signatureLength, delta, status;

	/* Hash the data to be signed */
	setMessageCreateObjectInfo( &createInfo, hashAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
					 ( void * ) object, objectLength );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
					 ( void * ) object, 0 );

	/* Create the wrapped-up signed object.  This gets somewhat ugly because
	   the only way we can find out how long the signature will be is by
	   actually creating it, since the ASN.1 encoding constraints mean the
	   size can vary by a few bytes depending on what values the integers
	   which make up the signature take.  Because of this, we first generate
	   the signature a reasonable distance back from the start of the buffer,
	   write the header and data to sign at the start, and finally move the
	   signature down to the end of the header.  Because the combination of
	   data to sign and signature are virtually always in the range 256-64K
	   bytes, the data move is almost never performed */
	status = createSignature( signatureStart, &signatureLength, signContext,
							  createInfo.cryptHandle, SIGNATURE_X509 );
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );
	sMemConnect( &stream, signedObject, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, signatureLength + objectLength );
	swrite( &stream, object, objectLength );
#if INT_MAX > 32767
	if( largeObject )
		delta = ( objectLength + signatureLength < 65536L ) ? 1 : 0;
	else
#endif /* 32-bit ints */
	delta = ( objectLength + signatureLength < 128 ) ? 2 : \
			( objectLength + signatureLength < 256 ) ? 1 : 0;
	if( delta )
		/* This only ever really happens for CRL's with a single cert
		   and no extensions */
		memmove( sMemBufPtr( &stream ), sMemBufPtr( &stream ) + delta,
				 signatureLength );

	*signedObjectLength = ( int ) stell( &stream ) + signatureLength;
	sMemDisconnect( &stream );

	return( status );
	}

int checkX509signature( const void *signedObject, void **object,
						int *objectLength, CRYPT_CONTEXT sigCheckContext )
	{
	CRYPT_ALGO signAlgo, sigCheckAlgo, hashAlgo;
	CREATEOBJECT_INFO createInfo;
	STREAM stream;
	BYTE *objectPtr;
	int status, length, extraLength = 0;

	/* Check the start of the object */
	sMemConnect( &stream, ( void * ) signedObject, STREAMSIZE_UNKNOWN );
	status = readSequence( &stream, NULL );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}

	/* Record the start and size of the signed object */
	objectPtr = sMemBufPtr( &stream );
	status = readSequence( &stream, &length );
	if( cryptStatusError( status ) )
		{
		sMemDisconnect( &stream );
		return( status );
		}
	sSkip( &stream, length );		/* Move past the object */
	length += status;				/* Include length of header */
	if( objectLength != NULL )
		*objectLength = length;
	if( object != NULL )
		*object = objectPtr;

	/* If we're just performing a general check on the object, exit now */
	if( sigCheckContext == CRYPT_ERROR )
		{
		sMemDisconnect( &stream );
		return( CRYPT_OK );
		}

	/* Create a hash context from the algorithm identifier of the signature */
	status = krnlSendMessage( sigCheckContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &sigCheckAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		{
		/* If it's a broken CRMF signature, there's an extra [1] 
		   encapsulating the signature */
		if( peekTag( &stream ) == MAKE_CTAG( 1 ) )
			extraLength = readConstructed( &stream, NULL, 1 );
		status = readAlgoIDex( &stream, &signAlgo, &hashAlgo, NULL );
		}
	if( cryptStatusOK( status ) && sigCheckAlgo != signAlgo )
		/* The signature algorithm isn't what we expected, the best we can do
		   is report a certificate data error */
		status = CRYPT_ERROR_BADDATA;
	if( cryptStatusOK( status ) )
		{
		setMessageCreateObjectInfo( &createInfo, hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Hash the signed data and check the signature on the object */
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
					 objectPtr, length );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
					 objectPtr, 0 );
	status = checkSignature( objectPtr + length + extraLength, 
							 sigCheckContext, createInfo.cryptHandle, 
							 SIGNATURE_X509 );

	/* Clean up */
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	return( status );
	}

/****************************************************************************
*																			*
*							Create/Check a Signature 						*
*																			*
****************************************************************************/

/* Create/check a signature */

C_RET cryptCreateSignature( C_OUT void C_PTR signature, 
							C_OUT int C_PTR signatureLength,
							C_IN CRYPT_CONTEXT signContext,
							C_IN CRYPT_CONTEXT hashContext )
	{
	int status;

	/* Perform basic error checking */
	if( signature != NULL )
		{
		if( checkBadPtrWrite( signature, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( signatureLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*signatureLength = 0;
	status = krnlSendMessage( signContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGN );
	if( status == CRYPT_ARGERROR_OBJECT )
		status = CRYPT_ERROR_PARAM3;
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_HASH );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM4 : status );

	/* Call the low-level signature create function to create the signature */
	status = createSignature( signature, signatureLength, signContext,
							  hashContext, SIGNATURE_CRYPTLIB );
	return( ( status == CRYPT_ARGERROR_OBJECT ) ? CRYPT_ERROR_PARAM3 : \
			( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ERROR_PARAM4 : status );
	}

/* Check a signature on a block of data */

C_RET cryptCheckSignature( C_IN void C_PTR signature,
						   C_IN CRYPT_HANDLE sigCheckKey,
						   C_IN CRYPT_CONTEXT hashContext )
	{
	CRYPT_CONTEXT sigCheckContext;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( signature, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_ERROR_PARAM1 );
	status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK );
	if( status == CRYPT_ARGERROR_OBJECT ) 
		status = CRYPT_ERROR_PARAM2;
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_HASH );
		if( status == CRYPT_ARGERROR_OBJECT ) 
			status = CRYPT_ERROR_PARAM3;
		}
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDEPENDENT,
								  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the low-level signature check function to check the signature */
	status = checkSignature( signature, sigCheckContext, hashContext, 
							 SIGNATURE_CRYPTLIB );
	return( ( status == CRYPT_ARGERROR_OBJECT ) ? CRYPT_ERROR_PARAM2 : \
			( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ERROR_PARAM3 : status );
	}

/****************************************************************************
*																			*
*							Extended Create/Check a Signature 				*
*																			*
****************************************************************************/

/* The maximum size for the encoded CMS signed attributes */

#define ENCODED_ATTRIBUTE_SIZE	512

/* Create a CMS signature */

static int createSignedAttributes( CRYPT_CONTEXT iAttributeHash,
								   BYTE *encodedAttributes,
								   int *encodedAttributeSize,
								   const CRYPT_CERTIFICATE iCmsAttributes,
								   const CRYPT_CONTEXT iMessageHash,
								   const BOOLEAN lengthCheckOnly )
	{
	RESOURCE_DATA msgData;
	BYTE temp, hash[ CRYPT_MAX_HASHSIZE ];
	int status;

	/* Extract the message hash information and add it as a messageDigest 
	   attribute, replacing any existing value if necessary.  If we're
	   doing a call just to get the length of the exported data, we use a 
	   dummy hash value since the hashing may not have completed yet */
	krnlSendMessage( iCmsAttributes, RESOURCE_IMESSAGE_DELETEATTRIBUTE,
					 NULL, CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	setResourceData( &msgData, hash, CRYPT_MAX_HASHSIZE );
	if( lengthCheckOnly )
		status = krnlSendMessage( iMessageHash, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE,
								  &msgData.length, CRYPT_CTXINFO_BLOCKSIZE );
	else
		status = krnlSendMessage( iMessageHash, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_HASHVALUE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iCmsAttributes, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusError( status ) )
		return( status );

	/* Export the attributes into an encoded signedAttributes data block,
	   replace the IMPLICIT [ 0 ] tag at the start with a SET OF tag to allow
	   the attributes to be hashed, hash them into the attribute hash context, 
	   and replace the original tag */
	if( lengthCheckOnly )
		{
		setResourceData( &msgData, NULL, 0 );
		}
	else
		setResourceData( &msgData, encodedAttributes, ENCODED_ATTRIBUTE_SIZE );
	status = krnlSendMessage( iCmsAttributes, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ENC_CMSATTR );
	if( cryptStatusError( status ) )
		return( status );
	*encodedAttributeSize = msgData.length;
	temp = encodedAttributes[ 0 ];
	encodedAttributes[ 0 ] = BER_SET;
	krnlSendMessage( iAttributeHash, RESOURCE_IMESSAGE_CTX_HASH, 
					 encodedAttributes, *encodedAttributeSize );
	status = krnlSendMessage( iAttributeHash, RESOURCE_IMESSAGE_CTX_HASH, 
							  "", 0 );
	encodedAttributes[ 0 ] = temp;

	return( status );
	}

static int createSignatureCMS( void *signature, int *signatureLength,
							   const CRYPT_CONTEXT signContext,
							   const CRYPT_CONTEXT iHashContext,
							   const CRYPT_CERTIFICATE extraData )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_CERTIFICATE iCmsAttributes = extraData, iSigningCert;
	CRYPT_ALGO hashAlgo;
	STREAM stream;
	BYTE encodedAttributes[ ENCODED_ATTRIBUTE_SIZE ];
	BYTE dataSignature[ CRYPT_MAX_PKCSIZE ];
	int encodedAttributeSize, dataSignatureSize, length, status;

	/* Get the message hash algo and signing cert */
	status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( signContext, RESOURCE_IMESSAGE_GETDEPENDENT, 
								  &iSigningCert, OBJECT_TYPE_CERTIFICATE );
	else
		if( status == CRYPT_ARGERROR_OBJECT )
			/* Remap the error code to refer to the correct parameter */
			status = CRYPT_ARGERROR_NUM1;
	if( cryptStatusError( status ) )
		return( status );

	/* If we're using signed attributes, set them up to be added to the 
	   signature info */
	if( extraData != CRYPT_UNUSED )
		{
		CREATEOBJECT_INFO createInfo;

		if( extraData == CRYPT_USE_DEFAULT )
			{
			/* If there are no attributes included as extra data, generate 
			   them ourselves */
			setMessageCreateObjectInfo( &createInfo, 
										CRYPT_CERTTYPE_CMS_ATTRIBUTES );
			status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
									  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
									  &createInfo, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			iCmsAttributes = createInfo.cryptHandle;
			}

		/* Generate the signed attributes and hash them into the CMS hash
		   context */
		setMessageCreateObjectInfo( &createInfo, hashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			status = createSignedAttributes( createInfo.cryptHandle, 
								encodedAttributes, &encodedAttributeSize,
								iCmsAttributes, iHashContext,
								( signature == NULL ) ? TRUE : FALSE );
		if( extraData == CRYPT_USE_DEFAULT )
			krnlSendNotifier( iCmsAttributes, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			return( status );
			}
		iCmsHashContext = createInfo.cryptHandle;
		}
	else
		/* No signed attributes present */
		encodedAttributeSize = 0;

	/* Create the signature */
	status = createSignature( ( signature == NULL ) ? NULL : dataSignature,
							  &dataSignatureSize, signContext, 
							  iCmsHashContext, SIGNATURE_CMS );
	if( iCmsHashContext != iHashContext )
		krnlSendNotifier( iCmsHashContext, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signerInfo record */
	sMemOpen( &stream, signature, 
			  ( signature == NULL ) ? 0 : STREAMSIZE_UNKNOWN );
	status = writeSignerInfo( &stream, iSigningCert, hashAlgo, 
							  encodedAttributes, encodedAttributeSize,
							  dataSignature, dataSignatureSize );
	length = stell( &stream );
	sMemDisconnect( &stream );
	if( !cryptStatusError( status ) )
		*signatureLength = length;

	return( status );
	}

/* Check a CMS signature */

static int checkSignatureCMS( const void *signature, 
							  const CRYPT_CONTEXT sigCheckContext,
							  const CRYPT_CONTEXT iHashContext, 
							  CRYPT_CERTIFICATE *iExtraData,
							  const CRYPT_HANDLE iSigCheckKey )
	{
	CRYPT_CONTEXT iCmsHashContext = iHashContext;
	CRYPT_ALGO hashAlgo, signatureHashAlgo;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE hashValue[ CRYPT_MAX_HASHSIZE ];
	void *iAndSStart, *encodedAttributes, *dataSignature;
	int encodedAttributeSize, status;

	if( iExtraData != NULL )
		*iExtraData = CRYPT_ERROR;

	/* Get the message hash algo */
	status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_GETATTRIBUTE,
							  &hashAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		/* Remap the error code to refer to the correct parameter if 
		   necessary */
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ARGERROR_NUM1 : status );

	/* Unpack the SignerInfo record and make sure that the supplied key is
	   the correct one for the sig check and the supplied hash context 
	   matches the algorithm used in the signature */
	sMemConnect( &stream, signature, STREAMSIZE_UNKNOWN );
	status = readSignerInfo( &stream, &signatureHashAlgo, &iAndSStart, 
							 &encodedAttributes, &encodedAttributeSize, 
							 &dataSignature );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( krnlSendMessage( iSigCheckKey, RESOURCE_IMESSAGE_COMPARE,
			iAndSStart, RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER ) != CRYPT_OK )
		return( CRYPT_ERROR_WRONGKEY );
	if( signatureHashAlgo != hashAlgo )
		return( CRYPT_ARGERROR_NUM1 );

	/* If there are signedAttributes present, hash the data, substituting a 
	   SET OF tag for the IMPLICIT [ 0 ] tag at the start */
	if( encodedAttributes != NULL )
		{
		static const BYTE setTag[] = { BER_SET };
		CREATEOBJECT_INFO createInfo;

		setMessageCreateObjectInfo( &createInfo, signatureHashAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
						 ( BYTE * ) setTag, sizeof( BYTE ) );
		krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
						 ( ( BYTE * ) encodedAttributes ) + 1, 
						 encodedAttributeSize - 1 );
		krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_CTX_HASH, 
						 "", 0 );
		iCmsHashContext = createInfo.cryptHandle;
		}

	/* Check the signature */
	status = checkSignature( dataSignature, sigCheckContext, iCmsHashContext,
							 SIGNATURE_CMS );
	if( encodedAttributes == NULL )
		/* No signed attributes, we're done */
		return( status );
	krnlSendNotifier( iCmsHashContext, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Import the attributes and make sure the data hash value given in the
	   signed attributes matches the user-supplied hash */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = encodedAttributes;
	createInfo.strArgLen1 = encodedAttributeSize;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );
	setResourceData( &msgData, hashValue, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_CERTINFO_CMS_MESSAGEDIGEST );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( iHashContext, RESOURCE_IMESSAGE_COMPARE,
								  &msgData, RESOURCE_MESSAGE_COMPARE_HASH );
		if( cryptStatusError( status ) )
			status = CRYPT_ERROR_SIGNATURE;
		}
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}

	/* If the user wants to look at the attributes, make them externally
	   visible, otherwise delete them */
	if( iExtraData != NULL )
		*iExtraData = createInfo.cryptHandle;
	else
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );

	return( status );
	}

/* Create/check an extended signature type, either a cryptlib signature or a
   CMS-style signature */

C_RET cryptCreateSignatureEx( C_OUT void C_PTR signature, 
							  C_OUT int C_PTR signatureLength,
							  C_IN CRYPT_FORMAT_TYPE formatType,
							  C_IN CRYPT_CONTEXT signContext,
							  C_IN CRYPT_CONTEXT hashContext,
							  C_IN CRYPT_HANDLE extraData )
	{
	int status;

	/* Perform basic error checking */
	if( signature != NULL )
		{
		if( checkBadPtrWrite( signature, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( signature, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( signatureLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*signatureLength = 0;
	if( formatType <= CRYPT_FORMAT_NONE || formatType >= CRYPT_FORMAT_LAST )
		return( CRYPT_ERROR_PARAM3 );
	if( formatType == CRYPT_FORMAT_PGP )
		return( CRYPT_ERROR_NOTAVAIL );	/* Not supported yet */
	status = krnlSendMessage( signContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_SIGN );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM4 : status );
	if( formatType == CRYPT_FORMAT_CMS || \
		formatType == CRYPT_FORMAT_SMIME )
		{
		int certType;

		/* Make sure the signing context has a cert attached to it */
		status = krnlSendMessage( signContext, RESOURCE_MESSAGE_GETATTRIBUTE,
								  &certType, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			return( CRYPT_ERROR_PARAM4 );

		/* Make sure the extra data object is in order */
		if( extraData != CRYPT_USE_DEFAULT )
			{
			status = krnlSendMessage( extraData, RESOURCE_MESSAGE_GETATTRIBUTE,
									  &certType, CRYPT_CERTINFO_CERTTYPE );
			if( cryptStatusError( status ) || \
				certType != CRYPT_CERTTYPE_CMS_ATTRIBUTES )
				return( CRYPT_ERROR_PARAM6 );
			}
		}
	status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_HASH );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM5 : status );
	if( formatType == CRYPT_FORMAT_CRYPTLIB && extraData != CRYPT_USE_DEFAULT )
		return( CRYPT_ERROR_PARAM6 );

	/* Call the low-level signature create function to create the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		return( createSignature( signature, signatureLength, signContext,
								 hashContext, SIGNATURE_CRYPTLIB ) );
	status = createSignatureCMS( signature, signatureLength,
								 signContext, hashContext, extraData );
	return( ( status == CRYPT_ARGERROR_OBJECT ) ? CRYPT_ERROR_PARAM4 : \
			( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ERROR_PARAM5 : status );
	}

static CRYPT_FORMAT_TYPE getFormatType( const void *data )
	{
	CRYPT_FORMAT_TYPE formatType = CRYPT_FORMAT_NONE;
	STREAM stream;
	int status;

	/* Figure out what we've got.  A cryptlib signature begins:
		cryptlibSignature ::= SEQUENCE {
			version		INTEGER (3),
			keyID [ 0 ]	OCTET STRING
	   while a CMS signature begins:
		cmsSignature ::= SEQUENCE {
			version		INTEGER (1),
			digestAlgo	SET OF {
	   which allows us to determine which type of object we have */
	sMemConnect( &stream, data, 50 );
	status = readSequence( &stream, NULL );
	if( !cryptStatusError( status ) )
		{
		long version;

		if( !cryptStatusError( readShortInteger( &stream, &version ) ) )
			formatType = ( version == 1 ) ? CRYPT_FORMAT_CMS : \
						 ( version == 3 ) ? CRYPT_FORMAT_CRYPTLIB : \
						 CRYPT_FORMAT_NONE;
		}
	sMemDisconnect( &stream );

	return( formatType  );
	}

C_RET cryptCheckSignatureEx( C_IN void C_PTR signature,
							 C_IN CRYPT_HANDLE sigCheckKey,
							 C_IN CRYPT_CONTEXT hashContext,
							 C_OUT CRYPT_HANDLE C_PTR extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT sigCheckContext;
	int status;

	/* Perform basic error checking */
	if( signature != NULL && checkBadPtrRead( signature, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_ERROR_PARAM1 );
	if( ( formatType = getFormatType( signature ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );
	status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sigCheckContext, RESOURCE_MESSAGE_CHECK, 
								  NULL, RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK );
	if( cryptStatusOK( status ) )
		{
		status = krnlSendMessage( hashContext, RESOURCE_MESSAGE_CHECK, NULL,
								  RESOURCE_MESSAGE_CHECK_HASH );
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM3;
		}
	else
		if( status == CRYPT_ARGERROR_OBJECT )
			status = CRYPT_ERROR_PARAM2;
	if( cryptStatusError( status ) )
		return( status );
	if( formatType == CRYPT_FORMAT_CMS )
		{
		int certType;

		/* Make sure the sig check key includes a cert */
		status = krnlSendMessage( sigCheckKey, RESOURCE_MESSAGE_GETATTRIBUTE,
								  &certType, CRYPT_CERTINFO_CERTTYPE );
		if( cryptStatusError( status ) ||
			( certType != CRYPT_CERTTYPE_CERTIFICATE && \
			  certType != CRYPT_CERTTYPE_CERTCHAIN ) )
			return( CRYPT_ERROR_PARAM2 );
		}

	/* Call the low-level signature check function to check the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		{
		if( extraData != NULL )
			return( CRYPT_ERROR_PARAM4 );
		return( checkSignature( signature, sigCheckContext, hashContext,
								SIGNATURE_CRYPTLIB ) );
		}
	if( extraData != NULL )
		{
		if( checkBadPtrWrite( extraData, sizeof( int ) ) )
			return( CRYPT_ERROR_PARAM5 );
		*extraData = CRYPT_ERROR;
		}
	status = checkSignatureCMS( signature, sigCheckContext, hashContext,
								extraData, sigCheckKey );
	if( cryptStatusOK( status ) && extraData != NULL )
		/* Make the recovered signing attributes externally visible */
		krnlSendMessage( *extraData, RESOURCE_IMESSAGE_SETATTRIBUTE,
						 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );

	return( ( status == CRYPT_ARGERROR_OBJECT ) ? CRYPT_ERROR_PARAM2 : \
			( status == CRYPT_ARGERROR_NUM1 ) ? CRYPT_ERROR_PARAM3 : status );
	}

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions which have already checked the parameters for validity.  In
   addition the iExtraData value can take two out-of-band values,
   CRYPT_USE_DEFAULT (generate the default signing attributes for the caller)
   or CRYPT_UNUSED (don't use any signing attributes, valid only when signing
   raw data) */

int iCryptCreateSignatureEx( void *signature, int *signatureLength,
							 const CRYPT_FORMAT_TYPE formatType,
							 const CRYPT_CONTEXT iSignContext,
							 const CRYPT_CONTEXT iHashContext,
							 const CRYPT_HANDLE iExtraData,
							 const char *tsaInfo )
	{
	/* Clear return value */
	*signatureLength = 0;

	/* Call the low-level signature create function to create the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		return( createSignature( signature, signatureLength, iSignContext,
								 iHashContext, SIGNATURE_CRYPTLIB ) );
	return( createSignatureCMS( signature, signatureLength,
								iSignContext, iHashContext, iExtraData ) );
	}

int iCryptCheckSignatureEx( const void *signature,
							const CRYPT_HANDLE iSigCheckKey,
							const CRYPT_CONTEXT iHashContext,
							CRYPT_HANDLE *extraData )
	{
	CRYPT_FORMAT_TYPE formatType;
	CRYPT_CONTEXT sigCheckContext;
	int status;

	/* Perform basic error checking */
	if( ( formatType = getFormatType( signature ) ) == CRYPT_FORMAT_NONE )
		return( CRYPT_ERROR_BADDATA );
	status = krnlSendMessage( iSigCheckKey, RESOURCE_IMESSAGE_GETDEPENDENT,
							  &sigCheckContext, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );

	/* Call the low-level signature check function to check the signature */
	if( formatType == CRYPT_FORMAT_CRYPTLIB )
		return( checkSignature( signature, sigCheckContext, iHashContext,
								SIGNATURE_CRYPTLIB ) );
	if( extraData != NULL )
		*extraData = CRYPT_ERROR;
	return( checkSignatureCMS( signature, sigCheckContext, iHashContext,
							   extraData, iSigCheckKey ) );
	}
