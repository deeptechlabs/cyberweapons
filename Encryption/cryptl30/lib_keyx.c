/****************************************************************************
*																			*
*						  cryptlib Key Exchange Routines					*
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

/****************************************************************************
*																			*
*							Low-level Key Export Functions					*
*																			*
****************************************************************************/

/* Export a conventionally encrypted session key */

static int exportConventionalKey( void *encryptedKey, int *encryptedKeyLength,
								  const CRYPT_CONTEXT iSessionKeyContext,
								  const CRYPT_CONTEXT iExportContext )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE buffer[ CRYPT_MAX_KEYSIZE + 16 ];
	int keySize, ivSize, status;

	krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &keySize, CRYPT_CTXINFO_KEYSIZE );
	krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &ivSize, CRYPT_CTXINFO_IVSIZE );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];
		int dummyDataSize;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0,
							  NULL, 0, iSessionKeyContext, iExportContext,
							  CRYPT_UNUSED );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo, 
								  MECHANISM_CMS );
		dummyDataSize = mechanismInfo.wrappedDataLength;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Generate an IV to allow the KEK write to succeed - see the comment
		   below about this */
		if( ivSize )
			krnlSendNotifier( iExportContext, RESOURCE_IMESSAGE_CTX_GENIV );

		/* Write the data to a null stream to determine its size*/
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKEKInfo( &nullStream, iExportContext, dummyBuffer,
							   dummyDataSize );
		*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Load an IV into the exporting context.  This is somewhat nasty in that
	   a side-effect of exporting a key is to load an IV into the exporting
	   context which isn't really part of the functions job description.  The
	   alternative is to require the user to explicitly load an IV before
	   exporting the key, which is equally nasty (they'll never remember).  
	   The lesser of the two evils is to load the IV here and assume that 
	   anyone loading the IV themselves will read the docs which warn about 
	   the side-effects of exporting a key.

	   Note that we always load a new IV when we export a key because the
	   caller may be using the context to exchange multiple keys.  Since each
	   exported key requires its own IV, we perform an unconditional reload.
	   In addition because we don't want another thread coming along and
	   changing the IV while we're in the process of encrypting with it, we
	   lock the exporting key object until the encryption has completed and 
	   the IV is written to the output */
	krnlSendNotifier( iExportContext, RESOURCE_IMESSAGE_LOCK );
	if( ivSize )
		krnlSendNotifier( iExportContext, RESOURCE_IMESSAGE_CTX_GENIV );

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_KEYSIZE + 16,
						  NULL, 0, iSessionKeyContext, iExportContext,
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo, 
							  MECHANISM_CMS );
	if( !cryptStatusError( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKEKInfo( &stream, iExportContext, 
							   mechanismInfo.wrappedData, 
							   mechanismInfo.wrappedDataLength );
		*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	clearMechanismInfo( &mechanismInfo );
	zeroise( buffer, CRYPT_MAX_KEYSIZE + 16 );
	krnlSendNotifier( iExportContext, RESOURCE_IMESSAGE_UNLOCK );

	return( status );
	}

/* Export a public-key encrypted session key */

static int exportPublicKey( void *encryptedKey, int *encryptedKeyLength,
							const CRYPT_CONTEXT iSessionKeyContext,
							const CRYPT_CONTEXT iExportContext,
							const void *auxInfo, const int auxInfoLength,
							const RECIPIENT_TYPE recipientType )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int keySize, status;

	krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &keySize, CRYPT_CTXINFO_KEYSIZE );

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;
		BYTE dummyBuffer[ CRYPT_MAX_PKCSIZE ];
		int dummyDataSize;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0,
							  NULL, 0, iSessionKeyContext, iExportContext,
							  CRYPT_UNUSED );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo, 
								  MECHANISM_PKCS1 );
		dummyDataSize = mechanismInfo.wrappedDataLength;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		/* Write the data to a null stream to determine its size */
		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyTransInfo( &nullStream, iExportContext, dummyBuffer,
						dummyDataSize, auxInfo, auxInfoLength, recipientType );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Encrypt the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_PKCSIZE, NULL, 0, 
						  iSessionKeyContext, iExportContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo, 
							  MECHANISM_PKCS1 );
	if( cryptStatusOK( status ) )
		{
		STREAM stream;

		sMemOpen( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKeyTransInfo( &stream, iExportContext, 
									mechanismInfo.wrappedData, 
									mechanismInfo.wrappedDataLength, 
									auxInfo, auxInfoLength, recipientType );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	clearMechanismInfo( &mechanismInfo );

	/* Clean up */
	return( status );
	}

/* Export a key agreement key */

static int exportKeyAgreeKey( void *encryptedKey, int *encryptedKeyLength,
							  const CRYPT_CONTEXT iSessionKeyContext,
							  const CRYPT_CONTEXT iExportContext,
							  const CRYPT_CONTEXT iAuxContext,
							  const void *auxInfo, const int auxInfoLength )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int wrappedKeyLen, ukmLen, status;

	/* If we're just doing a length check, write the data to a null stream
	   and return its length */
	if( encryptedKey == NULL )
		{
		STREAM nullStream;

		/* Calculate the eventual encrypted key size */
		setMechanismWrapInfo( &mechanismInfo, NULL, 0,
							  NULL, 0, iSessionKeyContext, iExportContext,
							  iAuxContext );
		status = krnlSendMessage( iExportContext, 
								  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo, 
								  MECHANISM_KEA );
		wrappedKeyLen = mechanismInfo.wrappedDataLength >> 8;
		ukmLen = mechanismInfo.wrappedDataLength & 0xFF;
		clearMechanismInfo( &mechanismInfo );
		if( cryptStatusError( status ) )
			return( status );

		sMemOpen( &nullStream, NULL, 0 );
		status = writeKeyAgreeInfo( &nullStream, iExportContext, 
									buffer, wrappedKeyLen, buffer, 
									ukmLen, auxInfo, auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &nullStream );
		sMemClose( &nullStream );

		return( status );
		}

	/* Export the session key and write the result to the output stream */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_PKCSIZE,
						  NULL, 0, iSessionKeyContext, iExportContext,
						  iAuxContext );
	status = krnlSendMessage( iExportContext, RESOURCE_IMESSAGE_DEV_EXPORT, 
							  &mechanismInfo, MECHANISM_KEA );
	if( !cryptStatusError( status ) )
		{
		STREAM stream;

		/* Extract the length information */
		wrappedKeyLen = mechanismInfo.wrappedDataLength >> 8;
		ukmLen = mechanismInfo.wrappedDataLength & 0xFF;

		sMemOpen( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
		status = writeKeyAgreeInfo( &stream, iExportContext, buffer, 
									wrappedKeyLen, buffer, ukmLen, auxInfo, 
									auxInfoLength );
		if( cryptStatusOK( status ) )
			*encryptedKeyLength = stell( &stream );
		sMemDisconnect( &stream );
		}
	clearMechanismInfo( &mechanismInfo );

	/* Clean up */
	zeroise( buffer, CRYPT_MAX_PKCSIZE );
	return( status );
	}

/****************************************************************************
*																			*
*							Low-level Key Import Functions					*
*																			*
****************************************************************************/

/* Import a conventionally encrypted session key */

static int importConventionalKey( const void *encryptedKey,
								  const CRYPT_CONTEXT iSessionKeyContext,
								  const CRYPT_CONTEXT iImportContext )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode;
	MECHANISM_WRAP_INFO mechanismInfo;
	QUERY_INFO queryInfo;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE keyBuffer[ CRYPT_MAX_KEYSIZE ], iv[ CRYPT_MAX_IVSIZE ];
	int ivSize, status;

	/* Get information on the importing key */
	status = krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we'll be using the correct type of encryption context to
	   decrypt it */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKEKInfo( &stream, &queryInfo, iv, &ivSize );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo != queryInfo.cryptAlgo || cryptMode != queryInfo.cryptMode )
		return( CRYPT_ARGERROR_NUM1 );

	/* Extract the encrypted key from the buffer and decrypt it.  Since we 
	   don't want another thread changing the IV while we're using the import
	   context, we lock it for the duration */
	krnlSendNotifier( iImportContext, RESOURCE_IMESSAGE_LOCK );
	if( needsIV( cryptMode ) && cryptAlgo != CRYPT_ALGO_RC4 )
		{
		setResourceData( &msgData, iv, ivSize );
		krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_IV );
		}
	setMechanismWrapInfo( &mechanismInfo, 
						  queryInfo.dataStart, queryInfo.dataLength, 
						  keyBuffer, CRYPT_MAX_KEYSIZE, 
						  CRYPT_UNUSED, iImportContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_IMPORT, &mechanismInfo, 
							  MECHANISM_CMS );
	krnlSendNotifier( iImportContext, RESOURCE_IMESSAGE_UNLOCK );

	/* Load the decrypted keying information into a context */
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, mechanismInfo.keyData, 
						 mechanismInfo.keyDataLength );
		status = krnlSendMessage( iSessionKeyContext, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEY );
		if( status == CRYPT_ARGERROR_STR1 || \
			status == CRYPT_ARGERROR_NUM1 )
			/* If there was an error with the key value or size, convert the
			   return value into something more appropriate */
			status = CRYPT_ERROR_BADDATA;
		}
	clearMechanismInfo( &mechanismInfo );
	zeroise( keyBuffer, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/* Import a public-key encrypted session key */

static int importPublicKey( const void *encryptedKey, 
							const CRYPT_CONTEXT iSessionKeyContext,
							const CRYPT_CONTEXT iImportContext )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	QUERY_INFO queryInfo;
	STREAM stream;
	BYTE keyBuffer[ CRYPT_MAX_KEYSIZE ];
	int status;

	/* Read the encrypted key record up to the start of the encrypted key and
	   make sure we've been given the correct key */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKeyTransInfo( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
	if( queryInfo.formatType == CRYPT_FORMAT_CMS )
		{
		if( krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_COMPARE,
				queryInfo.iAndSStart,
				RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER ) != CRYPT_OK )
			status = CRYPT_ERROR_WRONGKEY;
		}
	else
		if( krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_COMPARE,
				queryInfo.keyID,
				RESOURCE_MESSAGE_COMPARE_KEYID ) != CRYPT_OK )
			status = CRYPT_ERROR_WRONGKEY;
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the encrypted key to the buffer and decrypt it */
	setMechanismWrapInfo( &mechanismInfo, 
						  queryInfo.dataStart, queryInfo.dataLength, 
						  keyBuffer, CRYPT_MAX_KEYSIZE, 
						  CRYPT_UNUSED, iImportContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_IMPORT, &mechanismInfo, 
							  MECHANISM_PKCS1 );
	if( !cryptStatusError( status ) )
		{
		RESOURCE_DATA msgData;
		int keySize;

		status = krnlSendMessage( iSessionKeyContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &keySize, CRYPT_CTXINFO_KEYSIZE );
		if( keySize > mechanismInfo.keyDataLength )
			/* This should never happen, if it does we should at least 
			   try it with the shorter key size rather than giving up */
			keySize = mechanismInfo.keyDataLength;
		if( cryptStatusOK( status ) )
			{
			setResourceData( &msgData, mechanismInfo.keyData, keySize );
			status = krnlSendMessage( iSessionKeyContext, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
									  &msgData, CRYPT_CTXINFO_KEY );
			}
		}
	clearMechanismInfo( &mechanismInfo );
	zeroise( keyBuffer, CRYPT_MAX_KEYSIZE );

	return( status );
	}

/* Import a key agreement session key */

static int importKeyAgreeKey( const void *encryptedKey, 
							  const CRYPT_CONTEXT iSessionKeyContext,
							  const CRYPT_CONTEXT iImportContext )
	{
	CRYPT_CONTEXT iLocalContext;
	QUERY_INFO queryInfo;
	STREAM stream;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	int status;

	/* Read the key agreement record.  Due to the somewhat peculiar concept
	   of what constitutes a public key for DH, this doesn't really work as
	   well as the standard key wrap algorithms since what we're reading are
	   the components of a complete context.  As a result the initiator and
	   responder for the DH exchange end up with the following:

							Initiator				Responder

	   cryptInfoPtr			p, g, x(I), y(I)		-

	   iLocalContext		p, g, y(R)				p, g, y(I)

	   If we're doing the import for the responder, we copy the values from
	   the import context into the responder context and perform a key load,
	   which generates the responders x value and key ID.  This is a horrible
	   kludge, what we should be doing is passing the import context back to
	   the user but this isn't possible because cryptImportKey() passes the
	   import context by value.

	   If we're doing the import for the initiator, we just check that the
	   key used by the responder was the same as the one used by the
	   initiator */
	sMemConnect( &stream, encryptedKey, STREAMSIZE_UNKNOWN );
	status = readKeyAgreeInfo( &stream, &queryInfo, &iLocalContext );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );
#if 0
	getCheckInternalResource( iImportContext, cryptInfoPtr, 
							  RESOURCE_TYPE_CONTEXT );
	getCheckInternalResource2( iLocalContext, localContextInfoPtr, 
							   RESOURCE_TYPE_CONTEXT, cryptInfoPtr );
	if( !cryptInfoPtr->ctxPKC.keySet )
		{
		BIGNUM *tmp;

		/* Swap the newly-read parameters in the import context with the
		   uninitialised values in the import context */
		tmp = cryptInfoPtr->ctxPKC.dhParam_p;
		cryptInfoPtr->ctxPKC.dhParam_p = localContextInfoPtr->ctxPKC.dhParam_p;
		localContextInfoPtr->ctxPKC.dhParam_p = tmp;
		tmp = cryptInfoPtr->ctxPKC.dhParam_g;
		cryptInfoPtr->ctxPKC.dhParam_g = localContextInfoPtr->ctxPKC.dhParam_g;
		localContextInfoPtr->ctxPKC.dhParam_g = tmp;
		tmp = cryptInfoPtr->ctxPKC.dhParam_yPrime;
		cryptInfoPtr->ctxPKC.dhParam_yPrime = localContextInfoPtr->ctxPKC.dhParam_yPrime;
		localContextInfoPtr->ctxPKC.dhParam_yPrime = tmp;

		/* Perform an internal load */
		status = cryptInfoPtr->capabilityInfo->initKeyFunction( \
								cryptInfoPtr, NULL, LOAD_INTERNAL_PUBLIC );
		if( cryptStatusOK( status ) )
			cryptInfoPtr->ctxPKC.keySet = TRUE;
		}
	else
		/* Make sure the responders key was the same as the intiators key */
		if( memcmp( cryptInfoPtr->ctxPKC.keyID, localContextInfoPtr->ctxPKC.keyID,
					KEYID_SIZE ) )
			status = CRYPT_ERROR_WRONGKEY;
		else
			{
			BIGNUM *tmp;

			tmp = cryptInfoPtr->ctxPKC.dhParam_yPrime;
			cryptInfoPtr->ctxPKC.dhParam_yPrime = localContextInfoPtr->ctxPKC.dhParam_yPrime;
			localContextInfoPtr->ctxPKC.dhParam_yPrime = tmp;
			}
	unlockResource( localContextInfoPtr );
	unlockResource( cryptInfoPtr );
#endif /* 0 */
	krnlSendNotifier( iLocalContext, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate the shared secret value and load it into the session key
	   context.  We use a fixed 64-bit salt and explicitly set the iteration 
	   count to make sure it isn't upset if the user changes config options */
	status = krnlSendMessage( iImportContext, RESOURCE_IMESSAGE_CTX_DECRYPT, 
							  buffer, CRYPT_UNUSED );
	if( !cryptStatusError( status ) )
		{
		static const BYTE *salt = "\x00\x00\x00\x00\x00\x00\x00\x00";
		static const int iterations = 100;
		RESOURCE_DATA msgData;

		krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_SETATTRIBUTE, 
						 ( int * ) &iterations, CRYPT_CTXINFO_KEYING_ITERATIONS );
		setResourceData( &msgData, ( void * ) salt, 8 );
		krnlSendMessage( iSessionKeyContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_KEYING_SALT );
		setResourceData( &msgData, buffer, status );
		status = krnlSendMessage( iSessionKeyContext, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_CTXINFO_KEYING_VALUE );
		}

	return( status );
	}

/****************************************************************************
*																			*
*							Import/Export a Session Key						*
*																			*
****************************************************************************/

/* Get the issuerAndSerialNumber for a certificate */

static int getIssuerAndSerialNumber( CRYPT_HANDLE iCryptHandle,
									 BYTE **bufferPtr, int *lengthPtr )
	{
	RESOURCE_DATA msgData;
	BYTE *buffer = *bufferPtr;
	int status;

	/* Find out how large the data will be and allocate a buffer for it if
	   necessary */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) && msgData.length > 1024 && \
		( buffer = malloc( msgData.length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusError( status ) )
		return( status );

	/* Copy the data into the buffer */
	msgData.data = buffer;
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusError( status ) )
		{
		if( buffer != *bufferPtr )
			free( buffer );
		return( status );
		}
	*bufferPtr = msgData.data;
	*lengthPtr = msgData.length;

	return( CRYPT_OK );
	}

/* Import an extended encrypted key, either a cryptlib key or a CMS key */

C_RET cryptImportKeyEx( C_IN void C_PTR encryptedKey,
						C_IN CRYPT_CONTEXT importKey,
						C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode = CRYPT_MODE_NONE;
	QUERY_INFO queryInfo;
	STREAM stream;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	int owner, originalOwner = CRYPT_UNUSED, status;

	/* Perform basic error checking */
	if( checkBadPtrRead( encryptedKey, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_ERROR_PARAM1 );
	sMemConnect( &stream, ( void * ) encryptedKey, STREAMSIZE_UNKNOWN );
	status = queryObject( &stream, &queryInfo );
	sMemDisconnect( &stream );
	if( cryptStatusError( status ) )
		return( status );

	/* Check the importing key */
	status = krnlSendMessage( importKey, RESOURCE_MESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && \
		( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) )
		status = krnlSendMessage( importKey, RESOURCE_MESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM2 : status );
	if( cryptMode == CRYPT_MODE_NONE )
		checkType = ( cryptAlgo == CRYPT_ALGO_DH ) ? \
					RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT : \
					RESOURCE_MESSAGE_CHECK_PKC_DECRYPT;
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	status = krnlSendMessage( importKey, RESOURCE_MESSAGE_CHECK, NULL,
							  checkType );
	if( cryptAlgo == CRYPT_ALGO_DH && status == CRYPT_ERROR_NOTINITED )
		/* For key agreement keys the fact that there's no key attribute set
		   is OK since the key parameters are read from the exchanged object */
		status = CRYPT_OK;
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM2 : status );

	/* Check the session key */
	status = krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_CHECK, 
							  NULL, RESOURCE_MESSAGE_CHECK_CRYPT );
	if( status == CRYPT_OK )
		return( CRYPT_ERROR_INITED );	/* Shouldn't have key attr.present */
	if( cryptStatusError( status ) && status != CRYPT_ERROR_NOTINITED )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );

	/* If the importing key is owned, bind the session key context to the same 
	   owner before we load a key into it.  We also need to save the original 
	   owner so we can undo the binding later if things fail */
	krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_GETATTRIBUTE,
					 &originalOwner, CRYPT_PROPERTY_OWNER );
	status = krnlSendMessage( importKey, RESOURCE_MESSAGE_GETATTRIBUTE,
							  &owner, CRYPT_PROPERTY_OWNER );
	if( cryptStatusOK( status ) && owner != CRYPT_UNUSED )
		krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_SETATTRIBUTE,
						 &owner, CRYPT_PROPERTY_OWNER );

	/* Import it as appropriate */
	if( cryptMode == CRYPT_MODE_NONE )	/* It's a PKC */
		{
		if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
			status = importKeyAgreeKey( encryptedKey, sessionKeyContext, 
										importKey );
		else
			status = importPublicKey( encryptedKey, sessionKeyContext, 
									  importKey );
		}
	else
		status = importConventionalKey( encryptedKey, sessionKeyContext, 
										importKey );

	/* If the import failed, return the session key context to its
	   original owner */
	if( cryptStatusError( status ) )
		krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_SETATTRIBUTE,
						 &originalOwner, CRYPT_PROPERTY_OWNER );

	return( status );
	}

C_RET cryptImportKey( C_IN void C_PTR encryptedKey,
					  C_IN CRYPT_CONTEXT importKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	/* Currently cryptImportKey() and cryptImportKeyEx() do the same thing */
	return( cryptImportKeyEx( encryptedKey, importKey, sessionKeyContext ) );
	}

/* Export an extended encrypted key, either a cryptlib key or a CMS key */

C_RET cryptExportKeyEx( C_OUT void C_PTR encryptedKey, 
						C_OUT int C_PTR encryptedKeyLength,
						C_IN CRYPT_FORMAT_TYPE formatType,
						C_IN CRYPT_HANDLE exportKey,
						C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode = CRYPT_MODE_NONE, sessionKeyMode;
	const RECIPIENT_TYPE recipientType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? RECIPIENT_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_CMS || \
			  formatType == CRYPT_FORMAT_SMIME ) ? RECIPIENT_CMS : RECIPIENT_NONE;
	BYTE auxDataBuffer[ 1024 ], *auxData = auxDataBuffer;
	RESOURCE_MESSAGE_CHECK_TYPE checkType;
	int auxDataLength = 1024, status;

	/* Perform basic error checking */
	if( encryptedKey != NULL )
		{
		if( checkBadPtrWrite( encryptedKey, MIN_CRYPT_OBJECTSIZE ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( encryptedKey, 0, MIN_CRYPT_OBJECTSIZE );
		}
	if( checkBadPtrWrite( encryptedKeyLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*encryptedKeyLength = 0;
	if( formatType != CRYPT_FORMAT_CRYPTLIB && \
		formatType != CRYPT_FORMAT_CMS && formatType != CRYPT_FORMAT_SMIME )
		return( CRYPT_ERROR_PARAM3 );

	/* Check the exporting key */
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && \
		( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) )
		status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );
	if( cryptMode == CRYPT_MODE_NONE )
		checkType = ( cryptAlgo == CRYPT_ALGO_DH ) ? \
					RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT : \
					RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT;
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	status = krnlSendMessage( exportKey, RESOURCE_MESSAGE_CHECK, NULL,
							  checkType );
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM3 : status );

	/* Check the exported key */
	status = krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_GETATTRIBUTE,
							  &sessionKeyMode, CRYPT_CTXINFO_MODE );
	if( status == CRYPT_ARGERROR_VALUE )
		{
		/* No encryption mode attribute present, it has to be a MAC 
		   context */
		checkType = RESOURCE_MESSAGE_CHECK_MAC;
		status = CRYPT_OK;
		}
	else
		checkType = RESOURCE_MESSAGE_CHECK_CRYPT;
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( sessionKeyContext, RESOURCE_MESSAGE_CHECK, 
								  NULL, checkType );
	if( cryptAlgo == CRYPT_ALGO_DH )
		{
		/* If we're using a key agreement algorithm it doesn't matter if the
		   session key context has a key attribute present or not, but the 
		   format has to be cryptlib */
		if( status == CRYPT_ERROR_NOTINITED )
			status = CRYPT_OK;
		if( formatType == CRYPT_FORMAT_CMS || \
			formatType == CRYPT_FORMAT_SMIME )
			status = CRYPT_ERROR_PARAM3;
		}
	if( cryptStatusError( status ) )
		return( ( status == CRYPT_ARGERROR_OBJECT ) ? \
				CRYPT_ERROR_PARAM4 : status );

	/* If we're exporting a key in CMS format using a public key we need to
	   obtain recipient information */
	if( ( formatType == CRYPT_FORMAT_CMS || \
		  formatType == CRYPT_FORMAT_SMIME ) && cryptMode == CRYPT_MODE_NONE )
		{
		if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
			{
			RESOURCE_DATA msgData;

			setResourceData( &msgData, auxDataBuffer, 1024 );
			status = krnlSendMessage( exportKey, 
								RESOURCE_MESSAGE_GETATTRIBUTE_S, &msgData, 
								CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
			if( cryptStatusError( status ) )
				status = CRYPT_ERROR_PARAM4;
			auxDataLength = msgData.length;
			}
		else
			status = getIssuerAndSerialNumber( exportKey, &auxData,
											   &auxDataLength );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export it as appropriate */
	if( cryptMode == CRYPT_MODE_NONE )
		{
		if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
			status = exportKeyAgreeKey( encryptedKey, encryptedKeyLength,
										sessionKeyContext, exportKey, 
										CRYPT_UNUSED, auxData, auxDataLength );
		else
			status = exportPublicKey( encryptedKey, encryptedKeyLength,
									  sessionKeyContext, exportKey, auxData, 
									  auxDataLength, recipientType );
		}
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										sessionKeyContext, exportKey );

	/* Clean up */
	if( auxData != auxDataBuffer )
		free( auxData );
	return( status );
	}

C_RET cryptExportKey( C_OUT void C_PTR encryptedKey, 
					  C_OUT int C_PTR encryptedKeyLength,
					  C_IN CRYPT_HANDLE exportKey,
					  C_IN CRYPT_CONTEXT sessionKeyContext )
	{
	int status;

	status = cryptExportKeyEx( encryptedKey, encryptedKeyLength, 
							   CRYPT_FORMAT_CRYPTLIB, exportKey, 
							   sessionKeyContext );
	return( ( status == CRYPT_ERROR_PARAM4 ) ? CRYPT_ERROR_PARAM3 : \
			( status == CRYPT_ERROR_PARAM5 ) ? CRYPT_ERROR_PARAM4 : status );
	}

/****************************************************************************
*																			*
*						Internal Import/Export Functions					*
*																			*
****************************************************************************/

/* Internal versions of the above.  These skip a lot of the checking done by
   the external versions since they're only called by cryptlib internal
   functions which have already checked the parameters for validity */

int iCryptImportKeyEx( const void *encryptedKey, 
					   const CRYPT_CONTEXT iImportKey,
					   const CRYPT_CONTEXT iSessionKeyContext )
	{
	CRYPT_ALGO cryptAlgo;
	int status;

	/* Import it as appropriate.  We don't handle key agreement at this
	   level */
	status = krnlSendMessage( iImportKey, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		return( importConventionalKey( encryptedKey, iSessionKeyContext, 
									   iImportKey ) );
	return( importPublicKey( encryptedKey, iSessionKeyContext, 
							 iImportKey ) );
	}

int iCryptExportKeyEx( void *encryptedKey, int *encryptedKeyLength,
					   const CRYPT_FORMAT_TYPE formatType,
					   const CRYPT_CONTEXT iSessionKeyContext,
					   const CRYPT_CONTEXT iExportKey,
					   const CRYPT_CONTEXT iAuxContext )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode = CRYPT_MODE_NONE;
	const RECIPIENT_TYPE recipientType = \
			( formatType == CRYPT_FORMAT_CRYPTLIB ) ? RECIPIENT_CRYPTLIB : \
			( formatType == CRYPT_FORMAT_CMS || \
			  formatType == CRYPT_FORMAT_SMIME ) ? RECIPIENT_CMS : RECIPIENT_NONE;
	BYTE auxDataBuffer[ 1024 ], *auxData = auxDataBuffer;
	int auxDataLength = 1024, status;

	*encryptedKeyLength = 0;

	/* Perform simplified error checking */
	status = krnlSendMessage( iExportKey, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusOK( status ) && \
		( cryptAlgo >= CRYPT_ALGO_FIRST_CONVENTIONAL && \
		  cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL ) )
		status = krnlSendMessage( iExportKey, RESOURCE_IMESSAGE_GETATTRIBUTE, 
								  &cryptMode, CRYPT_CTXINFO_MODE );
	if( cryptStatusError( status ) )
		return( status );

	/* If we're exporting a key in CMS format using a public key we need to
	   obtain recipient information */
	if( ( formatType == CRYPT_FORMAT_CMS || \
		  formatType == CRYPT_FORMAT_SMIME ) && cryptMode == CRYPT_MODE_NONE )
		{
		if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
			{
			RESOURCE_DATA msgData;

			setResourceData( &msgData, auxDataBuffer, 1024 );
			status = krnlSendMessage( iExportKey, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER );
			if( cryptStatusError( status ) )
				status = CRYPT_ARGERROR_OBJECT;
			auxDataLength = msgData.length;
			}
		else
			status = getIssuerAndSerialNumber( iExportKey, &auxData,
											   &auxDataLength );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Export it as appropriate.  We don't handle key agreement at this
	   level */
	if( cryptMode == CRYPT_MODE_NONE )
		{
		if( cryptAlgo == CRYPT_ALGO_DH || cryptAlgo == CRYPT_ALGO_KEA )
			status = exportKeyAgreeKey( encryptedKey, encryptedKeyLength,
										iSessionKeyContext, iExportKey, 
										iAuxContext, auxData, auxDataLength );
		else
			status = exportPublicKey( encryptedKey, encryptedKeyLength,
									  iSessionKeyContext, iExportKey, 
									  auxData, auxDataLength, recipientType );
		}
	else
		status = exportConventionalKey( encryptedKey, encryptedKeyLength,
										iSessionKeyContext, iExportKey );

	/* Clean up */
	if( auxData != auxDataBuffer )
		free( auxData );
	return( status );
	}

/****************************************************************************
*																			*
*								Object Query Function						*
*																			*
****************************************************************************/

/* Query an object.  This is just a wrapper which provides an external
   interface for queryObject() */

C_RET cryptQueryObject( C_IN void C_PTR objectData,
						C_OUT CRYPT_OBJECT_INFO C_PTR cryptObjectInfo )
	{
	QUERY_INFO queryInfo;
	STREAM stream;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( objectData, MIN_CRYPT_OBJECTSIZE ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( cryptObjectInfo, sizeof( CRYPT_OBJECT_INFO ) ) )
		return( CRYPT_ERROR_PARAM2 );
	memset( cryptObjectInfo, 0, sizeof( CRYPT_OBJECT_INFO ) );

	/* Query the object.  This is just a wrapper for the lower-level
	   queryObject() function */
	sMemConnect( &stream, ( void * ) objectData, STREAMSIZE_UNKNOWN );
	status = queryObject( &stream, &queryInfo );
	sMemDisconnect( &stream );

	/* Copy the externally-visible fields across, setting any unused numeric
	   fields to CRYPT_ERROR */
	if( cryptStatusOK( status ) )
		{
		cryptObjectInfo->objectType = queryInfo.type;
		cryptObjectInfo->cryptAlgo = queryInfo.cryptAlgo;
		cryptObjectInfo->cryptMode = queryInfo.cryptMode;
		if( queryInfo.type == CRYPT_OBJECT_SIGNATURE )
			cryptObjectInfo->hashAlgo = queryInfo.hashAlgo;
		if( queryInfo.type == CRYPT_OBJECT_ENCRYPTED_KEY && \
			queryInfo.saltLength )
			{
			memcpy( cryptObjectInfo->salt, queryInfo.salt, 
					queryInfo.saltLength );
			cryptObjectInfo->saltSize = queryInfo.saltLength;
			}
		}

	return( status );
	}
