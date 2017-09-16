/****************************************************************************
*																			*
*						  cryptlib PKCS #12 Routines						*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

/* This code is based on breakms.c, which breaks the encryption of several of
   MS's extremely broken PKCS #12 implementations.  Because of the security
   problems associated with key files produced by MS software, cryptlib 
   doesn't support this format, especially not for export.  As one vendor who
   shall remain anonymous put it, "We don't want to put our keys anywhere 
   where MS software can get to them" */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "asn1.h"
  #include "asn1oid.h"
  #include "keyset.h"
#elif  defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1oid.h"
  #include "keyset.h"
#else
  #include "crypt.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1oid.h"
  #include "misc/keyset.h"
#endif /* Compiler-specific includes */

/* OID information for a PKCS #12 file */

static const OID_SELECTION dataOIDselection[] = {
    { OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, CRYPT_OK },
    { NULL, 0, 0, 0 }
    };

static const OID_SELECTION keyDataOIDselection[] = {
	{ OID_CMS_ENCRYPTEDDATA, 0, 2, TRUE },				/* Encr.priv.key */
	{ OID_CMS_DATA, CRYPT_UNUSED, CRYPT_UNUSED, FALSE },/* Non-encr priv.key */
	{ NULL, 0, 0, 0 }
	};

/* Read data from a PKCS #12, an incredibly screwed-up and messy format with
   any number of incompatible and broken implementations.  The general format
   is usually:

	PFX ::= SEQUENCE {
		version				INTEGER (3),
		SEQUENCE {					-- authSafes
			contentType		OBJECT IDENTIFIER id-Data,
			content	  [ 0 ]	EXPLICIT OCTET STRING {
				SEQUENCE {			-- authenticatedSafes
					SEQUENCE {		-- authenticatedSafe
						contentType		OBJECT IDENTIFIER id-Data, id-EncryptedData,
						content	  [ 0 ]	EXPLICIT OCTET STRING {
							{
							}
						}
					}
				}
			} */

#if 0
static int readPKCS8Key( STREAM *stream, CRYPT_CONTEXT *iCryptContextPtr,
							const char *password )
	{
	CRYPT_CONTEXT iCryptContext;
	BYTE *buffer, hashResult[ CRYPT_MAX_HASHSIZE ], dataType[ 11 ];
	int hashInfoSize, hashInputSize, hashOutputSize;
	HASHFUNCTION hashFunction;
	long length;
	int dataTypeLength, status;

	/* Read the encryption algorithm type */
	status = checkReadOID( stream, OID_RC4 );
	if( status <= 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the OCTET STRING containing the encrypted RSA key */
	if( readTag( stream ) != BER_OCTETSTRING )
		return( CRYPT_ERROR_BADDATA );
	readLength( stream, &length );
	if( length > 8192 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the encrypted data into an in-memory buffer */
	if( ( buffer = ( BYTE * ) malloc( ( size_t ) length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	sread( stream, buffer, ( int ) length );
	if( ( status = sGetStatus( stream ) ) == CRYPT_UNDERFLOW ||
		status == CRYPT_DATA_READ )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( CRYPT_ERROR_BADDATA );
		}

	/* Hash the passphrase with MD5 */
	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashInputSize,
					   &hashOutputSize, &hashInfoSize );
	hashFunction( NULL, hashResult, ( void * ) password, strlen( password ),
				  HASH_ALL );

	/* Load the hashed passphrase into an encryption context.  Since it's an
	   internal key load, this clears the hashed key */
	status = iCryptCreateContext( &iCryptContext, CRYPT_ALGO_RC4,
								  CRYPT_MODE_STREAM );
	if( !cryptStatusError( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, hashResult, hashOutputSize );
		status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEY, 0 );
		}
	if( cryptStatusError( status ) )
		{
		zeroise( buffer, ( int ) length );
		free( buffer );
		return( status );
		}

	/* Decrypt the private key components */
	iCryptDecrypt( iCryptContext, buffer, ( int ) length );
	iCryptDestroyObject( iCryptContext );

	/* Read the private key fields */
	status = readPKCS8PrivateKey( buffer, ( int ) length, iCryptContextPtr );

	/* Clean up (the buffer has already been wiped in readPKCS8PrivateKey() */
	free( buffer );
	return( status );
	}
#endif /* 0 */

static int unwrapOctetString( STREAM *stream, BYTE *buffer, 
							  const int totalLength )
	{
	int bufPos = 0, status;

	while( !checkEOC( stream ) )
		{
		long length;

		/* Read the current OCTET STRING segment into the buffer */
		if( readTag( stream ) != BER_OCTETSTRING )
			return( CRYPT_ERROR_BADDATA );
		status = readLength( stream, &length );
		if( cryptStatusError( status ) )
			return( status );

		/* Make sure we don't overshoot the buffer if the length encodings 
		   are wrong */
		if( bufPos + length > totalLength )
			return( CRYPT_ERROR_BADDATA );

		/* Copy in the current segment */
		status = sread( stream, buffer + bufPos, ( int ) length );
		bufPos += ( int ) length;
		}

	return( bufPos );
	}

/* Get a key from a PKCS #12 file.  In practice we should use the same method
   as the one used by the PKCS #15 code where we scan the file when we open it
   (stripping out unnecessary junk on the way) and simply fetch the 
   appropriate key from the preprocessed data when getItem() is called */

static int getItemFunction( KEYSET_INFO *keysetInfo,
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	STREAM *stream = &keysetInfo->keysetFile.stream, memStream;
	BYTE *buffer;
	BOOLEAN isIndefinite = FALSE;
	long value;
	int totalLength, status;

	/* Read the outer wrapper, version number field, and CMS data wrapper */
	status = readSequence( stream, NULL );
	if( cryptStatusError( status ) || \
		cryptStatusError( readShortInteger( stream, &value ) ) || \
		( value != 3 ) )
		return( CRYPT_ERROR_BADDATA );
	status = readCMSheader( stream, dataOIDselection, &value );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_BADDATA );
	if( value == CRYPT_UNUSED )
		isIndefinite = TRUE;

	/* Extract the OCTET STRING data into an in-memory buffer.  If the file
	   is of a known length we allocate a buffer of that size, otherwise we
	   just try for a reasonable value (indefinite-length encodings are only
	   used by the broken Netscape code which breaks each component up into
	   its own OCTET STRING) */
	totalLength = ( isIndefinite ) ? 16384 : ( int ) value;
	if( ( buffer = malloc( totalLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	if( isIndefinite )
		status = totalLength = unwrapOctetString( stream, buffer,
												  totalLength );
	else
		status = sread( stream, buffer, totalLength );
	if( cryptStatusError( status ) )
		{
		free( buffer );
		return( status );
		}

	/* Extract the next level of unnecessarily nested data from the mess */
	sMemConnect( &memStream, buffer, totalLength );
	status = readSequence( &memStream, NULL );
	if( !cryptStatusError( status ) )
		status = readCMSheader( &memStream, keyDataOIDselection, &value );
	if( !cryptStatusError( status ) )
		{
		BYTE *innerBuffer;

		/* If it's straight Data, it'll be a PKCS #8 encrypted nested mess
		   rather than a straight encrypted mess */
		isIndefinite = ( value == CRYPT_UNUSED ) ? TRUE : FALSE;
		if( !isIndefinite )
			totalLength = ( int ) value;
		if( ( innerBuffer = malloc( totalLength ) ) != NULL )
			{
			if( isIndefinite )
				{
				status = totalLength = unwrapOctetString( &memStream,
												innerBuffer, totalLength );
				if( !cryptStatusError( status ) )
					status = CRYPT_OK;
				}
			else
				status = sread( stream, innerBuffer, totalLength );

			/* At this point you're on your own - this is too ghastly to
			   continue */

			free( innerBuffer );
			}
		}
	sMemDisconnect( &memStream );
	free( buffer );

	status = CRYPT_ERROR;	/* Make sure we always fail */
	return( status );
	}

/* A PKCS #12 file can contain steaming mounds of keys and whatnot, so when we 
   open it we scan it and record various pieces of information about it which 
   we can use later when we need to access it */

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *name,
							   const char *arg1, const char *arg2,
							   const char *arg3, const CRYPT_KEYOPT_TYPE options )
	{
	assert( name == NULL ); assert( arg1 == NULL ); 
	assert( arg2 == NULL ); assert( arg3 == NULL );

	return( CRYPT_OK );
	}

int setAccessMethodPKCS12( KEYSET_INFO *keysetInfo )
	{
	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
