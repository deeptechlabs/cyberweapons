/****************************************************************************
*																			*
*						 cryptlib HTTP Mapping Routines						*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <string.h>
#include <time.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "keyset.h"
  #include "net.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "keyset.h"
  #include "net.h"
#else
  #include "crypt.h"
  #include "misc/keyset.h"
  #include "misc/net.h"
#endif /* Compiler-specific includes */

/* The default size of the HTTP read buffer.  This is a bit of a difficult
   quantity to get right, for cert's it's way too big, for cert chains it's
   a bit too big, and for CRL's it could be much too small (1/4MB CRL's
   have been seen in the wild).  We try to allocate an appropriate-sized
   buffer if we can, otherwise we grow it in HTTP_BUFFER_STEP chunks */

#define HTTP_BUFFER_SIZE	8192
#define HTTP_BUFFER_STEP	16384

#ifdef DBX_HTTP

/****************************************************************************
*																			*
*						 		Keyset Access Routines						*
*																			*
****************************************************************************/

/* Map a Tcp4u status to a cryptlib one */

static int mapError( KEYSET_INFO *keysetInfoPtr, int status )
	{
	/* Remember the error code and message */
	keysetInfoPtr->errorCode = status;
	strncpy( keysetInfoPtr->errorMessage, Tcp4uErrorString( status ),
			 MAX_ERRMSG_SIZE - 1 );
	keysetInfoPtr->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	return( Tcp4MapError( status ) );
	}

/* The callback used to handle data read from a socket */

static BOOL CALLBACK httpCallback( long lBytesTransferred, long lTotalBytes,
								   long lUserValue, LPCSTR data, int dataLength )
	{
	KEYSET_INFO *keysetInfoPtr = ( KEYSET_INFO * ) lUserValue;
	const int bufSize = keysetInfoPtr->keyDataSize;

	/* If nothing has been transferred yet, just return (we always get this
	   at least once when only the headers have been transferred) */
	if( !dataLength )
		{
		/* If we know how big the file will be and it's bigger than the
		   allocated buffer, allocate room for it.  We don't use realloc()
		   because there's no need to preserve any existing data */
		if( lTotalBytes > bufSize )
			{
			free( keysetInfoPtr->keyData );
			if( ( keysetInfoPtr->keyData = malloc( lTotalBytes + 512 ) ) == NULL )
				return( FALSE );
			keysetInfoPtr->keyDataSize = lTotalBytes + 512;
			}

		return( TRUE );
		}

	/* Copy the transferred data in, expanding the buffer if necessary */
	if( keysetInfoPtr->keysetHTTP.bufPos + dataLength > bufSize )
		{
		const int newSize = max( bufSize + HTTP_BUFFER_STEP, lTotalBytes );
		void *newBuffer = realloc( keysetInfoPtr->keyData, newSize );

		if( newBuffer == NULL )
			return( FALSE );
		keysetInfoPtr->keyData = newBuffer;
		keysetInfoPtr->keyDataSize = newSize;
		}
	memcpy( ( BYTE * ) keysetInfoPtr->keyData + \
			keysetInfoPtr->keysetHTTP.bufPos, data, dataLength );
	keysetInfoPtr->keysetHTTP.bufPos += dataLength;

	return( TRUE );
	}

/* Fetch data from a URL */

static int getItemFunction( KEYSET_INFO *keysetInfo, 
							CRYPT_HANDLE *iCryptHandle, 
							const CRYPT_KEYID_TYPE keyIDtype, 
							const void *keyID,  const int keyIDlength, 
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	char url[ MAX_DNS_SIZE + 1 ], proxy[ MAX_DNS_SIZE + 1 ];
	int timeout, status;

	assert( keyIDtype == CRYPT_KEYID_NAME || keyIDtype == CRYPT_KEYID_EMAIL );
	assert( auxInfo == NULL ); assert( *auxInfoLength == 0 );

	/* Convert the URL into a null-terminated form */
	if( keyIDlength > MAX_DNS_SIZE - 1 )
		return( CRYPT_ARGERROR_STR1 );
	memcpy( url, keyID, keyIDlength );
	url[ keyIDlength ] = '\0';

	/* Get HTTP-related config options */
	setResourceData( &msgData, proxy, MAX_DNS_SIZE );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
					 CRYPT_OPTION_KEYS_HTTP_PROXY );
	proxy[ msgData.length ] = '\0';
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, &timeout,
					 CRYPT_OPTION_KEYS_HTTP_TIMEOUT );

	/* If we haven't allocated a buffer for the data yet, do so now */
	if( keysetInfo->keyData == NULL )
		{
		if( ( keysetInfo->keyData = malloc( HTTP_BUFFER_SIZE ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keysetInfo->keyDataSize = HTTP_BUFFER_SIZE;
		}
	keysetInfo->keysetHTTP.bufPos = 0;

	/* Read the data into the buffer */
	Http4uSetTimeout( timeout );
	status = Http4uGetFileEx( url, *proxy ? proxy : NULL, NULL, NULL,
							  httpCallback, ( long ) keysetInfo, NULL, 
							  0, NULL, 0 );
	if( status != HTTP4U_SUCCESS )
		return( mapError( keysetInfo, status ) );

	/* Create a certificate object from the returned data */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = keysetInfo->keyData;
	createInfo.strArgLen1 = keysetInfo->keyDataSize;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCryptHandle = createInfo.cryptHandle;
	return( status );
	}

static int initKeysetFunction( KEYSET_INFO *keysetInfo, const char *dummy1,
							   const char *dummy2, const char *dummy3,
							   const char *dummy4, 
							   const CRYPT_KEYOPT_TYPE options )
	{
	/* HTTP is stateless so there's nothing to do at this point */
	return( CRYPT_OK );
	}

static void shutdownKeysetFunction( KEYSET_INFO *keysetInfo )
	{
	if( keysetInfo->keyData != NULL )
		{
		zeroise( keysetInfo->keyData, keysetInfo->keyDataSize );
		free( keysetInfo->keyData );
		keysetInfo->keyData = NULL;
		}
	}

int setAccessMethodHTTP( KEYSET_INFO *keysetInfo )
	{
#ifdef DYNAMIC_LOAD
	/* Make sure the TCP/IP interface has been initialised */
	if( hTCP == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* DYNAMIC_LOAD */

	/* Set the access method pointers */
	keysetInfo->initKeysetFunction = initKeysetFunction;
	keysetInfo->shutdownKeysetFunction = shutdownKeysetFunction;
	keysetInfo->getItemFunction = getItemFunction;

	return( CRYPT_OK );
	}
#endif /* DBX_HTTP */
