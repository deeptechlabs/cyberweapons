/****************************************************************************
*																			*
*						cryptlib SSL v3 Session Management					*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "misc.h"
  #include "session.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../misc/net.h"
  #include "../session/session.h"
#else
  #include "crypt.h"
  #include "misc/net.h"
  #include "session/session.h"
#endif /* Compiler-specific includes */

/* Default SSL port */

#define SSL_PORT					443

/* SSL constants */

#define ID_SIZE						1	/* ID byte */
#define UINT16_SIZE					2	/* 16 bits */
#define LENGTH_SIZE					3	/* 24 bits */
#define VERSIONINFO_SIZE			2	/* 0x03, 0x00 */
#define ALERTINFO_SIZE				2	/* level + description */
#define SSL_HEADER_SIZE				5	/* Type, version, length */
#define SSL_NONCE_SIZE				32	/* Size of client/svr nonce */
#define SSL_SECRET_SIZE				48	/* Size of premaster/master secret */
#define MIN_SSL_PACKET_SIZE			4	/* Server hello done */
#define MAX_KEYBLOCK_SIZE			( ( 20 + 24 + 8 ) * 2 )	/* 3DES + SHA-1 */
#define MD5MAC_SIZE					16	/* Size of MD5 proto-HMAC */
#define SHA1MAC_SIZE				20	/* Size of SHA-1 proto-HMAC */

/* Default SSL send/receive buffer size */

#define BUFFER_SIZE					( 16384 + 64 )

/* SSL message types */

#define SSL_MSG_CHANGE_CIPHER_SPEC	20
#define SSL_MSG_ALERT				21
#define SSL_MSG_HANDSHAKE			22
#define SSL_MSG_APPLICATION_DATA	23

#define SSL_MSG_FIRST				20
#define SSL_MSG_LAST				23

/* SSL handshake message subtypes */

#define SSL_HAND_CLIENT_HELLO		0x01
#define SSL_HAND_SERVER_HELLO		0x02
#define SSL_HAND_SERVER_CERT		0x0B
#define SSL_HAND_SERVER_HELLODONE	0x0E
#define SSL_HAND_CLIENT_KEYEXCHANGE	0x10

/* SSL alert levels and types */

#define SSL_ALERTLEVEL_WARNING				1
#define SSL_ALERTLEVEL_FATAL				2

#define SSL_ALERT_CLOSE_NOTIFY				0
#define SSL_ALERT_UNEXPECTED_MESSAGE		10
#define SSL_ALERT_BAD_RECORD_MAC			20
#define SSL_ALERT_DECOMPRESSION_FAILURE		30
#define SSL_ALERT_HANDSHAKE_FAILURE			40
#define SSL_ALERT_NO_CERTIFICATE			41
#define SSL_ALERT_BAD_CERTIFICATE			42
#define SSL_ALERT_UNSUPPORTED_CERTIFICATE	43
#define SSL_ALERT_CERTIFICATE_REVOKED		44
#define SSL_ALERT_CERTIFICATE_EXPIRED		45
#define SSL_ALERT_CERTIFICATE_UNKNOWN		46
#define SSL_ALERT_ILLEGAL_PARAMETER			47
#define TLS_ALERT_UNKNOWN_CA				48
#define TLS_ALERT_ACCESS_DENIED				49
#define TLS_ALERT_DECODE_ERROR				50
#define TLS_ALERT_DECRYPT_ERROR				51
#define TLS_ALERT_EXPORT_RESTRICTION		60
#define TLS_ALERT_PROTOCOL_VERSION			70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR			80
#define TLS_ALERT_USER_CANCELLED			90
#define TLS_ALERT_NO_RENEGOTIATION			100

/* SSL cipher suites */

typedef enum {
	SSL_NULL_WITH_NULL, SSL_RSA_WITH_NULL_MD5, SSL_RSA_WITH_NULL_SHA,
	SSL_RSA_EXPORT_WITH_RC4_40_MD5, SSL_RSA_WITH_RC4_128_MD5,
	SSL_RSA_WITH_RC4_128_SHA, SSL_RSA_EXPORT_WITH_RC2_CBC_40_MD5,
	SSL_RSA_WITH_IDEA_CBC_SHA, SSL_RSA_EXPORT_WITH_DES40_CBC_SHA,
	SSL_RSA_WITH_DES_CBC_SHA, SSL_RSA_WITH_3DES_EDE_CBC_SHA,
	SSL_LAST } SSL_CIPHERSUITE_TYPE;

/* SSL and TLS major and minor version numbers */

#define SSL_MAJOR_VERSION		3
#define SSL_MINOR_VERSION		0
#define TLS_MINOR_VERSION		1

/* SSL sender magic values for the finished message MAC */

#define SSL_SENDER_CLIENTMAGIC	"\x43\x4C\x4E\x54"
#define SSL_SENDER_SERVERMAGIC	"\x53\x52\x56\x52"
#define SSL_SENDERMAGIC_SIZE	4

/* Proto-HMAC padding data */

#define PROTOHMAC_PAD1			"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36" \
								"\x36\x36\x36\x36\x36\x36\x36\x36"
#define PROTOHMAC_PAD2			"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" \
								"\x5C\x5C\x5C\x5C\x5C\x5C\x5C\x5C" 

/* SSL handshake state information.  This is passed around various 
   subfunctions which handle individual parts of the handshake */

typedef struct {
	/* Client and server proto-HMAC contexts */
	CRYPT_CONTEXT clientMD5context, clientSHA1context;
	CRYPT_CONTEXT serverMD5context, serverSHA1context;

	/* Client and server nonces */
	BYTE nonceBuffer[ SSL_NONCE_SIZE + SSL_NONCE_SIZE ];
	BYTE clientNonce[ SSL_NONCE_SIZE ], serverNonce[ SSL_NONCE_SIZE ];

	/* Premaster and master secrets */
	BYTE premasterSecret[ SSL_SECRET_SIZE ];
	BYTE masterSecret[ SSL_SECRET_SIZE ];
	} SSL_HANDSHAKE_INFO;

#ifdef NET_TCP 

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Most of the SSL packets have fixed formats, so we can construct them by
   copying in a constant template and setting up the variable fields.  The
   following templates are for various packet types */

#define FINISHED_TEMPLATE_SIZE			10
#define CLOSEALERT_TEMPLATE_SIZE		7

static const BYTE finishedTemplate[] = {
	SSL_MSG_HANDSHAKE,							/* ID */
	SSL_MAJOR_VERSION, SSL_MINOR_VERSION,		/* Version */
	0, SSL_HEADER_SIZE + MD5MAC_SIZE + SHA1MAC_SIZE,/* Length */
		SSL_MSG_HANDSHAKE,						/* ID */
		SSL_MAJOR_VERSION, SSL_MINOR_VERSION,	/* Version */
		0, MD5MAC_SIZE + SHA1MAC_SIZE			/* Length */
	};
static const BYTE closeAlertTemplate[] = {
	SSL_MSG_ALERT,								/* ID */
	SSL_MAJOR_VERSION, SSL_MINOR_VERSION,		/* Version */
	0, 2,										/* Length */
	SSL_ALERTLEVEL_WARNING, SSL_ALERT_CLOSE_NOTIFY
	};

/* Map a Tcp4u status to a cryptlib one */

static int mapError( SESSION_INFO *sessionInfoPtr, int status )
	{
	/* Remember the error code and message */
	sessionInfoPtr->errorCode = status;
	strncpy( sessionInfoPtr->errorMessage, Tcp4uErrorString( status ),
			 MAX_ERRMSG_SIZE - 1 );
	sessionInfoPtr->errorMessage[ MAX_ERRMSG_SIZE - 1 ] = '\0';

	return( Tcp4MapError( status ) );
	}

/* Set up the information implied by an SSL cipher suite */

static int initCiphersuiteInfo( SESSION_INFO *sessionInfoPtr,
								const int cipherSuite )
	{
	if( cipherSuite == SSL_RSA_WITH_3DES_EDE_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_3DES;
		sessionInfoPtr->integrityAlgo = CRYPT_ALGO_SHA;
		sessionInfoPtr->cryptBlocksize = 8;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_RC4_128_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_RC4;
		sessionInfoPtr->integrityAlgo = CRYPT_ALGO_SHA;
		sessionInfoPtr->cryptBlocksize = 1;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_RC4_128_MD5 )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_RC4;
		sessionInfoPtr->integrityAlgo = CRYPT_ALGO_MD5;
		sessionInfoPtr->cryptBlocksize = 1;
		sessionInfoPtr->authBlocksize = MD5MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_IDEA_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_IDEA;
		sessionInfoPtr->integrityAlgo = CRYPT_ALGO_SHA;
		sessionInfoPtr->cryptBlocksize = 8;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}
	if( cipherSuite == SSL_RSA_WITH_DES_CBC_SHA )
		{
		sessionInfoPtr->cryptAlgo = CRYPT_ALGO_DES;
		sessionInfoPtr->integrityAlgo = CRYPT_ALGO_SHA;
		sessionInfoPtr->cryptBlocksize = 8;
		sessionInfoPtr->authBlocksize = SHA1MAC_SIZE;
		return( CRYPT_OK );
		}

	return( CRYPT_ERROR_NOTAVAIL );
	}

/* Initialise and destroy the handshake state information */

static void destroyHandshakeInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Destroy any active contexts */
	if( handshakeInfo->clientMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientMD5context,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverMD5context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverMD5context,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->clientSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->clientSHA1context,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
	if( handshakeInfo->serverSHA1context != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->serverSHA1context,
						  RESOURCE_IMESSAGE_DECREFCOUNT );

	zeroise( handshakeInfo, sizeof( SSL_HANDSHAKE_INFO ) );
	}

static int initHandshakeInfo( SSL_HANDSHAKE_INFO *handshakeInfo )
	{
	CREATEOBJECT_INFO createInfo;
	int status;

	/* Initialise the handshake state info values */
	memset( handshakeInfo, 0, sizeof( SSL_HANDSHAKE_INFO ) );
	handshakeInfo->clientMD5context = \
		handshakeInfo->serverMD5context = \
		handshakeInfo->clientSHA1context = \
		handshakeInfo->serverSHA1context = CRYPT_ERROR;

	/* Create the MAC contexts for ingoing and outgoing data.  Since SSL uses
	   a pre-HMAC variant, we can't use real HMAC but have to construct it
	   ourselves from MD5 and SHA-1 */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_MD5 );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverMD5context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->clientSHA1context = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_SHA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		handshakeInfo->serverSHA1context = createInfo.cryptHandle;
		return( CRYPT_OK );
		}

	/* One or more of the contexts couldn't be created, destroy all the 
	   contexts which have been created so far */
	destroyHandshakeInfo( handshakeInfo );
	return( status );
	}

/* Initialise and destroy the security contexts */

static void destroySecurityContexts( SESSION_INFO *sessionInfoPtr )
	{
	/* Destroy any active contexts */
	if( sessionInfoPtr->iKeyexCryptContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iKeyexCryptContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iKeyexCryptContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthInContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iAuthOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iAuthOutContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iAuthOutContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptInContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptInContext = CRYPT_ERROR;
		}
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		krnlSendNotifier( sessionInfoPtr->iCryptOutContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		sessionInfoPtr->iCryptOutContext = CRYPT_ERROR;
		}
	}

static int initSecurityContexts( SESSION_INFO *sessionInfoPtr )
	{
	CREATEOBJECT_INFO createInfo;
	int status;

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->integrityAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iAuthOutContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
	else
		/* One or more of the contexts couldn't be created, destroy all the 
		   contexts which have been created so far */
		destroySecurityContexts( sessionInfoPtr );
	return( status );
	}

/* Encrypt a data block */

static int encryptData( SESSION_INFO *sessionInfoPtr, BYTE *data,
						const int dataLength )
	{
	int length = dataLength, status;

	/* If it's a block cipher, we need to add and-of-block padding */
	if( sessionInfoPtr->cryptBlocksize > 1 )
		{
		BYTE *dataPadPtr = data + dataLength;
		const int padSize = ( sessionInfoPtr->cryptBlocksize - 1 ) - \
						    ( dataLength & ( sessionInfoPtr->cryptBlocksize - 1 ) );
		int i;

		for( i = 0; i < padSize + 1; i++ )
			*dataPadPtr++ = padSize;	/* PKCS #5 padding required by TLS */
		length += padSize + 1;
		}

	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
							  RESOURCE_IMESSAGE_CTX_ENCRYPT, data, length );
	return( cryptStatusError( status ) ? status : length );
	}

/* Perform a dual MAC of a data block */

static int macData( SSL_HANDSHAKE_INFO *handshakeInfo, const void *data,
					const int dataLength )
	{
	int status;

	status = krnlSendMessage( handshakeInfo->clientMD5context,
							  RESOURCE_IMESSAGE_CTX_HASH, 
							  ( void * ) data, dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->clientSHA1context,
								  RESOURCE_IMESSAGE_CTX_HASH, 
								  ( void * ) data, dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverMD5context,
								  RESOURCE_IMESSAGE_CTX_HASH, 
								  ( void * ) data, dataLength );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( handshakeInfo->serverSHA1context,
								  RESOURCE_IMESSAGE_CTX_HASH, 
								  ( void * ) data, dataLength );
	return( status );
	}

/* Wrap/unwrap data in various packets:

	byte		type = 20 (changeCipher), 22 (handshake)
	byte[2]		version = { 0x03, 0x00 }
	uint16		len

   This takes as input a data packet with a 5-byte gap at the start for the
   header and wraps it up as appropriate in the SSL/TLS packet 
   encapsulation */

static void wrapHandshakePacket( void *data, const int length,
								 const CRYPT_FORMAT_TYPE sessionType )
	{
	BYTE *dataPtr = data;

	/* Add the length and type at the start */
	*dataPtr++ = SSL_MSG_HANDSHAKE;
	*dataPtr++ = SSL_MAJOR_VERSION;
	*dataPtr++ = ( sessionType == CRYPT_FORMAT_SSL ) ? \
				 SSL_MINOR_VERSION : TLS_MINOR_VERSION;
	mputBWord( dataPtr, length );
	}

/* Process an alert packet */

static int processAlert( SESSION_INFO *sessionInfoPtr, const SOCKET socket )
	{
	const static struct {
		const int type;
		const char *message;
		} alertInfo[] = {
		{ SSL_ALERT_CLOSE_NOTIFY, "Close notify" },
		{ SSL_ALERT_UNEXPECTED_MESSAGE, "Unexpected message" },
		{ SSL_ALERT_BAD_RECORD_MAC, "Bad record MAC" },
		{ SSL_ALERT_DECOMPRESSION_FAILURE, "Decompression failure" },
		{ SSL_ALERT_HANDSHAKE_FAILURE, "Handshake failure" },
		{ SSL_ALERT_NO_CERTIFICATE, "No certificate" },
		{ SSL_ALERT_BAD_CERTIFICATE, "Bad certificate" },
		{ SSL_ALERT_UNSUPPORTED_CERTIFICATE, "Unsupported certificate" },
		{ SSL_ALERT_CERTIFICATE_REVOKED, "Certificate revoked" },
		{ SSL_ALERT_CERTIFICATE_EXPIRED, "Certificate expired" },
		{ SSL_ALERT_CERTIFICATE_UNKNOWN, "Certificate unknown" },
		{ SSL_ALERT_ILLEGAL_PARAMETER, "Illegal parameter" },
		{ TLS_ALERT_UNKNOWN_CA, "Unknown CA" },
		{ TLS_ALERT_ACCESS_DENIED, "Access denied" },
		{ TLS_ALERT_DECODE_ERROR, "Decode error" },
		{ TLS_ALERT_DECRYPT_ERROR, "Decrypt error" },
		{ TLS_ALERT_EXPORT_RESTRICTION, "Export restriction" },
		{ TLS_ALERT_PROTOCOL_VERSION, "Protocol version" },
		{ TLS_ALERT_INSUFFICIENT_SECURITY, "Insufficient security" },
		{ TLS_ALERT_INTERNAL_ERROR, "Internal error" },
		{ TLS_ALERT_USER_CANCELLED, "User cancelled" },
		{ TLS_ALERT_NO_RENEGOTIATION, "No renegotiation" },
		{ CRYPT_ERROR, NULL }
		};
	int type, i, status;

	/* Get the alert packet and tell the server we're going away */
	status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
					  ALERTINFO_SIZE, sessionInfoPtr->timeout, 
					  HFILE_ERROR );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	TcpSend( socket, closeAlertTemplate, CLOSEALERT_TEMPLATE_SIZE,
			 FALSE, HFILE_ERROR );

	/* Process the alert info */
	if( sessionInfoPtr->receiveBuffer[ 0 ] != SSL_ALERTLEVEL_WARNING && \
		sessionInfoPtr->receiveBuffer[ 0 ] != SSL_ALERTLEVEL_FATAL )
		return( CRYPT_ERROR_BADDATA );
	sessionInfoPtr->errorCode = type = sessionInfoPtr->receiveBuffer[ 1 ];
	for( i = 0; alertInfo[ i ].type != CRYPT_ERROR && \
				alertInfo[ i ].type != type; i++ );
	if( alertInfo[ i ].type == CRYPT_ERROR )
		return( CRYPT_ERROR_BADDATA );
	strcpy( sessionInfoPtr->errorMessage, 
			( sessionInfoPtr->type == CRYPT_FORMAT_SSL ) ? \
			"Received SSL alert message: " : "Received TLS alert message: " );
	strcat( sessionInfoPtr->errorMessage, alertInfo[ i ].message );
	return( CRYPT_ERROR_FAILED );
	}

/* Read an SSL packet */

static int readPacket( SESSION_INFO *sessionInfoPtr, 
					   SSL_HANDSHAKE_INFO *handshakeInfo,
					   const SOCKET socket, const int packetType )
	{
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	int totalLength, ch, status;

	/* Read the SSL packet header data */
	status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
					  SSL_HEADER_SIZE, sessionInfoPtr->timeout, 
					  HFILE_ERROR );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	macData( handshakeInfo, sessionInfoPtr->receiveBuffer, SSL_HEADER_SIZE );

	/* Check for an SSL alert message */
	ch = *bufPtr++;
	if( ch == SSL_MSG_ALERT )
		{
		if( *bufPtr++ != SSL_MAJOR_VERSION )
			return( CRYPT_ERROR_BADDATA );
		ch = *bufPtr++;
		if( ( ch != SSL_MINOR_VERSION && ch != TLS_MINOR_VERSION ) || \
			*bufPtr++ != 0 || *bufPtr++ != ALERTINFO_SIZE )
			return( CRYPT_ERROR_BADDATA );
		return( processAlert( sessionInfoPtr, socket ) );
		}

	/* Decode the SSL handshake header */
	if( ch != packetType || *bufPtr++ != SSL_MAJOR_VERSION )
		return( CRYPT_ERROR_BADDATA );
	ch = *bufPtr++;
	if( ch != SSL_MINOR_VERSION && ch != TLS_MINOR_VERSION )
		return( CRYPT_ERROR_BADDATA );
	totalLength = mgetBWord( bufPtr );
	if( totalLength < MIN_SSL_PACKET_SIZE || totalLength > BUFFER_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Read the payload packet(s) */
	status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
					  totalLength, sessionInfoPtr->timeout, HFILE_ERROR );
	if( status < TCP4U_SUCCESS ) 
		return( mapError( sessionInfoPtr, status ) );
	sessionInfoPtr->receiveBufPos = 0;
	sessionInfoPtr->receiveBufEnd = totalLength;
	macData( handshakeInfo, sessionInfoPtr->receiveBuffer, totalLength );
	return( CRYPT_OK );
	}

/* Perform the initial part of the handshake with the server */

static int beginHandshake( SESSION_INFO *sessionInfoPtr, 
						   SSL_HANDSHAKE_INFO *handshakeInfo, 
						   const SOCKET socket )
	{
	CRYPT_QUERY_INFO queryInfo;
	BYTE *bufPtr, *bufMarkPtr, *lengthPtr;
	int length, cipherSuite, ch, status;

	/* Build the client hello packet:
		byte		ID = 1
		uint24		len
		byte[2]		version = { 0x03, 0x00 }
		uint32		time			| Session ID
		byte[28]	nonce			|
		byte		sessIDlen = 0	| May receive nonzero len +
		uint16		suiteLen		|	<len> bytes data
		uint16[]	suite
		byte		coprLen = 1
		byte[]		copr = { 0x00 } */
	getNonce( handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	bufPtr = sessionInfoPtr->sendBuffer + SSL_HEADER_SIZE;
	*bufPtr++ = SSL_HAND_CLIENT_HELLO;
	*bufPtr++ = 0;
	lengthPtr = bufPtr;	/* Low 16 bits of length */
	bufPtr += LENGTH_SIZE - 1;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = ( sessionInfoPtr->type == CRYPT_FORMAT_SSL ) ? \
				SSL_MINOR_VERSION : TLS_MINOR_VERSION;
	memcpy( bufPtr, handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	bufPtr += SSL_NONCE_SIZE;
	*bufPtr++ = '\0';		/* No session ID */
	bufMarkPtr = bufPtr;
	bufPtr += UINT16_SIZE;	/* Leave room for length */
	if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_3DES ) ) )
		{
		mputBWord( bufPtr, SSL_RSA_WITH_3DES_EDE_CBC_SHA ); 
		}
	if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_RC4 ) ) )
		{
		mputBWord( bufPtr, SSL_RSA_WITH_RC4_128_SHA );
		mputBWord( bufPtr, SSL_RSA_WITH_RC4_128_MD5 );
		}
	if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_IDEA ) ) )
		{ 
		mputBWord( bufPtr, SSL_RSA_WITH_IDEA_CBC_SHA ); 
		}
	if( cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_DES ) ) )
		{ 
		mputBWord( bufPtr, SSL_RSA_WITH_DES_CBC_SHA ); 
		}
	mputBWord( bufMarkPtr, bufPtr - ( bufMarkPtr + UINT16_SIZE ) );
	*bufPtr++ = 1;						/* No compression */
	*bufPtr++ = 0;
	length = bufPtr - ( sessionInfoPtr->sendBuffer + SSL_HEADER_SIZE );
	mputBWord( lengthPtr, length - ( ID_SIZE + LENGTH_SIZE ) );
	wrapHandshakePacket( sessionInfoPtr->sendBuffer, length, 
						 sessionInfoPtr->type );

	/* Send the client hello to the server and read back and process the 
	   servers data (server hello, cert or key mgt. packets, and server 
	   done) */
	status = TcpSend( socket, sessionInfoPtr->sendBuffer, 
					  SSL_HEADER_SIZE + length, FALSE, HFILE_ERROR );
	if( status != TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	macData( handshakeInfo, sessionInfoPtr->sendBuffer, 
			 SSL_HEADER_SIZE + length );
	status = readPacket( sessionInfoPtr, handshakeInfo, socket, 
						 SSL_MSG_HANDSHAKE );
	if( cryptStatusError( status ) )
		return( status );

	/* Process the server hello:
		byte		ID = 2
		uint24		len
		byte[2]		version = { 0x03, 0x00 }
		uint32		time			| Session ID
		byte[28]	nonce			|
		byte		sessIDlen = 0
		uint16		suite
		byte		copr = 0 */
	bufPtr = sessionInfoPtr->receiveBuffer;
	if( *bufPtr++ != SSL_HAND_SERVER_HELLO || *bufPtr++ != 0 )
		return( CRYPT_ERROR_BADDATA );
	length = mgetBWord( bufPtr );
	if( length < VERSIONINFO_SIZE + SSL_NONCE_SIZE + 1 + UINT16_SIZE + 1 || \
		*bufPtr++ != SSL_MAJOR_VERSION )
		return( CRYPT_ERROR_BADDATA );
	ch = *bufPtr++;
	if( ch != SSL_MINOR_VERSION && ch != TLS_MINOR_VERSION )
		return( CRYPT_ERROR_BADDATA );
	sessionInfoPtr->receiveBufPos = ID_SIZE + LENGTH_SIZE + length;
	if( ch == SSL_MINOR_VERSION && sessionInfoPtr->type == CRYPT_FORMAT_TLS )
		/* If the server can't do TLS, fall back to SSL */
		sessionInfoPtr->type = CRYPT_FORMAT_SSL;
	memcpy( handshakeInfo->serverNonce, bufPtr, SSL_NONCE_SIZE );
	bufPtr += SSL_NONCE_SIZE;
	length = *bufPtr++;		/* Session ID length */
	if( length > 32 )
		return( CRYPT_ERROR_BADDATA );
	bufPtr += length;	/* Skip session ID */
	cipherSuite = mgetBWord( bufPtr );
	status = initCiphersuiteInfo( sessionInfoPtr, cipherSuite );
	if( cryptStatusError( status ) )
		return( status );
	if( *bufPtr++ )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/* Exchange keys with the server */

static int exchangeKeys( SESSION_INFO *sessionInfoPtr, 
						 SSL_HANDSHAKE_INFO *handshakeInfo, 
						 const SOCKET socket )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE *bufPtr = sessionInfoPtr->receiveBuffer + \
				   sessionInfoPtr->receiveBufPos;
	int length, keySize, status;

	/* Process the server cert chain:
		byte		ID = 0x0B
		uint24		len
		uint24		certLen			| 1...n certs ordered
		byte[]		cert			|   leaf -> root */
	if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
		{
		status = readPacket( sessionInfoPtr, handshakeInfo, socket, 
							 SSL_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr = sessionInfoPtr->receiveBuffer;
		}		
	if( *bufPtr++ != SSL_HAND_SERVER_CERT || *bufPtr++ != 0 )
		return( CRYPT_ERROR_BADDATA );
	length = mgetBWord( bufPtr );
	if( length < 64 || length > BUFFER_SIZE || \
		*bufPtr++ != 0 )
		return( CRYPT_ERROR_BADDATA );
	sessionInfoPtr->receiveBufPos += ID_SIZE + LENGTH_SIZE + length;
	length = mgetBWord( bufPtr );	/* Length of cert chain */

	/* Import the cert chain.  Since this isn't a true cert chain (in the 
	   sense of being degenerate PKCS #7 SignedData) but a special-case 
	   SSL-encoded cert chain, we notify the cert management code of this 
	   when it performs the import */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.createIndirect = TRUE;
	createInfo.arg1 = CERTFORMAT_SSLCHAIN;
	createInfo.strArg1 = bufPtr;
	createInfo.strArgLen1 = length;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusError( status ) )
		return( status );

	/* Make sure we can encrypt using the key we've been given (this performs 
	   a variety of checks alongside the obvious one, so it's a good general 
	   health check before we go any further).  If this fails, we convert the 
	   result to a wrong key error rather than a check failure */
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_CHECK, NULL,
							  RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_WRONGKEY );
	sessionInfoPtr->iKeyexCryptContext = createInfo.cryptHandle;
	krnlSendMessage( sessionInfoPtr->iKeyexCryptContext,
					 RESOURCE_IMESSAGE_GETATTRIBUTE, &keySize,
					 CRYPT_CTXINFO_KEYSIZE );
	bufPtr += length;

	/* Process the server hello done:
		byte		ID = 0x0E
		uint24		len = 0 */
	if( sessionInfoPtr->receiveBufPos >= sessionInfoPtr->receiveBufEnd )
		{
		status = readPacket( sessionInfoPtr, handshakeInfo, socket, 
							 SSL_MSG_HANDSHAKE );
		if( cryptStatusError( status ) )
			return( status );
		bufPtr = sessionInfoPtr->receiveBuffer;
		}		
	if( *bufPtr++ != SSL_HAND_SERVER_HELLODONE || *bufPtr++ != 0 || \
		*bufPtr++ != 0 || *bufPtr++ != 0 )
		return( CRYPT_ERROR_BADDATA );

	/* Build the client key exchange packet:
		byte		ID = 0x10
		uint24		len
		byte[]		rsaPKCS1( byte[2] { 0x03, 0x00 } || byte[46] random ) */
	bufPtr = sessionInfoPtr->sendBuffer + SSL_HEADER_SIZE;
	*bufPtr++ = SSL_HAND_CLIENT_KEYEXCHANGE;
	*bufPtr++ = 0;
	mputBWord( bufPtr, keySize );

	/* Create the premaster secret, wrap it using the servers public key, and
	   send it to the server */
	handshakeInfo->premasterSecret[ 0 ] = SSL_MAJOR_VERSION;
	handshakeInfo->premasterSecret[ 1 ] = \
						( sessionInfoPtr->type == CRYPT_FORMAT_SSL ) ? \
						SSL_MINOR_VERSION : TLS_MINOR_VERSION;
	setResourceData( &msgData, 
					 handshakeInfo->premasterSecret + VERSIONINFO_SIZE, 
					 SSL_SECRET_SIZE - VERSIONINFO_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	setMechanismWrapInfo( &mechanismInfo, bufPtr, CRYPT_MAX_PKCSIZE, 
						  handshakeInfo->premasterSecret, SSL_SECRET_SIZE, 
						  CRYPT_UNUSED, sessionInfoPtr->iKeyexCryptContext, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo,
							  MECHANISM_PKCS1 );
	if( cryptStatusError( status ) )
		return( status );
	length = ID_SIZE + LENGTH_SIZE + keySize;
	wrapHandshakePacket( sessionInfoPtr->sendBuffer, length,
						 sessionInfoPtr->type );
	status = TcpSend( socket, sessionInfoPtr->sendBuffer, 
					  SSL_HEADER_SIZE + length, FALSE, HFILE_ERROR );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	macData( handshakeInfo, sessionInfoPtr->sendBuffer, 
			 SSL_HEADER_SIZE + length );

	return( CRYPT_OK );
	}

/* Complete the handshake with the server */

static int completeHandshake( SESSION_INFO *sessionInfoPtr, 
							  SSL_HANDSHAKE_INFO *handshakeInfo, 
							  const SOCKET socket )
	{
	MECHANISM_DERIVE_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	BYTE masterSecret[ SSL_SECRET_SIZE ], keyBlock[ MAX_KEYBLOCK_SIZE ];
	BYTE clientMD5[ CRYPT_MAX_HASHSIZE ], clientSHA1[ CRYPT_MAX_HASHSIZE ];
	BYTE serverMD5[ CRYPT_MAX_HASHSIZE ], serverSHA1[ CRYPT_MAX_HASHSIZE ];
	BYTE *bufPtr, *keyBlockPtr, *encryptDataPtr;
	int length, keySize, ivSize, status;

	/* Create the security contexts required for the session */
	status = initSecurityContexts( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	krnlSendMessage( sessionInfoPtr->iCryptInContext,
					 RESOURCE_IMESSAGE_GETATTRIBUTE, &keySize,
					 CRYPT_CTXINFO_KEYSIZE );
	krnlSendMessage( sessionInfoPtr->iCryptInContext,
					 RESOURCE_IMESSAGE_GETATTRIBUTE, &ivSize,
					 CRYPT_CTXINFO_IVSIZE );

	/* Convert the premaster secret into the master secret */
	memcpy( handshakeInfo->nonceBuffer, handshakeInfo->clientNonce, 
			SSL_NONCE_SIZE );
	memcpy( handshakeInfo->nonceBuffer + SSL_NONCE_SIZE, 
			handshakeInfo->serverNonce, SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, masterSecret, SSL_SECRET_SIZE,
							handshakeInfo->premasterSecret, SSL_SECRET_SIZE,
							handshakeInfo->nonceBuffer, 
								SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_SSL );
	if( cryptStatusError( status ) )
		return( status );

	/* Convert the master secret into keying material */
	memcpy( handshakeInfo->nonceBuffer, handshakeInfo->serverNonce, 
			SSL_NONCE_SIZE );
	memcpy( handshakeInfo->nonceBuffer + SSL_NONCE_SIZE, 
			handshakeInfo->clientNonce, SSL_NONCE_SIZE );
	setMechanismDeriveInfo( &mechanismInfo, keyBlock, MAX_KEYBLOCK_SIZE,
							masterSecret, SSL_SECRET_SIZE,
							handshakeInfo->nonceBuffer, 
								SSL_NONCE_SIZE + SSL_NONCE_SIZE, 1 );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_DERIVE,
							  &mechanismInfo, MECHANISM_SSL );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Load the keys and secrets */
	memcpy( sessionInfoPtr->sslMacWriteSecret, keyBlock, 
			sessionInfoPtr->authBlocksize );
	keyBlockPtr = keyBlock + sessionInfoPtr->authBlocksize;
	memcpy( sessionInfoPtr->sslMacReadSecret, keyBlockPtr,
			sessionInfoPtr->authBlocksize );
	keyBlockPtr += sessionInfoPtr->authBlocksize;
	setResourceData( &msgData, keyBlockPtr, keySize );
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	keyBlockPtr += keySize;
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, keyBlockPtr, keySize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEY );
		keyBlockPtr += keySize;
		}
	if( cryptStatusOK( status ) && ivSize )
		{
		setResourceData( &msgData, keyBlockPtr, ivSize );
		krnlSendMessage( sessionInfoPtr->iCryptOutContext, 
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_IV );
		keyBlockPtr += ivSize;
		setResourceData( &msgData, keyBlockPtr, ivSize );
		krnlSendMessage( sessionInfoPtr->iCryptInContext, 
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_IV );
		}
	zeroise( keyBlock, MAX_KEYBLOCK_SIZE );
	if( cryptStatusError( status ) )
		{
		zeroise( masterSecret, SSL_SECRET_SIZE );
		return( status );
		}

	/* Generate the inner portion of the handshake messages MAC:
		hash( handshake_messages || cl/svr_magic || master_secret || pad1 ) */
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, 
					 SSL_SENDER_CLIENTMAGIC, SSL_SENDERMAGIC_SIZE );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, 
					 SSL_SENDER_SERVERMAGIC, SSL_SENDERMAGIC_SIZE );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, 
					 SSL_SENDER_CLIENTMAGIC, SSL_SENDERMAGIC_SIZE );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, 
					 SSL_SENDER_SERVERMAGIC, SSL_SENDERMAGIC_SIZE );
	macData( handshakeInfo, handshakeInfo->masterSecret, SSL_SECRET_SIZE );
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 48 );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 40 );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 48 );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD1, 40 );
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	setResourceData( &msgData, clientMD5, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->clientMD5context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );
	setResourceData( &msgData, clientSHA1, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->clientSHA1context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );
	setResourceData( &msgData, serverMD5, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->serverMD5context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );
	setResourceData( &msgData, serverSHA1, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->serverSHA1context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );

	/* Reset the hash contexts */
	krnlSendMessage( handshakeInfo->clientMD5context, 
					 RESOURCE_IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->clientSHA1context, 
					 RESOURCE_IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->serverMD5context, 
					 RESOURCE_IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_HASHVALUE );
	krnlSendMessage( handshakeInfo->serverSHA1context, 
					 RESOURCE_IMESSAGE_DELETEATTRIBUTE, NULL, 
					 CRYPT_CTXINFO_HASHVALUE );

	/* Generate the outer portion of the handshake messages MAC:
		hash( master_secret || pad2 || inner_hash ) */
	macData( handshakeInfo, handshakeInfo->masterSecret, SSL_SECRET_SIZE );
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 48 );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 40 );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 48 );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, PROTOHMAC_PAD2, 40 );
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, clientMD5, MD5MAC_SIZE );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, clientSHA1, SHA1MAC_SIZE );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, serverMD5, MD5MAC_SIZE );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, serverSHA1, SHA1MAC_SIZE );
	krnlSendMessage( handshakeInfo->clientMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->clientSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->serverMD5context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );
	krnlSendMessage( handshakeInfo->serverSHA1context,
					 RESOURCE_IMESSAGE_CTX_HASH, "", 0 );

	/* Build the change cipher spec and finished packets:
		byte		ID = 0x14
		uint24		len
		byte[16]	MD5 MAC
		byte[20]	SHA-1 MAC */
	bufPtr = sessionInfoPtr->sendBuffer;
	*bufPtr++ = SSL_MSG_CHANGE_CIPHER_SPEC;
	*bufPtr++ = SSL_MAJOR_VERSION;
	*bufPtr++ = ( sessionInfoPtr->type == CRYPT_FORMAT_SSL ) ? \
				SSL_MINOR_VERSION : TLS_MINOR_VERSION;
	*bufPtr++ = 0;
	*bufPtr++ = 1;	/* Length */
	*bufPtr++ = 1;	/* Data */
	bufPtr = encryptDataPtr = bufPtr + SSL_HEADER_SIZE;
	memcpy( bufPtr, finishedTemplate, FINISHED_TEMPLATE_SIZE );
	bufPtr += FINISHED_TEMPLATE_SIZE;
	setResourceData( &msgData, bufPtr, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->serverMD5context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );
	setResourceData( &msgData, bufPtr + MD5MAC_SIZE, CRYPT_MAX_HASHSIZE );
	krnlSendMessage( handshakeInfo->serverSHA1context, 
					 RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
					 CRYPT_CTXINFO_HASHVALUE );
	length = encryptData( sessionInfoPtr, encryptDataPtr, 
						  FINISHED_TEMPLATE_SIZE + MD5MAC_SIZE + SHA1MAC_SIZE );
	if( cryptStatusError( length ) )
		return( length );
	wrapHandshakePacket( sessionInfoPtr->sendBuffer + SSL_HEADER_SIZE + 1, 
						 length, sessionInfoPtr->type );
	status = TcpSend( socket, sessionInfoPtr->sendBuffer, 
					  SSL_HEADER_SIZE + length, FALSE, HFILE_ERROR );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );

	/* Process the server change cipher spec */
	status = readPacket( sessionInfoPtr, handshakeInfo, socket, 
						 SSL_MSG_CHANGE_CIPHER_SPEC );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	if( *bufPtr++ != 1 )
		return( CRYPT_ERROR_BADDATA );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Prepare an SSL session */

static int initFunction( SESSION_INFO *sessionInfoPtr )
	{
	/* Set the default SSL server */
	sessionInfoPtr->serverPort = SSL_PORT;

	/* Set the default SSL buffer sizes */
	sessionInfoPtr->sendBufSize = \
		sessionInfoPtr->receiveBufSize = BUFFER_SIZE;

	return( CRYPT_OK );
	}

/* Close a previously-opened SSL session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	SOCKET socket = sessionInfoPtr->socket;

	if( sessionInfoPtr->socket != CRYPT_ERROR )
		TcpClose( &socket );
	sessionInfoPtr->socket = CRYPT_ERROR;
	}

/* Connect to an SSL server */

static int connectFunction( SESSION_INFO *sessionInfoPtr )
	{
	SSL_HANDSHAKE_INFO handshakeInfo;
	SOCKET socket;
	unsigned short port = sessionInfoPtr->serverPort;
	int status;

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE,
					 &sessionInfoPtr->timeout, 
					 CRYPT_OPTION_SESSION_TIMEOUT );

//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
sessionInfoPtr->type = CRYPT_FORMAT_TLS;
#if 0
{
MECHANISM_DERIVE_INFO mechanismInfo;
BYTE master[ SSL_SECRET_SIZE ], key[ 64 ];
BYTE nonceBuffer[ 32 + 32 ];
BYTE clientNonce[ 32 ] = {
	0x23, 0x68, 0xf3, 0x11, 0x72, 0x44, 0xa5, 0x8a,
	0xc4, 0x77, 0xf3, 0x22, 0x26, 0xa3, 0xa2, 0xba,
	0xb5, 0x38, 0x18, 0xa1, 0xca, 0x21, 0x45, 0xca,
	0x0a, 0x62, 0xf3, 0xa1, 0xff, 0x09, 0xa6, 0x2a
	};
BYTE serverNonce[ 32 ] = {
	0xaa, 0x33, 0x18, 0xa1, 0xca, 0x01, 0x45, 0x2a,
	0x0a, 0x6a, 0x83, 0xc1, 0xaf, 0x09, 0x96, 0x2a,
	0x23, 0x6c, 0x83, 0x16, 0x62, 0x44, 0x05, 0x8a,
	0xff, 0x77, 0x23, 0x44, 0x36, 0xa3, 0x02, 0x2a
	};
BYTE preMaster[ 48 ] = {
	0x01, 0x01, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
	0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55
	};
int status;

memcpy( nonceBuffer, clientNonce, 32 );
memcpy( nonceBuffer + 32, serverNonce, 32 );
setMechanismDeriveInfo( &mechanismInfo, master, 48, preMaster, 48, 
						nonceBuffer, 32 + 32, 1 );
status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
						  RESOURCE_IMESSAGE_DEV_DERIVE,
						  &mechanismInfo, MECHANISM_SSL );
memcpy( nonceBuffer, serverNonce, 32 );
memcpy( nonceBuffer + 32, clientNonce, 32 );
setMechanismDeriveInfo( &mechanismInfo, key, 64, master, 48,
						nonceBuffer, 32 + 32, 1 );
status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
						  RESOURCE_IMESSAGE_DEV_DERIVE,
						  &mechanismInfo, MECHANISM_SSL );
if( status );
}
#endif /* 0 */
#if 1
{
MECHANISM_DERIVE_INFO mechanismInfo;
BYTE master[ 104 ];
BYTE nonceBuffer[ 14 + 32 + 32 ];
BYTE clientNonce[ 32 ] = {
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD
	};
BYTE serverNonce[ 32 ] = {
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD,
	0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD, 0xCD
	};
BYTE preMaster[ 48 ] = {
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB,
	0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB, 0xAB
	};
int status;

memcpy( nonceBuffer, "PRF Testvector", 14 );
memcpy( nonceBuffer + 14, clientNonce, 32 );
memcpy( nonceBuffer + 14 + 32, serverNonce, 32 );
setMechanismDeriveInfo( &mechanismInfo, master, 104, preMaster, 48, 
						nonceBuffer, 14 + 32 + 32, 1 );
status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
						  RESOURCE_IMESSAGE_DEV_DERIVE,
						  &mechanismInfo, MECHANISM_TLS );
{
HASHFUNCTION hashFunction;
int hashSize;

getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
hashFunction( NULL, nonceBuffer, master, 104, HASH_ALL );
}
if( status );
}
#endif /* 0 */
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
#if 0
{
BYTE packet[] = {
										0x80, 0x3a, 0x01, 0x03, 0x00, 0x00, 0x21, 0x00, 0x00, 0x00,
	0x10, 0x01, 0x00, 0x80, 0x02, 0x00, 0x80, 0x03, 0x00, 0x80, 0x04, 0x00, 0x80, 0x06, 0x00, 0x40,
	0x07, 0x00, 0xc0, 0x00, 0x00, 0x04, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x09, 0x00, 0x00, 0x03, 0x00,
	0x00, 0x06, 0x0f, 0x4b, 0xf2, 0x78, 0xec, 0xdb, 0x84, 0x58, 0xdf, 0x58, 0x04, 0x3b, 0xc3, 0xb9,
	0xe8, 0x97
	};
memcpy( sessionInfoPtr->sendBuffer, packet, sizeof( packet ) );
length = sizeof( packet ) - SSL_HEADER_SIZE;
}
#endif /* 0 */
//!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!

	/* Connect to the remote server */
	status = TcpConnect( &socket, sessionInfoPtr->serverName, NULL, &port );
	if( status != TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );

	/* Initialise the handshake info and begin the handshake */
	status = initHandshakeInfo( &handshakeInfo );
	if( cryptStatusOK( status ) )
		status = beginHandshake( sessionInfoPtr, &handshakeInfo, socket );
	if( cryptStatusError( status ) )
		{
		destroyHandshakeInfo( &handshakeInfo );
		TcpClose( &socket );
		return( status );
		}

	/* Exchange a key with the server */
	status = exchangeKeys( sessionInfoPtr, &handshakeInfo, socket );
	if( cryptStatusError( status ) )
		{
		destroySecurityContexts( sessionInfoPtr );
		destroyHandshakeInfo( &handshakeInfo );
		TcpClose( &socket );
		return( status );
		}

	/* Complete the handshake */
	status = completeHandshake( sessionInfoPtr, &handshakeInfo, socket );
	destroyHandshakeInfo( &handshakeInfo );
	if( cryptStatusError( status ) )
		{
		destroySecurityContexts( sessionInfoPtr );
		TcpClose( &socket );
		return( status );
		}

	sessionInfoPtr->socket = socket;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Get data from an SSL server */

static int getDataFunction( SESSION_INFO *sessionInfoPtr, void *data,
							const int length )
	{
	UNUSED( sessionInfoPtr );
	UNUSED( data );

	return( 0 );
	}

/* Send data to an SSL server */

static int putDataFunction( SESSION_INFO *sessionInfoPtr, const void *data,
							const int length )
	{
	UNUSED( sessionInfoPtr );
	UNUSED( data );

	return( 0 );
	}

/****************************************************************************
*																			*
*						Control Information Management Functions			*
*																			*
****************************************************************************/

int setAccessMethodSSL( SESSION_INFO *sessionInfoPtr )
	{
#ifdef DYNAMIC_LOAD
	/* Make sure the TCP/IP interface has been initialised */
	if( hTCP == NULL_INSTANCE )
		return( CRYPT_ERROR_OPEN );
#endif /* DYNAMIC_LOAD */

	/* Set the access method pointers */
	sessionInfoPtr->initFunction = initFunction;
	sessionInfoPtr->shutdownFunction = shutdownFunction;
	sessionInfoPtr->connectFunction = connectFunction;
	sessionInfoPtr->getDataFunction = getDataFunction;
	sessionInfoPtr->putDataFunction = putDataFunction;

	return( CRYPT_OK );
	}
#endif /* NET_TCP */
