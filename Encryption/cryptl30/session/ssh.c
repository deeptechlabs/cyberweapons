/****************************************************************************
*																			*
*						cryptlib SSH v1 Session Management					*
*						Copyright Peter Gutmann 1998-2000					*
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

/* Default SSH port */

#define SSH_PORT				22

/* Various SSH constants */

#define ID_SIZE					1	/* ID byte */
#define LENGTH_SIZE				4	/* Size of packet length field */
#define CRC_SIZE				4	/* Size of CRC value */
#define MPI_LENGTH_SIZE			2	/* Size of MPI length field */
#define SSH_COOKIE_SIZE			8	/* Size of anti-spoofing cookie */
#define SSH_SESSIONID_SIZE		16	/* Size of session ID */
#define SSH_HEADER_SIZE			5	/* Size of the SSH packet header */
#define SSH_SECRET_SIZE			32	/* Size of SSH shared secret */

/* Default and maximum SSH send/receive buffer sizes */

#define BUFFER_SIZE				( 16384 + 64 )
#define MAX_BUFFER_SIZE			262144L

/* SSH major and minor version numbers */

#define SSH_MAJOR_VERSION		1
#define SSH_MINOR_VERSION		5

/* SSH ID information */

#define SSH_ID					"SSH-"	/* Start of SSH ID */
#define SSH_ID_SIZE				4	/* Size of SSH ID */
#define SSH_ID_MAX_SIZE			( 4 + 40 )	/* Max.size of SSH ID string */

/* SSH packet types */

#define SSH_MSG_DISCONNECT		1	/* Disconnect session */
#define SSH_SMSG_PUBLIC_KEY		2	/* Server public key */
#define SSH_CMSG_SESSION_KEY	3	/* Encrypted session key */
#define SSH_CMSG_USER			4	/* User name */
#define SSH_CMSG_AUTH_PASSWORD	9	/* Password */
#define SSH_CMSG_REQUEST_PTY	10	/* Request a pty */
#define SSH_CMSG_EXEC_SHELL		12	/* Request a shell */
#define SSH_SMSG_SUCCESS		14	/* Success status message */
#define SSH_SMSG_FAILURE		15	/* Failure status message */
#define SSH_CMSG_STDIN_DATA		16	/* Data from client stdin */
#define SSH_SMSG_STDOUT_DATA	17	/* Data from server stdout */
#define SSH_MSG_IGNORE			32	/* Noop */
#define SSH_MSG_DEBUG			36	/* Debugging/informational message */
#define SSH_CMSG_MAX_PACKET_SIZE 38	/* Maximum data packet size */

/* Special-case expected-packet-type values which are passed to readPacket()
   to handle situations where more than one return value is valid (CMSG_USER
   can return failure meaning "no password" even if there's no actual 
   failure */

#define SSH_MSG_SPECIAL_USEROPT		100	/* Value to handle user name */

/* SSH cipher types */

#define SSH_CIPHER_NONE			0	/* No encryption */
#define SSH_CIPHER_IDEA			1	/* IDEA/CFB */
#define SSH_CIPHER_DES			2	/* DES/CBC */
#define SSH_CIPHER_3DES			3	/* 3DES/inner-CBC */
#define SSH_CIPHER_TSS			4	/* Deprecated */
#define SSH_CIPHER_RC4			5	/* RC4 */
#define SSH_CIPHER_BLOWFISH		6	/* Blowfish */
#define SSH_CIPHER_CRIPPLED		7	/* Reserved, from ssh 1.2.x source */

/* SSH authentication types */

#define SSH_AUTH_RHOSTS			1	/* .rhosts or /etc/hosts.equiv */
#define SSH_AUTH_RSA			2	/* RSA challenge-response */
#define SSH_AUTH_PASSWORD		3	/* Password */
#define SSH_AUTH_RHOSTS_RSA		4	/* .rhosts with RSA challenge-response */
#define SSH_AUTH_TIS			5	/* TIS authsrv */
#define SSH_AUTH_KERBEROS		6	/* Kerberos */
#define SSH_PASS_KERBEROS_TGT	7	/* Kerberos TGT-passing */

/* Macros to evaluate the effective length for a packet and the number of 
   padding bytes to add to a packet to make it a multiple of 8 bytes long */

#define getEffectiveLength( length ) \
		( ID_SIZE + ( length ) + CRC_SIZE )
#define getPadLength( length ) \
		( 8 - ( getEffectiveLength( length ) & 7 ) )

/* SSH handshake state information.  This is passed around various 
   subfunctions which handle individual parts of the handshake */

typedef struct {
	/* Session state information */
	BYTE cookie[ SSH_COOKIE_SIZE ];			/* Anti-spoofing cookie */
	BYTE sessionID[ SSH_SESSIONID_SIZE ];	/* Session ID */

	/* The host and server key modulus, needed to compute the session ID */
	BYTE hostModulus[ CRYPT_MAX_PKCSIZE ], serverModulus[ CRYPT_MAX_PKCSIZE ];
	int hostModulusLength, serverModulusLength;

	/* Key information */
	BYTE sessionKey[ SSH_SECRET_SIZE ];		/* Shared secret value */

	/* Short-term server key */
	CRYPT_CONTEXT iServerCryptContext;
	} SSH_HANDSHAKE_INFO;

#ifdef NET_TCP

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

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

/* Calculate the CRC32 for a data block.  This uses the slightly nonstandard
   variant from SSH which calculates the UART-style reflected value and
   doesn't pre-set the value to all ones (done to to catch leading zero
   bytes, which happens quite a bit with SSH because of the 32-bit length at
   the start) or XOR it with all ones before returning it.  This means that
   the resulting CRC is not the same as the one in Ethernet, Pkzip, and most
   other implementations */

static const LONG crc32table[] = {
	0x00000000UL, 0x77073096UL, 0xEE0E612CUL, 0x990951BAUL,
	0x076DC419UL, 0x706AF48FUL, 0xE963A535UL, 0x9E6495A3UL,
	0x0EDB8832UL, 0x79DCB8A4UL, 0xE0D5E91EUL, 0x97D2D988UL,
	0x09B64C2BUL, 0x7EB17CBDUL, 0xE7B82D07UL, 0x90BF1D91UL,
	0x1DB71064UL, 0x6AB020F2UL, 0xF3B97148UL, 0x84BE41DEUL,
	0x1ADAD47DUL, 0x6DDDE4EBUL, 0xF4D4B551UL, 0x83D385C7UL,
	0x136C9856UL, 0x646BA8C0UL, 0xFD62F97AUL, 0x8A65C9ECUL,
	0x14015C4FUL, 0x63066CD9UL, 0xFA0F3D63UL, 0x8D080DF5UL,
	0x3B6E20C8UL, 0x4C69105EUL, 0xD56041E4UL, 0xA2677172UL,
	0x3C03E4D1UL, 0x4B04D447UL, 0xD20D85FDUL, 0xA50AB56BUL,
	0x35B5A8FAUL, 0x42B2986CUL, 0xDBBBC9D6UL, 0xACBCF940UL,
	0x32D86CE3UL, 0x45DF5C75UL, 0xDCD60DCFUL, 0xABD13D59UL,
	0x26D930ACUL, 0x51DE003AUL, 0xC8D75180UL, 0xBFD06116UL,
	0x21B4F4B5UL, 0x56B3C423UL, 0xCFBA9599UL, 0xB8BDA50FUL,
	0x2802B89EUL, 0x5F058808UL, 0xC60CD9B2UL, 0xB10BE924UL,
	0x2F6F7C87UL, 0x58684C11UL, 0xC1611DABUL, 0xB6662D3DUL,
	0x76DC4190UL, 0x01DB7106UL, 0x98D220BCUL, 0xEFD5102AUL,
	0x71B18589UL, 0x06B6B51FUL, 0x9FBFE4A5UL, 0xE8B8D433UL,
	0x7807C9A2UL, 0x0F00F934UL, 0x9609A88EUL, 0xE10E9818UL,
	0x7F6A0DBBUL, 0x086D3D2DUL, 0x91646C97UL, 0xE6635C01UL,
	0x6B6B51F4UL, 0x1C6C6162UL, 0x856530D8UL, 0xF262004EUL,
	0x6C0695EDUL, 0x1B01A57BUL, 0x8208F4C1UL, 0xF50FC457UL,
	0x65B0D9C6UL, 0x12B7E950UL, 0x8BBEB8EAUL, 0xFCB9887CUL,
	0x62DD1DDFUL, 0x15DA2D49UL, 0x8CD37CF3UL, 0xFBD44C65UL,
	0x4DB26158UL, 0x3AB551CEUL, 0xA3BC0074UL, 0xD4BB30E2UL,
	0x4ADFA541UL, 0x3DD895D7UL, 0xA4D1C46DUL, 0xD3D6F4FBUL,
	0x4369E96AUL, 0x346ED9FCUL, 0xAD678846UL, 0xDA60B8D0UL,
	0x44042D73UL, 0x33031DE5UL, 0xAA0A4C5FUL, 0xDD0D7CC9UL,
	0x5005713CUL, 0x270241AAUL, 0xBE0B1010UL, 0xC90C2086UL,
	0x5768B525UL, 0x206F85B3UL, 0xB966D409UL, 0xCE61E49FUL,
	0x5EDEF90EUL, 0x29D9C998UL, 0xB0D09822UL, 0xC7D7A8B4UL,
	0x59B33D17UL, 0x2EB40D81UL, 0xB7BD5C3BUL, 0xC0BA6CADUL,
	0xEDB88320UL, 0x9ABFB3B6UL, 0x03B6E20CUL, 0x74B1D29AUL,
	0xEAD54739UL, 0x9DD277AFUL, 0x04DB2615UL, 0x73DC1683UL,
	0xE3630B12UL, 0x94643B84UL, 0x0D6D6A3EUL, 0x7A6A5AA8UL,
	0xE40ECF0BUL, 0x9309FF9DUL, 0x0A00AE27UL, 0x7D079EB1UL,
	0xF00F9344UL, 0x8708A3D2UL, 0x1E01F268UL, 0x6906C2FEUL,
	0xF762575DUL, 0x806567CBUL, 0x196C3671UL, 0x6E6B06E7UL,
	0xFED41B76UL, 0x89D32BE0UL, 0x10DA7A5AUL, 0x67DD4ACCUL,
	0xF9B9DF6FUL, 0x8EBEEFF9UL, 0x17B7BE43UL, 0x60B08ED5UL,
	0xD6D6A3E8UL, 0xA1D1937EUL, 0x38D8C2C4UL, 0x4FDFF252UL,
	0xD1BB67F1UL, 0xA6BC5767UL, 0x3FB506DDUL, 0x48B2364BUL,
	0xD80D2BDAUL, 0xAF0A1B4CUL, 0x36034AF6UL, 0x41047A60UL,
	0xDF60EFC3UL, 0xA867DF55UL, 0x316E8EEFUL, 0x4669BE79UL,
	0xCB61B38CUL, 0xBC66831AUL, 0x256FD2A0UL, 0x5268E236UL,
	0xCC0C7795UL, 0xBB0B4703UL, 0x220216B9UL, 0x5505262FUL,
	0xC5BA3BBEUL, 0xB2BD0B28UL, 0x2BB45A92UL, 0x5CB36A04UL,
	0xC2D7FFA7UL, 0xB5D0CF31UL, 0x2CD99E8BUL, 0x5BDEAE1DUL,
	0x9B64C2B0UL, 0xEC63F226UL, 0x756AA39CUL, 0x026D930AUL,
	0x9C0906A9UL, 0xEB0E363FUL, 0x72076785UL, 0x05005713UL,
	0x95BF4A82UL, 0xE2B87A14UL, 0x7BB12BAEUL, 0x0CB61B38UL,
	0x92D28E9BUL, 0xE5D5BE0DUL, 0x7CDCEFB7UL, 0x0BDBDF21UL,
	0x86D3D2D4UL, 0xF1D4E242UL, 0x68DDB3F8UL, 0x1FDA836EUL,
	0x81BE16CDUL, 0xF6B9265BUL, 0x6FB077E1UL, 0x18B74777UL,
	0x88085AE6UL, 0xFF0F6A70UL, 0x66063BCAUL, 0x11010B5CUL,
	0x8F659EFFUL, 0xF862AE69UL, 0x616BFFD3UL, 0x166CCF45UL,
	0xA00AE278UL, 0xD70DD2EEUL, 0x4E048354UL, 0x3903B3C2UL,
	0xA7672661UL, 0xD06016F7UL, 0x4969474DUL, 0x3E6E77DBUL,
	0xAED16A4AUL, 0xD9D65ADCUL, 0x40DF0B66UL, 0x37D83BF0UL,
	0xA9BCAE53UL, 0xDEBB9EC5UL, 0x47B2CF7FUL, 0x30B5FFE9UL,
	0xBDBDF21CUL, 0xCABAC28AUL, 0x53B39330UL, 0x24B4A3A6UL,
	0xBAD03605UL, 0xCDD70693UL, 0x54DE5729UL, 0x23D967BFUL,
	0xB3667A2EUL, 0xC4614AB8UL, 0x5D681B02UL, 0x2A6F2B94UL,
	0xB40BBE37UL, 0xC30C8EA1UL, 0x5A05DF1BUL, 0x2D02EF8DUL
	};

static LONG calculateCRC( const BYTE *data, const int dataLength )
	{
	LONG crc32 = 0;
	int i;

	for( i = 0; i < dataLength; i++ )
		crc32 = crc32table[ ( int ) ( crc32 ^ data[ i ] ) & 0xFF ] ^ ( crc32 >> 8 );

	return( crc32 );
	}

/* Generate an SSH session ID */

static void generateSessionID( SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	HASHFUNCTION hashFunction;
	BYTE hashInfo[ MAX_HASHINFO_SIZE ];
	int hashSize;

	/* Get the hash algorithm information and hash the server key modulus, 
	   host key modulus, and cookie.  The SSH documentation and source code
	   are quite confusing on this issue, giving the key components to be 
	   hashed multiple names (server key, host key, session key, public key, 
	   etc etc).  The correct order is:
		hash( host modulus || server modulus || cookie ) */
	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
	hashFunction( hashInfo, NULL, handshakeInfo->hostModulus, 
				  handshakeInfo->hostModulusLength, HASH_START );
	hashFunction( hashInfo, NULL, handshakeInfo->serverModulus, 
				  handshakeInfo->serverModulusLength, HASH_CONTINUE );
	hashFunction( hashInfo, handshakeInfo->sessionID,
				  handshakeInfo->cookie, SSH_COOKIE_SIZE, HASH_END );
	}

/* Process the public key data.  The preceding key length value isn't useful 
   because it contains the nominal key size in bits rather than the size of 
   the following data, so we have to poke into the data to find out how much 
   there is.  In addition we need to take a copy of the key modulus since 
   it's needed later for calculating the session ID */

static int processPublickeyData( const void *data, 
								 SSH_HANDSHAKE_INFO *handshakeInfo, 
								 const BOOLEAN isServerKey )
	{
	BYTE *dataPtr = ( BYTE * ) data;
	int eLength, nLength;

	eLength = mgetBWord( dataPtr );
	dataPtr += bitsToBytes( eLength );
	nLength = mgetBWord( dataPtr );
	nLength = bitsToBytes( nLength );
	if( isServerKey )
		{
		memcpy( handshakeInfo->serverModulus, dataPtr, nLength );
		handshakeInfo->serverModulusLength = nLength;
		}
	else
		{
		memcpy( handshakeInfo->hostModulus, dataPtr, nLength );
		handshakeInfo->hostModulusLength = nLength;
		}
	
	return( MPI_LENGTH_SIZE + bitsToBytes( eLength ) + \
			MPI_LENGTH_SIZE + nLength );
	}

/* Convert an SSH algorithm ID to a cryptlib ID in preferred-algorithm order.
   We can't use 3DES since this uses inner-CBC which is both nonstandard and 
   has known (although not serious) weaknesses.  If we wanted to implement it 
   in a portable manner (ie usable with external drivers and devices) we'd 
   have to synthesize it using three lots of DES-CBC since nothing implements 
   the variant which SSH uses */

static CRYPT_ALGO convertAlgoID( const int value )
	{
	CRYPT_QUERY_INFO queryInfo;

	if( ( value & ( 1 << SSH_CIPHER_BLOWFISH ) ) && \
		cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_BLOWFISH ) ) )
		return( CRYPT_ALGO_BLOWFISH );
	if( ( value & ( 1 << SSH_CIPHER_IDEA ) ) && \
		cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_IDEA ) ) )
		return( CRYPT_ALGO_IDEA );
	if( ( value & ( 1 << SSH_CIPHER_RC4 ) ) && \
		cryptStatusOK( krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								&queryInfo, CRYPT_ALGO_RC4 ) ) )
		return( CRYPT_ALGO_RC4 );
	if( value & ( 1 << SSH_CIPHER_DES ) )
		return( CRYPT_ALGO_DES );

	return( CRYPT_ALGO_NONE );
	}

/* Initialise and destroy the handshake state information */

static void destroyHandshakeInfo( SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Destroy any active contexts */
	if( handshakeInfo->iServerCryptContext != CRYPT_ERROR )
		krnlSendNotifier( handshakeInfo->iServerCryptContext,
						  RESOURCE_IMESSAGE_DECREFCOUNT );

	zeroise( handshakeInfo, sizeof( SSH_HANDSHAKE_INFO ) );
	}

static int initHandshakeInfo( SSH_HANDSHAKE_INFO *handshakeInfo )
	{
	/* Initialise the handshake state info values */
	memset( handshakeInfo, 0, sizeof( SSH_HANDSHAKE_INFO ) );
	handshakeInfo->iServerCryptContext = CRYPT_ERROR;

	return( CRYPT_OK );
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

	setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptInContext = createInfo.cryptHandle;
		setMessageCreateObjectInfo( &createInfo, sessionInfoPtr->cryptAlgo );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		}
	if( cryptStatusOK( status ) )
		{
		sessionInfoPtr->iCryptOutContext = createInfo.cryptHandle;
		if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_RC4 || \
			sessionInfoPtr->cryptAlgo == CRYPT_ALGO_IDEA )
			{
			const int cryptMode = \
						( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_RC4 ) ? \
						CRYPT_MODE_OFB : CRYPT_MODE_CFB;

			status = krnlSendMessage( createInfo.cryptHandle,
								RESOURCE_IMESSAGE_SETATTRIBUTE,
								( void * ) &cryptMode, CRYPT_CTXINFO_MODE );
			if( cryptStatusOK( status ) )
				status = krnlSendMessage( createInfo.cryptHandle,
								RESOURCE_IMESSAGE_SETATTRIBUTE,
								( void * ) &cryptMode, CRYPT_CTXINFO_MODE );
			}
		}
	if( cryptStatusError( status ) )
		/* One or more of the contexts couldn't be created, destroy all the 
		   contexts which have been created so far */
		destroySecurityContexts( sessionInfoPtr );
	return( status );
	}

/* Read an SSH packet */

static int readPacket( SESSION_INFO *sessionInfoPtr, 
					   const SOCKET socket, const int expectedType )
	{
	long length;
	int padLength, packetType;

	/* Alongside the expected packets the server can send us all sorts of nop
	   messages, ranging from explicits nops (SSH_MSG_IGNORE) through to
	   general chattiness (SSH_MSG_DEBUG).  Because we can receive any
	   quantity of these at any time, we have to run the receive code in a 
	   loop to strip them out */
	do
		{
		BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
		LONG crc32, storedCrc32;
		int status;

		/* Read the SSH packet header:
			uint32		length
			byte[]		padding, 8 - ( length & 7 ) bytes
			byte		type
			byte[]		data
			uint32		crc32	- Calculated over padding, type, and data */
		status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
						  LENGTH_SIZE, sessionInfoPtr->timeout, 
						  HFILE_ERROR );
		if( status < TCP4U_SUCCESS )
			return( mapError( sessionInfoPtr, status ) );
		length = mgetBLong( bufPtr );
		if( length < SSH_HEADER_SIZE || \
			length > sessionInfoPtr->receiveBufSize - 8 )
			return( CRYPT_ERROR_BADDATA );
		padLength = 8 - ( length & 7 );
		status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
						  padLength + length, sessionInfoPtr->timeout, 
						  HFILE_ERROR );
		if( status < TCP4U_SUCCESS )
			return( mapError( sessionInfoPtr, status ) );
		if( sessionInfoPtr->iCryptInContext != CRYPT_ERROR )
			{
			/* Decrypt the payload with handling for SSH's Blowfish
			   endianness bug */
			if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
				longReverse( ( LONG * ) sessionInfoPtr->receiveBuffer,
							 padLength + length );
			status = krnlSendMessage( sessionInfoPtr->iCryptInContext,
									  RESOURCE_IMESSAGE_CTX_DECRYPT, 
									  sessionInfoPtr->receiveBuffer,
									  padLength + length );
			if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
				longReverse( ( LONG * ) sessionInfoPtr->receiveBuffer,
							 padLength + length );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Calculate the CRC-32 over the padding, type, and data and make 
		   sure it matches the transmitted value */
		length -= CRC_SIZE;	/* CRC isn't part of data payload */
		crc32 = calculateCRC( sessionInfoPtr->receiveBuffer, 
							  padLength + length );
		bufPtr = sessionInfoPtr->receiveBuffer + padLength + length;
		storedCrc32 = mgetBLong( bufPtr );
		if( crc32 != storedCrc32 )
			/* If we're expecting a success packet after a key exchange or an 
			   immediate post-key-exchange packet and don't get it then it's 
			   more likely that the problem is due to the wrong key being 
			   used than data corruption, so we return a wrong key error 
			   instead of bad data */
			return( ( expectedType == SSH_SMSG_SUCCESS ) ? 
					CRYPT_ERROR_WRONGKEY : CRYPT_ERROR_BADDATA );
		packetType = sessionInfoPtr->receiveBuffer[ padLength ];
		}
	while( packetType == SSH_MSG_IGNORE || packetType == SSH_MSG_DEBUG );

	/* Make sure we either got what we asked for or one of the allowed 
	   special-case packets */
	if( packetType == SSH_MSG_DISCONNECT )
		{
		BYTE *bufPtr = sessionInfoPtr->receiveBuffer + padLength + ID_SIZE;
		int length;

		/* Server is disconnecting, find out why */
		length = mgetBLong( bufPtr );
		if( length > MAX_ERRMSG_SIZE - 30 )
			return( CRYPT_ERROR_OVERFLOW );
		strcpy( sessionInfoPtr->errorMessage, 
				"Received SSH server message: " );
		memcpy( sessionInfoPtr->errorMessage + 29, bufPtr, length );
		sessionInfoPtr->errorMessage[ 29 + length ] = '\0';
		return( CRYPT_ERROR_FAILED );
		}
	if( expectedType == SSH_MSG_SPECIAL_USEROPT )
		{
		/* Sending an SSH_CMSG_USER can result in an SSH_SMSG_FAILURE if the 
		   user needs some form of authentiction to log on, so we have to 
		   filter this and convert it into a TRUE/FALSE value to let the 
		   caller know whether they have to send a password or not */
		if( packetType == SSH_SMSG_SUCCESS )
			return( FALSE );
		if( packetType == SSH_SMSG_FAILURE )
			return( TRUE );
		}
	if( packetType != expectedType )
		return( CRYPT_ERROR_BADDATA );

	/* Move the data down in the buffer to get rid of the padding */
	memmove( sessionInfoPtr->receiveBuffer, 
			 sessionInfoPtr->receiveBuffer + padLength + ID_SIZE, 
			 length - ID_SIZE );

	return( length - ID_SIZE );
	}

/* Send an SSH packet */

static int sendPacket( SESSION_INFO *sessionInfoPtr, 
					   const SOCKET socket, const int packetType,
					   const int dataLength )
	{
	BYTE *bufPtr = sessionInfoPtr->sendBuffer;
	LONG crc32;
	const int length = getEffectiveLength( dataLength );
	const int padLength = getPadLength( dataLength );
	int status;

	/* Add the SSH packet header:
		uint32		length
		byte[]		padding, 8 - ( length & 7 ) bytes
		byte		type
		byte[]		data
		uint32		crc32	- Calculated over padding, type, and data */
	mputBLong( bufPtr, ( long ) length );
	getNonce( bufPtr, padLength );
	bufPtr[ padLength ] = packetType;
	crc32 = calculateCRC( bufPtr, padLength + ID_SIZE + dataLength );
	bufPtr += padLength + ID_SIZE + dataLength;
	mputBLong( bufPtr, crc32 );
	if( sessionInfoPtr->iCryptOutContext != CRYPT_ERROR )
		{
		/* Encrypt the payload with handling for SSH's Blowfish
		   endianness bug */
		if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
			longReverse( ( LONG * ) ( sessionInfoPtr->sendBuffer + LENGTH_SIZE ),
						 padLength + length );
		status = krnlSendMessage( sessionInfoPtr->iCryptOutContext,
								  RESOURCE_IMESSAGE_CTX_ENCRYPT, 
								  sessionInfoPtr->sendBuffer + LENGTH_SIZE,
								  padLength + length );
		if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
			longReverse( ( LONG * ) ( sessionInfoPtr->sendBuffer + LENGTH_SIZE ),
						 padLength + length );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = TcpSend( socket, sessionInfoPtr->sendBuffer, 
					  LENGTH_SIZE + padLength + length, FALSE, HFILE_ERROR );
	if( status != TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );

	return( CRYPT_OK );
	}

/* Perform the initial part of the handshake with the server */

static int beginHandshake( SESSION_INFO *sessionInfoPtr, 
						   SSH_HANDSHAKE_INFO *handshakeInfo,
						   const SOCKET socket )
	{
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	BYTE *bufPtr;
	int length, value, i, status;

	/* Read the server version info.  This is rather ugly since it's a
	   variable-length string terminated with a newline, so we have to 
	   process it a character at a time after the initial fixed data */
	status = TcpRecv( socket, sessionInfoPtr->receiveBuffer, 
					  SSH_ID_SIZE, sessionInfoPtr->timeout, 
					  HFILE_ERROR );
	if( status < TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );
	if( memcmp( sessionInfoPtr->receiveBuffer, SSH_ID, SSH_ID_SIZE ) )
		return( CRYPT_ERROR_BADDATA );
	for( i = 0; i < SSH_ID_MAX_SIZE - SSH_ID_SIZE; i++ )
		{
		status = TcpRecv( socket, sessionInfoPtr->receiveBuffer + i, 
						  1, sessionInfoPtr->timeout, HFILE_ERROR );
		if( status < TCP4U_SUCCESS )
			return( mapError( sessionInfoPtr, status ) );
		if( sessionInfoPtr->receiveBuffer[ i ] == '\n' )
			break;
		}
	if( i == SSH_ID_MAX_SIZE - SSH_ID_SIZE )
		return( CRYPT_ERROR_BADDATA );

	/* Send back our own version info.  We use the lowest common denominator 
	   of our version (1.5, described in the only existing spec for SSH v1)
	   and whatever the server can handle */
	strcpy( sessionInfoPtr->sendBuffer, "SSH-1.5-cryptlib\n" );
	if( sessionInfoPtr->receiveBuffer[ 0 ] == '1' && \
		sessionInfoPtr->receiveBuffer[ 2 ] < SSH_MINOR_VERSION )
		sessionInfoPtr->sendBuffer[ 6 ] = sessionInfoPtr->receiveBuffer[ 2 ];
	status = TcpSend( socket, sessionInfoPtr->sendBuffer, 
					  strlen( sessionInfoPtr->sendBuffer ), FALSE, 
					  HFILE_ERROR );
	if( status != TCP4U_SUCCESS )
		return( mapError( sessionInfoPtr, status ) );

	/* Create the contexts to hold the server and host keys */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	handshakeInfo->iServerCryptContext = createInfo.cryptHandle;
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_RSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	sessionInfoPtr->iKeyexCryptContext = createInfo.cryptHandle;

	/* Process the server public key packet:
		byte[8]		cookie
		uint32		keysize_bits		- Usually 768 bits
		mpint		serverkey_exponent
		mpint		serverkey_modulus
		uint32		keysize_bits		- Usually 1024 bits
		mpint		hostkey_exponent
		mpint		hostkey_modulus
		uint32		protocol_flags		- Not used
		uint32		offered_ciphers
		uint32		offered_authent */
	length = readPacket( sessionInfoPtr, socket, SSH_SMSG_PUBLIC_KEY );
	if( cryptStatusError( length ) )
		return( length );
	bufPtr = sessionInfoPtr->receiveBuffer;
	memcpy( handshakeInfo->cookie, bufPtr, SSH_COOKIE_SIZE );
	bufPtr += SSH_COOKIE_SIZE;
	length = ( int ) mgetBLong( bufPtr );
	if( length < 512 || length > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_ERROR_BADDATA );
	length = processPublickeyData( bufPtr, handshakeInfo, TRUE );
	setResourceData( &msgData, bufPtr, length );
	status = krnlSendMessage( handshakeInfo->iServerCryptContext, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_SSH_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += length;
	length = ( int ) mgetBLong( bufPtr );
	if( length < 512 || length > bytesToBits( CRYPT_MAX_PKCSIZE ) )
		return( CRYPT_ERROR_BADDATA );
	length = processPublickeyData( bufPtr, handshakeInfo, FALSE );
	setResourceData( &msgData, bufPtr, length );
	status = krnlSendMessage( sessionInfoPtr->iKeyexCryptContext, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_SSH_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr += length + 4;					/* Skip protocol flags */
	value = ( int ) mgetBLong( bufPtr );	/* Offered ciphers */
	sessionInfoPtr->cryptAlgo = convertAlgoID( value );
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_NONE )
		return( CRYPT_ERROR_NOTAVAIL );
	value = ( int ) mgetBLong( bufPtr );	/* Offered authentication */
	if( !( value & ( 1 << SSH_AUTH_PASSWORD ) ) )
		return( CRYPT_ERROR_NOTAVAIL );

	return( CRYPT_OK );
	}

/* Exchange keys with the server */

static int exchangeKeys( SESSION_INFO *sessionInfoPtr, 
						 SSH_HANDSHAKE_INFO *handshakeInfo, 
						 const SOCKET socket )
	{
	MECHANISM_WRAP_INFO mechanismInfo;
	RESOURCE_DATA msgData;
	BYTE buffer[ CRYPT_MAX_PKCSIZE ];
	BYTE *bufPtr = sessionInfoPtr->sendBuffer;
	int length, dataLength, value, i, status;

	/* Output start of the session key packet:
		byte		cipher_type
		byte[8]		cookie
		mpint		double_enc_sessionkey
		uint32		protocol_flags */
	switch( sessionInfoPtr->cryptAlgo )
		{
		case CRYPT_ALGO_BLOWFISH:
			value = SSH_CIPHER_BLOWFISH;
			break;
		case CRYPT_ALGO_DES:
			value = SSH_CIPHER_DES;
			break;
		case CRYPT_ALGO_IDEA:
			value = SSH_CIPHER_IDEA;
			break;
		case CRYPT_ALGO_RC4:
			value = SSH_CIPHER_RC4;
			break;
		default:
			assert( NOTREACHED );
		}
	*bufPtr++ = value;
	memcpy( bufPtr, handshakeInfo->cookie, SSH_COOKIE_SIZE );
	bufPtr += SSH_COOKIE_SIZE;

	/* Generate the session ID and secure state information, and XOR the 
	   secure state with the session ID */
	generateSessionID( handshakeInfo );
	setResourceData( &msgData, handshakeInfo->sessionKey, SSH_SECRET_SIZE );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_RANDOM );
	if( cryptStatusError( status ) )
		return( status );
	for( i = 0; i < SSH_SESSIONID_SIZE; i++ )
		handshakeInfo->sessionKey[ i ] ^= handshakeInfo->sessionID[ i ];

	/* Export the secure state information in double-encrypted form, first
	   with the server key, then with the host key */
	setMechanismWrapInfo( &mechanismInfo, buffer, CRYPT_MAX_PKCSIZE, 
						  handshakeInfo->sessionKey, SSH_SECRET_SIZE, 
						  CRYPT_UNUSED, handshakeInfo->iServerCryptContext, 
						  CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo,
							  MECHANISM_PKCS1 );
	if( cryptStatusError( status ) )
		return( status );
	length = mechanismInfo.wrappedDataLength;
	setMechanismWrapInfo( &mechanismInfo, 
						  bufPtr + MPI_LENGTH_SIZE, CRYPT_MAX_PKCSIZE, 
						  buffer, length, CRYPT_UNUSED, 
						  sessionInfoPtr->iKeyexCryptContext, CRYPT_UNUSED );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE,
							  RESOURCE_IMESSAGE_DEV_EXPORT, &mechanismInfo,
							  MECHANISM_PKCS1 );
	if( cryptStatusError( status ) )
		return( status );
	length = bytesToBits( mechanismInfo.wrappedDataLength );
	mputBWord( bufPtr, length );
	bufPtr += mechanismInfo.wrappedDataLength;

	/* XOR the state with the session ID to recover the actual state */
	for( i = 0; i < SSH_SESSIONID_SIZE; i++ )
		handshakeInfo->sessionKey[ i ] ^= handshakeInfo->sessionID[ i ];

	/* Write the various flags */
	mputBLong( bufPtr, 0 );		/* Protocol flags */

	/* Move the data up in the buffer to allow for the variable-length
	   padding */
	dataLength = bufPtr - sessionInfoPtr->sendBuffer;
	memmove( sessionInfoPtr->sendBuffer + LENGTH_SIZE + \
			 getPadLength( dataLength ) + ID_SIZE,
			 sessionInfoPtr->sendBuffer, dataLength );
	return( sendPacket( sessionInfoPtr, socket, SSH_CMSG_SESSION_KEY,
						dataLength ) );
	}

/* Complete the handshake with the server */

static int completeHandshake( SESSION_INFO *sessionInfoPtr, 
							  SSH_HANDSHAKE_INFO *handshakeInfo, 
							  const SOCKET socket )
	{
	RESOURCE_DATA msgData;
	BYTE *bufPtr;
	int keySize, ivSize, padLength, length, status;

	/* Create the security contexts required for the session */
	status = initSecurityContexts( sessionInfoPtr );
	if( cryptStatusError( status ) )
		return( status );
	if( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_BLOWFISH )
		/* For Blowfish the session key size doesn't match the default 
		   Blowfish key size so we explicitly specify its length */
		keySize = SSH_SECRET_SIZE;
	else
		krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 RESOURCE_IMESSAGE_GETATTRIBUTE, &keySize,
						 CRYPT_CTXINFO_KEYSIZE );
	if( krnlSendMessage( sessionInfoPtr->iCryptInContext,
						 RESOURCE_IMESSAGE_GETATTRIBUTE, &ivSize,
						 CRYPT_CTXINFO_IVSIZE ) == CRYPT_ERROR_NOTAVAIL )
		/* It's a stream cipher */
		ivSize = 0;

	/* Load the keys.  For RC4, which is IV-less, the session key is split 
	   into two parts, with the first part being the receive key and the 
	   second part being the send key.  For other algorithms, the entire
	   session key is used for both send and receive contexts */
	setResourceData( &msgData, ( sessionInfoPtr->cryptAlgo == CRYPT_ALGO_RC4 ) ? \
					 handshakeInfo->sessionKey + 16 : handshakeInfo->sessionKey,
					 keySize );
	status = krnlSendMessage( sessionInfoPtr->iCryptOutContext, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, handshakeInfo->sessionKey, keySize );
		status = krnlSendMessage( sessionInfoPtr->iCryptInContext, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_CTXINFO_KEY );
		}
	if( cryptStatusOK( status ) && ivSize )
		{
		static const char iv[ CRYPT_MAX_IVSIZE ] = { 0 };

		setResourceData( &msgData, ( void * ) iv, ivSize );
		krnlSendMessage( sessionInfoPtr->iCryptOutContext, 
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_IV );
		setResourceData( &msgData, ( void * ) iv, ivSize );
		krnlSendMessage( sessionInfoPtr->iCryptInContext, 
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
						 &msgData, CRYPT_CTXINFO_IV );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Read back the server ack and send the user name:
		string		username */
	status = readPacket( sessionInfoPtr, socket, SSH_SMSG_SUCCESS );
	if( cryptStatusError( status ) )
		return( status );
	padLength = getPadLength( LENGTH_SIZE + sessionInfoPtr->sshUserNameLength );
	bufPtr = sessionInfoPtr->sendBuffer + LENGTH_SIZE + padLength + ID_SIZE;
	mputBLong( bufPtr,  sessionInfoPtr->sshUserNameLength );
	memcpy( bufPtr, sessionInfoPtr->sshUserName, 
			sessionInfoPtr->sshUserNameLength );
	status = sendPacket( sessionInfoPtr, socket, SSH_CMSG_USER,
						 LENGTH_SIZE + sessionInfoPtr->sshUserNameLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Read back the server ack and send the password if required:
		string		password
	   The password is optional, if the server returns a failure packet 
	   (converted to a TRUE return status) it means a password is required,
	   otherwise it isn't and we're already logged in */
	status = readPacket( sessionInfoPtr, socket, SSH_MSG_SPECIAL_USEROPT );
	if( status == TRUE )
		{
		padLength = getPadLength( LENGTH_SIZE + sessionInfoPtr->sshPasswordLength );
		bufPtr = sessionInfoPtr->sendBuffer + LENGTH_SIZE + padLength + ID_SIZE;
		mputBLong( bufPtr,  sessionInfoPtr->sshPasswordLength );
		memcpy( bufPtr, sessionInfoPtr->sshPassword, 
				sessionInfoPtr->sshPasswordLength );
		status = sendPacket( sessionInfoPtr, socket, SSH_CMSG_AUTH_PASSWORD,
							 LENGTH_SIZE + sessionInfoPtr->sshPasswordLength );
		if( cryptStatusOK( status ) )
			status = readPacket( sessionInfoPtr, socket, SSH_SMSG_SUCCESS );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Tell the server to adjust its maximum packet size if required:
		uint32		packet size
	   We mask off the low bits of the length because the buffer is slightly 
	   larger than required to provide a little slop space */
	if( sessionInfoPtr->sendBufSize < MAX_BUFFER_SIZE )
		{
		const int maxLength = sessionInfoPtr->sendBufSize & ~0xFFF;

		padLength = getPadLength( LENGTH_SIZE );
		bufPtr = sessionInfoPtr->sendBuffer + LENGTH_SIZE + padLength + ID_SIZE; 
		mputBLong( bufPtr, maxLength );
		status = sendPacket( sessionInfoPtr, socket, SSH_CMSG_MAX_PACKET_SIZE,
							 LENGTH_SIZE );
		if( cryptStatusOK( status ) )
			status = readPacket( sessionInfoPtr, socket, SSH_SMSG_SUCCESS );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Request a pty from the server:
		string		TERM environment variable
		uint32		rows
		uint32		cols
		uint32		pixel width
		uint32		pixel height 
		byte		tty mode info */
	padLength = getPadLength( ( LENGTH_SIZE + 5 ) + ( LENGTH_SIZE * 4 ) + 1 );
	bufPtr = sessionInfoPtr->sendBuffer + LENGTH_SIZE + padLength + ID_SIZE; 
	mputBLong( bufPtr, 5 );
	memcpy( bufPtr, "vt100", 5 );	/* Generic terminal type */
	bufPtr += 5;
	mputBLong( bufPtr, 24 );
	mputBLong( bufPtr, 80 );		/* 24 x 80 */
	mputBLong( bufPtr, 0 );
	mputBLong( bufPtr, 0 );			/* No graphics capabilities */
	*bufPtr = 0;					/* No special TTY modes */
	status = sendPacket( sessionInfoPtr, socket, SSH_CMSG_REQUEST_PTY,
						 ( LENGTH_SIZE + 5 ) + ( LENGTH_SIZE * 4 ) + 1 );
	if( cryptStatusOK( status ) )
		status = readPacket( sessionInfoPtr, socket, SSH_SMSG_SUCCESS );
	if( cryptStatusError( status ) )
		return( status );

	/* Tell the server to create a shell for us and read back the resulting
	   message:
		string		data */
	status = sendPacket( sessionInfoPtr, socket, SSH_CMSG_EXEC_SHELL, 0 );
	if( cryptStatusOK( status ) )
		status = readPacket( sessionInfoPtr, socket, SSH_SMSG_STDOUT_DATA );
	if( cryptStatusError( status ) )
		return( status );
	bufPtr = sessionInfoPtr->receiveBuffer;
	length = ( int ) mgetBLong( bufPtr );
	if( length <= 0 || length > sessionInfoPtr->receiveBufSize )
		return( CRYPT_ERROR_BADDATA );
	memmove( sessionInfoPtr->receiveBuffer, 
			 sessionInfoPtr->receiveBuffer + LENGTH_SIZE, length );
	sessionInfoPtr->receiveBufEnd = length;

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Init/Shutdown Functions						*
*																			*
****************************************************************************/

/* Prepare an SSH session */

static int initFunction( SESSION_INFO *sessionInfoPtr )
	{
	/* Set the default SSH server */
	sessionInfoPtr->serverPort = SSH_PORT;

	/* Set the default SSH buffer sizes */
	sessionInfoPtr->sendBufSize = BUFFER_SIZE;
	sessionInfoPtr->receiveBufSize = BUFFER_SIZE;

	return( CRYPT_OK );
	}

/* Close a previously-opened SSH session */

static void shutdownFunction( SESSION_INFO *sessionInfoPtr )
	{
	SOCKET socket = sessionInfoPtr->socket;

	if( sessionInfoPtr->socket != CRYPT_ERROR )
		TcpClose( &socket );
	sessionInfoPtr->socket = CRYPT_ERROR;
	}

/* Connect to an SSH server */

static int connectFunction( SESSION_INFO *sessionInfoPtr )
	{
	SSH_HANDSHAKE_INFO handshakeInfo;
	SOCKET socket;
	const BYTE *bufPtr = sessionInfoPtr->receiveBuffer;
	unsigned short port = sessionInfoPtr->serverPort;
	int status;

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE,
					 &sessionInfoPtr->timeout, 
					 CRYPT_OPTION_SESSION_TIMEOUT );

	/* Make sure we have all the required resources */
	if( sessionInfoPtr->sshUserNameLength == 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_USERNAME, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}
	if( sessionInfoPtr->sshPasswordLength == 0 )
		{
		setErrorInfo( sessionInfoPtr, CRYPT_SESSINFO_PASSWORD, 
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}

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

	/* We're done, remember the state info */
	sessionInfoPtr->socket = socket;

	return( status );
	}

/****************************************************************************
*																			*
*								Get/Put Data Functions						*
*																			*
****************************************************************************/

/* Get data from an SSH server */

static int getDataFunction( SESSION_INFO *sessionInfoPtr, void *data,
							const int length )
	{
	int bytesToCopy = length, remainder;

	/* Adjust the data to copy length by the amount we have available */
	if( bytesToCopy > sessionInfoPtr->receiveBufEnd )
		bytesToCopy = sessionInfoPtr->receiveBufEnd;

	/* Copy the data across and move any remaining data down to the start of 
	   the receive buffer */
	memcpy( data, sessionInfoPtr->receiveBuffer, bytesToCopy );
	remainder = sessionInfoPtr->receiveBufEnd - bytesToCopy;
	if( remainder )
		memmove( sessionInfoPtr->receiveBuffer, 
				 sessionInfoPtr->receiveBuffer + bytesToCopy, remainder );
	sessionInfoPtr->receiveBufEnd = remainder;
	
	return( bytesToCopy );
	}

/* Send data to an SSH server */

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

int setAccessMethodSSH( SESSION_INFO *sessionInfoPtr )
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
