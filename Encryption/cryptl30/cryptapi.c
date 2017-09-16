/****************************************************************************
*																			*
*						 cryptlib External API Interface					*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "crypt.h"

/* The command types */

typedef enum {
	COMMAND_NONE,				/* No command type */
	COMMAND_SERVERQUERY,		/* Get info on server */
	COMMAND_RESULT,				/* Result from server */
	COMMAND_CREATEOBJECT,		/* Create an object */
	COMMAND_CREATEOBJECT_INDIRECT,	/* Create an object indirectly */
	COMMAND_EXPORTOBJECT,		/* Export object in encoded form */
	COMMAND_DESTROYOBJECT,		/* Destroy an object */
	COMMAND_QUERYCAPABILITY,	/* Query capabilities */
	COMMAND_GENKEY,				/* Generate key */
	COMMAND_ENCRYPT,			/* Encrypt/sign/hash */ 
	COMMAND_DECRYPT,			/* Decrypt/sig check/hash */
	COMMAND_GETATTRIBUTE,		/* Get/set/delete attribute */
	COMMAND_SETATTRIBUTE,
	COMMAND_DELETEATTRIBUTE,
	COMMAND_GETKEY,				/* Get/set/delete key */
	COMMAND_SETKEY,
	COMMAND_DELETEKEY,
	COMMAND_PUSHDATA,
	COMMAND_POPDATA,			/* Push/pop data */
	COMMAND_CERTSIGN,			/* Sign certificate */
	COMMAND_CERTCHECK,			/* Check signature on certificate */
	COMMAND_ASYNCOP,			/* Async keygen op */
	COMMAND_LAST				/* Last command type */
	} COMMAND_TYPE;

/* The maximum number of integer and string args */

#define MAX_ARGS				4
#define MAX_STRING_ARGS			2

/* The possible command flags */

#define COMMAND_FLAG_NONE		0x00	/* No command flag */
#define COMMAND_FLAG_LENGTHONLY	0x01	/* Return only length of string arg */

/* If we're running in separate address spaces we need to have some sort of 
   client/server mechanism to communicate with processes running in the other
   address space.  Each message when encoded looks as follows:

	type			: 8
	flags			: 8
	noArgs			: 8
	noStringArgs	: 8
	length			: 32
	arg * 0..n		: 32 * n
	stringArg * 0..n: 32 + data * n

   The fixed header consists of a 32-bit type+format information value and
   length (to allow the entire message to be read using only two read calls) 
   followed by a 1 - MAX_ARGS integer args and 0 - MAX_STRING_ARGS variable-
   length data args.  The protocol is completely stateless, the client sends 
   COMMAND_xxx requests to the server and the server responds with 
   COMMAND_RESULT messages.  Typically the first command is 
   COMMAND_SERVERQUERY to determine server parameters.  The command formats 
   are as follows (arguments in square brackets are implied arguments whose
   values are supplied at the C function level but which aren't passed over
   the wire, this is used to handle reads of string values):

	COMMAND_SERVERQUERY
		<none>						word: status
									word: protocol version
									word: max.fragment size
	COMMAND_CREATEOBJECT
		word: handle				word: status
		word: object type			word: new handle
		word(s) | str(s): params
	COMMAND_CREATEOBJECT_INDIRECT
		word: handle				word: status
		word: object type			word: new handle
		str : encoded object data
	COMMAND_EXPORTOBJECT
		word: handle				word: status
		word(s): params				word: str_length | str: data
	COMMAND_DESTROYOBJECT
		word: handle				word: status
	COMMAND_QUERYCAPABILITY
		word: handle				word: status
		word: algo					word: str_length | str : data
		word: mode
		[str: return buffer]
	COMMAND_GENKEY
		word: handle				word: status
		word: keysize
		word: is_async (optional)
	COMMAND_ENCRYPT
		word: handle				word: status
		str : data					str : data
	COMMAND_DECRYPT
		word: handle				word: status
		str : data					str : data
	COMMAND_GETATTRIBUTE
		word: handle				word: status
		word: attribute type		word: value | word: str_length | str: data
		word: get_str_data (optional)
		[str: return buffer for str_data]
	COMMAND_SETATTRIBUTE
		word: handle				word: status
		word: attribute type
		word: value | str : value
	COMMAND_DELETEATTRIBUTE
		word: handle				word: status
		word: attribute type
	COMMAND_GETKEY
		word: handle				word: status
		word: key ID type			word: handle
		str : key ID (optional)
		str : password (optional)
	COMMAND_SETKEY
		word: handle				word: status
		word: key handle
		str : password (optional)
	COMMAND_DELETEKEY
		word: handle				word: status
		word: key ID type
		str : key ID
	COMMAND_PUSHDATA
		word: handle				word: status
		str : data					word: length
	COMMAND_POPDATA
		word: handle				word: status
		word: length				str : data
		[str: return buffer]
	COMMAND_CERTSIGN
		word: handle				word: status
		word: sig.key handle
	COMMAND_CERTCHECK
		word: handle				word: status
		word: check key handle
	COMMAND_ASYNCOP
		word: handle				word: status
		word: get status/cancel op */

/* The maximum size of a message fragment.  Messages containing more data
   than this are broken up into fragments */

#define MAX_FRAGMENT_SIZE		16384

/* The size of the I/O buffer used to assemble messages.  This is equal to
   the maximum fragment size plus the maximum header size for commands which
   require fragmentation (COMMAND_ENCRYPT/COMMAND_DECRYPT and 
   COMMAND_PUSHDATA/COMMAND_POPDATA) */

#define IO_BUFSIZE				MAX_FRAGMENT_SIZE + 32

/* The size of an integer as encoded in a message and the size of the fixed-
   length fields */

#define COMMAND_WORDSIZE		4
#define COMMAND_FIXED_DATA_SIZE	( COMMAND_WORDSIZE * 2 )

/* Macros to encode/decode a message type value */

#define putMessageType( buffer, type, flags, noInt, noString ) \
		{ \
		buffer[ 0 ] = ( BYTE ) ( type & 0xFF ); \
		buffer[ 1 ] = ( BYTE ) ( flags & 0xFF ); \
		buffer[ 2 ] = noInt; \
		buffer[ 3 ] = noString; \
		}
#define getMessageType( buffer, type, flags, noInt, noString ) \
		type = buffer[ 0 ]; flags = buffer[ 1 ]; \
		noInt = buffer[ 2 ]; noString = buffer[ 3 ]

/* Macros to encode/decode an integer value and a length */

#define putMessageWord( buffer, word ) \
		{ \
		( buffer )[ 0 ] = ( BYTE ) ( ( ( word ) >> 24 ) & 0xFF ); \
		( buffer )[ 1 ] = ( BYTE ) ( ( ( word ) >> 16 ) & 0xFF ); \
		( buffer )[ 2 ] = ( BYTE ) ( ( ( word ) >> 8 ) & 0xFF ); \
		( buffer )[ 3 ] = ( BYTE ) ( ( word ) & 0xFF ); \
		}
#define getMessageWord( buffer ) \
		( ( ( ( long ) ( buffer )[ 0 ] ) << 24 ) | \
		  ( ( ( long ) ( buffer )[ 1 ] ) << 16 ) | \
		  ( ( ( long ) ( buffer )[ 2 ] ) << 8 ) | \
			  ( long ) ( buffer )[ 3 ] )

#define getMessageLength	getMessageWord
#define putMessageLength	putMessageWord

/* Check whether a decoded command header contains valid data */

#define checkCommandInfo( cmd, length ) \
		( ( cmd )->type > COMMAND_NONE && \
		  ( cmd )->type < COMMAND_LAST && \
		  ( ( cmd )->flags == COMMAND_FLAG_NONE || \
		    ( cmd )->flags == COMMAND_FLAG_LENGTHONLY ) && \
		  ( cmd )->noArgs >= 1 && ( cmd )->noArgs <= MAX_ARGS && \
		  ( cmd )->noStrArgs >= 0 && ( cmd )->noStrArgs <= MAX_STRING_ARGS && \
		  ( cmd )->strArgLen[ 0 ] >= 0 && \
		  ( cmd )->strArgLen[ 1 ] >= 0 && \
		  ( length ) >= 0 && ( length ) <= IO_BUFSIZE )

/* A structure to contain the command elements */

typedef struct {
	COMMAND_TYPE type;					/* Command type */
	int flags;							/* Command flags */
	int noArgs, noStrArgs;				/* Number of int, string args */
	int arg[ MAX_ARGS ];				/* Integer arguments */
	void *strArg[ MAX_STRING_ARGS ];	/* String args */
	int strArgLen[ MAX_STRING_ARGS ];
	} COMMAND_INFO;

/* Handlers for the various commands */

static int cmdAsyncOp( COMMAND_INFO *cmd )
	{
	int dummy, status;

	assert( cmd->type == COMMAND_ASYNCOP );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2); 
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ERROR_PARAM1 );

	/* This command is a kitchen-sink operation used to manage async ops.on
	   contexts.  If the arg is zero, it gets the objects status, otherwise
	   it cancels an async operation.  
	   
	   First, since we're about to access an internal attribute (which can 
	   only be done through an internal message), we have to explicitly make 
	   sure the object is externally visible.  We do this by reading its 
	   algorithm type, which is a context-only attribute which ensures that
	   what'll be reported is the status of whatever it is which could be
	   busy rather than the status of an associated object (eg an envelope,
	   which is never busy, in any case we can't use a universal object
	   attribute like a property because these are handled by the kernel and
	   aren't affected by the object state).
	   
	   Since the context attribute read returns an error value if the object 
	   is in a non-normal state, we allow some error types through */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
							  &dummy, CRYPT_CTXINFO_ALGO );
	if( status != CRYPT_OK && status != CRYPT_ERROR_BUSY )
		return( status );

	/* If we're after the object status or it's in the normal status (ie 
	   there's nothing to do), return now */
	if( !cmd->arg[ 1 ] || status == CRYPT_OK )
		return( status );

	/* If the object is busy, reset its status to non-busy.  If the object is 
	   still busy when the message is received, the abort flag will be set, 
	   otherwise the message won't have any effect */
	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_IMESSAGE_SETATTRIBUTE,
							 MESSAGE_VALUE_OK, CRYPT_IATTRIBUTE_STATUS ) );
	}

static int cmdCreateObject( COMMAND_INFO *cmd )
	{
	CREATEOBJECT_INFO createInfo;
	BOOLEAN bindToOwner = FALSE, hasStrArg = FALSE;
	int owner, status;

	assert( cmd->type == COMMAND_CREATEOBJECT );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs >= 3 && cmd->noArgs <= 4 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) && \
		cmd->arg[ 0 ] != SYSTEM_OBJECT_HANDLE )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= OBJECT_TYPE_NONE || \
		cmd->arg[ 1 ] >= OBJECT_TYPE_LAST )
		return( CRYPT_ERROR_FAILED );	/* Internal error */
	switch( cmd->arg[ 1 ] )
		{
		case OBJECT_TYPE_CONTEXT:
			assert( cmd->noArgs == 3 );
			assert( cmd->noStrArgs == 0 );
			if( ( cmd->arg[ 2 ] <= CRYPT_ALGO_NONE || \
				  cmd->arg[ 2 ] >= CRYPT_ALGO_LAST ) && \
				cmd->arg[ 2 ] != CRYPT_USE_DEFAULT )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case OBJECT_TYPE_CERTIFICATE:
			assert( cmd->noArgs == 3 );
			assert( cmd->noStrArgs == 0 );
			if( cmd->arg[ 2 ] <= CRYPT_CERTTYPE_NONE || \
				cmd->arg[ 2 ] >= CRYPT_CERTTYPE_LAST_EXTERNAL )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case OBJECT_TYPE_DEVICE:
			assert( cmd->noArgs == 3 );
			assert( cmd->noStrArgs == 1 );
			if( cmd->arg[ 2 ] <= CRYPT_DEVICE_NONE || \
				cmd->arg[ 2 ] >= CRYPT_DEVICE_LAST )
				return( CRYPT_ARGERROR_NUM1 );
			if( cmd->arg[ 2 ] == CRYPT_DEVICE_PKCS11 )
				{
				if( cmd->strArgLen[ 0 ] < 2 || \
					cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE )
					return( CRYPT_ARGERROR_STR1 );
				hasStrArg = TRUE;
				}
			break;

		case OBJECT_TYPE_KEYSET:
			assert( cmd->noArgs == 4 );
			assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );
			if( cmd->arg[ 2 ] <= CRYPT_KEYSET_NONE || \
				cmd->arg[ 2 ] >= CRYPT_KEYSET_LAST )
				return( CRYPT_ARGERROR_NUM1 );
			if( cmd->arg[ 2 ] == CRYPT_KEYSET_HTTP )
				{
				if( cmd->strArgLen[ 0 ] )
					return( CRYPT_ARGERROR_STR1 );
				}
			else
				{
				if( cmd->strArgLen[ 0 ] < 2 || \
					cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE )
					return( CRYPT_ARGERROR_STR1 );
				hasStrArg = TRUE;
				}
			if( cmd->arg[ 3 ] < CRYPT_KEYOPT_NONE || \
				cmd->arg[ 3 ] >= CRYPT_KEYOPT_LAST )
				/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
				return( CRYPT_ARGERROR_NUM2 );
			break;

		case OBJECT_TYPE_ENVELOPE:
			assert( cmd->noArgs == 3 );
			assert( cmd->noStrArgs == 0 );
			if( cmd->arg[ 2 ] < CRYPT_FORMAT_FIRST_ENVELOPE || \
				cmd->arg[ 2 ] > CRYPT_FORMAT_LAST_ENVELOPE )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		case OBJECT_TYPE_SESSION:
			assert( cmd->noArgs == 3 );
			assert( cmd->noStrArgs == 0 );
			if( cmd->arg[ 2 ] < CRYPT_FORMAT_FIRST_SESSION || \
				cmd->arg[ 2 ] > CRYPT_FORMAT_LAST_SESSION )
				return( CRYPT_ARGERROR_NUM1 );
			break;

		default:
			assert( NOTREACHED );
		}

	/* If we're creating the object via a device, we should set the new 
	   object owner to the device owner */
	if( cmd->arg[ 0 ] != SYSTEM_OBJECT_HANDLE )
		{
		bindToOwner = TRUE;
		owner = cmd->arg[ 0 ];
		}

	/* Create the object via the device.  Since we're usually doing this via 
	   the system object which is invisible to the user, we have to use an
	   internal message for this one case */
	setMessageCreateObjectInfo( &createInfo, cmd->arg[ 2 ] );
	if( cmd->noArgs == 4 )
		createInfo.arg2 = cmd->arg[ 3 ];
	if( hasStrArg )
		{
		createInfo.strArg1 = cmd->strArg[ 0 ];
		createInfo.strArgLen1 = cmd->strArgLen[ 0 ];
		if( cmd->noStrArgs > 1 )
			{
			createInfo.strArg2 = cmd->strArg[ 1 ];
			createInfo.strArgLen2 = cmd->strArgLen[ 1 ];
			}
		}
	if( cmd->arg[ 0 ] == SYSTEM_OBJECT_HANDLE )
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, cmd->arg[ 1 ] );
	else
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_DEV_CREATEOBJECT,
								  &createInfo, cmd->arg[ 1 ] );
	if( cryptStatusError( status ) )
		return( status );

	/* If the device used to create the object is bound to a thread, bind the 
	   created object to the thread as well.  If this fails, we don't return 
	   the object to the caller since it would be returned in a potentially 
	   unbound state */
	if( bindToOwner )
		{
		int ownerID;

		status = krnlSendMessage( owner, RESOURCE_IMESSAGE_GETATTRIBUTE,
								  &ownerID, CRYPT_PROPERTY_OWNER );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( createInfo.cryptHandle, 
									  RESOURCE_IMESSAGE_SETATTRIBUTE,
									  &ownerID, CRYPT_PROPERTY_OWNER );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			return( status );
			}
		}

	/* Make the newly-created object externally visible */
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	cmd->arg[ 0 ] = createInfo.cryptHandle;
	return( status );
	}

static int cmdCreateObjectIndirect( COMMAND_INFO *cmd )
	{
	CREATEOBJECT_INFO createInfo;
	int status;

	assert( cmd->type == COMMAND_CREATEOBJECT_INDIRECT );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	if( cmd->arg[ 0 ] != SYSTEM_OBJECT_HANDLE )
		return( CRYPT_ERROR_FAILED );	/* Internal error */
	if( cmd->arg[ 1 ] != OBJECT_TYPE_CERTIFICATE )
		return( CRYPT_ERROR_FAILED );	/* Internal error */
	if( cmd->strArgLen[ 0 ] < MIN_CERTSIZE )
		return( CRYPT_ARGERROR_STR1 );

	/* Create the object via the device.  Since we're usually doing this via 
	   the system object which is invisible to the user, we have to use an
	   internal message for this one case */
	setMessageCreateObjectInfo( &createInfo, CERTIMPORT_NORMAL );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = cmd->strArg[ 0 ];
	createInfo.strArgLen1 = cmd->strArgLen[ 0 ];
	status = krnlSendMessage( cmd->arg[ 0 ], 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, cmd->arg[ 1 ] );
	if( cryptStatusError( status ) )
		return( status );

	/* Make the newly-created object externally visible */
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	cmd->arg[ 0 ] = createInfo.cryptHandle;
	return( status );
	}

static int cmdDecrypt( COMMAND_INFO *cmd )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode = CRYPT_MODE_NONE;
	int status;

	assert( cmd->type == COMMAND_DECRYPT );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
		if( cryptStatusError( status ) )
				return( status );
		}
	if( cmd->strArgLen[ 0 ] < 0 )
		return( CRYPT_ARGERROR_NUM1 );
	if( cryptMode == CRYPT_MODE_ECB || cryptMode == CRYPT_MODE_CBC )
		{
		int blockSize;

		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE,
								  &blockSize, CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusOK( status ) && cmd->strArgLen[ 0 ] % blockSize )
			status = CRYPT_ARGERROR_NUM1;
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Make sure the IV has been set */
	if( cryptAlgo != CRYPT_ALGO_RC4 && \
		( cryptMode == CRYPT_MODE_CBC || cryptMode == CRYPT_MODE_CFB || \
		  cryptMode == CRYPT_MODE_OFB ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_IV );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( krnlSendMessage( cmd->arg[ 0 ], ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH ) ? \
							 RESOURCE_MESSAGE_CTX_HASH : RESOURCE_MESSAGE_CTX_DECRYPT, 
							 cmd->strArgLen[ 0 ] ? cmd->strArg[ 0 ] : "", 
							 cmd->strArgLen[ 0 ] ) );
	}

static int cmdDeleteAttribute( COMMAND_INFO *cmd )
	{
	assert( cmd->type == COMMAND_DELETEATTRIBUTE );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= CRYPT_ATTRIBUTE_NONE || \
		cmd->arg[ 1 ] >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_DELETEATTRIBUTE,
							 NULL, cmd->arg[ 1 ] ) );
	}

static int cmdDeleteKey( COMMAND_INFO *cmd )
	{
	MESSAGE_KEYMGMT_INFO deletekeyInfo;

	assert( cmd->type == COMMAND_DELETEKEY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= CRYPT_KEYID_NONE || \
		cmd->arg[ 1 ] >= CRYPT_KEYID_LAST_EXTERNAL )
		return( CRYPT_ARGERROR_NUM1 );
	if( cmd->strArgLen[ 0 ] < 2 || \
		cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ARGERROR_STR1 );

	/* Delete the key from the keyset */
	setMessageKeymgmtInfo( &deletekeyInfo, cmd->arg[ 1 ], cmd->strArg[ 0 ], 
						   cmd->strArgLen[ 0 ], NULL, 0, 0 );
	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_KEY_DELETEKEY, 
							 &deletekeyInfo, 0 ) );
	}

static int cmdDestroyObject( COMMAND_INFO *cmd )
	{
	int dummy, status;

	assert( cmd->type == COMMAND_DESTROYOBJECT );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );

	/* Since we're about to access an internal attribute which can only be 
	   done through an internal message, we have to explicitly make sure the 
	   object is externally visible.  We do this by reading it's locked 
	   property (which is valid for all objects) */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
							  &dummy, CRYPT_PROPERTY_LOCKED );
	if( cryptStatusError( status ) )
		return( status );

	/* Make the object internal, which marks it as invalid for any external
	   access (to the caller, it looks like it's been destroyed).  After
	   this, decrement its reference count (which may or may not actually
	   destroy it) */
	krnlSendMessage( cmd->arg[ 0 ], RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_TRUE, CRYPT_IATTRIBUTE_INTERNAL );
	return( krnlSendNotifier( cmd->arg[ 0 ], RESOURCE_IMESSAGE_DECREFCOUNT ) );
	}

static int cmdEncrypt( COMMAND_INFO *cmd )
	{
	CRYPT_ALGO cryptAlgo;
	CRYPT_MODE cryptMode = CRYPT_MODE_NONE;
	int status;

	assert( cmd->type == COMMAND_ENCRYPT );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
							  &cryptAlgo, CRYPT_CTXINFO_ALGO );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo <= CRYPT_ALGO_LAST_CONVENTIONAL )
		{
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE,
								  &cryptMode, CRYPT_CTXINFO_MODE );
		if( cryptStatusError( status ) )
				return( status );
		}
	if( cmd->strArgLen[ 0 ] < 0 )
		return( CRYPT_ARGERROR_NUM1 );
	if( cryptMode == CRYPT_MODE_ECB || cryptMode == CRYPT_MODE_CBC )
		{
		int blockSize;

		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE,
								  &blockSize, CRYPT_CTXINFO_BLOCKSIZE );
		if( cryptStatusOK( status ) && cmd->strArgLen[ 0 ] % blockSize )
			status = CRYPT_ARGERROR_NUM1;
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If there's no IV set, generate one ourselves */
	if( cryptAlgo != CRYPT_ALGO_RC4 && \
		( cryptMode == CRYPT_MODE_CBC || cryptMode == CRYPT_MODE_CFB || \
		  cryptMode == CRYPT_MODE_OFB ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_IV );
		if( cryptStatusError( status ) )
			if( status == CRYPT_ERROR_NOTINITED )
				krnlSendNotifier( cmd->arg[ 0 ], RESOURCE_MESSAGE_CTX_GENIV );
			else
				return( status );
		}

	return( krnlSendMessage( cmd->arg[ 0 ], ( cryptAlgo >= CRYPT_ALGO_FIRST_HASH ) ? \
							 RESOURCE_MESSAGE_CTX_HASH : RESOURCE_MESSAGE_CTX_ENCRYPT, 
							 cmd->strArgLen[ 0 ] ? cmd->strArg[ 0 ] : "", 
							 cmd->strArgLen[ 0 ] ) );
	}

static int cmdExportObject( COMMAND_INFO *cmd )
	{
	CRYPT_ATTRIBUTE_TYPE formatType;
	RESOURCE_DATA msgData;
	int dummy, status;

	assert( cmd->type == COMMAND_EXPORTOBJECT );
	assert( cmd->flags == COMMAND_FLAG_NONE || \
			cmd->flags == COMMAND_FLAG_LENGTHONLY );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= CRYPT_CERTFORMAT_NONE || \
		cmd->arg[ 1 ] >= CRYPT_CERTFORMAT_LAST )
		/* At the moment the only object we can export is a cert, so we
		   make sure the format type is valid for this */
		return( CRYPT_ARGERROR_NUM1 );
	
	/* Convert the format type into the appropriate attribute type to read
	   from the object */
	formatType = ( cmd->arg[ 1 ] == CRYPT_CERTFORMAT_CERTIFICATE ) ? \
				 CRYPT_IATTRIBUTE_ENC_CERT : \
				 ( cmd->arg[ 1 ] == CRYPT_CERTFORMAT_CERTCHAIN ) ? \
				 CRYPT_IATTRIBUTE_ENC_CERTCHAIN : \
				 ( cmd->arg[ 1 ] == CRYPT_CERTFORMAT_TEXT_CERTIFICATE ) ? \
				 CRYPT_IATTRIBUTE_TEXT_CERT : CRYPT_IATTRIBUTE_TEXT_CERTCHAIN;

	/* Since we're about to access an internal attribute (which can only be 
	   done through an internal message), we have to explicitly make sure 
	   the object is externally visible.  We do this by reading its cert
	   type, which is a cert-only attribute which ensures that any possible
	   error status which will be reported is that of the cert rather than 
	   that of an associated object.  If that succeeds, we read the encoded
	   cert attribute */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
							  &dummy, CRYPT_CERTINFO_CERTTYPE );
	if( cryptStatusError( status ) )
		return( status );
	if( cmd->flags == COMMAND_FLAG_LENGTHONLY )
		{
		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, formatType );
		if( cryptStatusOK( status ) )
			cmd->arg[ 0 ] = msgData.length;
		}
	else
		{
		setResourceData( &msgData, cmd->strArg[ 0 ], cmd->strArgLen[ 0 ] );
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, formatType );
		if( cryptStatusOK( status ) )
			cmd->strArgLen[ 0 ] = msgData.length;
		}
	return( status );
	}

static int cmdGenKey( COMMAND_INFO *cmd )
	{
	assert( cmd->type == COMMAND_GENKEY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs >= 2 && cmd->noArgs <= 3 );
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( ( cmd->arg[ 1 ] < bitsToBytes( MIN_KEYSIZE_BITS ) || \
		  cmd->arg[ 1 ] > CRYPT_MAX_PKCSIZE ) && \
		( cmd->arg[ 1 ] != CRYPT_USE_DEFAULT ) )
		return( CRYPT_ARGERROR_NUM1 );

	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_CTX_GENKEY, 
							 &cmd->arg[ 1 ], ( cmd->noArgs > 2 ) ? \
							 ( cmd->arg[ 2 ] ? TRUE : FALSE ) : FALSE ) );
	}

static int cmdGetAttribute( COMMAND_INFO *cmd )
	{
	RESOURCE_DATA msgData;
	int status;

	assert( cmd->type == COMMAND_GETATTRIBUTE );
	assert( cmd->flags == COMMAND_FLAG_NONE || \
			cmd->flags == COMMAND_FLAG_LENGTHONLY );
	assert( cmd->noArgs >= 2 && cmd->noArgs <= 3 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) && cmd->arg[ 0 ] != CRYPT_UNUSED )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= CRYPT_ATTRIBUTE_NONE || \
		cmd->arg[ 1 ] >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Get the attribute data from the object */
	if( cmd->noArgs == 2 )
		return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE,
								 &cmd->arg[ 0 ], cmd->arg[ 1 ] ) );
	if( cmd->flags == COMMAND_FLAG_LENGTHONLY )
		{
		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE_S,
								  &msgData, cmd->arg[ 1 ] );
		if( cryptStatusOK( status ) )
			cmd->arg[ 0 ] = msgData.length;
		}
	else
		{
		setResourceData( &msgData, cmd->strArg[ 0 ], cmd->strArgLen[ 0 ] );
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_GETATTRIBUTE_S,
								  &msgData, cmd->arg[ 1 ] );
		if( cryptStatusOK( status ) )
			cmd->strArgLen[ 0 ] = msgData.length;
		}
	return( status );
	}

static int cmdGetKey( COMMAND_INFO *cmd )
	{
	MESSAGE_KEYMGMT_INFO getkeyInfo;
	int owner, status;

	assert( cmd->type == COMMAND_GETKEY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs >= 1 && cmd->noStrArgs <= 2 );

	/* Perform basic server-side error checking.  Because of keyset queries 
	   we have to accept CRYPT_KEYID_NONE as well as obviously valid key 
	   ID's */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] < CRYPT_KEYID_NONE || \
		cmd->arg[ 1 ] >= CRYPT_KEYID_LAST_EXTERNAL )
		return( CRYPT_ARGERROR_NUM1 );
	if( cmd->arg[ 1 ] == CRYPT_KEYID_NONE )
		{
		if( cmd->strArgLen[ 0 ] )
			return( CRYPT_ARGERROR_NUM1 );
		}
	else
		if( cmd->strArgLen[ 0 ] < 2 || \
			cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE )
			return( CRYPT_ARGERROR_STR1 );

	/* Read the key from the keyset */
	setMessageKeymgmtInfo( &getkeyInfo, cmd->arg[ 1 ], 
						   cmd->strArgLen[ 0 ] ? cmd->strArg[ 0 ] : NULL, 
							cmd->strArgLen[ 0 ], 
						   cmd->strArgLen[ 1 ] ? cmd->strArg[ 1 ] : NULL, 
							cmd->strArgLen[ 1 ], 
						   ( cmd->noStrArgs < 2 ) ? KEYMGMT_FLAG_PUBLICKEY : \
													KEYMGMT_FLAG_PRIVATEKEY );
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_KEY_GETKEY, 
							  &getkeyInfo, 0 );
	if( cryptStatusError( status ) )
		return( status );

	/* If the keyset is bound to a thread, bind the key read from it to the 
	   thread as well.  If this fails, we don't return the imported key to 
	   the caller since it would be returned in a potentially unbound state */
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_GETATTRIBUTE, 
							  &owner, CRYPT_PROPERTY_OWNER );
	if( cryptStatusError( status ) )
		{
		krnlSendNotifier( getkeyInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	krnlSendMessage( getkeyInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 &owner, CRYPT_PROPERTY_OWNER );

	/* Make the key externally visible */
	krnlSendMessage( getkeyInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_FALSE, CRYPT_IATTRIBUTE_INTERNAL );
	cmd->arg[ 0 ] = getkeyInfo.cryptHandle;
		
	return( CRYPT_OK );
	}

static int cmdPopData( COMMAND_INFO *cmd )
	{
	RESOURCE_DATA msgData;
	int status;

	assert( cmd->type == COMMAND_POPDATA );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] < 1 )
		return( CRYPT_ARGERROR_NUM1 );

	/* Get the data from the object.  We always copy out the byte count value
	   because it's valid even if an error occurs */
	setResourceData( &msgData, cmd->strArg[ 0 ], cmd->arg[ 1 ] );
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_ENV_POPDATA,
							  &msgData, 0 );
	cmd->strArgLen[ 0 ] = msgData.length;
	return( status );
	}

static int cmdPushData( COMMAND_INFO *cmd )
	{
	RESOURCE_DATA msgData;
	int status;

	assert( cmd->type == COMMAND_PUSHDATA );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 1 );
	assert( cmd->noStrArgs == 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->strArgLen[ 0 ] < 0 )
		return( CRYPT_ARGERROR_NUM1 );

	/* Send the data to the object.  We always copy out the byte count value
	   because it's valid even if an error occurs */
	setResourceData( &msgData, cmd->strArgLen[ 0 ] ? cmd->strArg[ 0 ] : NULL, 
					 cmd->strArgLen[ 0 ] );
	status = krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_ENV_PUSHDATA,
							  &msgData, 0 );
	cmd->arg[ 0 ] = msgData.length;
	return( status );
	}

static int cmdQueryCapability( COMMAND_INFO *cmd )
	{
	CRYPT_QUERY_INFO queryInfo;
	int status;

	assert( cmd->type == COMMAND_QUERYCAPABILITY );
	assert( cmd->flags == COMMAND_FLAG_NONE || \
			cmd->flags == COMMAND_FLAG_LENGTHONLY );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );
	assert( cmd->flags == COMMAND_FLAG_LENGTHONLY || \
			cmd->strArg[ 0 ] != NULL );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) && \
		cmd->arg[ 0 ] != SYSTEM_OBJECT_HANDLE )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] < CRYPT_ALGO_NONE || cmd->arg[ 1 ] >= CRYPT_ALGO_LAST )
		return( CRYPT_ARGERROR_NUM1 );

	/* Query the device for information on the given algorithm and mode */
	if( cmd->arg[ 0 ] == SYSTEM_OBJECT_HANDLE )
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY,
								  &queryInfo, cmd->arg[ 1 ] );
	else
		status = krnlSendMessage( cmd->arg[ 0 ], 
								  RESOURCE_MESSAGE_DEV_QUERYCAPABILITY,
								  &queryInfo, cmd->arg[ 1 ] );
	if( cryptStatusOK( status ) )
		{
		/* Return either the length or the full capability into depending on
		   what the caller has asked for */
		if( cmd->flags == COMMAND_FLAG_LENGTHONLY )
			cmd->arg[ 0 ] = sizeof( CRYPT_QUERY_INFO );
		else
			{
			memcpy( cmd->strArg[ 0 ], &queryInfo, 
					sizeof( CRYPT_QUERY_INFO ) );
			cmd->strArgLen[ 0 ] = sizeof( CRYPT_QUERY_INFO );
			}
		}

	return( status );
	}

static int cmdServerQuery( COMMAND_INFO *cmd )
	{
	int value;

	assert( cmd->type == COMMAND_SERVERQUERY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 0 );
	assert( cmd->noStrArgs == 0 );

	/* Return information about the server */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_MESSAGE_GETATTRIBUTE,
					 &value, CRYPT_OPTION_INFO_MAJORVERSION );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_MESSAGE_GETATTRIBUTE,
					 &value, CRYPT_OPTION_INFO_MINORVERSION );

	return( CRYPT_OK );
	}

static int cmdSetAttribute( COMMAND_INFO *cmd )
	{
	RESOURCE_DATA msgData;

	assert( cmd->type == COMMAND_SETATTRIBUTE );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( ( cmd->noArgs == 3 && cmd->noStrArgs == 0 ) ||
			( cmd->noArgs == 2 && cmd->noStrArgs == 1 ) );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) && cmd->arg[ 0 ] != CRYPT_UNUSED )
		return( CRYPT_ARGERROR_OBJECT );
	if( cmd->arg[ 1 ] <= CRYPT_ATTRIBUTE_NONE || \
		cmd->arg[ 1 ] >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ARGERROR_NUM1 );
	if( cmd->noStrArgs == 1 )
		{
		if( cmd->arg[ 1 ] == CRYPT_CTXINFO_KEY_COMPONENTS )
			{
			/* Public key components constitute a special case since the 
			   composite structures used are quite large */
			if( cmd->strArgLen[ 0 ] != sizeof( CRYPT_PKCINFO_RSA ) && \
				cmd->strArgLen[ 0 ] != sizeof( CRYPT_PKCINFO_DLP ) ) 
				return( CRYPT_ARGERROR_NUM2 );
			}
		else
			if( cmd->strArgLen[ 0 ] < 1 || \
				cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE )
				return( CRYPT_ARGERROR_NUM2 );
		}

	/* Send the attribute data to the object, mapping the return code to the
	   correct value if necessary */
	if( cmd->noStrArgs == 0 )
		return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_SETATTRIBUTE,
								 ( void * ) &cmd->arg[ 2 ], cmd->arg[ 1 ] ) );
	setResourceData( &msgData, cmd->strArg[ 0 ], cmd->strArgLen[ 0 ] );
	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_SETATTRIBUTE_S,
							 &msgData, cmd->arg[ 1 ] ) );
	}

static int cmdSetKey( COMMAND_INFO *cmd )
	{
	MESSAGE_KEYMGMT_INFO setkeyInfo;

	assert( cmd->type == COMMAND_SETKEY );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs >= 0 && cmd->noStrArgs <= 1 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( !checkHandleRange( cmd->arg[ 1 ] ) )
		return( CRYPT_ARGERROR_NUM1 );
	if( cmd->noStrArgs == 1 && \
		( cmd->strArgLen[ 0 ] < 2 || \
		  cmd->strArgLen[ 0 ] >= MAX_ATTRIBUTE_SIZE ) )
		return( CRYPT_ARGERROR_STR1 );

	/* Add the key */
	setMessageKeymgmtInfo( &setkeyInfo, CRYPT_KEYID_NONE, NULL, 0, 
						   ( cmd->noStrArgs == 1 ) ? cmd->strArg[ 0 ] : NULL, 
						   cmd->strArgLen[ 0 ], ( cmd->noStrArgs == 1 ) ? 
						   KEYMGMT_FLAG_PRIVATEKEY : KEYMGMT_FLAG_PUBLICKEY );
	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_KEY_SETKEY, 
							 &setkeyInfo, cmd->arg[ 1 ] ) );
	}

static int cmdCertCheck( COMMAND_INFO *cmd )
	{
	assert( cmd->type == COMMAND_CERTCHECK );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( !checkHandleRange( cmd->arg[ 1 ] ) && \
		( cmd->arg[ 1 ] != CRYPT_UNUSED ) )
		return( CRYPT_ARGERROR_NUM1 );

	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_CRT_SIGCHECK, 
							 NULL, cmd->arg[ 1 ] ) );
	}

static int cmdCertSign( COMMAND_INFO *cmd )
	{
	assert( cmd->type == COMMAND_CERTSIGN );
	assert( cmd->flags == COMMAND_FLAG_NONE );
	assert( cmd->noArgs == 2 );
	assert( cmd->noStrArgs == 0 );

	/* Perform basic server-side error checking */
	if( !checkHandleRange( cmd->arg[ 0 ] ) )
		return( CRYPT_ARGERROR_OBJECT );
	if( !checkHandleRange( cmd->arg[ 1 ] ) )
		return( CRYPT_ARGERROR_NUM1 );

	return( krnlSendMessage( cmd->arg[ 0 ], RESOURCE_MESSAGE_CRT_SIGN, 
							 NULL, cmd->arg[ 1 ] ) );
	}

/* Process a command from the client and send it to the appropriate handler */

typedef int ( *COMMAND_HANDLER )( COMMAND_INFO *cmd );

static const COMMAND_HANDLER commandHandlers[] = {
	NULL, cmdServerQuery, NULL, cmdCreateObject, cmdCreateObjectIndirect,
	cmdExportObject, cmdDestroyObject, cmdQueryCapability, cmdGenKey, 
	cmdEncrypt, cmdDecrypt, cmdGetAttribute, cmdSetAttribute, 
	cmdDeleteAttribute, cmdGetKey, cmdSetKey, cmdDeleteKey, cmdPushData,
	cmdPopData, cmdCertSign, cmdCertCheck, cmdAsyncOp };

static void processCommand( BYTE *buffer )
	{
	COMMAND_INFO cmd = { 0 };
	BYTE header[ COMMAND_FIXED_DATA_SIZE ], *bufPtr;
	long totalLength;
	int i, status;

	/* Read the client's message header */
	memcpy( header, buffer, COMMAND_FIXED_DATA_SIZE );

	/* Process the fixed message header and make sure it's valid */
	getMessageType( header, cmd.type, cmd.flags, cmd.noArgs, cmd.noStrArgs );
	totalLength = getMessageLength( header + COMMAND_WORDSIZE );
	if( !checkCommandInfo( &cmd, totalLength ) || \
		cmd.type == COMMAND_RESULT )
		{
		/* Return an invalid result message */
		putMessageType( buffer, COMMAND_RESULT, 0, 0, 0 );
		putMessageLength( buffer + COMMAND_WORDSIZE, 0 );
		return;
		}

	/* Read the rest of the clients message */
	bufPtr = buffer + COMMAND_FIXED_DATA_SIZE;
	for( i = 0; i < cmd.noArgs; i++ )
		{
		cmd.arg[ i ] = getMessageWord( bufPtr );
		bufPtr += COMMAND_WORDSIZE;
		}
	for( i = 0; i < cmd.noStrArgs; i++ )
		{
		cmd.strArgLen[ i ] = getMessageWord( bufPtr );
		cmd.strArg[ i ] = bufPtr + COMMAND_WORDSIZE;
		bufPtr += COMMAND_WORDSIZE + cmd.strArgLen[ i ];
		}

	/* If it's a command which returns a string value, obtain the returned 
	   data in the buffer.  Normally we limit the size to the maximum
	   attribute size, however encoded objects and data popped from 
	   envelopes/sessions can be larger than this so we use the entire buffer 
	   minus a safety margin */
	if( cmd.type == COMMAND_POPDATA || \
		( cmd.flags != COMMAND_FLAG_LENGTHONLY && \
		  ( cmd.type == COMMAND_EXPORTOBJECT || \
			cmd.type == COMMAND_QUERYCAPABILITY || \
			( cmd.type == COMMAND_GETATTRIBUTE && \
			  cmd.noArgs == 3 ) ) ) )
		{
		cmd.noStrArgs = 1;
		cmd.strArg[ 0 ] = bufPtr;
		if( cmd.type == COMMAND_EXPORTOBJECT || cmd.type == COMMAND_POPDATA )
			{
			cmd.strArgLen[ 0 ] = IO_BUFSIZE - 16 - ( bufPtr - buffer );
			assert( cmd.type != COMMAND_POPDATA || \
					cmd.strArgLen[ 0 ] >= MAX_FRAGMENT_SIZE );
			}
		else
			cmd.strArgLen[ 0 ] = MAX_ATTRIBUTE_SIZE;
		}

	/* Process the command and copy any return information back to the 
	   caller */
	status = commandHandlers[ cmd.type ]( &cmd );
	bufPtr = buffer;
	if( cryptStatusError( status ) )
		{
		/* The push data command is a special case since an error can occur 
		   after some data has been processed, so we still need to copy back
		   a result even if we get an error status */
		if( cmd.type == COMMAND_PUSHDATA )
			{
			putMessageType( bufPtr, COMMAND_RESULT, 0, 2, 0 );
			putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE * 2 );
			putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE, status );
			putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE,
							cmd.arg[ 0 ] );
			return;
			}

		/* The command failed, return a simple status value */
		putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 0 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE );
		putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE, status );
		return;
		}
	if( cmd.type == COMMAND_CREATEOBJECT || \
		cmd.type == COMMAND_CREATEOBJECT_INDIRECT || \
		cmd.type == COMMAND_GETKEY || \
		cmd.type == COMMAND_PUSHDATA || \
		( ( cmd.type == COMMAND_EXPORTOBJECT || \
			cmd.type == COMMAND_QUERYCAPABILITY ) && \
		  cmd.flags == COMMAND_FLAG_LENGTHONLY ) || \
		( cmd.type == COMMAND_GETATTRIBUTE && \
		  ( cmd.noArgs == 2 || cmd.flags == COMMAND_FLAG_LENGTHONLY ) ) )
		{
		/* Return object handle or numeric value or string length */
		putMessageType( bufPtr, COMMAND_RESULT, 0, 2, 0 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE * 2 );
		putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE, CRYPT_OK );
		putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE,
						cmd.arg[ 0 ] );
		return;
		}
	if( cmd.type == COMMAND_ENCRYPT || \
		cmd.type == COMMAND_DECRYPT || \
		cmd.type == COMMAND_POPDATA || \
		cmd.type == COMMAND_EXPORTOBJECT || \
		cmd.type == COMMAND_QUERYCAPABILITY || \
		cmd.type == COMMAND_GETATTRIBUTE )
		{
		const long dataLength = cmd.strArgLen[ 0 ];

		/* Return capability info or attribute data and length */
		putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 1 );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, 
						  ( COMMAND_WORDSIZE * 2 ) + cmd.strArgLen[ 0 ] );
		putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE, CRYPT_OK );
		putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE,
						dataLength );
		if( dataLength )
			memmove( bufPtr + COMMAND_FIXED_DATA_SIZE + ( COMMAND_WORDSIZE * 2 ), 
					 cmd.strArg[ 0 ], dataLength );
		return;
		}
	putMessageType( bufPtr, COMMAND_RESULT, 0, 1, 0 );
	putMessageLength( bufPtr + COMMAND_WORDSIZE, COMMAND_WORDSIZE );
	putMessageWord( bufPtr + COMMAND_FIXED_DATA_SIZE, CRYPT_OK );
	}

/* Dummy forwarding procedure to take the place of the comms channel between
   client and server */

static void serverTransact( void *clientBuffer )
	{
	BYTE serverBuffer[ IO_BUFSIZE ];
	int length;

	/* Copy the command to the server buffer, process it, and copy the result
	   back to the client buffer to emulate the client <-> server 
	   transmission */
	length = getMessageLength( ( BYTE * ) clientBuffer + COMMAND_WORDSIZE );
	memcpy( serverBuffer, clientBuffer, length + COMMAND_FIXED_DATA_SIZE );
	processCommand( serverBuffer );
	length = getMessageLength( ( BYTE * ) serverBuffer + COMMAND_WORDSIZE );
	memcpy( clientBuffer, serverBuffer, length + COMMAND_FIXED_DATA_SIZE );
	}

/* Dispatch a command to the server */

static int dispatchCommand( COMMAND_INFO *cmd )
	{
	COMMAND_INFO sentCmd = *cmd;
	BYTE buffer[ IO_BUFSIZE ], *bufPtr = buffer;
	BYTE header[ COMMAND_FIXED_DATA_SIZE ];
	BYTE *payloadStartPtr, *payloadPtr;
	const BOOLEAN isPushPop = \
		( cmd->type == COMMAND_PUSHDATA || cmd->type == COMMAND_POPDATA ) ? \
		TRUE : FALSE;
	const BOOLEAN isDataCommand = \
		( cmd->type == COMMAND_ENCRYPT || cmd->type == COMMAND_DECRYPT || \
		  isPushPop ) ? TRUE : FALSE;
	const long payloadLength = ( cmd->noArgs * COMMAND_WORDSIZE ) + \
							   ( cmd->noStrArgs * COMMAND_WORDSIZE ) + \
							   cmd->strArgLen[ 0 ] + cmd->strArgLen[ 1 ];
	long dataLength = cmd->strArgLen[ 0 ], resultLength;
	int i;

	assert( checkCommandInfo( cmd, 0 ) );

	/* Clear the return value */
	memset( cmd, 0, sizeof( COMMAND_INFO ) );

	/* Make sure the data will fit into the buffer */
	if( !isDataCommand && \
		( COMMAND_FIXED_DATA_SIZE + payloadLength ) > IO_BUFSIZE )
		{
		long maxLength = dataLength;
		int maxPos = 0;

		/* Find the longest arg (the one which contributes most to the
		   problem) and report it as an error */
		for( i = 0; i < sentCmd.noStrArgs; i++ )
			if( sentCmd.strArgLen[ i ] > maxLength )
				{
				maxLength = sentCmd.strArgLen[ i ];
				maxPos = i;
				}
		return( CRYPT_ARGERROR_STR1 - maxPos );
		}

	/* If it's a short-datasize command, process it and return immediately */
	if( !isDataCommand || ( dataLength < MAX_FRAGMENT_SIZE ) )
		{
		/* Write the header and message fields to the buffer */
		putMessageType( bufPtr, sentCmd.type, sentCmd.flags, 
						sentCmd.noArgs, sentCmd.noStrArgs );
		putMessageLength( bufPtr + COMMAND_WORDSIZE, payloadLength );
		bufPtr += COMMAND_FIXED_DATA_SIZE;
		for( i = 0; i < sentCmd.noArgs; i++ )
			{
			putMessageWord( bufPtr, sentCmd.arg[ i ] );
			bufPtr += COMMAND_WORDSIZE;
			}
		for( i = 0; i < sentCmd.noStrArgs; i++ )
			{
			const int argLength = sentCmd.strArgLen[ i ];

			putMessageWord( bufPtr, argLength );
			if( argLength > 0 )
				memcpy( bufPtr + COMMAND_WORDSIZE, sentCmd.strArg[ i ], 
						argLength );
			bufPtr += COMMAND_WORDSIZE + argLength;
			}

		/* Send the command to the server and read the servers message header */
		serverTransact( buffer );
		memcpy( header, buffer, COMMAND_FIXED_DATA_SIZE );

		/* Process the fixed message header and make sure it's valid */
		getMessageType( header, cmd->type, cmd->flags, 
						cmd->noArgs, cmd->noStrArgs );
		resultLength = getMessageLength( header + COMMAND_WORDSIZE );
		if( !checkCommandInfo( cmd, resultLength ) || \
			cmd->type != COMMAND_RESULT )
			return( CRYPT_ERROR );

		/* Read the rest of the servers message */
		bufPtr = buffer + COMMAND_FIXED_DATA_SIZE;
		for( i = 0; i < cmd->noArgs; i++ )
			{
			cmd->arg[ i ] = getMessageWord( bufPtr );
			bufPtr += COMMAND_WORDSIZE;
			}
		for( i = 0; i < cmd->noStrArgs; i++ )
			{
			cmd->strArgLen[ i ] = getMessageWord( bufPtr );
			cmd->strArg[ i ] = bufPtr + COMMAND_WORDSIZE;
			bufPtr += COMMAND_WORDSIZE + cmd->strArgLen[ i ];
			}

		/* The first value returned is the status code, if it's nonzero return
		   it to the caller, otherwise move the other values down */
		if( cryptStatusError( cmd->arg[ 0 ] ) )
			{
			/* The push data command is a special case since it returns a 
			   bytes copied value even if an error occurs */
			if( sentCmd.type == COMMAND_PUSHDATA )
				{
				const int status = cmd->arg[ 0 ];

				cmd->arg[ 0 ] = cmd->arg[ 1 ];
				cmd->arg[ 1 ] = 0;
				cmd->noArgs--;
				return( status );
				}
			return( cmd->arg[ 0 ] );
			}
		assert( cryptStatusOK( cmd->arg[ 0 ] ) );
		for( i = 1; i < cmd->noArgs; i++ )
			cmd->arg[ i - 1 ] = cmd->arg[ i ];
		cmd->arg[ i ] = 0;
		cmd->noArgs--;

		/* Copy any string arg data back to the caller */
		if( cmd->noStrArgs && cmd->strArgLen[ 0 ] )
			{
			memcpy( sentCmd.strArg[ 0 ], cmd->strArg[ 0 ], 
					cmd->strArgLen[ 0 ] );
			cmd->strArg[ 0 ] = sentCmd.strArg[ 0 ];
			if( isPushPop )
				/* A data pop returns the actual number of copied bytes 
				   (which may be less than the requested number of bytes) as
				   arg 0 */
				cmd->arg[ 0 ] = cmd->strArgLen[ 0 ];
			}

		return( CRYPT_OK );
		}

	/* Remember where the variable-length payload starts in the buffer and
	   where it's to be copied to */
	payloadStartPtr = buffer + COMMAND_FIXED_DATA_SIZE + COMMAND_WORDSIZE;
	payloadPtr = sentCmd.strArg[ 0 ];

	/* It's a long-datasize command, handle fragmentation */
	do
		{
		COMMAND_INFO cmdResult = { 0 };
		const int fragmentLength = min( dataLength, MAX_FRAGMENT_SIZE );
		int status;

		/* Write the fixed and variable-length message fields to the buffer */
		putMessageType( buffer, sentCmd.type, 0, sentCmd.noArgs, 
						sentCmd.noStrArgs );
		if( sentCmd.type == COMMAND_POPDATA )
			{
			putMessageLength( buffer + COMMAND_WORDSIZE, 
							  ( COMMAND_WORDSIZE * 2 ) );
			}
		else
			{
			putMessageLength( buffer + COMMAND_WORDSIZE, 
							  ( COMMAND_WORDSIZE * 2 ) + fragmentLength );
			}
		putMessageWord( buffer + COMMAND_FIXED_DATA_SIZE, 
						sentCmd.arg[ 0 ] );
		putMessageWord( payloadStartPtr, fragmentLength );
		if( sentCmd.type != COMMAND_POPDATA )
			memcpy( payloadStartPtr + COMMAND_WORDSIZE, payloadPtr,
					fragmentLength );

		/* Process as much data as we can and read the servers message
		   header */
		serverTransact( buffer );
		memcpy( header, buffer, COMMAND_FIXED_DATA_SIZE );

		/* Process the fixed message header and make sure it's valid */
		getMessageType( header, cmdResult.type, cmdResult.flags, 
						cmdResult.noArgs, cmdResult.noStrArgs );
		resultLength = getMessageLength( header + COMMAND_WORDSIZE );
		if( !checkCommandInfo( &cmdResult, resultLength ) || \
			cmdResult.type != COMMAND_RESULT || \
			cmdResult.flags != COMMAND_FLAG_NONE )
			return( CRYPT_ERROR );
		if( sentCmd.type == COMMAND_PUSHDATA )
			{
			if( cmdResult.noArgs != 2 || cmdResult.noStrArgs )
				return( CRYPT_ERROR );
			}
		else
			if( cmdResult.noArgs != 1 || cmdResult.noStrArgs != 1 )
				return( CRYPT_ERROR );

		/* Process the fixed message header and make sure it's valid */
		bufPtr = buffer + COMMAND_FIXED_DATA_SIZE;
		status = getMessageWord( bufPtr );
		if( cryptStatusError( status ) )
			{
			/* The push data command is a special case since it returns a 
			   bytes copied value even if an error occurs */
			if( sentCmd.type == COMMAND_PUSHDATA )
				{
				const long bytesCopied = \
							getMessageWord( bufPtr + COMMAND_WORDSIZE );

				if( bytesCopied < 0 )
					return( CRYPT_ERROR );
				cmdResult.arg[ 0 ] = cmd->arg[ 0 ] + bytesCopied;
				cmdResult.noArgs = 1;
				}
			*cmd = cmdResult;
			return( status );
			}
		assert( cryptStatusOK( status ) );
		
		/* Read the rest of the servers message */
		resultLength = getMessageWord( bufPtr + COMMAND_WORDSIZE );
		if( isPushPop )
			{
			/* It's a variable-length transformation, we have to return a
			   non-negative number of bytes */
			if( resultLength <= 0 )
				{
				if( resultLength == 0 )
					/* We've run out of data, return to the caller */
					break;
				return( CRYPT_ERROR );
				}
			cmd->arg[ 0 ] += resultLength;
			if( sentCmd.type == COMMAND_POPDATA )
				memcpy( payloadPtr, payloadStartPtr + COMMAND_WORDSIZE, 
						resultLength );
			}
		else
			{
			/* It's an encrypt/decrypt, the result must be a 1:1 
			   transformation */
			if( resultLength != fragmentLength )
				return( CRYPT_ERROR );
			memcpy( payloadPtr, payloadStartPtr + COMMAND_WORDSIZE, 
					resultLength );
			}

		/* Move on to the next fragment */
		payloadPtr += resultLength;
		dataLength -= resultLength;
		}
	while( dataLength > 0 );

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Utility Functions							*
*																			*
****************************************************************************/

/* Internal parameter errors are reported in terms of the parameter type (eg
   invalid object, invalid attribute), but externally they're reported in
   terms of parameter numbers.  Before we return error values to the caller,
   we have to map them from the internal representation to the position they
   occur in in the function parameter list.  The following function takes a
   list of parameter types and maps the returned parameter type error to a
   parameter position error */

typedef enum { 
	ARG_D,			/* Dummy placeholder */
	ARG_O,			/* Object */
	ARG_V,			/* Value (attribute) */
	ARG_N,			/* Numeric arg */
	ARG_S,			/* String arg */
	ARG_LAST
	} ERRORMAP;

static int mapError( const ERRORMAP *errorMap, const int status )
	{
	ERRORMAP type;
	int count = 0, i;

	/* If it's not an internal parameter error, let it out */
	if( !cryptArgError( status ) )
		{
		assert( status <= 0 && status >= CRYPT_ENVELOPE_RESOURCE );
		return( status );
		}

	/* Map the parameter error to a position error */
	switch( status )
		{
		case CRYPT_ARGERROR_OBJECT:
			type = ARG_O;
			break;
		case CRYPT_ARGERROR_VALUE:
			type = ARG_V;
			break;
		case CRYPT_ARGERROR_NUM1:
			type = ARG_N;
			count = CRYPT_ARGERROR_NUM1 - status;
			break;
		case CRYPT_ARGERROR_STR1:
			type = ARG_S;
			count = CRYPT_ARGERROR_STR1 - status;
			break;
		default:
			assert( NOTREACHED );
		}
	for( i = 0; errorMap[ i ] != ARG_LAST; i++ )
		if( errorMap[ i ] == type && !count-- )
			return( CRYPT_ERROR_PARAM1 - i );
	assert( NOTREACHED );
	return( CRYPT_ERROR_FAILED );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*								Create/Destroy Objects						*
*																			*
****************************************************************************/

/* Create an encryption context */

C_RET cryptCreateContext( C_OUT CRYPT_CONTEXT C_PTR cryptContext,
						  C_IN CRYPT_ALGO cryptAlgo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 0, 
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_CONTEXT } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*cryptContext = CRYPT_ERROR;
	if( ( cryptAlgo <= CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST ) && \
		cryptAlgo != CRYPT_USE_DEFAULT )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = cryptAlgo;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*cryptContext = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Create an encryption context via the device */

C_RET cryptDeviceCreateContext( C_IN CRYPT_DEVICE device,
							    C_OUT CRYPT_CONTEXT C_PTR cryptContext,
							    C_IN CRYPT_ALGO cryptAlgo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 0, 
		  { 0, OBJECT_TYPE_CONTEXT } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_D, ARG_N, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( device ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*cryptContext = CRYPT_ERROR;
	if( ( cryptAlgo <= CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST ) && \
		cryptAlgo != CRYPT_USE_DEFAULT )
		return( CRYPT_ERROR_PARAM3 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = device;
	cmd.arg[ 2 ] = cryptAlgo;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*cryptContext = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Create a certificate */

C_RET cryptCreateCert( C_OUT CRYPT_CERTIFICATE C_PTR certificate,
					   C_IN CRYPT_CERTTYPE_TYPE certType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 0, 
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_CERTIFICATE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( checkBadPtrWrite( certificate, sizeof( CRYPT_CERTIFICATE ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*certificate = CRYPT_ERROR;
	if( certType <= CRYPT_CERTTYPE_NONE || \
		certType >= CRYPT_CERTTYPE_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = certType;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*certificate = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Open a device */

C_RET cryptDeviceOpen( C_OUT CRYPT_DEVICE C_PTR device,
					   C_IN CRYPT_DEVICE_TYPE deviceType,
					   C_IN char C_PTR name )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 1,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_DEVICE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( device, sizeof( CRYPT_DEVICE ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*device = CRYPT_ERROR;
	if( deviceType <= CRYPT_DEVICE_NONE || deviceType >= CRYPT_DEVICE_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( deviceType == CRYPT_DEVICE_PKCS11 && \
		( checkBadPtrRead( name, 2 ) || \
		  strlen( name ) >= MAX_ATTRIBUTE_SIZE ) )
		return( CRYPT_ERROR_PARAM3 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = deviceType;
	cmd.strArg[ 0 ] = ( void * ) name;
	if( name != NULL )
		cmd.strArgLen[ 0 ] = strlen( name );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*device = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Create an envelope */

C_RET cryptCreateEnvelope( C_OUT CRYPT_ENVELOPE C_PTR envelope,
						   C_IN CRYPT_FORMAT_TYPE formatType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 0,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_ENVELOPE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( envelope, sizeof( CRYPT_SESSION ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*envelope = CRYPT_ERROR;
	if( formatType < CRYPT_FORMAT_FIRST_ENVELOPE || \
		formatType > CRYPT_FORMAT_LAST_ENVELOPE )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = formatType;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*envelope = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Open/create a keyset */

C_RET cryptKeysetOpen( C_OUT CRYPT_KEYSET C_PTR keyset, 
					   C_IN CRYPT_KEYSET_TYPE keysetType,
					   C_IN char C_PTR name, C_IN CRYPT_KEYOPT_TYPE options )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 4, 1,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_KEYSET } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( keyset, sizeof( CRYPT_KEYSET ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*keyset = CRYPT_ERROR;
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( keysetType == CRYPT_KEYSET_HTTP )
		{
		if( name != NULL )
			return( CRYPT_ERROR_PARAM3 );
		}
	else
		if( checkBadPtrRead( name, 2 ) || \
			strlen( name ) >= MAX_ATTRIBUTE_SIZE )
			return( CRYPT_ERROR_PARAM3 );
	if( options < CRYPT_KEYOPT_NONE || options >= CRYPT_KEYOPT_LAST )
		/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
		return( CRYPT_ERROR_PARAM4 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = keysetType;
	cmd.arg[ 3 ] = options;
	cmd.strArg[ 0 ] = ( void * ) name;
	if( name != NULL )
		cmd.strArgLen[ 0 ] = strlen( name );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*keyset = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

C_RET cryptKeysetOpenEx( C_OUT CRYPT_KEYSET C_PTR keyset,
                         C_IN CRYPT_KEYSET_TYPE keysetType,
                         C_IN char C_PTR name, C_IN char C_PTR param1,
                         C_IN char C_PTR param2, C_IN char C_PTR param3,
                         C_IN CRYPT_KEYOPT_TYPE options )
    {
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 4, 1,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_KEYSET } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_S, ARG_S, ARG_S, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrRead( keyset, sizeof( CRYPT_KEYSET ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*keyset = CRYPT_ERROR;
	if( keysetType <= CRYPT_KEYSET_NONE || keysetType >= CRYPT_KEYSET_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( keysetType == CRYPT_KEYSET_HTTP )
		{
		if( name != NULL )
			return( CRYPT_ERROR_PARAM3 );
		}
	else
		{
		if( checkBadPtrRead( name, 2 ) || \
			strlen( name ) >= MAX_ATTRIBUTE_SIZE )
			return( CRYPT_ERROR_PARAM3 );
		if( param1 != NULL && \
			( checkBadPtrRead( param1, 2 ) || \
			  strlen( param1 ) >= MAX_ATTRIBUTE_SIZE ) )
			return( CRYPT_ERROR_PARAM4 );
		}
	if( options < CRYPT_KEYOPT_NONE || options >= CRYPT_KEYOPT_LAST )
		/* CRYPT_KEYOPT_NONE is a valid setting for this parameter */
		return( CRYPT_ERROR_PARAM7 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = keysetType;
	cmd.arg[ 3 ] = options;
	cmd.strArg[ 0 ] = ( void * ) name;
	if( name != NULL )
		cmd.strArgLen[ 0 ] = strlen( name );
	cmd.strArg[ 1 ] = ( void * ) param1;
	if( name != NULL )
		cmd.strArgLen[ 1 ] = strlen( param1 );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*keyset = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Create a session */

C_RET cryptCreateSession( CRYPT_SESSION C_PTR session,
						  C_IN CRYPT_FORMAT_TYPE formatType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT, COMMAND_FLAG_NONE, 3, 0,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_SESSION } };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic error checking */
	if( checkBadPtrWrite( session, sizeof( CRYPT_SESSION ) ) )
		return( CRYPT_ERROR_PARAM1 );
	*session = CRYPT_ERROR;
	if( formatType < CRYPT_FORMAT_FIRST_SESSION || \
		formatType > CRYPT_FORMAT_LAST_SESSION )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 2 ] = formatType;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*session = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Destroy object functions */

C_RET cryptDestroyObject( C_IN CRYPT_HANDLE cryptHandle )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_DESTROYOBJECT, COMMAND_FLAG_NONE, 1, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) )
		return( CRYPT_ERROR_PARAM1 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptHandle;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptDestroyCert( C_IN CRYPT_CERTIFICATE certificate )
	{
	return( cryptDestroyObject( certificate ) );
	}
C_RET cryptDestroyContext( C_IN CRYPT_CONTEXT cryptContext )
	{
	return( cryptDestroyObject( cryptContext ) );
	}
C_RET cryptDestroyEnvelope( C_IN CRYPT_ENVELOPE cryptEnvelope )
	{
	return( cryptDestroyObject( cryptEnvelope ) );
	}
C_RET cryptDeviceClose( C_IN CRYPT_DEVICE device )
	{
	return( cryptDestroyObject( device ) );
	}
C_RET cryptKeysetClose( C_IN CRYPT_KEYSET keyset )
	{
	return( cryptDestroyObject( keyset ) );
	}
C_RET cryptDestroySession( C_IN CRYPT_SESSION session )
	{
	return( cryptDestroyObject( session ) );
	}

/****************************************************************************
*																			*
*						Attribute Manipulation Functions					*
*																			*
****************************************************************************/

/* Get an attribute */

C_RET cryptGetAttribute( C_IN CRYPT_HANDLE cryptHandle, 
						 C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
						 C_OUT int C_PTR value )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GETATTRIBUTE, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_V, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) && cryptHandle != CRYPT_UNUSED )
		return( CRYPT_ERROR_PARAM1 );
	if( attributeType <= CRYPT_ATTRIBUTE_NONE || attributeType >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrWrite( value, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*value = CRYPT_ERROR;

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptHandle;
	cmd.arg[ 1 ] = attributeType;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*value = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

C_RET cryptGetAttributeString( C_IN CRYPT_HANDLE cryptHandle, 
							   C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
							   C_OUT void C_PTR value, 
							   C_OUT int C_PTR valueLength )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GETATTRIBUTE, COMMAND_FLAG_NONE, 3, 0,
		  { 0, 0, TRUE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_V, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) && cryptHandle != CRYPT_UNUSED )
		return( CRYPT_ERROR_PARAM1 );
	if( attributeType <= CRYPT_ATTRIBUTE_NONE || attributeType >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrWrite( valueLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM4 );
	*valueLength = CRYPT_ERROR;
	if( value != NULL )
		*( ( BYTE * ) value ) = '\0';

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	if( value == NULL )
		cmd.flags = COMMAND_FLAG_LENGTHONLY;
	cmd.arg[ 0 ] = cryptHandle;
	cmd.arg[ 1 ] = attributeType;
	cmd.strArg[ 0 ] = value;
	cmd.strArgLen[ 0 ] = 0;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*valueLength = ( value == NULL ) ? cmd.arg[ 0 ] : cmd.strArgLen[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Set an attribute */

C_RET cryptSetAttribute( C_IN CRYPT_HANDLE cryptHandle, 
						 C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
						 C_IN int value )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_SETATTRIBUTE, COMMAND_FLAG_NONE, 3, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_V, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) && cryptHandle != CRYPT_UNUSED )
		return( CRYPT_ERROR_PARAM1 );
	if( attributeType <= CRYPT_ATTRIBUTE_NONE || attributeType >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptHandle;
	cmd.arg[ 1 ] = attributeType;
	cmd.arg[ 2 ] = value;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptSetAttributeString( C_IN CRYPT_HANDLE cryptHandle, 
							   C_IN CRYPT_ATTRIBUTE_TYPE attributeType,
							   C_IN void C_PTR value, C_IN int valueLength )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_SETATTRIBUTE, COMMAND_FLAG_NONE, 2, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_V, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) && cryptHandle != CRYPT_UNUSED )
		return( CRYPT_ERROR_PARAM1 );
	if( attributeType <= CRYPT_ATTRIBUTE_NONE || attributeType >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrRead( value, 1 ) )
		return( CRYPT_ERROR_PARAM3 );
	if( attributeType == CRYPT_CTXINFO_KEY_COMPONENTS )
		{
		/* Public key components constitute a special case since the 
		   composite structures used are quite large */
		if( valueLength != sizeof( CRYPT_PKCINFO_RSA ) && \
			valueLength != sizeof( CRYPT_PKCINFO_DLP ) ) 
			return( CRYPT_ERROR_PARAM4 );
		}
	else
		if( valueLength < 1 || valueLength > MAX_ATTRIBUTE_SIZE ) 
			return( CRYPT_ERROR_PARAM4 );
	if( checkBadPtrRead( value, valueLength ) )
		return( CRYPT_ERROR_PARAM3 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptHandle;
	cmd.arg[ 1 ] = attributeType;
	cmd.strArg[ 0 ] = ( void * ) value;
	cmd.strArgLen[ 0 ] = valueLength;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Delete an attribute */

C_RET cryptDeleteAttribute( C_IN CRYPT_HANDLE cryptHandle, 
							C_IN CRYPT_ATTRIBUTE_TYPE attributeType )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_DELETEATTRIBUTE, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_V, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptHandle ) && cryptHandle != CRYPT_UNUSED )
		return( CRYPT_ERROR_PARAM1 );
	if( attributeType <= CRYPT_ATTRIBUTE_NONE || attributeType >= CRYPT_ATTRIBUTE_LAST )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptHandle;
	cmd.arg[ 1 ] = attributeType;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/****************************************************************************
*																			*
*								Encryption Functions						*
*																			*
****************************************************************************/

/* Generate a key into an encryption context */

C_RET cryptGenerateKey( C_IN CRYPT_CONTEXT cryptContext )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GENKEY, COMMAND_FLAG_NONE, 2, 0,
		  { 0, CRYPT_USE_DEFAULT } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptGenerateKeyEx( C_IN CRYPT_CONTEXT cryptContext,
						  C_IN int keyLength )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GENKEY, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );
	if( keyLength < bitsToBytes( MIN_KEYSIZE_BITS ) || \
		keyLength > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	cmd.arg[ 1 ] = keyLength;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Asynchronous key generate operations */

C_RET cryptGenerateKeyAsync( C_IN CRYPT_CONTEXT cryptContext )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GENKEY, COMMAND_FLAG_NONE, 3, 0,
		  { 0, CRYPT_USE_DEFAULT, TRUE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptGenerateKeyAsyncEx( C_IN CRYPT_CONTEXT cryptContext,
							   C_IN int keyLength )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GENKEY, COMMAND_FLAG_NONE, 3, 0,
		  { 0, 0, TRUE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );
	if( keyLength < bitsToBytes( MIN_KEYSIZE_BITS ) || \
		keyLength > CRYPT_MAX_PKCSIZE )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	cmd.arg[ 1 ] = keyLength;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Query the status of an asynchronous operation.  This has more or less the
   same effect as calling any other operation (both will return 
   CRYPT_ERROR_BUSY if the context is busy), but this is a pure query 
   function with no other side effects */

C_RET cryptAsyncQuery( C_IN CRYPT_CONTEXT cryptContext )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_ASYNCOP, COMMAND_FLAG_NONE, 2, 0,
		  { 0, FALSE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Cancel an asynchronous operation on a context */

C_RET cryptAsyncCancel( C_IN CRYPT_CONTEXT cryptContext )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_ASYNCOP, COMMAND_FLAG_NONE, 2, 0,
		  { 0, TRUE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Encrypt/decrypt data */

C_RET cryptEncrypt( C_IN CRYPT_CONTEXT cryptContext, 
					C_INOUT void C_PTR buffer,
					C_IN int length )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_ENCRYPT, COMMAND_FLAG_NONE, 1, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );
	if( length < 0 )
		return( CRYPT_ERROR_PARAM3 );
	if( checkBadPtrRead( buffer, length ) )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	cmd.strArg[ 0 ] = buffer;
	cmd.strArgLen[ 0 ] = length;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptDecrypt( C_IN CRYPT_CONTEXT cryptContext, 
					C_INOUT void C_PTR buffer,
					C_IN int length )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_DECRYPT, COMMAND_FLAG_NONE, 1, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_S, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( cryptContext ) )
		return( CRYPT_ERROR_PARAM1 );
	if( length < 0 )
		return( CRYPT_ERROR_PARAM3 );
	if( checkBadPtrRead( buffer, length ) )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = cryptContext;
	cmd.strArg[ 0 ] = buffer;
	cmd.strArgLen[ 0 ] = length;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Sign/sig.check a certificate object.  The possibilities for signing are as 
   follows:

						Signer
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert
		  |					   |
	Chain | Chain, length = 2  | Chain, length = n+1 

   For sig.checking the cert object is checked against an issuing key/
   certificate or against a CRL, either as a raw CRL or a keyset contain 
   revocation information */

C_RET cryptSignCert( C_IN CRYPT_CERTIFICATE certificate,
					 C_IN CRYPT_CONTEXT signContext )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CERTSIGN, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( certificate ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !checkHandleRange( signContext ) )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = certificate;
	cmd.arg[ 1 ] = signContext;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptCheckCert( C_IN CRYPT_HANDLE certificate,
					  C_IN CRYPT_HANDLE sigCheckKey )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CERTCHECK, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( certificate ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !checkHandleRange( sigCheckKey ) && ( sigCheckKey != CRYPT_UNUSED ) )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = certificate;
	cmd.arg[ 1 ] = sigCheckKey;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Import/export a certificate, CRL, certification request, or cert chain.
   In the export case this just copies the internal encoded object to an
   external buffer.  For cert/cert chain export the possibilities are as
   follows:

						Export
	Type  |		Cert				Chain
	------+--------------------+---------------
	Cert  | Cert			   | Cert as chain
		  |					   |
	Chain | Currently selected | Chain
		  | cert in chain	   | */

C_RET cryptImportCert( C_IN void C_PTR certObject, 
					   C_IN int certObjectLength,
					   C_OUT CRYPT_CERTIFICATE C_PTR certificate )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_CREATEOBJECT_INDIRECT, COMMAND_FLAG_NONE, 2, 1,
		  { SYSTEM_OBJECT_HANDLE, OBJECT_TYPE_CERTIFICATE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_S, ARG_N, ARG_D, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( certObjectLength < MIN_CERTSIZE )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrRead( certObject, certObjectLength ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( certificate, sizeof( CRYPT_CERTIFICATE ) ) )
		return( CRYPT_ERROR_PARAM3 );
	*certificate = CRYPT_ERROR;

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.strArg[ 0 ] = ( void * ) certObject;
	cmd.strArgLen[ 0 ] = certObjectLength;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*certificate = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

C_RET cryptExportCert( C_OUT void C_PTR certObject, 
					   C_OUT int C_PTR certObjectLength,
					   C_IN CRYPT_CERTFORMAT_TYPE certFormatType,
					   C_IN CRYPT_HANDLE certificate )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_EXPORTOBJECT, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_D, ARG_D, ARG_N, ARG_O, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( certObject != NULL )
		{
		if( checkBadPtrWrite( certObject, MIN_CERTSIZE ) )
			return( CRYPT_ERROR_PARAM1 );
		memset( certObject, 0, MIN_CERTSIZE );
		}
	if( checkBadPtrWrite( certObjectLength, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*certObjectLength = CRYPT_ERROR;
	if( certFormatType <= CRYPT_CERTFORMAT_NONE || \
		certFormatType >= CRYPT_CERTFORMAT_LAST )
		return( CRYPT_ERROR_PARAM3 );
	if( !checkHandleRange( certificate ) )
		return( CRYPT_ERROR_PARAM4 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	if( certObject == NULL )
		cmd.flags = COMMAND_FLAG_LENGTHONLY;
	cmd.arg[ 0 ] = certificate;
	cmd.arg[ 1 ] = certFormatType;
	cmd.strArg[ 0 ] = certObject;
	cmd.strArgLen[ 0 ] = 0;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*certObjectLength = ( certObject == NULL ) ? \
							cmd.arg[ 0 ] : cmd.strArgLen[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/****************************************************************************
*																			*
*								Envelope Functions							*
*																			*
****************************************************************************/

/* Push data into an envelope/session object */

C_RET cryptPushData( C_IN CRYPT_HANDLE envelope, C_IN void C_PTR buffer,
					 C_IN int length, C_OUT int C_PTR bytesCopied )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_PUSHDATA, COMMAND_FLAG_NONE, 1, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_S, ARG_N, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int dummy, status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( envelope ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !length )
		{
		if( buffer != NULL )
			return( CRYPT_ERROR_PARAM2 );

		/* If the user isn't interested in the bytes copied count, point at a
		   dummy location */
		if( bytesCopied == NULL )
			bytesCopied = &dummy;
		}
	else
		{
		if( checkBadPtrRead( buffer, length ) )
			return( CRYPT_ERROR_PARAM2 );
		if( length < 0 )
			return( CRYPT_ERROR_PARAM3 );
		if( checkBadPtrWrite( bytesCopied, sizeof( int ) ) )
			return( CRYPT_ERROR_PARAM4 );
		}
	*bytesCopied = 0;

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = envelope;
	cmd.strArg[ 0 ] = ( void * ) buffer;
	cmd.strArgLen[ 0 ] = length;
	status = dispatchCommand( &cmd );
	*bytesCopied = cmd.arg[ 0 ];
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Pop data from an envelope/session object */

C_RET cryptPopData( C_IN CRYPT_ENVELOPE envelope, C_OUT void C_PTR buffer,
					C_IN int length, C_OUT int C_PTR bytesCopied )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_POPDATA, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_S, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( envelope ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( buffer, length ) )
		return( CRYPT_ERROR_PARAM2 );
	if( length <= 0 )
		return( CRYPT_ERROR_PARAM3 );
	memset( buffer, 0, min( length, 16 ) );
	if( checkBadPtrWrite( bytesCopied, sizeof( int ) ) )
		return( CRYPT_ERROR_PARAM4 );
	*bytesCopied = 0;

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = envelope;
	cmd.arg[ 1 ] = length;
	cmd.strArg[ 0 ] = ( void * ) buffer;
	cmd.strArgLen[ 0 ] = length;
	status = dispatchCommand( &cmd );
	*bytesCopied = cmd.arg[ 0 ];
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/****************************************************************************
*																			*
*								Keyset Functions							*
*																			*
****************************************************************************/

/* Retrieve a key from a keyset or equivalent object */

C_RET cryptGetPublicKey( C_IN CRYPT_KEYSET keyset,
						 C_OUT CRYPT_HANDLE C_PTR cryptKey,
						 C_IN CRYPT_KEYID_TYPE keyIDtype,
						 C_IN void C_PTR keyID )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GETKEY, COMMAND_FLAG_NONE, 2, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_D, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking.  Because of keyset queries 
	   we have to accept CRYPT_KEYID_NONE and a null keyID as well as 
	   obviously valid key ID's */
	if( !checkHandleRange( keyset ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( cryptKey, sizeof( CRYPT_HANDLE ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*cryptKey = CRYPT_ERROR;
	if( keyIDtype < CRYPT_KEYID_NONE || \
		keyIDtype >= CRYPT_KEYID_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM3 );
	if( keyIDtype == CRYPT_KEYID_NONE )
		{
		if( keyID != NULL )
			return( CRYPT_ERROR_PARAM4 );
		}
	else
		if( keyID == NULL || checkBadPtrRead( keyID, 2 ) || \
			strlen( keyID ) >= MAX_ATTRIBUTE_SIZE )
			return( CRYPT_ERROR_PARAM4 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = keyset;
	cmd.arg[ 1 ] = keyIDtype;
	cmd.strArg[ 0 ] = ( void * ) keyID;
	if( keyID != NULL )
		cmd.strArgLen[ 0 ] = strlen( keyID );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*cryptKey = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

C_RET cryptGetPrivateKey( C_IN CRYPT_HANDLE keyset,
						  C_OUT CRYPT_CONTEXT C_PTR cryptContext,
						  C_IN CRYPT_KEYID_TYPE keyIDtype,
						  C_IN void C_PTR keyID, C_IN void C_PTR password )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_GETKEY, COMMAND_FLAG_NONE, 2, 2 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_D, ARG_N, ARG_S, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( keyset ) )
		return( CRYPT_ERROR_PARAM1 );
	if( checkBadPtrWrite( cryptContext, sizeof( CRYPT_CONTEXT ) ) )
		return( CRYPT_ERROR_PARAM2 );
	*cryptContext = CRYPT_ERROR;
	if( keyIDtype <= CRYPT_KEYID_NONE || \
		keyIDtype >= CRYPT_KEYID_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM3 );
	if( checkBadPtrRead( keyID, 2 ) || \
		strlen( keyID ) >= MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ERROR_PARAM4 );
	if( password != NULL && \
		( checkBadPtrRead( password, 2 ) || \
		  strlen( password ) >= MAX_ATTRIBUTE_SIZE ) )
		return( CRYPT_ERROR_PARAM5 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = keyset;
	cmd.arg[ 1 ] = keyIDtype;
	cmd.strArg[ 0 ] = ( void * ) keyID;
	cmd.strArgLen[ 0 ] = strlen( keyID );
	cmd.strArg[ 1 ] = ( void * ) password;
	if( password != NULL )
		cmd.strArgLen[ 1 ] = strlen( password );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		{
		*cryptContext = cmd.arg[ 0 ];
		return( CRYPT_OK );
		}
	return( mapError( errorMap, status ) );
	}

/* Add a key from a keyset or equivalent object */

C_RET cryptAddPublicKey( C_IN CRYPT_KEYSET keyset,
						 C_IN CRYPT_CERTIFICATE certificate )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_SETKEY, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( keyset ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !checkHandleRange( certificate ) )
		return( CRYPT_ERROR_PARAM2 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = keyset;
	cmd.arg[ 1 ] = certificate;
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptAddPrivateKey( C_IN CRYPT_KEYSET keyset,
						  C_IN CRYPT_HANDLE cryptKey,
						  C_IN void C_PTR password )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_SETKEY, COMMAND_FLAG_NONE, 2, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( keyset ) )
		return( CRYPT_ERROR_PARAM1 );
	if( !checkHandleRange( cryptKey ) )
		return( CRYPT_ERROR_PARAM2 );
	if( password != NULL && \
		( checkBadPtrRead( password, 2 ) || checkBadPassword( password ) || \
		  strlen( password ) >= MAX_ATTRIBUTE_SIZE ) )
		return( CRYPT_ERROR_PARAM3 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = keyset;
	cmd.arg[ 1 ] = cryptKey;
	cmd.strArg[ 0 ] = ( void * ) password;
	if( password != NULL )
		cmd.strArgLen[ 0 ] = strlen( password );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/* Delete a key from a keyset or equivalent object */

C_RET cryptDeleteKey( C_IN CRYPT_KEYSET keyset,
					  C_IN CRYPT_KEYID_TYPE keyIDtype,
					  C_IN void C_PTR keyID )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_DELETEKEY, COMMAND_FLAG_NONE, 2, 1 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( keyset ) )
		return( CRYPT_ERROR_PARAM1 );
	if( keyIDtype <= CRYPT_KEYID_NONE || \
		keyIDtype >= CRYPT_KEYID_LAST_EXTERNAL )
		return( CRYPT_ERROR_PARAM2 );
	if( checkBadPtrRead( keyID, 2 ) || \
		strlen( keyID ) > MAX_ATTRIBUTE_SIZE )
		return( CRYPT_ERROR_PARAM3 );

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	cmd.arg[ 0 ] = keyset;
	cmd.arg[ 1 ] = keyIDtype;
	cmd.strArg[ 0 ] = ( void * ) keyID;
	cmd.strArgLen[ 0 ] = strlen( keyID );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

/****************************************************************************
*																			*
*									Misc Functions							*
*																			*
****************************************************************************/

/* cryptlib/object query functions */

C_RET cryptQueryCapability( C_IN CRYPT_ALGO cryptAlgo,
							C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_QUERYCAPABILITY, COMMAND_FLAG_NONE, 2, 0,
		  { SYSTEM_OBJECT_HANDLE } };
	static const ERRORMAP errorMap[] = \
		{ ARG_N, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_ERROR_PARAM1 );
	if( cryptQueryInfo != NULL )
		{
		if( checkBadPtrWrite( cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) ) )
			return( CRYPT_ERROR_PARAM3 );
		memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
		}

	/* Dispatch the command.  We need to map parameter errors down one 
	   because the system object is invisible to the caller */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	if( cryptQueryInfo == NULL )
		cmd.flags = COMMAND_FLAG_LENGTHONLY;
	cmd.arg[ 1 ] = cryptAlgo;
	cmd.strArg[ 0 ] = cryptQueryInfo;
	cmd.strArgLen[ 0 ] = sizeof( CRYPT_QUERY_INFO );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}

C_RET cryptDeviceQueryCapability( C_IN CRYPT_DEVICE device,
								  C_IN CRYPT_ALGO cryptAlgo,
								  C_OUT CRYPT_QUERY_INFO C_PTR cryptQueryInfo )
	{
	static const COMMAND_INFO cmdTemplate = \
		{ COMMAND_QUERYCAPABILITY, COMMAND_FLAG_NONE, 2, 0 };
	static const ERRORMAP errorMap[] = \
		{ ARG_O, ARG_N, ARG_N, ARG_S, ARG_LAST };
	COMMAND_INFO cmd;
	int status;

	/* Perform basic client-side error checking */
	if( !checkHandleRange( device ) )
		return( CRYPT_ERROR_PARAM1 );
	if( cryptAlgo < CRYPT_ALGO_NONE || cryptAlgo >= CRYPT_ALGO_LAST )
		return( CRYPT_ERROR_PARAM2 );
	if( cryptQueryInfo != NULL )
		{
		if( checkBadPtrWrite( cryptQueryInfo, sizeof( CRYPT_QUERY_INFO ) ) )
			return( CRYPT_ERROR_PARAM4 );
		memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) );
		}

	/* Dispatch the command */
	memcpy( &cmd, &cmdTemplate, sizeof( COMMAND_INFO ) );
	if( cryptQueryInfo == NULL )
		cmd.flags = COMMAND_FLAG_LENGTHONLY;
	cmd.arg[ 0 ] = device;
	cmd.arg[ 1 ] = cryptAlgo;
	cmd.strArg[ 0 ] = cryptQueryInfo;
	cmd.strArgLen[ 0 ] = sizeof( CRYPT_QUERY_INFO );
	status = dispatchCommand( &cmd );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );
	return( mapError( errorMap, status ) );
	}
