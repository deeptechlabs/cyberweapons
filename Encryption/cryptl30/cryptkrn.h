/****************************************************************************
*																			*
*					  cryptlib Kernel Interface Header File 				*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _CRYPTKRN_DEFINED

#define _CRYPTKRN_DEFINED

/****************************************************************************
*																			*
*							Object Message Types							*
*																			*
****************************************************************************/

/* The object types */

typedef enum {
	OBJECT_TYPE_NONE,				/* No object type */
	OBJECT_TYPE_CONTEXT,			/* Context */
	OBJECT_TYPE_KEYSET,				/* Keyset */
	OBJECT_TYPE_ENVELOPE,			/* Envelope */
	OBJECT_TYPE_CERTIFICATE,		/* Certificate */
	OBJECT_TYPE_DEVICE,				/* Crypto device */
	OBJECT_TYPE_SESSION,			/* Secure session */
	OBJECT_TYPE_LAST				/* Last object type */
	} OBJECT_TYPE;

/* Object subtypes.  The subtype names aren't needed by the kernel (it just 
   treats the values as an anonymous bitfield during an ACL check) but they 
   are used in the ACL definitions and by the code which calls 
   krnlCreateObject(), so they need to be defined here */

#define SUBTYPE_CTX_CONV		0x00000001L
#define SUBTYPE_CTX_PKC			0x00000002L
#define SUBTYPE_CTX_HASH		0x00000004L
#define SUBTYPE_CTX_MAC			0x00000008L

#define SUBTYPE_CERT_CERT		0x00000010L
#define SUBTYPE_CERT_CERTREQ	0x00000020L
#define SUBTYPE_CERT_CRMFREQ	0x00000040L
#define SUBTYPE_CERT_CERTCHAIN	0x00000080L
#define SUBTYPE_CERT_ATTRCERT	0x00000100L
#define SUBTYPE_CERT_CRL		0x00000200L
#define SUBTYPE_CERT_CMSATTR	0x00000400L

#define SUBTYPE_KEYSET_FILE		0x00001000L
#define SUBTYPE_KEYSET_DBMS		0x00002000L
#define SUBTYPE_KEYSET_HTTP		0x00004000L
#define SUBTYPE_KEYSET_LDAP		0x00008000L
#define SUBTYPE_KEYSET_SCARD	0x00010000L

#define SUBTYPE_ENV_ENV			0x00100000L
#define SUBTYPE_ENV_DEENV		0x00200000L

#define SUBTYPE_DEV_FORTEZZA	0x00400000L
#define SUBTYPE_DEV_PKCS11		0x00800000L

#define SUBTYPE_SESSION_SSH		0x01000000L
#define SUBTYPE_SESSION_SSL		0x02000000L
#define SUBTYPE_SESSION_TLS		0x04000000L
#define SUBTYPE_SESSION_CMP		0x08000000L

#define SUBTYPE_ANY				-1		/* Generic any-type */

/* Message flags.  Normally messages can only be sent to external objects, 
   however we can also explicitly send them to internal objects which means 
   the external access ACL isn't checked.  This can only be done from inside 
   cryptlib, for example when an object sends a message to a subordinate 
   object */

#define RESOURCE_MESSAGE_INTERNAL	0x100
#define MKINTERNAL( message )		( message | RESOURCE_MESSAGE_INTERNAL )

/* A mask to extract the basic message type */

#define RESOURCE_MESSAGE_MASK		0xFF

/* The message types which can be sent to an object via krnlSendMessage().  
   By default messages can only be sent to externally visible objects, there 
   are also internal versions which can be sent to all objects.  
   
   The declaration has to be here because it's needed for the object table 
   declaration.

   The object messages have the following arguments:

	Type								DataPtr			Value
	---------------------------			-------			-----
	MESSAGE_DESTROY						NULL			0
	MESSAGE_INC/DECREFCOUNT				NULL			0
	MESSAGE_GETDEPENDENT				&objectHandle	objectType
	MESSAGE_SETDEPENDENT				&objectHandle	incRefCount
	MESSAGE_GET/SETATTRIBUTE			&value			attributeType
	MESSAGE_DELETEATTRIBUTE				NULL			attributeType
	MESSAGE_COMPARE						&value			compareType
	MESSAGE_CLONE						&clonedHandle	0
	MESSAGE_CHECK						NULL			requestedUse
	MESSAGE_LOCK/UNLOCK					NULL			0

	MESSAGE_CHANGENOTIFY				&value			attributeType
										Data from message which triggered the
										changeNotify

	MESSAGE_CTX_ENC/DEC/SIG/SIGCHK/HASH	&value			valueLength
	MESSAGE_CTX_GENKEY					&keySize		isAsync
	MESSAGE_CTX_GENIV					NULL			0

	MESSAGE_CRT_SIGN,					NULL			sigKey
	MESSAGE_CRT_SIGCHECK,				NULL			verifyObject

	MESSAGE_DEV_QUERYCAPABILITY			&queryInfo		algorithm
	MESSAGE_DEV_EXP/IMP/SIG/SIGCHK/DER	&mechanismInfo	mechanismType
	MESSAGE_DEV_CREATEOBJECT			&createInfo		objectType

	MESSAGE_ENV_PUSH/POPDATA			&value			0

	MESSAGE_KEY_GET/DELETEKEY			&keymgmtInfo	0
	MESSAGE_KEY_SETKEY					&keymgmtInfo	key
	MESSAGE_KEY_GETNEXTCERT				&keymgmtInfo	0 */

typedef enum {
	RESOURCE_MESSAGE_NONE,				/* No message */

	/* Control messages to externally visible objects.  These messages are
	   handled directly by the kernel and don't affect the object itself.  If 
	   the object status is anything other than CRYPT_OK then any attempt to
	   send a non-control message to it will return the object status as an 
	   error code.  This is because it's possible to perform control 
	   functions which are handled by the kernel on an object in an abnormal
	   state (eg busy, signalled, notinited), but it's not possible to use it
	   in a normal manner */
	RESOURCE_MESSAGE_DESTROY,			/* Destroy the object */
	RESOURCE_MESSAGE_INCREFCOUNT,		/* Increment object ref.count */
	RESOURCE_MESSAGE_DECREFCOUNT,		/* Decrement object ref.count */
	RESOURCE_MESSAGE_GETDEPENDENT,		/* Get dependent object */
	RESOURCE_MESSAGE_SETDEPENDENT,		/* Set dependent object (eg ctx->dev) */

	/* General messages to externally visible objects.  The reason for the
	   numeric vs non-numeric attribute messages is that the data types 
	   these work with are explicitly specified by the user based on which
	   function they call to get/set them rather than being implicitly 
	   specified by the attribute ID.  Because of the explicit typing, the 
	   handlers have to be able to check to make sure the actual type matches
	   what the user specified, so we need one message type for numeric
	   attributes and one for string attributes.
	   
	   The check message is used for informational purposes only so that 
	   problems (eg attempt to use a public key where a private key is 
	   required) can be reported to the user immediately as a function 
	   parameter error rather than appearing much later as an object use 
	   permission error when the kernel blocks the access.  Actual access
	   checking is still done at the kernel level to avoid the confused 
	   deputy problem */
	RESOURCE_MESSAGE_GETATTRIBUTE,		/* Get numeric object attribute */
	RESOURCE_MESSAGE_GETATTRIBUTE_S,	/* Get string object attribute */
	RESOURCE_MESSAGE_SETATTRIBUTE,		/* Set numeric object attribute */
	RESOURCE_MESSAGE_SETATTRIBUTE_S,	/* Set string object attribute */
	RESOURCE_MESSAGE_DELETEATTRIBUTE,	/* Delete object attribute */
	RESOURCE_MESSAGE_COMPARE,			/* Compare objs. or obj.properties */
	RESOURCE_MESSAGE_CLONE,				/* Clone the object */
	RESOURCE_MESSAGE_CHECK,				/* Check object info */
	RESOURCE_MESSAGE_LOCK,				/* Lock object for exclusive use */
	RESOURCE_MESSAGE_UNLOCK,			/* Unlock object */

	/* Messages sent from the kernel to object message handlers (these never
	   originate from outside the kernel) */
	RESOURCE_MESSAGE_CHANGENOTIFY,		/* Notification of obj.status chge.*/

	/* Object-type-specific messages */
	RESOURCE_MESSAGE_CTX_ENCRYPT,		/* Context: Action = encrypt */
	RESOURCE_MESSAGE_CTX_DECRYPT,		/* Context: Action = decrypt */
	RESOURCE_MESSAGE_CTX_SIGN,			/* Context: Action = sign */
	RESOURCE_MESSAGE_CTX_SIGCHECK,		/* Context: Action = sigcheck */
	RESOURCE_MESSAGE_CTX_HASH,			/* Context: Action = hash */
	RESOURCE_MESSAGE_CTX_GENKEY,		/* Context: Generate a key */
	RESOURCE_MESSAGE_CTX_GENIV,			/* Context: Generate an IV */
	RESOURCE_MESSAGE_CRT_SIGN,			/* Cert: Action = sign cert */
	RESOURCE_MESSAGE_CRT_SIGCHECK,		/* Cert: Action = check/verify cert */
	RESOURCE_MESSAGE_DEV_QUERYCAPABILITY,/* Device: Query capability */
	RESOURCE_MESSAGE_DEV_EXPORT,		/* Device: Action = export key */
	RESOURCE_MESSAGE_DEV_IMPORT,		/* Device: Action = import key */
	RESOURCE_MESSAGE_DEV_SIGN,			/* Device: Action = sign */
	RESOURCE_MESSAGE_DEV_SIGCHECK,		/* Device: Action = sig.check */
	RESOURCE_MESSAGE_DEV_DERIVE,		/* Device: Action = derive key */
	RESOURCE_MESSAGE_DEV_CREATEOBJECT,	/* Device: Create object */
	RESOURCE_MESSAGE_ENV_PUSHDATA,		/* Envelope: Push data */
	RESOURCE_MESSAGE_ENV_POPDATA,		/* Envelope: Pop data */
	RESOURCE_MESSAGE_KEY_GETKEY,		/* Keyset: Instantiate ctx/cert */
	RESOURCE_MESSAGE_KEY_SETKEY,		/* Keyset: Add ctx/cert */
	RESOURCE_MESSAGE_KEY_DELETEKEY,		/* Keyset: Delete key/cert */
	RESOURCE_MESSAGE_KEY_GETNEXTCERT,	/* Keyset: Get certs in cert chain */
	RESOURCE_MESSAGE_LAST,				/* Last valid message type */

	/* Messages to all (including internal) object types */
	RESOURCE_IMESSAGE_DESTROY = MKINTERNAL( RESOURCE_MESSAGE_DESTROY ),
	RESOURCE_IMESSAGE_INCREFCOUNT = MKINTERNAL( RESOURCE_MESSAGE_INCREFCOUNT ),
	RESOURCE_IMESSAGE_DECREFCOUNT = MKINTERNAL( RESOURCE_MESSAGE_DECREFCOUNT ),

	RESOURCE_IMESSAGE_GETATTRIBUTE = MKINTERNAL( RESOURCE_MESSAGE_GETATTRIBUTE ),
	RESOURCE_IMESSAGE_GETATTRIBUTE_S = MKINTERNAL( RESOURCE_MESSAGE_GETATTRIBUTE_S ),
	RESOURCE_IMESSAGE_SETATTRIBUTE = MKINTERNAL( RESOURCE_MESSAGE_SETATTRIBUTE ),
	RESOURCE_IMESSAGE_SETATTRIBUTE_S = MKINTERNAL( RESOURCE_MESSAGE_SETATTRIBUTE_S ),
	RESOURCE_IMESSAGE_DELETEATTRIBUTE = MKINTERNAL( RESOURCE_MESSAGE_DELETEATTRIBUTE ),
	RESOURCE_IMESSAGE_GETDEPENDENT = MKINTERNAL( RESOURCE_MESSAGE_GETDEPENDENT ),
	RESOURCE_IMESSAGE_SETDEPENDENT = MKINTERNAL( RESOURCE_MESSAGE_SETDEPENDENT ),
	RESOURCE_IMESSAGE_COMPARE = MKINTERNAL( RESOURCE_MESSAGE_COMPARE ),
	RESOURCE_IMESSAGE_CLONE = MKINTERNAL( RESOURCE_MESSAGE_CLONE ),
	RESOURCE_IMESSAGE_CHECK = MKINTERNAL( RESOURCE_MESSAGE_CHECK ),
	RESOURCE_IMESSAGE_LOCK = MKINTERNAL( RESOURCE_MESSAGE_LOCK ),
	RESOURCE_IMESSAGE_UNLOCK = MKINTERNAL( RESOURCE_MESSAGE_UNLOCK ),

	RESOURCE_IMESSAGE_CHANGENOTIFY = MKINTERNAL( RESOURCE_MESSAGE_CHANGENOTIFY ),

	RESOURCE_IMESSAGE_CTX_ENCRYPT = MKINTERNAL( RESOURCE_MESSAGE_CTX_ENCRYPT ),
	RESOURCE_IMESSAGE_CTX_DECRYPT = MKINTERNAL( RESOURCE_MESSAGE_CTX_DECRYPT ),
	RESOURCE_IMESSAGE_CTX_SIGN = MKINTERNAL( RESOURCE_MESSAGE_CTX_SIGN ),
	RESOURCE_IMESSAGE_CTX_SIGCHECK = MKINTERNAL( RESOURCE_MESSAGE_CTX_SIGCHECK ),
	RESOURCE_IMESSAGE_CTX_HASH = MKINTERNAL( RESOURCE_MESSAGE_CTX_HASH ),
	RESOURCE_IMESSAGE_CTX_GENKEY = MKINTERNAL( RESOURCE_MESSAGE_CTX_GENKEY ),
	RESOURCE_IMESSAGE_CTX_GENIV = MKINTERNAL( RESOURCE_MESSAGE_CTX_GENIV ),
	RESOURCE_IMESSAGE_CRT_SIGN = MKINTERNAL( RESOURCE_MESSAGE_CRT_SIGN ),
	RESOURCE_IMESSAGE_CRT_SIGCHECK = MKINTERNAL( RESOURCE_MESSAGE_CRT_SIGCHECK ),
	RESOURCE_IMESSAGE_DEV_QUERYCAPABILITY = MKINTERNAL( RESOURCE_MESSAGE_DEV_QUERYCAPABILITY ),
	RESOURCE_IMESSAGE_DEV_EXPORT = MKINTERNAL( RESOURCE_MESSAGE_DEV_EXPORT ),
	RESOURCE_IMESSAGE_DEV_IMPORT = MKINTERNAL( RESOURCE_MESSAGE_DEV_IMPORT ),
	RESOURCE_IMESSAGE_DEV_SIGN = MKINTERNAL( RESOURCE_MESSAGE_DEV_SIGN ),
	RESOURCE_IMESSAGE_DEV_SIGCHECK = MKINTERNAL( RESOURCE_MESSAGE_DEV_SIGCHECK ),
	RESOURCE_IMESSAGE_DEV_DERIVE = MKINTERNAL( RESOURCE_MESSAGE_DEV_DERIVE ),
	RESOURCE_IMESSAGE_DEV_CREATEOBJECT = MKINTERNAL( RESOURCE_MESSAGE_DEV_CREATEOBJECT ),
	RESOURCE_IMESSAGE_ENV_PUSHDATA = MKINTERNAL( RESOURCE_MESSAGE_ENV_PUSHDATA ),
	RESOURCE_IMESSAGE_ENV_POPDATA = MKINTERNAL( RESOURCE_MESSAGE_ENV_POPDATA ),
	RESOURCE_IMESSAGE_KEY_GETKEY = MKINTERNAL( RESOURCE_MESSAGE_KEY_GETKEY ),
	RESOURCE_IMESSAGE_KEY_SETKEY = MKINTERNAL( RESOURCE_MESSAGE_KEY_SETKEY ),
	RESOURCE_IMESSAGE_KEY_DELETEKEY = MKINTERNAL( RESOURCE_MESSAGE_KEY_DELETEKEY ),
	RESOURCE_IMESSAGE_KEY_GETNEXTCERT = MKINTERNAL( RESOURCE_MESSAGE_KEY_GETNEXTCERT ),
	RESOURCE_IMESSAGE_LAST = MKINTERNAL( RESOURCE_MESSAGE_LAST )
	} RESOURCE_MESSAGE_TYPE;

/* The properties which RESOURCE_MESSAGE_COMPARE can compare */

typedef enum {
	RESOURCE_MESSAGE_COMPARE_NONE,		/* No comparison */
	RESOURCE_MESSAGE_COMPARE_HASH,		/* Compare hash value */
	RESOURCE_MESSAGE_COMPARE_KEYID,		/* Compare key ID */
	RESOURCE_MESSAGE_COMPARE_ISSUERANDSERIALNUMBER,	/* Compare IAndS */
	RESOURCE_MESSAGE_COMPARE_FINGERPRINT,	/* Compare cert.fingerprint */
	RESOURCE_MESSAGE_COMPARE_LAST		/* Last possible compare type */
	} RESOURCE_MESSAGE_COMPARE_TYPE;

/* The checks which RESOURCE_MESSAGE_CHECK performs */

typedef enum {
	RESOURCE_MESSAGE_CHECK_NONE,		/* No check */
	RESOURCE_MESSAGE_CHECK_PKC,			/* Public or private key context */
	RESOURCE_MESSAGE_CHECK_PKC_PRIVATE,	/* Private key context */
	RESOURCE_MESSAGE_CHECK_PKC_ENCRYPT,	/* Public encryption context */
	RESOURCE_MESSAGE_CHECK_PKC_DECRYPT,	/* Private decryption context */
	RESOURCE_MESSAGE_CHECK_PKC_SIGCHECK,/* Public signature check context */
	RESOURCE_MESSAGE_CHECK_PKC_SIGN,	/* Private signature context */
	RESOURCE_MESSAGE_CHECK_PKC_KA_EXPORT,/* Key agreement - export context */
	RESOURCE_MESSAGE_CHECK_PKC_KA_IMPORT,/* Key agreement - import context */
	RESOURCE_MESSAGE_CHECK_CRYPT,		/* Conventional encryption context */
	RESOURCE_MESSAGE_CHECK_HASH,		/* Hash context */
	RESOURCE_MESSAGE_CHECK_MAC,			/* MAC context */
	RESOURCE_MESSAGE_CHECK_KEYGEN,		/* Key generation capability */
	RESOURCE_MESSAGE_CHECK_LAST			/* Last possible check type */
	} RESOURCE_MESSAGE_CHECK_TYPE;

/* When getting/setting data, the information may be a variable-length string
   rather than a simple integer value, which would require two calls (one to
   communicate the length and one for the data).  To avoid this, we pass a
   pointer to a data-and-length structure rather than a pointer to the data */

typedef struct {
	void *data;							/* Data */
	int length;							/* Length */
	} RESOURCE_DATA;

#define setResourceData( resDataPtr, dataPtr, dataLength ) \
	{ \
	memset( ( resDataPtr ), 0, sizeof( RESOURCE_DATA ) ); \
	( resDataPtr )->data = ( dataPtr ); \
	( resDataPtr )->length = ( dataLength ); \
	}

/* Some messages communicate standard data values which are used again and 
   again so we predefine values for these which can be used globally */

#define MESSAGE_VALUE_TRUE			( ( void * ) &messageValueTrue )
#define MESSAGE_VALUE_FALSE			( ( void * ) &messageValueFalse )
#define MESSAGE_VALUE_OK			( ( void * ) &messageValueCryptOK )
#define MESSAGE_VALUE_ERROR			( ( void * ) &messageValueCryptError )
#define MESSAGE_VALUE_SIGNALLED		( ( void * ) &messageValueCryptSignalled )
#define MESSAGE_VALUE_UNUSED		( ( void * ) &messageValueCryptUnused )
#define MESSAGE_VALUE_DEFAULT		( ( void * ) &messageValueCryptUseDefault )
#define MESSAGE_VALUE_CURSORFIRST	( ( void * ) &messageValueCursorFirst )
#define MESSAGE_VALUE_CURSORNEXT	( ( void * ) &messageValueCursorNext )
#define MESSAGE_VALUE_CURSORPREVIOUS ( ( void * ) &messageValueCursorPrevious )
#define MESSAGE_VALUE_CURSORLAST	( ( void * ) &messageValueCursorLast )

extern const int messageValueTrue, messageValueFalse;
extern const int messageValueCryptOK, messageValueCryptError;
extern const int messageValueCryptSignalled;
extern const int messageValueCryptUnused, messageValueCryptUseDefault;
extern const int messageValueCursorFirst, messageValueCursorNext;
extern const int messageValueCursorPrevious, messageValueCursorLast;

/* Test for membership within an attribute class */

#define isAttribute( attribute ) \
	( ( attribute ) > CRYPT_ATTRIBUTE_NONE && \
	  ( attribute ) < CRYPT_ATTRIBUTE_LAST )
#define isOptionAttribute( attribute ) \
	( ( attribute ) > CRYPT_OPTION_FIRST && \
	  ( attribute ) < CRYPT_OPTION_LAST )
#define isInternalAttribute( attribute ) \
	( ( attribute ) > CRYPT_IATTRIBUTE_FIRST && \
	  ( attribute ) < CRYPT_IATTRIBUTE_LAST )

/* Check whether a message is in a given message class */

#define isAttributeMessage( message ) \
	( ( message ) >= RESOURCE_MESSAGE_GETATTRIBUTE && \
	  ( message ) <= RESOURCE_MESSAGE_DELETEATTRIBUTE )
#define isActionMessage( message ) \
	( ( message ) >= RESOURCE_MESSAGE_CTX_ENCRYPT && \
	  ( message ) <= RESOURCE_MESSAGE_CTX_HASH )
#define isMechanismActionMessage( message ) \
	( ( message ) >= RESOURCE_MESSAGE_DEV_EXPORT && \
	  ( message ) <= RESOURCE_MESSAGE_DEV_DERIVE )

/* The following handles correspond to built-in fixed object types which are
   available throughout the architecture.  Currently there is a single
   internal system object which encapsulates the built-in RNG and the built-
   in mechanism types, if this ever becomes a bottleneck the two can be
   separated into different objects */

#define SYSTEM_OBJECT_HANDLE	0	/* Internal system object */

#define NO_SYSTEM_OBJECTS		1	/* Total number of system objects */

/* We limit the maximum number of objects to a sensible value to prevent 
   deliberate/accidental DoS attacks.  The following represents about 64MB
   of object data which should be a good indication that there are more
   objects present than there should be */

#define MAX_OBJECTS				16384

/* Prototype for an objects message-handling function */

typedef int ( *RESOURCE_MESSAGE_FUNCTION )( const int objectHandle,
							const RESOURCE_MESSAGE_TYPE message,
							void *messageDataPtr, const int messageValue );

/****************************************************************************
*																			*
*							Action Message Types							*
*																			*
****************************************************************************/

/* Action messages come in two types, direct action messages and mechanism-
   action messages.  Action messages apply directly to action objects (for
   example transform a block of data) while mechanism-action messages apply
   to device objects and involve extra formatting above and beyond the direct
   action (for example perform PKCS #1 padding and then transform a block of
   data) */

/* Action permissions.  Each object can can have a range of permission 
   settings which control how action messages sent to it are handled.  The
   most common case is that the action isn't available for this object,
   ACTION_PERM_NOTAVAIL.  This is an all-zero permission, so the default is
   deny-all unless the action is explicitly permitted.  The permissions are
   ACTION_PERM_NONE, which means the action is in theory available but has
   been turned off, ACTION_PERM_NONE_EXTERNAL, which means the action is only 
   valid if the message is coming from inside cryptlib, and ACTION_PERM_ALL, 
   which means the action is available for anyone.
   
   The kernel enforces a ratchet for these setting which only allows them to
   be set to a more restrictive value than their existing one.  If a setting
   starts out as not available on object creation, it can never be enabled. 
   If a setting starts as none-external, it can only be set to a straight 
   none, but never to all */

#define ACTION_PERM_NOTAVAIL		0x00
#define ACTION_PERM_NONE			0x01
#define ACTION_PERM_NONE_EXTERNAL	0x02
#define ACTION_PERM_ALL				0x03

#define ACTION_PERM_BASE	RESOURCE_MESSAGE_CTX_ENCRYPT
#define ACTION_PERM_MASK	0x03
#define ACTION_PERM_COUNT	( RESOURCE_MESSAGE_CTX_GENKEY - \
							  RESOURCE_MESSAGE_CTX_ENCRYPT + 1 )
#define ACTION_PERM_LAST	\
		( 1 << ( ( ( ACTION_PERM_COUNT ) * 2 ) + 1 ) )
#define ACTION_PERM_SHIFT( action ) \
		( ( ( action ) - ACTION_PERM_BASE ) * 2 )
#define MK_ACTION_PERM( action, perm ) \
		( ( perm ) << ACTION_PERM_SHIFT( action ) )

/* The mechanism types */

typedef enum {
	MECHANISM_NONE,				/* No mechanism */
	MECHANISM_PKCS1,			/* PKCS #1 sign/encrypt */
	MECHANISM_PKCS5,			/* PKCS #5 derive */
	MECHANISM_CMS,				/* CMS key wrap */
	MECHANISM_KEA,				/* KEA key agreement */
	MECHANISM_OAEP,				/* OAEP encrypt */
	MECHANISM_SSH,				/* ssh key wrap */
	MECHANISM_SSL,				/* SSL derive */
	MECHANISM_TLS,				/* TLS derive */
	MECHANISM_CMP,				/* CMP/Entrust derive */
	MECHANISM_PRIVATEKEYWRAP,	/* Private key wrap */
	MECHANISM_LAST				/* Last valid mechanism type */
	} MECHANISM_TYPE;

/* A structure to hold information needed by the key export/import mechanism.
   The key can be passed as raw key data or as a context if tied to hardware
   which doesn't allow keying material outside the hardware's security 
   perimeter:

	PKCS #1		wrappedData = wrapped key
				keyData = raw key - or -
				keyContext = context containing raw key
				wrapContext = wrap/unwrap PKC context
				auxContext = CRYPT_UNUSED
	CMS			wrappedData = wrapped key
				keyData = raw key - or -
				keyContext = context containing raw key
				wrapContext = wrap/unwrap conventional context
				auxContext = CRYPT_UNUSED
	KEA			wrappedData = len + TEK( MEK ), len + UKM
				keyData = NULL
				keyContext = MEK
				wrapContext = recipient KEA public key
				auxContext = originator KEA private key
	ssh			wrappedData = double-wrapped key
				keyData = raw key
				keyContext = CRYPT_UNUSED
				wrapContext = server PKC key
				auxContext = host PKC key
	Private		wrappedData = Padded encrypted private key components
	key wrap	keyData = -
				keyContext = context containing private key
				wrapContext = wrap/unwrap conventional context
				auxContext = CRYPT_UNUSED */

typedef struct {
	void *wrappedData;			/* Wrapped key */
	int wrappedDataLength;
	void *keyData;				/* Raw key */
	int keyDataLength;
	CRYPT_HANDLE keyContext;	/* Context containing raw key */
	CRYPT_HANDLE wrapContext;	/* Wrap/unwrap context */
	CRYPT_HANDLE auxContext;	/* Auxiliary context */
	} MECHANISM_WRAP_INFO;

/* A structure to hold information needed by the sign/sig check mechanism:

	PKCS #1		signature = signature
				hash, hashAlgo = hash information
				hashContext = CRYPT_UNUSED */

typedef struct {
	void *signature;			/* Signature */
	int signatureLength;
	void *hash;
	int hashLength;				/* Hash */
	CRYPT_ALGO hashAlgo;		/* Hash algo */
	CRYPT_CONTEXT hashContext;
	CRYPT_HANDLE signContext;	/* Signing context */
	} MECHANISM_SIGN_INFO;

/* A structure to hold information needed by the key derive mechanism:

	PKCS #5		dataOut = key data
	CMP			dataIn = password
				salt = salt
				iterations = iteration count
	SSL/TLS		dataOut = key data/master secret
				dataIn = master secret/premaster secret
				salt = client || server random/server || client random
				iterations = CRYPT_UNUSED */

typedef struct {
	void *dataOut;				/* Output keying information */
	int dataOutLength;
	void *dataIn;				/* Input keying information */
	int dataInLength;
	void *salt;					/* Salt/randomiser */
	int saltLength;
	int iterations;				/* Iterations of derivation function */
	} MECHANISM_DERIVE_INFO;

/* Macros to make it easier to work with the mechanism info types.  The 
   shortened name forms in the macro args are necessary to avoid clashes with
   the struct members.  The long lines are necessary because older Borland
   compilers can't handle line breaks at the point in a macro definition */

#define clearMechanismInfo( mechanismInfo ) \
		memset( mechanismInfo, 0, sizeof( *mechanismInfo ) )

#define setMechanismWrapInfo( mechanismInfo, wrapped, wrappedLen, key, keyLen, keyCtx, wrapCtx, auxCtx ) \
		{ \
		( mechanismInfo )->wrappedData = ( wrapped ); \
		( mechanismInfo )->wrappedDataLength = ( wrappedLen ); \
		( mechanismInfo )->keyData = ( key ); \
		( mechanismInfo )->keyDataLength = ( keyLen ); \
		( mechanismInfo )->keyContext = ( keyCtx ); \
		( mechanismInfo )->wrapContext = ( wrapCtx ); \
		( mechanismInfo )->auxContext = ( auxCtx ); \
		}

#define setMechanismSignInfo( mechanismInfo, sig, sigLen, hashVal, hashValLen, hAlgo, hashCtx, signCtx ) \
		{ \
		( mechanismInfo )->signature = ( sig ); \
		( mechanismInfo )->signatureLength = ( sigLen ); \
		( mechanismInfo )->hash = ( hashVal ); \
		( mechanismInfo )->hashLength = ( hashValLen ); \
		( mechanismInfo )->hashAlgo = ( hAlgo ); \
		( mechanismInfo )->hashContext = ( hashCtx ); \
		( mechanismInfo )->signContext = ( signCtx ); \
		}

#define setMechanismDeriveInfo( mechanismInfo, out, outLen, in, inLen, slt, sltLen, iters ) \
		{ \
		( mechanismInfo )->dataOut = ( out ); \
		( mechanismInfo )->dataOutLength = ( outLen ); \
		( mechanismInfo )->dataIn = ( in ); \
		( mechanismInfo )->dataInLength = ( inLen ); \
		( mechanismInfo )->salt = ( slt ); \
		( mechanismInfo )->saltLength = ( sltLen ); \
		( mechanismInfo )->iterations = ( iters ); \
		}

/****************************************************************************
*																			*
*								Misc Message Types							*
*																			*
****************************************************************************/

/* Beside the general data+length and mechanism messages, we also have a 
   number of special-purposes messages which require their own parameter
   data structures.  These are:

   Create object messages, used to create objects via a device.  Usually this
   is the system object, but it can also be used to create contexts in 
   hardware devices.  The create indirect flag is used if we're instantiating
   an object via encoded data, in this case the string arg contains the pre-
   encoded object.  This is used for example to instantiate a cert object
   from an encoded cert */

typedef struct {
	CRYPT_HANDLE cryptHandle;	/* Handle to created object */
	BOOLEAN createIndirect;		/* Create via indirect data */
	int arg1, arg2;				/* Integer args */
	void *strArg1, *strArg2;	/* String args */
	int strArgLen1, strArgLen2;
	} CREATEOBJECT_INFO;

#define setMessageCreateObjectInfo( createObjectInfo, a1 ) \
		{ \
		memset( createObjectInfo, 0, sizeof( CREATEOBJECT_INFO ) ); \
		( createObjectInfo )->cryptHandle = CRYPT_ERROR; \
		( createObjectInfo )->arg1 = ( a1 ); \
		}

/* Key management messages, used to get and delete keys.  The keyIDtype, 
   keyID, and keyIDlength are mandatory, the aux.info depends on the type 
   if message (optional password for private key get/set, state information
   for get next cert, null otherwise), and the flags are generally only 
   required where the keyset can hold both types of keys (for example a 
   crypto device acting as a keyset).  In addition to the flags which are
   used to narrow down the key selection, we can also specify a usage
   preference for cases where we may have multiple keys with the same
   keyID which differ only in required usage.  Currently the only time
   where this is necessary is for distinguishing confidentiality from
   signature-key usage, in the future this can be extended to cover other
   usage types if required */

#define KEYMGMT_FLAG_PUBLICKEY		0x01	/* Read public key */
#define KEYMGMT_FLAG_PRIVATEKEY		0x02	/* Read private key */
#define KEYMGMT_FLAG_CHECK_ONLY		0x04	/* Perform existence check only */
#define KEYMGMT_FLAG_LABEL_ONLY		0x08	/* Get key label only */
#define KEYMGMT_FLAG_USAGE_CRYPT	0x10	/* Prefer encryption key */
#define KEYMGMT_FLAG_USAGE_SIGN		0x20	/* Prefer signature key */

typedef struct {
	CRYPT_HANDLE cryptHandle;	/* Returned key */
	CRYPT_KEYID_TYPE keyIDtype;	/* Key ID type */
	const void *keyID;			/* Key ID */
	int keyIDlength;
	void *auxInfo;				/* Aux.info (eg password for private key) */
	int auxInfoLength;
	int flags;					/* Options for read */
	} MESSAGE_KEYMGMT_INFO;

#define setMessageKeymgmtInfo( keymgmtInfo, idType, id, idLength, aux, auxLen, keyFlags ) \
		{ \
		( keymgmtInfo )->cryptHandle = CRYPT_ERROR; \
		( keymgmtInfo )->keyIDtype = ( idType ); \
		( keymgmtInfo )->keyID = ( id ); \
		( keymgmtInfo )->keyIDlength = ( idLength ); \
		( keymgmtInfo )->auxInfo = ( aux ); \
		( keymgmtInfo )->auxInfoLength = ( auxLen ); \
		( keymgmtInfo )->flags = ( keyFlags ); \
		}

/****************************************************************************
*																			*
*					Object Table Definition and Access Macros				*
*																			*
****************************************************************************/

/* The object manipulation functions are implemented as macros since they
   need to access data internal to the object whose location differs
   depending on the object type.  For example the code to lock an object
   needs to manipulate the objects internal mutex, which will be stored in
   different locations for different objects.  Because of this we use macros
   to do this and let the compiler sort out the memory location within the
   object.  It would be somewhat cleaner to do this as a function, but this
   would mean ensuring the object-management related information was stored
   at the same location in each object (at the start of the object), which
   isn't very practical for clonable objects which assume that ephemeral data
   is located at the end of the object.

   To convert from the external handles which are used to reference internal
   data structures to the internal structure itself, the kernel maintains an
   object property table which contains the information required to manage 
   access */

typedef struct {
	/* Object type and value */
	OBJECT_TYPE type;			/* Object type */
	void *objectPtr;			/* Object data */

	/* Object properties */
	int flags;					/* Internal-only, locked, etc */
	int actionFlags;			/* Permitted actions */
	int subType;				/* Object subtype for attribute ACL chk.*/
	int forwardCount;			/* Number of times ownership can be transferred */
	int usageCount;				/* Number of times obj.can be used */
	int referenceCount;			/* Number of references to this object */
	int inUse;					/* Whether object is busy processing a msg.*/
/*	time_t lastAccess;			// Last access time */

	/* Object methods */
	RESOURCE_MESSAGE_FUNCTION messageFunction;
								/* The objects message handler */
	/* Dependent objects */
	CRYPT_HANDLE dependentObject;	/* Dependent object (context or cert) */
	CRYPT_HANDLE dependentDevice;	/* Dependent crypto device */

	/* Variable-length fields */
	DECLARE_OWNERSHIP_VARS		/* Information on the objects owner */
	} OBJECT_INFO;

extern OBJECT_INFO *objectTable;
extern int objectTableSize;

/* The variables required to synchronise access to the object map */

DEFINE_LOCKING_VARS( objectTable )

/* The flags which apply to each object in the table */

#define OBJECT_FLAG_NONE		0x0000	/* Non-flag */
#define OBJECT_FLAG_NOTINITED	0x0001	/* Still being initialised */
#define OBJECT_FLAG_INTERNAL	0x0002	/* Internal-use only */
#define OBJECT_FLAG_LOCKED		0x0004	/* Security properties can't be modified */
#define OBJECT_FLAG_BUSY		0x0008	/* Busy with async.op */
#define OBJECT_FLAG_SIGNALLED	0x0010	/* In signalled state */
#define OBJECT_FLAG_HIGH		0x0020	/* In 'high' security state */

/* The flags which convey information about an objects status */

#define OBJECT_FLAGMASK_STATUS \
		( OBJECT_FLAG_NOTINITED | OBJECT_FLAG_BUSY | OBJECT_FLAG_SIGNALLED )

/* Map an external object handle to an object data pointer.  This macro is
   used in a number of the following macros, but should never be called
   directly since it doesn't perform any object locking.  The checks
   performed are as follows:

	Check that the handle refers to an object within the object table
	Check that the object isn't a cryptlib-internal object
	Check that the object is accessible to the caller
	Check that the object is of the requested type

   If all these checks succeed, a pointer to the object data is returned */

#define mapResourceHandle( handle, resType ) \
	( ( ( handle ) >= 0 && ( handle ) < objectTableSize && \
			!( objectTable[ handle ].flags & OBJECT_FLAG_INTERNAL ) && \
			checkObjectOwnership( objectTable[ handle ] ) && \
			objectTable[ handle ].type == resType ) ? \
			objectTable[ ( handle ) ].objectPtr : NULL )

/* Map an internal object handle to an object data pointer.  This macro is
   almost identical to mapResourceHandle() except that it doesn't check
   whether the handle is for internal use only */

#define mapInternalResourceHandle( handle, resType ) \
	( ( ( handle ) >= 0 && ( handle ) < objectTableSize && \
			objectTable[ handle ].type == resType ) ? \
			objectTable[ ( handle ) ].objectPtr : NULL )

/* Get an object, lock it for exclusive use, and exit with an error code if 
   there's a problem */

#define getCheckResource( handle, objectPtr, resType, errCode ) \
	{ \
	int flags; \
	\
	lockGlobalResource( objectTable ); \
	objectPtr = mapResourceHandle( handle, resType ); \
	if( objectPtr != NULL && \
		!( ( flags = objectTable[ ( handle ) ].flags ) & \
			 ( OBJECT_FLAG_BUSY | OBJECT_FLAG_SIGNALLED ) ) ) \
		{ lockResource( objectPtr ); } \
	unlockGlobalResource( objectTable ); \
	if( ( objectPtr ) == NULL ) \
		return( errCode ); \
	if( flags & ( OBJECT_FLAG_BUSY | OBJECT_FLAG_SIGNALLED ) ) \
		return( ( flags & OBJECT_FLAG_SIGNALLED ) ? \
				CRYPT_ERROR_SIGNALLED : CRYPT_ERROR_BUSY ); \
	}

/* A variant of the above which is only used with internal objects, so the 
   only way the object could be absent is if it was signalled.  Returning 
   any other form of error code in fact presents considerable difficulties 
   since internal objects are hidden from the user, and a return code of 
   (say) CRYPT_BADPARM2 wouldn't make much sense */

#define getCheckInternalResource( handle, objectPtr, resType ) \
	{ \
	lockGlobalResource( objectTable ); \
	objectPtr = mapInternalResourceHandle( handle, resType ); \
	if( objectPtr != NULL ) \
		{ lockResource( objectPtr ); } \
	unlockGlobalResource( objectTable ); \
	if( objectPtr == NULL ) \
		return( CRYPT_ERROR_SIGNALLED ); \
	}

/* Sometimes we have multiple objects which need to be unlocked on exit.
   The following variant of the previous macro unlocks an extra object
   before returning */

#define getCheckInternalResource2( handle, objectPtr, resType, secondObjectPtr ) \
	{ \
	lockGlobalResource( objectTable ); \
	objectPtr = mapInternalResourceHandle( handle, resType ); \
	if( objectPtr != NULL ) \
		{ lockResource( objectPtr ); } \
	unlockGlobalResource( objectTable ); \
	if( objectPtr == NULL ) \
		{ unlockResourceExit( secondObjectPtr, CRYPT_ERROR_SIGNALLED ); } \
	}

/* The following macros process object ownership information using the
   previously-defined primitives */

#ifndef checkObjectOwnership			/* May be defined to empty macro */
  #define checkObjectOwnership( objectPtr ) \
		( ( objectPtr## ).objectOwner == ( OWNERSHIP_VAR_TYPE ) CRYPT_UNUSED || \
		  ( objectPtr## ).objectOwner == getCurrentIdentity() )
  #define checkObjectOwned( objectPtr ) \
		( ( objectPtr## ).objectOwner != ( OWNERSHIP_VAR_TYPE ) CRYPT_UNUSED )
  #define getObjectOwnership( objectPtr ) \
		( objectPtr## )->objectOwner
  #define setObjectOwnership( objectPtr, owner ) \
		( objectPtr## )->objectOwner = ( OWNERSHIP_VAR_TYPE ) ( owner )
#endif /* checkObjectOwnership */

/* Since we typically unlock an object when we've finished using it, we
   combine the unlock and function exit in one macro */

#ifndef unlockResourceExit				/* May be defined to empty macro */
  #define unlockResourceExit( objectPtr, retCode )	\
		{ \
		unlockResource( objectPtr ); \
		return( retCode ); \
		}
#endif /* !unlockResourceExit */

/****************************************************************************
*																			*
*							Object Management Functions						*
*																			*
****************************************************************************/

/* Object management functions.  A dummy object is one which exists but
   doesn't have the capabilities of the actual object (for example an
   encryption context which just maps to underlying crypto hardware).  This
   doesn't affect krnlCreateObject(), but is used by the object-type-specific
   routines which decorate the results of krnlCreateObject() with object-
   specific extras */

#define CREATEOBJECT_FLAG_SECUREMALLOC \
									0x01	/* Use krnlMemAlloc() to alloc.*/
#define CREATEOBJECT_FLAG_DUMMY		0x02	/* Dummy obj.used as placeholder */

int krnlCreateObject( void **objectInfo, const OBJECT_TYPE type, 
					  const int subType, const int objectSize, 
					  const int createObjectFlags, const int actionFlags,
					  RESOURCE_MESSAGE_FUNCTION messageFunction );

/* Object messaging functions */

int krnlSendMessage( const int objectHandle,
					 const RESOURCE_MESSAGE_TYPE message,
					 void *messageDataPtr, const int messageValue );
void krnlSendBroadcast( const OBJECT_TYPE type,
						const RESOURCE_MESSAGE_TYPE message,
						void *messageDataPtr, const int messageValue );

/* Since some messages contain no data but act only as notifiers, we define
   the following macro to make using them less messy */

#define krnlSendNotifier( handle, message ) \
		krnlSendMessage( handle, message, NULL, 0 )

/* Semaphores */

typedef enum {
	SEMAPHORE_NONE,					/* No semaphore */
	SEMAPHORE_DRIVERBIND,			/* Async driver bind */
	SEMAPHORE_LAST					/* Last semaphore */
	} SEMAPHORE_TYPE;

/* Set/clear/wait on a semaphore */

void setSemaphore( const SEMAPHORE_TYPE semaphore, 
				   const SEMAPHORE_HANDLE object );
void clearSemaphore( const SEMAPHORE_TYPE semaphore );
void waitSemaphore( const SEMAPHORE_TYPE semaphore );

/* Register and deregister service functions to be called by cryptlibs
   background thread */

int registerServiceRoutine( void ( *serviceDispatchFunction )
	( const int object, void ( *serviceFunction )( void *info ) ),
	void ( *serviceFunction )( void *info ), const int object );
void deregisterServiceRoutine( const int serviceID );

/* Secure memory handling functions */

int krnlMemalloc( void **pointer, int size );
void krnlMemfree( void **pointer );
int krnlMemsize( const void *pointer );

#endif /* _CRYPTKRN_DEFINED */
