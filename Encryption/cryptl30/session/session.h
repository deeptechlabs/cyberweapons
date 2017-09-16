/****************************************************************************
*																			*
*						Secure Session Routines Header File					*
*						 Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#ifndef _SES_DEFINED

#define _SES_DEFINED

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* The structure which stores the information on a session */

typedef struct SI {
	/* Control and status information */
	CRYPT_FORMAT_TYPE type;				/* Session type */
	BOOLEAN sessionOpen;				/* Whether session is active */
	CRYPT_ALGO cryptAlgo;				/* Negotiated encryption algo */
	CRYPT_ALGO integrityAlgo;			/* Negotiated integrity prot.algo */

	/* Data buffer information */
	BYTE *sendBuffer, *receiveBuffer;	/* Data buffer */
	int sendBufSize, receiveBufSize;	/* Total buffer size */
	int sendBufPos, receiveBufPos;		/* Current position in buffer */
	int sendBufEnd, receiveBufEnd;		/* Total data in buffer */

	/* The session generally has various contexts associated with it, some
	   short-term (eg public-key contexts used to establish the session) and
	   some long-term (eg encryption contexts used to perform bulk data
	   encryption).  The following values store these contexts */
	CRYPT_CONTEXT iKeyexCryptContext;	/* Key exchange encryption */
	CRYPT_CONTEXT iKeyexAuthContext;	/* Key exchange authentication */
	CRYPT_CONTEXT iCryptInContext, iCryptOutContext;
										/* In/outgoing data encryption */
	CRYPT_CONTEXT iAuthInContext, iAuthOutContext;
										/* In/outgoing auth/integrity */
	int cryptBlocksize, authBlocksize;	/* Block size of crypt, auth.algos */

	/* SSL protocol-specific information.  The SSL MAC read/write secrets 
	   are required because SSL 3.0 uses a proto-HMAC which isn't handled 
	   by cryptlib.  We leave the data in normal memory because it's only
	   usable for an active attack which means recovering it from swap
	   afterwards isn't a problem */
	BYTE sslMacReadSecret[ CRYPT_MAX_HASHSIZE ],
		 sslMacWriteSecret[ CRYPT_MAX_HASHSIZE ];	/* Proto-HMAC keys */
	int sslReadSeqNo, sslWriteSeqNo;	/* Packet sequence number */

	/* SSH protocol-specific information.  The user name and password are
	   required to authenticate the client to the server */
	char sshUserName[ CRYPT_MAX_TEXTSIZE ], sshPassword[ CRYPT_MAX_TEXTSIZE ];
	int sshUserNameLength, sshPasswordLength;

	/* Network connection information.  The read timeout is updated from the
	   CRYPT_OPTION_SESSION_TIMEOUT value at the start of each block of reads
	   to save having to repeatedly read the config value */
	char serverName[ MAX_URL_SIZE + 1 ];/* Server name */
	int serverPort;						/* Port on server */
	long socket;						/* Network socket handle */
	int timeout;						/* Read timeout in seconds */

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE + 1 ];

	/* Pointers to session access methods */
	int ( *initFunction )( struct SI *sessionInfoPtr );
	void ( *shutdownFunction )( struct SI *sessionInfoPtr );
	int ( *connectFunction )( struct SI *sessionInfoPtr );
	int ( *putDataFunction )( struct SI *sessionInfoPtr, const void *data,
							  const int length );
	int ( *getDataFunction )( struct SI *sessionInfoPtr, void *data,
							  const int length );

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The object's handle, used when sending messages to the object when
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the resource locking (the
	   actual values are defined in cryptos.h) */
	DECLARE_OBJECT_LOCKING_VARS
	} SESSION_INFO;

/* Prototypes for session mapping functions */

int setAccessMethodSSL( SESSION_INFO *sessionInfoPtr );
int setAccessMethodSSH( SESSION_INFO *sessionInfoPtr );
int setAccessMethodCMP( SESSION_INFO *sessionInfoPtr );

#endif /* _SES_DEFINED */
