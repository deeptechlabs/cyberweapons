/****************************************************************************
*																			*
*					  cryptlib Keyset Interface Header File 				*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _KEYSET_DEFINED

#define _KEYSET_DEFINED

/* Various include files needed by the DBMS libraries.  To enable the code
   for a particular database interface, define DBX_<database-type> (multiple
   database types can be defined, the required interface is selected at
   runtime).  Currently supported database types and operating systems are:

	DBX_ODBC		Generic ODBC (always enabled under Windows)
	DBX_MSQL		mSQL
	DBX_MYSQL		MySQL
	DBX_ORACLE		Oracle
	DBX_POSTGRES	Postgres
	DBX_LDAP		LDAP (always enabled under Windows)
	DBX_HTTP		HTTP (always enabled under Windows) */

#include <time.h>
#ifdef DBX_ODBC
  /* As part of the ever-changing way of identifying Win32, Microsoft changed
	 the predefined constant from WIN32 to _WIN32 in VC++ 2.1.  However the
	 ODBC header files still expect to find WIN32, and if this isn't defined
	 will use the default (ie C) calling convention instead of the Pascal
	 convention which is actually used by the ODBC functions.  This means
	 that both the caller and the callee clean up the stack, so that for each
	 ODBC call the stack creeps upwards by a few bytes until eventually the
	 local variables and/or return address get trashed.  This problem is
	 usually hidden by the fact that something else defines WIN32 so
	 everything works OK, but the October 1997 development platform upgrade
	 changes this so compiling the code after this update is installed breaks
	 things.

	 To avoid this problem, we define WIN32 if it isn't defined, which
	 ensures that the ODBC header files work properly */
  #if defined( __WIN32__ ) && !defined( WIN32 )
	#define WIN32
  #endif /* __WIN32__ && !WIN32 */
  #include <sql.h>
  #include <sqlext.h>
#endif /* __WINDOWS__ */
#ifdef DBX_MSQL
  #include "msql.h"
#endif /* DBX_MSQL */
#ifdef DBX_MYSQL
  #include <mysql.h>
#endif /* DBX_MYSQL */
#ifdef DBX_ORACLE
  #include "oratypes.h"
  #include "ocidfn.h"
  #include "ociapr.h"
#endif /* DBX_ORACLE */
#ifdef DBX_POSTGRES
  #include "libpq-fe.h"
#endif /* DBX_POSTGRES */
#ifdef DBX_LDAP
  /* These should really be taken from the system include directory but
     this leads to too many complaints from people who don't read the
	 LDAP installation section of the manual */
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "ldap.h"
  #else
	#include "misc/ldap.h"
  #endif /* Compiler-specific includes */
#endif /* DBX_LDAP */
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL )
	#include "stream.h"
  #elif defined( INC_CHILD )
	#include "../keymgmt/stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */
#if defined( INC_ALL )
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../misc/scard.h"
#else
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

/* The size of various fields, or the maximum size if the exact size is of
   variable length.  The keyID size is based on the size of the base64-encoded 
   first 128 bits of an SHA-1 hash (the base64 encoding adds up to 2 bytes of
   padding and a byte of null terminator, we strip the padding after encoding
   so the given encoded size is slightly shorter than normal).  The field
   size value is encoded into the SQL strings and is also given in text form
   for this purpose (without the terminator being included).  The SQL query
   size is the size of the DN and other components, the key ID's, and the key
   itself */

#define DBXKEYID_SIZE				16		/* Full keyID = 128 bits */
#define MAX_ENCODED_DBXKEYID_SIZE	23		/* base64-encoded + '\0' */
#define TEXT_DBXKEYID_SIZE			"22"

#define MAX_CERT_SIZE				1536
#define MAX_ENCODED_CERT_SIZE		2048	/* base64-encoded */
#define TEXT_MAX_ENCODED_CERT_SIZE	"2047"
#define MAX_SQL_QUERY_SIZE			( ( 7 * CRYPT_MAX_TEXTSIZE ) + \
									  ( 3 * MAX_ENCODED_DBXKEYID_SIZE ) + \
									  MAX_ENCODED_CERT_SIZE + 128 )

/* Some older compilers don't yet have the ANSI FILENAME_MAX define so we
   define a reasonable value here (the length is checked when we open the
   keyset so there's no chance it'll overflow even if the OS path limit is
   higher than what's defined here) */

#ifndef FILENAME_MAX
  #if defined( __MSDOS16__ )
	#define FILENAME_MAX	80
  #elif defined( __hpux )
	#include <sys/param.h>	/* HPUX's stdio.h defines this to be 14 (!!) */
	#define FILENAME_MAX	MAXPATHLEN
  #else
	#define FILENAME_MAX	256
  #endif /* __MSDOS16__ */
#endif /* FILENAME_MAX */

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* The precise type of the key file we're working with.  This is used for
   type checking to make sure we don't try to find private keys in a
   collection of public-key certificates or whatever */

typedef enum {
	KEYSET_SUBTYPE_NONE,			/* Unknown */
	KEYSET_SUBTYPE_ERROR,			/* Bad keyset format */
	KEYSET_SUBTYPE_PGP_PUBLIC,		/* PGP public keyring */
	KEYSET_SUBTYPE_PGP_PRIVATE,		/* PGP private keyring */
	KEYSET_SUBTYPE_PKCS12,			/* PKCS #12 key mess */
	KEYSET_SUBTYPE_PKCS15			/* PKCS #15 keys */
	} KEYSET_SUBTYPE;

/* The state of a database keyset query operation, used to retrive multiple
   keys from a keyset */

typedef enum {
	QUERY_NONE,						/* No query */
	QUERY_START,					/* Query initialisation */
	QUERY_INPROGRESS,				/* Query in progress */
	QUERY_COMPLETE					/* Query completed */
	} QUERY_STATE;

/* When perform a DBMS transaction which returns information there are several
   variations on the basic query type.  The following values tell 
   performQuery() which type of operation to perform */

typedef enum {
	DBMS_QUERY_NORMAL,		/* Standard data fetch */
	DBMS_QUERY_CHECK,		/* Check-type fetch, don't fetch data */
	DBMS_QUERY_START,		/* Begin an ongoing query */
	DBMS_QUERY_CONTINUE,	/* Continue a previous ongoing query */
	DBMS_QUERY_CANCEL		/* Cancel ongoing query */
	} DBMS_QUERY_TYPE;

/* The internal fields in a keyset which hold data for the various keyset
   types.   These are implemented as a union to allow keyset-type-specific
   information to be passed to lower-level routines without having to have
   an entire keyset record present, and as a convenient side-effect to
   conserve memory with some of the more data-intensive types such as
   database keysets.  In addition the structures provide a convenient way to
   group the context-type-specific parameters */

typedef enum { KEYSET_NONE, KEYSET_FILE, KEYSET_DBMS, KEYSET_SMARTCARD,
			   KEYSET_LDAP, KEYSET_HTTP } KEYSET_TYPE;

struct KI;	/* Forward declaration for argument to function pointers */

typedef struct {
	/* The I/O stream and file name, whether the stream is currently open,
	   and whether there's in-memory data present which needs to be flushed
	   to the stream */
	STREAM stream;					/* I/O stream for key file */
	char fileName[ FILENAME_MAX ];	/* Name of key file */
	} FILE_INFO;

typedef struct {
	/* DBMS status information */
	BOOLEAN needsUpdate;			/* Whether key DBX needs to be committed */
	BOOLEAN hasBinaryBlobs;			/* Whether DBMS supports binary blobs */
	char blobName[ 64 ];			/* Name of blob data type */
	QUERY_STATE queryState;			/* State of DBMS query */

	/* For some database types or access methods, we need to bind the
	   locations of variables and use placeholders in the SQL text rather
	   than passing the data as part of the SQL.  The following variables are
	   the storage which is bound */
  #ifdef __WINDOWS__
	TIMESTAMP_STRUCT boundDate;		/* Bound data value */
  #endif /* __WINDOWS__ */
	char boundKeyData[ MAX_ENCODED_CERT_SIZE ];
	int boundKeyDataLen;			/* Bound key data value */
	time_t date;					/* Date in non-bound form */

	/* Database-specific information */
  #ifdef __WINDOWS__
	/* ODBC access information */
	HENV hEnv;						/* Environment handle */
	HDBC hDbc;						/* Connection handle */
	HSTMT hStmt;					/* Statement handle */
	SWORD blobType;					/* SQL type of blob data type */
	SDWORD cbBlobLength;			/* Length of key (blob) data */
  #endif /* __WINDOWS__ */
  #ifdef DBX_MSQL
	int sock;						/* Connection handle */
  #endif /* DBX_MSQL */
  #ifdef DBX_MYSQL
	MYSQL *connection;				/* Connection handle */
  #endif /* DBX_MYSQL */
  #ifdef DBX_ORACLE
	Lda_Def lda;					/* Logon data area */
	ub1 hda[ 256 ];					/* Host data area */
	Cda_Def cda;					/* Cursor data area */
  #endif /* DBX_ORACLE */
  #ifdef DBX_POSTGRES
	PGconn *pgConnection;			/* Connection handle */
	PGresult *pgResult;				/* Query result handle */
  #endif /* DBX_POSTGRES */

	/* Pointers to the access methods.  These are used by the generic DBMS 
	   code to map down to database backend-specific functions */
	int ( *openDatabase )( struct KI *keysetInfo, const char *name,
						   const char *server, const char *user,
						   const char *password );
	void ( *closeDatabase )( struct KI *keysetInfo );
	int ( *performUpdate )( struct KI *keysetInfo, const char *command,
							const BOOLEAN hasBoundData );
	int ( *performCheck )( struct KI *keysetInfo, const char *command );
	int ( *performQuery )( struct KI *keysetInfo, const char *command,
						   char *data, int *dataLength, const int maxLength,
						   const DBMS_QUERY_TYPE queryType );
	} DBMS_INFO;

typedef struct {
	/* An HTTP fetch differs from the other types of read in that it can
	   return data in multiple chunks depending on how much comes over the
	   net at once.  Because of this we need to track what's come in, and 
	   also allocate more buffer space on demand if required.  The following
	   variables handle the on-demand reallocation of buffer space */
	int bufPos;						/* Current position in buffer */
	} HTTP_INFO;

typedef struct {
	/* LDAP status information */
	QUERY_STATE queryState;			/* State of directory query */

#ifdef DBX_LDAP
	/* LDAP access information */
	LDAP *ld;						/* LDAP connection information */
	void *result;					/* State information for ongoing queries */
#endif /* DBX_LDAP */

	/* The names of the object class and various attributes.  These are
	   stored as part of the keyset context since they may be user-defined or
	   the library-wide definition may change over time */
	char nameObjectClass[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of object class */
	char nameCACert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of CA cert attribute */
	char nameCert[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of cert attribute */
	char nameCRL[ CRYPT_MAX_TEXTSIZE + 1 ];		/* Name of CRL attribute */
	char nameEmail[ CRYPT_MAX_TEXTSIZE + 1 ];	/* Name of email addr.attr.*/
	CRYPT_CERTTYPE_TYPE objectType;				/* Preferred obj.type to fetch */

	/* When storing a cert we need the certificate DN, email address,
	   and cert expiry date */
	char C[ CRYPT_MAX_TEXTSIZE + 1 ], SP[ CRYPT_MAX_TEXTSIZE + 1 ],
		L[ CRYPT_MAX_TEXTSIZE + 1 ], O[ CRYPT_MAX_TEXTSIZE + 1 ],
		OU[ CRYPT_MAX_TEXTSIZE + 1 ], CN[ CRYPT_MAX_TEXTSIZE + 1 ];
	char email[ CRYPT_MAX_TEXTSIZE + 1 ];
	time_t date;
	} LDAP_INFO;

/* Defines to make access to the union fields less messy */

#define keysetFile		keysetInfo.fileInfo
#define keysetDBMS		keysetInfo.dbmsInfo
#define keysetScard		keysetInfo.scardInfo
#define keysetHTTP		keysetInfo.httpInfo
#define keysetLDAP		keysetInfo.ldapInfo

/* The structure which stores information on a keyset */

typedef struct KI {
	/* General keyset information */
	KEYSET_TYPE type;				/* Keyset type (native, PGP, X.509, etc) */
	KEYSET_SUBTYPE subType;			/* Keyset subtype (public, private, etc) */
	CRYPT_KEYOPT_TYPE options;		/* Keyset option flags */
	BOOLEAN isOpen;					/* Whether keyset is open */
	BOOLEAN isEmpty;				/* Whether keyset is empty */
	BOOLEAN isDirty;				/* Whether keyset data has been changed */

	/* The keyset-type-specific information */
	union {
		FILE_INFO fileInfo;
		DBMS_INFO dbmsInfo;
		SCARD_INFO scardInfo;
		HTTP_INFO httpInfo;
		LDAP_INFO ldapInfo;
		} keysetInfo;				/* Keyset-specific information */

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];

	/* Pointers to keyset access methods */
	int ( *initKeysetFunction )( struct KI *keysetInfo, const char *name,
								 const char *arg1, const char *arg2,
								 const char *arg3, const CRYPT_KEYOPT_TYPE options );
	void ( *shutdownKeysetFunction )( struct KI *keysetInfo );
	int ( *getItemFunction )( struct KI *keysetInfo,
							  CRYPT_HANDLE *iCryptHandle, 
							  const CRYPT_KEYID_TYPE keyIDtype, 
							  const void *keyID,  const int keyIDlength, 
							  void *auxInfo, int *auxInfoLength, 
							  const int flags );
	int ( *setItemFunction )( struct KI *deviceInfo,
							  const CRYPT_HANDLE iCryptHandle,
							  const char *password, const int passwordLength );
	int ( *deleteItemFunction )( struct KI *keysetInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength );
	int ( *getNextCertFunction )( struct KI *keysetInfo, 
								  CRYPT_CERTIFICATE *iCertificate,
								  int *stateInfo, 
								  const CRYPT_KEYID_TYPE keyIDtype,
								  const void *keyID, const int keyIDlength,
								  const CERTIMPORT_TYPE options );
	int ( *queryFunction )( struct KI *keysetInfo, const char *query,
							const int queryLength );

	/* Some keysets require keyset-type-specific data storage which is 
	   managed via the following variables */
	void *keyData;					/* Keyset data buffer */
	int keyDataSize;				/* Buffer size */

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
	   the actual variables required to handle the object locking (the actual 
	   values are defined in cryptos.h) */
	DECLARE_OBJECT_LOCKING_VARS
	} KEYSET_INFO;

/* Prototypes for keyset mapping functions */

int setAccessMethodDBMS( KEYSET_INFO *keysetInfo,
						 const CRYPT_KEYSET_TYPE type );
int setAccessMethodHTTP( KEYSET_INFO *keysetInfo );
int setAccessMethodLDAP( KEYSET_INFO *keysetInfo );
int setAccessMethodPGP( KEYSET_INFO *keysetInfo );
int setAccessMethodPKCS12( KEYSET_INFO *keysetInfo );
int setAccessMethodPKCS15( KEYSET_INFO *keysetInfo );
int setAccessMethodScard( KEYSET_INFO *keysetInfo, const char *name );

#endif /* _KEYSET_DEFINED */
