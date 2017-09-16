/****************************************************************************
*																			*
*					  cryptlib Device Interface Header File 				*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#ifndef _DEVICE_DEFINED

#define _DEVICE_DEFINED

#if defined( INC_ALL )
  #include "scard.h"
#elif defined( INC_CHILD )
  #include "../misc/scard.h"
#else
  #include "misc/scard.h"
#endif /* Compiler-specific includes */

/* The maximum length of error message we can store */

#define MAX_ERRMSG_SIZE		512

/* Device information flags.  The "needs login" flag is a general device
   flag which indicates that this type of device needs a user login before
   it can be used and is set when the device is first opened, the "logged in"
   flag is an ephemeral flag which indicates whether the user is currently
   logged in.  The "device active" flag indicates that a session with the
   device is currently active and needs to be shut down when the device
   object is destroyed */

#define DEVICE_NEEDSLOGIN	0x0001	/* User must log in to use dev.*/
#define DEVICE_READONLY		0x0002	/* Device can't be written to */
#define DEVICE_ACTIVE		0x0004	/* Device is currently active */
#define DEVICE_LOGGEDIN		0x0008	/* User is logged into device */

/* Devices implement mechanisms in the same way that contexts implement 
   actions.  Since the mechanism space is sparse, dispatching is handled by
   looking up the required mechanism in a table of (action, mechanism, 
   function) triples.  The table is sorted by order of most-frequently-used 
   mechanisms to speed things up, although the overhead is vanishingly small 
   anyway */

typedef int ( *MECHANISM_FUNCTION )( void *deviceInfoPtr,
									 void *mechanismInfo );
typedef struct {
	const RESOURCE_MESSAGE_TYPE action;
	const MECHANISM_TYPE mechanism;
	const MECHANISM_FUNCTION function;
	} MECHANISM_FUNCTION_INFO;

/* Devices can also be used to create further objects.  Most can only create
   contexts, but the system object can create any kind of object */

typedef int ( *CREATEOBJECT_FUNCTION )( CREATEOBJECT_INFO *objectInfo,
										const void *auxDataPtr,
										const int auxValue );
typedef struct {
	const OBJECT_TYPE type;
	const CREATEOBJECT_FUNCTION function;
	} CREATEOBJECT_FUNCTION_INFO;

/* The structure which stores information on a device */

typedef struct DI {
	/* General device information.  Alongside various handles used to access
	   the device we also record whether the user has authenticated
	   themselves to the device since some devices have multiple user-access
	   states and the user needs to be logged out of one state before they
	   can log in to another state */
	CRYPT_DEVICE_TYPE type;			/* Device type */
	long deviceHandle;				/* Handle to the device */
	long slotHandle;				/* Handle to slot for multi-device */
	int flags;						/* Device information flags */

	/* Each device provides various capabilities which are held in the 
	   following list.  When we need to create an object via the device, we
	   look up the requirements in the capability info and feed it to
	   createObjectFromCapability() */
	const void FAR_BSS *capabilityInfo;

	/* Some devices have minimum and maximum PIN/password lengths, if these
	   are known we record them when the device is initialised */
	int minPinSize, maxPinSize;		/* Minimum, maximum PIN lengths */

	/* Last-error information.  To help developers in debugging, we store
	   the error code and error text (if available) */
	int errorCode;
	char errorMessage[ MAX_ERRMSG_SIZE ];

	/* Pointers to device access methods */
	int ( *initDeviceFunction )( struct DI *deviceInfo, const char *name,
								 const int nameLength );
	void ( *shutdownDeviceFunction )( struct DI *deviceInfo );
	int ( *controlFunction )( struct DI *deviceInfo,
							  const CRYPT_ATTRIBUTE_TYPE type,
							  const void *data1, const int data1Length,
							  const void *data2, const int data2Length );
	int ( *getItemFunction )( struct DI *deviceInfo,
							  CRYPT_CONTEXT *iCryptContext,
							  const CRYPT_KEYID_TYPE keyIDtype,
							  const void *keyID, const int keyIDlength,
							  void *auxInfo, int *auxInfoLength, 
							  const int flags );
	int ( *setItemFunction )( struct DI *deviceInfo,
							  const CRYPT_HANDLE iCryptHandle );
	int ( *deleteItemFunction )( struct DI *deviceInfo,
								 const CRYPT_KEYID_TYPE keyIDtype,
								 const void *keyID, const int keyIDlength );
	int ( *getNextCertFunction )( struct DI *deviceInfo, 
								  CRYPT_CERTIFICATE *iCertificate,
								  int *stateInfo, 
								  const CRYPT_KEYID_TYPE keyIDtype,
								  const void *keyID, const int keyIDlength,
								  const CERTIMPORT_TYPE options );
	int ( *getRandomFunction)( struct DI *deviceInfo, void *buffer,
							   const int length );

	/* Mechanism information */
	const MECHANISM_FUNCTION_INFO *mechanismFunctions;

	/* Create object methods */
	const CREATEOBJECT_FUNCTION_INFO *createObjectFunctions;

	/* Information for randomness pseudo-devices */
	void *randomInfo;

	/* Information for smart card devices */
	SCARD_INFO deviceScard;

	/* Information for PKCS #11 devices */
	int deviceNo;					/* Index into PKCS #11 token table */

	/* Information for Fortezza devices */
	long largestBlockSize;			/* Largest single data block size */
	void *personalities;			/* Device personality list */
	int personalityCount;			/* Number of personalities */
	long keyRegisterFlags;			/* Bitfield of key regs.in use */
	int keyRegisterCount;			/* Number of key registers */
	void *certHashes;				/* Hashes of certs in card */
	BOOLEAN certHashesInitialised;	/* Whether hashes are initialised */
	int currentPersonality;			/* Currently selected personality */
	BYTE leafString[ 16 ];			/* LEAF-suppressed string */

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
	   the actual variables required to handle the object locking (the
	   actual values are defined in cryptos.h) */
	DECLARE_OBJECT_LOCKING_VARS
	} DEVICE_INFO;

/* Prototypes for the capability info sanity-check function in crypt.c.  This
   function is only called via an assert() and isn't used in non-debug builds */

BOOLEAN capabilityInfoOK( const void *capabilityInfoPtr );

/* Prototypes for functions in asn1keys.c */

int sizeofFlatPublicKey( const CRYPT_ALGO cryptAlgo, 
						 const void *component1, const int component1Length,
						 const void *component2, const int component2Length,
						 const void *component3, const int component3Length,
						 const void *component4, const int component4Length );
int writeFlatPublicKey( void *buffer, const CRYPT_ALGO cryptAlgo, 
						const void *component1, const int component1Length,
						const void *component2, const int component2Length,
						const void *component3, const int component3Length,
						const void *component4, const int component4Length );

/* Prototypes for device mapping functions */

int setDeviceCEI( DEVICE_INFO *deviceInfo );
int setDeviceFortezza( DEVICE_INFO *deviceInfo );
int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name,
					 const int nameLength );
int setDeviceSystem( DEVICE_INFO *deviceInfo );

#endif /* _DEVICE_DEFINED */
