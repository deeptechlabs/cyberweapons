/****************************************************************************
*																			*
*					  cryptlib Encryption Context Header File 				*
*						Copyright Peter Gutmann 1992-1998					*
*																			*
****************************************************************************/

#ifndef _CRYPTCTX_DEFINED

#define _CRYPTCTX_DEFINED

/* If the general cryptlib header hasn't been included yet, include it now */

#ifndef _CRYPT_DEFINED
  #include "crypt.h"
#endif /* _CRYPT_DEFINED */

/* If the bignum header hasn't been included yet, include it now */

#ifndef BN_H
  #if defined( INC_ALL )
	#include "bn.h"
  #else
	#include "bn/bn.h"
  #endif /* Compiler-specific includes */
#endif /* BN_H */

/* We need to include the following because the encryption context stores
   validity information for private keys */

#include <time.h>

/* When reading a key into a PKC context, we read the data straight into the 
   context-internal bignums rather than passing them in via a 
   CRYPT_PKCINFO_xxx intermediary.  In this case we pass in the following 
   dummy struct to tell the key load code to use the built-in values */

typedef struct {
	int dummy;
	} PKCINFO_LOADINTERNAL;

/****************************************************************************
*																			*
*								Data Structures								*
*																			*
****************************************************************************/

/* A forward declaration for the parameter type passed to functions in the
   CAPABILITY_INFO struct */

struct CI;

/* The structure used to store internal information about the crypto library
   capabilities.  This information is used internally by the library and is
   not available to users */

typedef struct CA {
	/* Basic identification information for the algorithm */
	const CRYPT_ALGO cryptAlgo;		/* The encryption algorithm */
	const int blockSize;			/* The basic block size of the algorithm */
	const char *algoName;			/* Algorithm name */

	/* Keying information.  Note that the maximum sizes may vary (for
	   example for two-key triple DES vs three-key triple DES) so the
	   crypt query functions should be used to determine the actual size
	   for a particular context rather than just using maxKeySize */
	const int minKeySize;			/* Minimum key size in bytes */
	const int keySize;				/* Recommended key size in bytes */
	const int maxKeySize;			/* Maximum key size in bytes */

	/* The functions for implementing the algorithm */
	int ( *selfTestFunction )( void );
	int ( *initFunction )( struct CI *cryptInfoPtr );
	int ( *endFunction )( struct CI *cryptInfoPtr );
	int ( *initIVFunction )( struct CI *cryptInfoPtr, const void *iv, const int ivLength );
	int ( *initKeyFunction )( struct CI *cryptInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( struct CI *cryptInfoPtr, const int keySizeBits );
	int ( *getKeysizeFunction )( struct CI *cryptInfoPtr );
	int ( *encryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *encryptCBCFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptCBCFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *encryptCFBFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptCFBFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *encryptOFBFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptOFBFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *signFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( struct CI *cryptInfoPtr, void *buffer, int length );

	/* Non-native implementations may require extra parameters (for example
	   to specify the algorithm and mode in the manner required by the
	   non-native implementation), the following values can be used to store 
	   these parameters */
	const int param1, param2, param3, param4;

	/* Sometimes the capabilities may be stored as a dynamically-created
	   linked list instead of a static table, so we need to store a pointer
	   to the next element in the list */
	struct CA *next;    			/* Next element in list */
	} CAPABILITY_INFO;

/* The internal fields in a context which hold data for a conventional,
   public-key, hash, or MAC algorithm.  These are implemented as a union to
   conserve memory if the entire context is allocated in pagelocked memory,
   leading to a lot of memory being consumed by unused storage.  In addition
   these structures provide a convenient way to group the context-type-
   specific parameters.

   For the following context types, CONTEXT_CONV and CONTEXT_HASH should be
   allocated in pagelocked memory since they contain the sensitive userKey
   and partially sensitve IV fields */

typedef enum { CONTEXT_NONE, CONTEXT_CONV, CONTEXT_PKC, CONTEXT_HASH,
			   CONTEXT_MAC } CONTEXT_TYPE;

#define needsSecureMemory( contextType ) \
		( contextType == CONTEXT_CONV || contextType == CONTEXT_MAC )

typedef struct {
	/* General algorithm information */
	CRYPT_MODE mode;				/* Encryption mode being used */

	/* User keying information for.  The user key is the key as entered by
	   the user, the IV is the initial IV */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];		/* User encryption key */
	BYTE iv[ CRYPT_MAX_IVSIZE ];	/* Initial IV */
	int userKeyLength;				/* User encryption key length in bytes */
	int ivLength;					/* IV length in bytes */
	BOOLEAN keySet;					/* Whether the key is set up */
	BOOLEAN ivSet;					/* Whether the IV is set up */

	/* Conventional encryption keying information.  The key is the raw
	   encryption key stored in whatever form is required by the algorithm,
	   usually the key-scheduled user key.  The IV is the current working IV.
	   The ivCount is the number of bytes of IV which have been used, and is
	   used when a block cipher is used as a stream cipher */
	void *key;						/* Internal working key */
	BYTE currentIV[ CRYPT_MAX_IVSIZE ];	/* Internal working IV */
	int keyLength;					/* Internal key length in bytes */
	int ivCount;					/* Internal IV count for chaining modes */

	/* Information obtained when a key suitable for use by this algorithm
	   is derived from a longer user key */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Salt */
	int saltLength;					/* Salt size */
	int keySetupIterations;			/* Number of times setup was iterated */
	CRYPT_ALGO keySetupAlgorithm;	/* Algorithm used for key setup */
	} CONV_INFO;

typedef struct {
	/* General information on the key: Whether it's a public or private key,
	   whether a key is loaded, the nominal key size in bits, and the key
	   ID */
	BOOLEAN isPublicKey;			/* Whether key is a public key */
	BOOLEAN keySet;					/* Whether the key is set up */
	int keySizeBits;				/* Nominal key size in bits */
	BYTE keyID[ KEYID_SIZE ];		/* Key ID for this key */

	/* Public-key encryption keying information.  Since each algorithm has
	   its own unique parameters, the bignums are given generic names here.
	   The algorithm-specific code refers to them by their actual names,
	   which are implemented as symbolic defines of the form
	   <algo>Param_<param_name>, eg rsaParam_e */
	BIGNUM *param1;
	BIGNUM *param2;
	BIGNUM *param3;
	BIGNUM *param4;
	BIGNUM *param5;
	BIGNUM *param6;
	BIGNUM *param7;
	BIGNUM *param8;					/* The PKC key components */
	BN_MONT_CTX *montCTX1;
	BN_MONT_CTX *montCTX2;
	BN_MONT_CTX *montCTX3;			/* Precompute Montgomery values */

	/* If the context is tied to a device the keying info won't be available, 
	   however we generally need the public key information for use in cert 
	   requests and whatnot so we save a copy as SubjectPublicKeyInfo when
	   the key is loaded/generated */
	void *publicKeyInfo;			/* X.509 SubjectPublicKeyInfo */
	int publicKeyInfoSize;			/* Key info size */

	/* For key agreement keys, we also store domain parameters (which 
	   identify the domain of the originator and recipient keys) and the
	   public value used in the key agreement process.  These are just 
	   pointers to the encoded data in the publicKeyInfo */
	void *domainParamPtr;			/* Domain parameters within publicKeyInfo */
	int domainParamSize;
	void *publicValuePtr;			/* Public value within publicKeyInfo */
	int publicValueSize;
	} PKC_INFO;

typedef struct {
	/* Data required to store the current state of the hashing */
	void *hashInfo;					/* Current hash state */

	/* Hash information.  This is the result of the hash operation, which has
	   to be stored in the context for certain implementations which return
	   the hash result immediately as part of the final part of the hashing
	   operation.  This also means we can destroy the algorithm-specific
	   information as soon as the hashing has completed */
	BYTE hash[ CRYPT_MAX_HASHSIZE ];

	/* A flag which is set if processing has completed and can't be resumed */
	BOOLEAN done;					/* Whether the operation is complete */
	} HASH_INFO;

typedef struct {
	/* User keying information */
	BYTE userKey[ CRYPT_MAX_KEYSIZE ];	/* User MAC key */
	int userKeyLength;				/* User MAC key length in bytes */
	BOOLEAN keySet;					/* Whether the key is set up */

	/* Data required to store the current state of the MACing */
	void *macInfo;					/* Current MAC state */

	/* MAC information.  This is the result of the hash operation, which has
	   to be stored in the context for certain implementations which return
	   the hash result immediately as part of the final part of the hashing
	   operation.  This also means we can destroy the algorithm-specific
	   information as soon as the hashing has completed */
	BYTE mac[ CRYPT_MAX_HASHSIZE ];

	/* A flag which is set if processing has completed and can't be resumed */
	BOOLEAN done;					/* Whether the operation is complete */

	/* Information obtained when a key suitable for use by this algorithm
	   is derived from a longer user key */
	BYTE salt[ CRYPT_MAX_HASHSIZE ];/* Salt */
	int saltLength;					/* Salt size */
	int keySetupIterations;			/* Number of times setup was iterated */
	CRYPT_ALGO keySetupAlgorithm;	/* Algorithm used for key setup */
	} MAC_INFO;

/* Defines to make access to the union fields less messy */

#define ctxConv		keyingInfo.convInfo
#define ctxPKC		keyingInfo.pkcInfo
#define ctxHash		keyingInfo.hashInfo
#define ctxMAC		keyingInfo.macInfo

/* An encryption context */

typedef struct CI {
	/* Basic information on the encryption we're using */
	const CAPABILITY_INFO *capabilityInfo;	/* Encryption capability info */

	/* The algorithm-type-specific information */
	CONTEXT_TYPE type;				/* The context type */
	union {
		CONV_INFO convInfo;
		PKC_INFO pkcInfo;
		HASH_INFO hashInfo;
		MAC_INFO macInfo;
		} keyingInfo;				/* Algorithm-specific information */
	BOOLEAN keyingInfoInited;		/* Whether algo-specific info is inited */

	/* If implemented using a crypto device, the object information is
	   usually stored inside the device.  The following value contains the
	   reference to the crypto object inside the device */
	long deviceObject;

	/* The label for this object, typically used to identify stored keys */
	char label[ CRYPT_MAX_TEXTSIZE ];/* Text string identifying key */
	int labelSize;					/* Size of label */

	/* Whether the context is being used for an asynchronous operation such
	   as key generation, and whether to abort the asynchronous operation.
	   If the object status is set to CRYPT_BUSY, any attempt to access it
	   will return CRYPT_BUSY.  The doAbort flag is used by cryptAsyncAbort()
	   to signal to the async operation that it should finish processing and
	   clean up.  The done flag is used to indicate that the async operation
	   has completed, so that further status change operations have no
	   effect.  The asyncStatus records the result of the operation, which is
	   returned from cryptAsyncQuery() */
	BOOLEAN doAbort;				/* Whether to abort async operation */
	BOOLEAN done;					/* Whether async operation is complete */
	int asyncStatus;				/* Exit status of the async operation */

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
	} CRYPT_INFO;

/* Symbolic defines for the various PKC components for different PKC
   algorithms.  All of the DLP algorithms actually use the same parameters,
   so we define generic DLP names for them */

#define isDLPAlgorithm( algo ) \
		( ( algo ) == CRYPT_ALGO_DH || ( algo ) == CRYPT_ALGO_DSA || \
		  ( algo ) == CRYPT_ALGO_ELGAMAL )

#define dlpParam_p			param1
#define dlpParam_g			param2
#define dlpParam_q			param3
#define dlpParam_y			param4
#define dlpParam_x			param5
#define dhParam_yPrime		param6	/* Special value for DH */

#define rsaParam_n			param1
#define rsaParam_e			param2
#define rsaParam_d			param3
#define rsaParam_p			param4
#define rsaParam_q			param5
#define rsaParam_u			param6
#define rsaParam_exponent1	param7
#define rsaParam_exponent2	param8
#define rsaParam_mont_n		montCTX1
#define rsaParam_mont_p		montCTX2
#define rsaParam_mont_q		montCTX3

/* Because there's no really clean way to throw an exception in C and the
   bnlib routines don't carry around state information like the stream
   library does, we need to perform an error check for most of the routines
   we call.  To make this slightly less ugly we define the following macro
   which performs the check for us by updating a variable called `status'
   with the result of a bnlib call */

#define CK( x )	status |= x

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Low-level capability checking and context-creation functions used when 
   creating a context in a device */

int checkCapability( const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr );
int createContextFromCapability( CRYPT_CONTEXT *cryptContext,
					const CAPABILITY_INFO FAR_BSS *capabilityInfoPtr,
					const int objectFlags );

/* Key generation-related routines */

int generateDLPKey( CRYPT_INFO *cryptInfo, const int keyBits, const int qBits );
int checkDLParams( const CRYPT_INFO *cryptInfo );
int generateBignum( BIGNUM *bn, const int noBits, const BYTE high,
					const BYTE low );
int calculateKeyID( CRYPT_INFO *cryptInfo );
int keygenCallback( void *callbackArg );

#endif /* _CRYPTCTX_DEFINED */
