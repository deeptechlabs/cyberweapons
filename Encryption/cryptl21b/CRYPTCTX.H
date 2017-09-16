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

/****************************************************************************
*																			*
*						Data Size and Crypto-related Constants				*
*																			*
****************************************************************************/

/* The quantization level for KeyInfo records.  Records which are visible
   to outsiders are padded out to a multiple of this size to obscure the
   nature of their contents.  Note that if this value is increased to >= 128,
   the code which calculates the data size for the padding will need to be
   changed since the object is an ASN.1 record for which the length encoding
   grows by one byte when the length is >= 128 */

#define KEYINFO_PADSIZE			64

/* The maximum conventional key size in bits.  In order to avoid problems
   with space inside shorter RSA-encrypted blocks, we limit the total keysize
   to 256 bits, which is adequate for all purposes - the limiting factor is
   three-key triple DES, which requires 3 * 64 bits of key and absolutely
   must have that many bits or it just reduces to two-key triple-DES.
   Unfortunately when loading a default-length key into a context we can't
   tell what the user is going to do with the generated key (for example
   whether they will export it using a very short public key) so we have to
   take the approach of using a practical length which will work even with a
   512-bit public key.  This means that for Blowfish, RC2, RC4, and RC5 the
   keylength is shorter than strictly necessary (actually for RC2 we have to
   limit the keysize to 128 bits for CMS/SMIME compatibility) */

#define MAX_KEYSIZE_BITS		256

/* The size of the key check value */

#define KEY_CHECKVALUE_SIZE		4

/* The HMAC input and output padding values */

#define HMAC_IPAD	0x36
#define HMAC_OPAD	0x5C

/* When reading a key into a public-key context, we read the data straight
   into the context-internal bignums rather than passing them in via a
   CRYPT_PKCINFO_xxx intermediary.  In this case we use the following magic
   values for the key length to tell the key load code to use the built-in
   values.  The separation of public and private loads is for private key
   read code which first reads and loads the public values and later reads,
   decrypts, and loads the private values */

#define LOAD_INTERNAL			-10
#define LOAD_INTERNAL_PUBLIC	-11
#define LOAD_INTERNAL_PRIVATE	-12

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
	const CRYPT_MODE cryptMode;		/* The encryption mode */
	const int blockSize;			/* The basic block size of the algorithm */
	const char *algoName;			/* Algorithm name */
	const char *modeName;			/* Mode name */

	/* Keying information.  Note that the maximum sizes may vary (for
	   example for two-key triple DES vs three-key triple DES) so the
	   crypt query functions should be used to determine the actual size
	   for a particular context rather than just using maxKeySize */
	const int minKeySize;			/* Minimum key size in bytes */
	const int keySize;				/* Recommended key size in bytes */
	const int maxKeySize;			/* Maximum key size in bytes */

	/* IV information */
	const int minIVsize;			/* Minimum IV size in bytes */
	const int ivSize;				/* Recommended IV size in bytes */
	const int maxIVsize;			/* Maximum IV size in bytes */

	/* The functions for implementing the algorithm */
	int ( *selfTestFunction )( void );
	int ( *initFunction )( struct CI *cryptInfoPtr, const void *cryptInfoEx );
	int ( *endFunction )( struct CI *cryptInfoPtr );
	int ( *initIVFunction )( struct CI *cryptInfoPtr, const void *iv, const int ivLength );
	int ( *initKeyFunction )( struct CI *cryptInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( struct CI *cryptInfoPtr, const int keySizeBits );
	int ( *getKeysizeFunction )( struct CI *cryptInfoPtr );
	int ( *encryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *signFunction )( struct CI *cryptInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( struct CI *cryptInfoPtr, void *buffer, int length );

	/* The results of the self-test for this algorithm */
	int selfTestStatus;

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

	/* Some algorithms have user-definable various parameters, the following
	   variables record these parameters */
	int algorithmParam1, algorithmParam2;
	BOOLEAN nonDefaultValues;		/* Whether params are non-default vals */

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
	int lastPublicComponent;		/* Last PKC component which is public */
	int lastPublicMontCTX;			/* Last MONT_CTX which is public */

	/* If this is a private key it may have X.509-related data associated
	   with it.  The following is an internal data-only certificate object
	   which contains this information */
	CRYPT_CERTIFICATE iDataCert;
	} PKC_INFO;

typedef struct {
	/* Data required to store the current state of the hashing */
	void *hashInfo;					/* Current hash state */

	/* Some algorithms have user-definable various parameters, the following
	   variables record these parameters */
	int algorithmParam1;
	BOOLEAN nonDefaultValues;		/* Whether params are non-default vals */

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

	/* Some algorithms have user-definable various parameters, the following
	   variables record these parameters */
	int algorithmParam1;
	BOOLEAN nonDefaultValues;		/* Whether params are non-default vals */

	/* MAC information.  This is the result of the hash operation, which has
	   to be stored in the context for certain implementations which return
	   the hash result immediately as part of the final part of the hashing
	   operation.  This also means we can destroy the algorithm-specific
	   information as soon as the hashing has completed */
	BYTE mac[ CRYPT_MAX_HASHSIZE ];

	/* A flag which is set if processing has completed and can't be resumed */
	BOOLEAN done;					/* Whether the operation is complete */
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

	/* If implemented using a crypto device, the object information is
	   usually stored inside the device.  The following values contain the
	   references to the crypto device and the object handle in the device */
	CRYPT_DEVICE iCryptDevice;
	long iCryptDeviceHandle;

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

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The object handle, used when sending messages to the object from
	   functions when only the CRYPT_INFO data is available */
	CRYPT_CONTEXT objectHandle;

	/* The reference count for this object.  If this drops below zero, the
	   object is destroyed */
	int refCount;					/* Reference count for object */

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the resource locking (the
	   actual values are defined in cryptos.h) */
	DECLARE_RESOURCE_LOCKING_VARS
	} CRYPT_INFO;

/* Symbolic defines for the various PKC components for different PKC
   algorithms */

#define dhParam_p			param1
#define dhParam_g			param2
#define dhParam_y			param3
#define dhParam_x			param4
#define dhParam_yPrime		param5
#define DH_LAST_PUBLIC		3

#define dsaParam_p			param1
#define dsaParam_q			param2
#define dsaParam_g			param3
#define dsaParam_y			param4
#define dsaParam_x			param5
#define DSA_LAST_PUBLIC		4

#define egParam_p			param1
#define egParam_g			param2
#define egParam_y			param3
#define egParam_x			param4
#define EG_LAST_PUBLIC		3

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
#define RSA_LAST_PUBLIC		2

/* Because there's no really clean way to throw an exception in C and the
   bnlib routines don't carry around state information like the stream
   library does, we need to perform an error check for most of the routines
   we call.  To make this slightly less ugly we define the following macro
   which performs the check for us by updating a variable called `status'
   with the result of a bnlib call */

#define CK( x )	status |= x

/****************************************************************************
*																			*
*								Useful General Macros						*
*																			*
****************************************************************************/

/* Whether an encryption mode needs an IV or not */

#define needsIV( mode )	( ( mode ) == CRYPT_MODE_CBC || \
						  ( mode ) == CRYPT_MODE_CFB || \
						  ( mode ) == CRYPT_MODE_OFB )

/****************************************************************************
*																			*
*								Internal API Functions						*
*																			*
****************************************************************************/

/* Routines to get/set algorithm-specific information.  These should really
   be implemented as capabilityInfo function pointers but this makes type
   checking difficult */

int getRC5info( const CRYPT_INFO *cryptInfo );
void setRC5info( CRYPT_INFO *cryptInfo, const int rounds );
int getSaferInfo( const CRYPT_INFO *cryptInfo, BOOLEAN *useSaferSK );
void setSaferInfo( CRYPT_INFO *cryptInfo, const BOOLEAN useSaferSK,
				   const int rounds );
BOOLEAN getSHAinfo( const CRYPT_INFO *cryptInfo );
void setSHAinfo( CRYPT_INFO *cryptInfo, const BOOLEAN isSHA );

/* Miscellaneous routines */

int generateBignum( BIGNUM *bn, const int noBits, const BYTE high,
					const BYTE low );
int calculateKeyCheckValue( const CRYPT_INFO *cryptInfo, BYTE *checkValue );
int calculateKeyID( const CRYPT_ALGO cryptAlgo, const PKC_INFO *pkcInfo,
					BYTE *keyID );
int keygenCallback( void *callbackArg );

#endif /* _CRYPTCTX_DEFINED */
