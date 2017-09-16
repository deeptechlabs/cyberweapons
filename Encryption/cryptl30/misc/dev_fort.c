/****************************************************************************
*																			*
*							cryptlib Fortezza Routines						*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

/* This file contains its own version of the various Fortezza definitions and
   values to avoid potential copyright problems with redistributing the
   Fortezza interface library header files */

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "cryptctx.h"
  #include "asn1.h"
  #include "asn1oid.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../cryptctx.h"
  #include "../keymgmt/asn1.h"
  #include "../keymgmt/asn1oid.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "cryptctx.h"
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1oid.h"
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* Uncomment the following to fake out writes to the card.  This makes 
   testing easier since it allows the code to be debugged without messing up 
   data stored on the card when the program is terminated halfway through an 
   update */

/*#define NO_UPDATE	/**/

/* Return codes */

#define CI_OK				0	/* OK */
#define CI_FAIL				1	/* Generic failure */
#define CI_INV_STATE		9	/* Device in invalid state for this fn.*/
#define CI_EXEC_FAIL		10	/* Command execution failed */
#define CI_NO_KEY			11	/* No key loaded */
#define CI_NO_IV			12	/* No IV loaded */
#define CI_NO_X				13	/* No DSA x value loaded */
#define CI_NO_CARD			-20	/* Card not present */
#define CI_BAD_CARD			-30	/* Invalid or malfunctioning card */
#define CI_BAD_TUPLES		-44	/* Bad information in card */

/* Constants */

#define CI_NULL_FLAG		0	/* No operation */

#define CI_PIN_SIZE			12	/* Maximum size of PIN */
#define CI_NAME_SIZE		32	/* Maximum size of name */
#define CI_CERT_SIZE		2048/* Maximum size of certificate */
#define CI_CERT_NAME_SIZE	32	/* Maximum size of cert label */

#define CI_SSO_PIN			37	/* SSO PIN */
#define CI_USER_PIN			42	/* User PIN */

#define CI_KEA_TYPE			5	/* KEA algorithm */
#define CI_DSA_TYPE			10	/* DSA algorithm */
#define CI_DSA_KEA_TYPE		15	/* DSA+KEA algorithm */

#define CI_INITIATOR_FLAG	0	/* Flag for KEA initiator */
#define CI_RECIPIENT_FLAG	1	/* Flag for KEA responder */

#define CI_ENCRYPT_TYPE		0	/* Cipher mode = encryption */
#define CI_DECRYPT_TYPE		1	/* Cipher mode = decryption */

#define CI_ECB64_MODE		0	/* Skipjack/ECB */
#define CI_CBC64_MODE		1	/* Skipjack/CBC */
#define CI_OFB64_MODE		2	/* Skipjack/OFB */
#define CI_CFB64_MODE		3	/* Skipjack/CFB */

#define CI_POWER_UP			0	/* Initialising card */
#define CI_UNINITIALIZED	1	/* Uninitialized/zeroized with z/PIN entered */
#define CI_INITIALIZED		2	/* Initialized card */
#define CI_SSO_INITIALIZED	3	/* SSO PIN loaded */
#define CI_LAW_INITIALIZED	4	/* LAW/CAW init'd (ie user certs loaded) */
#define CI_USER_INITIALIZED	5	/* User PIN loaded */
#define CI_STANDBY			6	/* Wait for personality to be set */
#define CI_READY			7	/* Ready for use */
#define CI_ZEROIZED			8	/* Zeroized */
#define CI_INTERNAL_FAILURE	-1	/* Bang */

/* Data types */

typedef BYTE *CI_DATA;				/* Pointer to plaintext/ciphertext */
typedef BYTE CI_PIN[ CI_PIN_SIZE + 4];	/* Longword-padded PIN */
typedef BYTE CI_CERT_STR[ CI_CERT_NAME_SIZE + 4 ];	/* Certificate label */
typedef BYTE CI_CERTIFICATE[ 2048 ];/* Certificate */
typedef BYTE CI_IV[ 24 ];			/* LEAF + IV */
typedef BYTE CI_P[ 128 ];			/* DSA p parameter */
typedef BYTE CI_Q[ 20 ];			/* DSA q parameter */
typedef BYTE CI_G[ 128 ];			/* DSA g paramter */
typedef BYTE CI_Y[ 128 ];			/* DSA y value */
typedef BYTE CI_HASHVALUE[ 20 ];	/* SHA-1 hash value */
typedef BYTE CI_SIGNATURE[ 40 ];	/* DSA signature value */
typedef BYTE CI_RA[ 128 ];			/* KSA Ra value */
typedef BYTE CI_RB[ 128 ];			/* KSA Rb value */
typedef BYTE CI_KEY[ 12 ];			/* KEA-wrapped Skipjack key */
typedef BYTE CI_RANDOM[ 20 ];		/* Random data */
typedef BYTE CI_RANDSEED[ 8 ];		/* Random seed value */
typedef BYTE CI_KS[ 10 ];			/* Storage key */
typedef unsigned int CI_STATE, *CI_STATE_PTR;	/* Device state */
typedef struct {
	int CertificateIndex;			/* Cert.number */
	CI_CERT_STR CertLabel;			/* Personality label */
	} CI_PERSON, *CI_PERSON_PTR;
typedef struct {
	int LibraryVersion;				/* CI lib.version */
	int ManufacturerVersion;		/* Hardware version */
	char ManufacturerName[ CI_NAME_SIZE + 4 ];	/* Manuf.name */
	char ProductName[ CI_NAME_SIZE + 4 ];	/* Product name */
	char ProcessorType[ CI_NAME_SIZE + 4 ];	/* CPU type */
	unsigned long UserRAMSize;		/* Bytes of user RAM */
	unsigned long LargestBlockSize;	/* Max.single data block size */
	int KeyRegisterCount;			/* Number of key registers */
	int CertificateCount;			/* Max.number of certificates */
	int CryptoCardFlag;				/* Card present if nonzero */
	int ICDVersion;					/* ICD compliance level */
	int ManufacturerSWVer;			/* Device's firmware version */
	int DriverVersion;				/* Device driver version */
	} CI_CONFIG, *CI_CONFIG_PTR;

/* Various constants not defined in the Fortezza driver code */

#define FORTEZZA_IVSIZE		24			/* Size of LEAF+IV */

#ifdef DEV_FORTEZZA

/* Return a pointer to the n-th personality in a personality list */

#define getPersonality( deviceInfo, index ) \
		( &( ( ( CI_PERSON * ) deviceInfo->personalities )[ index ] ) )

/* Prototypes for functions in cryptcap.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO cryptAlgo );

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* The number of sockets present in the system */

static int noSockets;

/* Global function pointers.  These are necessary because the functions need
   to be dynamically linked since not all systems contain the necessary
   DLL's.  Explicitly linking to them will make cryptlib unloadable on most
   systems */

#define NULL_HINSTANCE	( HINSTANCE ) NULL

static HINSTANCE hFortezza = NULL_HINSTANCE;

typedef int ( *CI_CHANGEPIN )( int PINType, CI_PIN pOldPIN, CI_PIN pNewPIN );
typedef int ( *CI_CHECKPIN )( int PINType, CI_PIN pPIN );
typedef int ( *CI_CLOSE )( unsigned int Flags, int SocketIndex );
typedef int ( *CI_DECRYPT )( unsigned int CipherSize, CI_DATA pCipher,
							 CI_DATA pPlain );
typedef int ( *CI_DELETECERTIFICATE )( int CertificateIndex );
typedef int ( *CI_DELETEKEY )( int RegisterIndex );
typedef int ( *CI_ENCRYPT )( unsigned int PlainSize, CI_DATA pPlain,
							 CI_DATA pCipher );
typedef int ( *CI_GENERATEIV )( CI_IV pIV );
typedef int ( *CI_GENERATEMEK )( int RegisterIndex, int Reserved );
typedef int ( *CI_GENERATERA )( CI_RA pRa );
typedef int ( *CI_GENERATERANDOM )( CI_RANDOM pRandom );
typedef int ( *CI_GENERATETEK )( int Flags, int RegisterIndex, CI_RA Ra, 
								 CI_RB Rb, unsigned int YSize, CI_Y pY );
typedef int ( *CI_GENERATEX )( int CertificateIndex, int AlgorithmType,
							   unsigned int PAndGSize, unsigned int QSize,
							   CI_P pP, CI_Q pQ, CI_G pG, unsigned int YSize,
							   CI_Y pY );
typedef int ( *CI_GETCERTIFICATE )( int CertificateIndex, 
									CI_CERTIFICATE pCertificate );
typedef int ( *CI_GETCONFIGURATION )( CI_CONFIG_PTR pConfiguration );
typedef int ( *CI_GETPERSONALITYLIST )( int EntryCount, 
										CI_PERSON pPersonalityList[] );
typedef int ( *CI_GETSTATE )( CI_STATE_PTR pState );
typedef int ( *CI_INITIALIZE )( int *SocketCount );
typedef int ( *CI_LOADCERTIFICATE )( int CertificateIndex, CI_CERT_STR pLabel, 
									 CI_CERTIFICATE pCertificate, long Reserved );
typedef int ( *CI_LOADINITVALUES )( CI_RANDSEED pRandSeed, CI_KS pKs );
typedef int ( *CI_LOADIV )( CI_IV pIV );
typedef int ( *CI_LOCK )( int Flags );
typedef int ( *CI_OPEN )( unsigned int *Flags, int SocketIndex );
typedef int ( *CI_RESET )( void );
typedef int ( *CI_SETKEY )( int RegisterIndex );
typedef int ( *CI_SETMODE )( int CryptoType, int CryptoMode );
typedef int ( *CI_SETPERSONALITY )( int CertificateIndex );
typedef int ( *CI_SIGN )( CI_HASHVALUE pHashValue, CI_SIGNATURE pSignature );
typedef int ( *CI_TERMINATE )( void );
typedef int ( *CI_UNLOCK )( void );
typedef int ( *CI_UNWRAPKEY )( int UnwrapIndex, int KeyIndex, CI_KEY pKey );
typedef int ( *CI_VERIFYSIGNATURE )( CI_HASHVALUE pHashValue, unsigned int YSize,
									 CI_Y pY, CI_SIGNATURE pSignature );
typedef int ( *CI_WRAPKEY )( int WrapIndex, int KeyIndex, CI_KEY pKey );
typedef int ( *CI_ZEROIZE )( void );
static CI_CHANGEPIN pCI_ChangePIN = NULL;
static CI_CHECKPIN pCI_CheckPIN = NULL;
static CI_CLOSE pCI_Close = NULL;
static CI_DECRYPT pCI_Decrypt = NULL;
static CI_DELETECERTIFICATE pCI_DeleteCertificate = NULL;
static CI_DELETEKEY pCI_DeleteKey = NULL;
static CI_ENCRYPT pCI_Encrypt = NULL;
static CI_GENERATEIV pCI_GenerateIV = NULL;
static CI_GENERATEMEK pCI_GenerateMEK = NULL;
static CI_GENERATERA pCI_GenerateRa = NULL;
static CI_GENERATERANDOM pCI_GenerateRandom = NULL;
static CI_GENERATETEK pCI_GenerateTEK = NULL;
static CI_GENERATEX pCI_GenerateX = NULL;
static CI_GETCERTIFICATE pCI_GetCertificate = NULL;
static CI_GETCONFIGURATION pCI_GetConfiguration = NULL;
static CI_GETPERSONALITYLIST pCI_GetPersonalityList = NULL;
static CI_GETSTATE pCI_GetState = NULL;
static CI_INITIALIZE pCI_Initialize = NULL;
static CI_LOADCERTIFICATE pCI_LoadCertificate = NULL;
static CI_LOADINITVALUES pCI_LoadInitValues = NULL;
static CI_LOADIV pCI_LoadIV = NULL;
static CI_LOCK pCI_Lock = NULL;
static CI_OPEN pCI_Open = NULL;
static CI_RESET pCI_Reset = NULL;
static CI_SETKEY pCI_SetKey = NULL;
static CI_SETMODE pCI_SetMode = NULL;
static CI_SETPERSONALITY pCI_SetPersonality = NULL;
static CI_SIGN pCI_Sign = NULL;
static CI_TERMINATE pCI_Terminate = NULL;
static CI_UNLOCK pCI_Unlock = NULL;
static CI_UNWRAPKEY pCI_UnwrapKey = NULL;
static CI_VERIFYSIGNATURE pCI_VerifySignature = NULL;
static CI_WRAPKEY pCI_WrapKey = NULL;
static CI_ZEROIZE pCI_Zeroize = NULL;

/* Depending on whether we're running under Win16 or Win32 we load the device
   driver under a different name */

#ifdef __WIN16__
  #define FORTEZZA_LIBNAME	"TSSP.DLL"
#else
  #define FORTEZZA_LIBNAME	"TSSP32.DLL"
#endif /* __WIN16__ */

/* Dynamically load and unload any necessary card drivers */

void deviceInitFortezza( void )
	{
	void initCapabilities( void );
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	static BOOLEAN initCalled = FALSE;

	/* If we've previously tried to init the drivers, don't try it again */
	if( initCalled )
		return;
	initCalled = TRUE;
	initCapabilities();

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	hFortezza = LoadLibrary( FORTEZZA_LIBNAME );
	SetErrorMode( errorMode );
	if( hFortezza < HINSTANCE_ERROR )
		{
		hFortezza = NULL_HINSTANCE;
		return;
		}
#else
	if( ( hFortezza = LoadLibrary( FORTEZZA_LIBNAME ) ) == NULL_HINSTANCE )
		return;
#endif /* __WIN32__ */

	/* Now get pointers to the functions */
	pCI_ChangePIN = ( CI_CHANGEPIN ) GetProcAddress( hFortezza, "CI_ChangePIN" );
	pCI_CheckPIN = ( CI_CHECKPIN ) GetProcAddress( hFortezza, "CI_CheckPIN" );
	pCI_Close = ( CI_CLOSE ) GetProcAddress( hFortezza, "CI_Close" );
	pCI_Decrypt = ( CI_DECRYPT ) GetProcAddress( hFortezza, "CI_Decrypt" );
	pCI_DeleteCertificate = ( CI_DELETECERTIFICATE ) GetProcAddress( hFortezza, "CI_DeleteCertificate" );
	pCI_DeleteKey = ( CI_DELETEKEY ) GetProcAddress( hFortezza, "CI_DeleteKey" );
	pCI_Encrypt = ( CI_ENCRYPT ) GetProcAddress( hFortezza, "CI_Encrypt" );
	pCI_GenerateIV = ( CI_GENERATEIV ) GetProcAddress( hFortezza, "CI_GenerateIV" );
	pCI_GenerateMEK = ( CI_GENERATEMEK ) GetProcAddress( hFortezza, "CI_GenerateMEK" );
	pCI_GenerateRa = ( CI_GENERATERA ) GetProcAddress( hFortezza, "CI_GenerateRa" );
	pCI_GenerateRandom = ( CI_GENERATERANDOM ) GetProcAddress( hFortezza, "CI_GenerateRandom" );
	pCI_GenerateTEK = ( CI_GENERATETEK ) GetProcAddress( hFortezza, "CI_GenerateTEK" );
	pCI_GenerateX = ( CI_GENERATEX ) GetProcAddress( hFortezza, "CI_GenerateX" );
	pCI_GetCertificate = ( CI_GETCERTIFICATE ) GetProcAddress( hFortezza, "CI_GetCertificate" );
	pCI_GetConfiguration = ( CI_GETCONFIGURATION ) GetProcAddress( hFortezza, "CI_GetConfiguration" );
	pCI_GetPersonalityList = ( CI_GETPERSONALITYLIST ) GetProcAddress( hFortezza, "CI_GetPersonalityList" );
	pCI_GetState = ( CI_GETSTATE ) GetProcAddress( hFortezza, "CI_GetState" );
	pCI_Initialize = ( CI_INITIALIZE ) GetProcAddress( hFortezza, "CI_Initialize" );
	pCI_LoadCertificate = ( CI_LOADCERTIFICATE ) GetProcAddress( hFortezza, "CI_LoadCertificate" );
	pCI_LoadInitValues = ( CI_LOADINITVALUES ) GetProcAddress( hFortezza, "CI_LoadInitValues" );
	pCI_LoadIV = ( CI_LOADIV ) GetProcAddress( hFortezza, "CI_LoadIV" );
	pCI_Lock = ( CI_LOCK ) GetProcAddress( hFortezza, "CI_Lock" );
	pCI_Open = ( CI_OPEN ) GetProcAddress( hFortezza, "CI_Open" );
	pCI_Reset = ( CI_RESET ) GetProcAddress( hFortezza, "CI_Reset" );
	pCI_SetKey = ( CI_SETKEY ) GetProcAddress( hFortezza, "CI_SetKey" );
	pCI_SetMode = ( CI_SETMODE ) GetProcAddress( hFortezza, "CI_SetMode" );
	pCI_SetPersonality = ( CI_SETPERSONALITY ) GetProcAddress( hFortezza, "CI_SetPersonality" );
	pCI_Sign = ( CI_SIGN ) GetProcAddress( hFortezza, "CI_Sign" );
	pCI_Terminate = ( CI_TERMINATE ) GetProcAddress( hFortezza, "CI_Terminate" );
	pCI_Unlock = ( CI_UNLOCK ) GetProcAddress( hFortezza, "CI_Unlock" );
	pCI_UnwrapKey = ( CI_UNWRAPKEY ) GetProcAddress( hFortezza, "CI_UnwrapKey" );
	pCI_VerifySignature = ( CI_VERIFYSIGNATURE ) GetProcAddress( hFortezza, "CI_VerifySignature" );
	pCI_WrapKey = ( CI_WRAPKEY ) GetProcAddress( hFortezza, "CI_WrapKey" );
	pCI_Zeroize = ( CI_ZEROIZE ) GetProcAddress( hFortezza, "CI_Zeroize" );

	/* Make sure we got valid pointers for every device function */
	if( pCI_ChangePIN == NULL || pCI_CheckPIN == NULL || pCI_Close == NULL ||
		pCI_Decrypt == NULL || pCI_DeleteCertificate == NULL || 
		pCI_DeleteKey == NULL || pCI_Encrypt == NULL || 
		pCI_GenerateIV == NULL || pCI_GenerateMEK == NULL || 
		pCI_GenerateRa == NULL || pCI_GenerateRandom == NULL || 
		pCI_GenerateTEK == NULL || pCI_GenerateX == NULL || 
		pCI_GetCertificate == NULL || pCI_GetConfiguration == NULL || 
		pCI_GetPersonalityList == NULL || pCI_GetState == NULL || 
		pCI_Initialize == NULL || pCI_LoadCertificate == NULL || 
		pCI_LoadInitValues == NULL || pCI_LoadIV == NULL || 
		pCI_Lock == NULL || pCI_Open == NULL || pCI_Reset == NULL || 
		pCI_SetKey == NULL || pCI_SetMode == NULL || 
		pCI_SetPersonality == NULL || pCI_Sign == NULL || 
		pCI_Terminate == NULL || pCI_Unlock == NULL || 
		pCI_UnwrapKey == NULL || pCI_VerifySignature == NULL || 
		pCI_WrapKey == NULL || pCI_Zeroize == NULL )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		return;
		}

	/* Initialise the Fortezza library */
	if( pCI_Initialize( &noSockets ) != CI_OK )
		{
		/* Free the library reference and reset the handle */
		FreeLibrary( hFortezza );
		hFortezza = NULL_HINSTANCE;
		}
	}

void deviceEndFortezza( void )
	{
	if( hFortezza != NULL_HINSTANCE )
		{
		pCI_Terminate();
		FreeLibrary( hFortezza );
		}
	hFortezza = NULL_HINSTANCE;
	}

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a Fortezza-specific error to a cryptlib error */

static int mapError( const int errorCode, const int defaultError )
	{
	switch( errorCode )
		{
		case CI_OK:
			return( CRYPT_OK );
		case CI_NO_CARD:
		case CI_BAD_CARD:
			return( CRYPT_ERROR_SIGNALLED );
		case CI_INV_STATE:
		case CI_NO_IV:
		case CI_NO_KEY:
			return( CRYPT_ERROR_NOTINITED );
		case CI_EXEC_FAIL:
			return( CRYPT_ERROR_FAILED );
		}

	return( defaultError );
	}

/* Set up a PIN in the format required by the Fortezza driver */

static void initPIN( CI_PIN pinBuffer, const void *pin, const int pinLength )
	{
	memset( pinBuffer, 0, sizeof( CI_PIN ) );
	if( pinLength )
		memcpy( pinBuffer, pin, pinLength );
	pinBuffer[ pinLength ] = '\0';	/* Ensure PIN is null-terminated */	
	}

/* Find a free key register */

static int findFreeKeyRegister( DEVICE_INFO *deviceInfo )
	{
	int mask = 2, i;

	/* Search the register-in-use flags for a free register */
	for( i = 1; i < deviceInfo->keyRegisterCount; i++ )
		{
		if( !( deviceInfo->keyRegisterFlags & mask ) )
			break;
		mask <<= 1;
		}
	
	return( ( i == deviceInfo->keyRegisterCount ) ? \
			CRYPT_ERROR_OVERFLOW : i );
	}

/* Find a free key/certificate slot */

static int findFreeCertificate( DEVICE_INFO *deviceInfo )
	{
	CI_PERSON *personalityList = deviceInfo->personalities;
	int certIndex;

	for( certIndex = 0; certIndex < deviceInfo->personalityCount; 
		 certIndex++ )
		if( personalityList[ certIndex ].CertLabel[ 0 ] == '\0' )
			return( certIndex );

	return( CRYPT_ERROR );
	}

/* Find a certificate/personality using the labelling system defined in
   SDN.605 */

static int findCertificate( DEVICE_INFO *deviceInfo, const char *label,
							const int labelLength )
	{
	static const char *names[] = { 
		"DSAI", "DSAO", "DSAX",		/* DSA individual, org, cert-only */
		"KEAK", "KEAX",				/* KEA, cert-only */
		"CAX1", "PCA1", "PAA1",		/* DSA CA, PCA, PAA */
		"INKS", "ONKS",				/* Legacy DSA+KEA individual, org */
		"INKX", "ONKX",				/* Legacy KEA individual, org */
		NULL };
	CI_PERSON *personalityList = deviceInfo->personalities;
	int labelIndex, certIndex;

	/* If a label is specified, look for the cert for the personality with 
	   the given label */
	if( label != NULL )
		{
		for( certIndex = 0; certIndex < deviceInfo->personalityCount; 
			 certIndex++ )
			if( !memcmp( personalityList[ certIndex ].CertLabel + 8, label, 
						 labelLength ) )
				return( certIndex );
		
		return( CRYPT_ERROR );
		}

	/* No label given, look for the certificate in order of likeliness.  
	   First we look for a personal certificate with a signing key, if that
	   fails we look for an organisational certificate with a signing key */
	for( labelIndex = 0; names[ labelIndex ] != NULL; labelIndex++ )
		for( certIndex = 0; certIndex < deviceInfo->personalityCount; 
			 certIndex++ )
			if( !strncmp( personalityList[ certIndex ].CertLabel, \
						  names[ labelIndex ], 4 ) )
				return( certIndex );

	return( CRYPT_ERROR );
	}

/* Build a list of hashes of all certificates on the card */

static void getCertificateInfo( DEVICE_INFO *deviceInfo )
	{
	CI_PERSON *personalityList = deviceInfo->personalities;
	CI_HASHVALUE *hashList = deviceInfo->certHashes;
	CI_CERTIFICATE certificate;
	HASHFUNCTION hashFunction;
	int hashSize, certIndex, certSize;

	/* Get the hash algorithm information */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	memset( hashList, 0, deviceInfo->personalityCount * sizeof( CI_HASHVALUE ) );
	for( certIndex = 0; certIndex < deviceInfo->personalityCount; certIndex++ )
		{
		/* If there's no cert present at this location, continue */
		if( !personalityList[ certIndex ].CertLabel[ 0 ] || \
			pCI_GetCertificate( certIndex, certificate ) != CI_OK )
			continue;

		/* Get the hash of the certificate data.  Sometimes the card can
		   contain existing cert entries with garbage values so we don't 
		   hash the cert data if it doesn't look right */
		certSize = getObjectLength( certificate, sizeof( CI_CERTIFICATE ) );
		if( certificate[ 0 ] != BER_SEQUENCE || \
			certSize < 256 || certSize > CI_CERT_SIZE )
			continue;
		hashFunction( NULL, hashList[ certIndex ], certificate, certSize, 
					  HASH_ALL );
		}
	deviceInfo->certHashesInitialised = TRUE;
	}

/* Update certificate/personality information to reflect changes made in the 
   device */

static void updateCertificateInfo( DEVICE_INFO *deviceInfo, 
								   const int certIndex, 
								   const void *certificate, 
								   const int certSize, const char *label )
	{
	CI_PERSON *personality = getPersonality( deviceInfo, certIndex );
	CI_HASHVALUE *hashList = deviceInfo->certHashes;

	/* Update the hash for the certificate if necessary */
	if( deviceInfo->certHashesInitialised )
		if( certSize != CRYPT_UNUSED )
			{
			HASHFUNCTION hashFunction;
			int hashSize;

			getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );
			hashFunction( NULL, hashList[ certIndex ], ( void * ) certificate, 
						  certSize, HASH_ALL );
			}
		else
			/* There's no cert present at this location, make sure the hash
			   is zero */
			memset( hashList[ certIndex ], 0, sizeof( CI_HASHVALUE ) );

	/* Update the label for the certificate/personality */
	memset( personality->CertLabel, 0, sizeof( CI_CERT_STR ) );
	strcpy( personality->CertLabel, label );
	}

/* Set up certificate information and load it into the card */

static int updateCertificate( DEVICE_INFO *deviceInfo, const int certIndex, 
							  const CRYPT_CERTIFICATE iCryptCert, 
							  const void *certData, const int certDataSize,
							  const char *labelData, const int parentIndex )
	{
	CI_PERSON *personalityList = deviceInfo->personalities;
	CI_CERT_STR label;
	CI_CERTIFICATE certificate;
	int certificateLength = CRYPT_UNUSED, status;

	/* Set up the label for the certificate.  This is somewhat ad hoc since
	   non-DOD Fortezza usage won't follow the somewhat peculiar certification
	   heirarchy designed for DOD/government use, so we just mark a cert as 
	   CA/individual rather than CA/PCA/PAA.  In addition we select between 
	   organisational and individual certs based on whether an 
	   organizationName or organizationalUnitName is present */
	memset( label, 0, sizeof( CI_CERT_STR ) );
	if( certData == NULL )
		{
		CI_PERSON *personality = getPersonality( deviceInfo, certIndex );
		const BOOLEAN newEntry = personality->CertLabel[ 0 ] ? FALSE : TRUE;
		int value;

		/* Determine the appropriate label for the cert */
		status = krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE,
								  &value, CRYPT_CERTINFO_CA );
		if( cryptStatusOK( status ) && value )
			strcpy( label, "CAX1FF" );
		else
			{
			/* If there's a key agreement key usage, it must be KEA */
			status = krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE,
									  &value, CRYPT_CERTINFO_KEYUSAGE );
			if( cryptStatusOK( status ) && \
				( value & ( CRYPT_KEYUSAGE_KEYAGREEMENT | \
							CRYPT_KEYUSAGE_ENCIPHERONLY | \
							CRYPT_KEYUSAGE_DECIPHERONLY ) ) )
				strcpy( label, "KEAKFF" );
			else
				{
				RESOURCE_DATA msgData;

				/* Select the SubjectName as the current DN and check whether
				   there's organisation-related components present.  Given the
				   dog's breakfast of DN components present in most certs this
				   will probably misidentify individual keys as organisational 
				   ones some of the time, but it's unlikely that anything 
				   distinguishes between I and O keys anyway */
				value = CRYPT_UNUSED;
				krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
								 &value, CRYPT_CERTINFO_SUBJECTNAME );
				setResourceData( &msgData, NULL, 0 );
				status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								CRYPT_CERTINFO_ORGANIZATIONNAME );
				if( status == CRYPT_ERROR_NOTFOUND )
					{
					setResourceData( &msgData, NULL, 0 );
					status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
					}
				strcpy( label, ( status == CRYPT_ERROR_NOTFOUND ) ? \
						"DSAIFF" : "DSAOFF" );
				}

			/* If it's a completely new entry (ie one which doesn't 
			   correspond to a private key), mark it as a cert-only key */
			if( newEntry )
				label[ 3 ] = 'X';
			}
		sprintf( label + 6, "%02X", ( parentIndex != CRYPT_UNUSED ) ? 
				 parentIndex : 0xFF );

		/* Special-case override: If this is certificate slot 0, it's a PAA 
		   cert being installed by the SSO */
		if( !certIndex )
			memcpy( label, "PAA1FFFF", 8 );

		/* If there's label data supplied (which happens for cert-only certs
		   with no associated personality), use that */
		if( labelData != NULL )
			strcpy( label + 8, labelData );
		else
			/* Reuse the existing label */
			strcpy( label + 8, personality->CertLabel + 8 );
		}
	else
		{
		/* Set the SDN.605 related certificate locator to indicate that no 
		   parent or sibling certificates are present for this key, and use 
		   the cryptlib U/E specifier "TEMP" to indicate a temporary key 
		   awaiting a certificate */
		strcpy( label, "TEMPFFFF" );
		strncpy( label + 8, labelData, 24 );
		}

	/* Set up the certificate data and send it to the card */
	memset( certificate, 0, sizeof( CI_CERTIFICATE ) );
	if( certData == NULL )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, NULL, 0 );
		status = krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		if( cryptStatusOK( status ) )
			{
			certificateLength = msgData.length;
			if( certificateLength > sizeof( CI_CERTIFICATE ) )
				return( CRYPT_ERROR_OVERFLOW );
			setResourceData( &msgData, certificate, certificateLength );
			status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								CRYPT_IATTRIBUTE_ENC_CERT );
			}
		if( cryptStatusError( status ) )
			return( status );
		}
	else
		memcpy( certificate, certData, certDataSize );
#ifndef NO_UPDATE
	status = pCI_LoadCertificate( certIndex, label, certificate, 0 );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
#endif /* NO_UPDATE */

	/* Update the in-memory copy of the cert information */
	updateCertificateInfo( deviceInfo, certIndex, certificate, 
						   certificateLength, label );

	return( CRYPT_OK );
	}

/* Update a card using the certs in a cert chain */

static int updateCertChain( DEVICE_INFO *deviceInfo,
							const CRYPT_CERTIFICATE iCryptCert,
							const int leafCertIndex )
	{
	CI_PERSON *personalityList = deviceInfo->personalities;
	BOOLEAN presentList[ 16 ];
	int certList[ 16 ], parentList[ 16 ];
	int chainIndex = 0, freeCertIndex = 1, oldCertIndex, value, i;

	/* Initialise the certificate index information and hashes for the certs
	   on the card if necessary.  certList[] contains the mapping of certs in
	   the chain to positions in the card, parentList[] contains the mapping
	   of certs in the chain to the position of their parents in the card */
	for( i = 0; i < 16; i++ )
		{
		presentList[ i ] = FALSE;
		certList[ i ] = parentList[ i ] = CRYPT_UNUSED;
		}
	if( !deviceInfo->certHashesInitialised )
		getCertificateInfo( deviceInfo );

	/* Start at the top-level cert and work our way down, which ensures that
	   the CA certs appear first, and that if an update fails, the parent
	   cert pointers point to valid fields (since higher-level certs are
	   added first) */
	krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORLAST, CRYPT_CERTINFO_CURRENT_CERTIFICATE );

	/* Pass 1: Build an index of cert and parent cert positions in the card.  
	   Once this loop has completed, certList[] contains a mapping from cert 
	   chain position to position in the card, and parentList[] contains a 
	   mapping from cert chain position to parent cert position in the card */
	do
		{
		CI_HASHVALUE *hashList = deviceInfo->certHashes;
		RESOURCE_DATA msgData;
		CI_HASHVALUE hash;
		BOOLEAN isPresent = FALSE;
		int certIndex;

		/* Get the hash for this cert and check whether it's already present */
		setResourceData( &msgData, &hash, sizeof( CI_HASHVALUE ) );
		if( cryptStatusError( \
			krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							 &msgData, CRYPT_CERTINFO_FINGERPRINT_SHA ) ) )
			return( CRYPT_ARGERROR_NUM1 );
		for( certIndex = 0; certIndex < deviceInfo->personalityCount; certIndex++ )
			if( !memcmp( hashList[ certIndex ], hash, sizeof( CI_HASHVALUE ) ) )
				{
				isPresent = TRUE;
				break;
				}

		/* Set the mapping from cert to parent cert position in the card.  
		   The cert at position 0 is the root cert */
		if( chainIndex != 0 )
			parentList[ chainIndex ] = oldCertIndex;
		
		/* Set the mapping from cert to position in the card */
		if( isPresent )
			{
			certList[ chainIndex ] = certIndex;
			presentList[ chainIndex ] = TRUE;
			}
		else
			{
			/* Make sure there's room for more certificates in the card */
			if( freeCertIndex >= deviceInfo->personalityCount )
				return( CRYPT_ERROR_OVERFLOW );	/* No more room in card */

			/* Allocate this cert to the next free position in the card */
			while( freeCertIndex < deviceInfo->personalityCount && \
				   personalityList[ freeCertIndex ].CertLabel[ 0 ] != '\0' )
				freeCertIndex++;
			certList[ chainIndex ] = freeCertIndex;
			}

		/* Remember the just-assigned position in the card and move on to the
		   next cert in the chain */
		oldCertIndex = certList[ chainIndex ];
		chainIndex++;
		}
	while( krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							MESSAGE_VALUE_CURSORPREVIOUS,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );

	/* The last cert in the chain will either already be present, or be 
	   present in raw-key form.  If it's present in raw-key form the previous
	   code will add it as a pseudo-new cert, so we go back and set its index
	   to the actual position without marking it as present */
	if( certList[ chainIndex - 1 ] == freeCertIndex )
		certList[ chainIndex - 1 ] = leafCertIndex;

	/* Pass 2: Update either the label or cert+label as required */
	value = CRYPT_CURSOR_LAST;
	krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, &value, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	value = CRYPT_CURSOR_PREVIOUS;
	chainIndex = 0;
	do
		{
		const int parentIndex = parentList[ chainIndex ];
		const int certIndex = certList[ chainIndex ];
		const BOOLEAN isPresent = presentList[ chainIndex++ ];
		char name[ CRYPT_MAX_TEXTSIZE + 1 ], *labelPtr = NULL;
		int status;

		/* If the cert is already present, make sure the parent index info
		   is correct */
		if( isPresent )
			{
			CI_CERTIFICATE certificate;
			char buffer[ 8 ];
			int index;

			/* If the cert is present and the parent cert index is correct,
			   continue */
			if( ( sscanf( personalityList[ certIndex ].CertLabel + 6, "%02X", 
						  &index ) == 1 ) && \
				( parentIndex == index || parentIndex == CRYPT_UNUSED ) )
				continue;

			/* Update the parent cert index in the label, read the cert, and 
			   write it back out with the new label */
			sprintf( buffer, "%02X", parentIndex );
			memcpy( personalityList[ certIndex ].CertLabel + 6, buffer, 2 );
			status = pCI_GetCertificate( certIndex, certificate );
#ifndef NO_UPDATE
			if( status == CI_OK )
				status = pCI_LoadCertificate( certIndex, 
									personalityList[ certIndex ].CertLabel,
									certificate, 0 );
#endif /* NO_UPDATE */
			if( status != CI_OK )
				return( mapError( status, CRYPT_ERROR_WRITE ) );
			continue;
			}
		
		/* If we're adding a new cert for a non-present personality, get 
		   SubjectName information from the cert to use as the label and make 
		   sure it's within the maximum allowed length.  Some certs don't 
		   have CN components, so we try for the OU instead.  If that also 
		   fails, we try for the O, and if that fails we  just use a dummy 
		   label */
		if( certIndex != leafCertIndex || !certIndex )
			{
			RESOURCE_DATA msgData;

			value = CRYPT_UNUSED;
			krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
							 &value, CRYPT_CERTINFO_SUBJECTNAME );
			setResourceData( &msgData, name, CRYPT_MAX_TEXTSIZE );
			status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								&msgData, CRYPT_CERTINFO_COMMONNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				status = krnlSendMessage( iCryptCert, 
								RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
								CRYPT_CERTINFO_ORGANIZATIONALUNITNAME );
			if( status == CRYPT_ERROR_NOTFOUND )
				strcpy( name, "CA certificate-only entry" );
			else
				name[ min( msgData.length, 24 ) ] = '\0';
			labelPtr = name;
			}

		/* Write the new cert and label */
		status = updateCertificate( deviceInfo, certIndex, iCryptCert, 
									NULL, 0, labelPtr, parentIndex );
		if( cryptStatusError( status ) )
			return( status );
		}
	while( krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, &value,
							CRYPT_CERTINFO_CURRENT_CERTIFICATE ) == CRYPT_OK );
	
	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Table of mechanisms supported by this device.  These are sorted in order 
   of frequency of use in order to make lookups a bit faster */

int exportKEA( DEVICE_INFO *deviceInfo, MECHANISM_WRAP_INFO *mechanismInfo );
int importKEA( DEVICE_INFO *deviceInfo, MECHANISM_WRAP_INFO *mechanismInfo );

static const MECHANISM_FUNCTION_INFO objectMechanisms[] = {
	{ RESOURCE_MESSAGE_DEV_EXPORT, MECHANISM_KEA, exportKEA },
	{ RESOURCE_MESSAGE_DEV_IMPORT, MECHANISM_KEA, importKEA },
	{ RESOURCE_MESSAGE_NONE, MECHANISM_NONE, NULL }
	};

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	/* Clear the personality list if it exists */
	if( deviceInfo->personalities != NULL )
		{
		zeroise( deviceInfo->personalities, 
				 deviceInfo->personalityCount * sizeof( CI_PERSON ) );
		free( deviceInfo->personalities );
		deviceInfo->personalities = NULL;
		deviceInfo->personalityCount = 0;
		}
	if( deviceInfo->certHashes != NULL )
		{
		zeroise( deviceInfo->certHashes, 
				 deviceInfo->personalityCount * sizeof( CI_HASHVALUE ) );
		free( deviceInfo->certHashes );
		deviceInfo->certHashes = NULL;
		deviceInfo->certHashesInitialised = FALSE;
		}

	/* Unlock the socket and close the session with the device */
	if( deviceInfo->flags & DEVICE_LOGGEDIN )
		{
		pCI_Unlock();
		deviceInfo->flags &= ~DEVICE_LOGGEDIN;
		}
	pCI_Close( CI_NULL_FLAG, deviceInfo->slotHandle );
	}

/* Open a session with the device */

static int initDeviceFunction( DEVICE_INFO *deviceInfo, const char *name,
							   const int nameLength )
	{
	CI_CONFIG deviceConfiguration;
	int socket, status;

	UNUSED( name );

	/* The Fortezza open is in theory a bit problematic since the open will 
	   succeed even if there's no device in the socket, so after we perform 
	   the open we reset the card and check its state to make sure we're not 
	   just rhapsodising into the void.  In practice the currently available
	   (1996-vintage non PnP) NT Fortezza driver won't load unless there's a
	   card inserted so this isn't usually a problem, but multi-slot readers
	   with the card inserted in a slot other than the first one, possible 
	   future drivers, and the Unix driver (which has a dedicated daemon to 
	   handle the card) may not exhibit this behaviour so we check for things
	   working in the manner specified in the docs.

	   The choice of socket for the card can be a bit confusing.  According 
	   to some docs the socket can start from 0 (in violation of the spec),
	   whereas others say they should start from 1, since it doesn't hurt to
	   start from 0 we go from there (typically we just get a 
	   CI_INV_SOCKET_INDEX for slot 0).  Once we've done that, we reset the 
	   card to get it into a known state (although judging by the equivalent
	   time delay of CI_Open() and CI_Reset(), the open does this anyway) and
	   check that a card is actually present (see the comments above - the 
	   NSA must be using their own drivers recovered from crashed UFO's if 
	   their ones really do behave as documented).

	   In addition, since cryptlib's LAW/CAW functionality is currently 
	   disabled (it's unlikely that vendors would make Uninitialised (state = 
	   1) cards available), we also make sure the card is in a usable state, 
	   meaning that it's ready for use, either waiting for a user PIN or with 
	   the PIN already set.  If you have access to Uninitialised-state cards,
	   remove this check and uncomment the code to handle the 
	   CRYPT_DEVINFO_INITIALISE message */
	for( socket = 0; socket <= noSockets; socket++ )
		{
		CI_STATE deviceState;

		/* Try and open the card in the current socket */
		status = pCI_Open( CI_NULL_FLAG, socket );
		if( status != CI_OK )
			continue;
		deviceInfo->slotHandle = socket;

		/* We've opened the card, reset it to get it into a known state
		   and make sure the state is valid.  Unfortunately the exact 
		   definition of a valid state is a bit tricky, for example we 
		   shouldn't allow the initialised or SSO initialised states here 
		   since there doesn't appear to be any way to get from them to 
		   CAW initialised at this point (that is, you need to go 
		   uninitialised -> initialised -> SSO initialised -> CAW 
		   initialised in a straight sequence), however we need to get
		   past this point in order to perform the only valid operation on
		   the card (zeroise) so we have to let these pass even though
		   there's not much we can do in them */
		status = pCI_Reset();
		if( status == CI_OK )
			status = pCI_GetState( &deviceState );
		if( status != CI_OK || \
			( deviceState == CI_POWER_UP || \
			  deviceState == CI_INTERNAL_FAILURE ) )
			{
			pCI_Close( CI_NULL_FLAG, socket );
			if( status == CI_OK )
				status = CI_INV_STATE;
			continue;
			}
		deviceInfo->flags = DEVICE_ACTIVE | DEVICE_NEEDSLOGIN;
		break;
		}
	if( status != CI_OK )
		{
		deviceInfo->errorCode = status;
		return( CRYPT_ERROR_OPEN );
		}

	/* Set up device-specific information.  We can't read the personality 
	   list until the user logs on, so all we can do at this point is 
	   allocate memory for it.  Note that personality 0 can never be selected
	   and so it isn't returned when the personality info is read, this leads 
	   to confusing fencepost errors so when we allocate/read the personality
	   info we leave space for a zero-th personality which is never used */
	pCI_GetConfiguration( &deviceConfiguration );
	deviceInfo->largestBlockSize = deviceConfiguration.LargestBlockSize;
	deviceInfo->minPinSize = 4;
	deviceInfo->maxPinSize = CI_PIN_SIZE;
	deviceInfo->keyRegisterCount = deviceConfiguration.KeyRegisterCount;
	deviceInfo->keyRegisterFlags = 1;	/* Register 0 is reserved */
	deviceInfo->personalityCount = deviceConfiguration.CertificateCount + 1;
	deviceInfo->personalities = malloc( deviceInfo->personalityCount * \
										sizeof( CI_PERSON ) );
	deviceInfo->certHashes = malloc( deviceInfo->personalityCount * \
									 sizeof( CI_HASHVALUE ) );
	deviceInfo->certHashesInitialised = FALSE;
	deviceInfo->currentPersonality = CRYPT_ERROR;
	if( deviceInfo->personalities == NULL || deviceInfo->certHashes == NULL )
		{
		shutdownDeviceFunction( deviceInfo );
		return( CRYPT_ERROR_MEMORY );
		}
	memset( deviceInfo->personalities, 0, 
			deviceInfo->personalityCount * sizeof( CI_PERSON ) );
	memset( deviceInfo->certHashes, 0, 
			deviceInfo->personalityCount * sizeof( CI_HASHVALUE ) );

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	STATIC_FN int findCertificate( DEVICE_INFO *deviceInfo, const char *label, 
								   const int labelLength );
	int status;

	/* Handle user authorisation */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		CI_PERSON *personalityList = deviceInfo->personalities;
		CI_PIN pin;
		BYTE ivBuffer[ 64 ];	/* For LEAF handling */
		int certIndex;

		initPIN( pin, data1, data1Length );
		status = pCI_CheckPIN( ( type == CRYPT_DEVINFO_AUTHENT_USER ) ? \
							   CI_USER_PIN : CI_SSO_PIN, pin );
		if( status != CI_OK )
			return( ( status == CI_FAIL ) ? CRYPT_ERROR_WRONGKEY : \
					mapError( status, CRYPT_ERROR_WRONGKEY ) );

		/* Get the list of device personalities (skipping the zero-th 
		   personality which can't be selected) and lock the device for our 
		   exclusive use.  We should really do this as soon as we open the 
		   device to make sure the user isn't presented with any nasty 
		   surprises due to state changes caused by other active sessions 
		   with the device, but the driver won't let us do it until we've 
		   authenticated ourselves to the device */
		status = pCI_GetPersonalityList( deviceInfo->personalityCount - 1, 
										 &personalityList[ 1 ] );
		if( status == CI_OK )
			{
			int index;

			/* Set a label for the zero-th personality (which can't be 
			   explicitly accessed but whose cert can be read) to make sure 
			   it isn't treated as an empty personality slot */
			strcpy( personalityList[ 0 ].CertLabel, 
					"PAA1FFFFPersonality 0 dummy label" );

			/* Perform a sanity check for certificate indices.  The 
			   documentation implies that the certificate index always 
			   matches the personality index (skipping the zero-th 
			   personality), but doesn't seem to mandate this anywhere so 
			   we make sure things really are set up this way */
			for( index = 0; index < deviceInfo->personalityCount; index++ )
				{
				CI_PERSON *personality = getPersonality( deviceInfo, index );

				if( personality->CertificateIndex != 0 && \
					personality->CertificateIndex != index )
					{
					status = CI_BAD_TUPLES;
					break;
					}
				}
			}
		if( status == CI_OK )
			status = pCI_Lock( CI_NULL_FLAG );
		if( status != CI_OK )
			{
			pCI_Reset();	/* Log off */
			deviceInfo->errorCode = status;
			return( CRYPT_ERROR_FAILED );
			}
		deviceInfo->flags |= DEVICE_LOGGEDIN;		

		/* Look for the most likely required personality (other than 
		   personality 0, which is a non-personality used for the CA
		   root cert) and set it as the currently active one.  If this 
		   fails we stay with the default personality for lack of any 
		   better way to handle it */
		certIndex = findCertificate( deviceInfo, NULL, 0 );
		if( !cryptStatusError( certIndex ) && certIndex )
			{
			pCI_SetPersonality( certIndex );
			deviceInfo->currentPersonality = certIndex;
			}

		/* Handle LEAF suppression.  On LEAF-suppressed cards the LEAF bytes
		   are replaced by 'THIS IS NOT LEAF', in case there are cards which
		   use a different string we remember it with the device info so we 
		   can load LEAF-less IV's */
		status = pCI_DeleteKey( 1 );
		if( status == CI_OK )
			status = pCI_GenerateMEK( 1, 0 );
		if( status == CI_OK )
			status = pCI_SetKey( 1 );
		if( status == CI_OK )
			status = pCI_GenerateIV( ivBuffer );
		memcpy( deviceInfo->leafString, ( status == CI_OK ) ? \
				ivBuffer : "THIS IS NOT LEAF", 16 );
		pCI_DeleteKey( 1 );

		return( CRYPT_OK );
		}

	/* Handle authorisation value change */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER || \
		type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		CI_PIN oldPIN, newPIN;

		initPIN( oldPIN, data1, data1Length );
		initPIN( newPIN, data2, data2Length );

		status = pCI_ChangePIN( ( type == CRYPT_DEVINFO_SET_AUTHENT_USER ) ? \
								CI_USER_PIN : CI_SSO_PIN, oldPIN, newPIN );
		return( ( status == CI_FAIL ) ? CRYPT_ERROR_WRONGKEY : \
				mapError( status, CRYPT_ERROR_WRONGKEY ) );
		}

	/* Handle initialisation */
	if( type == CRYPT_DEVINFO_INITIALISE )
		{
		CI_RANDOM randomBuffer;
		CI_STATE deviceState;
		CI_PIN pin;

		/* Make sure the device is in the uninitialised state */
		status = pCI_GetState( &deviceState );
		if( status != CI_OK || deviceState != CI_UNINITIALIZED )
			return( CRYPT_ERROR_INITED );

		/* Log on with the SSO PIN */
		initPIN( pin, data1, data1Length );
		status = pCI_CheckPIN( CI_SSO_PIN, pin );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );

		/* Load the random number seed and storage key from the device's
		   RNG output and make sure the card has now in the initialised
		   state */
		status = pCI_GenerateRandom( randomBuffer );
		if( status == CI_OK )
			status = pCI_LoadInitValues( randomBuffer, 
										 randomBuffer + sizeof( CI_RANDSEED ) );
		zeroise( randomBuffer, sizeof( CI_RANDOM ) );
		if( status == CI_OK )
			status = pCI_GetState( &deviceState );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		if( deviceState != CI_INITIALIZED )
			return( CRYPT_ERROR_FAILED );
		return( CRYPT_OK );
		}

	/* Handle zeroisation */
	if( type == CRYPT_DEVINFO_ZEROISE )
		{
		CI_STATE deviceState;
		CI_PIN pin;

		/* Zeroise the card */
		status = pCI_Zeroize();
		if( status == CI_OK )
			status = pCI_GetState( &deviceState );
		if( status != CI_OK )
			return( mapError( status, CRYPT_ERROR_FAILED ) );
		if( deviceState != CI_ZEROIZED )
			return( CRYPT_ERROR_FAILED );

		/* Log on with the zeroise PIN to move it into the uninitialised 
		   state */
		initPIN( pin, data1, data1Length );
		status = pCI_CheckPIN( CI_SSO_PIN, pin );
		return( mapError( status, CRYPT_ERROR_WRONGKEY ) );
		}

	assert( NOTREACHED );
	return( CRYPT_ERROR_NOTAVAIL );	/* Get rid of compiler warning */
	}

/****************************************************************************
*																			*
*						 	Misc.Device Interface Routines					*
*																			*
****************************************************************************/

/* Get random data from the device */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length )
	{
	CI_RANDOM randomBuffer;
	BYTE *bufPtr = buffer;
	int count, status;

	/* Get as many 20-byte blocks as required to fill the request */
	for( count = 0; count < length; count += 20 )
		{
		const int noBytes = min( 20, length - count );

		status = pCI_GenerateRandom( randomBuffer );
		if( status != CI_OK )
			break;
	
		memcpy( bufPtr, randomBuffer, noBytes );
		bufPtr += noBytes;
		}
	zeroise( randomBuffer, 20 );

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Instantiate an object in a device.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate).  If the
   value being read is a public key and there's a certificate attached, the
   instantiated object is a native cryptlib object rather than a device
   object with a native certificate object attached because there doesn't 
   appear to be any good reason to create the public-key object in the device, 
   and the cryptlib native object will probably be faster anyway */

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	static const int keySize = 128;
	const CAPABILITY_INFO *capabilityInfoPtr;
	CRYPT_CERTIFICATE iCryptCert;
	CRYPT_ALGO cryptAlgo;
	CI_PERSON *personality;
	CI_CERTIFICATE certificate;
	RESOURCE_DATA msgData;
	BOOLEAN certPresent = TRUE;
	int certIndex, status;

	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the referenced personality on the device and determine the 
	   algorithm type for the key */
	certIndex = findCertificate( deviceInfo, keyID, keyIDlength );
	if( certIndex == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		/* If we're just checking whether an object exists, return now */
		return( CRYPT_OK );
	personality = getPersonality( deviceInfo, certIndex );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		{
		/* All we want is the key label, copy it back to the caller and
		   exit */
		*auxInfoLength = strlen( personality->CertLabel + 8 );
		if( auxInfo != NULL )
			memcpy( auxInfo, personality->CertLabel + 8, *auxInfoLength );
		return( CRYPT_OK );
		}
	status = pCI_GetCertificate( certIndex, certificate );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_READ ) );
	if( !memcmp( personality->CertLabel, "TEMP", 4 ) )
		{
		STREAM stream;

		/* It's a work in progress, read the algorithm from the start of the 
		   public key data */
		sMemConnect( &stream, certificate, 128 );
		status = readSequence( &stream, NULL );
		if( !cryptStatusError( status ) )
			status = readAlgoID( &stream, &cryptAlgo );
		sMemDisconnect( &stream );
		if( cryptStatusError( status ) )
			return( status );

		/* Remember that there's no cert available for this key */
		certPresent = FALSE;
		}
	else
		/* It's a certificate, determine the algorithm type from the label */
		if( !memcmp( personality->CertLabel, "DSA", 3 ) || \
			!memcmp( personality->CertLabel, "CAX", 3 ) || \
			!memcmp( personality->CertLabel, "PCA", 3 ) || \
			!memcmp( personality->CertLabel, "PAA", 3 ) )
			cryptAlgo = CRYPT_ALGO_DSA;
		else
			if( !memcmp( personality->CertLabel, "KEA", 3 ) )
				cryptAlgo = CRYPT_ALGO_KEA;
			else
				return( CRYPT_ERROR_BADDATA );
	capabilityInfoPtr = findCapabilityInfo( deviceInfo->capabilityInfo, 
											cryptAlgo );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );
	
	/* If we're after a private key, make sure it really is a private key.  
	   This check isn't completely effective since the CA labels don't
	   identify the presence of a private key */
	if( personality->CertLabel[ 4 ] == 'X' && \
		( flags & KEYMGMT_FLAG_PRIVATEKEY ) )
		return( CRYPT_ERROR_NOTFOUND );

	/* Try and create a certificate chain which matches the key.  The process 
	   is as follows:

		if public key
			if cert
				create native cert chain (+key) object
			else
				create device pubkey object, mark as "key loaded"
		else
			create device privkey object, mark as "key loaded"
			if cert
				create native data-only cert chain object
				attach cert chain object to key

	   The reason for doing things this way is given in the comment at the 
	   top of this section */
	if( certPresent )
		{
		status = iCryptImportCertIndirect( &iCryptCert, 
						deviceInfo->objectHandle, keyIDtype, keyID, 
						keyIDlength, ( flags & KEYMGMT_FLAG_PRIVATEKEY ) ? \
						CERTIMPORT_DATA_ONLY : CERTIMPORT_NORMAL );
		if( cryptStatusError( status ) )
			return( status );

		/* We got the cert, if we're being asked for a public key then we've 
		   created a native object to contain it so we return that */
		if( flags & KEYMGMT_FLAG_PUBLICKEY )
			{
			/* Set up the keying info in the context based on the data from
			   the cert if necessary */
			if( cryptAlgo == CRYPT_ALGO_KEA )
				{
				BYTE keyDataBuffer[ 1024 ];

				setResourceData( &msgData, keyDataBuffer, 1024 );
				status = krnlSendMessage( iCryptCert, 
										  RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
										  &msgData, CRYPT_IATTRIBUTE_SPKI );
				if( cryptStatusOK( status ) )
					status = krnlSendMessage( iCryptCert, 
										  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
										  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
				if( cryptStatusError( status ) )
					{
					krnlSendNotifier( iCryptCert, 
									  RESOURCE_IMESSAGE_DECREFCOUNT );
					return( status );
					}
				}

			*iCryptContext = iCryptCert;
			return( CRYPT_OK );
			}
		}

	/* Create a dummy context for the key, remember the device it's contained 
	   in, the index of the device-internal key, and the object's label, mark 
	   it as initialised (ie with a key loaded), and if there's a cert present 
	   attach it to the context.  The cert is an internal object used only by 
	   the context so we tell the kernel to mark it as owned by the context 
	   only */
	status = createContextFromCapability( iCryptContext, capabilityInfoPtr, 
										  CREATEOBJECT_FLAG_DUMMY );
	if( cryptStatusError( status ) )
		{
		if( certPresent )
			krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETDEPENDENT,
					 &deviceInfo->objectHandle, TRUE );
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &certIndex, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	setResourceData( &msgData, personality->CertLabel + 8,
					 strlen( personality->CertLabel + 8 ) );
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	if( certPresent && cryptAlgo == CRYPT_ALGO_KEA )
		{
		BYTE keyDataBuffer[ 1024 ];

		/* Set up the keying info in the context based on the data from the 
		   cert if necessary */
		setResourceData( &msgData, keyDataBuffer, 1024 );
		status = krnlSendMessage( iCryptCert, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_SPKI );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( *iCryptContext, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
								  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( *iCryptContext, RESOURCE_IMESSAGE_DECREFCOUNT );
			*iCryptContext = CRYPT_ERROR;
			return( status );
			}
		}
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 ( void * ) &keySize, CRYPT_IATTRIBUTE_KEYSIZE );
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 MESSAGE_VALUE_UNUSED, CRYPT_IATTRIBUTE_INITIALISED );
	if( certPresent )
		krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETDEPENDENT, 
						 &iCryptCert, FALSE );

	return( status );
	}

/* Update a device with a certificate */

static int setItemFunction( DEVICE_INFO *deviceInfo, 
							const CRYPT_HANDLE iCryptHandle )
	{
	CRYPT_CERTIFICATE iCryptCert;
	int certIndex, status;

	/* Read the personality index at which we're adding the certificate */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE, &certIndex, 
					 CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( certIndex < 0 )
		return( CRYPT_ARGERROR_NUM1 );

	/* Get the cert objects handle, lock it for our exclusive use, update the 
	   card with the cert(s), and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETDEPENDENT, 
					 &iCryptCert, OBJECT_TYPE_CERTIFICATE );
	status = krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );
	status = updateCertChain( deviceInfo, iCryptCert, certIndex );
	krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_UNLOCK );

	return( status );
	}

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	int certIndex, status;

	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the item to delete based on the label */
	certIndex = findCertificate( deviceInfo, keyID, keyIDlength );
	if( certIndex == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );
	status = pCI_DeleteCertificate( certIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_WRITE ) );
	updateCertificateInfo( deviceInfo, certIndex, NULL, CRYPT_UNUSED, "" );
	return( CRYPT_OK );
	}

/* Get the sequence of certs in a chain from a device */

static int getNextCertFunction( DEVICE_INFO *deviceInfo, 
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, 
								const CRYPT_KEYID_TYPE keyIDtype,
								const void *keyID, const int keyIDlength,
								const CERTIMPORT_TYPE options )
	{
	CREATEOBJECT_INFO createInfo;
	CI_PERSON *personality;
	BYTE buffer[ CI_CERT_SIZE ];
	int status;

	assert( keyIDtype == CRYPT_KEYID_NONE || keyIDtype == CRYPT_KEYID_NAME );

	/* If it's the first cert, find it based on the label */
	if( keyIDtype == CRYPT_KEYID_NAME )
		*stateInfo = findCertificate( deviceInfo, keyID, keyIDlength );
	else
		{
		/* If the previous cert was the last one, there's nothing left to fetch */
		if( *stateInfo == CRYPT_ERROR )
			return( CRYPT_ERROR_NOTFOUND );

		/* Find the parent for the last cert we got using the SDN.605 
		   labelling scheme */
		personality = getPersonality( deviceInfo, *stateInfo );
		if( !memcmp( personality->CertLabel + 4, "0999", 4 ) || \
			!memcmp( personality->CertLabel + 6, "FF", 2 ) || \
			sscanf( personality->CertLabel + 6, "%02X", stateInfo ) != 1 )
			*stateInfo = 255;
		*stateInfo = ( *stateInfo == 255 ) ? CRYPT_ERROR : *stateInfo;
		}
	if( *stateInfo == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Get the cert at this position */
	status = pCI_GetCertificate( *stateInfo, buffer );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_READ ) );
	setMessageCreateObjectInfo( &createInfo, options );
	createInfo.createIndirect = TRUE;
	createInfo.strArg1 = buffer;
	createInfo.strArgLen1 = CI_CERT_SIZE;
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( cryptStatusOK( status ) )
		*iCertificate = createInfo.cryptHandle;
	return( status );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Initialise the encryption */

static int initFunction( CRYPT_INFO *cryptInfo )
	{
	int mode, status;

	/* We're encrypting data, set the appropriate mode for future
	   en/decryption */
	switch( cryptInfo->ctxConv.mode )
		{
		case CRYPT_MODE_ECB:
			mode = CI_ECB64_MODE;
			break;

		case CRYPT_MODE_CBC:
			mode = CI_CBC64_MODE;
			break;

		case CRYPT_MODE_CFB:
			mode = CI_CFB64_MODE;
			break;

		case CRYPT_MODE_OFB:
			mode = CI_OFB64_MODE;
			break;
		}
	status = pCI_SetMode( CI_DECRYPT_TYPE, mode );
	if( status == CI_OK )
		status = pCI_SetMode( CI_ENCRYPT_TYPE, mode );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Load an IV.  Handling IV generation/loading is very problematic since we 
   can't generate an IV until the key is generated (since it depends on the 
   key), however implicitly generating a key into the context at this point 
   will change its state so that a future attempt to explicitly generate a key 
   will fail.  This is complicated by the fact that although there are a 
   number of key registers, the cryptologic can only have one active mode and
   one active IV.  To get around this we'd have to do the following:

	initIV:
		if( !key )
			generateKey();
			autoKey = TRUE;
		generateIV();
	
	initKey:
		if( autoKey == TRUE )
			return( OK );
		generateKey()

   but this doesn't work due to the problem mentioned above, so for now we
   just assume we'll be called from within cryptlib, which gets it right (it's
   unlikely users will be able to work with the complex Fortezza key 
   management, so there's little chance the sequencing will become messed up).
   
   In practice it's even worse than this, because the cryptologic on some 
   cards imposes even more limitations than this.  The standard way to use a
   session/content-enryption key is:

	generate session/conetent-encryption key;
	export wrapped key;
	encrypt data with key;

   This doesn't work here because the act of exporting the session key screws
   up the state of the key.  Specifically, after executing the following code
   sequence:

	// Generate the session key
	CI_DeleteKey( mekIndex );
	CI_GenerateMEK( mekIndex, 0 );
	CI_SetKey( mekIndex );
	CI_GenerateIV( ivBuffer );

	// Export the encrypted session key
	CI_SetPersonality( personality );
	CI_GenerateRa( Ra );
	CI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, Ra, 
					( void * ) Rb, sizeof( CI_RB ), recipientPublicValue );
	CI_WrapKey( tekIndex, mekIndex, wrappedKey );
	CI_DeleteKey( tekIndex );

	// Encrypt data with the key
	CI_Encrypt( length, buffer, buffer );

   the CI_Encrypt() fails with CI_NO_KEY.  Calling CI_SetKey() before 
   CI_Encrypt() causes it to fail with a CI_NO_IV instead.  Calling 
   CI_Encrypt() immediately after CI_GenerateTEK() results in a CI_FAIL.
   This indicates that the TEK wrapping upsets the state of the cryptologic
   which in turn upsets any attempt to use the MEK later on.

   Because of this problem, we can't generate the IV in the initIVFunction()
   but have to wait until after the key wrap operations have been performed.  
   The code kludges this by setting the ivSet flag at this point without
   setting the IV and then generating the real IV as a side-effect of the key
   wrapping.  This only works if we're wrapping the key for a single recipient 
   using a TEK, it doesn't work if we're wrapping using Ks or if there's more
   than one recipient because we can't tell in advance whether this is the 
   last operation before we encrypt (and therefore whether it's safe to 
   generate an IV now).
   
   The problems with IV handling extend even further than this.  The 
   following simple sequence of calls (generating an IV, reading it out, 
   loading it back in, and then attempting to encrypt) produce a "no IV 
   loaded" error even though all the previous calls succeeded:

	CI_SetMode( CI_DECRYPT_TYPE, CI_CBC64_MODE );
	CI_DeleteKey( 5 );
	CI_GenerateMEK( 5, 0 );
	CI_SetKey( 5 );
	CI_GenerateIV( ivBuffer );
	CI_SetKey( 5 );		// Required or the IV load fails with CI_EXEC_FAIL
	CI_LoadIV( ivBuffer );
	CI_Encrypt( 8, ivBuffer, ivBuffer ); // Result = CI_NO_IV

   Presumably this is because of interlocks on the card or Capstone chip 
   which date back to the LEAF period and which ensure that it's not possible
   to fiddle with non-LEAF'd IV's or anything else even if the card firmware 
   is somehow compromised or has unexpected failure modes.  The result is 
   that it's possible to use the device exactly as intended by its original 
   designers but probably not possible (or at least very difficult) to use it 
   in any other way.  The unexpected return codes are <wild speculation> 
   possibly caused by this functionality not being anticipated by the 
   firmware vendors</wild speculation>.  In any case it's a nice failsafe
   design */

static int initIVFunction( CRYPT_INFO *cryptInfo, const void *iv,
						   const int ivLength )
	{
	BYTE ivBuffer[ FORTEZZA_IVSIZE ];
	int status;

	assert( ivLength == CRYPT_USE_DEFAULT || ivLength == 8 );

	/* If the user has supplied an IV, load it into the device, taking into
	   account LEAF suppression */
	if( ivLength != CRYPT_USE_DEFAULT )
		{
		CRYPT_DEVICE iCryptDevice;
		DEVICE_INFO *deviceInfo;

		if( !cryptInfo->ctxConv.ivSet )
			{
			/* Get the LEAF-suppression string from the device associated 
			   with the context */
			status = krnlSendMessage( cryptInfo->objectHandle, 
									  RESOURCE_IMESSAGE_GETDEPENDENT, 
									  &iCryptDevice, OBJECT_TYPE_DEVICE );
			if( cryptStatusError( status ) )
				return( status );
			getCheckInternalResource( iCryptDevice, deviceInfo, 
									  OBJECT_TYPE_DEVICE );
			memcpy( ivBuffer, deviceInfo->leafString, 16 );
			unlockResource( deviceInfo );

			/* Copy in the actual IV and load it */
			memcpy( ivBuffer + FORTEZZA_IVSIZE - 8, iv, 8 );
			status = pCI_LoadIV( ivBuffer );
			if( status != CI_OK )
				return( mapError( status, CRYPT_ERROR_FAILED ) );
			}

		/* Copy the IV details into the context */
		cryptInfo->ctxConv.ivLength = 8;
		memset( cryptInfo->ctxConv.iv, 0, CRYPT_MAX_IVSIZE );
		memcpy( cryptInfo->ctxConv.iv, iv, 8 );
		cryptInfo->ctxConv.ivSet = TRUE;

		return( CRYPT_OK );
		}

	/* We can't generate an IV at this point (see the comment above) so all
	   we can do is set up a dummy IV and set the 'IV set' flag to avoid 
	   getting an error from the higher-level code and return.  The real IV 
	   will be set when the key is wrapped */
	memset( cryptInfo->ctxConv.iv, 0, CRYPT_MAX_IVSIZE );
	cryptInfo->ctxConv.ivLength = 8;
	cryptInfo->ctxConv.ivSet = TRUE;

	return( CRYPT_OK );
	}

/* Initialise a key.  Since Fortezza keys can't be directly loaded, this
   function always returns a permission denied error */

static int initKeyFunction( CRYPT_INFO *cryptInfo, const void *key, 
							const int keyLength )
	{
	UNUSED( cryptInfo );
	UNUSED( key );

	return( CRYPT_ERROR_PERMISSION );
	}

/* Generate a key.  This is somewhat ugly since Fortezza keys (at least KEA 
   ones) require the use of shared domain parameters (the DSA p, q, and g 
   values) which are managed through some sort of unspecified external means.
   At the moment we use the domain parameters from a Motorola test 
   implementation, users in other domains will have to substitute their own 
   parameters as required */

static int generateKeyFunction( CRYPT_INFO *cryptInfo,
								const int keySizeBits )
	{
	static const CI_P p = {
		0xD4, 0x38, 0x02, 0xC5, 0x35, 0x7B, 0xD5, 0x0B, 
		0xA1, 0x7E, 0x5D, 0x72, 0x59, 0x63, 0x55, 0xD3,
		0x45, 0x56, 0xEA, 0xE2, 0x25, 0x1A, 0x6B, 0xC5, 
		0xA4, 0xAB, 0xAA, 0x0B, 0xD4, 0x62, 0xB4, 0xD2, 
		0x21, 0xB1, 0x95, 0xA2, 0xC6, 0x01, 0xC9, 0xC3, 
		0xFA, 0x01, 0x6F, 0x79, 0x86, 0x83, 0x3D, 0x03, 
		0x61, 0xE1, 0xF1, 0x92, 0xAC, 0xBC, 0x03, 0x4E, 
		0x89, 0xA3, 0xC9, 0x53, 0x4A, 0xF7, 0xE2, 0xA6, 
		0x48, 0xCF, 0x42, 0x1E, 0x21, 0xB1, 0x5C, 0x2B, 
		0x3A, 0x7F, 0xBA, 0xBE, 0x6B, 0x5A, 0xF7, 0x0A, 
		0x26, 0xD8, 0x8E, 0x1B, 0xEB, 0xEC, 0xBF, 0x1E, 
		0x5A, 0x3F, 0x45, 0xC0, 0xBD, 0x31, 0x23, 0xBE, 
		0x69, 0x71, 0xA7, 0xC2, 0x90, 0xFE, 0xA5, 0xD6, 
		0x80, 0xB5, 0x24, 0xDC, 0x44, 0x9C, 0xEB, 0x4D, 
		0xF9, 0xDA, 0xF0, 0xC8, 0xE8, 0xA2, 0x4C, 0x99, 
		0x07, 0x5C, 0x8E, 0x35, 0x2B, 0x7D, 0x57, 0x8D
		};
	static const CI_Q q = {
		0xA7, 0x83, 0x9B, 0xF3, 0xBD, 0x2C, 0x20, 0x07, 
		0xFC, 0x4C, 0xE7, 0xE8, 0x9F, 0xF3, 0x39, 0x83, 
		0x51, 0x0D, 0xDC, 0xDD
		};
	static const CI_G g = {
		0x0E, 0x3B, 0x46, 0x31, 0x8A, 0x0A, 0x58, 0x86, 
		0x40, 0x84, 0xE3, 0xA1, 0x22, 0x0D, 0x88, 0xCA, 
		0x90, 0x88, 0x57, 0x64, 0x9F, 0x01, 0x21, 0xE0, 
		0x15, 0x05, 0x94, 0x24, 0x82, 0xE2, 0x10, 0x90, 
		0xD9, 0xE1, 0x4E, 0x10, 0x5C, 0xE7, 0x54, 0x6B, 
		0xD4, 0x0C, 0x2B, 0x1B, 0x59, 0x0A, 0xA0, 0xB5, 
		0xA1, 0x7D, 0xB5, 0x07, 0xE3, 0x65, 0x7C, 0xEA, 
		0x90, 0xD8, 0x8E, 0x30, 0x42, 0xE4, 0x85, 0xBB, 
		0xAC, 0xFA, 0x4E, 0x76, 0x4B, 0x78, 0x0E, 0xDF, 
		0x6C, 0xE5, 0xA6, 0xE1, 0xBD, 0x59, 0x77, 0x7D, 
		0xA6, 0x97, 0x59, 0xC5, 0x29, 0xA7, 0xB3, 0x3F, 
		0x95, 0x3E, 0x9D, 0xF1, 0x59, 0x2D, 0xF7, 0x42, 
		0x87, 0x62, 0x3F, 0xF1, 0xB8, 0x6F, 0xC7, 0x3D, 
		0x4B, 0xB8, 0x8D, 0x74, 0xC4, 0xCA, 0x44, 0x90, 
		0xCF, 0x67, 0xDB, 0xDE, 0x14, 0x60, 0x97, 0x4A, 
		0xD1, 0xF7, 0x6D, 0x9E, 0x09, 0x94, 0xC4, 0x0D
		};
	const CRYPT_ALGO cryptAlgo = cryptInfo->capabilityInfo->cryptAlgo;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE yBuffer[ 128 ], keyDataBuffer[ 1024 ];
	int certIndex, keyDataSize, status;

	assert( keySizeBits == 80 || keySizeBits == bytesToBits( 128 ) );

	/* Get the info for the device associated with this context */
	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );

	/* If it's a Skipjack context, just generate a key in the key register */
	if( cryptAlgo == CRYPT_ALGO_SKIPJACK )
		{
		const int keyIndex = findFreeKeyRegister( deviceInfo );

		if( cryptStatusError( keyIndex ) )
			unlockResourceExit( deviceInfo, keyIndex );

		/* We've got a key register to use, generate a key into it and 
		   remember its value */
		status = pCI_GenerateMEK( keyIndex, 0 );
		if( status == CI_OK )
			{
			const int keySize = bitsToBytes( 80 );

			/* Mark this key register as being in use */
			deviceInfo->keyRegisterFlags |= ( 1 << keyIndex );

			/* Remember what we've set up */
			krnlSendMessage( cryptInfo->objectHandle, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE,
							 ( void * ) &keyIndex, 
							 CRYPT_IATTRIBUTE_DEVICEOBJECT );
			krnlSendMessage( cryptInfo->objectHandle, 
							 RESOURCE_IMESSAGE_SETATTRIBUTE, 
							 ( void * ) &keySize, 
							 CRYPT_IATTRIBUTE_KEYSIZE );
			}
		status = mapError( status, CRYPT_ERROR_FAILED );

		unlockResourceExit( deviceInfo, status );
		}

	/* Find a certificate slot in which we can store the new key */
	certIndex = findFreeCertificate( deviceInfo );
	if( certIndex == CRYPT_ERROR )
		unlockResourceExit( deviceInfo, CRYPT_ERROR_OVERFLOW );

#ifndef NO_UPDATE
	/* Generate the X component, receiving the Y component in return */
	status = pCI_GenerateX( certIndex, ( cryptAlgo == CRYPT_ALGO_DSA ) ? \
							CI_DSA_TYPE : CI_KEA_TYPE, 128, 20, ( void * ) p, 
							( void * ) q, ( void * ) g, 128, yBuffer );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		unlockResourceExit( deviceInfo, status );
		}
#else
	memset( yBuffer, 0, 128 );
	memcpy( yBuffer, "\x12\x34\x56\x78\x90\x12\x34\x56", 8 );
	memcpy( yBuffer + 120, "\x12\x34\x56\x78\x90\x12\x34\x56", 8 );
#endif /* NO_UPDATE */

	/* Send the keying info to the context */
	status = keyDataSize = sizeofFlatPublicKey( cryptAlgo, p, 128, q, 20, 
												g, 128, yBuffer, 128 );
	if( !cryptStatusError( status ) )
		status = writeFlatPublicKey( keyDataBuffer, cryptAlgo, p, 128, q, 20, 
									 g, 128, yBuffer, 128 );
	if( cryptStatusOK( status ) )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( cryptInfo->objectHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		{
#ifndef NO_UPDATE
		pCI_DeleteCertificate( certIndex );
#endif /* NO_UPDATE */
		unlockResourceExit( deviceInfo, status );
		}

	/* Save the encoded public key info in the card.  We need to do this 
	   because we can't recreate the y value without generating a new private
	   key */
	status = updateCertificate( deviceInfo, certIndex, CRYPT_UNUSED, 
								keyDataBuffer, keyDataSize, cryptInfo->label, 
								CRYPT_UNUSED );
	if( cryptStatusError( status ) )
		{
#ifndef NO_UPDATE
		pCI_DeleteCertificate( certIndex );
#endif /* NO_UPDATE */
		unlockResourceExit( deviceInfo, status );
		}

	/* Remember what we've set up */
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &certIndex, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 ( void * ) &keySizeBits, CRYPT_IATTRIBUTE_KEYSIZE );
	cryptInfo->ctxPKC.isPublicKey = FALSE;

	unlockResourceExit( deviceInfo, status );
	}

/* Select the appropriate personality for a context if required.  There are
   two variations, one which selects a personality given context data and
   one which selects it given device data */

static int selectPersonalityContext( const CRYPT_INFO *cryptInfo )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int status;

	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	if( deviceInfo->currentPersonality != cryptInfo->deviceObject )
		{
		status = pCI_SetPersonality( cryptInfo->deviceObject );
		if( status == CI_OK )
			deviceInfo->currentPersonality = cryptInfo->deviceObject;
		}
	unlockResource( deviceInfo );
	return( status );
	}

static int selectPersonality( DEVICE_INFO *deviceInfo, 
							  const CRYPT_CONTEXT iCryptContext )
	{
	int deviceObject, status;

	/* Get the personality associated with the context */
	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_GETATTRIBUTE, 
							  &deviceObject, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );

	/* If it's not the currently selected one, select it */
	if( deviceInfo->currentPersonality != deviceObject )
		{
		status = pCI_SetPersonality( deviceObject );
		if( status == CI_OK )
			deviceInfo->currentPersonality = deviceObject;
		}

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Encrypt/decrypt data */

static int encryptFunction( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	int status;

	status = pCI_Encrypt( length, buffer, buffer );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

static int decryptFunction( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	int status;

	status = pCI_Decrypt( length, buffer, buffer );
	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/* Sign/sig check data */

static int signFunction( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	CI_SIGNATURE signature;
	STREAM stream;
	int status;

	assert( length == 20 );

	/* Sign the hash */
	status = selectPersonalityContext( cryptInfo );
	if( status == CI_OK )
		status = pCI_Sign( buffer, signature );
	if( status != CI_OK )
		return( ( status == CI_EXEC_FAIL || status == CI_NO_X ) ?
				CRYPT_ERROR_FAILED : mapError( status, CRYPT_ERROR_FAILED ) );

	/* Reformat the signature into the form expected by cryptlib */
	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, sizeofInteger( signature, 20 ) +
							sizeofInteger( signature + 20, 20 ) );
	writeInteger( &stream, signature, 20, DEFAULT_TAG );
	writeInteger( &stream, signature + 20, 20, DEFAULT_TAG );
	status = stell( &stream );
	sMemDisconnect( &stream );

	return( status );
	}

static int readFixedValue( STREAM *stream, BYTE *buffer )
	{
	int length, status;

	/* Read an integer value and pad it out to a fixed length if necessary */
	status = readInteger( stream, buffer, &length, 20 );
	if( cryptStatusError( status ) )
		return( status );
	if( length < 20 )
		{
		const int delta = 20 - length;

		memmove( buffer, buffer + delta, length );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

static int sigCheckFunction( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	CI_SIGNATURE signature;
	STREAM stream;
	int status;

	assert( length > 20 + 40 );

	/* Decode the signature from the cryptlib format */
	sMemConnect( &stream, ( BYTE * ) buffer + 20, STREAMSIZE_UNKNOWN );
	status = readSequence( &stream, NULL );
	if( !cryptStatusError( status ) )
		status = readFixedValue( &stream, signature );
	if( !cryptStatusError( status ) )
		status = readFixedValue( &stream, signature + 20 );
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_BADDATA );
	sMemDisconnect( &stream );

	/* Verify the signature */
	status = selectPersonalityContext( cryptInfo );
	if( status == CI_OK )
		status = pCI_VerifySignature( buffer, 0, NULL, signature );
	return( ( status == CI_EXEC_FAIL ) ? \
			CRYPT_ERROR_FAILED : mapError( status, CRYPT_ERROR_FAILED ) );
	}

/****************************************************************************
*																			*
*						 	Mechanism Interface Routines					*
*																			*
****************************************************************************/

/* Perform key agreement.  Since the return value is assumed to be a single 
   blob but we use the presence of a null pointer to denote a dummy export, 
   we can't pass back multi-element length information so we have to encode
   the length as two byte values to handle the wrapped key + UKM */

static const CI_RB Rb = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 
	};

#define encodeLengths( wrappedKeySize, ukmSize ) \
		( ( ( wrappedKeySize ) << 8 ) | ( ukmSize ) )

static int exportKEA( DEVICE_INFO *deviceInfo, 
					  MECHANISM_WRAP_INFO *mechanismInfo )
	{
	RESOURCE_DATA msgData;
	BYTE recipientPublicValue[ 128 ], ivBuffer[ FORTEZZA_IVSIZE ];
	void *wrappedKeyPtr = mechanismInfo->wrappedData;
	void *ukmPtr = ( BYTE * ) mechanismInfo->wrappedData + sizeof( CI_KEY );
	int tekIndex, mekIndex, status;

	/* Sanity check the input data */
	assert( ( mechanismInfo->wrappedData == NULL && \
			  mechanismInfo->wrappedDataLength == 0 ) || \
			( mechanismInfo->wrappedDataLength >= \
			  sizeof( CI_KEY ) + sizeof( CI_RA ) ) );
	assert( mechanismInfo->keyData == NULL );
	assert( mechanismInfo->keyDataLength == 0 );

	/* Clear the return value */
	if( mechanismInfo->wrappedData != NULL )
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );

	/* If this is just a length check, we're done */
	if( mechanismInfo->wrappedData == NULL )
		{
		/* Since the return value is assumed to be a single blob but we use
		   the presence of a null pointer to denote a dummy export, we can't
		   pass back multi-element length information so we have to encode
		   the length as two byte values to handle the wrapped key + UKM */
		mechanismInfo->wrappedDataLength = \
					encodeLengths( sizeof( CI_KEY ), sizeof( CI_RA ) );
		return( CRYPT_OK );
		}

	/* Get the public value from the recipient context, the MEK register from 
	   the session key context and find a free key register to work with */
	setResourceData( &msgData, recipientPublicValue, 128 );
	status = krnlSendMessage( mechanismInfo->wrapContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData,
							  CRYPT_IATTRIBUTE_PUBLICVALUE );
	if( cryptStatusOK( status ) )
		status = krnlSendMessage( mechanismInfo->keyContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, &mekIndex, 
								  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusOK( status ) )
		status = findFreeKeyRegister( deviceInfo );
	if( cryptStatusError( status ) )
		return( status );
	tekIndex = status;

	/* Generate the Ra value from the callers private key, and generate the
	   TEK based on the recipients y value.  Note that the generation of the
	   TEK has to immediately follow the generation of Ra because the device
	   state for the TEK generation is carried over from the Ra generation */
	status = selectPersonality( deviceInfo, mechanismInfo->auxContext );
	if( status == CI_OK )
		status = pCI_GenerateRa( ukmPtr );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, ukmPtr, 
								  ( void * ) Rb, sizeof( CI_RB ), 
								  recipientPublicValue );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		return( status );
		}

	/* Wrap the MEK with the TEK and free the TEK register */
	status = pCI_WrapKey( tekIndex, mekIndex, wrappedKeyPtr );
	pCI_DeleteKey( tekIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
	mechanismInfo->wrappedDataLength = \
					encodeLengths( sizeof( CI_KEY ), sizeof( CI_RA ) );

	/* Now that we're past the cryptologic-scrambling TEK-wrapping operation, 
	   we can re-select the MEK and generate an IV for it.  See the 
	   initIVFunction() comments for more details on this */
	status = pCI_SetKey( mekIndex );
	if( status == CI_OK )
		status = pCI_GenerateIV( ivBuffer );
	if( status != CI_OK )
		{
		memset( mechanismInfo->wrappedData, 0, 
				mechanismInfo->wrappedDataLength );
		return( mapError( status, CRYPT_ERROR_FAILED ) );
		}
	setResourceData( &msgData, ivBuffer + FORTEZZA_IVSIZE - 8, 8 );
	status = krnlSendMessage( mechanismInfo->keyContext, 
							  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
							  CRYPT_CTXINFO_IV );

	return( status );
	}

#if 0	/* 22/09/99 Replaced by mechanism function */
static int keyAgreeOriginatorFunction( CRYPT_INFO *cryptInfo, void *buffer, 
									   int length )
	{
	KEYAGREE_INFO *keyAgreeInfo = ( KEYAGREE_INFO * ) buffer;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int tekIndex, mekIndex, status;

	/* Check the input parameters */
	if( keyAgreeInfo->publicValueLen != sizeof( CI_Y ) )
		return( CRYPT_ERROR_BADDATA );

	/* Get the MEK from the session key context */
	status = krnlSendMessage( keyAgreeInfo->sessionKeyContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &mekIndex, 
							  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Get the info for the device associated with this context and keep it 
	   locked it while we work with it.  This is necessary because of the 
	   implicit key selection used by the Fortezza crypto library, if we were
	   to unlock the device at any point another thread could enable the use 
	   of a different key */
	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );

	/* Get a free key register to work with */
	tekIndex = findFreeKeyRegister( deviceInfo );
	if( cryptStatusError( tekIndex ) )
		unlockResourceExit( deviceInfo, tekIndex );

	/* Generate the Ra value from the callers private key, and generate the
	   TEK based on the recipients y value */
	status = selectPersonalityContext( cryptInfo );
	if( status == CI_OK )
		status = pCI_GenerateRa( keyAgreeInfo->ukm );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_INITIATOR_FLAG, tekIndex, 
								  keyAgreeInfo->ukm, ( void * ) Rb, 128, 
								  keyAgreeInfo->publicValue );
	if( status != CI_OK )
		{
		status = mapError( status, CRYPT_ERROR_FAILED );
		unlockResourceExit( deviceInfo, status );
		}
	keyAgreeInfo->ukmLen = sizeof( CI_RA );

	/* Wrap the MEK with the TEK and free the TEK register */
	status = pCI_WrapKey( tekIndex, mekIndex, keyAgreeInfo->wrappedKey );
	pCI_DeleteKey( tekIndex );
	unlockResource( deviceInfo );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );
	keyAgreeInfo->wrappedKeyLen = sizeof( CI_KEY );

	return( CRYPT_OK );
	}
#endif /* 0 */

static int importKEA( DEVICE_INFO *deviceInfo, 
					  MECHANISM_WRAP_INFO *mechanismInfo )
	{
	return( CRYPT_ERROR );
	}

static int keyAgreeRecipientFunction( CRYPT_INFO *cryptInfo, void *buffer, 
									  int length )
	{
	KEYAGREE_INFO *keyAgreeInfo = ( KEYAGREE_INFO * ) buffer;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int tekIndex, mekIndex, status;

	/* Check the input parameters */
	if( keyAgreeInfo->publicValueLen != sizeof( CI_Y ) || \
		keyAgreeInfo->ukmLen != sizeof( CI_RA ) || \
		keyAgreeInfo->wrappedKeyLen != sizeof( CI_KEY ) )
		return( CRYPT_ERROR_BADDATA );

	/* Get the MEK from the session key context */
	status = krnlSendMessage( keyAgreeInfo->sessionKeyContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE, &mekIndex, 
							  CRYPT_IATTRIBUTE_DEVICEOBJECT );
	if( cryptStatusError( status ) )
		return( status );
	
	/* Get the info for the device associated with this context and keep it 
	   locked it while we work with it.  This is necessary because of the 
	   implicit key selection used by the Fortezza crypto library, if we were
	   to unlock the device at any point another thread could enable the use 
	   of a different key */
	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							  OBJECT_TYPE_DEVICE );
	if( cryptStatusError( status ) )
		return( status );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );

	/* Get a free key register to work with */
	tekIndex = findFreeKeyRegister( deviceInfo );
	if( cryptStatusError( tekIndex ) )
		unlockResourceExit( deviceInfo, tekIndex );

	/* Generate the TEK based on the originators y value, Ra, and the 
	   recipients private key */
	status = selectPersonalityContext( cryptInfo );
	if( status == CI_OK )
		status = pCI_GenerateTEK( CI_RECIPIENT_FLAG, tekIndex, 
								  keyAgreeInfo->ukm, ( void * ) Rb, 128, 
								  keyAgreeInfo->publicValue );

	/* Unwrap the MEK with the TEK and free the TEK register */
	status = pCI_UnwrapKey( tekIndex, mekIndex, keyAgreeInfo->wrappedKey );
	pCI_DeleteKey( tekIndex );
	if( status != CI_OK )
		return( mapError( status, CRYPT_ERROR_FAILED ) );

	return( mapError( status, CRYPT_ERROR_FAILED ) );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The capability information for this device.  We don't do SHA-1 using the
   device since the implementation is somewhat clunky and will be much slower
   than a native one */

#define bits(x)	bitsToBytes(x)

static CAPABILITY_INFO FAR_BSS capabilities[] = {
	/* The DSA capabilities */
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 1024 ), bits( 1024 ), bits( 1024 ), 
		NULL, NULL, NULL, NULL, initKeyFunction, generateKeyFunction, NULL, 
		NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 
		signFunction, sigCheckFunction },

	/* The Skipjack capabilities.  Note that we're using a LEAF-suppressed IV */
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ), 
		NULL, initFunction, NULL, initIVFunction, initKeyFunction, generateKeyFunction, NULL, 
		encryptFunction, decryptFunction, encryptFunction, decryptFunction, 
		encryptFunction, decryptFunction, encryptFunction, decryptFunction },

	/* The KEA capabilities.  The capabilities can't be applied directly but 
	   are used via higher-level mechanisms so the associated function 
	   pointers are all null */
	{ CRYPT_ALGO_KEA, bits( 0 ), "KEA",
		bits( 1024 ), bits( 1024 ), bits( 1024 ), 
		NULL, NULL, NULL, NULL, NULL, generateKeyFunction },

	/* The end-of-list marker */
	{ CRYPT_ALGO_NONE }
	};

/* Initialise the capability info */

static void initCapabilities( void )
	{
	CAPABILITY_INFO *prevCapabilityInfoPtr = NULL;
	int i;

	for( i = 0; capabilities[ i ].cryptAlgo != CRYPT_ALGO_NONE; i++ )
		{
		assert( capabilities[ i ].cryptAlgo == CRYPT_ALGO_KEA || \
				capabilityInfoOK( &capabilities[ i ] ) );
		if( prevCapabilityInfoPtr != NULL )
			prevCapabilityInfoPtr->next = &capabilities[ i ];
		prevCapabilityInfoPtr = &capabilities[ i ];
		}
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDeviceFortezza( DEVICE_INFO *deviceInfo )
	{
	/* Load the Fortezza driver DLL's if they aren't already loaded */
	if( hFortezza == NULL_HINSTANCE )
		{
		deviceInitFortezza();
		if( hFortezza == NULL_HINSTANCE )
			return( CRYPT_ERROR_OPEN );
		}

	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getItemFunction = getItemFunction;
	deviceInfo->setItemFunction = setItemFunction;
	deviceInfo->deleteItemFunction = deleteItemFunction;
	deviceInfo->getNextCertFunction = getNextCertFunction;
	deviceInfo->getRandomFunction = getRandomFunction;
	deviceInfo->capabilityInfo = capabilities;
	deviceInfo->mechanismFunctions = objectMechanisms;

	return( CRYPT_OK );
	}
#endif /* DEV_FORTEZZA */
