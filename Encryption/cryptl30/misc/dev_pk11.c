/****************************************************************************
*																			*
*							cryptlib PKCS #11 Routines						*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "cryptctx.h"
  #include "asn1.h"
  #include "device.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../cryptctx.h"
  #include "../keymgmt/asn1.h"
  #include "device.h"
#else
  #include "crypt.h"
  #include "cryptctx.h"
  #include "keymgmt/asn1.h"
  #include "misc/device.h"
#endif /* Compiler-specific includes */

/* Uncomment the following to fake out writes to the device.  This makes 
   testing easier since it allows the code to be debugged without messing up 
   data stored on the device when the program is terminated halfway through an 
   update */

/*#define NO_UPDATE	/**/

/* Before we can include the PKCS #11 headers we need to define a few OS-
   specific things which are required by the headers */

#ifdef __WINDOWS__
  #ifdef __WIN16__
	#pragma pack( 1 )					/* Struct packing */
	#define CK_PTR	far *				/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __export _far _pascal name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __export _far _pascal (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (_far _pascal * name)
  #else
	#pragma pack( push, cryptoki, 1 )	/* Struct packing */
	#define CK_PTR	*					/* Pointer type */
	#define CK_DEFINE_FUNCTION( returnType, name ) \
								returnType __declspec( dllexport ) name
	#define CK_DECLARE_FUNCTION( returnType, name ) \
								 returnType __declspec( dllimport ) name
	#define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
								returnType __declspec( dllimport ) (* name)
	#define CK_CALLBACK_FUNCTION( returnType, name ) \
								  returnType (* name)
  #endif /* Win16 vs Win32 */
#else
  #define CK_PTR	*					/* Pointer type */
  #define CK_DEFINE_FUNCTION( returnType, name ) \
							  returnType name
  #define CK_DECLARE_FUNCTION( returnType, name ) \
							   returnType name
  #define CK_DECLARE_FUNCTION_POINTER( returnType, name ) \
									   returnType (* name)
  #define CK_CALLBACK_FUNCTION( returnType, name ) \
								returnType (* name)
#endif /* __WINDOWS__ */
#ifndef NULL_PTR
  #define NULL_PTR	NULL
#endif /* NULL_PTR */

#if defined( INC_ALL ) || defined( INC_CHILD )
  #include "pkcs11.h"
#else
  #include "misc/pkcs11.h"
#endif /* Compiler-specific includes */

/* The max. number of drivers we can work with and the max.number of slots
   per driver */

#define MAX_PKCS11_DRIVERS		5
#define MAX_PKCS11_SLOTS		16

/* The default slot to look for tokens in */

#define DEFAULT_SLOT			0

/* Occasionally we need to read things into host memory from a device, the
   following value defines the maximum size of the on-stack buffer, if the
   data is larger than this we dynamically allocate the buffer (this almost
   never occurs) */

#define MAX_BUFFER_SIZE			1024

/* Encryption contexts can store extra implementation-dependant parameters,
   the following macros maps these generic parameter names to the PKCS #11
   values */

#define paramMechanism	param1
#define paramKeyType	param2

/* Prototypes for functions in cryptcap.c */

const void FAR_BSS *findCapabilityInfo( const void FAR_BSS *capabilityInfoPtr,
										const CRYPT_ALGO cryptAlgo );

#ifdef DEV_PKCS11

/****************************************************************************
*																			*
*						 		Init/Shutdown Routines						*
*																			*
****************************************************************************/

/* Whether the PKCS #11 library has been initialised or not, this is
   initialised on demand the first time it's accessed */

static BOOLEAN pkcs11Initialised = FALSE;

#ifdef DYNAMIC_LOAD

/* Since we can be using multiple PKCS #11 drivers, we define an array of
   them and access the appropriate one by its name */

typedef struct {
	char name[ 32 + 1 ];			/* Name of device */
	INSTANCE_HANDLE hPKCS11;		/* Handle to driver */
	CK_C_CloseSession pC_CloseSession;	/* Interface function pointers */
	CK_C_CreateObject pC_CreateObject;
	CK_C_Decrypt pC_Decrypt;
	CK_C_DecryptInit pC_DecryptInit;
	CK_C_DestroyObject pC_DestroyObject;
	CK_C_Encrypt pC_Encrypt;
	CK_C_EncryptInit pC_EncryptInit;
	CK_C_Finalize pC_Finalize;
	CK_C_FindObjects pC_FindObjects;
	CK_C_FindObjectsFinal pC_FindObjectsFinal;
	CK_C_FindObjectsInit pC_FindObjectsInit;
	CK_C_GenerateKeyPair pC_GenerateKeyPair;
	CK_C_GenerateRandom pC_GenerateRandom;
	CK_C_GetAttributeValue pC_GetAttributeValue;
	CK_C_GetMechanismInfo pC_GetMechanismInfo;
	CK_C_GetSlotList pC_GetSlotList;
	CK_C_GetTokenInfo pC_GetTokenInfo;
	CK_C_InitPIN pC_InitPIN;
	CK_C_InitToken pC_InitToken;
	CK_C_Login pC_Login;
	CK_C_Logout pC_Logout;
	CK_C_OpenSession pC_OpenSession;
	CK_C_SetAttributeValue pC_SetAttributeValue;
	CK_C_SetPIN pC_SetPIN;
	CK_C_Sign pC_Sign;
	CK_C_SignInit pC_SignInit;
	CK_C_UnwrapKey pC_UnwrapKey;
	CK_C_Verify pC_Verify;
	CK_C_VerifyInit pC_VerifyInit;
	} PKCS11_INFO;

static PKCS11_INFO pkcs11InfoTbl[ MAX_PKCS11_DRIVERS ];

/* The use of dynamically bound function pointers vs statically linked
   functions requires a bit of sleight of hand since we can't give the
   pointers the same names as prototyped functions.  To get around this we
   redefine the actual function names to the names of the pointers */

#define C_CloseSession		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_CloseSession
#define C_CreateObject		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_CreateObject
#define C_Decrypt			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Decrypt
#define C_DecryptInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_DecryptInit
#define C_DestroyObject		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_DestroyObject
#define C_Encrypt			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Encrypt
#define C_EncryptInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_EncryptInit
#define C_Finalize			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Finalize
#define C_FindObjects		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjects
#define C_FindObjectsFinal	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjectsFinal
#define C_FindObjectsInit	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_FindObjectsInit
#define C_GenerateKeyPair	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GenerateKeyPair
#define C_GenerateRandom	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GenerateRandom
#define C_GetAttributeValue	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetAttributeValue
#define C_GetMechanismInfo	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetMechanismInfo
#define C_GetSlotList		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetSlotList
#define C_GetTokenInfo		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_GetTokenInfo
#define C_Initialize		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Initialize
#define C_InitPIN			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_InitPIN
#define C_InitToken			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_InitToken
#define C_Login				pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Login
#define C_Logout			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Logout
#define C_OpenSession		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_OpenSession
#define C_SetAttributeValue	pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_SetAttributeValue
#define C_SetPIN			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_SetPIN
#define C_Sign				pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Sign
#define C_SignInit			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_SignInit
#define C_UnwrapKey			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_UnwrapKey
#define C_Verify			pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_Verify
#define C_VerifyInit		pkcs11InfoTbl[ deviceInfo->deviceNo ].pC_VerifyInit

/* Dynamically load and unload any necessary PKCS #11 drivers */

static int loadPKCS11driver( PKCS11_INFO *pkcs11Info,
							 const char *driverName )
	{
	CK_C_GetInfo pC_GetInfo;
	CK_C_Initialize pC_Initialize;
	CK_INFO info;
	CK_RV status;
#ifdef __WIN16__
	UINT errorMode;
#endif /* __WIN16__ */
	BOOLEAN isInitialised = FALSE;
	int i = 32;

	/* Obtain a handle to the device driver module */
#ifdef __WIN16__
	errorMode = SetErrorMode( SEM_NOOPENFILEERRORBOX );
	pkcs11Info->hPKCS11 = LoadLibrary( driverName );
	SetErrorMode( errorMode );
	if( pkcs11Info->hPKCS11 < HINSTANCE_ERROR )
		{
		pkcs11Info->hPKCS11 = NULL_HINSTANCE;
		return( CRYPT_ERROR );
		}
#else
	if( ( pkcs11Info->hPKCS11 = DynamicLoad( driverName ) ) == NULL_INSTANCE )
		return( CRYPT_ERROR );
#endif /* OS-specific dynamic load */

	/* Now get pointers to the functions */
	pC_GetInfo = ( CK_C_GetInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetInfo" );
	pC_Initialize = ( CK_C_Initialize ) DynamicBind( pkcs11Info->hPKCS11, "C_Initialize" );
	pkcs11Info->pC_CloseSession = ( CK_C_CloseSession ) DynamicBind( pkcs11Info->hPKCS11, "C_CloseSession" );
	pkcs11Info->pC_CreateObject = ( CK_C_CreateObject ) DynamicBind( pkcs11Info->hPKCS11, "C_CreateObject" );
	pkcs11Info->pC_Decrypt = ( CK_C_Decrypt ) DynamicBind( pkcs11Info->hPKCS11, "C_Decrypt" );
	pkcs11Info->pC_DecryptInit = ( CK_C_DecryptInit ) DynamicBind( pkcs11Info->hPKCS11, "C_DecryptInit" );
	pkcs11Info->pC_DestroyObject = ( CK_C_DestroyObject ) DynamicBind( pkcs11Info->hPKCS11, "C_DestroyObject" );
	pkcs11Info->pC_Encrypt = ( CK_C_Encrypt ) DynamicBind( pkcs11Info->hPKCS11, "C_Encrypt" );
	pkcs11Info->pC_EncryptInit = ( CK_C_EncryptInit ) DynamicBind( pkcs11Info->hPKCS11, "C_EncryptInit" );
	pkcs11Info->pC_Finalize = ( CK_C_Finalize ) DynamicBind( pkcs11Info->hPKCS11, "C_Finalize" );
	pkcs11Info->pC_FindObjects = ( CK_C_FindObjects ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjects" );
	pkcs11Info->pC_FindObjectsFinal = ( CK_C_FindObjectsFinal ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjectsFinal" );
	pkcs11Info->pC_FindObjectsInit = ( CK_C_FindObjectsInit ) DynamicBind( pkcs11Info->hPKCS11, "C_FindObjectsInit" );
	pkcs11Info->pC_GenerateKeyPair = ( CK_C_GenerateKeyPair ) DynamicBind( pkcs11Info->hPKCS11, "C_GenerateKeyPair" );
	pkcs11Info->pC_GenerateRandom = ( CK_C_GenerateRandom ) DynamicBind( pkcs11Info->hPKCS11, "C_GenerateRandom" );
	pkcs11Info->pC_GetAttributeValue = ( CK_C_GetAttributeValue ) DynamicBind( pkcs11Info->hPKCS11, "C_GetAttributeValue" );
	pkcs11Info->pC_GetMechanismInfo = ( CK_C_GetMechanismInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetMechanismInfo" );
	pkcs11Info->pC_GetSlotList = ( CK_C_GetSlotList ) DynamicBind( pkcs11Info->hPKCS11, "C_GetSlotList" );
	pkcs11Info->pC_GetTokenInfo = ( CK_C_GetTokenInfo ) DynamicBind( pkcs11Info->hPKCS11, "C_GetTokenInfo" );
	pkcs11Info->pC_InitPIN = ( CK_C_InitPIN ) DynamicBind( pkcs11Info->hPKCS11, "C_InitPIN" );
	pkcs11Info->pC_InitToken = ( CK_C_InitToken ) DynamicBind( pkcs11Info->hPKCS11, "C_InitToken" );
	pkcs11Info->pC_Login = ( CK_C_Login ) DynamicBind( pkcs11Info->hPKCS11, "C_Login" );
	pkcs11Info->pC_Logout = ( CK_C_Logout ) DynamicBind( pkcs11Info->hPKCS11, "C_Logout" );
	pkcs11Info->pC_OpenSession = ( CK_C_OpenSession ) DynamicBind( pkcs11Info->hPKCS11, "C_OpenSession" );
	pkcs11Info->pC_SetAttributeValue = ( CK_C_SetAttributeValue ) DynamicBind( pkcs11Info->hPKCS11, "C_SetAttributeValue" );
	pkcs11Info->pC_SetPIN = ( CK_C_SetPIN ) DynamicBind( pkcs11Info->hPKCS11, "C_SetPIN" );
	pkcs11Info->pC_Sign = ( CK_C_Sign ) DynamicBind( pkcs11Info->hPKCS11, "C_Sign" );
	pkcs11Info->pC_SignInit = ( CK_C_SignInit ) DynamicBind( pkcs11Info->hPKCS11, "C_SignInit" );
	pkcs11Info->pC_UnwrapKey = ( CK_C_UnwrapKey ) DynamicBind( pkcs11Info->hPKCS11, "C_UnwrapKey" );
	pkcs11Info->pC_Verify = ( CK_C_Verify ) DynamicBind( pkcs11Info->hPKCS11, "C_Verify" );
	pkcs11Info->pC_VerifyInit = ( CK_C_VerifyInit ) DynamicBind( pkcs11Info->hPKCS11, "C_VerifyInit" );

	/* Make sure we got valid pointers for every device function.  
	   C_FindObjectsFinal() wasn't added until 2.x and some drivers don't
	   implement it (a smaller subset of them nevertheless claim to be 2.x 
	   drivers), so we allow this to be null - the code won't call it if it's
	   not present */
	if( pC_GetInfo == NULL || pC_Initialize == NULL ||
		pkcs11Info->pC_CloseSession == NULL ||
		pkcs11Info->pC_CreateObject == NULL ||
		pkcs11Info->pC_Decrypt == NULL ||
		pkcs11Info->pC_DecryptInit == NULL ||
		pkcs11Info->pC_DestroyObject == NULL ||
		pkcs11Info->pC_Encrypt == NULL ||
		pkcs11Info->pC_EncryptInit == NULL ||
		pkcs11Info->pC_Finalize == NULL ||
		pkcs11Info->pC_FindObjects == NULL ||
		pkcs11Info->pC_FindObjectsInit == NULL ||
		pkcs11Info->pC_GenerateRandom == NULL ||
		pkcs11Info->pC_GenerateKeyPair == NULL ||
		pkcs11Info->pC_GetAttributeValue == NULL ||
		pkcs11Info->pC_GetMechanismInfo == NULL ||
		pkcs11Info->pC_GetSlotList == NULL ||
		pkcs11Info->pC_GetTokenInfo == NULL || 
		pkcs11Info->pC_InitPIN == NULL || 
		pkcs11Info->pC_InitToken == NULL || pkcs11Info->pC_Login == NULL ||
		pkcs11Info->pC_Logout == NULL || pkcs11Info->pC_OpenSession == NULL ||
		pkcs11Info->pC_SetAttributeValue == NULL ||
		pkcs11Info->pC_SetPIN == NULL || pkcs11Info->pC_Sign == NULL ||
		pkcs11Info->pC_SignInit == NULL || pkcs11Info->pC_UnwrapKey == NULL || 
		pkcs11Info->pC_Verify == NULL || pkcs11Info->pC_VerifyInit == NULL )
		{
		/* Free the library reference and clear the info */
		DynamicUnload( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Initialise the PKCS #11 library and get info on the device.  We have 
	   to use some kludges to handle v1-style functions */
	status = pC_Initialize( NULL_PTR ) & 0xFFFF;
	if( status == CKR_OK )
		{
		isInitialised = TRUE;
		status = pC_GetInfo( &info ) & 0xFFFF;
		}
	if( status == CKR_OK && info.cryptokiVersion.major <= 1 )
		/* There are four types of PKCS #11 driver around: v1, v1-like 
		   claiming to be v2, v2-like claiming to be v1, and v2.  cryptlib
		   can in theory handle all of these, however there are some problem
		   areas with v1 (for example v1 uses 16-bit values while v2 uses 32-
		   bit ones, this is usually OK because data is passed around as 32-
		   bit values with the high bits zeroed but some implementations may
		   leave garbage in the high 16 bits which leads to all sorts of 
		   confusion).  Because of this we explicitly fail if something claims
		   to be v1 even though it might work in practice */
		status = CKR_FUNCTION_NOT_SUPPORTED;
	if( status != CKR_OK )
		{
		if( isInitialised )
			pkcs11Info->pC_Finalize( NULL_PTR );
		DynamicUnload( pkcs11Info->hPKCS11 );
		memset( pkcs11Info, 0, sizeof( PKCS11_INFO ) );
		return( CRYPT_ERROR );
		}

	/* Copy out the device drivers name so the user can access it by name.  
	   Some vendors erroneously null-terminate the string so we check for 
	   nulls as well */
	memcpy( pkcs11Info->name, info.libraryDescription, 32 );
	while( i && ( pkcs11Info->name[ i - 1 ] == ' ' || \
				  !pkcs11Info->name[ i - 1 ] ) )
		i--;
	pkcs11Info->name[ i ] = '\0';

	return( CRYPT_OK );
	}

void deviceEndPKCS11( void )
	{
	int i;

	for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
		{
		if( pkcs11InfoTbl[ i ].hPKCS11 != NULL_INSTANCE )
			{
			pkcs11InfoTbl[ i ].pC_Finalize( NULL_PTR );
			DynamicUnload( pkcs11InfoTbl[ i ].hPKCS11 );
			}
		pkcs11InfoTbl[ i ].hPKCS11 = NULL_INSTANCE;
		}
	pkcs11Initialised = FALSE;
	}

void deviceInitPKCS11( void )
	{
	int tblIndex = 0, optionIndex;

	/* If we've previously tried to init the drivers, don't try it again */
	if( pkcs11Initialised )
		return;
	memset( pkcs11InfoTbl, 0, sizeof( pkcs11InfoTbl ) );

	/* Try and link in each driver specified in the config options */
	for( optionIndex = 0; optionIndex < MAX_PKCS11_DRIVERS; optionIndex++ )
		{
		RESOURCE_DATA msgData;
		char deviceDriverName[ MAX_PATH_LENGTH + 1 ];
		int status;

		setResourceData( &msgData, deviceDriverName, MAX_PATH_LENGTH );
		status = krnlSendMessage( CRYPT_UNUSED, 
						RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
						optionIndex + CRYPT_OPTION_DEVICE_PKCS11_DVR01 );
		if( cryptStatusError( status ) )
			continue;
		deviceDriverName[ msgData.length ] = '\0';
		status = loadPKCS11driver( &pkcs11InfoTbl[ tblIndex++ ], 
								   deviceDriverName );
		if( cryptStatusOK( status ) )
			pkcs11Initialised = TRUE;
		}
	}

#else

void deviceInitPKCS11( void )
	{
	/* If we've previously tried to init the drivers, don't try it again */
	if( pkcs11Initialised )
		return;

	if( C_Initialize( NULL_PTR ) != CKR_OK )
		return;
	pkcs11Initialised = TRUE;
	}

void deviceEndPKCS11( void )
	{
	if( pkcs11Initialised )
		C_Finalize( NULL_PTR );
	pkcs11Initialised = FALSE;
	}
#endif /* DYNAMIC_LOAD */

/****************************************************************************
*																			*
*						 		Utility Routines							*
*																			*
****************************************************************************/

/* Map a PKCS #11-specific error to a cryptlib error */

static int mapError( DEVICE_INFO *deviceInfo, const CK_RV errorCode,
					 const int defaultError )
	{
	deviceInfo->errorCode = ( int ) errorCode;
	switch( ( int ) errorCode )
		{
		case CKR_OK:
			return( CRYPT_OK );
		case CKR_HOST_MEMORY:
		case CKR_DEVICE_MEMORY:
			return( CRYPT_ERROR_MEMORY );
		case CKR_DEVICE_ERROR:
		case CKR_DEVICE_REMOVED:
			return( CRYPT_ERROR_SIGNALLED );
		case CKR_PIN_INCORRECT:
		case CKR_PIN_INVALID:
		case CKR_PIN_LEN_RANGE:
			return( CRYPT_ERROR_WRONGKEY );
		case CKR_SIGNATURE_INVALID:
			return( CRYPT_ERROR_SIGNATURE );
		case CKR_TOKEN_WRITE_PROTECTED:
		case CKR_USER_NOT_LOGGED_IN:
		case CKR_INFORMATION_SENSITIVE:
			return( CRYPT_ERROR_PERMISSION );
		case CKR_DATA_LEN_RANGE:
			return( CRYPT_ERROR_OVERFLOW );
		case CKR_USER_ALREADY_LOGGED_IN:
			return( CRYPT_ERROR_INITED );
		case CKR_USER_PIN_NOT_INITIALIZED:
			return( CRYPT_ERROR_NOTINITED );
		}

	return( defaultError );
	}

/* Find an object based on a given template.  There are two variations of 
   this, one which finds one and only one object, and the other which
   returns the first object it finds without treating the presence of 
   multiple objects as an error.
   
   The way in which this call works has special significance, there are PKCS
   #11 implementations which don't allow any other calls during the init/find/
   final sequence, so the code is structured to always call them one after 
   the other without any intervening calls.  In addition some drivers are
   confused over whether they're 1.x or 2.x and may or may not implement
   C_FindObjectsFinal().  Because of this we call it if it exists, if it 
   doesn't we assume the driver can handle cleanup itself (this situation
   shouldn't occur because we've checked for 1.x drivers earlier, but there
   are one or two drivers where it does happen) */

static int findDeviceObjects( DEVICE_INFO *deviceInfo, 
							  CK_OBJECT_HANDLE *hObject,
							  const CK_ATTRIBUTE *template,
							  const CK_ULONG templateCount,
							  const BOOLEAN onlyOne )
	{
	CK_OBJECT_HANDLE hObjectArray[ 2 ];
	CK_ULONG ulObjectCount;
	CK_RV status;

	status = C_FindObjectsInit( deviceInfo->deviceHandle,
								( CK_ATTRIBUTE_PTR ) template,
								templateCount );
	if( status == CKR_OK )
		{
		status = C_FindObjects( deviceInfo->deviceHandle, hObjectArray, 
								2, &ulObjectCount );
		if( C_FindObjectsFinal != NULL )
			C_FindObjectsFinal( deviceInfo->deviceHandle );
		}
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_NOTFOUND ) );
	if( !ulObjectCount )
		return( CRYPT_ERROR_NOTFOUND );
	if( ulObjectCount > 1 && onlyOne )
		return( CRYPT_ERROR_DUPLICATE );
	if( hObject != NULL )
		*hObject = hObjectArray[ 0 ];

	return( CRYPT_OK );
	}

static int findObject( DEVICE_INFO *deviceInfo, CK_OBJECT_HANDLE *hObject,
					   const CK_ATTRIBUTE *template,
					   const CK_ULONG templateCount )
	{
	return( findDeviceObjects( deviceInfo, hObject, 
							   template, templateCount, TRUE ) );
	}

static int findObjectEx( DEVICE_INFO *deviceInfo, CK_OBJECT_HANDLE *hObject,
						 const CK_ATTRIBUTE *template,
						 const CK_ULONG templateCount )
	{
	return( findDeviceObjects( deviceInfo, hObject, 
							   template, templateCount, FALSE ) );
	}

/* Set up certificate information and load it into the card */

static int updateCertificate( DEVICE_INFO *deviceInfo, 
							  const CRYPT_HANDLE iCryptHandle )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	static const CK_BBOOL bTrue = TRUE, bFalse = FALSE;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bFalse, sizeof( CK_BBOOL ) },
		{ CKA_ID, NULL_PTR, 0 },
		{ CKA_SUBJECT, NULL_PTR, 0 },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 },
		{ CKA_VALUE, NULL_PTR, 0 },
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_OBJECT_HANDLE hObject;
	RESOURCE_DATA msgData;
	STREAM stream;
	BYTE keyID[ CRYPT_MAX_HASHSIZE ], certBuffer[ MAX_BUFFER_SIZE ];
	BYTE sBuffer[ MAX_BUFFER_SIZE ], iAndSBuffer[ MAX_BUFFER_SIZE ];
	BYTE *sBufPtr = sBuffer, *iAndSBufPtr = iAndSBuffer;
	BYTE *certBufPtr = certBuffer;
	long serialNoLength;
	int length, status;

	/* Get the key ID for the cert and use it to locate the corresponding
	   public or private key object.  This is used both as a check to ensure
	   that the certificate corresponds to a key in the device and to allow
	   further attributes used for the certificate to be copied from the key.
	   In theory this would allow us to read the label from the key so that 
	   we can reuse it for the cert, but there doesn't seem to be any good
	   reason for this and it could lead to problems with multiple certs with
	   the same labels so we don't do it */
	setResourceData( &msgData, keyID, CRYPT_MAX_HASHSIZE );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusError( status ) )
		return( CRYPT_ARGERROR_NUM1 );
	keyTemplate[ 1 ].pValue = msgData.data;
	keyTemplate[ 1 ].ulValueLen = msgData.length;
	status = findObject( deviceInfo, &hObject, keyTemplate, 2 );
	if( cryptStatusError( status ) )
		{
		/* Couldn't find a private key with this ID, try for a public key */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubkeyClass;
		status = findObject( deviceInfo, &hObject, keyTemplate, 2 );
		}
	if( cryptStatusError( status ) )
		return( CRYPT_ERROR_NOTFOUND );
	certTemplate[ 4 ].pValue = msgData.data;
	certTemplate[ 4 ].ulValueLen = msgData.length;

	/* Get the subjectName from the cert */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_SUBJECT );
	if( cryptStatusOK( status ) && msgData.length > MAX_BUFFER_SIZE && \
	    ( sBufPtr = malloc( msgData.length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) )
		{
		msgData.data = sBufPtr;
		status = krnlSendMessage( iCryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_SUBJECT );
		}
	if( cryptStatusError( status ) )
		{
		if( sBufPtr != sBuffer && sBufPtr != NULL )
			free( sBufPtr );
		return( status );
		}
	certTemplate[ 5 ].pValue = msgData.data;
	certTemplate[ 5 ].ulValueLen = msgData.length;

	/* Get the issuerAndSerialNumber from the cert */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
	if( cryptStatusOK( status ) && msgData.length > MAX_BUFFER_SIZE && \
	    ( iAndSBufPtr = malloc( msgData.length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) )
		{
		msgData.data = iAndSBufPtr;
		status = krnlSendMessage( iCryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER );
		}
	if( cryptStatusError( status ) )
		{
		if( sBufPtr != sBuffer )
			free( sBufPtr );
		if( iAndSBufPtr != iAndSBuffer && iAndSBufPtr != NULL )
			free( iAndSBufPtr );
		return( status );
		}
	sMemConnect( &stream, iAndSBufPtr, msgData.length );
	readSequence( &stream, NULL );
	certTemplate[ 6 ].pValue = sMemBufPtr( &stream );
	readSequence( &stream, &length );
	certTemplate[ 6 ].ulValueLen = ( int ) sizeofObject( length );
	sSkip( &stream, length );
	certTemplate[ 7 ].pValue = sMemBufPtr( &stream );
	readTag( &stream );
	readLength( &stream, &serialNoLength );
	certTemplate[ 7 ].ulValueLen = ( int ) sizeofObject( serialNoLength );
	sMemDisconnect( &stream );

	/* Get the certificate data */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
	if( cryptStatusOK( status ) && msgData.length > MAX_BUFFER_SIZE && \
	    ( certBufPtr = malloc( msgData.length ) ) == NULL )
		status = CRYPT_ERROR_MEMORY;
	if( cryptStatusOK( status ) )
		{
		msgData.data = certBufPtr;
		status = krnlSendMessage( iCryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_ENC_CERT );
		}
	if( cryptStatusError( status ) )
		{
		if( sBufPtr != sBuffer )
			free( sBufPtr );
		if( iAndSBufPtr != iAndSBuffer )
			free( iAndSBufPtr );
		if( certBufPtr != certBuffer && certBufPtr != NULL )
			free( certBufPtr );
		return( status );
		}
	certTemplate[ 8 ].pValue = msgData.data;
	certTemplate[ 8 ].ulValueLen = msgData.length;

	/* We've finally got everything available, try and update the device with
	   the certificate data */
#ifndef NO_UPDATE
	status = C_CreateObject( deviceInfo->deviceHandle,
							 ( CK_ATTRIBUTE_PTR ) certTemplate, 9, &hObject );
	if( status != CKR_OK )
		status = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
#endif /* NO_UPDATE */

	/* Clean up */
	if( sBufPtr != sBuffer )
		free( sBufPtr );
	if( iAndSBufPtr != iAndSBuffer )
		free( iAndSBufPtr );
	if( certBufPtr != certBuffer )
		free( certBufPtr );
	return( status );
	}

/****************************************************************************
*																			*
*					Device Init/Shutdown/Device Control Routines			*
*																			*
****************************************************************************/

/* Prototypes for functions to get and free device capability information */

static void freeCapabilities( DEVICE_INFO *deviceInfo );
static int getCapabilities( DEVICE_INFO *deviceInfo );

/* Prototypes for device-specific functions */

static int getRandomFunction( DEVICE_INFO *deviceInfo, void *buffer,
							  const int length );

/* Close a previously-opened session with the device.  We have to have this
   before the init function since it may be called by it if the init process
   fails */

static void shutdownDeviceFunction( DEVICE_INFO *deviceInfo )
	{
	/* Log out and close the session with the device */
	if( deviceInfo->flags & DEVICE_LOGGEDIN )
		C_Logout( deviceInfo->deviceHandle );
	C_CloseSession( deviceInfo->deviceHandle );
	deviceInfo->deviceHandle = CRYPT_ERROR;
	deviceInfo->flags &= ~( DEVICE_ACTIVE | DEVICE_LOGGEDIN );

	/* Free the device capability information */
	freeCapabilities( deviceInfo );
	}

/* Open a session with the device */

static int initDeviceFunction( DEVICE_INFO *deviceInfo, const char *name,
							   const int nameLength )
	{
	CK_SESSION_HANDLE hSession;
	CK_SLOT_ID slotList[ MAX_PKCS11_SLOTS ];
	CK_ULONG slotCount = MAX_PKCS11_SLOTS;
	CK_TOKEN_INFO tokenInfo;
	CK_RV status;
	int tokenSlot = DEFAULT_SLOT, i, cryptStatus;

	/* Get information on all available slots */
	status = C_GetSlotList( TRUE, slotList, &slotCount );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_OPEN ) );
	if( !slotCount )	/* Can happen in some circumstances */
		return( CRYPT_ERROR_OPEN );

	/* Check whether a token name (used to select the slot) has been 
	   specified */
	for( i = 1; i < nameLength - 1; i++ )
		if( name[ i ] == ':' && name[ i + 1 ] == ':' )
			{
			const void *tokenName = name + i + 2;	/* Skip '::' */
			const int tokenNameLength = nameLength - ( i + 2 );

			if( tokenNameLength <= 0 )
				return( CRYPT_ARGERROR_STR1 );

			/* Check each slot for a token matching the given name */
			for( tokenSlot = 0; tokenSlot < slotCount; tokenSlot++ )
				{
				status = C_GetTokenInfo( slotList[ tokenSlot ], &tokenInfo );
				if( status == CKR_OK && \
					!strnicmp( tokenName, tokenInfo.label, tokenNameLength ) )
					break;
				};
			if( tokenSlot == slotCount )
				return( CRYPT_ERROR_NOTFOUND );
			}
	deviceInfo->slotHandle = slotList[ tokenSlot ];

	/* Open a session with the device in the first slot.  This gets a bit
	   awkward because we can't tell whether a R/W session is OK without
	   opening a session, but we can't open a session unless we know whether
	   a R/W session is OK, so first we try for a RW session and if that
	   fails we go for a read-only session */
	status = C_OpenSession( deviceInfo->slotHandle, 
							CKF_RW_SESSION | CKF_SERIAL_SESSION, NULL_PTR, 
							NULL_PTR, &hSession );
	if( status == CKR_TOKEN_WRITE_PROTECTED )
		status = C_OpenSession( deviceInfo->slotHandle, 
								CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, 
								&hSession );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_OPEN ) );
	deviceInfo->deviceHandle = hSession;
	deviceInfo->flags |= DEVICE_ACTIVE;

	/* Set up any device-specific capabilities */
	status = C_GetTokenInfo( deviceInfo->slotHandle, &tokenInfo );
	if( status != CKR_OK )
		{
		shutdownDeviceFunction( deviceInfo );
		return( mapError( deviceInfo, status, CRYPT_ERROR_OPEN ) );
		}
	if( tokenInfo.flags & CKF_RNG )
		/* The device has an onboard RNG we can use */
		deviceInfo->getRandomFunction = getRandomFunction;
	if( tokenInfo.flags & CKF_WRITE_PROTECTED )
		/* The device can't have data on it changed */
		deviceInfo->flags |= DEVICE_READONLY;
	if( tokenInfo.flags & CKF_LOGIN_REQUIRED )
		/* The user needs to log in before using various device functions */
		deviceInfo->flags |= DEVICE_NEEDSLOGIN;
	deviceInfo->minPinSize = ( int ) tokenInfo.ulMinPinLen;
	deviceInfo->maxPinSize = ( int ) tokenInfo.ulMaxPinLen;

	/* Set up the capability information for this device */
	cryptStatus = getCapabilities( deviceInfo );
	if( cryptStatusError( cryptStatus ) )
		{
		shutdownDeviceFunction( deviceInfo );
		return( ( cryptStatus == CRYPT_ERROR ) ? \
				CRYPT_ERROR_OPEN : ( int ) cryptStatus );
		}

	return( CRYPT_OK );
	}

/* Handle device control functions */

static int controlFunction( DEVICE_INFO *deviceInfo,
							const CRYPT_ATTRIBUTE_TYPE type,
							const void *data1, const int data1Length,
							const void *data2, const int data2Length )
	{
	CK_RV status;

	/* Handle user authorisation */
	if( type == CRYPT_DEVINFO_AUTHENT_USER || \
		type == CRYPT_DEVINFO_AUTHENT_SUPERVISOR )
		{
		/* If the user is already logged in, log them out before we try
		   logging in with a new authentication value */
		if( deviceInfo->flags & DEVICE_LOGGEDIN )
			{
			C_Logout( deviceInfo->deviceHandle );
			deviceInfo->flags &= ~DEVICE_LOGGEDIN;
			}

		/* Authenticate the user to the device */
		status = C_Login( deviceInfo->deviceHandle,
						  ( type == CRYPT_DEVINFO_AUTHENT_USER ) ? \
						  CKU_USER : CKU_SO, ( CK_CHAR_PTR ) data1,
						  ( CK_ULONG ) data1Length );
		if( status == CKR_OK || status == CKR_USER_ALREADY_LOGGED_IN )
			deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( mapError( deviceInfo, status, CRYPT_ERROR ) );
		}

	/* Handle authorisation value change */
	if( type == CRYPT_DEVINFO_SET_AUTHENT_USER || \
		type == CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR )
		{
		status = C_SetPIN( deviceInfo->deviceHandle, ( CK_CHAR_PTR ) data1,
						   ( CK_ULONG ) data1Length, ( CK_CHAR_PTR ) data2,
						   ( CK_ULONG ) data2Length );
		return( mapError( deviceInfo, status, CRYPT_ERROR ) );
		}

	/* Handle initialisation and zeroisation */
	if( type == CRYPT_DEVINFO_INITIALISE || \
		type == CRYPT_DEVINFO_ZEROISE )
		{
		CK_SESSION_HANDLE hSession;
		CK_CHAR label[ 32 ];

		/* If there's a session active with the device, log out and terminate
		   the session, since the token init will reset this */
		if( deviceInfo->deviceHandle != CRYPT_ERROR )
			{
			C_Logout( deviceInfo->deviceHandle );
			C_CloseSession( deviceInfo->deviceHandle );
			}
		deviceInfo->deviceHandle = CRYPT_ERROR;

		/* Initialise/clear the device */
		memset( label, ' ', 32 );
		status = C_InitToken( deviceInfo->slotHandle, 
							  ( CK_CHAR_PTR ) data1,
							  ( CK_ULONG ) data1Length, label );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_ERROR ) );

		/* Reopen the session with the device */
		status = C_OpenSession( deviceInfo->slotHandle,
								CKF_RW_SESSION | CKF_SERIAL_SESSION,
								NULL_PTR, NULL_PTR, &hSession );
		if( status != CKR_OK )
			return( mapError( deviceInfo, status, CRYPT_ERROR_OPEN ) );
		deviceInfo->deviceHandle = hSession;

		/* If it's a straight zeroise, we're done */
		if( type == CRYPT_DEVINFO_ZEROISE )
			return( CRYPT_OK );

		/* We're initialising it, log in as supervisor and set the initial 
		   user PIN to the same as the SSO PIN.  We do this because the init
		   user PIN functionality is a bit of an oddball function which has
		   to fill the gap between C_InitToken() (which sets the SSO PIN) and
		   C_SetPIN() (which can only set the SSO PIN for the SSO or the user 
		   PIN for the user).  Setting the user PIN by the SSO, which is 
		   usually required to perform any useful (non-administrative) 
		   function with the token, requires the special-case C_InitPIN().
		   Since the token will initially be used by the SSO we set it to the 
		   same as the SSO PIN and rely on the user to change it before they
		   hand it over to the user.  In most cases the user *is* the SSO, so
		   this ensures the device behaves as expected when the user isn't 
		   even aware that there are SSO and user roles.
		   
		   A useful side-effect of this is that it eliminates problems with
		   some devices which behave somewhat strangely if the SSO PIN is set
		   but the user PIN isn't */
		status = C_Login( deviceInfo->deviceHandle, CKU_SO,
						  ( CK_CHAR_PTR ) data1, ( CK_ULONG ) data1Length );
		if( status == CKR_OK )
			status = C_InitPIN( deviceInfo->deviceHandle, 
								( CK_CHAR_PTR ) data1, 
								( CK_ULONG ) data1Length );
		if( status != CKR_OK )
			{
			C_Logout( deviceInfo->deviceHandle );
			C_CloseSession( deviceInfo->deviceHandle );
			deviceInfo->deviceHandle = CRYPT_ERROR;
			return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );
			}

		/* We're logged in and ready to go */
		deviceInfo->flags |= DEVICE_LOGGEDIN;
		return( CRYPT_OK );
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
	CK_RV status;

	status = C_GenerateRandom( deviceInfo->deviceHandle, buffer, length );
	return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );
	}

/* Get the label for an object */

static int getObjectLabel( DEVICE_INFO *deviceInfo, 
						   const CK_OBJECT_HANDLE hObject, 
						   char *label, int *labelLength )
	{
	CK_ATTRIBUTE keyLabelTemplate = \
		{ CKA_LABEL, NULL_PTR, 0 };
	char labelBuffer[ CRYPT_MAX_TEXTSIZE ], *labelPtr = label;
	int status;

	status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
								  &keyLabelTemplate, 1 );
	if( status == CKR_OK )
		{
		if( keyLabelTemplate.ulValueLen > CRYPT_MAX_TEXTSIZE && \
			( labelPtr = malloc( ( size_t ) \
							( keyLabelTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		keyLabelTemplate.pValue = labelPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
									  &keyLabelTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		*labelLength = 0;
		if( label != NULL )
			label[ 0 ] = '\0';
		}
	else
		{
		*labelLength = min( keyLabelTemplate.ulValueLen, CRYPT_MAX_TEXTSIZE );
		if( label != NULL )
			memcpy( label, labelPtr, *labelLength );
		}
	if( labelPtr != labelBuffer )
		free( labelPtr );
	return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );
	}

/* Instantiate a cert object from a handle */

static int instantiateCert( DEVICE_INFO *deviceInfo, 
							const CK_OBJECT_HANDLE hCertificate, 
							CRYPT_CERTIFICATE *iCryptCert,
							const BOOLEAN createContext )
	{
	CK_ATTRIBUTE dataTemplate = \
		{ CKA_VALUE, NULL_PTR, 0 };
	CK_RV status;
	CREATEOBJECT_INFO createInfo;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Fetch the cert data into local memory */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hCertificate,
								  &dataTemplate, 1 );
	if( status == CKR_OK )
		{
		if( dataTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = malloc( ( size_t ) ( dataTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		dataTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hCertificate,
									  &dataTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			free( bufPtr );
		return( mapError( deviceInfo, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Import the cert as a cryptlib object */
	setMessageCreateObjectInfo( &createInfo, ( createContext ) ? \
								CERTIMPORT_NORMAL : CERTIMPORT_DATA_ONLY );
	createInfo.createIndirect = TRUE;
	createInfo.arg2 = CERTFORMAT_NORMAL;
	createInfo.strArg1 = bufPtr;
	createInfo.strArgLen1 = dataTemplate.ulValueLen;
	cryptStatus = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								   RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								   &createInfo, OBJECT_TYPE_CERTIFICATE );
	if( bufPtr != buffer )
		free( bufPtr );
	if( cryptStatusOK( cryptStatus ) )
		*iCryptCert = createInfo.cryptHandle;
	return( cryptStatus );
	}

/* Find a certificate object based on various search criteria:
   
	- Find cert matching the ID of an object hObject - certFromObject()
	- Find cert matching a supplied template - certFromTemplate()
	- Find cert matching a given ID - certFromID()
	- Find cert matching a given label - certFromLabel()
	- Find any X.509 cert - certFromLabel().

  These are general-purpose functions whose behaviour can be modified through
  the following action codes */

typedef enum {
	FINDCERT_NORMAL,		/* Instantiate standard cert+context */
	FINDCERT_DATAONLY,		/* Instantiate data-only cert */
	FINDCERT_P11OBJECT		/* Return handle to PKCS #11 object */
	} FINDCERT_ACTION;

static int findCertFromID( DEVICE_INFO *deviceInfo,
						   const void *certID, 
						   const int certIDlength,
						   CRYPT_CERTIFICATE *iCryptCert,
						   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, ( CK_VOID_PTR ) certID, certIDlength }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given ID */
	cryptStatus = findObject( deviceInfo, &hCertificate, certTemplate, 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( deviceInfo, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

static int findCertFromObject( DEVICE_INFO *deviceInfo,
							   const CK_OBJECT_HANDLE hObject, 
							   CRYPT_CERTIFICATE *iCryptCert,
							   const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ID, NULL, 0 }
		};
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* We're looking for a cert whose ID matches the object, read the key ID 
	   from the device */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = malloc( ( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			free( bufPtr );
		return( mapError( deviceInfo, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Look for a certificate with the same ID as the key */
	cryptStatus = findCertFromID( deviceInfo, bufPtr, 
								  idTemplate.ulValueLen, iCryptCert,
								  findAction );
	if( bufPtr != buffer )
		free( bufPtr );
	return( cryptStatus );
	}

static int findCertFromTemplate( DEVICE_INFO *deviceInfo,
								 const CK_ATTRIBUTE *findTemplate,
								 const int templateCount,
								 CRYPT_CERTIFICATE *iCryptCert,
								 const FINDCERT_ACTION findAction )
	{
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert from the given template */
	cryptStatus = findObject( deviceInfo, &hCertificate, findTemplate, 
							  templateCount );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( deviceInfo, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

static int findCertFromLabel( DEVICE_INFO *deviceInfo,
							  const char *label, const int labelLength,
							  CRYPT_CERTIFICATE *iCryptCert,
							  const FINDCERT_ACTION findAction )
	{
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, NULL, 0 }
		};
	CK_OBJECT_HANDLE hCertificate;
	int cryptStatus;

	*iCryptCert = CRYPT_ERROR;

	/* Try and find the cert with the given label */
	if( label != NULL )
		{
		certTemplate[ 2 ].pValue = ( CK_VOID_PTR ) label;
		certTemplate[ 2 ].ulValueLen = labelLength;
		}
	cryptStatus = findObject( deviceInfo, &hCertificate, certTemplate, 
							  ( label == NULL ) ? 2 : 3 );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	if( findAction == FINDCERT_P11OBJECT )
		{
		*iCryptCert = hCertificate;
		return( CRYPT_OK );
		}

	return( instantiateCert( deviceInfo, hCertificate, iCryptCert, 
							 ( findAction == FINDCERT_NORMAL ) ? \
							 TRUE : FALSE ) );
	}

/* Find an object from a source object by matching ID's.  This is used to
   find a key matching a cert, a public key matching a private key, or
   other objects with similar relationships */

static int findObjectFromObject( DEVICE_INFO *deviceInfo,
								 const CK_OBJECT_HANDLE hSourceObject, 
								 const CK_OBJECT_CLASS objectClass,
								 CK_OBJECT_HANDLE *hObject )
	{
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &objectClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_ID, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE idTemplate = \
		{ CKA_ID, NULL_PTR, 0 };
	CK_RV status;
	BYTE buffer[ MAX_BUFFER_SIZE ], *bufPtr = buffer;
	int cryptStatus;

	*hObject = CRYPT_ERROR;

	/* We're looking for a key whose ID matches that of the source object, 
	   read it's cert ID */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hSourceObject, 
								  &idTemplate, 1 );
	if( status == CKR_OK )
		{
		if( idTemplate.ulValueLen > MAX_BUFFER_SIZE && \
			( bufPtr = malloc( ( size_t ) ( idTemplate.ulValueLen ) ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );
		idTemplate.pValue = bufPtr;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hSourceObject,
									  &idTemplate, 1 );
		}
	if( status != CKR_OK )
		{
		if( bufPtr != buffer )
			free( bufPtr );
		return( mapError( deviceInfo, status, CRYPT_ERROR_NOTFOUND ) );
		}

	/* Find the key object with the given ID */
	keyTemplate[ 1 ].pValue = bufPtr;
	keyTemplate[ 1 ].ulValueLen = idTemplate.ulValueLen;
	cryptStatus = findObject( deviceInfo, hObject, keyTemplate, 2 );
	if( bufPtr != buffer )
		free( bufPtr );
	return( cryptStatus );
	}

/* Read a flag for an object.  An absent value is treated as FALSE */

static BOOLEAN readFlag( DEVICE_INFO *deviceInfo, 
						 const CK_OBJECT_HANDLE hObject,
						 const CK_ATTRIBUTE_TYPE flagType )
	{
	CK_BBOOL bFlag;
	CK_ATTRIBUTE flagTemplate = { flagType, &bFlag, sizeof( CK_BBOOL ) };

	return( ( C_GetAttributeValue( deviceInfo->deviceHandle, hObject,
								   &flagTemplate, 1 ) == CKR_OK && bFlag ) ? \
			TRUE : FALSE );
	}
		
/* Instantiate an object in a device.  This works like the create context
   function but instantiates a cryptlib object using data already contained
   in the device (for example a stored private key or certificate).  If the
   value being read is a public key and there's a certificate attached, the
   instantiated object is a native cryptlib object rather than a device
   object with a native certificate object attached because there doesn't 
   appear to be any good reason to create the public-key object in the device, 
   and for most devices the cryptlib native object will be faster anyway */

static int getItemFunction( DEVICE_INFO *deviceInfo,
							CRYPT_CONTEXT *iCryptContext,
							const CRYPT_KEYID_TYPE keyIDtype,
							const void *keyID, const int keyIDlength,
							void *auxInfo, int *auxInfoLength, 
							const int flags )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	const CAPABILITY_INFO *capabilityInfoPtr;
	CK_ATTRIBUTE iAndSTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_ISSUER, NULL_PTR, 0 },
		{ CKA_SERIAL_NUMBER, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, NULL_PTR, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, NULL_PTR, 0 }
		};
	CK_ATTRIBUTE keyTypeTemplate = \
		{ CKA_KEY_TYPE, NULL_PTR, sizeof( CK_KEY_TYPE ) };
	CK_ATTRIBUTE keySizeTemplate = \
		{ 0, NULL_PTR, 0 };
	CK_ATTRIBUTE keyLabelTemplate = \
		{ CKA_LABEL, NULL_PTR, 0 };
	CK_OBJECT_HANDLE hObject, hCertificate;
	CK_KEY_TYPE keyType;
	CRYPT_CERTIFICATE iCryptCert;
	CRYPT_ALGO cryptAlgo;
	BOOLEAN certViaPrivateKey = FALSE, privateKeyViaCert = FALSE;
	BOOLEAN certPresent = FALSE;
	char label[ CRYPT_MAX_TEXTSIZE ];
	int keySize, actionFlags = 0, labelLength, status;

	/* If we're looking for something based on an issuerAndSerialNumber, set 
	   up the search template */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		STREAM stream;
		long serialNoLength;
		int length;

		sMemConnect( &stream, keyID, STREAMSIZE_UNKNOWN );
		readSequence( &stream, NULL );
		iAndSTemplate[ 2 ].pValue = sMemBufPtr( &stream );
		readSequence( &stream, &length );
		iAndSTemplate[ 2 ].ulValueLen = ( int ) sizeofObject( length );
		sSkip( &stream, length );
		iAndSTemplate[ 3 ].pValue = sMemBufPtr( &stream );
		readTag( &stream );
		readLength( &stream, &serialNoLength );
		iAndSTemplate[ 3 ].ulValueLen = ( int ) sizeofObject( serialNoLength );
		sMemDisconnect( &stream );
		}

	/* If we're looking for a public key, try for a cert first.  Some non-
	   crypto-capable devices don't have an explicit CKO_PUBLIC_KEY but only 
	   a CKO_CERTIFICATE, so we try to create a cert object before we try 
	   anything else.  If the keyID type is an ID or label, this won't 
	   necessarily locate the cert since it could be unlabelled or have a 
	   different label/ID, so if this fails we try again by going via the
	   private key with the given label/ID */
	if( flags & KEYMGMT_FLAG_PUBLICKEY )
		{
		const FINDCERT_ACTION findAction = \
			( flags & ( KEYMGMT_FLAG_CHECK_ONLY | KEYMGMT_FLAG_LABEL_ONLY ) ) ? \
			FINDCERT_P11OBJECT : FINDCERT_NORMAL;

		if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
			status = findCertFromTemplate( deviceInfo, iAndSTemplate, 4, 
										   &iCryptCert, findAction );
		else
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				status = findCertFromID( deviceInfo, keyID, keyIDlength, 
										 &iCryptCert, findAction );
			else
				status = findCertFromLabel( deviceInfo, keyID, keyIDlength, 
											&iCryptCert, findAction );
		if( cryptStatusOK( status ) )
			{
			/* If we're just checking whether an object exists, return now.  
			   If all we want is the key label, copy it back to the caller 
			   and exit */
			if( flags & KEYMGMT_FLAG_CHECK_ONLY )
				return( CRYPT_OK );
			if( flags & KEYMGMT_FLAG_LABEL_ONLY )
				return( getObjectLabel( deviceInfo, 
										( CK_OBJECT_HANDLE ) iCryptCert, 
										auxInfo, auxInfoLength ) );

			*iCryptContext = iCryptCert;
			return( CRYPT_OK );
			}
		else
			/* If we're looking for a specific match on a certificate (rather 
			   than just a general public key) and we don't find anything, 
			   exit now */
			if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
				return( status );
		}

	/* Either there were no certs found or we're looking for a private key 
	   (or, somewhat unusually, a raw public key).  At this point we can 
	   approach the problem from one of two sides, if we've got an 
	   issuerAndSerialNumber we have to find the matching cert and get the 
	   key from that, otherwise we find the key and get the cert from that */
	if( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER )
		{
		/* Try and find the cert from the given template */
		status = findObject( deviceInfo, &hCertificate, iAndSTemplate, 4 );
		if( cryptStatusOK( status ) )
			{
			/* We found the cert, use it to find the corresponding private 
			   key */
			status = findObjectFromObject( deviceInfo, hCertificate, 
										   CKO_PRIVATE_KEY, &hObject );
			if( cryptStatusError( status ) )
				return( status );
	
			/* Remember that we've already got a cert to attach to the private
			   key */
			privateKeyViaCert = TRUE;
			}
		else
			/* If we didn't find anything, it may be because whoever set up
			   the token didn't set the iAndS rather than because there's no
			   key there, so we only bail out if we got some unexpected type 
			   of error */
			if( status != CRYPT_ERROR_NOTFOUND )
				return( status );
		}
	else
		{
		const int keyTemplateCount = ( keyID == NULL ) ? 1 : 2;

		/* Try and find the object with the given label/ID, or the first 
		   object of the given class if no ID is given */
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) \
								  ( ( flags & KEYMGMT_FLAG_PUBLICKEY ) ? \
								  &pubkeyClass : &privkeyClass );
		if( keyIDtype != CRYPT_KEYID_NONE )
			{
			if( keyIDtype == CRYPT_IKEYID_KEYID )
				keyTemplate[ 1 ].type = CKA_ID;
			keyTemplate[ 1 ].pValue = ( CK_VOID_PTR ) keyID;
			keyTemplate[ 1 ].ulValueLen = keyIDlength;
			}
		status = findObject( deviceInfo, &hObject, keyTemplate, 
							 keyTemplateCount );
		if( status == CRYPT_ERROR_NOTFOUND && \
			( flags & KEYMGMT_FLAG_PUBLICKEY ) )
			{
			/* Some devices may only contain private key objects with 
			   associated certificates which can't be picked out of the other 
			   cruft which is present without going via the private key, so 
			   if we're looking for a public key and don't find one, we try 
			   again for a private key whose sole function is to point to an 
			   associated cert */
			keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
			status = findObject( deviceInfo, &hObject, keyTemplate, 
								 keyTemplateCount );
			if( cryptStatusError( status ) )
				return( status );
		
			/* Remember that although we've got a private key object, we only 
			   need it to find the associated cert and not finding an 
			   associated cert is an error */
			certViaPrivateKey = TRUE;
			}
		}

	/* If we're looking for any kind of private key and we either have an
	   explicit cert.ID but couldn't find a cert for it or we don't have a 
	   proper ID to search on and a generic search found more than one 
	   matching object, chances are we're after a generic decrypt key.  The 
	   former only occurs in misconfigured or limited-memory tokens, the 
	   latter only in rare tokens which store more than one private key, 
	   typically one for signing and one for verification.  
	   
	   If either of these cases occur we try again looking specifically for 
	   a decryption key.  Even this doesn't always work, there's at least one 
	   >1-key token which marks a signing key as a decryption key so we still 
	   get a CRYPT_ERROR_DUPLICATE error.
	   
	   Finally, if we can't find a decryption key either, we look for an
	   unwrapping key.  This may or may not work, depending on whether we 
	   have a decryption key marked as valid for unwrapping but not 
	   decryption, or a key which is genuinely only valid for unwrapping, but
	   at this point we're ready to try anything */
	if( ( flags & KEYMGMT_FLAG_PRIVATEKEY ) && \
		( keyIDtype == CRYPT_IKEYID_ISSUERANDSERIALNUMBER && \
		  status == CRYPT_ERROR_NOTFOUND ) || \
		( status == CRYPT_ERROR_DUPLICATE ) )
		{
		static const CK_BBOOL bTrue = TRUE;
		CK_ATTRIBUTE decryptKeyTemplate[] = {
			{ CKA_CLASS, ( CK_VOID_PTR ) &privkeyClass, sizeof( CK_OBJECT_CLASS ) },
			{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) }
			};

		status = findObject( deviceInfo, &hObject, decryptKeyTemplate, 2 );
		if( cryptStatusError( status ) )
			{
			decryptKeyTemplate[ 1 ].type = CKA_UNWRAP;
			status = findObject( deviceInfo, &hObject, decryptKeyTemplate, 2 );
			}
		}
	if( cryptStatusError( status ) )
		return( status );

	/* If we're just checking whether an object exists, return now.  If all 
	   we want is the key label, copy it back to the caller and exit */
	if( flags & KEYMGMT_FLAG_CHECK_ONLY )
		return( CRYPT_OK );
	if( flags & KEYMGMT_FLAG_LABEL_ONLY )
		return( getObjectLabel( deviceInfo, hObject, auxInfo, 
								auxInfoLength ) );

	/* We found something, map the key type to a cryptlib algorithm ID and
	   determine the key size, and find its capabilities */
	keyTypeTemplate.pValue = &keyType;
	C_GetAttributeValue( deviceInfo->deviceHandle, hObject, 
						 &keyTypeTemplate, 1 );
	switch( ( int ) keyType )
		{
		case CKK_RSA:
			cryptAlgo = CRYPT_ALGO_RSA;
			keySizeTemplate.type = CKA_MODULUS;
			break;
		case CKK_DSA:
			cryptAlgo = CRYPT_ALGO_DSA;
			keySizeTemplate.type = CKA_PRIME;
			break;
		case CKK_DH:
			cryptAlgo = CRYPT_ALGO_DH;
			keySizeTemplate.type = CKA_PRIME;
			break;
		default:
			return( CRYPT_ERROR_NOTAVAIL );
		}
	C_GetAttributeValue( deviceInfo->deviceHandle, hObject, 
						 &keySizeTemplate, 1 );
	keySize = keySizeTemplate.ulValueLen;
	capabilityInfoPtr = findCapabilityInfo( deviceInfo->capabilityInfo, 
											cryptAlgo );
	if( capabilityInfoPtr == NULL )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Try and find a certificate which matches the key.  The process is as
	   follows:

		if cert object found in issuerAndSerialNumber search
			create native data-only cert object
			attach cert object to key
		else
			if public key
				if cert
					create native cert (+context) object
				else
					create device pubkey object, mark as "key loaded"
			else
				create device privkey object, mark as "key loaded"
				if cert
					create native data-only cert object
					attach cert object to key

	   The reason for doing things this way is given in the comment at the 
	   top of this section */
	if( privateKeyViaCert )
		{
		/* We've already got the cert object handle, instantiate a native
		   data-only cert from it */
		status = instantiateCert( deviceInfo, hCertificate, &iCryptCert, 
								  FALSE );
		if( cryptStatusError( status ) )
			return( status );
		certPresent = TRUE;
		}
	else
		{
		status = findCertFromObject( deviceInfo, hObject, &iCryptCert, 
									 ( flags & KEYMGMT_FLAG_PUBLICKEY ) ? \
									 FINDCERT_NORMAL : FINDCERT_DATAONLY );
		if( cryptStatusError( status ) )
			{
			/* If we get a CRYPT_ERROR_NOTFOUND this is OK since it means 
			   there's no cert present, however anything else is an error. In 
			   addition if we've got a private key whose only function is to 
			   point to an associated cert then not finding anything is also 
			   an error */
			if( status != CRYPT_ERROR_NOTFOUND || certViaPrivateKey )
				return( status );
			}
		else
			{
			/* We got the cert, if we're being asked for a public key then
			   we've created a native object to contain it so we return that */
			certPresent = TRUE;
			if( flags & KEYMGMT_FLAG_PUBLICKEY )
				{
				*iCryptContext = iCryptCert;
				return( CRYPT_OK );
				}
			}
		}

	/* Get the permitted capabilities for the object.  Since the keys are
	   sensitive (otherwise they wouldn't be held in a crypto device) we
	   don't allow external use */
	if( readFlag( deviceInfo, hObject, CKA_ENCRYPT ) )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_ENCRYPT, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( readFlag( deviceInfo, hObject, CKA_DECRYPT ) || \
		readFlag( deviceInfo, hObject, CKA_UNWRAP ) )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_DECRYPT, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( readFlag( deviceInfo, hObject, CKA_SIGN ) )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGN, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( readFlag( deviceInfo, hObject, CKA_VERIFY ) )
		actionFlags |= MK_ACTION_PERM( RESOURCE_MESSAGE_CTX_SIGCHECK, 
									   ACTION_PERM_NONE_EXTERNAL );
	if( !actionFlags )
		{
		/* If no usage is allowed, we can't do anything with the object so
		   we don't even try to create it */
		if( certPresent )
			krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( CRYPT_ERROR_PERMISSION );
		}

	/* Create a dummy context for the key, remember the device it's 
	   contained in, the handle for the device-internal key, and the object's
	   label, mark it as initialised (ie with a key loaded), and if there's a 
	   cert present attach it to the context.  The cert is an internal object 
	   used only by the context so we tell the kernel to mark it as owned by 
	   the context only */
	status = getObjectLabel( deviceInfo, hObject, label, &labelLength );
	if( cryptStatusOK( status ) )
		status = createContextFromCapability( iCryptContext, 
								capabilityInfoPtr, CREATEOBJECT_FLAG_DUMMY );
	if( cryptStatusError( status ) )
		{
		if( certPresent )
			krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_DECREFCOUNT );
		return( status );
		}
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETDEPENDENT,
					 &deviceInfo->objectHandle, TRUE );
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &hObject, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &actionFlags, CRYPT_IATTRIBUTE_ACTIONPERMS );
	if( labelLength )
		{
		RESOURCE_DATA msgData;

		setResourceData( &msgData, label, labelLength );
		krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
						 &msgData, CRYPT_CTXINFO_LABEL );
		}
	krnlSendMessage( *iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 &keySize, CRYPT_IATTRIBUTE_KEYSIZE );
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
	int status;

	/* Lock the cert for our exclusive use (in case it's a cert chain, we 
	   also select the first cert in the chain), update the device with the 
	   cert, and unlock it to allow others access */
	krnlSendMessage( iCryptHandle, RESOURCE_IMESSAGE_GETDEPENDENT,
					 &iCryptCert, OBJECT_TYPE_CERTIFICATE );
	krnlSendMessage( iCryptCert, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 MESSAGE_VALUE_CURSORFIRST, 
					 CRYPT_CERTINFO_CURRENT_CERTIFICATE );
	status = krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_LOCK );
	if( cryptStatusError( status ) )
		return( status );
	status = updateCertificate( deviceInfo, iCryptCert );
	krnlSendNotifier( iCryptCert, RESOURCE_IMESSAGE_UNLOCK );

	return( status );
	}

/* Delete an object in a device */

static int deleteItemFunction( DEVICE_INFO *deviceInfo,
							   const CRYPT_KEYID_TYPE keyIDtype,
							   const void *keyID, const int keyIDlength )
	{
	static const CK_OBJECT_CLASS pubkeyClass = CKO_PUBLIC_KEY;
	static const CK_OBJECT_CLASS privkeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
	static const CK_CERTIFICATE_TYPE certType = CKC_X_509;
	CK_ATTRIBUTE certTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &certClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_CERTIFICATE_TYPE, ( CK_VOID_PTR ) &certType, sizeof( CK_CERTIFICATE_TYPE ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &pubkeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, ( CK_VOID_PTR ) keyID, keyIDlength }
		};
	CK_OBJECT_HANDLE hPrivkey = CRYPT_ERROR, hCertificate = CRYPT_ERROR;
	CK_OBJECT_HANDLE hPubkey = CRYPT_ERROR;
	int status;

	assert( keyIDtype == CRYPT_KEYID_NAME );

	/* Find the object to delete based on the label.  Since we can have 
	   multiple related objects (eg a key and a cert) with the same label, a 
	   straight search for all objects with a given label could return
	   CRYPT_ERROR_DUPLICATE so we search for the objects by type as well as 
	   label.  In addition even a search for specific objects can return
	   CRYPT_ERROR_DUPLICATE so we use the Ex version of findObject() to make
	   sure we don't get an error if multiple objects exist.  Although
	   cryptlib won't allow more than one object with a given label to be
	   created, other applications might create duplicate labels, the correct
	   behaviour in these circumstances is uncertain, what we do for now is
	   delete the first object we find which matches the label.
	   
	   First we try for a cert and use that to find associated keys */
	status = findObjectEx( deviceInfo, &hCertificate, certTemplate, 3 );
	if( cryptStatusOK( status ) )
		{
		/* We got a cert, if there are associated keys delete them as well */
		status = findObjectFromObject( deviceInfo, hCertificate, 
									   CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( status ) )
			hPubkey = CRYPT_ERROR;
		status = findObjectFromObject( deviceInfo, hCertificate, 
									   CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( status ) )
			hPrivkey = CRYPT_ERROR;

		/* Delete the cert */
		status = C_DestroyObject( deviceInfo->deviceHandle, hCertificate );
		if( status != CKR_OK )
			status = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
		return( status );
		}
	else
		{
		/* We didn't find a cert with the given label, try for public and
		   private keys */
		status = findObjectEx( deviceInfo, &hPubkey, keyTemplate, 2 );
		if( cryptStatusError( status ) )
			hPubkey = CRYPT_ERROR;
		keyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &privkeyClass;
		status = findObjectEx( deviceInfo, &hPrivkey, keyTemplate, 2 );
		if( cryptStatusError( status ) )
			hPrivkey = CRYPT_ERROR;

		/* There may be an unlabelled cert present, try and find it by 
		   looking for a cert matching the key ID */
		status = findObjectFromObject( deviceInfo, 
									   ( hPrivkey != CRYPT_ERROR ) ? \
									   hPrivkey : hPubkey, CKO_CERTIFICATE, 
									   &hCertificate );
		if( cryptStatusError( status ) )
			hCertificate = CRYPT_ERROR;
		}

	/* If we found a public key with a given label but no private key, try 
	   and find a matching private key by ID, and vice versa */
	if( hPubkey != CRYPT_ERROR && hPrivkey == CRYPT_ERROR )
		{
		status = findObjectFromObject( deviceInfo, hPubkey, 
									   CKO_PRIVATE_KEY, &hPrivkey );
		if( cryptStatusError( status ) )
			hPrivkey = CRYPT_ERROR;
		}
	if( hPrivkey != CRYPT_ERROR && hPubkey == CRYPT_ERROR )
		{
		status = findObjectFromObject( deviceInfo, hPrivkey, 
									   CKO_PUBLIC_KEY, &hPubkey );
		if( cryptStatusError( status ) )
			hPubkey = CRYPT_ERROR;
		}
	if( hPrivkey == CRYPT_ERROR && hPubkey == CRYPT_ERROR )
		return( CRYPT_ERROR_NOTFOUND );

	/* Delete the objects */
	status = CKR_OK;
	if( hCertificate != CRYPT_ERROR )
		status = C_DestroyObject( deviceInfo->deviceHandle, hCertificate );
	if( hPubkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( deviceInfo->deviceHandle, hPubkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( hPrivkey != CRYPT_ERROR )
		{
		int status2;

		status2 = C_DestroyObject( deviceInfo->deviceHandle, hPrivkey );
		if( status2 != CKR_OK && status == CKR_OK )
			status = status2;
		}
	if( status != CKR_OK )
		status = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	return( status );
	}

/* Get the sequence of certs in a chain from a device */

static int getNextCertFunction( DEVICE_INFO *deviceInfo, 
								CRYPT_CERTIFICATE *iCertificate,
								int *stateInfo, 
								const CRYPT_KEYID_TYPE keyIDtype,
								const void *keyID, const int keyIDlength,
								const CERTIMPORT_TYPE options )
	{
	/* Currently unused */
	return( CRYPT_ERROR_NOTFOUND );
	}

/****************************************************************************
*																			*
*						 	Capability Interface Routines					*
*																			*
****************************************************************************/

/* Sign data, check a signature.  We use Sign and Verify rather than the
   xxxRecover variants because there's no need to use Recover, and because
   many implementations don't do Recover */

static int genericSign( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						const CK_MECHANISM *pMechanism, 
						const void *inBuffer, const int inLength, 
						void *outBuffer, const int outLength )
	{
	CK_ULONG resultLen = outLength;
	CK_RV status;

	status = C_SignInit( deviceInfo->deviceHandle,
						 ( CK_MECHANISM_PTR ) pMechanism, 
						 cryptInfo->deviceObject );
	if( status == CKR_OK )
		status = C_Sign( deviceInfo->deviceHandle, ( CK_BYTE_PTR ) inBuffer, 
						 inLength, outBuffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

static int genericVerify( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						  const CK_MECHANISM *pMechanism, 
						  const void *inBuffer, const int inLength, 
						  void *outBuffer, const int outLength )
	{
	CK_RV status;

	status = C_VerifyInit( deviceInfo->deviceHandle,
						   ( CK_MECHANISM_PTR ) pMechanism,
						   cryptInfo->deviceObject );
	if( status == CKR_OK )
		status = C_Verify( deviceInfo->deviceHandle, ( CK_BYTE_PTR ) inBuffer, 
						   inLength, outBuffer, outLength );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	return( CRYPT_OK );
	}

/* Encrypt, decrypt */

static int genericEncrypt( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length )
	{
	CK_ULONG resultLen = length;
	CK_RV status;

	status = C_EncryptInit( deviceInfo->deviceHandle,
							( CK_MECHANISM_PTR ) pMechanism,
							cryptInfo->deviceObject );
	if( status == CKR_OK )
		status = C_Encrypt( deviceInfo->deviceHandle, buffer, length,
							buffer, &resultLen );
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	/* When performing raw RSA operations, some buggy implementations 
	   perform leading-zero trunction, so we restore leading zeroes if
	   necessary */
	if( pMechanism->mechanism == CKM_RSA_X_509 && \
		( int ) resultLen < length )
		{
		const int delta = length - resultLen;

		memmove( ( BYTE * ) buffer + delta, buffer, resultLen );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

static int genericDecrypt( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo,
						   const CK_MECHANISM *pMechanism, void *buffer,
						   const int length )
	{
	CK_ULONG resultLen = length;
	CK_RV status;

	status = C_DecryptInit( deviceInfo->deviceHandle,
							( CK_MECHANISM_PTR ) pMechanism,
							cryptInfo->deviceObject );
	if( status == CKR_OK )
		status = C_Decrypt( deviceInfo->deviceHandle, buffer, length,
							buffer, &resultLen );
	if( status == CKR_KEY_FUNCTION_NOT_PERMITTED )
		{
		static const CK_OBJECT_CLASS secretKeyClass = CKO_SECRET_KEY;
		static const CK_KEY_TYPE secretKeyType = CKK_GENERIC_SECRET;
		CK_ATTRIBUTE asymTemplate[] = { 
			{ CKA_CLASS, ( CK_VOID_PTR ) &secretKeyClass, sizeof( CK_OBJECT_CLASS ) },
			{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &secretKeyType, sizeof( CK_KEY_TYPE ) },
			{ CKA_VALUE_LEN, &resultLen, sizeof( CK_ULONG ) } 
			};
		CK_ATTRIBUTE symTemplate[] = { CKA_VALUE, buffer, length };
		CK_OBJECT_HANDLE symKey;

		/* If a straight decrypt isn't allowed, try an unwrap instead and 
		   then export the key.  This works because we're using the same
		   mechanism as for decrypt and converting the entire "unwrapped key"
		   into a generic secret key which we then extract, which is the
		   same as doing a straight decrypt of the data.  The reason why it's
		   done in this roundabout manner is that this is the version 
		   Netscape tries first, so people doing a minimal implementation do
		   this first and don't bother with anything else.  Note that doing
		   it this way is rather slower than a straight decrypt, which is why
		   we try for decrypt first */
		status = C_UnwrapKey( deviceInfo->deviceHandle,
							  ( CK_MECHANISM_PTR ) pMechanism,
							  cryptInfo->deviceObject, buffer, length,
							  asymTemplate, 3, &symKey );
		if( status == CKR_OK )
			status = C_GetAttributeValue( deviceInfo->deviceHandle, 
										  symKey, symTemplate, 1 );
		if( status == CKR_OK )
			resultLen = symTemplate[ 0 ].ulValueLen;
		}
	if( status != CKR_OK )
		return( mapError( deviceInfo, status, CRYPT_ERROR_FAILED ) );

	/* When performing raw RSA operations, some buggy implementations 
	   perform leading-zero trunction, so we restore leading zeroes if
	   necessary */
	if( pMechanism->mechanism == CKM_RSA_X_509 && \
		( int ) resultLen < length )
		{
		const int delta = length - resultLen;

		memmove( ( BYTE * ) buffer + delta, buffer, resultLen );
		memset( buffer, 0, delta );
		}

	return( CRYPT_OK );
	}

/* Clean up the object associated with a context */

static int genericEndFunction( CRYPT_INFO *cryptInfo )
	{
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
							RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );

	/* Destroy the object */
	C_DestroyObject( deviceInfo->deviceHandle, cryptInfo->deviceObject );
	unlockResourceExit( deviceInfo, CRYPT_OK );
	}

/* RSA algorithm-specific mapping functions.  We always use the X.509 (raw)
   mechanism for the encrypt/decrypt/sign/verify functions since cryptlib
   does its own padding, and it means we can support any new padding method
   regardless of what the underlying implementation supports */

static int rsaSetKeyInfo( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo, 
						  const CK_OBJECT_HANDLE hPrivateKey,
						  const CK_OBJECT_HANDLE hPublicKey,
						  const void *n, const int nLen,
						  const void *e, const int eLen )
	{
	RESOURCE_DATA msgData;
	BYTE keyDataBuffer[ CRYPT_MAX_PKCSIZE * 2 ], idBuffer[ KEYID_SIZE ];
	int keyDataSize, status;

	status = keyDataSize = sizeofFlatPublicKey( CRYPT_ALGO_RSA, n, nLen, 
												e, eLen, NULL, 0, NULL, 0 );
	if( !cryptStatusError( status ) )
		status = writeFlatPublicKey( keyDataBuffer, CRYPT_ALGO_RSA, 
									 n, nLen, e, eLen, NULL, 0, NULL, 0 );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( cryptInfo->objectHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Remember what we've set up */
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 ( void * ) &hPrivateKey, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 ( void * ) &nLen, CRYPT_IATTRIBUTE_KEYSIZE );

	/* Get the key ID from the context and use it as the object ID.  Since 
	   some objects won't allow after-the-even ID updates, we don't treat a
	   failure to update as an error */
	setResourceData( &msgData, idBuffer, KEYID_SIZE );
	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusOK( status ) )
		{
#ifndef NO_UPDATE
		CK_ATTRIBUTE idTemplate = { CKA_ID, msgData.data, msgData.length };

		if( hPublicKey != CRYPT_UNUSED )
			C_SetAttributeValue( deviceInfo->deviceHandle, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( deviceInfo->deviceHandle, hPrivateKey, 
							 &idTemplate, 1 );
#endif /* NO_UPDATE */
		}
	
	return( status );
	}

static int rsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	static const CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	static const CK_KEY_TYPE type = CKK_RSA;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE rsaKeyTemplate[] = {
		/* Shared fields */
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_MODULUS, NULL, 0 },
		{ CKA_PUBLIC_EXPONENT, NULL, 0 },
		/* Private-key only fields */
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE_EXPONENT, NULL, 0 },
		{ CKA_PRIME_1, NULL, 0 },
		{ CKA_PRIME_2, NULL, 0 },
		{ CKA_EXPONENT_1, NULL, 0 },
		{ CKA_EXPONENT_2, NULL, 0 },
		{ CKA_COEFFICIENT, NULL, 0 },
		};
	CRYPT_PKCINFO_RSA *rsaKey = ( CRYPT_PKCINFO_RSA * ) key;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	CK_OBJECT_HANDLE hRsaKey;
	CK_RV status;
	const int templateCount = rsaKey->isPublicKey ? 8 : 15;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
							RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Set up the key values */
	rsaKeyTemplate[ 6 ].pValue = rsaKey->n;
	rsaKeyTemplate[ 6 ].ulValueLen = bitsToBytes( rsaKey->nLen );
	rsaKeyTemplate[ 7 ].pValue = rsaKey->e;
	rsaKeyTemplate[ 7 ].ulValueLen = bitsToBytes( rsaKey->eLen );
	if( !rsaKey->isPublicKey )
		{
		rsaKeyTemplate[ 9 ].pValue = rsaKey->d;
		rsaKeyTemplate[ 9 ].ulValueLen = bitsToBytes( rsaKey->dLen );
		rsaKeyTemplate[ 10 ].pValue = rsaKey->p;
		rsaKeyTemplate[ 10 ].ulValueLen = bitsToBytes( rsaKey->pLen );
		rsaKeyTemplate[ 11 ].pValue = rsaKey->q;
		rsaKeyTemplate[ 11 ].ulValueLen = bitsToBytes( rsaKey->qLen );
		rsaKeyTemplate[ 12 ].pValue = rsaKey->e1;
		rsaKeyTemplate[ 12 ].ulValueLen = bitsToBytes( rsaKey->e1Len );
		rsaKeyTemplate[ 13 ].pValue = rsaKey->e2;
		rsaKeyTemplate[ 13 ].ulValueLen = bitsToBytes( rsaKey->e2Len );
		rsaKeyTemplate[ 14 ].pValue = rsaKey->u;
		rsaKeyTemplate[ 14 ].ulValueLen = bitsToBytes( rsaKey->uLen );
		}
	else
		{
		/* If it's a public key, we need to change the type and indication of 
		   the operations it's allowed to perform */
		rsaKeyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
		rsaKeyTemplate[ 3 ].type = CKA_VERIFY;
		rsaKeyTemplate[ 4 ].type = CKA_ENCRYPT;
		}

	/* Load the key into the token */
#ifndef NO_UPDATE
	status = C_CreateObject( deviceInfo->deviceHandle, rsaKeyTemplate, 
							 templateCount, &hRsaKey );
	zeroise( rsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
#else
	{
	CK_ATTRIBUTE blemTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize }
		};

	if( rsaKey->isPublicKey )
		blemTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
	status = findObject( deviceInfo, &hRsaKey, blemTemplate, 2 );
	}
#endif /* NO_UPDATE */
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		unlockResourceExit( deviceInfo, cryptStatus );

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = rsaSetKeyInfo( deviceInfo, cryptInfo, 
								 hRsaKey, CRYPT_UNUSED,
								 rsaKey->n, bitsToBytes( rsaKey->nLen ), 
								 rsaKey->e, bitsToBytes( rsaKey->eLen ) );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( deviceInfo->deviceHandle, hRsaKey );

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaGenerateKey( CRYPT_INFO *cryptInfo, const int keysizeBits )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0 };
	static const CK_BBOOL bTrue = TRUE;
	static const BYTE exponent[] = { 0x01, 0x00, 0x01 };
	const CK_ULONG modulusBits = keysizeBits;
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_ENCRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_VERIFY, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PUBLIC_EXPONENT, ( CK_VOID_PTR ) exponent, sizeof( exponent ) },
		{ CKA_MODULUS_BITS, NULL, sizeof( CK_ULONG ) }
		};
	CK_ATTRIBUTE keyValueTemplate = { CKA_MODULUS, NULL_PTR, CRYPT_MAX_PKCSIZE };
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE n[ CRYPT_MAX_PKCSIZE ];
	CK_RV status;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
							RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Patch in the key size and generate the keys */
#ifndef NO_UPDATE
	publicKeyTemplate[ 5 ].pValue = ( CK_VOID_PTR ) &modulusBits;
	status = C_GenerateKeyPair( deviceInfo->deviceHandle,
								( CK_MECHANISM_PTR ) &mechanism,
								publicKeyTemplate, 6, privateKeyTemplate, 6,
								&hPublicKey, &hPrivateKey );
#else
	{
	CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
	CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	CK_ATTRIBUTE blemTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize }
		};
	status = findObject( deviceInfo, &hPrivateKey, blemTemplate, 2 );
	blemTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
	if( status == CKR_OK )
		status = findObject( deviceInfo, &hPublicKey, blemTemplate, 2 );
	}
#endif /* NO_UPDATE */
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		unlockResourceExit( deviceInfo, cryptStatus );

	/* Send the keying info to the context and set up the key ID info.  The
	   odd two-phase modulus read is necessary for buggy implementations 
	   which fail if the given size isn't exactly the same as the data size */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hPublicKey, 
								  &keyValueTemplate, 1 );
	if( status == CKR_OK )
		{
		keyValueTemplate.pValue = n;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hPublicKey, 
									  &keyValueTemplate, 1 );
		}
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = rsaSetKeyInfo( deviceInfo, cryptInfo, 
									 hPrivateKey, hPublicKey,
									 n, keyValueTemplate.ulValueLen, 
									 exponent, sizeof( exponent ) );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( deviceInfo->deviceHandle, hPublicKey );
		C_DestroyObject( deviceInfo->deviceHandle, hPrivateKey );
		}

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaSign( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	const int keySize = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int cryptStatus;

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericSign( deviceInfo, cryptInfo, &mechanism, buffer, 
							   keySize, buffer, keySize );
	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaVerify( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE data[ CRYPT_MAX_PKCSIZE ];
	const int keySize = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int cryptStatus;

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericVerify( deviceInfo, cryptInfo, &mechanism, data,
								 keySize, buffer, keySize );
	if( length == CRYPT_USE_DEFAULT || !cryptStatusError( cryptStatus ) )
		cryptStatus = CRYPT_OK;  /* External calls don't return a length */
	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	const int keySize = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int cryptStatus;

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericEncrypt( deviceInfo, cryptInfo, &mechanism, buffer,
								  keySize );
	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int rsaDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_RSA_X_509, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	const int keySize = bitsToBytes( cryptInfo->ctxPKC.keySizeBits );
	int cryptStatus;

	assert( length == keySize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericDecrypt( deviceInfo, cryptInfo, &mechanism, buffer,
								  keySize );
	unlockResourceExit( deviceInfo, cryptStatus );
	}

/* DSA algorithm-specific mapping functions */

static int dsaSetKeyInfo( DEVICE_INFO *deviceInfo, CRYPT_INFO *cryptInfo, 
						  const CK_OBJECT_HANDLE hPrivateKey,
						  const CK_OBJECT_HANDLE hPublicKey,
						  const void *p, const int pLen,
						  const void *q, const int qLen,
						  const void *g, const int gLen,
						  const void *y, const int yLen )
	{
	RESOURCE_DATA msgData;
	BYTE keyDataBuffer[ CRYPT_MAX_PKCSIZE * 2 ], idBuffer[ KEYID_SIZE ];
	int keyDataSize, status;

	status = keyDataSize = sizeofFlatPublicKey( CRYPT_ALGO_DSA, p, pLen, 
												q, qLen, g, gLen, y, yLen );
	if( !cryptStatusError( status ) )
		status = writeFlatPublicKey( keyDataBuffer, CRYPT_ALGO_DSA, 
									 p, pLen, q, qLen, g, gLen, y, yLen );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, keyDataBuffer, keyDataSize );
		status = krnlSendMessage( cryptInfo->objectHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData,
								  CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Remember what we've set up */
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE,
					 ( void * ) &hPrivateKey, CRYPT_IATTRIBUTE_DEVICEOBJECT );
	krnlSendMessage( cryptInfo->objectHandle, RESOURCE_IMESSAGE_SETATTRIBUTE, 
					 ( void * ) &pLen, CRYPT_IATTRIBUTE_KEYSIZE );

	/* Get the key ID from the context and use it as the object ID.  Since 
	   some objects won't allow after-the-even ID updates, we don't treat a
	   failure to update as an error */
	setResourceData( &msgData, idBuffer, KEYID_SIZE );
	status = krnlSendMessage( cryptInfo->objectHandle, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
							  CRYPT_IATTRIBUTE_KEYID );
	if( cryptStatusOK( status ) )
		{
		CK_ATTRIBUTE idTemplate = { CKA_ID, msgData.data, msgData.length };

		if( hPublicKey != CRYPT_UNUSED )
			C_SetAttributeValue( deviceInfo->deviceHandle, hPublicKey, 
								 &idTemplate, 1 );
		C_SetAttributeValue( deviceInfo->deviceHandle, hPrivateKey, 
							 &idTemplate, 1 );
		}
	
	return( status );
	}

static int dsaInitKey( CRYPT_INFO *cryptInfo, const void *key, const int keyLength )
	{
	static const CK_OBJECT_CLASS privKeyClass = CKO_PRIVATE_KEY;
	static const CK_OBJECT_CLASS pubKeyClass = CKO_PUBLIC_KEY;
	static const CK_KEY_TYPE type = CKK_DSA;
	static const CK_BBOOL bTrue = TRUE;
	CK_ATTRIBUTE dsaKeyTemplate[] = {
		/* Shared fields */
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		{ CKA_VALUE, NULL, 0 },
		/* Private-key only fields */
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CRYPT_PKCINFO_DLP *dsaKey = ( CRYPT_PKCINFO_DLP * ) key;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	CK_OBJECT_HANDLE hDsaKey;
	CK_RV status;
	BYTE yValue[ CRYPT_MAX_PKCSIZE ];
	const int templateCount = dsaKey->isPublicKey ? 9 : 10;
	int yValueLength, cryptStatus;

	/* Creating a private-key object is somewhat problematic since the 
	   PKCS #11 interpretation of DSA reuses CKA_VALUE for x in the private
	   key and y in the public key, so it's not possible to determine y from
	   a private key because the x value is sensitive and can't be extracted.
	   Because of this we have to create a native private-key context which 
	   will generate the y value from x, read out the y value, and destroy
	   it again (see the comments in the DSA generate key section for more on
	   this problem).  Since this doesn't require the device, we do it before 
	   we grab the device */
	if( !dsaKey->isPublicKey )
		{
		CREATEOBJECT_INFO createInfo;
		RESOURCE_DATA msgData;
		STREAM stream;
		BYTE pubkeyBuffer[ CRYPT_MAX_PKCSIZE * 2 ], label[ 8 ];
		long length;

		/* Create a native private-key DSA context, which generates the y 
		   value internally */
		setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DSA );
		status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
								  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
								  &createInfo, OBJECT_TYPE_CONTEXT );
		if( cryptStatusError( status ) )
			return( status );
		getNonce( label, 8 );
		setResourceData( &msgData, label, 8 );
		krnlSendMessage( createInfo.cryptHandle, 
						 RESOURCE_IMESSAGE_SETATTRIBUTE_S, &msgData, 
						 CRYPT_CTXINFO_LABEL );
		setResourceData( &msgData, dsaKey, sizeof( CRYPT_PKCINFO_DLP ) );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_SETATTRIBUTE_S,
								  &msgData, CRYPT_CTXINFO_KEY_COMPONENTS );
		if( cryptStatusError( status ) )
			{
			krnlSendNotifier( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_DECREFCOUNT );
			return( status );
			}

		/* Get the public key data and extract the y value from it.  Note 
		   that the data used is represented in DER-canonical form, there may 
		   be PKCS #11 implementations which can't handle this (for example 
		   they may require y to be zero-padded to make it exactly 64 bytes 
		   rather than (say) 63 bytes if the high byte is zero), which will 
		   require the use of the readFixedValue() function used with the 
		   sign/verify code.  The real situation will probably be that half 
		   the implementations require padding and the other half don't */
		setResourceData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 2 );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
		krnlSendNotifier( createInfo.cryptHandle, 
						  RESOURCE_IMESSAGE_DECREFCOUNT );
		if( cryptStatusError( status ) )
			return( status );
		sMemConnect( &stream, msgData.data, msgData.length );
		readSequence( &stream, NULL );		/* SEQUENCE { */
		readUniversal( &stream );				/* AlgoID */
		readTag( &stream );						/* BIT STRING { */
		readLength( &stream, NULL );
		sgetc( &stream );	/* Skip extra bit count in bitfield */
		readTag( &stream );							/* INTEGER */
		readLength( &stream, &length );
		yValueLength = ( int ) length;
		memcpy( yValue, sMemBufPtr( &stream ), yValueLength );
		sMemClose( &stream );
		}

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
							RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Set up the key values */
	dsaKeyTemplate[ 5 ].pValue = dsaKey->p;
	dsaKeyTemplate[ 5 ].ulValueLen = bitsToBytes( dsaKey->pLen );
	dsaKeyTemplate[ 6 ].pValue = dsaKey->q;
	dsaKeyTemplate[ 6 ].ulValueLen = bitsToBytes( dsaKey->qLen );
	dsaKeyTemplate[ 7 ].pValue = dsaKey->g;
	dsaKeyTemplate[ 7 ].ulValueLen = bitsToBytes( dsaKey->gLen );
	if( !dsaKey->isPublicKey )
		{
		dsaKeyTemplate[ 8 ].pValue = dsaKey->x;
		dsaKeyTemplate[ 8 ].ulValueLen = bitsToBytes( dsaKey->xLen );
		}
	else
		{
		dsaKeyTemplate[ 8 ].pValue = dsaKey->y;
		dsaKeyTemplate[ 8 ].ulValueLen = bitsToBytes( dsaKey->yLen );

		/* If it's a public key, we need to change the type and indication of 
		   the operations it's allowed to perform */
		dsaKeyTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
		dsaKeyTemplate[ 3 ].type = CKA_VERIFY;
		}

	/* Load the key into the token */
#ifndef NO_UPDATE
	status = C_CreateObject( deviceInfo->deviceHandle, dsaKeyTemplate, 
							 templateCount, &hDsaKey );
	zeroise( dsaKeyTemplate, sizeof( CK_ATTRIBUTE ) * templateCount );
#else
	{
	CK_ATTRIBUTE blemTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &privKeyClass, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize }
		};
	if( dsaKey->isPublicKey )
		blemTemplate[ 0 ].pValue = ( CK_VOID_PTR ) &pubKeyClass;
	status = findObject( deviceInfo, &hDsaKey, blemTemplate, 2 );
	}
#endif /* NO_UPDATE */
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		unlockResourceExit( deviceInfo, cryptStatus );

	/* Send the keying info to the context and set up the key ID info */
	cryptStatus = dsaSetKeyInfo( deviceInfo, cryptInfo, 
								 hDsaKey, CRYPT_UNUSED,
								 dsaKey->p, bitsToBytes( dsaKey->pLen ), 
								 dsaKey->q, bitsToBytes( dsaKey->qLen ),
								 dsaKey->g, bitsToBytes( dsaKey->gLen ),
								 ( dsaKey->isPublicKey ) ? dsaKey->y : yValue,
								 ( dsaKey->isPublicKey ) ? \
									bitsToBytes( dsaKey->yLen ) : yValueLength );
	if( cryptStatusError( cryptStatus ) )
		C_DestroyObject( deviceInfo->deviceHandle, hDsaKey );

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int dsaGenerateKey( CRYPT_INFO *cryptInfo, const int keysizeBits )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA_KEY_PAIR_GEN, NULL_PTR, 0 };
	static const CK_BBOOL bTrue = TRUE;
	const CK_ULONG modulusBits = keysizeBits;
	CK_ATTRIBUTE privateKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_SIGN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		};
	CK_ATTRIBUTE publicKeyTemplate[] = {
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_LABEL, cryptInfo->label, cryptInfo->labelSize },
		{ CKA_VERIFY, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_PRIME, NULL, 0 },
		{ CKA_SUBPRIME, NULL, 0 },
		{ CKA_BASE, NULL, 0 },
		};
	CK_ATTRIBUTE yValueTemplate = { CKA_VALUE, NULL, CRYPT_MAX_PKCSIZE * 2 };
	CK_OBJECT_HANDLE hPublicKey, hPrivateKey;
	CREATEOBJECT_INFO createInfo;
	RESOURCE_DATA msgData;
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE pubkeyBuffer[ CRYPT_MAX_PKCSIZE * 2 ], label[ 8 ];
	CK_RV status;
	STREAM stream;
	long length;
	int keyLength = bitsToBytes( keysizeBits ), cryptStatus;

	/* CKM_DSA_KEY_PAIR_GEN is really a Clayton's key generation mechanism 
	   since it doesn't actually generate the p, q, or g values (presumably 
	   it dates back to the original FIPS 186 shared domain parameters idea).
	   Because of this we'd have to generate half the key ourselves in a 
	   native context, then copy portions from the native context over in 
	   flat form and complete the keygen via the device.  The easiest way to
	   do this is to create a native DSA context, generate a key, grab the
	   public portions, and destroy the context again (ie generate a full
	   key on a superscalar 500MHz RISC CPU, throw half of it away, and 
	   regenerate it on a 5MHz 8-bit tinkertoy).  Since the keygen can take 
	   awhile and doesn't require the device, we do it before we grab the 
	   device */
	setMessageCreateObjectInfo( &createInfo, CRYPT_ALGO_DSA );
	status = krnlSendMessage( SYSTEM_OBJECT_HANDLE, 
							  RESOURCE_IMESSAGE_DEV_CREATEOBJECT,
							  &createInfo, OBJECT_TYPE_CONTEXT );
	if( cryptStatusError( status ) )
		return( status );
	getNonce( label, 8 );
	setResourceData( &msgData, label, 8 );
	krnlSendMessage( createInfo.cryptHandle, RESOURCE_IMESSAGE_SETATTRIBUTE_S,
					 &msgData, CRYPT_CTXINFO_LABEL );
	status = krnlSendMessage( createInfo.cryptHandle, 
							  RESOURCE_IMESSAGE_CTX_GENKEY, 
							  ( int * ) &keyLength, FALSE );
	if( cryptStatusOK( status ) )
		{
		setResourceData( &msgData, pubkeyBuffer, CRYPT_MAX_PKCSIZE * 2 );
		status = krnlSendMessage( createInfo.cryptHandle, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	krnlSendNotifier( createInfo.cryptHandle, RESOURCE_IMESSAGE_DECREFCOUNT );
	if( cryptStatusError( status ) )
		return( status );

	/* Set up the public key info by extracting the flat values from the
	   SubjectPublicKeyInfo.  Note that the data used is represented in
	   DER-canonical form, there may be PKCS #11 implementations which
	   can't handle this (for example they may require q to be zero-padded
	   to make it exactly 20 bytes rather than (say) 19 bytes if the high
	   byte is zero), which will require the use of the readFixedValue()
	   function used with the sign/verify code.  The real situation will 
	   probably be that half the implementations require padding and the 
	   other half don't */
	sMemConnect( &stream, pubkeyBuffer, msgData.length );
	readSequence( &stream, NULL );				/* SEQUENCE */
	readSequence( &stream, NULL );					/* SEQUENCE */
	readUniversal( &stream );							/* OID */
	readSequence( &stream, NULL );						/* SEQUENCE */
	readTag( &stream );										/* p */
	readLength( &stream, &length );
	publicKeyTemplate[ 3 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 3 ].ulValueLen = length;
	sSkip( &stream, length );
	readTag( &stream );										/* q */
	readLength( &stream, &length );
	publicKeyTemplate[ 4 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 4 ].ulValueLen = length;
	sSkip( &stream, length );
	readTag( &stream );										/* g */
	readLength( &stream, &length );
	publicKeyTemplate[ 5 ].pValue = sMemBufPtr( &stream );
	publicKeyTemplate[ 5 ].ulValueLen = length;
	sMemDisconnect( &stream );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
							RESOURCE_IMESSAGE_GETDEPENDENT, &iCryptDevice, 
							OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Generate the keys */
	status = C_GenerateKeyPair( deviceInfo->deviceHandle,
								( CK_MECHANISM_PTR ) &mechanism,
								( CK_ATTRIBUTE_PTR ) publicKeyTemplate, 5,
								( CK_ATTRIBUTE_PTR ) privateKeyTemplate, 4,
								&hPublicKey, &hPrivateKey );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusError( cryptStatus ) )
		unlockResourceExit( deviceInfo, cryptStatus );

	/* Read back the generated y value, send the public key info to the 
	   context, and set up the key ID info.  The odd two-phase y value read 
	   is necessary for buggy implementations which fail if the given size 
	   isn't exactly the same as the data size */
	status = C_GetAttributeValue( deviceInfo->deviceHandle, hPublicKey,
								  &yValueTemplate, 1 );
	if( status == CKR_OK )
		{
		yValueTemplate.pValue = pubkeyBuffer;
		status = C_GetAttributeValue( deviceInfo->deviceHandle, hPublicKey, 
									  &yValueTemplate, 1 );
		}
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( cryptStatus ) )
		cryptStatus = dsaSetKeyInfo( deviceInfo, cryptInfo, 
			hPrivateKey, hPublicKey,
			publicKeyTemplate[ 3 ].pValue, publicKeyTemplate[ 3 ].ulValueLen, 
			publicKeyTemplate[ 4 ].pValue, publicKeyTemplate[ 4 ].ulValueLen, 
			publicKeyTemplate[ 5 ].pValue, publicKeyTemplate[ 5 ].ulValueLen,
			yValueTemplate.pValue, yValueTemplate.ulValueLen );
	if( cryptStatusError( cryptStatus ) )
		{
		C_DestroyObject( deviceInfo->deviceHandle, hPublicKey );
		C_DestroyObject( deviceInfo->deviceHandle, hPrivateKey );
		}

	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int dsaSign( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	STREAM stream;
	BYTE signature[ 40 ];
	int cryptStatus;

	assert( length == 20 );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericSign( deviceInfo, cryptInfo, &mechanism, buffer, 20,
							   signature, 40 );
	unlockResource( deviceInfo );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );

	/* Reformat the signature into the form expected by cryptlib */
	sMemConnect( &stream, buffer, STREAMSIZE_UNKNOWN );
	writeSequence( &stream, sizeofInteger( signature, 20 ) +
							sizeofInteger( signature + 20, 20 ) );
	writeInteger( &stream, signature, 20, DEFAULT_TAG );
	writeInteger( &stream, signature + 20, 20, DEFAULT_TAG );
	cryptStatus = stell( &stream );
	sMemDisconnect( &stream );

	return( cryptStatus );
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

static int dsaVerify( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	static const CK_MECHANISM mechanism = { CKM_DSA, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	STREAM stream;
	BYTE signature[ 40 ];
	int cryptStatus;

	assert( length > 20 + 40 );

	/* Decode the signature from the cryptlib format */
	sMemConnect( &stream, ( BYTE * ) buffer + 20, STREAMSIZE_UNKNOWN );
	cryptStatus = readSequence( &stream, NULL );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = readFixedValue( &stream, signature );
	if( !cryptStatusError( cryptStatus ) )
		cryptStatus = readFixedValue( &stream, signature + 20 );
	if( cryptStatusError( cryptStatus ) )
		return( CRYPT_ERROR_BADDATA );
	sMemDisconnect( &stream );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericVerify( deviceInfo, cryptInfo, &mechanism, buffer,
								 20, signature, 40 );
	unlockResourceExit( deviceInfo, cryptStatus );
	}

/* Conventional cipher-specific mapping functions */

static int cipherInitKey( CRYPT_INFO *cryptInfo, const void *key, 
						  const int keyLength )
	{
	static const CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	const CK_KEY_TYPE type = cryptInfo->capabilityInfo->paramKeyType;
	static const CK_BBOOL bFalse = FALSE, bTrue = TRUE;
	CK_ATTRIBUTE keyTemplate[] = {
		{ CKA_CLASS, ( CK_VOID_PTR ) &class, sizeof( CK_OBJECT_CLASS ) },
		{ CKA_KEY_TYPE, ( CK_VOID_PTR ) &type, sizeof( CK_KEY_TYPE ) },
		{ CKA_TOKEN, ( CK_VOID_PTR ) &bFalse, sizeof( CK_BBOOL ) },
		{ CKA_PRIVATE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_SENSITIVE, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_ENCRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_DECRYPT, ( CK_VOID_PTR ) &bTrue, sizeof( CK_BBOOL ) },
		{ CKA_VALUE, NULL_PTR, 0 }
		};
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	CK_OBJECT_HANDLE hObject;
	CK_RV status;
	int keySize = ( type == CKK_DES || type == CKK_DES3 || \
					type == CKK_IDEA || type == CKK_SKIPJACK ) ? \
					cryptInfo->capabilityInfo->keySize : keyLength;
	int cryptStatus;

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	assert( !( deviceInfo->flags & DEVICE_READONLY ) );

	/* Copy the key to internal storage */
	if( cryptInfo->ctxConv.userKey != key )
		memcpy( cryptInfo->ctxConv.userKey, key, keyLength );
	cryptInfo->ctxConv.userKeyLength = keyLength;

	/* Special-case handling for 2-key vs 3-key 3DES */
	if( cryptInfo->capabilityInfo->cryptAlgo == CRYPT_ALGO_3DES )
		{
		/* If the supplied key contanis only two DES keys, adjust the key to
		   make it the equivalent of 3-key 3DES.  In addition since the
		   nominal keysize is for 2-key 3DES, we have to make the actual size
		   the maximum size, corresponding to 3-key 3DES */
		if( keyLength <= bitsToBytes( 64 * 2 ) )
			memcpy( cryptInfo->ctxConv.userKey + bitsToBytes( 64 * 2 ),
					cryptInfo->ctxConv.userKey, bitsToBytes( 64 ) );
		keySize = cryptInfo->capabilityInfo->maxKeySize;
		}

	/* Set up the key values.  Since the key passed in by the user may be
	   smaller than the keysize required by algorithms which use fixed-size
	   keys, we use the (optionally) zero-padded key of the correct length 
	   held in the context rather than the variable-length user-supplied 
	   one */
	keyTemplate[ 7 ].pValue = cryptInfo->ctxConv.userKey;
	keyTemplate[ 7 ].ulValueLen = keySize;

	/* Load the key into the token */
	status = C_CreateObject( deviceInfo->deviceHandle,
							 ( CK_ATTRIBUTE_PTR ) keyTemplate, 8, &hObject );
	cryptStatus = mapError( deviceInfo, status, CRYPT_ERROR_FAILED );
	if( cryptStatusOK( status ) )
		cryptInfo->deviceObject = hObject;
	zeroise( keyTemplate, sizeof( CK_ATTRIBUTE ) * 8 );

	unlockResourceExit( deviceInfo, cryptStatus );
	}

/* Set up algorithm-specific encryption parameters */

static int initCryptParams( CRYPT_INFO *cryptInfo, void *paramData )
	{
	const int ivSize = cryptInfo->capabilityInfo->blockSize;

	if( cryptInfo->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC2 )
		{
		if( cryptInfo->ctxConv.mode == CRYPT_MODE_ECB )
			{
			CK_RC2_PARAMS_PTR rc2params = ( CK_RC2_PARAMS_PTR ) paramData;

			*rc2params = 128;
			return( sizeof( CK_RC2_PARAMS ) );
			}
		else
			{
			CK_RC2_CBC_PARAMS_PTR rc2params = ( CK_RC2_CBC_PARAMS_PTR ) paramData;

			rc2params->ulEffectiveBits = 128;
			memcpy( rc2params->iv, cryptInfo->ctxConv.currentIV, ivSize );
			return( sizeof( CK_RC2_CBC_PARAMS ) );
			}
		}
	if( cryptInfo->capabilityInfo->cryptAlgo == CRYPT_ALGO_RC5 )
		{
		if( cryptInfo->ctxConv.mode == CRYPT_MODE_ECB )
			{
			CK_RC5_PARAMS_PTR rc5params = ( CK_RC5_PARAMS_PTR ) paramData;

			rc5params->ulWordsize = 4;	/* Word size in bytes = blocksize/2 */
			rc5params->ulRounds = 12;
			return( sizeof( CK_RC5_PARAMS ) );
			}
		else
			{
			CK_RC5_CBC_PARAMS_PTR rc5params = ( CK_RC5_CBC_PARAMS_PTR ) paramData;

			rc5params->ulWordsize = 4;	/* Word size in bytes = blocksize/2 */
			rc5params->ulRounds = 12;
			rc5params->pIv = cryptInfo->ctxConv.currentIV;
			rc5params->ulIvLen = ivSize;
			return( sizeof( CK_RC5_CBC_PARAMS ) );
			}
		}
	return( 0 );
	}

static int cipherEncrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	CK_MECHANISM mechanism = { cryptInfo->capabilityInfo->paramMechanism, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE paramDataBuffer[ 64 ];
	const int ivSize = cryptInfo->capabilityInfo->blockSize;
	int paramSize, cryptStatus;

	/* If it's a courtesy end call, don't do anything */
	if( !length )
		return( CRYPT_OK );

	/* Set up algorithm and mode-specific parameters */
	paramSize = initCryptParams( cryptInfo, &paramDataBuffer );
	if( paramSize )
		{
		mechanism.pParameter = paramDataBuffer;
		mechanism.ulParameterLen = paramSize;
		}
	else
		/* Even if there are no algorithm-specific parameters, there may 
		   still be a mode-specific IV parameter */
		if( needsIV( cryptInfo->ctxConv.mode ) && \
			cryptInfo->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
			{
			mechanism.pParameter = cryptInfo->ctxConv.currentIV;
			mechanism.ulParameterLen = ivSize;
			}

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericEncrypt( deviceInfo, cryptInfo, &mechanism, buffer,
								  length );
	if( cryptStatusOK( cryptStatus ) )
		{
		if( needsIV( cryptInfo->ctxConv.mode ) && \
			cryptInfo->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
			/* Since PKCS #11 assumes that either all data is encrypted at 
			   once or that a given mechanism is devoted entirely to a single 
			   operation, we have to preserve the state (the IV) across 
			   calls */
			memcpy( cryptInfo->ctxConv.currentIV, \
					( BYTE * ) buffer + length - ivSize, ivSize );
		}
	unlockResourceExit( deviceInfo, cryptStatus );
	}

static int cipherDecrypt( CRYPT_INFO *cryptInfo, void *buffer, int length )
	{
	CK_MECHANISM mechanism = { cryptInfo->capabilityInfo->paramMechanism, NULL_PTR, 0 };
	CRYPT_DEVICE iCryptDevice;
	DEVICE_INFO *deviceInfo;
	BYTE paramDataBuffer[ 64 ], ivBuffer[ CRYPT_MAX_IVSIZE ];
	const int ivSize = cryptInfo->capabilityInfo->blockSize;
	int paramSize, cryptStatus;

	/* If it's a courtesy end call, don't do anything */
	if( !length )
		return( CRYPT_OK );

	/* Set up algorithm and mode-specific parameters */
	paramSize = initCryptParams( cryptInfo, &paramDataBuffer );
	if( paramSize )
		{
		mechanism.pParameter = paramDataBuffer;
		mechanism.ulParameterLen = paramSize;
		}
	else
		/* Even if there are no algorithm-specific parameters, there may 
		   still be a mode-specific IV parameter.  In addition we have to
		   save the end of the ciphertext as the IV for the next block if
		   this is required */
		if( needsIV( cryptInfo->ctxConv.mode ) && \
			cryptInfo->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
			{
			mechanism.pParameter = cryptInfo->ctxConv.currentIV;
			mechanism.ulParameterLen = ivSize;
			}
	if( needsIV( cryptInfo->ctxConv.mode ) && \
		cryptInfo->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
		memcpy( ivBuffer, ( BYTE * ) buffer + length - ivSize, ivSize );

	/* Get the info for the device associated with this context */
	cryptStatus = krnlSendMessage( cryptInfo->objectHandle, 
								   RESOURCE_IMESSAGE_GETDEPENDENT, 
								   &iCryptDevice, OBJECT_TYPE_DEVICE );
	if( cryptStatusError( cryptStatus ) )
		return( cryptStatus );
	getCheckInternalResource( iCryptDevice, deviceInfo, OBJECT_TYPE_DEVICE );
	cryptStatus = genericDecrypt( deviceInfo, cryptInfo, &mechanism, buffer,
								  length );
	if( !cryptStatusError( cryptStatus ) )
		{
		if( needsIV( cryptInfo->ctxConv.mode ) && \
			cryptInfo->capabilityInfo->cryptAlgo != CRYPT_ALGO_RC4 )
			/* Since PKCS #11 assumes that either all data is encrypted at 
			   once or that a given mechanism is devoted entirely to a single 
			   operation, we have to preserve the state (the IV) across 
			   calls */
			memcpy( cryptInfo->ctxConv.currentIV, ivBuffer, ivSize );
		}
	unlockResourceExit( deviceInfo, cryptStatus );
	}

/****************************************************************************
*																			*
*						 	Device Capability Routines						*
*																			*
****************************************************************************/

/* The reported key size for PKCS #11 implementations is rather inconsistent,
   most are reported in bits, a number don't return a useful value, and a few
   are reported in bytes.  The following macros sort out which algorithms
   have valid key size info and which report the length in bytes */

#define keysizeValid( algo ) \
	( ( algo ) == CRYPT_ALGO_RSA || ( algo ) == CRYPT_ALGO_DSA || \
	  ( algo ) == CRYPT_ALGO_RC2 || ( algo ) == CRYPT_ALGO_RC4 || \
	  ( algo ) == CRYPT_ALGO_RC5 || ( algo ) == CRYPT_ALGO_CAST )
#define keysizeBytes( algo ) \
	( ( algo ) == CRYPT_ALGO_RC5 || ( algo ) == CRYPT_ALGO_CAST )

/* Since cryptlib's CAPABILITY_INFO is fixed, all the fields are declared
   const so they'll probably be allocated in the code segment.  This doesn't
   quite work for PKCS #11 devices since things like the available key
   lengths can vary depending on the device which is plugged in, so we
   declare an equivalent structure here which makes the variable fields non-
   const.  Once the fields are set up, the result is copied into a
   dynamically-allocated CAPABILITY_INFO block at which point the fields are
   treated as const by the code */

typedef struct {
	const CRYPT_ALGO cryptAlgo;
	const int blockSize;
	const char *algoName;
	int minKeySize;						/* Non-const */
	int keySize;						/* Non-const */
	int maxKeySize;						/* Non-const */
	int ( *selfTestFunction )( void );
	int ( *initFunction )( struct CI *cryptInfoPtr, const void *cryptInfoEx );
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
	int param1, param2, param3, param4;	/* Non-const */
	struct CA *next;
	} VARIABLE_CAPABILITY_INFO;

/* Templates for the various capabilities.  These only contain the basic
   information, the remaining fields are filled in when the capability is set
   up */

#define bits(x)	bitsToBytes(x)

static CAPABILITY_INFO FAR_BSS capabilityTemplates[] = {
	/* Encryption capabilities */
	{ CRYPT_ALGO_DES, bits( 64 ), "DES",
		bits( 40 ), bits( 64 ), bits( 64 ) },
	{ CRYPT_ALGO_3DES, bits( 64 ), "3DES",
		bits( 64 + 8 ), bits( 128 ), bits( 192 ) },
	{ CRYPT_ALGO_IDEA, bits( 64 ), "IDEA",
		bits( 40 ), bits( 128 ), bits( 128 ) },
	{ CRYPT_ALGO_CAST, bits( 64 ), "CAST-128",
		bits( 40 ), bits( 128 ), bits( 128 ) },
	{ CRYPT_ALGO_RC2, bits( 64 ), "RC2",
		bits( 40 ), bits( 128 ), bits( 1024 ) },
	{ CRYPT_ALGO_RC4, bits( 8 ), "RC4",
		bits( 40 ), bits( 128 ), 256 },
	{ CRYPT_ALGO_RC5, bits( 64 ), "RC5",
		bits( 40 ), bits( 128 ), bits( 832 ) },
	{ CRYPT_ALGO_SKIPJACK, bits( 64 ), "Skipjack",
		bits( 80 ), bits( 80 ), bits( 80 ) },

	/* Hash capabilities */
	{ CRYPT_ALGO_MD2, bits( 128 ), "MD2",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_MD5, bits( 128 ), "MD5",
		bits( 0 ), bits( 0 ), bits( 0 ) },
	{ CRYPT_ALGO_SHA, bits( 160 ), "SHA",
		bits( 0 ), bits( 0 ), bits( 0 ) },

	/* Public-key capabilities */
	{ CRYPT_ALGO_RSA, bits( 0 ), "RSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },
	{ CRYPT_ALGO_DSA, bits( 0 ), "DSA",
		bits( 512 ), bits( 1024 ), CRYPT_MAX_PKCSIZE },
	};

/* Mapping of PKCS #11 device capabilities to cryptlib capabilities */

typedef struct {
	/* Mapping information.  Most PKC mechanisms have supplementary 
	   mechanisms used solely for key generation which doesn't make much 
	   sense, however it does mean that when checking the main mechanism for
	   keygen capabilities via the CKF_GENERATE_KEY_PAIR flag we have to make
	   a second check for the alternate mechanism since there's no consensus
	   over whether the presence of a keygen mechanism with a different ID
	   means the keygen flag should be set for the main mechanism */
	CK_MECHANISM_TYPE mechanism;	/* PKCS #11 mechanism type */
	CK_MECHANISM_TYPE keygenMechanism;	/* Supplementary keygen mechanism */
	CRYPT_ALGO cryptAlgo;			/* cryptlib algo and mode */
	CRYPT_MODE cryptMode;

	/* Equivalent PKCS #11 parameters */
	CK_KEY_TYPE keyType;			/* PKCS #11 key type */

	/* Function pointers */
	int ( *endFunction )( CRYPT_INFO *cryptInfoPtr );
	int ( *initKeyFunction )( CRYPT_INFO *cryptInfoPtr, const void *key, const int keyLength );
	int ( *generateKeyFunction )( CRYPT_INFO *cryptInfoPtr, const int keySizeBits );
	int ( *encryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *decryptFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *signFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	int ( *sigCheckFunction )( CRYPT_INFO *cryptInfoPtr, void *buffer, int length );
	} MECHANISM_INFO;

static const MECHANISM_INFO mechanismInfo[] = {
	{ CKM_RSA_PKCS, CKM_RSA_PKCS_KEY_PAIR_GEN, CRYPT_ALGO_RSA, CRYPT_MODE_NONE, CKK_RSA,
	  NULL, rsaInitKey, rsaGenerateKey, 
	  rsaEncrypt, rsaDecrypt, rsaSign, rsaVerify },
	{ CKM_DSA, CKM_DSA_KEY_PAIR_GEN, CRYPT_ALGO_DSA, CRYPT_MODE_NONE, CKK_DSA,
	  NULL, dsaInitKey, dsaGenerateKey, 
	  NULL, NULL, dsaSign, dsaVerify },
	{ CKM_DES_ECB, CRYPT_ERROR, CRYPT_ALGO_DES, CRYPT_MODE_ECB, CKK_DES,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_DES_CBC, CRYPT_ERROR, CRYPT_ALGO_DES, CRYPT_MODE_CBC, CKK_DES,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_DES3_ECB, CRYPT_ERROR, CRYPT_ALGO_3DES, CRYPT_MODE_ECB, CKK_DES3,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_DES3_CBC, CRYPT_ERROR, CRYPT_ALGO_3DES, CRYPT_MODE_CBC, CKK_DES3,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_IDEA_ECB, CRYPT_ERROR, CRYPT_ALGO_IDEA, CRYPT_MODE_ECB, CKK_IDEA,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_IDEA_CBC, CRYPT_ERROR, CRYPT_ALGO_IDEA, CRYPT_MODE_CBC, CKK_IDEA,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_CAST5_ECB, CRYPT_ERROR, CRYPT_ALGO_CAST, CRYPT_MODE_ECB, CKK_CAST5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_CAST5_CBC, CRYPT_ERROR, CRYPT_ALGO_CAST, CRYPT_MODE_CBC, CKK_CAST5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_RC2_ECB, CRYPT_ERROR, CRYPT_ALGO_RC2, CRYPT_MODE_ECB, CKK_RC2,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_RC2_CBC, CRYPT_ERROR, CRYPT_ALGO_RC2, CRYPT_MODE_CBC, CKK_RC2,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_RC4, CRYPT_ERROR, CRYPT_ALGO_RC4, CRYPT_MODE_OFB, CKK_RC4,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_RC5_ECB, CRYPT_ERROR, CRYPT_ALGO_RC5, CRYPT_MODE_ECB, CKK_RC5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_RC5_CBC, CRYPT_ERROR, CRYPT_ALGO_RC5, CRYPT_MODE_CBC, CKK_RC5,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_SKIPJACK_ECB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_ECB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_SKIPJACK_CBC64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CBC, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_SKIPJACK_CFB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_CFB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CKM_SKIPJACK_OFB64, CRYPT_ERROR, CRYPT_ALGO_SKIPJACK, CRYPT_MODE_OFB, CKK_SKIPJACK,
	  genericEndFunction, cipherInitKey, NULL, 
	  cipherEncrypt, cipherDecrypt, NULL, NULL },
	{ CRYPT_ERROR, CRYPT_ERROR, CRYPT_ALGO_NONE, CRYPT_MODE_NONE }
	};

/* Query a given capability for a device and fill out a capability info
   record for it if present */

static CAPABILITY_INFO *getCapability( const DEVICE_INFO *deviceInfo,
									   const MECHANISM_INFO *mechanismInfoPtr )
	{
	int loadIV( CRYPT_INFO *cryptInfoPtr, const void *iv, const int ivLength );
	VARIABLE_CAPABILITY_INFO *capabilityInfo;
	CK_MECHANISM_INFO mechanismInfo;
	CK_RV status;
	const CRYPT_ALGO cryptAlgo = mechanismInfoPtr->cryptAlgo;
	int hardwareOnly, i;

	/* Get the information for this mechanism.  Since many PKCS #11 drivers
	   implement some capabilities using God knows what sort of software
	   implementation, we provide the option to skip emulated mechanisms if
	   required */
	status = C_GetMechanismInfo( deviceInfo->slotHandle, 
								 mechanismInfoPtr->mechanism,
								 &mechanismInfo );
	if( status != CKR_OK )
		return( NULL );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &hardwareOnly, CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY );
	if( hardwareOnly && !( mechanismInfo.flags & CKF_HW ) )
		return( NULL );

	/* Copy across the template for this capability */
	if( ( capabilityInfo = malloc( sizeof( CAPABILITY_INFO ) ) ) == NULL )
		return( NULL );
	for( i = 0; \
		 capabilityTemplates[ i ].cryptAlgo != mechanismInfoPtr->cryptAlgo; \
		 i++ );
	assert( i < sizeof( capabilityTemplates ) / sizeof( CAPABILITY_INFO ) );
	memcpy( capabilityInfo, &capabilityTemplates[ i ],
			sizeof( CAPABILITY_INFO ) );

	/* Set up the keysize information if there's anything useful available */
	if( keysizeValid( mechanismInfoPtr->cryptAlgo ) )
		{
		int minKeySize = ( int ) mechanismInfo.ulMinKeySize;
		int maxKeySize = ( int ) mechanismInfo.ulMaxKeySize;

		/* Adjust the key size to bytes and make sure all values are 
		   consistent.  Some implementations report silly lower bounds (eg 
		   1-bit RSA, "You naughty minKey") so we adjust them to a sane value 
		   if necessary */
		if( !keysizeBytes( mechanismInfoPtr->cryptAlgo ) )
			{
			minKeySize = bitsToBytes( minKeySize );
			maxKeySize = bitsToBytes( maxKeySize );
			}
		if( minKeySize > capabilityInfo->minKeySize )
			capabilityInfo->minKeySize = minKeySize;
		if( capabilityInfo->keySize < capabilityInfo->minKeySize )
			capabilityInfo->keySize = capabilityInfo->minKeySize;
		capabilityInfo->maxKeySize = maxKeySize;
		if( capabilityInfo->keySize > capabilityInfo->maxKeySize )
			capabilityInfo->keySize = capabilityInfo->maxKeySize;
		capabilityInfo->endFunction = genericEndFunction;
		}

	/* Copy the cryptlib-equivalent PKCS #11 parameters across */
	capabilityInfo->paramMechanism = mechanismInfoPtr->mechanism;
	capabilityInfo->paramKeyType = mechanismInfoPtr->keyType;

	/* Set up the device-specific handlers */
	if( mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_RSA && \
		mechanismInfoPtr->cryptAlgo != CRYPT_ALGO_DSA )
		capabilityInfo->initIVFunction = loadIV;
	capabilityInfo->endFunction = mechanismInfoPtr->endFunction;
	capabilityInfo->initKeyFunction = mechanismInfoPtr->initKeyFunction;
	if( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR )
		capabilityInfo->generateKeyFunction = mechanismInfoPtr->generateKeyFunction;
	if( mechanismInfo.flags & CKF_SIGN )
		capabilityInfo->signFunction = mechanismInfoPtr->signFunction;
	if( mechanismInfo.flags & CKF_VERIFY )
		capabilityInfo->sigCheckFunction = mechanismInfoPtr->sigCheckFunction;
	if( mechanismInfo.flags & CKF_ENCRYPT )
		capabilityInfo->encryptFunction = mechanismInfoPtr->encryptFunction;
	if( mechanismInfo.flags & CKF_DECRYPT )
		capabilityInfo->decryptFunction = mechanismInfoPtr->decryptFunction;

	/* PKC keygen capabilities are generally present as separate mechanisms,
	   sometimes CKF_GENERATE_KEY_PAIR is set for the main mechanism and
	   sometimes it's set for the separate one so if it isn't present in the
	   main one we check the alternative one */
	if( !( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR ) && \
		( mechanismInfoPtr->keygenMechanism != CRYPT_ERROR ) )
		{
		status = C_GetMechanismInfo( deviceInfo->slotHandle, 
									 mechanismInfoPtr->keygenMechanism,
									 &mechanismInfo );
		if( status == CKR_OK && \
			( mechanismInfo.flags & CKF_GENERATE_KEY_PAIR ) )
			capabilityInfo->generateKeyFunction = \
									mechanismInfoPtr->generateKeyFunction;
		}

	/* If it's not a conventional encryption algo, we're done */
	if( mechanismInfoPtr->cryptAlgo < CRYPT_ALGO_FIRST_CONVENTIONAL || \
		mechanismInfoPtr->cryptAlgo > CRYPT_ALGO_LAST_CONVENTIONAL )
		return( ( CAPABILITY_INFO * ) capabilityInfo );

	/* PKCS #11 handles encryption modes by defining a separate mechanism for
	   each one, in order to enumerate all the modes available for a 
	   particular algorithm we check for each mechanism in turn and set up 
	   the appropriate function pointers if it's available */
	for( mechanismInfoPtr++; mechanismInfoPtr->cryptAlgo == cryptAlgo; 
		 mechanismInfoPtr++ )
		{
		/* There's a different form of the existing mechanism available,
		   check whether the driver implements it */
		status = C_GetMechanismInfo( deviceInfo->slotHandle, 
									 mechanismInfoPtr->mechanism,
									 &mechanismInfo );
		if( status != CKR_OK )
			continue;

		/* Set up the pointer for the appropriate encryption mode */
		switch( mechanismInfoPtr->cryptMode )
			{
			case CRYPT_MODE_CBC:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptCBCFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptCBCFunction = \
										mechanismInfoPtr->decryptFunction;
				break;
			case CRYPT_MODE_CFB:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptCFBFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptCFBFunction = \
										mechanismInfoPtr->decryptFunction;
				break;
			case CRYPT_MODE_OFB:
				if( mechanismInfo.flags & CKF_ENCRYPT )
					capabilityInfo->encryptOFBFunction = \
										mechanismInfoPtr->encryptFunction;
				if( mechanismInfo.flags & CKF_DECRYPT )
					capabilityInfo->decryptOFBFunction = \
										mechanismInfoPtr->decryptFunction;
				break;

			default:
				assert( NOTREACHED );
			}
		}

	return( ( CAPABILITY_INFO * ) capabilityInfo );
	}

/* Set the capability information based on device capabilities.  Since
   PKCS #11 devices can have assorted capabilities (and can vary depending
   on what's plugged in), we have to build this up on the fly rather than
   using a fixed table like the built-in capabilities */

static void freeCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityInfoPtr = \
				( CAPABILITY_INFO * ) deviceInfo->capabilityInfo;

	/* If the list was empty, return now */
	if( capabilityInfoPtr == NULL )
		return;
	deviceInfo->capabilityInfo = NULL;

	while( capabilityInfoPtr != NULL )
		{
		CAPABILITY_INFO *itemToFree = capabilityInfoPtr;

		capabilityInfoPtr = capabilityInfoPtr->next;
		zeroise( itemToFree, sizeof( CAPABILITY_INFO ) );
		free( itemToFree );
		}
	}

static int getCapabilities( DEVICE_INFO *deviceInfo )
	{
	CAPABILITY_INFO *capabilityListTail = \
				( CAPABILITY_INFO * ) deviceInfo->capabilityInfo;
	int i;

	assert( sizeof( CAPABILITY_INFO ) == sizeof( VARIABLE_CAPABILITY_INFO ) );

	/* Add capability information for each recognised mechanism type */
	for( i = 0; mechanismInfo[ i ].mechanism != CRYPT_ERROR; i++ )
		{
		CAPABILITY_INFO *newCapability;
		const CRYPT_ALGO cryptAlgo = mechanismInfo[ i ].cryptAlgo;

		newCapability = getCapability( deviceInfo, &mechanismInfo[ i ] );
		if( newCapability == NULL )
			continue;
		assert( capabilityInfoOK( newCapability ) );
		if( deviceInfo->capabilityInfo == NULL )
			deviceInfo->capabilityInfo = newCapability;
		else
			capabilityListTail->next = newCapability;
		capabilityListTail = newCapability;

		/* Since there may be alternative mechanisms to the current one 
		   defined, we have to skip mechanisms until we find a ones for a
		   new algorithm */
		while( mechanismInfo[ i + 1 ].cryptAlgo == cryptAlgo )
			i++;
		}

	return( ( deviceInfo->capabilityInfo == NULL ) ? CRYPT_ERROR : CRYPT_OK );
	}

/****************************************************************************
*																			*
*						 	Device Access Routines							*
*																			*
****************************************************************************/

/* Set up the function pointers to the device methods */

int setDevicePKCS11( DEVICE_INFO *deviceInfo, const char *name, 
					 const int nameLength )
	{
#ifdef DYNAMIC_LOAD
	int i, driveNameLength = nameLength;
#else
	UNUSED( name );
#endif /* DYNAMIC_LOAD */

	/* Make sure the PKCS #11 driver DLL's are loaded */
	if( !pkcs11Initialised )
		return( CRYPT_ERROR_OPEN );

#ifdef DYNAMIC_LOAD
	/* Check whether there's a token name appended to the driver name */
	for( i = 1; i < nameLength - 1; i++ )
		if( name[ i ] == ':' && name[ i + 1 ] == ':' )
			{
			driveNameLength = i;
			break;
			}

	/* Try and find the driver based on its name */
	for( i = 0; i < MAX_PKCS11_DRIVERS; i++ )
		if( !strnicmp( pkcs11InfoTbl[ i ].name, name, driveNameLength ) )
			break;
	if( i == MAX_PKCS11_DRIVERS )
		return( CRYPT_ARGERROR_STR1 );
	deviceInfo->deviceNo = i;
#endif /* DYNAMIC_LOAD */

	deviceInfo->initDeviceFunction = initDeviceFunction;
	deviceInfo->shutdownDeviceFunction = shutdownDeviceFunction;
	deviceInfo->controlFunction = controlFunction;
	deviceInfo->getItemFunction = getItemFunction;
	deviceInfo->setItemFunction = setItemFunction;
	deviceInfo->deleteItemFunction = deleteItemFunction;
	deviceInfo->getNextCertFunction = getNextCertFunction;
	deviceInfo->getRandomFunction = getRandomFunction;

	return( CRYPT_OK );
	}
#endif /* DEV_PKCS11 */
