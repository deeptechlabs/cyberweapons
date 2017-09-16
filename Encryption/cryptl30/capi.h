#ifndef _CAPI_DEFINED

#define _CAPI_DEFINED

/* This file exists solely to provide a mapping from the cryptlib 2.x 
   functions to the newer cryptlib 3.0 functions.  If you're writing new code
   you should use the interface in cryptlib.h rather than the 2.x interface.

   There are a few functions which don't translate transparently:

	cryptRetrieveIV() takes a length parameter, the original used an implicit
		IV length (this is a low-level function which is rarely called from 
		user code so the impact should be minimal).

	cryptDeriveKeyEx() has been replaced by a new PKCS #5v2-compatible version
		which uses the CRYPT_CTXINFO_KEYING_ALGO, 
		CRYPT_CTXINFO_KEYING_ITERATIONS, and CRYPT_CTXINFO_KEYING_SALT 
		attributes for the extra parameters.
		
	cryptGetErrorInfo(), used to read low-level error return values from 
		keysets and devices, has been replaced by the attributes 
		CRYPT_ATTRIBUTE_INT_ERRORCODE and CRYPT_ATTRIBUTE_INT_ERRORMESSAGE.
		The second use of cryptGetErrorInfo(), to read the type and locus of
		certificate errors, is still available.

	cryptCreateEnvelope() now takes a second parameter specifying the 
		envelope data format.  It isn't possible to fix this using 
		preprocessor tricks since both the source and destination have the
		same name */

#include "cryptlib.h"

/****************************************************************************
*																			*
*							cryptlib Legacy Functions						*
*																			*
****************************************************************************/

/* Encryption modes */

#define CRYPT_MODE_STREAM					0
#define CRYPT_MODE_PKC						0
#define CRYPT_MODE_FIRST_CONVENTIONAL		( CRYPT_MODE_NONE + 1 )
#define CRYPT_MODE_LAST_CONVENTIONAL		( CRYPT_MODE_LAST - 1 )

/* Data types */

#define CRYPT_CERTINFO_TYPE					CRYPT_ATTRIBUTE_TYPE
#define CRYPT_ENVINFO_TYPE					CRYPT_ATTRIBUTE_TYPE
#define CRYPT_OPTION_TYPE					CRYPT_ATTRIBUTE_TYPE
#define CRYPT_SESSINFO_TYPE					CRYPT_ATTRIBUTE_TYPE
#define CRYPT_DEVICECONTROL_TYPE			CRYPT_ATTRIBUTE_TYPE

/* Data values */

#define CRYPT_CERTINFO_NONE					CRYPT_ATTRIBUTE_NONE
#define CRYPT_ENVINFO_NONE					CRYPT_ATTRIBUTE_NONE
#define CRYPT_OPTION_NONE					CRYPT_ATTRIBUTE_NONE

/* Error types */

#define CRYPT_ERROR_TYPE					int
#define CRYPT_ERROR_NONE					CRYPT_OK

#define CRYPT_PKCCRYPT						CRYPT_FAILED

#define CRYPT_CERTERROR_NONE				CRYPT_ERROR_NONE
#define CRYPT_CERTERROR_SIZE				CRYPT_ERROR_SIZE
#define CRYPT_CERTERROR_VALUE				CRYPT_ERROR_VALUE
#define CRYPT_CERTERROR_CONSTRAINT			CRYPT_ERROR_CONSTRAINT
#define CRYPT_CERTERROR_ISSUERCONSTRAINT	CRYPT_ERROR_ISSUERCONSTRAINT
#define CRYPT_CERTERROR_ABSENT				CRYPT_ERROR_ABSENT
#define CRYPT_CERTERROR_PRESENT				CRYPT_ERROR_PRESENT
#define CRYPT_CERTERROR_LAST				CRYPT_ERROR_LAST
#define CRYPT_CERTERROR_TYPE				CRYPT_ERROR_TYPE

/* Superseded error codes */

#define CRYPT_ERROR							-1	/* No longer used */
#define CRYPT_SELFTEST						-1	/* Handled by disabling cap.*/
#define CRYPT_ORPHAN						CRYPT_ERROR_INCOMPLETE
#define CRYPT_NOALGO						CRYPT_ERROR_NOTAVAIL
#define CRYPT_NOMODE						CRYPT_ERROR_NOTAVAIL

/* Error codes */

#define CRYPT_BADPARM1						CRYPT_ERROR_PARAM1
#define CRYPT_BADPARM2						CRYPT_ERROR_PARAM2
#define CRYPT_BADPARM3						CRYPT_ERROR_PARAM3
#define CRYPT_BADPARM4						CRYPT_ERROR_PARAM4
#define CRYPT_BADPARM5						CRYPT_ERROR_PARAM5
#define CRYPT_BADPARM6						CRYPT_ERROR_PARAM6
#define CRYPT_BADPARM7						CRYPT_ERROR_PARAM7

#define CRYPT_NOMEM							CRYPT_ERROR_NOMEM
#define CRYPT_NOTINITED						CRYPT_ERROR_NOTINITED
#define CRYPT_INITED						CRYPT_ERROR_INITED
#define CRYPT_NOSECURE						CRYPT_ERROR_NOSECURE
#define CRYPT_NOKEY							CRYPT_ERROR_NOKEY
#define CRYPT_NORANDOM						CRYPT_ERROR_NORANDOM
#define CRYPT_FAILED						CRYPT_ERROR_FAILED

#define CRYPT_NOTAVAIL						CRYPT_ERROR_NOTAVAIL
#define CRYPT_NOPERM						CRYPT_ERROR_PERMISSION
#define CRYPT_WRONGKEY						CRYPT_ERROR_WRONGKEY
#define CRYPT_INCOMPLETE					CRYPT_ERROR_INCOMPLETE
#define CRYPT_COMPLETE						CRYPT_ERROR_COMPLETE
#define CRYPT_BUSY							CRYPT_ERROR_BUSY
#define CRYPT_SIGNALLED						CRYPT_ERROR_SIGNALLED

#define CRYPT_OVERFLOW						CRYPT_ERROR_OVERFLOW
#define CRYPT_UNDERFLOW						CRYPT_ERROR_UNDERFLOW
#define CRYPT_BADDATA						CRYPT_ERROR_BADDATA
#define CRYPT_BADSIG						CRYPT_ERROR_SIGNATURE
#define CRYPT_INVALID						CRYPT_ERROR_INVALID

#define CRYPT_DATA_OPEN						CRYPT_ERROR_OPEN
#define CRYPT_DATA_READ						CRYPT_ERROR_READ
#define CRYPT_DATA_WRITE					CRYPT_ERROR_WRITE
#define CRYPT_DATA_NOTFOUND					CRYPT_ERROR_NOTFOUND
#define CRYPT_DATA_DUPLICATE				CRYPT_ERROR_DUPLICATE

#if 0
#define CRYPT_ENVELOPE_RESOURCE				CRYPT_ERROR_ENVELOPE_RESOURCE
#endif

/* Renamed cert attributes */

#define CRYPT_CERTINFO_TRUSTED				CRYPT_CERTINFO_TRUSTEDUSAGE

/* Renamed cryptDeviceControl() option types */

#define CRYPT_DEVICECONTROL_INITIALISE		CRYPT_DEVINFO_INITIALISE
#define CRYPT_DEVICECONTROL_INITIALIZE		CRYPT_DEVINFO_INITIALISE,
#define CRYPT_DEVICECONTROL_AUTH_USER		CRYPT_DEVINFO_AUTHENT_USER
#define CRYPT_DEVICECONTROL_AUTH_SUPERVISOR	CRYPT_DEVINFO_AUTHENT_SUPERVISOR
#define CRYPT_DEVICECONTROL_SET_AUTH_USER	CRYPT_DEVINFO_SET_AUTHENT_USER
#define CRYPT_DEVICECONTROL_SET_AUTH_SUPERVISOR	CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR
#define CRYPT_DEVICECONTROL_ZEROISE			CRYPT_DEVINFO_ZEROISE
#define CRYPT_DEVICECONTROL_ZEROIZE			CRYPT_DEVINFO_ZEROISE

/* Init functions */

#define cryptInitEx		cryptInit

/* Configuration functions */

#define cryptSetOptionNumeric( cryptOption, value ) \
		cryptSetAttribute( CRYPT_UNUSED, cryptOption, value )
#define cryptSetOptionString( cryptOption, value ) \
		cryptSetAttributeString( CRYPT_UNUSED, cryptOption, value, strlen( value ) )
#define cryptGetOptionNumeric( cryptOption, value ) \
		cryptGetAttribute( CRYPT_UNUSED, cryptOption, value )
#define cryptGetOptionString( cryptOption, value, valueLength ) \
		cryptGetAttributeString( CRYPT_UNUSED, cryptOption, value, valueLength )
#define cryptReadOptions()

/* Object property functions */

#define cryptGetObjectProperty( cryptObject, property, value ) \
		cryptGetAttribute( cryptObject, property, value )
#define cryptSetObjectProperty( cryptObject, property, value ) \
		cryptSetAttribute( cryptObject, property, value )

/* Context functions.  The original cryptRetrieveIV() didn't take a length
   parameter, but we need to have this present in order to allow the call to
   be mapped to cryptGetAttributeString().  Hopefully most users won't be
   using this function anyway... */

#define cryptCreateContext( cryptContext, cryptAlgo, cryptMode ) \
		cryptCreateContext( cryptContext, cryptAlgo )
#define cryptCreateContextEx( cryptContext, cryptAlgo, cryptMode, cryptExInfo ) \
		cryptCreateContext( cryptContext, cryptAlgo, cryptMode )
#define cryptLoadKey( cryptContext, key, keyLength ) \
		cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEY, key, keyLength )
#define cryptLoadIV( cryptContext, iv, ivLength ) \
		cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_IV, iv, ivLength )
#define cryptRetrieveIV( cryptContext, iv, ivLength ) \
		cryptGetAttributeString( cryptContext, CRYPT_CTXINFO_IV, iv, ivLength )
#define cryptDeriveKey( cryptContext, userKey, userKeyLength ) \
		cryptSetAttributeString( cryptContext, CRYPT_CTXINFO_KEYING_VALUE, userKey, userKeyLength )

/* Certificate functions */

#define cryptGetCertComponentNumeric( cryptHandle, certInfoType, certInfo ) \
		cryptGetAttribute( cryptHandle, certInfoType, certInfo )
#define cryptGetCertComponentString( cryptHandle, certInfoType, certInfo, certInfoLength ) \
		cryptGetAttributeString( cryptHandle, certInfoType, certInfo, certInfoLength )
#define cryptAddCertComponentNumeric( cryptHandle, certInfoType, certInfo ) \
		cryptSetAttribute( cryptHandle, certInfoType, certInfo )
#define cryptAddCertComponentString( cryptHandle, certInfoType, certInfo, certInfoLength ) \
		cryptSetAttributeString( cryptHandle, certInfoType, certInfo, certInfoLength )
#define cryptDeleteCertComponent( cryptHandle, certInfoType ) \
		cryptDeleteAttribute( cryptHandle, certInfoType )

/* Keyset functions */

#define cryptKeysetQuery( keyset, query ) \
		cryptSetAttributeString( keyset, CRYPT_KEYSETINFO_QUERY, query, strlen( query ) )

/* Device functions */

#define cryptDeviceCreateContext( cryptDevice, cryptContext, cryptAlgo, cryptMode ) \
		cryptDeviceCreateContext( cryptDevice, cryptContext, cryptAlgo )
#define cryptDeviceControl( device, controlType, data, dataLength ) \
		cryptSetAttributeString( device, controlType, data, dataLength )

/* Envelope functions */

#define cryptCreateDeenvelope( envelope ) \
		cryptCreateEnvelope( envelope, CRYPT_FORMAT_AUTO )
#define cryptCreateEnvelopeEx( envelope, format, bufSize ) \
		cryptCreateEnvelope( envelope, ( ( format ) == CRYPT_USE_DEFAULT ) ? \
							 CRYPT_FORMAT_CRYPTLIB : ( format ) )
#define cryptAddEnvComponentNumeric( envelope, envInfoType, envInfo ) \
		cryptSetAttribute( envelope, envInfoType, envInfo )
#define cryptAddEnvComponentString( envelope, envInfoType, envInfo, envInfoLength ) \
		cryptSetAttributeString( envelope, envInfoType, envInfo, envInfoLength )
#define cryptGetEnvComponentNumeric( envelope, envInfoType, envInfo ) \
		cryptGetAttribute( envelope, envInfoType, envInfo )

/* Session functions */

#define cryptAddSessionComponentNumeric( session, sessionInfoType, sessionInfo ) \
		cryptSetAttribute( session, sessionInfoType, sessionInfo )

/* Misc functions.  GetErrorInfo function was used to get both internal error 
   code+string values and cert error type+locus, the following automated 
   replacement can only obtain cert errors (it's unlikely it was used much to 
   read internal error codes so this shouldn't be a major loss), 
   GetResourceOwnerName is no longer needed, and QueryContext has been 
   replaced by the ability to read individual attributes so we set it to all-
   zero */

#define cryptGetErrorInfo( cryptHandle, errorCode, errorString, errorStringLength ) \
		cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORTYPE, errorCode ), \
		cryptGetAttribute( cryptHandle, CRYPT_ATTRIBUTE_ERRORLOCUS, errorStringLength )
#define cryptGetResourceOwnerName( cryptEnvelope, name )	CRYPT_OK
#define cryptQueryContext( cryptHandle, cryptQueryInfo ) \
		memset( cryptQueryInfo, 0, sizeof( CRYPT_QUERY_INFO ) )
#define cryptWriteOptions() \
		cryptSetAttribute( CRYPT_UNUSED, CRYPT_OPTION_CONFIGCHANGED, FALSE )

#endif /* _CAPI_DEFINED */
