/****************************************************************************
*																			*
*						  Certificate Checking Routines						*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "cert.h"
  #include "certattr.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/cert.h"
  #include "keymgmt/certattr.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*								Key Usage Routines							*
*																			*
****************************************************************************/

/* The following keyUsage settings are used based on extendedKeyUsage and
   Netscape key usage extensions.  In the following 'Y' = required, 'w' =
   written but apparently not required, S = for signature keys only, E = for
   encryption keys only, KA = for key agreement keys only.

						dig	non	key	dat	key	cer	crl	enc	dec		CA
						sig	rep	enc	enc	agt	sig	sig	onl	onl
   PKIX:				-------------------------------------------
	serverAuth			 S		 E		KA
	clientAuth			 S
	codeSign			 Y
	email				 Y	 Y	 E
	ipsecEndSys			 S		 E		KA
	ipsecTunnel			 S		 E		KA
	ipsecUser			 S		 E		KA
	timeStamping		 Y	 Y
   MS:					-------------------------------------------
	individualCodeSign	 Y
	commercialCodeSign	 Y
	ctlSign				 Y
	sgc									?
	encryptedFS							?
   NS:					-------------------------------------------
	sgc									?
   NS extensions:		-------------------------------------------
	sslClient			 Y
	sslServer					 Y
	sMime				 S		 E
	objectSign			 Y
	sslCA                               	 Y	 w				 Y
	sMimeCA									 Y	 w				 Y
	objectSignCA							 Y	 w				 Y
						-------------------------------------------
						dig	non	key	dat	key	cer	crl	enc	dec		CA
						sig	rep	enc	enc	agt	sig	sig	onl	onl */

/* Masks for various key usage types */

#define USAGE_SIGN_MASK			( CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
								  CRYPT_KEYUSAGE_NONREPUDIATION | \
								  CRYPT_KEYUSAGE_KEYCERTSIGN | \
								  CRYPT_KEYUSAGE_CRLSIGN )
#define USAGE_CRYPT_MASK		( CRYPT_KEYUSAGE_KEYENCIPHERMENT | \
								  CRYPT_KEYUSAGE_DATAENCIPHERMENT )
#define USAGE_KEYAGREEMENT_MASK	( CRYPT_KEYUSAGE_KEYAGREEMENT | \
								  CRYPT_KEYUSAGE_ENCIPHERONLY | \
								  CRYPT_KEYUSAGE_DECIPHERONLY )

/* Flags to denote the algorithm type */

#define ALGO_TYPE_SIGN			1
#define ALGO_TYPE_CRYPT			2
#define ALGO_TYPE_KEYAGREEMENT	4

/* Table mapping extended key usage values to key usage flags */

static const struct {
	const CRYPT_ATTRIBUTE_TYPE usageType;
	const int keyUsageFlags;
	} extendedUsageInfo[] = {
	{ CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,	/* individualCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,	/* commercialCodeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,	/* certTrustListSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,	/* timeStampSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	  CRYPT_KEYUSAGE_NONE },	/* Not sure about this one */
	{ CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,	/* encrypedFileSystem */
	  CRYPT_KEYUSAGE_NONE },	/* Not sure about this one */
	{ CRYPT_CERTINFO_EXTKEY_SERVERAUTH,				/* serverAuth */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,				/* clientAuth */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_CODESIGNING,			/* codeSigning */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,		/* emailProtection */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,			/* ipsecEndSystem */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,			/* ipsecTunnel */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_IPSECUSER,				/* ipsecUser */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,			/* timeStamping */
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,	/* serverGatedCrypto */
	  CRYPT_KEYUSAGE_NONE },	/* Not sure about this one */
	{ CRYPT_ATTRIBUTE_NONE, 0 }
	};

/* Table mapping Netscape cert-type flags to extended key usage flags */

static const struct {
	const int certType;
	const int keyUsageFlags;
	} certTypeInfo[] = {
	{ CRYPT_NS_CERTTYPE_SSLCLIENT,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE },
	{ CRYPT_NS_CERTTYPE_SSLSERVER,
	  CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_NS_CERTTYPE_SMIME,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_KEYENCIPHERMENT },
	{ CRYPT_NS_CERTTYPE_OBJECTSIGNING,
	  CRYPT_KEYUSAGE_DIGITALSIGNATURE | CRYPT_KEYUSAGE_NONREPUDIATION },
	{ CRYPT_NS_CERTTYPE_RESERVED, 0 },
	{ CRYPT_NS_CERTTYPE_SSLCA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_NS_CERTTYPE_SMIMECA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA,
	  CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN },
	{ 0, 0 }
	};

/* Build up key usage flags consistent with the extended key usage purpose */

static int getExtendedKeyUsageFlags( const ATTRIBUTE_LIST *attributes,
									 const int algorithmType,
									 CRYPT_ATTRIBUTE_TYPE *errorLocus )
	{
	int keyUsage = 0, i;

	for( i = 0; extendedUsageInfo[ i ].usageType != CRYPT_ATTRIBUTE_NONE; i++ )
		{
		const ATTRIBUTE_LIST *attributeListPtr = findAttributeField( attributes, \
					extendedUsageInfo[ i ].usageType, CRYPT_ATTRIBUTE_NONE );
		int extendedUsage = 0;

		/* If this usage isn't present, continue */
		if( attributeListPtr == NULL )
			continue;

		/* If the usage is consistent with the algorithm type, add it */
		if( algorithmType & ALGO_TYPE_SIGN )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_SIGN_MASK;
		if( algorithmType & ALGO_TYPE_CRYPT )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_CRYPT_MASK;
		if( algorithmType & ALGO_TYPE_KEYAGREEMENT )
			extendedUsage |= extendedUsageInfo[ i ].keyUsageFlags & USAGE_KEYAGREEMENT_MASK;

		/* If there's no key usage consistent with the extended usage and the
		   extended usage isn't some special-case usage, return an error */
		if( !extendedUsage && extendedUsageInfo[ i ].keyUsageFlags )
			{
			*errorLocus = extendedUsageInfo[ i ].usageType;
			return( CRYPT_ERROR_INVALID );
			}

		keyUsage |= extendedUsage;
		}

	return( keyUsage );
	}

/* Build up key usage flags consistent with the Netscape cert-type purpose */

static int getCertTypeFlags( const ATTRIBUTE_LIST *attributes,
							 const int algorithmType,
							 CRYPT_ATTRIBUTE_TYPE *errorLocus, BOOLEAN *isCA )
	{
	const ATTRIBUTE_LIST *attributeListPtr = findAttributeField( attributes, \
							CRYPT_CERTINFO_NS_CERTTYPE, CRYPT_ATTRIBUTE_NONE );
	int nsCertType, keyUsage = 0, i;

	/* If there isn't a Netscape cert-type extension present, exit */
	if( attributeListPtr == NULL )
		return( 0 );
	nsCertType = ( int ) attributeListPtr->value;

	for( i = 0; certTypeInfo[ i ].certType; i++ )
		{
		int nsUsage = 0;

		/* If this isn't given cert-type, continue */
		if( !( nsCertType & certTypeInfo[ i ].certType ) )
			continue;

		/* If the usage is consistent with the algorithm type, add it */
		if( algorithmType & ALGO_TYPE_SIGN )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_SIGN_MASK;
		if( algorithmType & ALGO_TYPE_CRYPT )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_CRYPT_MASK;
		if( algorithmType & ALGO_TYPE_KEYAGREEMENT )
			nsUsage |= certTypeInfo[ i ].keyUsageFlags & USAGE_KEYAGREEMENT_MASK;

		/* If there's no key usage consistent with the Netscape cert-type,
		   return an error */
		if( !nsUsage )
			{
			*errorLocus = CRYPT_CERTINFO_NS_CERTTYPE;
			return( CRYPT_ERROR_INVALID );
			}

		keyUsage |= nsUsage;
		}

	/* If this is a CA cert-type, mark the key usage as being for a CA */
	if( nsCertType & ( CRYPT_NS_CERTTYPE_SSLCA | CRYPT_NS_CERTTYPE_SMIMECA | \
					   CRYPT_NS_CERTTYPE_OBJECTSIGNINGCA ) )
		*isCA = TRUE;

	return( keyUsage );
	}

/* Get the required key usage for the given cert object */

int getKeyUsageFlags( CERT_INFO *certInfoPtr, BOOLEAN *isCA )
	{
	int algorithmType = 0, keyUsage;

	*isCA = FALSE;

	/* Determine the possible algorithm usage type(s).  If we're passed a 
	   data-only cert (for example one from a cert chain read from an 
	   implicitly trusted private key store), there won't be a context 
	   present but we know the algorithm is OK for signing since it came 
	   from the trusted source */
	if( !cryptStatusError( certInfoPtr->iCryptContext ) )
		{
		int cryptAlgo;

		krnlSendMessage( certInfoPtr->iCryptContext, 
						 RESOURCE_IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
						 CRYPT_CTXINFO_ALGO );
		if( isCryptAlgo( cryptAlgo ) )
			algorithmType |= ALGO_TYPE_CRYPT;
		if( isSigAlgo( cryptAlgo ) )
			algorithmType |= ALGO_TYPE_SIGN;
		if( isKeyxAlgo( cryptAlgo ) )
			algorithmType |= ALGO_TYPE_KEYAGREEMENT;
		}
	else
		algorithmType = ALGO_TYPE_SIGN;

	/* Get the key usage flags for the given extended/Netscape usage type(s)
	   and algorithm type */
	keyUsage = getExtendedKeyUsageFlags( certInfoPtr->attributes,
										 algorithmType,
										 &certInfoPtr->errorLocus );
	keyUsage |= getCertTypeFlags( certInfoPtr->attributes, algorithmType,
								  &certInfoPtr->errorLocus, isCA );
	if( cryptStatusError( keyUsage ) )
		certInfoPtr->errorType = CRYPT_ERRTYPE_CONSTRAINT;

	return( keyUsage );
	}

/* Check that the key usage flags are in order */

static int checkKeyUsageFlags( CERT_INFO *certInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN isCA;
	int givenKeyUsage, keyUsage;

	/* Get the key usage modulo nonrepudiation and CRL signing (which have a
	   somewhat vague status) */
	keyUsage = getKeyUsageFlags( certInfoPtr, &isCA );
	if( cryptStatusError( keyUsage ) )
		return( keyUsage );
	keyUsage &= ~( CRYPT_KEYUSAGE_NONREPUDIATION | CRYPT_KEYUSAGE_CRLSIGN );

	/* Check the CA flag if necessary */
	if( isCA )
		{
		/* If the Netscape cert-type indicates the cert needs to be a CA cert
		   but it isn't marked as such, return an error */
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
									CRYPT_CERTINFO_CA, CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr == NULL || !attributeListPtr->value )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CA,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Make sure that the given usage is consistent with the required usage.
	   If there's no usage present we allow any usage, which isn't a good
	   thing but it's what's required */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
							CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE );
	givenKeyUsage = ( attributeListPtr == NULL ) ? \
					~0 : ( int ) attributeListPtr->value;
	if( ( keyUsage & givenKeyUsage ) != keyUsage )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Make sure mutually exclusive flags aren't set */
	if( ( keyUsage & CRYPT_KEYUSAGE_ENCIPHERONLY ) && \
		( keyUsage & CRYPT_KEYUSAGE_DECIPHERONLY ) )
		{
		setErrorInfo( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
					  CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Compare two attribute components */

static BOOLEAN compareAttributeComponents( const ATTRIBUTE_LIST *attribute1ptr,
										   const ATTRIBUTE_LIST *attribute2ptr )
	{
	const void *data1ptr, *data2ptr;

	/* Make sure either both are absent or present */
	if( attribute1ptr != NULL )
		{
		if( attribute2ptr == NULL )
			return( FALSE );	/* Both must be present or absent */
		}
	else
		{
		if( attribute2ptr != NULL )
			return( FALSE );	/* Both must be present or absent */
		return( TRUE );
		}

	/* If it's an attribute containing a composite field, use a special-case
	   compare */
	if( attribute1ptr->fieldType == FIELDTYPE_DN )
		return( compareDN( attribute1ptr->data, attribute2ptr->data, FALSE ) );

	/* Compare the data values */
	data1ptr = ( attribute1ptr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
			   attribute1ptr->smallData : attribute1ptr->data;
	data2ptr = ( attribute2ptr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
			   attribute2ptr->smallData : attribute2ptr->data;
	if( attribute1ptr->dataLength != attribute2ptr->dataLength || \
		memcmp( data1ptr, data2ptr, attribute1ptr->dataLength ) )
		return( FALSE );

	return( TRUE );
	}

/* Compare two altNames component by component */

static CRYPT_ATTRIBUTE_TYPE compareAltNames( const ATTRIBUTE_LIST *subjectAttributes,
											 const ATTRIBUTE_LIST *issuerAttributes )
	{
	ATTRIBUTE_LIST *subjectAttributeListPtr, *issuerAttributeListPtr;

	/* Check the otherName */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_OTHERNAME_TYPEID );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_OTHERNAME_TYPEID );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_OTHERNAME_TYPEID );
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_OTHERNAME_VALUE );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_OTHERNAME_VALUE );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_OTHERNAME_VALUE );

	/* Check the email address */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_RFC822NAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_RFC822NAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_RFC822NAME );

	/* Check the DNS name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_DNSNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DNSNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_DNSNAME );

	/* Check the directory name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_DIRECTORYNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DIRECTORYNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_DIRECTORYNAME );

	/* Check the EDI party name */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER );
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME );

	/* Check the URI */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );

	/* Check the IP address */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_IPADDRESS );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_IPADDRESS );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_IPADDRESS );

	/* Check the registered ID */
	subjectAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_ISSUERALTNAME, CRYPT_CERTINFO_REGISTEREDID );
	issuerAttributeListPtr = findAttributeField( issuerAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_REGISTEREDID );
	if( !compareAttributeComponents( subjectAttributeListPtr,
									 issuerAttributeListPtr ) )
		return( CRYPT_CERTINFO_REGISTEREDID );

	return( CRYPT_ATTRIBUTE_NONE );
	}

/* Perform a wildcarded compare or two strings in attributes */

static BOOLEAN wildcardStringMatch( const char *wildcardString, 
									const char *string )
	{
	while( *wildcardString && *string )
		{
		/* Match a wildcard */
		if( *wildcardString == '*' )
			{
			BOOLEAN isMatch = FALSE;

			/* Skip '*'s and exit if we've reached the end of the pattern */
			while( *wildcardString == '*' )
				wildcardString++;
			if( !*wildcardString )
				return( TRUE );

			/* Match to the next literal, then match the next section with
			   backtracking in case of a mismatch */
			while( *string && *wildcardString != *string )
				string++;
			while( *string && !isMatch )
				{
				isMatch = wildcardStringMatch( wildcardString, string );
				if( !isMatch )
					string++;
				}

			return( isMatch );
			}
		else
			if( *wildcardString != *string )
				return( FALSE );

		wildcardString++;
		string++;
		}

	/* If there are literals left in the wildcard or text string, we haven't
	   found a match yet */
	if( *wildcardString && ( *wildcardString != '*' || *++wildcardString ) )
		return( FALSE );
	return( *string ? FALSE : TRUE );
	}

static BOOLEAN wildcardMatch( const ATTRIBUTE_LIST *constrainedAttribute,
							  const ATTRIBUTE_LIST *attribute,
							  const BOOLEAN errorStatus )
	{
	const char *constrainedString = \
		( constrainedAttribute->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
		( char * ) constrainedAttribute->smallData : constrainedAttribute->data;
	const char *string = ( attribute->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
		( char * ) attribute->smallData : attribute->data;
	int count = 0, i;

	/* Perform a quick damage-control check to prevent excessive recursion:
	   There shouldn't be more than ten wildcard chars present (realistically
	   there shouldn't be more than one) */
	for( i = 0; string[ i ]; i++ )
		if( string[ i ] == '*' )
			count++;
	if( count > 10 )
		return( errorStatus );

	/* Pass the call on to the string matcher (this is recursive so we can't
	   do the match in this function) */
	return( wildcardStringMatch( string, constrainedString ) );
	}

/* Check name constraints placed by an issuer.  matchValue = TRUE for
   excluded subtrees (fail on a match), FALSE for included subtrees (fail on
   a mismatch) */

int checkNameConstraints( CERT_INFO *subjectCertInfoPtr,
						  const ATTRIBUTE_LIST *issuerAttributes,
						  const BOOLEAN matchValue )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const CRYPT_ATTRIBUTE_TYPE constraintType = ( matchValue ) ? \
		CRYPT_CERTINFO_EXCLUDEDSUBTREES : CRYPT_CERTINFO_PERMITTEDSUBTREES;
	ATTRIBUTE_LIST *attributeListPtr, *constrainedAttributeListPtr;
	int status = CRYPT_OK;

	/* Compare the DN if a constraint exists */
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_DIRECTORYNAME );
	if( compareDN( subjectCertInfoPtr->subjectName,
				   attributeListPtr->data, TRUE ) == matchValue )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Compare the Internet-related names if constraints exist */
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_RFC822NAME );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_RFC822NAME );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_DNSNAME );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_DNSNAME );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	attributeListPtr = findAttributeField( issuerAttributes,
							constraintType, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	constrainedAttributeListPtr = findAttributeField( subjectAttributes,
			CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER );
	if( attributeListPtr != NULL && constrainedAttributeListPtr != NULL && \
		wildcardMatch( constrainedAttributeListPtr, attributeListPtr,
					   FALSE ) == matchValue )
		status = CRYPT_ERROR_INVALID;
	if( cryptStatusError( status ) )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTALTNAME,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( status );
		}

	return( CRYPT_OK );
	}

/* Check policy constraints placed by an issuer */

int checkPolicyConstraints( CERT_INFO *subjectCertInfoPtr,
							const ATTRIBUTE_LIST *issuerAttributes )
	{
	ATTRIBUTE_LIST *attributeListPtr, *constrainedAttributeListPtr;

	/* Compare the issuer and subject policies if constraints exist */
	attributeListPtr = findAttributeField( issuerAttributes,
						CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ATTRIBUTE_NONE );
	constrainedAttributeListPtr = findAttributeField( subjectCertInfoPtr->attributes,
						CRYPT_CERTINFO_CERTPOLICYID, CRYPT_ATTRIBUTE_NONE );
	if( constrainedAttributeListPtr == NULL || \
		attributeListPtr->dataLength != constrainedAttributeListPtr->dataLength || \
		memcmp( attributeListPtr->smallData, constrainedAttributeListPtr->smallData,
				attributeListPtr->dataLength ) )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CERTPOLICYID,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Check for Constraint Violations						*
*																			*
****************************************************************************/

/* Check the validity of a CRL based on an issuer cert */

static int checkCRL( CERT_INFO *crlInfoPtr,
					 const CERT_INFO *issuerCertInfoPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* If it's a delta CRL, make sure the CRL numbers make sense (that is,
	   that the delta CRL was issued after the full CRL) */
	attributeListPtr = findAttribute( crlInfoPtr->attributes,
									  CRYPT_CERTINFO_DELTACRLINDICATOR );
	if( attributeListPtr != NULL )
		{
		const int deltaCRLindicator = ( int ) attributeListPtr->value;

		attributeListPtr = findAttribute( crlInfoPtr->attributes,
										  CRYPT_CERTINFO_CRLNUMBER );
		if( attributeListPtr != NULL && \
			attributeListPtr->value >= deltaCRLindicator )
			{
			setErrorInfo( crlInfoPtr, CRYPT_CERTINFO_DELTACRLINDICATOR,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* If a key usage attribute is present, make sure the issuer can sign
	   CRL's */
	attributeListPtr = findAttribute( issuerCertInfoPtr->attributes,
									  CRYPT_CERTINFO_KEYUSAGE );
	if( attributeListPtr != NULL )
		{
		if( !( attributeListPtr->value & issuerCertInfoPtr->trustedUsage & \
			   CRYPT_KEYUSAGE_CRLSIGN ) )
			{
			setErrorInfo( crlInfoPtr, 
						  ( attributeListPtr->value & CRYPT_KEYUSAGE_CRLSIGN ) ? \
							CRYPT_CERTINFO_TRUSTED_USAGE : CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}
	else
		/* There's no key usage present, make sure the issuer is at least 
		   trusted to sign CRL's */
		if( !( issuerCertInfoPtr->trustedUsage & CRYPT_KEYUSAGE_CRLSIGN ) )
			{
			setErrorInfo( crlInfoPtr, CRYPT_CERTINFO_TRUSTED_USAGE,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}


	/* If a basic constraints attribute is present, make sure the issuer is
	   a CA */
	attributeListPtr = findAttribute( issuerCertInfoPtr->attributes,
									  CRYPT_CERTINFO_CA );
	if( attributeListPtr != NULL && !attributeListPtr->value )
		{
		setErrorInfo( crlInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/* Check the validity of a subject cert based on an issuer cert */

int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr )
	{
	const ATTRIBUTE_LIST *subjectAttributes = subjectCertInfoPtr->attributes;
	const ATTRIBUTE_LIST *issuerAttributes = issuerCertInfoPtr->attributes;
	ATTRIBUTE_LIST *attributeListPtr;
	BOOLEAN subjectIsCA = FALSE, issuerIsCA = FALSE, boolean1, boolean2;
	const time_t currentTime = time( NULL );
	int validityNesting, status;

	/* If it's a certification request, there's nothing to check (yet) */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CERTREQUEST || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_CRMF_REQUEST || \
		subjectCertInfoPtr->type == CRYPT_CERTTYPE_NS_SPKAC )
		return( CRYPT_OK );

	/* If we're checking a CRL, call the special-case routine for this */
	if( subjectCertInfoPtr->type == CRYPT_CERTTYPE_CRL )
		return( checkCRL( subjectCertInfoPtr, issuerCertInfoPtr ) );

	/* Determine whether the subject or issuer are CA certs */
	attributeListPtr = findAttributeField( subjectAttributes, 
									CRYPT_CERTINFO_CA, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		subjectIsCA = ( BOOLEAN ) attributeListPtr->value;
	attributeListPtr = findAttributeField( issuerAttributes,
									CRYPT_CERTINFO_CA, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		issuerIsCA = ( BOOLEAN ) attributeListPtr->value;

	/* Check that the validity period is in order.  If we're checking an 
	   existing cert then the start time has to be valid, if we're creating
	   a new cert then it doesn't have to be valid since the cert could be
	   created for use in the future */
	if( subjectCertInfoPtr->startTime >= subjectCertInfoPtr->endTime || \
		( subjectCertInfoPtr->certificate != NULL && \
		  currentTime < subjectCertInfoPtr->startTime ) )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_VALIDFROM,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( currentTime > subjectCertInfoPtr->endTime )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_VALIDTO,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* Enforce validity period nesting if necessary */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &validityNesting, 
					 CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING );
	if( validityNesting )
		{
		if( subjectCertInfoPtr->startTime < issuerCertInfoPtr->startTime )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_VALIDFROM,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( subjectCertInfoPtr->endTime > issuerCertInfoPtr->endTime )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_VALIDTO,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Check that the cert usage flags are consistent */
	if( subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		status = checkKeyUsageFlags( subjectCertInfoPtr );
		if( cryptStatusError( status ) )
			return( status );
        }

	/* If the cert isn't self-signed (ie subject == issuer), check name and
	   altName chaining */
	if( subjectCertInfoPtr != issuerCertInfoPtr )
		{
		/* Check that the subject issuer and issuer subject names chain
		   properly  */
		if( !compareDN( subjectCertInfoPtr->issuerName,
						issuerCertInfoPtr->subjectName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

		/* If an issuer altname is present, check that it chains correctly */
		if( subjectCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
			{
			boolean1 = ( findAttribute( issuerAttributes,
					CRYPT_CERTINFO_SUBJECTALTNAME ) != NULL ) ? TRUE : FALSE;
			boolean2 = ( findAttribute( subjectAttributes,
					CRYPT_CERTINFO_ISSUERALTNAME ) != NULL ) ? TRUE : FALSE;
			if( boolean1 ^ boolean2 )
				{
				/* The altName must be present in both certs */
				if( boolean1 )
					{
					setErrorInfo( subjectCertInfoPtr,
								  CRYPT_CERTINFO_ISSUERALTNAME, 
								  CRYPT_ERRTYPE_CONSTRAINT );
					}
				else
					setErrorInfo( subjectCertInfoPtr,
								  CRYPT_CERTINFO_SUBJECTALTNAME, 
								  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}
			if( boolean1 && boolean2 )
				{
				subjectCertInfoPtr->errorLocus = compareAltNames( subjectAttributes,
														  issuerAttributes );
				if( subjectCertInfoPtr->errorLocus != CRYPT_ATTRIBUTE_NONE )
					return( CRYPT_ERROR_INVALID );
				}
			}
		}

	/* If there's a path length constraint present, make sure the cert is a
	   CA cert.  If the issuer path length is set to zero, make sure the
	   subject is a non-CA cert */
	attributeListPtr = findAttributeField( issuerAttributes,
					CRYPT_CERTINFO_PATHLENCONSTRAINT, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		if( !issuerIsCA )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		if( subjectCertInfoPtr != issuerCertInfoPtr && \
			!attributeListPtr->value && subjectIsCA )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_PATHLENCONSTRAINT,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}
	if( findAttributeField( subjectAttributes,
				CRYPT_CERTINFO_PATHLENCONSTRAINT, CRYPT_ATTRIBUTE_NONE ) && \
		!subjectIsCA )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If there's a name constraint present, make sure the cert is a CA
	   cert */
	if( findAttribute( subjectAttributes, CRYPT_CERTINFO_NAMECONSTRAINTS ) && \
		!subjectIsCA )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( findAttribute( issuerAttributes, CRYPT_CERTINFO_NAMECONSTRAINTS ) && \
		!issuerIsCA )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	/* If the issuing cert has name constraints and isn't self-signed (which
	   would apply the constraint to itself), make sure the subject name and
	   altName falls within the constrained subtrees.  Since excluded subtrees
	   override permitted subtrees, we check these first */
	if( !subjectCertInfoPtr->selfSigned )
		{
		if( findAttribute( issuerAttributes, \
						   CRYPT_CERTINFO_EXCLUDEDSUBTREES ) != NULL && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
													issuerAttributes, TRUE ) ) )
				return( CRYPT_ERROR_INVALID );
		if( findAttribute( issuerAttributes,
						   CRYPT_CERTINFO_PERMITTEDSUBTREES ) != NULL && \
			cryptStatusError( checkNameConstraints( subjectCertInfoPtr,
													issuerAttributes, FALSE ) ) )
			return( CRYPT_ERROR_INVALID );
		}

	/* If there's a policy constraint present, make sure the cert is a CA
	   cert.  If the skip count is set to zero, and check the issuer 
	   constraints against the subject */
	if( findAttribute( subjectAttributes, CRYPT_CERTINFO_POLICYCONSTRAINTS ) && \
		!subjectIsCA )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_CONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}
	if( findAttribute( issuerAttributes, CRYPT_CERTINFO_POLICYCONSTRAINTS ) )
		{
		if( !issuerIsCA )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

		/* Make sure the skip count is set to zero, which means the constraint
		   applies to the subject */
		attributeListPtr = findAttribute( issuerAttributes,
									CRYPT_CERTINFO_REQUIREEXPLICITPOLICY );
		if( attributeListPtr != NULL && attributeListPtr->value == 0 )
			{
			status = checkPolicyConstraints( subjectCertInfoPtr,
											 issuerAttributes );
			if( cryptStatusError( status ) )
				return( status );
			}
		}

	/* If a key usage attribute is present, make sure the issuer can sign
	   certs */
	attributeListPtr = findAttribute( issuerAttributes,
									  CRYPT_CERTINFO_KEYUSAGE );
	if( attributeListPtr != NULL )
		{
		if( !( attributeListPtr->value & issuerCertInfoPtr->trustedUsage & \
			   CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			setErrorInfo( subjectCertInfoPtr, 
						  ( attributeListPtr->value & CRYPT_KEYUSAGE_KEYCERTSIGN ) ? \
							CRYPT_CERTINFO_TRUSTED_USAGE : CRYPT_CERTINFO_KEYUSAGE,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}
		}
	else
		/* There's no key usage present, make sure the issuer is at least 
		   trusted to sign certs */
		if( !( issuerCertInfoPtr->trustedUsage & CRYPT_KEYUSAGE_KEYCERTSIGN ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_TRUSTED_USAGE,
						  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
			return( CRYPT_ERROR_INVALID );
			}

	/* If a basic constraints attribute is present, make sure the issuer is
	   a CA */
	if( findAttribute( issuerAttributes, CRYPT_CERTINFO_CA ) != NULL && \
		!issuerIsCA )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_CA,
					  CRYPT_ERRTYPE_ISSUERCONSTRAINT );
		return( CRYPT_ERROR_INVALID );
		}

	return( CRYPT_OK );
	}

/* Check that a key cert is valid for a particular purpose.  This is used
   mainly to check that contexts and certs are valid for key exchange/sig.
   generation, and isn't as rigorous as the cert/issuer cert check in
   checkCert() */

int checkCertUsage( const CERT_INFO *certInfoPtr, const int keyUsage,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* Check and enforce the keyUsage attribute if there's one present */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
							CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL && keyUsage != CRYPT_UNUSED )
		{
		const int trustedUsage = \
					attributeListPtr->value & certInfoPtr->trustedUsage;
		BOOLEAN usageOK = FALSE;

		/* If it's a key agreement usage the checking gets a bit complex, we
		   have to make sure it's both a permitted usage and not an excluded
		   usage */
		if( keyUsage == CRYPT_KEYUSAGE_ENCIPHERONLY || \
			keyUsage == CRYPT_KEYUSAGE_DECIPHERONLY )
			{
			const int excludedUsage = \
					( keyUsage == CRYPT_KEYUSAGE_ENCIPHERONLY ) ? \
					CRYPT_KEYUSAGE_DECIPHERONLY : CRYPT_KEYUSAGE_ENCIPHERONLY;

			if( ( trustedUsage & keyUsage ) && \
				!( trustedUsage & excludedUsage ) )
				usageOK = TRUE;
			}
		else
			/* Conventional usage flag, do a straight check */
			if( trustedUsage & keyUsage )
				usageOK = TRUE;
		if( !usageOK )
			{
			*errorLocus = ( attributeListPtr->value & keyUsage ) ? \
						  CRYPT_CERTINFO_TRUSTED_USAGE : CRYPT_CERTINFO_KEYUSAGE;
			*errorType = CRYPT_ERRTYPE_CONSTRAINT;
			return( CRYPT_ERROR_INVALID );
			}
		}

	/* Check and enforce the privateKeyUsage attribute if there's one
	   present */
	if( findAttributeField( certInfoPtr->attributes,
			CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD, CRYPT_ATTRIBUTE_NONE ) != NULL )
		{
		const time_t currentTime = time( NULL );

		attributeListPtr = findAttributeField( certInfoPtr->attributes,
				CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			currentTime < *( ( time_t * ) attributeListPtr->smallData ) )
			{
			*errorLocus = CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE;
			*errorType = CRYPT_ERRTYPE_CONSTRAINT;
			return( CRYPT_ERROR_INVALID );
			}
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
				CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER, CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr != NULL && \
			currentTime > *( ( time_t * ) attributeListPtr->smallData ) )
			{
			if( errorLocus != NULL )
				{
				*errorLocus = CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER;
				*errorType = CRYPT_ERRTYPE_CONSTRAINT;
				}
			return( CRYPT_ERROR_INVALID );
			}
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*						Check for Valid ASN.1 Encoding						*
*																			*
****************************************************************************/

/* The maximum nesting level for constructed or encapsulated objects (this
   can get surprisingly high for some of the more complex attributes).  This
   value is chosen to pass all normal certs while avoiding stack overflows
   for artificial bad data */

#define MAX_NESTING_LEVEL	50

/* When we parse a nested data object encapsulated within a larger object,
   the length is initially set to a magic value which is adjusted to the
   actual length once we start parsing the object */

#define LENGTH_MAGIC		177545L

/* Current parse state.  This is used to check for potential BIT STRING and
   OCTET STRING targets for OCTET/BIT STRING holes, which are always
   preceded by an AlgorithmIdentifier.  In order to detect these without
   having to know every imaginable AlgorithmIdentifier OID, we check for the
   following sequence of events:

	checkASN1Object								-- SEQUENCE
		checkASN1
			checkASN1Object
				checkPrimitive					-- OID
			checkASN1Object
				checkPrimitive					-- opt.BOOLEAN	  OCTET STRING
				checkPrimitive					-- NULL, or		|
				checkASN1Object					-- SEQUENCE		| BIT STRING
	checkASN1Object
		checkPrimitive							-- OCTET/BIT STRING

   This type of checking is rather awkward in the (otherwise stateless) code,
   but is the only way to be sure that it's safe to try burrowing into an
   OCTET STRING or BIT STRING to try to find encapsulated data, since
   otherwise even with relatively strict checking there's still a very small
   chance that random data will look like a nested object */

typedef enum {
	/* Generic non-state */
	STATE_NONE,

	/* States corresponding to ASN.1 primitives */
	STATE_BITSTRING, STATE_BOOLEAN, STATE_INTEGER, STATE_NULL,
	STATE_OCTETSTRING, STATE_OID, STATE_SEQUENCE, STATE_STRING, STATE_TIME,

	/* States corresponding to different parts of a SEQUENCE { OID, optional,
	   OCTET/BIT STRING } sequence */
	STATE_HOLE_OID, STATE_HOLE_BITSTRING, STATE_HOLE_OCTETSTRING,

	/* Error state */
	STATE_ERROR
	} ASN1_STATE;

/* Structure to hold info on an ASN.1 item */

typedef struct {
	int id;						/* Identifier */
	int tag;					/* Tag */
	long length;				/* Data length */
	BOOLEAN indefinite;			/* Item has indefinite length */
	int headerSize;				/* Size of tag+length */
	} ASN1_ITEM;

/* Table to identify valid string chars */

#define P	1						/* PrintableString */
#define I	2						/* IA5String */
#define PI	3						/* IA5String and PrintableString */

static const int charFlags[] = {
	/* 00  01  02  03  04  05  06  07  08  09  0A  0B  0C  0D  0E  0F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/* 10  11  12  13  14  15  16  17  18  19  1A  1B  1C  1D  1E  1F */
		0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,	0,
	/*		!	"	#	$	%	&	'	(	)	*	+	,	-	.	/ */
	   PI,	I,	I,	I,	I,	I,	I, PI, PI, PI,	I, PI, PI, PI, PI, PI,
	/*	0	1	2	3	4	5	6	7	8	9	:	;	<	=	>	? */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I, PI,	I, PI,
	/*	@	A	B	C	D	E	F	G	H	I	J	K	L	M	N	O */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	P	Q	R	S	T	U	V	W	X	Y	Z	[	\	]	^ _ */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	I,
	/*	`	a	b	c	d	e	f	g	h	i	j	k	l	m	n	o */
		I, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,
	/*	p	q	r	s	t	u	v	w	x	y	z	{	|	}	~  DL */
	   PI, PI, PI, PI, PI, PI, PI, PI, PI, PI, PI,	I,	I,	I,	I,	0
	};

static ASN1_STATE checkASN1( STREAM *stream, long length,
							 const int isIndefinite, const int level,
							 ASN1_STATE state );

/* Get an ASN.1 objects tag and length */

static int getItem( STREAM *stream, ASN1_ITEM *item )
	{
	int tag, length;

	memset( item, 0, sizeof( ASN1_ITEM ) );
	tag = sgetc( stream );
	item->headerSize = 1;
	item->id = tag & ~BER_SHORT_ID_MASK;
	tag &= BER_SHORT_ID_MASK;
	if( tag == BER_SHORT_ID_MASK )
		{
		int value;

		/* Long tag encoded as sequence of 7-bit values.  This doesn't try to
		   handle tags > INT_MAX, it'd be pretty peculiar ASN.1 if it had to
		   use tags this large */
		tag = 0;
		do
			{
			value = sgetc( stream );
			tag = ( tag << 7 ) | ( value & 0x7F );
			item->headerSize++;
			}
		while( value & 0x80 && sGetStatus( stream ) == CRYPT_OK );
		}
	item->tag = tag;
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	length = sgetc( stream );
	item->headerSize++;
	if( length & 0x80 )
		{
		int i;

		length &= 0x7F;
		if( length > 4 )
			/* Object has a bad length field, usually because we've lost sync
			   in the decoder or run into garbage */
			return( CRYPT_ERROR_BADDATA );
		item->headerSize += length;
		item->length = 0;
		if( !length )
			item->indefinite = TRUE;
		for( i = 0; i < length; i++ )
			{
			int ch = sgetc( stream );

			item->length = ( item->length << 8 ) | ch;
			}
		}
	else
		item->length = length;

	return( CRYPT_OK );
	}

/* Check whether an ASN.1 object is encapsulated inside an OCTET STRING or
   BIT STRING */

static BOOLEAN checkEncapsulation( STREAM *stream, const int length,
								   const BOOLEAN isBitstring,
								   const ASN1_STATE state )
	{
	BOOLEAN isEncapsulated = TRUE;
	long streamPos = stell( stream ), innerLength;
	int tag = readTag( stream );

	/* Perform a quick check to see whether an OCTET STRING or BIT STRING hole
	   is allowed at this point.  A BIT STRING must be preceded by { SEQ, OID,
	   NULL }.  An OCTET STRING must be preceded by { SEQ, OID, {BOOLEAN} } */
	if( ( isBitstring && state != STATE_HOLE_BITSTRING ) ||
		( !isBitstring && ( state != STATE_HOLE_OID && \
							state != STATE_HOLE_OCTETSTRING ) ) )
		{
		sungetc( stream );
		return( FALSE );
		}

	/* A BIT STRING which encapsulates something only ever contains
	   { SEQUENCE, sequence_length < length, INTEGER } */
	if( isBitstring )
		{
		/* Make sure there's a SEQUENCE of a vaguely correct length
		   present */
		if( tag != BER_SEQUENCE || \
			cryptStatusError( readLength( stream, &innerLength ) ) || \
			innerLength < length - 10 || innerLength > length + 10 )
			{
			sseek( stream, streamPos );
			return( FALSE );
			}
		
		/* Make sure that the first thing inside the SEQUENCE is an
		   INTEGER */
		if( readTag( stream ) != BER_INTEGER || \
			cryptStatusError( readLength( stream, &innerLength ) ) || \
			innerLength < length - 12 || innerLength > length + 8 )
			isEncapsulated = FALSE;
		
		sseek( stream, streamPos );
		return( isEncapsulated );
		}

	/* An OCTET STRING is more complex.  This could encapsulate any of:
		BIT STRING: keyUsage, crlReason, Netscape certType, must be
			<= 16 bits and a valid bitstring.
		GeneralisedTime: invalidityDate: too difficult to identify
			since the obvious check for a valid length will also fail
			invalid-length encodings, missing the very thing we usually
			want to check for.
		IA5String: Netscape extensions, also checked by the context-
			aware higher-level code which knows how long and in what
			format the string should be.
		INTEGER: deltaCRLIndicator, crlNumber, must be <= 16 bits).
		OCTET STRING: keyID, a blob which we don't check.
		OID: holdInstructionCode, which is difficult to identify and
			will be checked by the context-aware extension read code
			anyway.
		SEQUENCE: most extensions, a bit difficult to check but for
			now we make sure the length is roughly right */
	switch( tag )
		{
		case BER_BITSTRING:
			if( cryptStatusError( readLength( stream, &innerLength ) ) || \
				innerLength > 2 )
				isEncapsulated = FALSE;
			else
				{
				int ch = sgetc( stream );

				if( ch < 0 || ch > 7 )
					isEncapsulated = FALSE;
				}
			break;

		case BER_INTEGER:
			if( cryptStatusError( readLength( stream, &innerLength ) ) || \
				innerLength > 2 )
				isEncapsulated = FALSE;
			break;

		case BER_SEQUENCE:
			if( cryptStatusError( readLength( stream, &innerLength ) ) || \
				innerLength < length - 10 || innerLength > length + 10 )
				isEncapsulated = FALSE;
			break;

		default:
			isEncapsulated = FALSE;
		}
	sseek( stream, streamPos );
	return( isEncapsulated );
	}

/* Check a primitive ASN.1 object */

static ASN1_STATE checkPrimitive( STREAM *stream, const ASN1_ITEM *item,
								  const int level, const ASN1_STATE state )
	{
	int length = ( int ) item->length, ch, i;

	if( !item->length && item->tag != BER_NULL && item->tag != BER_RESERVED )
		return( STATE_ERROR );			/* Item has zero length */
	switch( item->tag )
		{
		case BER_BOOLEAN:
			ch = sgetc( stream );
			if( ch != 0 && ch != 0xFF )
				/* Value has non-DER encoding */
				return( STATE_ERROR );
			return( STATE_BOOLEAN );

		case BER_INTEGER:
		case BER_ENUMERATED:
			ch = sgetc( stream );
			if( ch & 0x80 )
				/* Integer has a negative value */
				return( STATE_ERROR );
			if( !ch && length > 1 )
				{
				if( sgetc( stream ) < 0x80 )
					/* Integer has non-DER encoding */
					return( STATE_ERROR );
				length--;
				}
			if( --length )
				sSkip( stream, length );
			return( STATE_INTEGER );

		case BER_BITSTRING:
			/* Check the number of unused bits */
			ch = sgetc( stream );
			length--;
			if( ch < 0 || ch > 7 )
				/* Invalid number of unused bits */
				return( STATE_ERROR );

			/* If it's short enough to be a bit flag, process it as a
			   sequence of bits */
			if( length == 1 || length == 2 )
				{
				unsigned int bitString, bitMask = 0xFF;
				int noBits;

				noBits = ( length * 8 ) - ch;

				/* In theory we should check for correct DER encoding of the
				   bits in the string, but so many programs get this wrong
				   (encoding spurious trailing zero bits) that we don't 
				   bother, and only check for spurious extra bits which are 
				   set */
				bitString = sgetc( stream );
				if( noBits > 8 )
					{
					bitString = ( bitString << 8 ) | sgetc( stream );
					bitMask = 0xFFFF;
					}
				if( ( bitMask >> noBits ) & bitString )
					/* There shouldn't be any bits set after the last valid
					   one */
					return( STATE_ERROR );
				return( STATE_BITSTRING );
				}
			/* Fall through */

		case BER_OCTETSTRING:
			/* If it's something encapsulated inside the string, handle it
			   as a constructed item */
			if( checkEncapsulation( stream, length, ( BOOLEAN )	/* VC++ kludge */
					( ( item->tag == BER_BITSTRING ) ? TRUE : FALSE ), state ) )
				{
				ASN1_STATE state;

				state = checkASN1( stream, length, item->indefinite,
								   level + 1, STATE_NONE );
				return( ( state == STATE_ERROR ) ? STATE_ERROR : STATE_NONE );
				}

			/* Skip the data */
			sSkip( stream, length );
			return( ( item->tag == BER_BITSTRING ) ? \
					STATE_BITSTRING : STATE_OCTETSTRING );

		case BER_OBJECT_IDENTIFIER:
			if( length > 64 )
				/* We shouldn't find OIDs this large */
				return( STATE_ERROR );

			/* At this point we could check for obsolete and deprecated OIDs,
			   but this will be caught later on anyway */
			sSkip( stream, length );
			return( STATE_OID );

		case BER_RESERVED:		/* EOC */
			break;

		case BER_NULL:
			return( STATE_NULL );

		case BER_OBJECT_DESCRIPTOR:
		case BER_STRING_GRAPHIC:
		case BER_STRING_ISO646:
		case BER_STRING_GENERAL:
		case BER_STRING_UNIVERSAL:
		case BER_STRING_NUMERIC:
		case BER_STRING_T61:
		case BER_STRING_VIDEOTEX:
		case BER_STRING_BMP:
			sSkip( stream, length );
			return( STATE_STRING );
		case BER_STRING_PRINTABLE:
			for( i = 0; i < length; i++ )
				{
				ch = sgetc( stream );
				if( ch >= 128 || !( charFlags[ ch ] & P ) )
					return( STATE_ERROR );
				}
			return( STATE_STRING );
		case BER_STRING_IA5:
			for( i = 0; i < length; i++ )
				{
				ch = sgetc( stream );
				if( ch >= 128 || !( charFlags[ ch ] & I ) )
					return( STATE_ERROR );
				}
			return( STATE_STRING );

		case BER_TIME_UTC:
		case BER_TIME_GENERALIZED:
			if( length != ( ( item->tag == BER_TIME_GENERALIZED ) ? 15 : 13 ) )
				return( STATE_ERROR );
			for( i = 0; i < length; i++ )
				{
				ch = sgetc( stream );
				if( !isdigit( ch ) && ch != 'Z' )
					return( STATE_ERROR );
				}
			return( STATE_TIME );

		default:
			/* Unrecognised primitive */
			return( STATE_ERROR );
		}

	return( STATE_NONE );
	}

/* Check a single ASN.1 object */

static ASN1_STATE checkASN1object( STREAM *stream, const ASN1_ITEM *item,
								   const int level, const ASN1_STATE state )
	{
	ASN1_STATE newState;

	if( ( item->id & BER_CLASS_MASK ) == BER_UNIVERSAL )
		{
		/* Perform a sanity check */
		if( ( item->tag != BER_NULL ) && ( item->length < 0 ) )
			/* Object has a bad length field, usually because we've lost sync
			   in the decoder or run into garbage */
			return( STATE_ERROR );

		/* If it's constructed, parse the nested object */
		if( ( item->id & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			return( checkASN1( stream, item->length, item->indefinite,
						level + 1, ( ( item->tag | item->id ) == BER_SEQUENCE ) ? \
						STATE_SEQUENCE : STATE_NONE ) );

		/* It's primitive, check the primitive element with optional state
		   update: SEQ + OID -> HOLE_OID; OID + NULL | BOOLEAN -> HOLE_OID */
		newState = checkPrimitive( stream, item, level + 1, state );
		if( state == STATE_SEQUENCE && newState == STATE_OID )
			return( STATE_HOLE_OID );
		if( state == STATE_HOLE_OID )
			{
			if( newState == STATE_NULL )
				return( STATE_HOLE_BITSTRING );
			if( newState == STATE_BOOLEAN )
				return( STATE_HOLE_OCTETSTRING );
			}
		return( ( newState == STATE_ERROR ) ? STATE_ERROR : STATE_NONE );
		}

	/* Tagged object, perform an initial sanity check */
	if( ( item->tag != BER_NULL ) && ( item->length < 0 ) )
		/* Object has a bad length field, usually because we've lost sync in
		   the decoder or run into garbage */
		return( STATE_ERROR );

	/* If it's constructed, check the various fields in it */
	if( item->length || item->indefinite )
		{
		if( ( item->id & BER_CONSTRUCTED_MASK ) == BER_CONSTRUCTED )
			{
			ASN1_STATE newState;

			newState = checkASN1( stream, item->length, item->indefinite,
								  level + 1, STATE_NONE );
			return( ( newState == STATE_ERROR ) ? STATE_ERROR : STATE_NONE );
			}

		/* This could be anything */
		sSkip( stream, item->length );
		return( STATE_NONE );
		}

	/* At this point we have a zero-length object which should be an error,
	   however PKCS #10 has the attribute-encoding problem which produces
	   these object so we can't complain about them */
	return( STATE_NONE );
	}

/* Check a complex ASN.1 object */

static ASN1_STATE checkASN1( STREAM *stream, long length, const int isIndefinite,
							 const int level, ASN1_STATE state )
	{
	ASN1_ITEM item;
	long lastPos = stell( stream );
	BOOLEAN seenEOC = FALSE;

	/* Sanity-check the nesting level */
	if( level > MAX_NESTING_LEVEL )
		return( STATE_ERROR );

	/* Special-case for zero-length objects */
	if( !length && !isIndefinite )
		return( STATE_NONE );

	while( getItem( stream, &item ) == CRYPT_OK )
		{
		/* If the length isn't known and the item has a definite length, set
		   the length to the items length */
		if( length == LENGTH_MAGIC && !item.indefinite )
			length = item.headerSize + item.length;

		/* Check whether this is an EOC for an indefinite item */
		if( !item.indefinite && ( item.id | item.tag ) == BER_RESERVED )
			seenEOC = TRUE;
		else
			{
			state = checkASN1object( stream, &item, level + 1, state );
			if( state == STATE_ERROR || sGetStatus( stream ) != CRYPT_OK )
				return( STATE_ERROR );
			}

		/* If it was an indefinite-length object (no length was ever set) and
		   we've come back to the top level, exit */
		if( length == LENGTH_MAGIC )
			return( 0 );

		length -= stell( stream ) - lastPos;
		lastPos = stell( stream );
		if( isIndefinite )
			{
			if( seenEOC )
				return( STATE_NONE );
			}
		else
			if( length <= 0 )
				return( ( length < 0 ) ? STATE_ERROR : state );
		}

	return( STATE_NONE );
	}

/* Check the encoding of a complete object and determine its length */

int checkEncoding( const void *certObjectPtr, const int length )
	{
	STREAM stream;
	ASN1_STATE state;
	int dataLength;

	sMemConnect( &stream, certObjectPtr, length );
	state = checkASN1( &stream, LENGTH_MAGIC, FALSE, 1, STATE_NONE );
	dataLength = ( int ) stell( &stream );
	sMemDisconnect( &stream );
	return( ( state == STATE_ERROR ) ? CRYPT_ERROR_BADDATA : dataLength );
	}
