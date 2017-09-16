/****************************************************************************
*																			*
*					  Certificate Component Handling Routines				*
*						Copyright Peter Gutmann 1997-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* This module includes (somewhat complex) handling for GeneralNames and
   DN's, which are handled via indirect selection.  There are four classes
   of field types which cover these names:

	GNSelection	= EXCLUDEDSUBTREES | ...
	GN			= OTHERNAME | ... | DIRECTORYNAME
	DNSelection	= SUBJECTNAME | ISSUERNAME | DIRECTORYNAME
	DN			= C | O | OU | CN | ...

   Note that DIRECTORYNAME is present twice since it's both a component of a
   GeneralName and a DN in its own right.  GNSelection and DNSelection
   components merely select a composite component, the primitive elements are
   read and written via the GN and DN values.  The selection process is as
   follows:

	GNSelection --+	(default = subjectAltName)
				  |
				  v
				 GN -+----------------> non-DirectoryName field
					 |
				  +--+ DirectoryName
				  |
	DNSelection --+	(default = subjectName)
				  |
				  v
				 DN ------------------> DN field

   Selecting a component can therefore lead through a complex heirarchy of
   explicit and implied selections, in the worst case being something like
   subjectAltName -> directoryName -> DN field */

/****************************************************************************
*																			*
*								Utility Routines							*
*																			*
****************************************************************************/

/* Convert a binary OID to its text form */

int oidToText( const BYTE *binaryOID, char *oid )
	{
	char *outputPtr = oid;
	int i, j, length = binaryOID[ 1 ];
	long value;

	/* Pick apart the OID.  This assumes that no OID component will be
	   larger than LONG_MAX */
	i = binaryOID[ 2 ] / 40;
	j = binaryOID[ 2 ] % 40;
	if( i > 2 )
		{
		/* Handle special case for large j if i = 2 */
		j += ( i - 2 ) * 40;
		i = 2;
		}
#if ( defined( sun ) && OSVERSION == 4 )
	outputPtr += strlen( sprintf( outputPtr, "%d %d", i, j ) );
#else
	outputPtr += sprintf( outputPtr, "%d %d", i, j );
#endif /* SunOS braindamage */
	value = 0;
	for( i = 3; i < length + 2; i++ )
		{
		value = ( value << 7 ) | ( binaryOID[ i ] & 0x7F );
		if( !( binaryOID[ i ] & 0x80 ) )
			{
#if ( defined( sun ) && OSVERSION == 4 )
			outputPtr += strlen( sprintf( outputPtr, " %ld", value ) );
#else
			outputPtr += sprintf( outputPtr, " %ld", value );
#endif /* SunOS braindamage */
			value = 0;
			}

		/* Make sure we don't overflow the buffer (the value 20 is the
		   maximum magnitude of a 64-bit int plus space plus '\0') */
		if( outputPtr - oid > ( CRYPT_MAX_TEXTSIZE * 2 ) - 20 )
			return( CRYPT_ERROR_BADDATA );
		}
	length = strlen( oid );
	oid[ length ] = '\0';		/* Not really necessary, but nice */

	return( length );
	}

/* Check that a time value is valid */

static int checkTime( CERT_INFO *certInfoPtr, const CRYPT_ATTRIBUTE_TYPE type,
					  const time_t currentValue, const time_t newValue,
					  const int newValueLength )
	{
	/* Check to make sure the time given isn't before 1993, the start date
	   for X.509v2 (this is more of a consistency check than any real
	   requirement) */
	if( newValue < 0x2B3C0000L )
		{
		setErrorInfo( certInfoPtr, type, CRYPT_ERRTYPE_ATTR_VALUE );
		return( CRYPT_ARGERROR_STR1 );
		}
	if( newValueLength != sizeof( time_t ) )
		{
		setErrorInfo( certInfoPtr, type, CRYPT_ERRTYPE_ATTR_SIZE );
		return( CRYPT_ARGERROR_NUM1 );
		}
	if( currentValue )
		{
		setErrorInfo( certInfoPtr, type, CRYPT_ERRTYPE_ATTR_PRESENT );
		return( CRYPT_ERROR_INITED );
		}
	return( CRYPT_OK );
	}

/* Option codes for the GeneralName/DN selection functions */

typedef enum {
	SELECT_SELECT,			/* Remember current value */
	SELECT_INSTANTIATE_SET,	/* Instatiate remembered value, set pointer */
	SELECT_SET,				/* Set pointer from remembered value */
	SELECT_SYNC				/* Clear pointer from remembered value if item
							   deleted */
	} SELECT_OPTION;

/* Select a DN */

static int selectDN( CERT_INFO *certInfoPtr, const CRYPT_ATTRIBUTE_TYPE type,
					 const SELECT_OPTION option )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* If we're being asked to remember the setting, just save the value and
	   exit */
	if( option == SELECT_SELECT )
		{
		if( certInfoPtr->currentDN != type )
			certInfoPtr->currentDNptr = NULL;
		certInfoPtr->currentDN = type;
		return( CRYPT_OK );
		}

	/* If there's no selection made, default to the subject name */
	if( certInfoPtr->currentDN == CRYPT_ATTRIBUTE_NONE )
		certInfoPtr->currentDN = CRYPT_CERTINFO_SUBJECTNAME;

	/* If we're being asked to sync the value to the current setting, make
	   sure the entry is still present and clear the settings if not */
	if( option == SELECT_SYNC )
		{
		const CRYPT_ATTRIBUTE_TYPE dnType = ( type == CRYPT_ATTRIBUTE_NONE ) ? \
											certInfoPtr->currentDN : type;
		ATTRIBUTE_LIST *attributeListPtr;

		/* If the subject name isn't present but is selected or specified,
		   clear the selection.  We can never get a sync on an issuer name
		   since it's read-only */
		if( dnType == CRYPT_CERTINFO_SUBJECTNAME )
			{
			if( certInfoPtr->subjectName == NULL )
				{
				certInfoPtr->currentDN = CRYPT_ATTRIBUTE_NONE;
				certInfoPtr->currentDNptr = NULL;
				}
			return( CRYPT_OK );
			}

		/* It's a DN in an attribute, check that the attribute is still
		   present and clear the DN selection if not */
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
				certInfoPtr->currentGeneralName, CRYPT_CERTINFO_DIRECTORYNAME );
		if( attributeListPtr == NULL )
			{
			certInfoPtr->currentDN = CRYPT_ATTRIBUTE_NONE;
			certInfoPtr->currentDNptr = NULL;
			}
		return( CRYPT_OK );
		}

	/* If the DN is already selected, return now */
	if( certInfoPtr->currentDNptr != NULL )
		return( CRYPT_OK );

	/* The issuer and subject name fields are always present */
	if( certInfoPtr->currentDN == CRYPT_CERTINFO_ISSUERNAME )
		{
		certInfoPtr->currentDNptr = &certInfoPtr->issuerName;

		/* If it's a self-signed cert and the issuer name isn't explicitly
		   present then it must be implicitly present as the subject name */
		if( certInfoPtr->issuerName == NULL && certInfoPtr->selfSigned )
			certInfoPtr->currentDNptr = &certInfoPtr->subjectName;

		return( CRYPT_OK );
		}
	if( certInfoPtr->currentDN == CRYPT_CERTINFO_SUBJECTNAME )
		{
		certInfoPtr->currentDNptr = &certInfoPtr->subjectName;
		return( CRYPT_OK );
		}

	/* From here on we're handling a DN in a GeneralName.  If there's
	   currently no GeneralName selected, default to the subject altName */
	if( certInfoPtr->currentGeneralName == CRYPT_ATTRIBUTE_NONE )
		certInfoPtr->currentGeneralName = CRYPT_CERTINFO_SUBJECTALTNAME;

	/* Try and find the requested DN */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
										   certInfoPtr->currentGeneralName,
										   CRYPT_CERTINFO_DIRECTORYNAME );
	if( attributeListPtr == NULL )
		{
		int value = CRYPT_UNUSED, status;

		/* If it's not present and we're not being asked to instantiate it,
		   return an error */
		if( option != SELECT_INSTANTIATE_SET )
			return( CRYPT_ERROR_NOTINITED );

		/* We're being asked to instantiate the DN, create the attribute
		   field which contains it */
		status = addAttributeField( &certInfoPtr->attributes,
					certInfoPtr->currentGeneralName,
					CRYPT_CERTINFO_DIRECTORYNAME, &value, CRYPT_UNUSED,
					FALSE, FALSE, &certInfoPtr->errorLocus,
					&certInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );

		attributeListPtr = findAttributeField( certInfoPtr->attributes,
				certInfoPtr->currentGeneralName, CRYPT_CERTINFO_DIRECTORYNAME );
		}

	/* Obtain the DN pointer from the attribute field */
	certInfoPtr->currentDNptr = ( DN_COMPONENT ** ) &attributeListPtr->data;

	return( CRYPT_OK );
	}

/* Select a GeneralName */

static ATTRIBUTE_LIST *selectGeneralName( CERT_INFO *certInfoPtr,
										  const CRYPT_ATTRIBUTE_TYPE certInfoType,
										  const SELECT_OPTION option  )
	{
	/* If it's a sync, make sure the selected GeneralName is still present */
	if( option == SELECT_SYNC )
		{
		if( certInfoPtr->currentGeneralName != CRYPT_ATTRIBUTE_NONE && \
			findAttributeField( certInfoPtr->attributes, \
								certInfoPtr->currentGeneralName, \
								CRYPT_ATTRIBUTE_NONE ) == NULL )
			certInfoPtr->currentGeneralName = CRYPT_ATTRIBUTE_NONE;

		return( NULL );		/* Return value is ignored */
		}

	/* If it's a straight GeneralName selection, remember the setting and
	   clear any DN selection */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		if( certInfoPtr->currentGeneralName != certInfoType )
			{
			certInfoPtr->currentGeneralName = certInfoType;
			selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SELECT );
			}
		return( findAttributeField( certInfoPtr->attributes,
					certInfoPtr->currentGeneralName, CRYPT_ATTRIBUTE_NONE ) );
		}

	/* If there's no General Name selected, default to the subject altName */
	if( certInfoPtr->currentGeneralName == CRYPT_ATTRIBUTE_NONE )
		certInfoPtr->currentGeneralName = CRYPT_CERTINFO_SUBJECTALTNAME;

	/* If we're selecting a DirectoryName, pass the call down to the DN
	   selection to set things up at that level */
	if( certInfoType == CRYPT_CERTINFO_DIRECTORYNAME )
		{
		if( cryptStatusError( selectDN( certInfoPtr,
								CRYPT_CERTINFO_DIRECTORYNAME, option ) ) )
			return( NULL );
		}

	return( findAttributeField( certInfoPtr->attributes,
						certInfoPtr->currentGeneralName, certInfoType ) );
	}

/* Find a field in an attribute.  This returns a pointer to the attribute
   field containing the given GeneralName or GeneralName component, the given
   DN, or the given field */

static ATTRIBUTE_LIST *selectNameOrField( CERT_INFO *certInfoPtr,
										  const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	/* If it's a GeneralName selection component or a GeneralName component,
	   locate the attribute field which it corresponds to */
	if( isGeneralNameSelectionComponent( certInfoType ) || \
		isGeneralNameComponent( certInfoType ) )
		return( selectGeneralName( certInfoPtr, certInfoType, SELECT_SELECT ) );

	/* If it's a DN selection component, move to the DirectoryName within the
	   appropriate GeneralName */
	if( isDNSelectionComponent( certInfoType ) )
		return( selectGeneralName( certInfoPtr, certInfoType, SELECT_SELECT ) );

	/* It's a standard attribute field, try and locate it (if it's something
	   else which isn't allowed, we'll get a null pointer returned) */
	return( findAttributeField( certInfoPtr->attributes, certInfoType,
								CRYPT_ATTRIBUTE_NONE ) );
	}

/****************************************************************************
*																			*
*									Add a Component							*
*																			*
****************************************************************************/

/* Add a certificate component */

int addCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  const void *certInfo, const int certInfoLength )
	{
	int status = CRYPT_OK;

	/* If it's a certificate pseudo-component, update the certificate info */
	if( certInfoType >= CRYPT_FIRST_PSEUDOINFO && \
		certInfoType <= CRYPT_LAST_PSEUDOINFO )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		const int value = *( ( int * ) certInfo );

		/* General certificate flags */
		if( certInfoType == CRYPT_CERTINFO_SELFSIGNED )
			{
			certInfoPtr->selfSigned = ( value ) ? TRUE : FALSE;
			return( CRYPT_OK );
			}

		/* Trust information */
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_USAGE )
			{
			certInfoPtr->trustedUsage = value;
			return( CRYPT_OK );
			}
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_IMPLICIT )
			{
			if( value )
				return( addTrustInfo( certInfoPtr ) );
			return( deleteTrustInfo( certInfoPtr ) );
			}

		/* Component cursor movement isn't supported yet */
		if( certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT )
			return( CRYPT_ARGERROR_VALUE );

		/* Certificate cursor movement (which selects a cert in a cert
		   chain or entry in a CRL) */
		if( certInfoType == CRYPT_CERTINFO_CURRENT_CERTIFICATE )
			{
			const BOOLEAN isCertChain = ( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN ) ? \
										TRUE : FALSE;

			/* We can only select certs in a cert chain or CRL */
			if( !isCertChain && certInfoPtr->type != CRYPT_CERTTYPE_CRL )
				return( CRYPT_ARGERROR_OBJECT );

			switch( value )
				{
				case CRYPT_CURSOR_FIRST:
					if( isCertChain )
						certInfoPtr->certChainPos = CRYPT_ERROR;
					else
						{
						certInfoPtr->currentRevocation = certInfoPtr->revocations;
						if( certInfoPtr->currentRevocation == NULL )
							return( CRYPT_ERROR_NOTFOUND );
						}
					break;

				case CRYPT_CURSOR_PREVIOUS:
					if( isCertChain )
						{
						if( certInfoPtr->certChainPos == CRYPT_ERROR )
							return( CRYPT_ERROR_NOTFOUND );
						certInfoPtr->certChainPos--;
						}
					else
						{
						CRL_ENTRY *crlInfo = certInfoPtr->revocations;

						if( certInfoPtr->currentRevocation == NULL )
							return( CRYPT_ERROR_NOTFOUND );

						/* Find the previous element in the list */
						if( crlInfo != certInfoPtr->currentRevocation )
							while( crlInfo->next != certInfoPtr->currentRevocation )
								crlInfo = crlInfo->next;
						certInfoPtr->currentRevocation = crlInfo;
						}
					break;

				case CRYPT_CURSOR_NEXT:
					if( isCertChain )
						{
						if( certInfoPtr->certChainPos >= certInfoPtr->certChainEnd - 1 )
							return( CRYPT_ERROR_NOTFOUND );
						certInfoPtr->certChainPos++;
						}
					else
						{
						if( certInfoPtr->currentRevocation == NULL || \
							certInfoPtr->currentRevocation->next == NULL )
							return( CRYPT_ERROR_NOTFOUND );
						certInfoPtr->currentRevocation = certInfoPtr->currentRevocation->next;
						}
					break;

				case CRYPT_CURSOR_LAST:
					if( isCertChain )
						certInfoPtr->certChainPos = certInfoPtr->certChainEnd - 1;
					else
						{
						CRL_ENTRY *crlInfo = certInfoPtr->revocations;

						/* Go to the end of the list */
						if( crlInfo != NULL )
							while( crlInfo->next != NULL )
								crlInfo = crlInfo->next;
						if( crlInfo == NULL )
							return( CRYPT_ERROR_NOTFOUND );

						certInfoPtr->currentRevocation = crlInfo;
						}
					break;

				default:
					return( CRYPT_ARGERROR_NUM1 );
				}

			return( CRYPT_OK );
			}

		/* If the new position is specified relative to a previous position,
		   try and move to that position.  Note that the seemingly illogical
		   comparison is used because the cursor positioning codes are
		   negative values */
		if( value <= CRYPT_CURSOR_FIRST && value >= CRYPT_CURSOR_LAST )
			{
			BOOLEAN isField = ( certInfoType == CRYPT_CERTINFO_CURRENT_FIELD ) ? \
							  TRUE : FALSE;
			int status;

			/* If it's an absolute positioning code, reset the attribute
			   cursor to the start of the list before we try to move it */
			if( value == CRYPT_CURSOR_FIRST || value == CRYPT_CURSOR_LAST )
				certInfoPtr->attributeCursor = certInfoPtr->attributes;

			/* Move the attribute cursor */
			if( certInfoPtr->attributeCursor == NULL )
				{
				status = ( value == CRYPT_CURSOR_FIRST || \
						   value == CRYPT_CURSOR_LAST ) ? \
						 CRYPT_ERROR_NOTFOUND : CRYPT_ERROR_NOTINITED;
				return( status );
				}
			status = moveAttributeCursor( &certInfoPtr->attributeCursor,
										  isField, value );
			return( status );
			}

		/* It's an absolute attribute position, try and move to the
		   attribute */
		if( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION )
			{
			attributeListPtr = findAttribute( certInfoPtr->attributes, value );
			if( attributeListPtr == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->attributeCursor = attributeListPtr;
			return( CRYPT_OK );
			}

		/* It's an absolute field postion, try and move to the field */
		attributeListPtr = selectNameOrField( certInfoPtr, value );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->attributeCursor = attributeListPtr;
		return( CRYPT_OK );
		}

	/* We're adding data to a certificate, clear the error information */
	clearErrorInfo( certInfoPtr );

	/* If it's a public key, take a copy of the context for the certificates
	   use */
	if( certInfoType == CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO )
		{
		CRYPT_CONTEXT iCryptContext;

		/* Make sure we haven't already got a public key present */
		if( certInfoPtr->iCryptContext != CRYPT_ERROR )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* Get the context handle and make sure the context is of the correct
		   type */
		status = krnlSendMessage( *( ( CRYPT_HANDLE * ) certInfo ),
								  RESOURCE_MESSAGE_GETDEPENDENT, &iCryptContext,
								  OBJECT_TYPE_CONTEXT );
		if( cryptStatusOK( status ) )
			status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_CHECK,
									  NULL, RESOURCE_MESSAGE_CHECK_PKC );
		if( cryptStatusError( status ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( status );
			}

		/* Take a copy of the context for the certificate */
		status = krnlSendMessage( certInfoPtr->objectHandle,
								  RESOURCE_MESSAGE_SETDEPENDENT, 
								  &iCryptContext, TRUE );
		certInfoPtr->iCryptContext = iCryptContext;

		return( status );
		}

	/* If it's a cert request, copy the public key context and the DN and any
	   valid attributes.  If it's cert request formatting info, record it */
	if( certInfoType == CRYPT_CERTINFO_CERTREQUEST )
		{
		CRYPT_CERTIFICATE certRequest = *( ( CRYPT_CERTIFICATE * ) certInfo );
		CERT_INFO *certRequestInfoPtr;

		/* Make sure we haven't already got a public key or DN present */
		if( certInfoPtr->iCryptContext != CRYPT_ERROR || \
			certInfoPtr->subjectName != NULL )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CERTREQUEST,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
			return( CRYPT_ERROR_INITED );
			}

		/* Copy the public key context, the DN, and the attributes.  We copy 
		   the attributes across after the DN because that copy is the 
		   hardest to undo (if there are already attributes present, the 
		   copied attributes will be mixed in among them so it's not really 
		   possible to undo the copy later without performing a complex 
		   selective delete) */
		getCheckResource( certRequest, certRequestInfoPtr,
						  OBJECT_TYPE_CERTIFICATE, CRYPT_ARGERROR_NUM1 );
		if( certRequestInfoPtr->type != CRYPT_CERTTYPE_CERTREQUEST && \
			certRequestInfoPtr->type != CRYPT_CERTTYPE_CRMF_REQUEST && \
			certRequestInfoPtr->type != CRYPT_CERTTYPE_NS_SPKAC )
			unlockResourceExit( certRequestInfoPtr, CRYPT_ARGERROR_NUM1 );
		if( certRequestInfoPtr->type != CRYPT_CERTTYPE_NS_SPKAC )
			{
			status = copyDN( &certInfoPtr->subjectName,
							 certRequestInfoPtr->subjectName );
			if( cryptStatusOK( status ) )
				{
				status = copyAttributes( &certInfoPtr->attributes,
										 certRequestInfoPtr->attributes,
										 &certInfoPtr->errorLocus,
										 &certInfoPtr->errorType );
				if( cryptStatusError( status ) )
					deleteDN( &certInfoPtr->subjectName );
				}
			}
		if( cryptStatusOK( status ) )
			{
			/* The copies succeeded, add a reference from the cert to the 
			   context associated with the cert request */
			certInfoPtr->iCryptContext = certRequestInfoPtr->iCryptContext;
			krnlSendMessage( certInfoPtr->objectHandle, 
							 RESOURCE_MESSAGE_SETDEPENDENT, 
							 &certRequestInfoPtr->iCryptContext, TRUE );
			}
		unlockResourceExit( certRequestInfoPtr, status );
		}

	/* If it's a certificate, copy the cert serial number across (for a CRL)
	   or store the whole thing (for a cert chain) */
	if( certInfoType == CRYPT_CERTINFO_USERCERTIFICATE )
		{
		CRYPT_CERTIFICATE userCert = *( ( CRYPT_HANDLE * ) certInfo );
		CERT_INFO *userCertInfoPtr;

		/* If it's a cert chain, just store the new cert and exit */
		if( certInfoPtr->type == CRYPT_CERTTYPE_CERTCHAIN )
			{
			int i;

			if( certInfoPtr->certChainEnd >= MAX_CHAINLENGTH )
				return( CRYPT_ERROR_OVERFLOW );

			/* Perform a simple check to make sure it hasn't been added
			   already */
			for( i = 0; i < certInfoPtr->certChainEnd; i++ )
				if( certInfoPtr->certChain[ i ] == userCert )
					{
					setErrorInfo( certInfoPtr, CRYPT_CERTINFO_USERCERTIFICATE,
								  CRYPT_ERRTYPE_ATTR_PRESENT );
					return( CRYPT_ERROR_INITED );
					}

			/* Make sure the cert object contains an encoded certificate
			   ready for use */
			status = krnlSendMessage( userCert, RESOURCE_MESSAGE_GETDEPENDENT,
									  &userCert, OBJECT_TYPE_CERTIFICATE );
			if( cryptStatusError( status ) )
				return( status );
			getCheckInternalResource( userCert, userCertInfoPtr,
									  OBJECT_TYPE_CERTIFICATE );
			if( userCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
				userCertInfoPtr->type != CRYPT_CERTTYPE_CERTCHAIN )
				/* Must be either a straight certificate or the certificate
				   at the start of a cert chain */
				status = CRYPT_ARGERROR_NUM1;
			else
				if( userCertInfoPtr->certificate == NULL )
					status = CRYPT_ERROR_NOTINITED;	/* Must be ready for use */
			unlockResource( userCertInfoPtr );
			if( cryptStatusError( status ) )
				return( status );

			/* Add the user cert and increment its reference count */
			krnlSendNotifier( userCert, RESOURCE_MESSAGE_INCREFCOUNT );
			certInfoPtr->certChain[ certInfoPtr->certChainEnd++ ] = userCert;
			return( CRYPT_OK );
			}

		/* Make sure we've been passed a cert to revoke */
		status = krnlSendMessage( userCert, RESOURCE_MESSAGE_GETDEPENDENT,
								  &userCert, OBJECT_TYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		getCheckInternalResource( userCert, userCertInfoPtr,
								  OBJECT_TYPE_CERTIFICATE );
		if( userCertInfoPtr->type != CRYPT_CERTTYPE_CERTIFICATE && \
			userCertInfoPtr->type != CRYPT_CERTTYPE_ATTRIBUTE_CERT )
			unlockResourceExit( userCertInfoPtr, CRYPT_ARGERROR_NUM1 );

		/* If there's an issuer name recorded in the CRL, make sure it
		   matches the one in the cert which is being added */
		if( certInfoPtr->issuerName != NULL && \
			!compareDN( certInfoPtr->issuerName, userCertInfoPtr->issuerName,
						FALSE ) )
			{
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			unlockResourceExit( userCertInfoPtr, CRYPT_ERROR_INVALID );
			}

		/* Add the cert to the CRL and make it the currently selected entry */
		status = addCRLEntry( &certInfoPtr->revocations,
					&certInfoPtr->currentRevocation, userCertInfoPtr->issuerName,
					userCertInfoPtr->serialNumber, userCertInfoPtr->serialNumberLength );
		if( status == CRYPT_ERROR_INITED )
			/* If this cert is already present in the list, set the extended
			   error code for it */
			setErrorInfo( certInfoPtr, CRYPT_CERTINFO_USERCERTIFICATE,
						  CRYPT_ERRTYPE_ATTR_PRESENT );
		if( cryptStatusError( status ) )
			unlockResourceExit( userCertInfoPtr, status );

		/* If there's no issuer name present yet, set the CRL issuer name to
		   the certs issuer to make sure we can't add certs or sign the CRL
		   with a different issuer */
		if( certInfoPtr->issuerName == NULL )
			status = copyDN( &certInfoPtr->issuerName,
							 userCertInfoPtr->issuerName );

		unlockResourceExit( userCertInfoPtr, status );
		}

	/* If it's a GeneralName or DN selection command, set up the selection */
	if( isGeneralNameSelectionComponent( certInfoType ) || \
		isDNSelectionComponent( certInfoType ) )
		{
		if( *( ( int * ) certInfo ) != CRYPT_UNUSED )
			return( CRYPT_ARGERROR_NUM1 );

		/* If it's a built-in DN, it's a straight selection */
		if( certInfoType == CRYPT_CERTINFO_SUBJECTNAME || \
			certInfoType == CRYPT_CERTINFO_ISSUERNAME )
			selectDN( certInfoPtr, certInfoType, SELECT_SELECT );
		else
			/* It's a GeneralName or a DN in a GeneralName, remember it */
			selectGeneralName( certInfoPtr, certInfoType, SELECT_SELECT );

		return( CRYPT_OK );
		}

	/* If it's a GeneralName component, add it to the current GeneralName */
	if( isGeneralNameComponent( certInfoType ) )
		{
		selectGeneralName( certInfoPtr, certInfoPtr->currentGeneralName,
						   SELECT_SELECT );
		return( addAttributeField( &certInfoPtr->attributes,
				certInfoPtr->currentGeneralName, certInfoType, certInfo,
				certInfoLength, FALSE, FALSE, &certInfoPtr->errorLocus,
				&certInfoPtr->errorType ) );
		}

	/* If it's a DN component, add it to the DN */
	if( isDNComponent( certInfoType ) )
		{
		ASN1_STRINGTYPE stringType;
		BYTE dnString[ ( CRYPT_MAX_TEXTSIZE + 1 ) * 2 ];
		int dnStringLength, status;

		/* Copy the string to the internal format */
		stringType = copyConvertString( certInfo, certInfoLength, dnString,
										&dnStringLength, CRYPT_MAX_TEXTSIZE,
										FALSE, FALSE );
		if( stringType == STRINGTYPE_NONE )
			{
			/* The copy can only fail if the data is too large */
			setErrorInfo( certInfoPtr, certInfoType, 
						  CRYPT_ERRTYPE_ATTR_SIZE );
			return( CRYPT_ARGERROR_NUM1 );
			}

		/* Add the string component to the DN */
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE,
						   SELECT_INSTANTIATE_SET );
		if( cryptStatusOK( status ) )
			status = insertDNComponent( certInfoPtr->currentDNptr,
										certInfoType, dnString,
										dnStringLength, stringType, FALSE,
										&certInfoPtr->errorType );
		if( cryptStatusError( status ) && status != CRYPT_ERROR_MEMORY )
			certInfoPtr->errorLocus = certInfoType;
		return( status );
		}

	/* If it's time information, set it.  We check to make sure the time
	   given isn't before 1993, the start date for X.509v2 (this is more of
	   a consistency check than any real requirement) and that we don't have
	   a negative validity period */
	if( certInfoType == CRYPT_CERTINFO_VALIDFROM || \
		certInfoType == CRYPT_CERTINFO_THISUPDATE )
		{
		time_t certTime = *( ( time_t * ) certInfo );

		status = checkTime( certInfoPtr, certInfoType, certInfoPtr->startTime,
							certTime, certInfoLength );
		if( cryptStatusError( status ) )
			return( status );
		if( certInfoPtr->endTime && certTime >= certInfoPtr->endTime )
			{
			setErrorInfo( certInfoPtr,
						  ( certInfoType == CRYPT_CERTINFO_VALIDFROM ) ? \
							CRYPT_CERTINFO_VALIDTO : CRYPT_CERTINFO_NEXTUPDATE,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ARGERROR_STR1 );
			}
		certInfoPtr->startTime = certTime;
		return( CRYPT_OK );
		}
	if( certInfoType == CRYPT_CERTINFO_VALIDTO || \
		certInfoType == CRYPT_CERTINFO_NEXTUPDATE )
		{
		time_t certTime = *( ( time_t * ) certInfo );

		status = checkTime( certInfoPtr, certInfoType, certInfoPtr->endTime,
							certTime, certInfoLength );
		if( cryptStatusError( status ) )
			return( status );
		if( certInfoPtr->startTime && certTime <= certInfoPtr->startTime )
			{
			setErrorInfo( certInfoPtr,
						  ( certInfoType == CRYPT_CERTINFO_VALIDTO ) ? \
							CRYPT_CERTINFO_VALIDFROM : CRYPT_CERTINFO_THISUPDATE,
						  CRYPT_ERRTYPE_CONSTRAINT );
			return( CRYPT_ARGERROR_STR1 );
			}
		certInfoPtr->endTime = certTime;
		return( CRYPT_OK );
		}
	if( certInfoType == CRYPT_CERTINFO_REVOCATIONDATE )
		{
		time_t certTime = *( ( time_t * ) certInfo ), *revocationTimePtr;

		status = checkTime( certInfoPtr, certInfoType, certInfoPtr->startTime,
							certTime, certInfoLength );
		if( cryptStatusError( status ) )
			return( status );

		/* If there's a specific revoked cert selected, set its revocation
		   time, otherwise if there are revoked certs present set the first
		   certs revocation time otherwise set the default revocation time */
		revocationTimePtr = ( certInfoPtr->currentRevocation != NULL ) ? \
							&certInfoPtr->currentRevocation->revocationTime : \
							( certInfoPtr->revocations != NULL ) ? \
							&certInfoPtr->revocations->revocationTime : \
								&certInfoPtr->revocationTime;
		*revocationTimePtr = certTime;
		return( CRYPT_OK );
		}

	/* If it's a known attribute, add it to the certificate */
	if( ( certInfoType >= CRYPT_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_FIRST_CMS && \
		  certInfoType <= CRYPT_LAST_CMS ) )
		{
		/* If it's a CRL per-entry attribute, add the attribute to the
		   currently selected entry */
		if( isCRLEntryComponent( certInfoType ) )
			{
			if( certInfoPtr->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			return( addAttributeField( &certInfoPtr->currentRevocation->attributes,
				certInfoType, CRYPT_ATTRIBUTE_NONE, certInfo, certInfoLength,
				FALSE, FALSE, &certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
			}

		return( addAttributeField( &certInfoPtr->attributes,
				certInfoType, CRYPT_ATTRIBUTE_NONE, certInfo, certInfoLength,
				FALSE, FALSE, &certInfoPtr->errorLocus, &certInfoPtr->errorType ) );
		}

	/* Everything else isn't available */
	return( CRYPT_ARGERROR_VALUE );
	}

/****************************************************************************
*																			*
*									Get a Component							*
*																			*
****************************************************************************/

/* Get a certificate component */

static int getCertAttributeComponentData( const ATTRIBUTE_LIST *attributeListPtr,
										  void *certInfo, int *certInfoLength )
	{
	/* If the data type is an OID, we have to convert it to a human-readable
	   form before we return it */
	if( attributeListPtr->fieldType == BER_OBJECT_IDENTIFIER )
		{
		char textOID[ CRYPT_MAX_TEXTSIZE * 2 ];
		int length;

		length = oidToText( attributeListPtr->smallData, textOID );
		*certInfoLength = length;
		if( certInfo != NULL )
			{
			if( checkBadPtrWrite( certInfo, strlen( textOID ) ) )
				return( CRYPT_ARGERROR_STR1 );
			memcpy( certInfo, textOID, length );
			}

		return( CRYPT_OK );
		}

	/* If it's a basic data value, copy it over as an integer */
	if( !attributeListPtr->dataLength )
		*( ( int * ) certInfo ) = ( int ) attributeListPtr->value;
	else
		{
		/* It's a more complex data type, copy it across either from the
		   small buffer in the attribute list entry or from an external
		   buffer */
		*certInfoLength = attributeListPtr->dataLength;
		if( certInfo != NULL )
			{
			if( checkBadPtrWrite( certInfo, attributeListPtr->dataLength ) )
				return( CRYPT_ARGERROR_STR1 );
			memcpy( certInfo, ( attributeListPtr->data != NULL ) ? \
					attributeListPtr->data : attributeListPtr->smallData,
					attributeListPtr->dataLength );
			}
		}

	return( CRYPT_OK );
	}

static int getCertAttributeComponent( CERT_INFO *certInfoPtr,
									  const CRYPT_ATTRIBUTE_TYPE certInfoType,
									  void *certInfo, int *certInfoLength )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* Try and find this attribute in the attribute list */
	if( isCRLEntryComponent( certInfoType ) )
		{
		/* It's a CRL per-entry attribute, get the attribute from the
		   currently selected entry */
		if( certInfoPtr->currentRevocation == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		attributeListPtr = findAttributeFieldEx( \
				certInfoPtr->currentRevocation->attributes, certInfoType );
		}
	else
		attributeListPtr = findAttributeFieldEx( certInfoPtr->attributes,
												 certInfoType );
	if( attributeListPtr == NULL )
		return( CRYPT_ERROR_NOTFOUND );

	/* If this is a non-present field in a present attribute with a default
	   value for the field, return that */
	if( isDefaultFieldValue( attributeListPtr ) )
		{
		*( ( int * ) certInfo ) = getDefaultFieldValue( certInfoType );
		return( CRYPT_OK );
		}

	/* If this is a non-present field in a present attribute which denotes
	   an entire (constructed) attribute, return a boolean indicating its
	   presence */
	if( isCompleteAttribute( attributeListPtr ) )
		{
		*( ( int * ) certInfo ) = TRUE;
		return( CRYPT_OK );
		}

	return( getCertAttributeComponentData( attributeListPtr, certInfo,
										   certInfoLength ) );
	}

/* Get a certificate component */

int getCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  void *certInfo, int *certInfoLength )
	{
	BOOLEAN returnData = ( certInfo != NULL ) ? TRUE : FALSE;
	void *data;
	int *valuePtr = ( int * ) certInfo;
	int dataLength = CRYPT_ERROR;

	/* If it's a certificate pseudo-component, return information on it */
	if( certInfoType >= CRYPT_FIRST_PSEUDOINFO && \
		certInfoType <= CRYPT_LAST_PSEUDOINFO )
		{
		/* The fingerprints are string components unlike all the others */
		if( certInfoType == CRYPT_CERTINFO_FINGERPRINT_MD5 || \
			certInfoType == CRYPT_CERTINFO_FINGERPRINT_SHA )
			{
			const CRYPT_ALGO cryptAlgo = \
					( certInfoType == CRYPT_CERTINFO_FINGERPRINT_MD5 ) ? \
					CRYPT_ALGO_MD5 : CRYPT_ALGO_SHA;
			HASHFUNCTION hashFunction;
			int hashSize;

			/* Get the hash algorithm information */
			getHashParameters( cryptAlgo, &hashFunction, &hashSize );
			*certInfoLength = hashSize;
			if( !returnData )
				return( CRYPT_OK );

			/* Write the hash (fingerprint) to the output */
			if( checkBadPtrWrite( certInfo, hashSize ) )
				return( CRYPT_ARGERROR_STR1 );
			if( certInfoPtr->certificate == NULL )
				return( CRYPT_ERROR_NOTINITED );
			hashFunction( NULL, certInfo, certInfoPtr->certificate,
						  certInfoPtr->certificateSize, HASH_ALL );
			return( CRYPT_OK );
			}

		if( certInfoType == CRYPT_CERTINFO_SELFSIGNED )
			*valuePtr = certInfoPtr->selfSigned;
		if( certInfoType == CRYPT_CERTINFO_IMMUTABLE )
			*valuePtr = ( certInfoPtr->certificate != NULL ) ? TRUE: FALSE;
		if( certInfoType == CRYPT_CERTINFO_CERTTYPE )
			/* Return the object type, converting a physical SPKAC into a
			   logical certRequest if necessary */
			*valuePtr = ( certInfoPtr->type == CRYPT_CERTTYPE_NS_SPKAC ) ? \
						CRYPT_CERTTYPE_CERTREQUEST : certInfoPtr->type;
		if( isCursorComponent( certInfoType ) )
			{
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTINITED );
			if( certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT )
				/* Components aren't supported yet */
				return( CRYPT_ARGERROR_VALUE );
			*valuePtr = ( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION ) ? \
						certInfoPtr->attributeCursor->attributeID :
						certInfoPtr->attributeCursor->fieldID;
			}
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_USAGE )
			{
			if( certInfoPtr->trustedUsage == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
			*valuePtr = certInfoPtr->trustedUsage;
			}
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_IMPLICIT )
			*valuePtr = checkCertTrusted( certInfoPtr );

		return( CRYPT_OK );
		}

	/* Return various easy-to-handle string resources */
	switch( certInfoType )
		{
		case CRYPT_CERTINFO_SERIALNUMBER:
			if( certInfoPtr->type == CRYPT_CERTTYPE_CRL )
				{
				const CRL_ENTRY *crlInfoPtr = \
					( certInfoPtr->currentRevocation != NULL ) ? \
					certInfoPtr->currentRevocation : certInfoPtr->revocations;

				dataLength = ( crlInfoPtr != NULL ) ? \
							 crlInfoPtr->serialNumberLength : 0;
				data = ( crlInfoPtr != NULL ) ? crlInfoPtr->serialNumber : NULL;
				}
			else
				{
				dataLength = certInfoPtr->serialNumberLength;
				data = certInfoPtr->serialNumber;
				}
			break;

		case CRYPT_CERTINFO_VALIDFROM:
		case CRYPT_CERTINFO_THISUPDATE:
			dataLength = sizeof( time_t );
			data = &certInfoPtr->startTime;
			break;

		case CRYPT_CERTINFO_VALIDTO:
		case CRYPT_CERTINFO_NEXTUPDATE:
			dataLength = sizeof( time_t );
			data = &certInfoPtr->endTime;
			break;

		case CRYPT_CERTINFO_REVOCATIONDATE:
			/* If there's a specific revoked cert selected, get its
			   revocation time, otherwise if there are revoked certs present
			   get the first certs revocation time otherwise get the
			   default revocation time */
			data = ( certInfoPtr->currentRevocation != NULL ) ? \
				   &certInfoPtr->currentRevocation->revocationTime : \
				   ( certInfoPtr->revocations != NULL ) ? \
				   &certInfoPtr->revocations->revocationTime : \
				   ( certInfoPtr->revocationTime ) ? \
				   &certInfoPtr->revocationTime : NULL;
			dataLength = ( data != NULL ) ? sizeof( time_t ) : 0;
			break;

		case CRYPT_CERTINFO_ISSUERUNIQUEID:
			dataLength = certInfoPtr->issuerUniqueIDlength;
			data = certInfoPtr->issuerUniqueID;
			break;

		case CRYPT_CERTINFO_SUBJECTUNIQUEID:
			dataLength = certInfoPtr->subjectUniqueIDlength;
			data = certInfoPtr->subjectUniqueID;
			break;
		}
	if( dataLength != CRYPT_ERROR )
		{
		if( !dataLength )
			return( CRYPT_ERROR_NOTINITED );
		*certInfoLength = dataLength;
		if( returnData )
			{
			if( checkBadPtrWrite( certInfo, dataLength ) )
				return( CRYPT_ARGERROR_STR1 );
			memcpy( certInfo, data, dataLength );
			}
		return( CRYPT_OK );
		}

	/* If it's a GeneralName or DN selection, return information on it */
	if( isGeneralNameSelectionComponent( certInfoType ) || \
		isDNSelectionComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		/* If it's a fixed DN, return information on it */
		if( certInfoType == CRYPT_CERTINFO_ISSUERNAME )
			{
			*valuePtr = ( certInfoPtr->issuerName != NULL ) ? TRUE : FALSE;
			return( CRYPT_OK );
			}
		if( certInfoType == CRYPT_CERTINFO_SUBJECTNAME )
			{
			*valuePtr = ( certInfoPtr->subjectName != NULL ) ? TRUE : FALSE;
			return( CRYPT_OK );
			}

		/* Determine whether the given component is present or not */
		attributeListPtr = selectGeneralName( certInfoPtr, certInfoType,
											  SELECT_SET );
		*valuePtr = ( attributeListPtr != NULL ) ? TRUE : FALSE;
		return( CRYPT_OK );
		}

	/* If it's a GeneralName component, find it in the current General Name
	   and return its value */
	if( isGeneralNameComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		/* Find the requested GeneralName component and return it to the
		   caller.  We don't have to deal with the special-case DirectoryName
		   since it's already handled above as a DN selection component */
		attributeListPtr = selectGeneralName( certInfoPtr, certInfoType,
											  SELECT_SET );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		return( getCertAttributeComponentData( attributeListPtr, certInfo,
											   certInfoLength ) );
		}

	/* If it's a DN component, find it in the DN and return its value */
	if( isDNComponent( certInfoType ) )
		{
		DN_COMPONENT *dnComponent = NULL;
		int status;

		/* Find the requested DN component and return it to the caller */
		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SET );
		if( cryptStatusOK( status ) )
			dnComponent = findDNComponent( *certInfoPtr->currentDNptr,
										   certInfoType, NULL, 0 );
		if( dnComponent == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		*certInfoLength = dnComponent->valueLength;
		if( returnData )
			{
			if( checkBadPtrWrite( certInfo, dnComponent->valueLength ) )
				return( CRYPT_ARGERROR_STR1 );
			memcpy( certInfo, dnComponent->value, dnComponent->valueLength );
			}

		return( CRYPT_OK );
		}

	/* If it's a known attribute, return it */
	if( ( certInfoType >= CRYPT_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_FIRST_CMS && \
		  certInfoType <= CRYPT_LAST_CMS ) )
		{
		int status;

		status = getCertAttributeComponent( certInfoPtr, certInfoType,
											certInfo, certInfoLength );
		return( status );
		}

	/* Everything else isn't available */
	return( CRYPT_ARGERROR_VALUE );
	}

/****************************************************************************
*																			*
*								Delete a Component							*
*																			*
****************************************************************************/

/* Delete a certificate component */

int deleteCertComponent( CERT_INFO *certInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE certInfoType )
	{
	/* If it's a certificate pseudo-component, delete it */
	if( certInfoType >= CRYPT_FIRST_PSEUDOINFO && \
		certInfoType <= CRYPT_LAST_PSEUDOINFO )
		{
		if( certInfoType == CRYPT_CERTINFO_SELFSIGNED )
			{
			if( !certInfoPtr->selfSigned )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->selfSigned = FALSE;
			}
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_USAGE )
			{
			if( certInfoPtr->trustedUsage == CRYPT_ERROR )
				return( CRYPT_ERROR_NOTFOUND );
			certInfoPtr->trustedUsage = CRYPT_ERROR;
			}
		if( certInfoType == CRYPT_CERTINFO_TRUSTED_IMPLICIT )
			return( deleteTrustInfo( certInfoPtr ) );
		if( isCursorComponent( certInfoType ) )
			{
			if( certInfoPtr->attributeCursor == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			if( certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT )
				/* Components aren't supported yet */
				return( CRYPT_ARGERROR_VALUE );
			if( certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION )
				deleteAttribute( &certInfoPtr->attributes,
								 &certInfoPtr->attributeCursor,
								 certInfoPtr->attributeCursor );
			else
				deleteAttributeField( &certInfoPtr->attributes,
									  &certInfoPtr->attributeCursor,
									  certInfoPtr->attributeCursor );

			/* Sync the GeneralName and DN selection in case we deleted the
			   attribute with the selected GeneralName or DN */
			selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
			selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
			}
		return( CRYPT_OK );
		}

	/* If it's a GeneralName, delete all the fields in it */
	if( isGeneralNameSelectionComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		/* Check whether this GeneralName is present */
		attributeListPtr = findAttributeField( certInfoPtr->attributes,
										certInfoType, CRYPT_ATTRIBUTE_NONE );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );

		/* Delete each field in the GeneralName */
		while( attributeListPtr != NULL )
			{
			deleteAttributeField( &certInfoPtr->attributes,
								  &certInfoPtr->attributeCursor,
								  attributeListPtr );
			attributeListPtr = findAttributeField( certInfoPtr->attributes,
										certInfoType, CRYPT_ATTRIBUTE_NONE );
			}

		/* Sync the GeneralName and DN selection in case we deleted the
		   selected GeneralName or DN */
		selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
		selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );

		return( CRYPT_OK );
		}

	/* If it's a GeneralName component, delete it from the currently selected
	   GeneralName */
	if( isGeneralNameComponent( certInfoType ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;

		/* Try and find the field in the current GeneralName */
		attributeListPtr = selectGeneralName( certInfoPtr, certInfoType,
											  SELECT_SET );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );

		/* Delete the field and sync the GeneralName and DN selections in
		   case we deleted the attribute with the selected GeneralName and
		   DN */
		deleteAttributeField( &certInfoPtr->attributes,
							  &certInfoPtr->attributeCursor,
							  attributeListPtr );
		selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
		selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );

		return( CRYPT_OK );
		}

	/* If it's the subject DN, delete it and sync the DN selection */
	if( certInfoType == CRYPT_CERTINFO_SUBJECTNAME )
		{
		deleteDN( &certInfoPtr->subjectName );
		selectDN( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME, SELECT_SYNC );
		}

	/* If it's a DN component, delete it from the DN and sync the
	   GeneralName/DN selection */
	if( isDNComponent( certInfoType ) )
		{
		int status;

		status = selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SET );
		if( cryptStatusOK( status ) )
			{
			status = deleteDNComponent( certInfoPtr->currentDNptr,
										certInfoType, NULL, 0 );
			selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
			selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
			}
		return( status );
		}

	/* If it's time information, clear it */
	if( certInfoType == CRYPT_CERTINFO_VALIDFROM || \
		certInfoType == CRYPT_CERTINFO_THISUPDATE )
		{
		if( !certInfoPtr->startTime )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->startTime = 0;
		return( CRYPT_OK );
		}
	if( certInfoType == CRYPT_CERTINFO_VALIDTO || \
		certInfoType == CRYPT_CERTINFO_VALIDFROM )
		{
		if( !certInfoPtr->endTime )
			return( CRYPT_ERROR_NOTFOUND );
		certInfoPtr->endTime = 0;
		return( CRYPT_OK );
		}
	if( certInfoType == CRYPT_CERTINFO_REVOCATIONDATE )
		{
		time_t *revocationTimePtr;

		/* If there's a specific revoked cert selected, delete its revocation
		   time, otherwise if there are revoked certs present delete the
		   first certs revocation time otherwise delete the default
		   revocation time */
		revocationTimePtr = ( certInfoPtr->currentRevocation != NULL ) ? \
							&certInfoPtr->currentRevocation->revocationTime : \
							( certInfoPtr->revocations != NULL ) ? \
							&certInfoPtr->revocations->revocationTime : \
							( certInfoPtr->revocationTime ) ? \
							&certInfoPtr->revocationTime : NULL;
		if( revocationTimePtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		*revocationTimePtr = 0;
		return( CRYPT_OK );
		}

	/* If it's a known attribute, delete it */
	if( ( certInfoType >= CRYPT_FIRST_EXTENSION && \
		  certInfoType <= CRYPT_LAST_EXTENSION ) || \
		( certInfoType >= CRYPT_FIRST_CMS && \
		  certInfoType <= CRYPT_LAST_CMS ) )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		const BOOLEAN isCRLEntry = isCRLEntryComponent( certInfoType ) ? \
								   TRUE : FALSE;

		if( isCRLEntry )
			{
			/* It's a CRL per-entry attribute, look for the attribute in the
			   currently selected entry */
			if( certInfoPtr->currentRevocation == NULL )
				return( CRYPT_ERROR_NOTFOUND );
			attributeListPtr = findAttributeFieldEx( \
				certInfoPtr->currentRevocation->attributes, certInfoType );
			}
		else
			attributeListPtr = findAttributeFieldEx( certInfoPtr->attributes,
													 certInfoType );
		if( attributeListPtr == NULL )
			return( CRYPT_ERROR_NOTFOUND );
		if( isDefaultFieldValue( attributeListPtr ) )
			/* This is a non-present field in a present attribute with a
			   default value for the field.  There isn't really any
			   satisfactory return code for this case, returning CRYPT_OK is
			   wrong because the caller can keep deleting the same field, and
			   return CRYPT_NOTFOUND is wrong because the caller may have
			   added the attribute at an earlier date but it was never
			   written to the cert/CRL because it had the default value, so
			   that to the caller it appears that the field they added has
			   been lost.  For now we return CRYPT_OK */
			return( CRYPT_OK );
		if( isCompleteAttribute( attributeListPtr ) )
			{
			ATTRIBUTE_LIST attributeListItem;

			/* This is a non-present field in a present attribute which
			   denotes an entire (constructed) attribute, create a special
			   list pseudo-entry to convey this and delete the entire
			   attribute */
			memcpy( &attributeListItem, attributeListPtr, sizeof( ATTRIBUTE_LIST ) );
			attributeListItem.value = certInfoType;
			if( isCRLEntry )
				deleteAttribute( &certInfoPtr->currentRevocation->attributes,
								 &certInfoPtr->attributeCursor,
								 &attributeListItem );
			else
				deleteAttribute( &certInfoPtr->attributes,
								 &certInfoPtr->attributeCursor,
								 &attributeListItem );
			}
		else
			/* It's a single field, delete that */
			if( isCRLEntry )
				deleteAttributeField( &certInfoPtr->currentRevocation->attributes,
									  &certInfoPtr->attributeCursor,
									  attributeListPtr );
			else
				deleteAttributeField( &certInfoPtr->attributes,
									  &certInfoPtr->attributeCursor,
									  attributeListPtr );

		/* Sync the GeneralName and DN selections in case we deleted the
		   attribute with the selected GeneralName and DN */
		selectGeneralName( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );
		selectDN( certInfoPtr, CRYPT_ATTRIBUTE_NONE, SELECT_SYNC );

		return( CRYPT_OK );
		}

	/* Everything else is an error */
	return( CRYPT_ARGERROR_VALUE );
	}
