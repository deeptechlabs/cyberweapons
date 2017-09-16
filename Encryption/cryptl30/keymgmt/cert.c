/****************************************************************************
*																			*
*						 Certificate Management Routines					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1objs.h"
  #include "asn1oid.h"
  #include "cert.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
#endif /* Compiler-specific includes */

/* The X.509v2 (for CRL's) and X.509v3 (for certificates) version numbers */

#define X509V2_VERSION		1
#define X509V3_VERSION		2

/* The DN is usually short, so we try and use static buffers where we can and
   only dynamically allocate buffers if it's necessary (a DN can in theory
   include a 2GB MPEG of the owner playing with their cat, but most don't).
   The following value is the threshold for which we use dynamically-
   allocated buffers for the DN.  The reason for doing this is that when
   processing a lot of keys at once, we'll be constantly allocating and
   freeing DN buffers in things like the cert ID generation function, where
   a stack-based fixed buffer will do 99% of the time */

#if defined( __MSDOS16__ ) || ( defined( __WIN32__ ) && defined( NT_KERNEL ) )
  #define DN_BUFFER_SIZE	512
#else
  #define DN_BUFFER_SIZE	2048
#endif /* DN buffer size defines */

/* Context-specific tags for certificates */

enum { CTAG_CE_VERSION, CTAG_CE_ISSUERUNIQUEID, CTAG_CE_SUBJECTUNIQUEID,
	   CTAG_CE_EXTENSIONS };

/* Context-specific tags for attribute certificates */

enum { CTAG_AC_BASECERTIFICATEID, CTAG_AC_ENTITYNAME,
	   CTAG_AC_OBJECTDIGESTINFO };

/* Context-specific tags for certification requests */

enum { CTAG_CR_ATTRIBUTES };

/* Context-specific tags for CRMF certification requests */

enum { CTAG_CF_VERSION, CTAG_CF_SERIALNUMBER, CTAG_CF_SIGNINGALG, 
	   CTAG_CF_ISSUER, CTAG_CF_VALIDITY, CTAG_CF_SUBJECT, CTAG_CF_PUBLICKEY,
	   CTAG_CF_ISSUERUID, CTAG_CF_SUBJECTUID, CTAG_CF_EXTENSIONS };

/* Prototypes for functions in certchk.c */

int getKeyUsageFlags( CERT_INFO *certInfoPtr, BOOLEAN *isCA );

/* Prototypes for functions in certstr.c */

int convertEmailAddress( CERT_INFO *certInfoPtr );

/****************************************************************************
*																			*
*									CertID Functions						*
*																			*
****************************************************************************/

/* Determine the size of a CertID */

int sizeofCertID( const CERT_INFO *certInfo )
	{
	return( ( int ) sizeofObject( \
				sizeofAlgoID( CRYPT_ALGO_SHA ) +
				sizeofObject( 20 ) + sizeofObject( 20 ) +
				sizeofInteger( certInfo->serialNumber,
							   certInfo->serialNumberLength ) ) );
	}

/* Write a certID */

int writeCertID( STREAM *stream, const CERT_INFO *certInfo )
	{
	BYTE buffer[ 20 ];
	int status;

	writeSequence( stream,
		sizeofAlgoID( CRYPT_ALGO_SHA ) +
		( int ) sizeofObject( 20 ) + ( int ) sizeofObject( 20 ) +
		sizeofInteger( certInfo->serialNumber,
					   certInfo->serialNumberLength ) );
	writeAlgoID( stream, CRYPT_ALGO_SHA );
	writeOctetString( stream, buffer, 20, DEFAULT_TAG );
	writeOctetString( stream, buffer, 20, DEFAULT_TAG );
	status = writeInteger( stream, certInfo->serialNumber,
						   certInfo->serialNumberLength, DEFAULT_TAG );
	return( status );
	}

/* Read a CertID */

int readCertID( STREAM *stream )
	{
	CRYPT_ALGO cryptAlgo;
	BYTE buffer[ 20 ];
	int length, status;

	/* Check the header and make sure the hash algorithm is one we can use */
	readSequence( stream, NULL );
	status = readAlgoID( stream, &cryptAlgo );
	if( cryptStatusError( status ) )
		return( status );
	if( cryptAlgo != CRYPT_ALGO_SHA )
		return( CRYPT_ERROR_NOTAVAIL );

	/* Read the certificate ID information */
	readOctetString( stream, buffer, &length, 20 );
	readOctetString( stream, buffer, &length, 20 );

	return( status );
	}

/****************************************************************************
*																			*
*									CRL Functions							*
*																			*
****************************************************************************/

/* Find an entry in a CRL */

static int findCRLEntry( CRL_ENTRY *listPtr, CRL_ENTRY **insertPoint,
						 const void *serialNumber,
						 const int serialNumberLength )
	{
	CRL_ENTRY *prevElement = NULL;

	*insertPoint = NULL;

	/* Find the correct place in the list to insert the new element and check
	   for duplicates.  We sort the entries by serial number for no
	   adequately explored reason (some implementations can optimise the
	   searching of CRL's based on this, but since there's no agreement on
	   whether to do it or not you can't tell whether it's safe to rely on
	   this) */
	while( listPtr != NULL )
		{
		if( listPtr->serialNumberLength == serialNumberLength )
			{
			const int compareStatus = memcmp( listPtr->serialNumber,
										serialNumber, serialNumberLength );

			if( !compareStatus )
				return( CRYPT_ERROR_INITED );/* Don't allow duplicates */
			if( compareStatus > 0 )
				break;					/* Insert before this point */
			}
		else
			if( listPtr->serialNumberLength > serialNumberLength )
				break;					/* Insert before this point */

		prevElement = listPtr;
		listPtr = listPtr->next;
		}

	/* Return the CRL entry after which we should insert the new value */
	*insertPoint = prevElement;
	return( CRYPT_OK );
	}

/* Check whether a cert has been revoked */

int checkRevocation( const CERT_INFO *certInfoPtr, CERT_INFO *crlInfoPtr )
	{
	CRL_ENTRY *revocationEntry;
	int status;

	/* If the issuers differ, the cert can't be in this CRL */
	if( crlInfoPtr->issuerDNsize != certInfoPtr->issuerDNsize || \
		memcmp( crlInfoPtr->issuerDNptr, certInfoPtr->issuerDNptr,
				crlInfoPtr->issuerDNsize ) )
		return( CRYPT_OK );

	/* Check whether the cert is present in the CRL */
	status = findCRLEntry( crlInfoPtr->revocations, &revocationEntry,
						   certInfoPtr->serialNumber,
						   certInfoPtr->serialNumberLength );
	if( cryptStatusOK( status ) )
		return( CRYPT_OK );

	/* Select the entry which contains the revocation.  The returned value
	   is the point after which we should insert a new value, so we set the
	   revocation selection to the following entry */
	if( revocationEntry == NULL )
		crlInfoPtr->currentRevocation = crlInfoPtr->revocations;
	else
		crlInfoPtr->currentRevocation = revocationEntry->next;
	return( CRYPT_ERROR_INVALID );
	}

/* Add an entry to a CRL */

int addCRLEntry( CRL_ENTRY **listHeadPtr, CRL_ENTRY **newEntryPosition,
				 const DN_COMPONENT *issuerDN, const void *serialNumber,
				 const int serialNumberLength )
	{
	CRL_ENTRY *newElement, *insertPoint;
	BYTE issuerID[ CRYPT_MAX_HASHSIZE ];
	int status;

	/* Find the insertion point for the new entry */
	status = findCRLEntry( *listHeadPtr, &insertPoint, serialNumber,
						   serialNumberLength );
	if( cryptStatusError( status ) )
		return( status );

	/* Generate a certificate ID for the cert revoked by this entry */
	status = generateCertID( issuerDN, serialNumber, serialNumberLength, 
							 issuerID );
	if( cryptStatusError( status ) )
		return( status );

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( CRL_ENTRY * ) malloc( sizeof( CRL_ENTRY ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( CRL_ENTRY ) );
	if( ( newElement->serialNumber = malloc( serialNumberLength ) ) == NULL )
		{
		free( newElement );
		return( CRYPT_ERROR_MEMORY );
		}
	memcpy( newElement->serialNumber, serialNumber, serialNumberLength );
	newElement->serialNumberLength = serialNumberLength;
	memcpy( newElement->issuerID, issuerID, CRYPT_MAX_HASHSIZE );

	/* Insert the new element into the list */
	if( *listHeadPtr == NULL )
		/* It's an empty list, make this the new list */
		*listHeadPtr = newElement;
	else
		if( insertPoint == NULL )
			{
			/* We're inserting at the start of the list, make this the new
			   first element */
			newElement->next = *listHeadPtr;
			*listHeadPtr = newElement;
			}
		else
			{
			/* Insert the element in the middle or end of the list */
			newElement->next = insertPoint->next;
			insertPoint->next = newElement;
			}
	*newEntryPosition = newElement;

	return( CRYPT_OK );
	}

/* Delete a CRL */

void deleteCRLEntries( CRL_ENTRY **listHeadPtr )
	{
	CRL_ENTRY *entryListPtr = *listHeadPtr;

	/* If the list was empty, return now */
	if( entryListPtr == NULL )
		return;
	*listHeadPtr = NULL;

	/* Destroy any remaining list items */
	while( entryListPtr != NULL )
		{
		CRL_ENTRY *itemToFree = entryListPtr;

		entryListPtr = entryListPtr->next;
		zeroise( itemToFree->serialNumber, itemToFree->serialNumberLength );
		free( itemToFree->serialNumber );
		if( itemToFree->attributes != NULL )
			deleteAttributes( &itemToFree->attributes );
		zeroise( itemToFree, sizeof( CRL_ENTRY ) );
		free( itemToFree );
		}
	}

/* Prepare the entries in a CRL prior to encoding them */

static int prepareCRLEntries( CRL_ENTRY *listPtr, const time_t defaultTime,
							  CRL_ENTRY **errorEntry,
							  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
							  CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRL_ENTRY *crlEntry;
	time_t currentTime = defaultTime;

	/* Set the revocation time if this hasn't already been set.  If there's a
	   default time set we use that, otherwise we use the current time */
	if( !currentTime )
		currentTime = time( NULL );
	for( crlEntry = listPtr; crlEntry != NULL; crlEntry = crlEntry->next )
		if( !crlEntry->revocationTime )
			crlEntry->revocationTime = currentTime;

	/* Check the attributes for each entry in a CRL */
	for( crlEntry = listPtr; crlEntry != NULL; crlEntry = crlEntry->next )
		{
		int status;

		status = checkAttributes( ATTRIBUTE_CERTIFICATE, crlEntry->attributes,
								  errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			/* Remember the entry which caused the problem */
			*errorEntry = crlEntry;
			return( status );
			}
		}

	return( CRYPT_OK );
	}

/* Read/write a CRL entry */

static int sizeofCRLentry( CRL_ENTRY *crlEntry )
	{
	/* Remember the encoded attribute size for later when we write the
	   attributes */
	crlEntry->attributeSize = sizeofAttributes( crlEntry->attributes );

	return( ( int ) sizeofObject( \
						sizeofInteger( crlEntry->serialNumber,
									   crlEntry->serialNumberLength ) +
						sizeofUTCTime() +
						( ( crlEntry->attributeSize ) ? \
							( int ) sizeofObject( crlEntry->attributeSize ) : 0 ) ) );
	}

static int readCRLentry( STREAM *stream, CRL_ENTRY **listHeadPtr,
						 CERT_INFO *certInfoPtr )
	{
	CRL_ENTRY *currentEntry;
	BYTE serialNumber[ 256 ];
	int serialNumberLength, endPos, length, status;
	time_t revocationTime;

	/* Determine the overall size of the entry */
	readSequence( stream, &length );
	endPos = ( int ) stell( stream ) + length;

	/* Read the integer component of the serial number and the revocation
	   time.  This makes the assumption that the serial number will have
	   a sane length */
	status = readInteger( stream, serialNumber, &serialNumberLength, 256 );
	if( !cryptStatusError( status ) )
		status = readUTCTime( stream, &revocationTime );
	if( cryptStatusError( status ) )
		return( status );

	/* Add the entry to the CRL */
	status = addCRLEntry( listHeadPtr, &currentEntry, 
						  certInfoPtr->issuerName, serialNumber, 
						  serialNumberLength );
	if( cryptStatusError( status ) )
		return( status );
	currentEntry->revocationTime = revocationTime;

	/* Read the extensions if there are any present.  Since these are per-
	   entry extensions we read them as CRYPT_CERTTYPE_NONE rather than
	   CRYPT_CERTTYPE_CRL to make sure they're processed as required */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &currentEntry->attributes,
						CRYPT_CERTTYPE_NONE, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	return( status );
	}

static int writeCRLentry( STREAM *stream, const CRL_ENTRY *crlEntry )
	{
	const int revocationLength = sizeofInteger( crlEntry->serialNumber,
						crlEntry->serialNumberLength ) + sizeofUTCTime() +
						( ( crlEntry->attributeSize ) ? \
							( int ) sizeofObject( crlEntry->attributeSize ) : 0 );

	/* Write the CRL entry */
	writeSequence( stream, revocationLength );
	writeInteger( stream, crlEntry->serialNumber,
				  crlEntry->serialNumberLength, DEFAULT_TAG );
	writeUTCTime( stream, crlEntry->revocationTime, DEFAULT_TAG );

	/* Write the per-entry extensions if necessary.  Since these are per-
	   entry extensions we write them as CRYPT_CERTTYPE_NONE rather than
	   CRYPT_CERTTYPE_CRL to make sure they're processed as required  */
	writeAttributes( stream, crlEntry->attributes, CRYPT_CERTTYPE_NONE,
					 crlEntry->attributeSize );

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*							Read Certificate Components						*
*																			*
****************************************************************************/

/* Read a certificate serial number */

static int readSerialNumber( STREAM *stream, void **serialNumber,
							 int *serialNumberLength )
	{
	BYTE integer[ 256 ];
	int integerLength, status;

	/* Read the integer component of the serial number.  This makes the
	   assumption that the serial number will have a sane length, because of
	   ASN.1 integer encoding issues trying to determine the data length
	   before we read it is somewhat complex */
	status = readInteger( stream, integer, &integerLength, 256 );
	if( cryptStatusError( status ) )
		return( status );

	/* Some certs may have a serial number of zero, which is turned into a
	   zero-length integer by the ASN.1 read code which truncates leading
	   zeroes which are added by the aforementioned ASN.1 encoding
	   constraints.  If we get a zero-length integer, we turn it into a
	   single zero byte */
	if( !integerLength )
		{
		integerLength++;
		*integer = 0;
		}

	/* Copy the data across for the caller */
	if( ( *serialNumber = malloc( integerLength ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( *serialNumber, integer, integerLength );
	*serialNumberLength = integerLength;
	return( CRYPT_OK );
	}

/* Read validity information.  We allow for GeneralizedTime encodings as
   well since these are used in some broken certs */

static int readValidity( STREAM *stream, time_t *validityNotBefore,
						 time_t *validityNotAfter,
						 CRYPT_ATTRIBUTE_TYPE *errorLocus )
	{
	int status;

	readSequence( stream, NULL );
	if( peekTag( stream ) == BER_TIME_UTC )
		status = readUTCTime( stream, validityNotBefore );
	else
		status = readGeneralizedTime( stream, validityNotBefore );
	if( cryptStatusError( status ) )
		*errorLocus = CRYPT_CERTINFO_VALIDFROM;
	else
		{
		if( peekTag( stream ) == BER_TIME_UTC )
			status = readUTCTime( stream, validityNotAfter );
		else
			status = readGeneralizedTime( stream, validityNotBefore );
		if( cryptStatusError( status ) )
			*errorLocus = CRYPT_CERTINFO_VALIDTO;
		}
	return( cryptStatusError( status  ) ? status : CRYPT_OK );
	}

/* Read a uniqueID */

static int readUniqueID( STREAM *stream, void **buffer, int *bufferSize )
	{
	long length;
	int status;

	/* Read the length of the unique ID, allocate room for it, and read it
	   into the cert */
	status = readLength( stream, &length );
	sgetc( stream );
	length--;			/* Skip bit count */
	if( cryptStatusError( status ) || length < 1 || length > 1024 )
		return( CRYPT_ERROR_BADDATA );
	if( ( *buffer = malloc( ( size_t ) length ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	*bufferSize = ( int ) length;
	sread( stream, *buffer, ( int ) length );
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );
	return( CRYPT_OK );
	}

/* Return from readCertInfo after encountering an error, setting the extended
   error information if the error was caused by invalid data.  Although this
   isn't actually returned to the caller because the context isn't created,
   it allows more precise error diagnosis for other routines */

static int certErrorReturn( CERT_INFO *certInfoPtr,
							const CRYPT_ATTRIBUTE_TYPE errorLocus,
							const int status )
	{
	if( status == CRYPT_ERROR_BADDATA || status == CRYPT_ERROR_UNDERFLOW )
		setErrorInfo( certInfoPtr, errorLocus, CRYPT_ERRTYPE_ATTR_VALUE );
	return( status );
	}

/* Read a Netscape SignedPublicKeyAndChallenge.  This isn't a supported
   object so all we can do is import it for use with other objects */

int readSPKACInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	long length;
	int status;

	/* Read the outer SEQUENCE (this has already been checked earlier on) */
	readSequence( stream, NULL );

	/* Read the public key information into an encryption context */
	status = readPublicKey( stream, &certInfoPtr->iCryptContext, 
							READKEY_OPTION_NONE );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr,
							CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, status ) );

	/* Make sure the challenge string is present */
	if( readTag( stream ) != BER_STRING_IA5 || \
		cryptStatusError( readLength( stream, &length ) ) || length > 128 )
		return( CRYPT_ERROR_BADDATA );
	sSkip( stream, length );

	/* SPKAC's are always self-signed */
	certInfoPtr->selfSigned = TRUE;
	return( status );
	}

/* Read the information in a certificate */

int readCertInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Read the outer SEQUENCE and version number if it's present (these have
	   already been checked earlier on) */
	readSequence( stream, &length );
	endPos = ( int ) stell( stream ) + length;
	if( checkReadCtag( stream, CTAG_CE_VERSION, TRUE ) )
		sSkip( stream, 4 );	/* Length, INTEGER, length, 1|2 */

	/* Read the serial number */
	status = readSerialNumber( stream, &certInfoPtr->serialNumber,
							   &certInfoPtr->serialNumberLength );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
								 status ) );

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack which isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the issuer name, validity information, and subject name.  We also
	   remember the position of the encoded subject name as an encoded blob
	   so we can copy it (complete with any encoding errors) to the issuer DN
	   field of any certs we sign */
	certInfoPtr->issuerDNptr = sMemBufPtr( stream );
	certInfoPtr->issuerDNsize = ( int ) stell( stream );
	status = readDN( stream, &certInfoPtr->issuerName );
	certInfoPtr->issuerDNsize = ( int ) stell( stream ) - certInfoPtr->issuerDNsize;
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
								 status ) );
	status = readValidity( stream, &certInfoPtr->startTime,
						   &certInfoPtr->endTime, &certInfoPtr->errorLocus );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, certInfoPtr->errorLocus, status ) );
	certInfoPtr->subjectDNptr = sMemBufPtr( stream );
	certInfoPtr->subjectDNsize = ( int ) stell( stream );
	status = readDN( stream, &certInfoPtr->subjectName );
	certInfoPtr->subjectDNsize = ( int ) stell( stream ) - certInfoPtr->subjectDNsize;
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
								 status ) );

	/* Check to see whether it's a self-signed cert */
	if( certInfoPtr->issuerDNsize == certInfoPtr->subjectDNsize && \
		!memcmp( certInfoPtr->issuerDNptr, certInfoPtr->subjectDNptr,
				 certInfoPtr->subjectDNsize ) )
		certInfoPtr->selfSigned = TRUE;

	/* Read the public key information */
	certInfoPtr->publicKeyInfo = sMemBufPtr( stream );
	if( certInfoPtr->dataOnly )
		/* We're doing deferred handling of the public key, skip it for now */
		status = readUniversal( stream );
	else
		status = readPublicKey( stream, &certInfoPtr->iCryptContext, 
								READKEY_OPTION_NONE );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
								 status ) );

	/* Read the issuer and subject unique ID's if there are any present */
	if( checkReadCtag( stream, CTAG_CE_ISSUERUNIQUEID, FALSE ) )
		{
		status = readUniqueID( stream, &certInfoPtr->issuerUniqueID,
							   &certInfoPtr->issuerUniqueIDlength );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_ISSUERUNIQUEID,
									 status ) );
		}
	if( checkReadCtag( stream, CTAG_CE_SUBJECTUNIQUEID, FALSE ) )
		{
		status = readUniqueID( stream, &certInfoPtr->subjectUniqueID,
							   &certInfoPtr->subjectUniqueIDlength );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTUNIQUEID,
									 status ) );
		}

	/* Read the extensions if there are any present.  Because some certs will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software which gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CERTIFICATE, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Convert an email address in a DN into an altName if required */
	if( cryptStatusOK( status ) )
		{
		int fixEmailAddress;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &fixEmailAddress, CRYPT_OPTION_CERT_FIXEMAILADDRESS );
		if( fixEmailAddress )
			status = convertEmailAddress( certInfoPtr );
		}

	return( status );
	}

/* Read the information in an attribute certificate */

int readAttributeCertInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Read the outer SEQUENCE and version number if it's present (these have
	   already been checked earlier on) */
	readSequence( stream, &length );
	endPos = ( int ) stell( stream ) + length;
	if( peekTag( stream ) == BER_INTEGER )
		sSkip( stream, 2 );	/* Length, 1 */

	/* Read the subject name */
	if( checkReadCtag( stream, CTAG_AC_BASECERTIFICATEID, TRUE ) )
		{
		/* !!!!!!!!!!!! */
		return( CRYPT_ERROR );	/* Not handled yet */
		}
	if( checkReadCtag( stream, CTAG_AC_ENTITYNAME, TRUE ) )
		{
		readLength( stream, NULL );
		status = readDN( stream, &certInfoPtr->subjectName );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
									 status ) );
		}

	/* Read the issuer name */
	certInfoPtr->issuerDNptr = sMemBufPtr( stream );
	certInfoPtr->issuerDNsize = ( int ) stell( stream );
	status = readDN( stream, &certInfoPtr->issuerName );
	certInfoPtr->issuerDNsize = ( int ) stell( stream ) - certInfoPtr->issuerDNsize;
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
								 status ) );

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack which isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the serial number */
	status = readSerialNumber( stream, &certInfoPtr->serialNumber,
							   &certInfoPtr->serialNumberLength );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SERIALNUMBER,
								 status ) );

	/* Read the validity information */
	status = readValidity( stream, &certInfoPtr->startTime,
						   &certInfoPtr->endTime, &certInfoPtr->errorLocus );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, certInfoPtr->errorLocus, status ) );

	/* Skip the attributes for now since these aren't really defined yet */
	readUniversal( stream );

	/* Read the issuer unique ID if there's one present */
	if( peekTag( stream ) == BER_BITSTRING )
		{
		status = readUniqueID( stream, &certInfoPtr->issuerUniqueID,
							   &certInfoPtr->issuerUniqueIDlength );
		if( cryptStatusError( status ) )
			return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_ISSUERUNIQUEID,
									 status ) );
		}

	/* Read the extensions if there are any present.  Because some certs will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software which gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_ATTRIBUTE_CERT, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	return( status );
	}

/* Read the information in a CRL */

int readCRLInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int length, endPos, status;

	/* Read the outer SEQUENCE and version number if it's present (these have
	   already been checked earlier on) */
	readSequence( stream, &length );
	endPos = ( int ) stell( stream ) + length;
	if( checkReadTag( stream, BER_INTEGER ) )
		sSkip( stream, 2 );	/* Length, 1 */

	/* Skip the signature algorithm information.  This was included to avert
	   a somewhat obscure attack which isn't possible anyway because of the
	   way the signature data is encoded in PKCS #1 sigs (although it's still
	   possible for some of the ISO sig.types) so there's no need to record
	   it */
	readUniversal( stream );

	/* Read the issuer name, update time, and optional next update time */
	certInfoPtr->issuerDNptr = sMemBufPtr( stream );
	certInfoPtr->issuerDNsize = ( int ) stell( stream );
	status = readDN( stream, &certInfoPtr->issuerName );
	certInfoPtr->issuerDNsize = ( int ) stell( stream ) - certInfoPtr->issuerDNsize;
	if( !cryptStatusError( status ) )
		status = readUTCTime( stream, &certInfoPtr->startTime );
	if( !cryptStatusError( status ) && peekTag( stream ) == BER_TIME_UTC )
		status = readUTCTime( stream, &certInfoPtr->endTime );
	if( cryptStatusError( status ) )
		return( status );

	/* Read the SEQUENCE OF revoked certs and make the currently selected one
	   the start of the list */
	status = readSequence( stream, &length );
	while( !cryptStatusError( status ) && length > 16 )
		{
		const int innerStartPos = ( int ) stell( stream );

		status = readCRLentry( stream, &certInfoPtr->revocations, certInfoPtr );
		length -= ( int ) stell( stream ) - innerStartPos;
		}
	if( cryptStatusError( status ) )
		return( status );
	certInfoPtr->currentRevocation = certInfoPtr->revocations;

	/* Read the extensions if there are any present.  Because some CRL's will
	   have broken encoding of lengths, we allow for a bit of slop for
	   software which gets the length encoding wrong by a few bytes */
	if( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CRL, endPos - stell( stream ),
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );

	/* Convert an email address in a DN into an altName if required */
	if( cryptStatusOK( status ) )
		{
		int fixEmailAddress;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &fixEmailAddress, CRYPT_OPTION_CERT_FIXEMAILADDRESS );
		if( fixEmailAddress )
			status = convertEmailAddress( certInfoPtr );
		}

	return( cryptStatusError( status ) ? status : CRYPT_OK );
	}

/* Read the information in a certification request */

int readCertRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	/* Skip the outer SEQUENCE and version number if it's present (these have
	   already been checked earlier on) */
	readSequence( stream, NULL );
	readUniversal( stream );

	/* Read the SubjectName and the public key information */
	status = readDN( stream, &certInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
								 status ) );
	certInfoPtr->publicKeyInfo = sMemBufPtr( stream );
	if( certInfoPtr->dataOnly )
		/* We're doing deferred handling of the public key, skip it for now */
		readUniversal( stream );
	else
		status = readPublicKey( stream, &certInfoPtr->iCryptContext, 
								READKEY_OPTION_NONE );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
								 status ) );

	/* Read the attributes */
	if( checkReadCtag( stream, CTAG_CR_ATTRIBUTES, TRUE ) )
		{
		long length;

		readLength( stream, &length );
		if( length >= MIN_ATTRIBUTE_SIZE )
			status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CERTREQUEST, length, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		}

	/* Convert an email address in a DN into an altName if required */
	if( cryptStatusOK( status ) )
		{
		int fixEmailAddress;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &fixEmailAddress, CRYPT_OPTION_CERT_FIXEMAILADDRESS );
		if( fixEmailAddress )
			status = convertEmailAddress( certInfoPtr );
		}

	/* Certification requests are always self-signed */
	certInfoPtr->selfSigned = TRUE;
	return( status );
	}

/* Read the information in a CRMF certificate request */

int readCRMFRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr )
	{
	int status;

	/* Skip the outer SEQUENCE, request ID, and inner SEQUENCE (these have 
	   already been checked earlier on) */
	readSequence( stream, NULL );
	readUniversal( stream );
	readSequence( stream, NULL );

	/* Skip any junk before the SubjectName */
	while( sGetStatus( stream ) == CRYPT_OK && \
		   peekTag( stream ) != MAKE_CTAG( CTAG_CF_SUBJECT ) )
		readUniversal( stream );
	if( sGetStatus( stream ) != CRYPT_OK )
		return( sGetStatus( stream ) );

	/* Read the SubjectName and the public key information */
	readConstructed( stream, NULL, CTAG_CF_SUBJECT );
	status = readDN( stream, &certInfoPtr->subjectName );
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTNAME,
								 status ) );
	certInfoPtr->publicKeyInfo = sMemBufPtr( stream );
	if( certInfoPtr->dataOnly )
		/* We're doing deferred handling of the public key, skip it for now */
		readUniversal( stream );
	else
		{
		BYTE *pubkeyTag = sMemBufPtr( stream );

		/* Work around yet more nonstandard tagging used for the public key.
		   This temporary rewrite is rather inelegant, but it's cleaner than
		   modifying readPublicKey() to work around arbitrary broken tagging */
		*pubkeyTag = BER_SEQUENCE;
		status = readPublicKey( stream, &certInfoPtr->iCryptContext, 
								READKEY_OPTION_NONE );
		*pubkeyTag = MAKE_CTAG( CTAG_CF_PUBLICKEY );
		}
	if( cryptStatusError( status ) )
		return( certErrorReturn( certInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
								 status ) );

	/* Read the attributes */
	if( checkReadCtag( stream, CTAG_CF_EXTENSIONS, TRUE ) )
		{
		long length;

		readLength( stream, &length );
		if( length >= MIN_ATTRIBUTE_SIZE )
			status = readAttributes( stream, &certInfoPtr->attributes,
						CRYPT_CERTTYPE_CRMF_REQUEST, length, 
						&certInfoPtr->errorLocus, &certInfoPtr->errorType );
		}

	/* Convert an email address in a DN into an altName if required */
	if( cryptStatusOK( status ) )
		{
		int fixEmailAddress;

		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &fixEmailAddress, CRYPT_OPTION_CERT_FIXEMAILADDRESS );
		if( fixEmailAddress )
			status = convertEmailAddress( certInfoPtr );
		}

	/* CRMF certification requests are always self-signed */
	certInfoPtr->selfSigned = TRUE;
	return( status );
	}

/****************************************************************************
*																			*
*						Write Certificate/Cert Request/CRL					*
*																			*
****************************************************************************/

/* Add standard X.509v3 extensions to a cert/attribute cert if they're not
   already present.  This function simply adds the required extensions, it
   doesn't check for consistency with existing extensions which is done later
   by checkCert() */

static int addStandardExtensions( CERT_INFO *certInfoPtr,
								  const BOOLEAN isCertificate )
	{
	CRYPT_ALGO cryptAlgo;
	ATTRIBUTE_LIST *attributeListPtr;
	BYTE keyID[ KEYID_SIZE ];
	BOOLEAN isCA;
	int keyUsage;

	/* If it's a standard certificate, get the key usage flags for the cert
	   based on any usage-related cert extensions, and get information on the
	   key in the cert */
	if( isCertificate )
		{
		RESOURCE_DATA msgData;
		int status;

		keyUsage = getKeyUsageFlags( certInfoPtr, &isCA );
		if( cryptStatusError( keyUsage ) )
			return( keyUsage );
		status = krnlSendMessage( certInfoPtr->iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE, &cryptAlgo, 
								  CRYPT_CTXINFO_ALGO );
		if( cryptStatusError( status ) )
			return( status );
		setResourceData( &msgData, keyID, KEYID_SIZE );
		status = krnlSendMessage( certInfoPtr->iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S, &msgData, 
								  CRYPT_IATTRIBUTE_KEYID );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Check whether there's a basicConstraints extension present and whether
	   this is a CA certificate */
	attributeListPtr = findAttributeField( certInfoPtr->attributes,
									CRYPT_CERTINFO_CA, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		isCA = ( BOOLEAN ) attributeListPtr->value;
	else
		{
		int value = isCA;	/* Type kludge for VC++ */
		int status;

		/* There's no basicConstraint extension present, add one and make
		   it the appropriate type of cert */
		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_CA, &value,
								   CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's not a key certificate, we're done */
	if( !isCertificate )
		return( CRYPT_OK );

	/* If there's no keyUsage implied by existing extensions and there's no
	   keyUsage extension present, add one based on the algorithm type */
	if( !keyUsage && \
		findAttributeField( certInfoPtr->attributes,
					CRYPT_CERTINFO_KEYUSAGE, CRYPT_ATTRIBUTE_NONE ) == NULL )
		{
		int status;

		if( isCA )
			{
			/* A non-signature key can never be a CA key */
			if( !isSigAlgo( cryptAlgo ) )
				{
				setErrorInfo( certInfoPtr, CRYPT_CERTINFO_CA,
							  CRYPT_ERRTYPE_CONSTRAINT );
				return( CRYPT_ERROR_INVALID );
				}

			/* We only allow the CA key to be used for certification-
			   related purposes, if they want anything else they have to
			   specify it explicitly */
			keyUsage = CRYPT_KEYUSAGE_KEYCERTSIGN | CRYPT_KEYUSAGE_CRLSIGN;
			}
		else
			{
			/* Set the key usage flags based on the algorithm type.  MS seem
			   to really like setting the nonrepudiation flag whenever they
			   set the digital signature flag, so we set this too */
			if( isSigAlgo( cryptAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_DIGITALSIGNATURE | \
							CRYPT_KEYUSAGE_NONREPUDIATION;
			if( isCryptAlgo( cryptAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYENCIPHERMENT;
			if( isKeyxAlgo( cryptAlgo ) )
				keyUsage |= CRYPT_KEYUSAGE_KEYAGREEMENT;
			}

		status = addCertComponent( certInfoPtr, CRYPT_CERTINFO_KEYUSAGE,
								   &keyUsage, CRYPT_UNUSED );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Add the subjectKeyIdentifier */
	return( addCertComponent( certInfoPtr, CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
							  keyID, KEYID_SIZE ) );
	}

/* Prepare to create a certificate object */

static int preEncodeCertificate( CERT_INFO *subjectCertInfoPtr,
								 const CERT_INFO *issuerCertInfoPtr,
								 const CRYPT_CERTTYPE_TYPE type )
	{
	int status;

	/* Handle various default certificate extensions if necessary */
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		{
		int encodeValidityNesting, createV3cert;

		/* Enforce validity period nesting if necessary */
		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &encodeValidityNesting, 
						 CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING );
		if( encodeValidityNesting )
			{
			/* Constrain the subject validity period to be within the issuer
			   validity period */
			if( subjectCertInfoPtr->startTime < issuerCertInfoPtr->startTime )
				subjectCertInfoPtr->startTime = issuerCertInfoPtr->startTime;
			if( subjectCertInfoPtr->endTime > issuerCertInfoPtr->endTime )
				subjectCertInfoPtr->endTime = issuerCertInfoPtr->endTime;
			}

		/* Add the standard X.509v3 extensions if these aren't already
		   present */
		krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
						 &createV3cert, CRYPT_OPTION_CERT_CREATEV3CERT );
		if( createV3cert )
			{
			status = addStandardExtensions( subjectCertInfoPtr,
					( BOOLEAN )	/* Needed by VC++ */
					( ( type == CRYPT_CERTTYPE_CERTIFICATE ) ? TRUE : FALSE ) );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		type == CRYPT_CERTTYPE_CRL )
		{
		/* Copy the issuer DN if this isn't already present */
		if( subjectCertInfoPtr->issuerName == NULL )
			{
			status = copyDN( &subjectCertInfoPtr->issuerName,
							 issuerCertInfoPtr->subjectName );
			if( cryptStatusError( status ) )
				return( status );
			}

		/* Copy any required extensions from the issuer to the subject cert
		   if necessary */
		if( !subjectCertInfoPtr->selfSigned )
			{
			status = copyIssuerAttributes( &subjectCertInfoPtr->attributes,
										   issuerCertInfoPtr->attributes,
										   &subjectCertInfoPtr->errorLocus,
										   &subjectCertInfoPtr->errorType,
										   subjectCertInfoPtr->type );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	if( type == CRYPT_CERTTYPE_CRL )
		{
		/* If it's a CRL, compare the revoked cert issuer DN and signer DN
		   to make sure we're not trying to revoke someone else's certs, and
		   prepare the revocation entries */
		if( !compareDN( subjectCertInfoPtr->issuerName,
						issuerCertInfoPtr->issuerName, FALSE ) )
			{
			setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_ISSUERNAME,
						  CRYPT_ERRTYPE_ATTR_VALUE );
			return( CRYPT_ERROR_INVALID );
			}

		status = prepareCRLEntries( subjectCertInfoPtr->revocations,
									subjectCertInfoPtr->revocationTime,
									&subjectCertInfoPtr->currentRevocation,
									&subjectCertInfoPtr->errorLocus,
									&subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Make sure everything is in order.  We perform the following checks for
	   the different object types:

	   Object		Checks
	   -----------------------------
		cert		key	DN	exts	cert
		attr.cert		DN	exts	cert
		cert.req	key	DN	exts
		CRL					exts	cert
		OCSP req.			exts */
	if( ( type == CRYPT_CERTTYPE_CERTIFICATE || \
		  type == CRYPT_CERTTYPE_CERTREQUEST || \
		  type == CRYPT_CERTTYPE_CRMF_REQUEST ) && \
		subjectCertInfoPtr->iCryptContext == CRYPT_ERROR )
		{
		setErrorInfo( subjectCertInfoPtr, CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO,
					  CRYPT_ERRTYPE_ATTR_ABSENT );
		return( CRYPT_ERROR_NOTINITED );
		}
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		type == CRYPT_CERTTYPE_CERTREQUEST || \
		type == CRYPT_CERTTYPE_CRMF_REQUEST )
		{
		/* If it's a cert request, we allow the country to be optional since
		   some CA's fill this in themselves */
		status = checkDN( subjectCertInfoPtr->subjectName, TRUE,
						  ( type == CRYPT_CERTTYPE_CERTREQUEST ) ? TRUE : FALSE,
						  &subjectCertInfoPtr->errorLocus,
						  &subjectCertInfoPtr->errorType );
		if( cryptStatusError( status ) )
			return( status );
		}
	status = checkAttributes( ATTRIBUTE_CERTIFICATE,
							  subjectCertInfoPtr->attributes,
							  &subjectCertInfoPtr->errorLocus,
							  &subjectCertInfoPtr->errorType );
	if( cryptStatusError( status ) )
		return( status );
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_ATTRIBUTE_CERT || \
		type == CRYPT_CERTTYPE_CRL )
		status = checkCert( subjectCertInfoPtr, issuerCertInfoPtr );
	return( status );
	}

/* Write certificate information:

	CertificateInfo ::= SEQUENCE {
		version			  [ 0 ]	INTEGER DEFAULT(0),
		serialNumber			INTEGER,
		signature				AlgorithmIdentifier,
		issuer					Name
		validity				Validity,
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		extensions		  [ 3 ]	Extensions OPTIONAL
		}

   version is set to 2 if any extensions are present */

int writeCertInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
				   const CERT_INFO *issuerCertInfoPtr,
				   const CRYPT_CONTEXT iIssuerCryptContext )
	{
	RESOURCE_DATA msgData;
	int issuerDNblob, length, pubKeyDataSize, extensionSize, status;

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CERTIFICATE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded: If we're being told to
	   treat it as a blob (necessary to propagate broken encodings) and it's
	   present in the issuer cert, use the blob, otherwise encode it
	   ourselves */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &issuerDNblob, CRYPT_OPTION_CERT_ISSUERNAMEBLOB );
	if( issuerDNblob && issuerCertInfoPtr->subjectDNptr == NULL )
		issuerDNblob = FALSE;
	subjectCertInfoPtr->issuerDNsize = issuerDNblob ? \
								issuerCertInfoPtr->subjectDNsize : \
								sizeofDN( subjectCertInfoPtr->issuerName );
	subjectCertInfoPtr->subjectDNsize = \
								sizeofDN( subjectCertInfoPtr->subjectName );

	/* Determine the size of the certificate information */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	pubKeyDataSize = msgData.length;
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( extensionSize ? ( int ) sizeofObject(
							sizeofShortInteger( X509V2_VERSION ) ) : 0 ) +
			 sizeofInteger( subjectCertInfoPtr->serialNumber,
							subjectCertInfoPtr->serialNumberLength ) +
			 sizeofContextAlgoID( iIssuerCryptContext, CRYPT_ALGO_SHA ) +
			 subjectCertInfoPtr->issuerDNsize + 
			 ( int ) sizeofObject( sizeofUTCTime() * 2 ) +
			 subjectCertInfoPtr->subjectDNsize + pubKeyDataSize +
			 ( extensionSize ? \
				( int ) sizeofObject( sizeofObject( extensionSize ) ) : 0 );


	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v3 certificate */
	if( extensionSize )
		{
		writeCtag( stream, CTAG_CE_VERSION );
		writeLength( stream, sizeofShortInteger( X509V3_VERSION ) );
		writeShortInteger( stream, X509V3_VERSION, DEFAULT_TAG );
		}

	/* Write the serial number and signature algorithm identifier */
	writeInteger( stream, subjectCertInfoPtr->serialNumber,
				  subjectCertInfoPtr->serialNumberLength, DEFAULT_TAG );
	status = writeContextAlgoID( stream, iIssuerCryptContext, CRYPT_ALGO_SHA );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the issuer name, validity period, and subject name */
	if( issuerDNblob )
		swrite( stream, issuerCertInfoPtr->subjectDNptr,
				issuerCertInfoPtr->subjectDNsize );
	else
		status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the public key information */
	if( !sIsNullStream( stream ) )
		{
		setResourceData( &msgData, sMemBufPtr( stream ), pubKeyDataSize );
		status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	sSkip( stream, pubKeyDataSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the extensions if necessary */
	writeAttributes( stream, subjectCertInfoPtr->attributes,
					 CRYPT_CERTTYPE_CERTIFICATE, extensionSize );

	return( sGetStatus( stream ) );
	}

/* Write attribute certificate information:

	AttributeCertificateInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(1),
		owner			  [ 1 ]	Name,
		issuer					Name,
		signature				AlgorithmIdentifier,
		serialNumber			INTEGER,
		validity				Validity,
		attributes				SEQUENCE OF Attribute,
		extensions				Extensions OPTIONAL
		} */

int writeAttributeCertInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
							const CERT_INFO *issuerCertInfoPtr,
							const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int issuerDNblob, length, extensionSize, issuerNameSize, status;

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_ATTRIBUTE_CERT );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded: If we're being told to
	   treat it as a blob (necessary to propagate broken encodings) and it's
	   present in the issuer cert, use the blob, otherwise encode it
	   ourselves */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &issuerDNblob, CRYPT_OPTION_CERT_ISSUERNAMEBLOB );
	if( issuerDNblob && issuerCertInfoPtr->subjectDNptr == NULL )
		issuerDNblob = FALSE;
	issuerNameSize = issuerDNblob ? issuerCertInfoPtr->subjectDNsize : \
									sizeofDN( subjectCertInfoPtr->issuerName );

	/* Determine the size of the certificate information */
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( int ) sizeofObject( sizeofDN( subjectCertInfoPtr->subjectName ) ) +
			 issuerNameSize +
			 sizeofContextAlgoID( iIssuerCryptContext, CRYPT_ALGO_SHA ) +
			 sizeofInteger( subjectCertInfoPtr->serialNumber,
							subjectCertInfoPtr->serialNumberLength ) +
			 ( int ) sizeofObject( sizeofUTCTime() * 2 ) +
			 ( int ) sizeofObject( 0 ) +
			 ( extensionSize ? ( int ) sizeofObject( extensionSize ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* Write the owner and issuer name */
	writeCtag( stream, CTAG_AC_ENTITYNAME );
	writeLength( stream, sizeofDN( subjectCertInfoPtr->subjectName ) );
	status = writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( cryptStatusOK( status ) )
		{
		if( issuerDNblob )
			swrite( stream, issuerCertInfoPtr->subjectDNptr,
					issuerCertInfoPtr->subjectDNsize );
		else
			status = writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
		}
	if( cryptStatusError( status ) )
		return( status );

	/* Write the signature algorithm identifier, serial number and validity
	   period */
	writeContextAlgoID( stream, iIssuerCryptContext, CRYPT_ALGO_SHA );
	writeInteger( stream, subjectCertInfoPtr->serialNumber,
				  subjectCertInfoPtr->serialNumberLength, DEFAULT_TAG );
	writeSequence( stream, sizeofUTCTime() * 2 );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes */
	writeSequence( stream, 0 );

	/* Write the extensions if necessary */
	writeAttributes( stream, subjectCertInfoPtr->attributes,
					 CRYPT_CERTTYPE_ATTRIBUTE_CERT, extensionSize );

	return( sGetStatus( stream ) );
	}

/* Write certificate request information:

	CertificationRequestInfo ::= SEQUENCE {
		version					INTEGER (0),
		subject					Name,
		subjectPublicKeyInfo	SubjectPublicKeyInfo,
		attributes		  [ 0 ]	SET OF Attribute
		}

   Attributes are omitted if there are no extensions present and
   CRYPT_OPTION_CERT_PKCS10ALT is set to TRUE.  If extensions are present,
   they are encoded as:

	SEQUENCE {							-- Attribute from X.501
		OBJECT IDENTIFIER {pkcs-9 14},	--   type
		SET OF {						--   values
			SEQUENCE OF {				-- ExtensionReq from CMMF draft
				<X.509v3 extensions>
				}
			}
		}

   as per the CMMF draft */

int writeCertRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	RESOURCE_DATA msgData;
	int useAltEncoding, length, pubKeyDataSize, extensionSize, status;

	if( iIssuerCryptContext );	/* Get rid of compiler warning */

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CERTREQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &useAltEncoding, CRYPT_OPTION_CERT_PKCS10ALT );
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	pubKeyDataSize = msgData.length;
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = sizeofShortInteger( 0 ) +
			 sizeofDN( subjectCertInfoPtr->subjectName ) + pubKeyDataSize;
	if( extensionSize )
		length += ( int ) sizeofObject( sizeofObject( 11 +	/* PKCS #9 OID size */
					( int ) sizeofObject( sizeofObject( extensionSize ) ) ) );
	else
		if( !useAltEncoding )
			length += ( int ) sizeofObject( 0 );

	/* Write the header, version number, DN, and public key */
	writeSequence( stream, length );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( !sIsNullStream( stream ) )
		{
		setResourceData( &msgData, sMemBufPtr( stream ), pubKeyDataSize );
		status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
		}
	sSkip( stream, pubKeyDataSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes */
	if( extensionSize )
		{
		writeCtag( stream, CTAG_CR_ATTRIBUTES );
		writeLength( stream, ( int ) sizeofObject( 11 +	/* PKCS #9 OID size */
					 ( int ) sizeofObject( sizeofObject( extensionSize ) ) ) );
		writeAttributes( stream, subjectCertInfoPtr->attributes,
						 CRYPT_CERTTYPE_CERTREQUEST, extensionSize );
		}
	else
		/* If there are no attributes and we're not using the PKCS #10
		   alternative encoding, write an (erroneous) zero-length field */
		if( !useAltEncoding )
			{
			writeCtag( stream, CTAG_CR_ATTRIBUTES );
			writeLength( stream, 0 );
			}

	return( status );
	}

/* Write CRMF certificate request information:

	CertReq ::= SEQUENCE {
		certReqID				INTEGER (0),
		certTemplate			SEQUENCE {
			subject		  [ 5 ]	EXPLICIT Name,
			publicKey	  [ 6 ]	SubjectPublicKeyInfo,
			extensions	  [ 9 ]	SET OF Attribute
			}
		} */

int writeCRMFRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	RESOURCE_DATA msgData;
	int payloadLength, pubKeyDataSize, extensionSize, dnSize, status;

	if( iIssuerCryptContext );	/* Get rid of compiler warning */

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CRMF_REQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded certificate request will be */
	setResourceData( &msgData, NULL, 0 );
	status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
							  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
							  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
	if( cryptStatusError( status ) )
		return( status );
	pubKeyDataSize = msgData.length;
	dnSize = sizeofDN( subjectCertInfoPtr->subjectName );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	payloadLength = sizeofObject( dnSize ) + pubKeyDataSize;
	if( extensionSize )
		payloadLength += ( int ) sizeofObject( extensionSize );

	/* Write the header, request ID, inner header, DN, and public key */
	writeSequence( stream, sizeofShortInteger( 0 ) + \
				   sizeofObject( payloadLength ) );
	writeShortInteger( stream, 0, DEFAULT_TAG );
	writeSequence( stream, payloadLength );
	writeConstructed( stream, dnSize, CTAG_CF_SUBJECT );
	writeDN( stream, subjectCertInfoPtr->subjectName, DEFAULT_TAG );
	if( !sIsNullStream( stream ) )
		{
		BYTE *dataPtr = sMemBufPtr( stream );

		setResourceData( &msgData, dataPtr, pubKeyDataSize );
		status = krnlSendMessage( subjectCertInfoPtr->iCryptContext, 
								  RESOURCE_IMESSAGE_GETATTRIBUTE_S,
								  &msgData, CRYPT_IATTRIBUTE_PUBLICKEY );
		
		/* Convert the SPKI SEQUENCE tag to the CRMF alternative */
		*dataPtr = MAKE_CTAG( CTAG_CF_PUBLICKEY );
		}
	sSkip( stream, pubKeyDataSize );
	if( cryptStatusError( status ) )
		return( status );

	/* Write the attributes */
	if( extensionSize )
		{
		writeConstructed( stream, extensionSize, CTAG_CF_EXTENSIONS );
		writeAttributes( stream, subjectCertInfoPtr->attributes,
						 CRYPT_CERTTYPE_CRMF_REQUEST, extensionSize );
		}

	return( status );
	}

/* Write CRL information:

	CRLInfo ::= SEQUENCE {
		version					INTEGER DEFAULT(0),
		signature				AlgorithmIdentifier,
		issuer					Name,
		thisUpdate				UTCTime,
		nextUpdate				UTCTime OPTIONAL,
		revokedCertificates		SEQUENCE OF SEQUENCE {
			userCertificate		CertificalSerialNumber,
			revocationDate		UTCTime
			extensions			Extensions OPTIONAL,
			},
		extensions		  [ 0 ]	Extensions OPTIONAL
		} */

int writeCRLInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
				  const CERT_INFO *issuerCertInfoPtr,
				  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	CRL_ENTRY *revocationInfo;
	int issuerDNblob, length, issuerNameSize, extensionSize;
	int revocationInfoLength = 0, status;

	/* Perform any necessary pre-encoding steps */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_CRL );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how the issuer name will be encoded: If we're being told to
	   treat it as a blob (necessary to propagate broken encodings) and it's
	   present in the issuer cert, use the blob, otherwise encode it
	   ourselves */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &issuerDNblob, CRYPT_OPTION_CERT_ISSUERNAMEBLOB );
	if( issuerDNblob && issuerCertInfoPtr->subjectDNptr == NULL )
		issuerDNblob = FALSE;
	issuerNameSize = issuerDNblob ? issuerCertInfoPtr->subjectDNsize : \
									sizeofDN( subjectCertInfoPtr->issuerName );

	/* Determine how big the encoded CRL will be */
	for( revocationInfo = subjectCertInfoPtr->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		revocationInfoLength += sizeofCRLentry( revocationInfo );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	length = ( extensionSize ? sizeofShortInteger( X509V2_VERSION ) : 0 ) +
			 sizeofContextAlgoID( iIssuerCryptContext, CRYPT_ALGO_SHA ) +
			 issuerNameSize + sizeofUTCTime() +
			 ( subjectCertInfoPtr->endTime ? sizeofUTCTime() : 0 ) +
			 ( int ) sizeofObject( revocationInfoLength ) +
			 ( extensionSize ? \
			   ( int ) sizeofObject( sizeofObject( extensionSize ) ) : 0 );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, length );

	/* If there are extensions present, mark this as a v2 CRL */
	if( extensionSize )
		writeShortInteger( stream, X509V2_VERSION, DEFAULT_TAG );

	/* Write the signature algorithm identifier, issuer name, and CRL time */
	status = writeContextAlgoID( stream, iIssuerCryptContext, CRYPT_ALGO_SHA );
	if( cryptStatusError( status ) )
		return( status );
	if( issuerDNblob )
		swrite( stream, issuerCertInfoPtr->subjectDNptr,
				issuerCertInfoPtr->subjectDNsize );
	else
		writeDN( stream, subjectCertInfoPtr->issuerName, DEFAULT_TAG );
	writeUTCTime( stream, subjectCertInfoPtr->startTime, DEFAULT_TAG );
	if( subjectCertInfoPtr->endTime )
		writeUTCTime( stream, subjectCertInfoPtr->endTime, DEFAULT_TAG );

	/* Write the SEQUENCE OF revoked certificates wrapper and the revoked
	   certificate information */
	writeSequence( stream, revocationInfoLength );
	for( revocationInfo = subjectCertInfoPtr->revocations;
		 revocationInfo != NULL; revocationInfo = revocationInfo->next )
		writeCRLentry( stream, revocationInfo );

	/* Write the extensions if necessary */
	writeAttributes( stream, subjectCertInfoPtr->attributes,
					 CRYPT_CERTTYPE_CRL, extensionSize );

	return( sGetStatus( stream ) );
	}

/* Write OCSP request information:

	OCSPRequestInfo ::= SEQUENCE {
		requestList				SEQUENCE OF SEQUENCE {
			reqCert				CertID,
			reqExtensions [ 0 ]	EXPLICIT Extensions OPTIONAL
			}
		} */

int writeOCSPRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext )
	{
	int extensionSize, requestLength, status;

	if( iIssuerCryptContext );	/* Get rid of unused parameter warning */

	/* Make sure everything is in order */
	if( sIsNullStream( stream ) )
		{
		status = preEncodeCertificate( subjectCertInfoPtr, issuerCertInfoPtr,
									   CRYPT_CERTTYPE_OCSP_REQUEST );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* Determine how big the encoded OCSP request will be */
	requestLength = sizeofCertID( subjectCertInfoPtr );
	extensionSize = sizeofAttributes( subjectCertInfoPtr->attributes );
	if( extensionSize )
		requestLength += ( int ) sizeofObject( extensionSize );

	/* Write the outer SEQUENCE wrapper */
	writeSequence( stream, ( int ) sizeofObject( sizeofObject( requestLength ) ) );

	/* Write the SEQUENCE OF requests wrapper and the request information */
	writeSequence( stream, ( int ) sizeofObject( requestLength ) );
	writeSequence( stream, requestLength );
	writeCertID( stream, subjectCertInfoPtr );

	/* Write the extensions if necessary */
	writeAttributes( stream, subjectCertInfoPtr->attributes,
					 CRYPT_CERTTYPE_OCSP_REQUEST, extensionSize );

	return( sGetStatus( stream ) );
	}

/****************************************************************************
*																			*
*									Misc. Functions							*
*																			*
****************************************************************************/

/* Generate a nameID or issuerID.  These are needed when storing/retrieving a
   cert to/from a RDBMS, which can't handle the awkward heirarchical ID's
   usually used in certs.  There are two types of ID's, the nameID, which is
   an SHA-1 hash of the DistinguishedName and used for X.509, and the
   issuerID, which is an SHA-1 hash of the IssuerAndSerialNumber and used for
   CRL's and CMS */

int generateCertID( const DN_COMPONENT *dn, const void *serialNumber,
					const int serialNumberLength, BYTE *certID )
	{
	HASHFUNCTION hashFunction;
	STREAM stream;
	BYTE buffer[ DN_BUFFER_SIZE ], *bufPtr = buffer;
	int length = sizeofDN( dn ), payloadSize;
	int hashSize, status;

	/* If it's an issuerID, add the size of the serial number and evaluate 
	   the total size */
	if( serialNumber != NULL )
		{
		payloadSize = length + \
					  sizeofInteger( serialNumber, serialNumberLength );
		length = ( int ) sizeofObject( payloadSize );
		}

	/* Get the hash algorithm information */
	getHashParameters( CRYPT_ALGO_SHA, &hashFunction, &hashSize );

	/* Allocate a buffer for the ID information if necessary */
	if( length > DN_BUFFER_SIZE )
		if( ( bufPtr = malloc( length ) ) == NULL )
			return( CRYPT_ERROR_MEMORY );

	/* Write the relevant information to a buffer and hash the data to get
	   the ID.  Since there are an infinite number of ways to misrepresent
	   DN's and the like, we recode them into the canonical form before
	   generating the ID to ensure that even if other software suddenly
	   changes the way it represents a DN, or the software which generated
	   a message requiring a certain cert encodes the DN differently to the
	   way the software which created the cert encodes it, we still
	   (hopefully) end up with the same ID */
	sMemOpen( &stream, bufPtr, length );
	if( serialNumber == NULL )
		status = writeDN( &stream, dn, DEFAULT_TAG );
	else
		{
		writeSequence( &stream, payloadSize );
		status = writeDN( &stream, dn, DEFAULT_TAG );
		if( cryptStatusOK( status ) )
			status = writeInteger( &stream, serialNumber,
								   serialNumberLength, DEFAULT_TAG );
		}
	if( cryptStatusOK( status ) )
		hashFunction( NULL, certID, bufPtr, length, HASH_ALL );
	sMemClose( &stream );
	if( length > DN_BUFFER_SIZE )
		free( bufPtr );
	if( cryptStatusError( status ) )
		return( status );

	return( CRYPT_OK );
	}
