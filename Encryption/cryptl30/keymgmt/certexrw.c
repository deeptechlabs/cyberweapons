/****************************************************************************
*																			*
*					Certificate Attribute Read/Write Routines				*
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
  #include "certattr.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1objs.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
  #include "keymgmt/certattr.h"
#endif /* Compiler-specific includes */

/* Context-specific tags for certificate/CRL extensions and CMS attributes */

#define CTAG_CE_EXTENSIONS					3
#define CTAG_CR_EXTENSIONS					0
#define CTAG_SI_AUTHENTICATEDATTRIBUTES		0

/* The PKCS #9 OID for cert extensions in a certification request, from the
   CMMF draft.  Naturally MS had to define their own incompatible OID for
   this, so we check for this as well */

#define PKCS9_EXTREQ_OID	"\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0E"
#define MS_EXTREQ_OID		"\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0E"

/* Prototypes for functions in certcomp.c */

int oidToText( const BYTE *binaryOID, char *oid );

/****************************************************************************
*																			*
*								Attribute Read Routines						*
*																			*
****************************************************************************/

/* Find the end of an item (either primitive or constructed) in the attribute
   table. Sometimes we may have already entered a constructed object (for
   example when an attribute has a version number so we don't know until we've
   started processing it that we can't do anything with it), if this is the
   case the depth parameter indicates how many nesting levels we have to
   undo */

static const ATTRIBUTE_INFO *findItemEnd( const ATTRIBUTE_INFO *attributeInfoPtr,
										  const int depth )
	{
	BOOLEAN attributeContinues;
	int currentDepth = depth;

	/* Skip to the end of the (potentially) constructed item by recording the
	   nesting level and continuing until either it reaches zero or we reach
	   the end of the item */
	do
		{
		/* If it's a sequence/set, increment the depth; if it's an end-of-
		   constructed-item marker, decrement it by the appropriate amount */
		if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
			attributeInfoPtr->fieldType == BER_SET )
			currentDepth++;
		currentDepth -= decodeNestingLevel( attributeInfoPtr->flags );

		/* Move to the next entry */
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		attributeInfoPtr++;
		}
	while( currentDepth > 0 && attributeContinues );

	return( attributeInfoPtr - 1 );
	}

/* Given a pointer to a set of SEQUENCE { type, value } entries, return a
   pointer to the value entry appropriate for the data in the stream.  If the
   entry contains user data in the { value } portion then the returned pointer
   points to this, if it contains a fixed value or isn't present at all then
   the returned pointer points to the { type } portion */

static const ATTRIBUTE_INFO *findIdentifiedItem( STREAM *stream,
									const ATTRIBUTE_INFO *attributeInfoPtr )
	{
	BYTE oid[ CRYPT_MAX_TEXTSIZE ];
	int oidLength, sequenceLength;

	/* Skip the sequence */
	readSequence( stream, &sequenceLength );

	/* Read the OID and walk down the list of entries trying to match it to
	  an allowed value */
	sequenceLength -= readRawObject( stream, oid, &oidLength,
									 CRYPT_MAX_TEXTSIZE, BER_OBJECT_IDENTIFIER );
	while( attributeInfoPtr->flags & FL_IDENTIFIER )
		{
		const BYTE *oidPtr;

		/* Skip the SEQUENCE and OID */
		attributeInfoPtr++;
		oidPtr = attributeInfoPtr->oid;
		if( !( attributeInfoPtr->flags & FL_NONENCODING ) )
			attributeInfoPtr++;
		else
			/* If this is a blob field, we've hit a dont-care value (usually
			   the last in a series of type-and-value pairs) which ensures
			   that new additions don't get processed as errors */
			if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
				{
				/* If there's a { value } attached to the type, skip it */
				if( sequenceLength )
					sSkip( stream, sequenceLength );
				return( attributeInfoPtr );
				}

		/* If the OID matches, return a pointer to the value entry */
		if( !memcmp( oidPtr, oid, sizeofOID( oidPtr ) ) )
			{
			/* If this is a fixed field and there's a value attached, skip
			   it */
			if( ( attributeInfoPtr->flags & FL_NONENCODING ) && sequenceLength )
				sSkip( stream, sequenceLength );

			return( attributeInfoPtr );
			}

		/* The OID doesn't match, skip the value entry and continue.  We set
		   the current nesting depth parameter to 1 since we've already
		   entered the SEQUENCE above */
		attributeInfoPtr = findItemEnd( attributeInfoPtr, 1 ) + 1;
		}

	/* We reached the end of the set of entries without matching the OID */
	return( NULL );
	}

/* Read a sequence of identifier fields.  Returns the number of fields read */

static int readIdentifierFields( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO **attributeInfoPtrPtr, const BOOLEAN criticalFlag, 
			const CRYPT_ATTRIBUTE_TYPE fieldID, CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			CRYPT_ERRTYPE_TYPE *errorType )
	{
	int count = 0, oidLength;

	while( peekTag( stream ) == BER_OBJECT_IDENTIFIER )
		{
		ATTRIBUTE_INFO *attributeInfoPtr = ( ATTRIBUTE_INFO * ) *attributeInfoPtrPtr;
		BYTE oid[ CRYPT_MAX_TEXTSIZE ];
		BOOLEAN attributeContinues;
		int status = CRYPT_ERROR_BADDATA;

		/* Read the OID and walk down the list of possible OIDs up to the end
		   of the group of alternatives trying to match it to an allowed
		   value */
		readRawObject( stream, oid, &oidLength, CRYPT_MAX_TEXTSIZE,
					   BER_OBJECT_IDENTIFIER );
		do
			{
			/* If the OID matches, add this field as an identifier field
			   (this will catch duplicate OIDs since we can't add the same
			   identifier field twice) */
			if( !memcmp( attributeInfoPtr->oid, oid, oidLength ) )
				{
				const int dummy = CRYPT_UNUSED;

				/* If there's a field value present then this is a CHOICE of
				   attributes whose value is the field value, so we add it
				   with this value */
				if( fieldID != CRYPT_ATTRIBUTE_NONE )
					status = addAttributeField( attributeListPtrPtr,
									fieldID, CRYPT_ATTRIBUTE_NONE,
									&attributeInfoPtr->fieldID, CRYPT_UNUSED,
									criticalFlag, FALSE, NULL, NULL );
				else
					/* It's a standard field */
					status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, criticalFlag, FALSE, NULL,
							NULL );
				count++;
				break;
				}
			attributeContinues = !( attributeInfoPtr->flags & FL_SEQEND ) && \
								  ( attributeInfoPtr->flags & FL_MORE );
			attributeInfoPtr++;
			}
		while( attributeContinues );

		/* If there's more than one OID present in a CHOICE, it's an error */
		if( fieldID != CRYPT_ATTRIBUTE_NONE && count > 1 )
			{
			*errorLocus = attributeInfoPtr->fieldID,
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_BADDATA );
			}

		/* If we've reached the end of the list and there was a problem
		   (either because the OID wasn't matched or because we reached the
		   end of the list of alternatives), return */
		if( cryptStatusError( status ) )
			return( status );
		}

	/* We've processed the non-data field(s), move on to the next field.
	   We move to the last valid non-data field rather than the start of the
	   field following it since the caller needs to be able to check whether
	   there are more fields to follow using the current fields flags */
	while( !( ( *attributeInfoPtrPtr )->flags & FL_SEQEND ) && \
			( ( *attributeInfoPtrPtr )->flags & FL_MORE ) )
		( *attributeInfoPtrPtr )++;

	return( CRYPT_OK );
	}

/* Read an attribute field */

static int readAttributeField( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO *attributeInfoPtr,
			const CRYPT_ATTRIBUTE_TYPE subtypeParent, const BOOLEAN criticalFlag,
			CRYPT_ATTRIBUTE_TYPE *errorLocus, CRYPT_ERRTYPE_TYPE *errorType )
	{
	CRYPT_ATTRIBUTE_TYPE fieldID, subFieldID;

	/* Set up the field identifiers depending on whether it's a normal field
	   or a subfield of a parent field */
	if( subtypeParent == CRYPT_ATTRIBUTE_NONE )
		{
		fieldID = attributeInfoPtr->fieldID;
		subFieldID = CRYPT_ATTRIBUTE_NONE;
		}
	else
		{
		fieldID = subtypeParent;
		subFieldID = attributeInfoPtr->fieldID;
		}

	/* If it's a sequence/set, there's no data to read so we skip the length
	   and move on to the fields within the sequence */
	if( attributeInfoPtr->fieldType == BER_SEQUENCE || \
		attributeInfoPtr->fieldType == BER_SET )
		return( cryptStatusError( readLength( stream, NULL ) ) ? \
				CRYPT_ERROR_BADDATA : CRYPT_OK );

	/* If it's an integer or time type, read it */
	if( attributeInfoPtr->fieldType == BER_INTEGER || \
		attributeInfoPtr->fieldType == BER_ENUMERATED || \
		attributeInfoPtr->fieldType == BER_BITSTRING || \
		attributeInfoPtr->fieldType == BER_BOOLEAN )
		{
		BOOLEAN boolean;
		long longValue;
		int value, status;

		/* Read the data as appropriate */
		switch( attributeInfoPtr->fieldType )
			{
			case BER_BITSTRING:
				status = readBitStringData( stream, &value );
				break;

			case BER_BOOLEAN:
				status = readBooleanData( stream, &boolean );
				value = boolean;
				break;

			case BER_ENUMERATED:
				status = readEnumeratedData( stream, &value );
				break;

			case BER_INTEGER:
				/* This will return an error code if the integer field is
				   too long */
				status = readShortIntegerData( stream, &longValue );
				value = ( int ) longValue;
				break;
			}
		if( cryptStatusError( status ) )
			return( status );

		/* Add the data for this attribute field */
		return( addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, &value, CRYPT_UNUSED, criticalFlag,
							FALSE, errorLocus, errorType ) );
		}
	if( attributeInfoPtr->fieldType == BER_TIME_GENERALIZED || \
		attributeInfoPtr->fieldType == BER_TIME_UTC )
		{
		time_t timeVal;
		int status;

		if( attributeInfoPtr->fieldType == BER_TIME_GENERALIZED )
			status = readGeneralizedTimeData( stream, &timeVal );
		else
			status = readUTCTimeData( stream, &timeVal );
		if( cryptStatusError( status ) )
			return( status );

		/* Add the data for this attribute field */
		return( addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, &timeVal, sizeof( time_t ),
							criticalFlag, FALSE, errorLocus, errorType ) );
		}

	/* If it's a string type, read it in as a blob */
	if( attributeInfoPtr->fieldType == BER_STRING_IA5 || \
		attributeInfoPtr->fieldType == BER_STRING_ISO646 || \
		attributeInfoPtr->fieldType == BER_STRING_NUMERIC || \
		attributeInfoPtr->fieldType == BER_STRING_PRINTABLE || \
		attributeInfoPtr->fieldType == BER_OCTETSTRING )
		{
		char stringBuffer[ 256 ];
		long length;
		int constrainedLength;

		if( cryptStatusError( readLength( stream, &length ) ) )
			return( CRYPT_ERROR_BADDATA );
		constrainedLength = ( int ) min( length, 256 );

		/* Read in the string to a maximum length of 256 characters
		   (anything longer than this is quietly truncated) */
		sread( stream, stringBuffer, constrainedLength );
		if( length > 256 )
			sSkip( stream, length - 256 );

		/* Add the data for this attribute field */
		return( addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, stringBuffer, constrainedLength,
							criticalFlag, FALSE, errorLocus, errorType ) );
		}

	/* If it's an OID, we need to convert it to a text OID since this is the
	   form expected by addAttributeField() */
	if( attributeInfoPtr->fieldType == BER_OBJECT_IDENTIFIER )
		{
		BYTE oid[ CRYPT_MAX_TEXTSIZE ];
		char textOID[ CRYPT_MAX_TEXTSIZE * 2 ];
		long length;
		int textOIDlength;

		readLength( stream, &length );
		if( length > CRYPT_MAX_TEXTSIZE )
			return( CRYPT_ERROR_BADDATA );
		oid[ 0 ] = BER_OBJECT_IDENTIFIER;
		oid[ 1 ] = ( BYTE ) length;
		sread( stream, oid + 2, ( int ) length );
		textOIDlength = oidToText( oid, textOID );
		if( cryptStatusError( textOIDlength ) )
			{
			*errorLocus = attributeInfoPtr->fieldID;
			*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ERROR_BADDATA );
			}
		return( addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, textOID, textOIDlength,
							criticalFlag, FALSE, errorLocus, errorType ) );
		}

	/* If it's a special-case field, read it */
	if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
		{
		void *bufPtr = sMemBufPtr( stream );
		long length;
		int readDataLength;

		/* Make sure the data in the stream is in order and then add it
		   directly (without going via a temporary buffer) */
		sgetc( stream );
		readDataLength = readLength( stream, &length );
		if( cryptStatusError( readDataLength ) )
			return( readDataLength );
		if( cryptStatusError( sSkip( stream, length ) ) )
			{
			*errorLocus = attributeInfoPtr->fieldID;
			*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ERROR_BADDATA );
			}
		length += 1 + readDataLength;	/* Tag + length-of-length */

		return( addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, bufPtr, ( int ) length,
							criticalFlag, FALSE, errorLocus, errorType ) );
		}
	if( attributeInfoPtr->fieldType == FIELDTYPE_DN )
		{
		ATTRIBUTE_LIST *attributeListPtr;
		DN_COMPONENT *dnComponentPtr = NULL;
		const int dummy = CRYPT_UNUSED;
		int status;

		/* Read the DN */
		status = readDNTag( stream, &dnComponentPtr,
							( attributeInfoPtr->fieldEncodedType ) ? \
							NO_TAG : DEFAULT_TAG );
		if( cryptStatusError( status ) )
			return( status );

		/* We're being asked to instantiate the field containing the DN,
		   create the attribute field which contains it and fill in the DN
		   value in the attribute data */
		status = addAttributeField( attributeListPtrPtr, fieldID,
							subFieldID, &dummy, CRYPT_UNUSED,
							criticalFlag, FALSE, errorLocus, errorType );
		if( cryptStatusError( status ) )
			{
			deleteDN( &dnComponentPtr );
			return( status );
			}
		attributeListPtr = findAttributeField( *attributeListPtrPtr,
											   fieldID, subFieldID );
		attributeListPtr->data = dnComponentPtr;

		return( CRYPT_OK );
		}

	assert( NOTREACHED );
	return( 0 );	/* Get rid of compiler warning */
	}

/* Read an attribute */

static int readAttribute( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
			const ATTRIBUTE_INFO *attributeInfoPtr, const int attributeLength,
			const BOOLEAN criticalFlag, CRYPT_ATTRIBUTE_TYPE *errorLocus,
			CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_INFO *savedAttributeInfoPtr = NULL;
	const ATTRIBUTE_INFO *setofItemStartPtr = NULL;
	const int endPos = ( int ) stell( stream ) + attributeLength;
	CRYPT_ATTRIBUTE_TYPE subtypeParent = CRYPT_ATTRIBUTE_NONE;
	BOOLEAN attributeContinues = TRUE;
	int setEndPos = 0, setEndEOC = 0, savedSetEndPos = 0;

	/* Process each field in the attribute.  This is a simple FSM driven by
	   the encoding table and the data we encounter.  The various states and
	   associated actions are indicated by the comment tags */
	do
		{
		BOOLEAN isTagged;
		int tag, status;

		/* Subtyped field: Switch to the new encoding table */
		if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
			{
			subtypeParent = attributeInfoPtr->fieldID;

			/* Push the current parse state and switch to the new state */
			savedAttributeInfoPtr = attributeInfoPtr;
			attributeInfoPtr = ( ATTRIBUTE_INFO * ) attributeInfoPtr->extraData;
			savedSetEndPos = setEndPos;
			setEndPos = 0;
			}

		/* CHOICE (of object identifiers): Read a single OID */
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
			{
			const ATTRIBUTE_INFO *extraDataPtr = attributeInfoPtr->extraData;
						/* Needed because ->extraData is read-only */

			status = readIdentifierFields( stream, attributeListPtrPtr,
						&extraDataPtr, criticalFlag, 
						attributeInfoPtr->fieldID, errorLocus, errorType );
			if( cryptStatusError( status ) )
				return( status );
			goto continueDecoding;
			}

		/* SET OF/SEQUENCE OF: Record its length and end position and
		   continue.  If we're processing a SET OF/SEQUENCE OF, check for the
		   end of an item or the end of the collection of items */
		if( attributeInfoPtr->flags & FL_SETOF )
			{
			void *objectPtr = sMemBufPtr( stream );
			int setofLength;

			/* Determine the length and start position of the set of items.
			   Some broken Verisign certs suddenly break into BER inside the
			   cert policy extension so if the length evaluates to zero we
			   have to determine it by burrowing into the ASN.1 */
			if( attributeInfoPtr->fieldType == BER_SET )
				readSet( stream, &setofLength );
			else
				readSequence( stream, &setofLength );
			if( !setofLength )
				{
				/* Get the overall length without the tag + indef.length */
				setofLength = getObjectLength( objectPtr, STREAMSIZE_UNKNOWN ) - 2;
				setEndEOC = 2;	/* Two bytes of EOC at end of object */
				}
			setEndPos = ( int ) stell( stream ) + setofLength;

			/* Remember where the first item in the SET/SEQUENCE starts.  We 
			   use this as a restart point when we're parsing the next item 
			   in the SET/SEQUENCE OF items using findIdentifiedItem() */
			setofItemStartPtr = ++attributeInfoPtr;
			continue;
			}
		if( setEndPos )
			{
			/* If we've reached the end of the collection of items, exit (at
			   the moment these items always occur at the end of an attribute,
			   this may need to be changed later) */
			if( stell( stream ) >= setEndPos - setEndEOC )
				{
				/* If the extension drops into BER, make sure the EOC is
				   present */
				if( setEndEOC && !checkEOC( stream ) )
					return( CRYPT_ERROR_BADDATA );
				break;
				}

			/* If we're looking for a new item, find the table entry which it
			   corresponds to.  This takes a pointer to the start of a set of
			   SEQUENCE { type, value } entries and returns a pointer to the
			   appropriate value entry.

			   The test for the start of a new item is a bit complex since we
			   could be at the end of the previous item (ie on the next item
			   flagged as an identifier) or at the end of the attribute (ie on
			   the start of the next attribute) */
			if( setEndPos && ( !( attributeInfoPtr[ -1 ].flags & FL_MORE ) ||
							   attributeInfoPtr->flags & FL_IDENTIFIER ) )
				{
				attributeInfoPtr = findIdentifiedItem( stream, setofItemStartPtr );
				if( attributeInfoPtr == NULL )
					return( CRYPT_ERROR_BADDATA );

				/* If it's a subtyped field, continue from a new encoding 
				   table */
				if( attributeInfoPtr->fieldType == FIELDTYPE_SUBTYPED )
					continue;

				/* If the { type, value } pair has a fixed value then the
				   information being conveyed is its presence, not its
				   contents, so we add an attribute corresponding to its ID
				   and continue.  The addition of the attribute is a bit
				   tricky, some of the fixed type-and-value pairs can have
				   multiple entries denoting things like { algorithm, weak
				   key }, { algorithm, average key }, { algorithm, strong
				   key }, however all we're interested in is the strong key
				   so we ignore the value and only use the type.  Since the
				   same type can be present multiple times (with different
				   { value }'s, we ignore data duplicate errors and
				   continue */
				if( attributeInfoPtr->flags & FL_NONENCODING )
					{
					const int dummy = CRYPT_UNUSED;

					/* If it's a blob field type, we've ended up at a
					   generic catch-any value and can't do much with it */
					if( attributeInfoPtr->fieldType != FIELDTYPE_BLOB )
						{
						/* Add the field type, discarding warnings about dups */
						status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							&dummy, CRYPT_UNUSED, criticalFlag, FALSE, NULL,
							NULL );
						if( status == CRYPT_ERROR_INITED )
							status = CRYPT_OK;
						if( cryptStatusError( status ) )
							return( status );
						}

					/* Reset the attribute info position in preparation for
					   the next value and continue */
					attributeInfoPtr = setofItemStartPtr;
					continue;
					}
				}
			}

		/* Identifier field: We've reached the first of a sequence of
		   possible alternatives, read the sequence of one or more fields and
		   continue */
		if( attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER )
			{
			status = readIdentifierFields( stream, attributeListPtrPtr,
								&attributeInfoPtr, criticalFlag,
								CRYPT_ATTRIBUTE_NONE, errorLocus, errorType );
			if( cryptStatusError( status ) )
				return( status );
			goto continueDecoding;
			}

		/* Non-encoding field: Check that it matches the required value and
		   continue */
		if( attributeInfoPtr->flags & FL_NONENCODING )
			{
			BYTE data[ 64 ];
			int dataLength;

			/* Read the data and continue.  We don't check its value for
			   reasons given under the SET-OF handling code above */
			status = readRawObject( stream, data, &dataLength, 64, CRYPT_UNUSED );
			if( cryptStatusError( status ) )
				return( status );

			goto continueDecoding;
			}

		/* Extract various pieces of information from the attribute field
		   definition */
		isTagged = ( attributeInfoPtr->fieldEncodedType ) ? TRUE : FALSE;
		tag = ( isTagged ) ? attributeInfoPtr->fieldEncodedType : \
							 attributeInfoPtr->fieldType;
		if( isTagged && ( attributeInfoPtr->fieldType == BER_SEQUENCE ||
						  attributeInfoPtr->fieldType == BER_SET ||
						  attributeInfoPtr->fieldType == FIELDTYPE_DN ||
						  ( attributeInfoPtr->flags & FL_EXPLICIT ) ) )
			/* If it's an implictly tagged sequence/set then it's constructed */
			tag |= BER_CONSTRUCTED;

		/* Optional field: Check whether it's present and if it isn't, move
		   on to the next field */
		if( ( attributeInfoPtr->flags & FL_OPTIONAL ) && \
			peekTag( stream ) != tag )
			{
			/* If it's a field with a default value, add that value.  This 
			   isn't needed for cryptlib's own use since it knows the default
			   values for fields, but can cause confusion for the caller if 
			   all fields in an attribute have default values because the 
			   attribute will appear to disappear when it's read in as no 
			   fields are ever added */
			if( attributeInfoPtr->flags & FL_DEFAULT )
				{
				const int value = ( int ) attributeInfoPtr->defaultValue;

				status = addAttributeField( attributeListPtrPtr, 
							attributeInfoPtr->fieldID,
							CRYPT_ATTRIBUTE_NONE, &value, CRYPT_UNUSED,
							criticalFlag, FALSE, NULL, NULL );
				if( cryptStatusError( status ) )
					return( status );
				}

			/* Skip to the end of the item and continue */
			attributeInfoPtr = findItemEnd( attributeInfoPtr, 0 );
			goto continueDecoding;
			}

		/* Read the tag for the field (either the field type or an explicit
		   or implicit tag) and make sure it matches what we're expecting */
		if( readTag( stream ) != tag )
			return( CRYPT_ERROR_BADDATA );

		/* Explicitly tagged field: Read the length for the previous field
		   and the inner field type and make sure it matches what we're
		   expecting, unless the inner field is a blob in which case it'll
		   be processed as an atomic unit by readAttributeField() */
		if( isTagged && ( attributeInfoPtr->flags & FL_EXPLICIT ) )
			{
			if( cryptStatusError( readLength( stream, NULL ) ) )
				return( CRYPT_ERROR_BADDATA );
			if( attributeInfoPtr->fieldType != FIELDTYPE_BLOB && \
				readTag( stream ) != attributeInfoPtr->fieldType )
				return( CRYPT_ERROR_BADDATA );
			}

		/* Read the field data */
		status = readAttributeField( stream, attributeListPtrPtr,
									 attributeInfoPtr, subtypeParent,
									 criticalFlag, errorLocus, errorType );
		if( cryptStatusError( status ) )
			return( status );

		/* Move on to the next field.  If we've reached the end of a subtyped
		   field, switch back to the main table */
continueDecoding:
		attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
		if( !attributeContinues && savedAttributeInfoPtr != NULL )
			{
			/* Pop the previous parse state and clear the stack entry */
			attributeInfoPtr = savedAttributeInfoPtr;
			savedAttributeInfoPtr = NULL;
			setEndPos = savedSetEndPos;
			savedSetEndPos = 0;
			subtypeParent = CRYPT_ATTRIBUTE_NONE;
			attributeContinues = ( attributeInfoPtr->flags & FL_MORE ) ? TRUE : FALSE;
			}
		attributeInfoPtr++;
		}
	while( attributeContinues && stell( stream ) < endPos );

	/* Handle the special case of (a) encoded data ending but fields with 
	   default values being present, or (b) encoded data continuing but no
	   more decoding information being present */
	if( attributeContinues )
		{
		/* If there are default fields to follow, add the default value - see
		   the comment on the handling of default fields above.  For now we 
		   only add the first field since the only attributes where this 
		   case can occur have a single default value as the next possible 
		   entry, burrowing down further causes complications due to default
		   values present in optional sequences */
		if( attributeInfoPtr->flags & FL_DEFAULT )
			{
			const int value = ( int ) attributeInfoPtr->defaultValue;
			int status;
	
			status = addAttributeField( attributeListPtrPtr, 
						attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE, 
						&value, CRYPT_UNUSED, criticalFlag, FALSE, NULL, NULL );
			if( cryptStatusError( status ) )
				return( status );
			}
		}
	else
		/* Some attributes have a SEQUENCE OF fields of no great use (eg
		   Microsoft's extensive CRLDistributionPoints lists providing 
		   redundant pointers to the same inaccessible MS-internal servers),
		   if there's any extraneous data left we just skip it */
		if( stell( stream ) < endPos )
			readUniversal( stream );

	/* More Verisign braindamage: There may be arbitrary levels of EOC's
	   at the end of an attribute, so we sit in a loop skipping them.
	   Eventually we'll run into the SEQUENCE for the signature
	   AlgorithmIdentifier which always follows attributes in certs, cert
	   requests, and CMS attributes */
	while( !peekTag( stream ) )
		checkEOC( stream );

	return( CRYPT_OK );
	}

/* Read a set of attributes */

int readAttributes( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
					const CRYPT_CERTTYPE_TYPE type, const int attributeSize,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
										 ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const int wrapperTag = ( attributeType == ATTRIBUTE_CMS ) ? \
						   BER_SET : BER_OCTETSTRING;
	int decodeCritical, keyIDblob, length, endPos, status;

	/* Read the X509v3 certificate/CRL extensions tag if it's a certificate 
	   or CRL or the CMMF wrapping if it's a certification request, and the 
	   SEQUENCE OF tag, and determine how far we can read.  CRL's have two
	   extension types, per-entry extensions which have only a SEQUENCE OF
	   tag, and entire-CRL extensions which have an extra context-specific 
	   tag.  To differentiate between the two, we read per-entry extensions
	   with a type of CRYPT_CERTTYPE_NONE */
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_CRL )
		{
		if( !checkReadCtag( stream, 
				( type == CRYPT_CERTTYPE_CERTIFICATE ) ? \
				CTAG_CE_EXTENSIONS : CTAG_CR_EXTENSIONS, TRUE ) || \
			cryptStatusError( readLength( stream, NULL ) ) )
			return( CRYPT_ERROR_BADDATA );
		}
	if( type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		/* The read of cert request extensions isn't as simple as it should
		   be, because alongside their incompatible request extension OID, 
		   Microsoft also invented other values containing God knows what 
		   sort of data (long Unicode strings describing the Windows module 
		   which created it (as if you'd need that to know where it came 
		   from), the scripts from "Gilligan's Island", every "Brady Bunch" 
		   episode ever made, dust from under somebody's bed from the 1930's,
		   etc).  Because of this, the following code skips over unknown
		   garbage until it finds a valid extension.
		   
		   Unfortunately this simple solution is complicated by the fact that
		   SET also defines non-CMMF-style attributes, however unlike MS's
		   stuff these are documented and stable, so if we find SET-style
		   attributes (or more generally any attributes we know about) we
		   process them normally.  Finally, since all attributes may be
		   either skipped or processed at this stage, we include provisions 
		   for bailing out if we exhaust the available attributes */
		endPos = stell( stream ) + attributeSize;
		while( cryptStatusOK( sGetStatus( stream ) ) )
			{
			ATTRIBUTE_INFO *attributeInfoPtr;
			BYTE buffer[ 32 ];
			int bufferLength;

			/* If we've run out of attributes without finding anything 
			   useful, exit */
			if( stell( stream ) > endPos - MIN_ATTRIBUTE_SIZE )
				return( CRYPT_OK );

			/* Read what the wrapper SEQUENCE and OID */
			readSequence( stream, NULL );
			status = readRawObject( stream, buffer, &bufferLength,
									32, BER_OBJECT_IDENTIFIER );
			if( cryptStatusError( status ) )
				return( CRYPT_ERROR_BADDATA );

			/* Check for a known attribute, which can happen with SET cert
			   requests.  If it's a known attribute, process it */
			attributeInfoPtr = oidToAttribute( attributeType, buffer );
			if( attributeInfoPtr != NULL )
				{
				status = readSet( stream, &length );
				if( cryptStatusOK( status ) )
					return( status );
				status = readAttribute( stream, attributeListPtrPtr,
										attributeInfoPtr, length,
										FALSE, errorLocus, errorType );
				if( cryptStatusError( status ) )
					{
					/* If the error information wasn't set by a lower-level
					   routine, set it now */
					if( *errorLocus == CRYPT_ATTRIBUTE_NONE )
						{
						*errorLocus = attributeInfoPtr->fieldID;
						*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
						}
					return( status );
					}
				}
			else
				/* It's not a known attribute, check whether it's a CMMF or
				   MS wrapper attribute */
				if( !memcmp( buffer, PKCS9_EXTREQ_OID, bufferLength ) || \
					!memcmp( buffer, MS_EXTREQ_OID, bufferLength ) )
					break;
				else
					{
					/* It's unknown MS garbage, skip it */
					readSet( stream, &length );
					sSkip( stream, length );
					}
			}
		readSet( stream, &length );
		}
	if( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		long value;

		if( !checkReadCtag( stream, CTAG_SI_AUTHENTICATEDATTRIBUTES, TRUE ) )
			return( CRYPT_ERROR_BADDATA );
		status = readLength( stream, &value );
		length = ( int ) value;
		}
	else
		if( type == CRYPT_CERTTYPE_CRMF_REQUEST )
			{
			/* CRMF attributes don't contain any wrapper, so there's nothing
			   to read */
			length = attributeSize;
			status = CRYPT_OK;
			}
		else
			status = readSequence( stream, &length );
	if( cryptStatusError( status ) )
		return( status );
	endPos = ( int ) stell( stream ) + length;

	/* Read config settings which affect the way we process attributes */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &decodeCritical, CRYPT_OPTION_CERT_DECODE_CRITICAL );
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &keyIDblob, CRYPT_OPTION_CERT_KEYIDBLOB );

	/* Read the collection of attributes.  We allow for a bit of slop for
	   software which gets the length encoding wrong by a few bytes */
	while( stell( stream ) <= endPos - MIN_ATTRIBUTE_SIZE )
		{
		ATTRIBUTE_INFO *attributeInfoPtr;
		BYTE oid[ MAX_OID_SIZE ];
		BOOLEAN criticalFlag = FALSE;
		long attributeLength;

		/* Read the outer wrapper */
		readSequence( stream, NULL );

		/* Determine the attribute type based on the OID */
		status = readRawObject( stream, oid, &length, MAX_OID_SIZE,
								BER_OBJECT_IDENTIFIER );
		if( cryptStatusError( status ) )
			return( CRYPT_ERROR_BADDATA );
		attributeInfoPtr = oidToAttribute( attributeType, oid );

		/* Read the optional critical flag if it's a certificate.  If the
		   extension is marked as being critical and we don't recognise it,
		   we can't process the certificate or CRL.  Because there are
		   logical problems in the use of the critical flag, we allow this to
		   be overridden if necessary with the CRYPT_OPTION_CERT_DECODE_-
		   CRITICAL option */
		if( attributeType != ATTRIBUTE_CMS )
			{
			if( checkReadTag( stream, BER_BOOLEAN ) )
				readBooleanData( stream, &criticalFlag );
			if( criticalFlag && attributeInfoPtr == NULL && decodeCritical )
				return( CRYPT_ERROR_PERMISSION );
			}

		/* Read the wrapper around the attribute payload */
		if( readTag( stream ) != wrapperTag || \
			cryptStatusError( readLength( stream, &attributeLength ) ) )
			{
			*errorLocus = attributeInfoPtr->fieldID;
			*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ERROR_BADDATA );
			}

		/* Some attributes are encoded in a variety of incompatible formats
		   and/or have a structure which is irrelevant, so we optionally read
		   them as blobs rather than trying to decompose them into their
		   component parts */
		if( attributeInfoPtr != NULL && \
			attributeInfoPtr->fieldID == CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER && \
			keyIDblob )
			{
			BYTE attributeBuffer[ 256 ];

			if( attributeLength > 256 )
				{
				*errorLocus = attributeInfoPtr->fieldID;
				*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
				return( CRYPT_ERROR_BADDATA );
				}
			sread( stream, attributeBuffer, ( int ) attributeLength );
			status = addAttributeField( attributeListPtrPtr,
							attributeInfoPtr->fieldID, CRYPT_ATTRIBUTE_NONE,
							attributeBuffer, ( int ) attributeLength,
							criticalFlag, TRUE, errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				if( status == CRYPT_ERROR_INITED )
					{
					/* If there's a duplicate attribute present, set error
					   information for it and flag it as a bad data error */
					*errorLocus = CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER;
					*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
					status = CRYPT_ERROR_BADDATA;
					}
				return( status );
				}
			continue;
			}

		/* If it's a known attribute, parse the payload */
		if( attributeInfoPtr != NULL )
			{
			status = readAttribute( stream, attributeListPtrPtr,
									attributeInfoPtr, ( int ) attributeLength,
									criticalFlag, errorLocus, errorType );
			if( cryptStatusError( status ) )
				{
				/* If the error information wasn't set by a lower-level
				   routine, set it now */
				if( *errorLocus == CRYPT_ATTRIBUTE_NONE )
					{
					*errorLocus = attributeInfoPtr->fieldID;
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
					}
				return( status );
				}
			continue;
			}

		/* It's an unrecognised attribute type, add the raw data to the list
		   of attributes */
		status = addAttribute( attributeType, attributeListPtrPtr, oid,
							   criticalFlag, sMemBufPtr( stream ),
							   ( int ) attributeLength );
		if( cryptStatusError( status ) )
			{
			if( status == CRYPT_ERROR_INITED )
				{
				/* If there's a duplicate attribute present, set error
				   information for it and flag it as a bad data error.  We
				   can't set an error locus since it's an unknown blob */
				*errorLocus = CRYPT_ATTRIBUTE_NONE;
				*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
				status = CRYPT_ERROR_BADDATA;
				}
			return( status );
			}
		sSkip( stream, attributeLength );	/* Skip the attribute data */
		}

	return( CRYPT_OK );
	}

/****************************************************************************
*																			*
*								Attribute Write Routines					*
*																			*
****************************************************************************/

/* When we write the attributes as a SET OF Attribute (as CMS does), we have
   to sort them by encoded value.  This is an incredible nuisance since it
   requires that each value be encoded and stored in encoded form, then the
   encoded forms sorted and emitted in that order.  To avoid this hassle, we
   keep a record of the current lowest encoded form and then find the next
   one by encoding enough information (the SEQUENCE and OID, CMS attributes
   don't have critical flags) on the fly to distinguish them.  This is
   actually less overhead than storing the encoded form because there are
   only a small total number of attributes (usually 3) and we don't have to
   malloc() storage for each one and manage the stored form if we do things
   on the fly */

static ATTRIBUTE_LIST *getNextEncodedAttribute( ATTRIBUTE_LIST *attributeListPtr,
												BYTE *prevEncodedForm )
	{
	ATTRIBUTE_LIST *currentAttributeListPtr = NULL;
	STREAM stream;
	BYTE currentEncodedForm[ 64 ], buffer[ 64 ];

	/* Connect the output stream and give the current encoded form the
	   maximum possible value */
	sMemOpen( &stream, buffer, 64 );
	currentEncodedForm[ 0 ] = 0xFF;

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	while( attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] :
			attributeListPtr->attributeInfoPtr;
		CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int attributeDataSize;

		/* Determine the size of the attribute payload */
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			attributeDataSize = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			attributeDataSize = attributeListPtr->encodedSize;

		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeInfoPtr->oid ) +
					   ( int ) sizeofObject( attributeDataSize ) );
		swrite( &stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it */
		if( memcmp( prevEncodedForm, buffer, 64 ) < 0 && \
			memcmp( buffer, currentEncodedForm, 64 ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, 64 );
			currentAttributeListPtr = attributeListPtr;
			}

		/* Move on to the next attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID )
			attributeListPtr = attributeListPtr->next;
		}

	/* Write the blob-type attributes */
	while( attributeListPtr != NULL )
		{
		/* Write the header and OID */
		sseek( &stream, 0 );
		writeSequence( &stream, sizeofOID( attributeListPtr->oid ) +
					   ( int ) sizeofObject( attributeListPtr->dataLength ) );
		swrite( &stream, attributeListPtr->oid,
				sizeofOID( attributeListPtr->oid ) );

		/* Check to see whether this is larger than the previous value but
		   smaller than any other one we've seen.  If it is, remember it */
		if( memcmp( prevEncodedForm, buffer, 64 ) < 0 && \
			memcmp( buffer, currentEncodedForm, 64 ) < 0 )
			{
			memcpy( currentEncodedForm, buffer, 64 );
			currentAttributeListPtr = attributeListPtr;
			}
		}

	sMemDisconnect( &stream );

	/* Remember the encoded form of the attribute and return a pointer to
	   it */
	memcpy( prevEncodedForm, currentEncodedForm, 64 );
	return( currentAttributeListPtr );
	}

/* Determine the size of a set of attributes and validate and preprocess the
   attribute information */

int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr )
	{
	int encodeCritical, signUnrecognised, attributeSize = 0;

	/* If there's nothing to write, return now */
	if( attributeListPtr == NULL )
		return( 0 );

	/* Determine the size of the recognised attributes */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &encodeCritical, CRYPT_OPTION_CERT_ENCODE_CRITICAL );
	while( attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] :
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int length = sizeofOID( attributeInfoPtr->oid );

		/* Determine the size of this attribute */
		if( encodeCritical && ( attributeInfoPtr->flags & FL_CRITICAL ) )
			length += sizeofBoolean();
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			length += ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			length += attributeListPtr->encodedSize;
		attributeSize += ( int ) sizeofObject( sizeofObject( length ) );

		/* Skip everything else in the current attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID )
			attributeListPtr = attributeListPtr->next;
		}

	/* If we're not going to be signing the blob-type attributes, return */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &signUnrecognised, 
					 CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
	if( !signUnrecognised )
		return( attributeSize );

	/* Determine the size of the blob-type attributes */
	while( attributeListPtr != NULL )
		{
		attributeSize += ( int ) sizeofObject( sizeofOID( attributeListPtr->oid ) + \
						 ( int ) sizeofObject( attributeListPtr->dataLength ) );
		if( encodeCritical && attributeListPtr->isCritical )
			attributeSize += sizeofBoolean();
		attributeListPtr = attributeListPtr->next;
		}

	return( attributeSize );
	}

/* Write an attribute field */

int writeAttributeField( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr )
	{
	const BOOLEAN isSpecial = ( attributeListPtr->fifoPos ) ? TRUE : FALSE;
	const ATTRIBUTE_INFO *attributeInfoPtr = ( isSpecial ) ? \
		attributeListPtr->encodingFifo[ --attributeListPtr->fifoPos ] :
		attributeListPtr->attributeInfoPtr;
	const void *dataPtr = ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
						  attributeListPtr->smallData : attributeListPtr->data;
	int tag, size, payloadSize, fieldType = attributeInfoPtr->fieldType;

	/* If this is just a marker for a series of CHOICE alternatives, return
	   without doing anything */
	if( fieldType == FIELDTYPE_CHOICE )
		return( CRYPT_OK );

	/* If this is a special-case object, determine the size of the data
	   payload */
	if( isSpecial )
		payloadSize = attributeListPtr->sizeFifo[ attributeListPtr->fifoPos ];

#if 0
	/* If it's a composite object which is being treated as a blob, make the
	   fieldType a blob */
	if( attributeListPtr->isBlob )
		fieldType = FIELDTYPE_BLOB;
#endif

	/* Calculate the size of the encoded data */
	if( isSpecial )
		{
		/* If it's a special-case field, the data size is taken from
		   somewhere other than the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				/* Fixed-value blob (as opposed to user-supplied one) */
				size = ( int ) attributeInfoPtr->defaultValue;
				break;

			case FIELDTYPE_IDENTIFIER:
				size = sizeofOID( attributeInfoPtr->oid );
				break;

			case BER_INTEGER:
				size = sizeofShortInteger( attributeInfoPtr->defaultValue );
				break;

			case BER_SEQUENCE:
			case BER_SET:
				size = ( int ) sizeofObject( payloadSize );
				break;

			default:
				/* Anything else isn't currently handled */
				sSetError( stream, CRYPT_ERROR );
				return( CRYPT_ERROR );
			}
		}
	else
		/* It's a standard object, take the size from the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
			case BER_OBJECT_IDENTIFIER:
				size = attributeListPtr->dataLength;
				break;

			case FIELDTYPE_DN:
				size = sizeofDN( attributeListPtr->data );
				break;

			case FIELDTYPE_IDENTIFIER:
				size = sizeofOID( attributeInfoPtr->oid );
				break;

			case BER_BITSTRING:
				size = sizeofBitString( attributeListPtr->value );
				break;

			case BER_BOOLEAN:
				size = sizeofBoolean();
				break;

			case BER_ENUMERATED:
				size = sizeofEnumerated( attributeListPtr->value );
				break;

			case BER_INTEGER:
				size = sizeofShortInteger( attributeListPtr->value );
				break;

			case BER_TIME_GENERALIZED:
				size = sizeofGeneralizedTime();
				break;

			case BER_TIME_UTC:
				size = sizeofUTCTime();
				break;

			default:
				size = ( int ) sizeofObject( attributeListPtr->dataLength );
			}

	/* If we're just calculating the attribute size, don't write any data */
	if( stream == NULL )
#if 0
		return( ( !attributeListPtr->isBlob && \
				  ( attributeInfoPtr->flags & FL_EXPLICIT ) ) ? \
				( int ) sizeofObject( size ) : size );
#else
		return( ( attributeInfoPtr->flags & FL_EXPLICIT ) ? \
				( int ) sizeofObject( size ) : size );
#endif

	/* If the field is explicitly tagged, add another layer of wrapping */
#if 0
	if( !attributeListPtr->isBlob && \
		( attributeInfoPtr->flags & FL_EXPLICIT ) )
#else
	if( attributeInfoPtr->flags & FL_EXPLICIT )
#endif
		{
		writeCtag( stream, attributeInfoPtr->fieldEncodedType );
		writeLength( stream, size );
		}

	/* If the encoded field type differs from the actual field type (because
	   if implicit tagging), and we're not specifically using explicit
	   tagging, and it's not a DN in a GeneralName (which is a tagged IMPLICIT
	   SEQUENCE overridden to make it EXPLICIT because of the tagged CHOICE
	   encoding rules), set the tag to the encoded field type rather than the
	   actual field type */
	if( attributeInfoPtr->fieldEncodedType && \
		!( attributeInfoPtr->flags & FL_EXPLICIT ) && \
		attributeInfoPtr->fieldType != FIELDTYPE_DN )
		tag = attributeInfoPtr->fieldEncodedType;
	else
		tag = DEFAULT_TAG;

	/* Write the data as appropriate */
	if( isSpecial )
		{
		/* If it's a special-case field, the data is taken from somewhere
		   other than the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				/* Fixed-value blob (as opposed to user-supplied one) */
				swrite( stream, attributeInfoPtr->extraData, size );
				break;

			case FIELDTYPE_IDENTIFIER:
				swrite( stream, attributeInfoPtr->oid, size );
				break;

			case BER_INTEGER:
				writeShortInteger( stream, attributeInfoPtr->defaultValue, tag );
				break;

			case BER_SEQUENCE:
			case BER_SET:
				if( tag != DEFAULT_TAG )
					{
					/* If it's an implicitly tagged sequence, it's a
					   constructed object */
					writeTag( stream, tag | BER_CONSTRUCTED );
					writeLength( stream, payloadSize );
					}
				else
					if( fieldType == BER_SET )
						writeSet( stream, payloadSize );
					else
						writeSequence( stream, payloadSize );
				break;

			default:
				/* Anything else isn't currently handled */
				sSetError( stream, CRYPT_ERROR );
				return( CRYPT_ERROR );
			}
		}
	else
		/* It's a standard object, take the data from the user-supplied data */
		switch( fieldType )
			{
			case FIELDTYPE_BLOB:
				swrite( stream, dataPtr, attributeListPtr->dataLength );
				break;

			case FIELDTYPE_DN:
				writeDN( stream, attributeListPtr->data, tag );
				break;

			case FIELDTYPE_IDENTIFIER:
				swrite( stream, attributeInfoPtr->oid, size );
				break;

			case BER_BITSTRING:
				writeBitString( stream, ( int ) attributeListPtr->value, tag );
				break;

			case BER_BOOLEAN:
				writeBoolean( stream, ( BOOLEAN ) attributeListPtr->value, tag );
				break;

			case BER_ENUMERATED:
				writeEnumerated( stream, ( int ) attributeListPtr->value, tag );
				break;

			case BER_INTEGER:
				writeShortInteger( stream, attributeListPtr->value, tag );
				break;

			case BER_OBJECT_IDENTIFIER:
				if( tag != DEFAULT_TAG )
					{
					/* This gets a bit messy because the OID is stored in
					   encoded form in the attribute, to write it as a tagged
					   value we have to write a different first byte */
					sputc( stream, tag );
					swrite( stream, ( ( BYTE * ) dataPtr ) + 1,
							attributeListPtr->dataLength - 1 );
					}
				else
					swrite( stream, dataPtr, attributeListPtr->dataLength );
				break;

			case BER_OCTETSTRING:
				writeOctetString( stream, dataPtr, attributeListPtr->dataLength, tag );
				break;

			case BER_STRING_IA5:
			case BER_STRING_ISO646:
			case BER_STRING_NUMERIC:
			case BER_STRING_PRINTABLE:
				writeCharacterString( stream, dataPtr, attributeListPtr->dataLength,
								( tag == DEFAULT_TAG ) ? fieldType : tag );
				break;

			case BER_TIME_GENERALIZED:
				writeGeneralizedTime( stream, *( time_t * ) attributeListPtr->smallData, tag );
				break;

			case BER_TIME_UTC:
				writeUTCTime( stream, *( time_t * ) attributeListPtr->smallData, tag );
				break;

			default:
				/* Anything else isn't currently handled */
				sSetError( stream, CRYPT_ERROR );
			}

	return( sGetStatus( stream ) );
	}

/* Write an attribute */

static ATTRIBUTE_LIST *writeAttribute( STREAM *stream,
									   ATTRIBUTE_LIST *attributeListPtr,
									   const int wrapperTag,
									   const BOOLEAN encodeCritical )
	{
	int flagSize;

	/* If it's a non-blob attribute, write it field by field */
	if( !isBlobAttribute( attributeListPtr ) )
		{
		const BOOLEAN isConstructed = ( attributeListPtr->fifoEnd ) ? TRUE : FALSE;
		const ATTRIBUTE_INFO *attributeInfoPtr = ( isConstructed ) ? \
			attributeListPtr->encodingFifo[ attributeListPtr->fifoEnd - 1 ] :
			attributeListPtr->attributeInfoPtr;
		const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
		int dataLength, length = sizeofOID( attributeInfoPtr->oid );

		/* Determine the size of the attribute payload */
		flagSize = ( encodeCritical && ( attributeInfoPtr->flags & FL_CRITICAL ) ) ? \
				   sizeofBoolean() : 0;
		if( isConstructed && attributeInfoPtr->fieldType != FIELDTYPE_CHOICE )
			dataLength = ( int ) sizeofObject( \
				attributeListPtr->sizeFifo[ attributeListPtr->fifoEnd - 1 ] );
		else
			dataLength = attributeListPtr->encodedSize;

		/* Write the outer SEQUENCE, OID, critical flag (if it's set) and
		   appropriate wrapper for the attribute payload */
		writeSequence( stream, length + flagSize + \
					   ( int ) sizeofObject( dataLength ) );
		swrite( stream, attributeInfoPtr->oid,
				sizeofOID( attributeInfoPtr->oid ) );
		if( flagSize )
			writeBoolean( stream, TRUE, DEFAULT_TAG );
		writeTag( stream, wrapperTag );
		writeLength( stream, dataLength );

		/* Write the current attribute */
		while( attributeListPtr != NULL && \
			   attributeListPtr->attributeID == attributeID && \
			   sGetStatus( stream ) == CRYPT_OK )
			{
			/* Write any encapsulating SEQUENCE's if necessary, followed by
			   the field itself.  In some rare instances we may have a zero-
			   length SEQUENCE (if all the member(s) of the sequence have
			   default values), so we only try to write the member if there's
			   encoding information for it present */
			attributeListPtr->fifoPos = attributeListPtr->fifoEnd;
			while( attributeListPtr->fifoPos )
				writeAttributeField( stream, ( ATTRIBUTE_LIST * ) attributeListPtr );
			if( attributeListPtr->attributeInfoPtr != NULL )
				writeAttributeField( stream, ( ATTRIBUTE_LIST * ) attributeListPtr );

			/* Move on to the next attribute field */
			attributeListPtr = attributeListPtr->next;
			}

		return( attributeListPtr );
		}

	/* Write the header, OID, critical flag (if present), and payload wrapped
	   up as appropriate */
	flagSize = ( encodeCritical && attributeListPtr->isCritical ) ? \
			   sizeofBoolean() : 0;
	writeSequence( stream, sizeofOID( attributeListPtr->oid ) + flagSize +
				   ( int ) sizeofObject( attributeListPtr->dataLength ) );
	swrite( stream, attributeListPtr->oid,
			sizeofOID( attributeListPtr->oid ) );
	if( flagSize )
		writeBoolean( stream, TRUE, DEFAULT_TAG );
	writeTag( stream, wrapperTag );
	writeLength( stream, attributeListPtr->dataLength );
	swrite( stream, ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
			attributeListPtr->smallData : attributeListPtr->data,
			attributeListPtr->dataLength );

	return( attributeListPtr->next );
	}

/* Write a set of attributes */

int writeAttributes( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr,
					 const CRYPT_CERTTYPE_TYPE type, const int attributeSize )
	{
	const int wrapperTag = ( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
						   BER_SET : BER_OCTETSTRING;
	int encodeCritical, signUnrecognised;

	/* If there's nothing to write, return now */
	if( attributeSize == 0 )
		return( CRYPT_OK );

	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &encodeCritical, CRYPT_OPTION_CERT_ENCODE_CRITICAL );

	/* Write the X509v3 certificate/CRL extensions tag if it's a certificate 
	   or CRL or the CMMF wrapping if it's a certification request, and the 
	   SEQUENCE OF tag unless it's CMS attributes..  CRL's have two extension 
	   types, per-entry extensions which have only a SEQUENCE OF tag, and 
	   entire-CRL extensions which have an extra context-specific tag.  To 
	   differentiate between the two, we write per-entry extensions with a 
	   type of CRYPT_CERTTYPE_NONE */
	if( type == CRYPT_CERTTYPE_CERTIFICATE || \
		type == CRYPT_CERTTYPE_CRL )
		{
		writeCtag( stream, ( type == CRYPT_CERTTYPE_CERTIFICATE ) ? \
				   CTAG_CE_EXTENSIONS : CTAG_CR_EXTENSIONS );
		writeLength( stream, ( int ) sizeofObject( attributeSize ) );
		}
	if( type == CRYPT_CERTTYPE_CERTREQUEST )
		{
		int innerSize = ( int ) sizeofObject( attributeSize );

		writeSequence( stream, sizeofOID( PKCS9_EXTREQ_OID ) + \
					   ( int ) sizeofObject( innerSize ) );
		swrite( stream, PKCS9_EXTREQ_OID, sizeofOID( PKCS9_EXTREQ_OID ) );
		writeSet( stream, innerSize );
		}
	if( type == CRYPT_CERTTYPE_CMS_ATTRIBUTES )
		{
		ATTRIBUTE_LIST *currentAttributePtr;
		BYTE currentEncodedForm[ 64 ];

		writeCtag( stream, CTAG_SI_AUTHENTICATEDATTRIBUTES );
		writeLength( stream, attributeSize );

		/* CMS attributes work somewhat differently from normal attributes in
		   that, since they're encoded as a SET OF Attribute, they have to be
		   sorted according to their encoded form before being written.  For
		   this reason we don't write them sorted by OID as with the other
		   attributes, but keep writing the next-lowest attribute until
		   they've all been written */
		memset( currentEncodedForm, 0, 64 );	/* Set lowest encoded form */
		currentAttributePtr = getNextEncodedAttribute( attributeListPtr,
													   currentEncodedForm );
		do
			{
			writeAttribute( stream, currentAttributePtr, wrapperTag,
							encodeCritical );
			currentAttributePtr = getNextEncodedAttribute( attributeListPtr,
														   currentEncodedForm );
			}
		while( currentAttributePtr != NULL && \
			   sGetStatus( stream ) == CRYPT_OK );

		return( sGetStatus( stream ) );
		}
	else
		if( type != CRYPT_CERTTYPE_CRMF_REQUEST )
			writeSequence( stream, attributeSize );

	/* Write the known attributes until we reach either the end of the list
	   or the first blob-type attribute */
	while( attributeListPtr != NULL && !isBlobAttribute( attributeListPtr ) && \
		   sGetStatus( stream ) == CRYPT_OK  )
		attributeListPtr = writeAttribute( stream, attributeListPtr,
										   wrapperTag, encodeCritical );

	/* If we're not going to be signing the blob-type attributes, return */
	krnlSendMessage( CRYPT_UNUSED, RESOURCE_IMESSAGE_GETATTRIBUTE, 
					 &signUnrecognised, 
					 CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES );
	if( !signUnrecognised )
		return( sGetStatus( stream ) );

	/* Write the blob-type attributes */
	while( attributeListPtr != NULL && sGetStatus( stream ) == CRYPT_OK  )
		attributeListPtr = writeAttribute( stream, attributeListPtr,
										   wrapperTag, encodeCritical );

	return( sGetStatus( stream ) );
	}
