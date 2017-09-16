/****************************************************************************
*																			*
*					Certificate Attribute Management Routines				*
*						Copyright Peter Gutmann 1996-1999					*
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

/* Prototypes for functions in lib_cert.c */

int textToOID( const char *oid, const int oidLength, BYTE *binaryOID );

/****************************************************************************
*																			*
*								Attribute Type Mapping						*
*																			*
****************************************************************************/

/* Get the attribute information for a given OID */

ATTRIBUTE_INFO *oidToAttribute( const ATTRIBUTE_TYPE attributeType,
								const BYTE *oid )
	{
	ATTRIBUTE_INFO *attributeInfoPtr = ( attributeType == ATTRIBUTE_CMS ) ? \
		( ATTRIBUTE_INFO * ) cmsAttributeInfo : ( ATTRIBUTE_INFO * ) extensionInfo;
	const int length = sizeofOID( oid );

	while( attributeInfoPtr->fieldID != CRYPT_ERROR )
		{
		if( attributeInfoPtr->oid != NULL && \
			sizeofOID( attributeInfoPtr->oid ) == length && \
			!memcmp( attributeInfoPtr->oid, oid, length ) )
			return( attributeInfoPtr );
		attributeInfoPtr++;
		}

	/* It's an unknown attribute */
	return( NULL );
	}

/* Get the attribute and attributeID for a field ID */

static const ATTRIBUTE_INFO *fieldIDToAttribute( const ATTRIBUTE_TYPE attributeType,
		const CRYPT_ATTRIBUTE_TYPE fieldID, const CRYPT_ATTRIBUTE_TYPE subFieldID,
		CRYPT_ATTRIBUTE_TYPE *attributeID )
	{
	const ATTRIBUTE_INFO *attributeInfoPtr = \
		( attributeType == ATTRIBUTE_CMS ) ? cmsAttributeInfo : extensionInfo;
	int i;

	/* Clear the return value */
	if( attributeID != NULL )
		*attributeID = CRYPT_ERROR;

	/* Find the information on this attribute field */
	for( i = 0; attributeInfoPtr[ i ].fieldID != CRYPT_ERROR; i++ )
		{
		/* If the previous entry doesn't have more data following it, the
		   current entry is the start of a complete attribute and therefore
		   contains the attribute ID */
		if( attributeID != NULL && \
			( !i || !( attributeInfoPtr[ i - 1 ].flags & FL_MORE ) ) )
			{
			int j;

			/* Usually the attribute ID is the fieldID for the first entry,
			   however in some cases the attributeID is the same as the
			   fieldID and isn't specified until later on (denoted by the
			   fieldID being FIELDID_FOLLOWS), so we have to look ahead to
			   find it */
			*attributeID = attributeInfoPtr[ i ].fieldID;
			for( j = i + 1; *attributeID == FIELDID_FOLLOWS; j++ )
				*attributeID = attributeInfoPtr[ j ].fieldID;
			}

		/* Check whether the field ID for this entry matches the one we want */
		if( attributeInfoPtr[ i ].fieldID == fieldID )
			{
			ATTRIBUTE_INFO *altEncodingTable = \
						( ATTRIBUTE_INFO * ) attributeInfoPtr[ i ].extraData;

			/* If we're after a subfield match as well, try and match the
			   subfield */
			if( subFieldID != CRYPT_ATTRIBUTE_NONE && altEncodingTable != NULL )
				{
				for( i = 0; altEncodingTable[ i ].fieldID != CRYPT_ERROR; i++ )
					if( altEncodingTable[ i ].fieldID == subFieldID )
						return( &altEncodingTable[ i ] );

				return( NULL );
				}

			return( &attributeInfoPtr[ i ] );
			}
		}

	return( NULL );
	}

/****************************************************************************
*																			*
*					Attribute Location/Cursor Movement Routines				*
*																			*
****************************************************************************/

/* Find the start and end of an attribute from a field within the
   attribute */

static ATTRIBUTE_LIST *findAttributeStart( const ATTRIBUTE_LIST *attributeListPtr )
	{
	ATTRIBUTE_LIST *attributeListCursor = ( ATTRIBUTE_LIST * ) attributeListPtr;
	CRYPT_ATTRIBUTE_TYPE attributeID;

	if( attributeListCursor == NULL )
		return( NULL );
	attributeID = attributeListCursor->attributeID;

	/* Move backwards until we find the start of the attribute */
	while( attributeListCursor->prev != NULL && \
		   attributeListCursor->prev->attributeID == attributeID )
		attributeListCursor = attributeListCursor->prev;

	return( attributeListCursor );
	}

static ATTRIBUTE_LIST *findAttributeEnd( ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;

	if( attributeListPtr == NULL )
		return( NULL );
	attributeID = attributeListPtr->attributeID;

	/* Move forwards until we find the start of the next attribute */
	while( attributeListPtr->next != NULL && \
		   attributeListPtr->next->attributeID == attributeID )
		attributeListPtr = attributeListPtr->next;

	return( attributeListPtr );
	}

/* Find an attribute in a list of certificate attributes by object identifier
   (for blob-type attributes) or by field and subfield ID (for known
   attributes), with extended handling for fields with default values */

ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *listHead,
									const BYTE *oid )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* Find the position of this component in the list */
	for( attributeListPtr = ( ATTRIBUTE_LIST * ) listHead;
		 attributeListPtr != NULL; attributeListPtr = attributeListPtr->next )
		if( sizeofOID( attributeListPtr->oid ) == sizeofOID( oid ) && \
			!memcmp( attributeListPtr->oid, oid, sizeofOID( oid ) ) )
			break;

	return( attributeListPtr );
	}

ATTRIBUTE_LIST *findAttributeField( const ATTRIBUTE_LIST *listHead,
									const CRYPT_ATTRIBUTE_TYPE fieldID,
									const CRYPT_ATTRIBUTE_TYPE subFieldID )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* Find the position of this component in the list */
	for( attributeListPtr = ( ATTRIBUTE_LIST * ) listHead;
		 attributeListPtr != NULL && attributeListPtr->fieldID != fieldID;
		 attributeListPtr = attributeListPtr->next );
	if( subFieldID == CRYPT_ATTRIBUTE_NONE )
		return( attributeListPtr );

	/* Find the subfield in the field */
	while( attributeListPtr != NULL && \
		   attributeListPtr->fieldID == fieldID )
		{
		if( attributeListPtr->subFieldID == subFieldID )
			return( attributeListPtr );
		attributeListPtr = attributeListPtr->next;
		}

	return( NULL );
	}

ATTRIBUTE_LIST *findAttributeFieldEx( const ATTRIBUTE_LIST *listHead,
									  const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	const ATTRIBUTE_TYPE attributeType = ( fieldID >= CRYPT_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	ATTRIBUTE_LIST *attributeListPtr;

	/* Find the position of this component in the list */
	for( attributeListPtr = ( ATTRIBUTE_LIST * ) listHead;
		 attributeListPtr != NULL && attributeListPtr->fieldID != fieldID;
		 attributeListPtr = attributeListPtr->next );

	/* If the field isn't present in the list of attributes, check whether
	   the attribute itself is present and whether this field has a default
	   value */
	if( attributeListPtr == NULL )
		{
		static const ATTRIBUTE_LIST defaultField = { 0, CRYPT_ERROR, 0 };
		static const ATTRIBUTE_LIST completeAttribute = { CRYPT_ERROR, 0, 0 };
		CRYPT_ATTRIBUTE_TYPE attributeID;
		const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
								fieldID, CRYPT_ATTRIBUTE_NONE, &attributeID );
		ATTRIBUTE_LIST *attributeListSearchPtr;

		/* If there's no attribute containing this field, exit */
		if( attributeInfoPtr == NULL )
			return( NULL );

		/* Check whether any part of the attribute which contains the given
		   field is present in the list of attribute fields */
		for( attributeListSearchPtr = ( ATTRIBUTE_LIST * ) listHead;
			 attributeListSearchPtr != NULL && \
				attributeListSearchPtr->attributeID != attributeID;
			 attributeListSearchPtr = attributeListSearchPtr->next );
		if( attributeListSearchPtr == NULL )
			return( NULL );

		/* Some other part of the attribute containing the given field is
		   present in the list.  If this field wasn't found that could either
		   be a default value (in which case we return an entry which denotes
		   that this field is absent but has a default setting) or a field
		   which denotes an entire constructed attribute (in which case we
		   return an entry which denotes this) */
		if( attributeInfoPtr->flags & FL_DEFAULT )
			return( ( ATTRIBUTE_LIST * ) &defaultField );
		if( attributeInfoPtr->fieldType == BER_SEQUENCE )
			return( ( ATTRIBUTE_LIST * ) &completeAttribute );
		}

	return( attributeListPtr );
	}

ATTRIBUTE_LIST *findAttribute( const ATTRIBUTE_LIST *listHead,
							   const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	ATTRIBUTE_LIST *attributeListPtr;

	/* Finding an overall attribute is a bit more complex than finding a
	   field since we may be given an attribute ID (which denotes the entire
	   attribute) or a field ID (which denotes one field in the attribute).
	   First we check for a match on the attribute ID */
	for( attributeListPtr = ( ATTRIBUTE_LIST * ) listHead;
		 attributeListPtr != NULL && attributeListPtr->attributeID != fieldID;
		 attributeListPtr = attributeListPtr->next );
	if( attributeListPtr != NULL )
		return( attributeListPtr );

	/* It wasn't a (present) attribute ID, try again looking for a field
	   within an attribute */
	attributeListPtr = findAttributeField( listHead, fieldID,
										   CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr == NULL )
		return( NULL );

	/* Find the start of the attribute which contains this field */
	return( findAttributeStart( attributeListPtr ) );
	}

/* Get the default value for an optional field of an attribute */

int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID )
	{
	const ATTRIBUTE_TYPE attributeType = ( fieldID >= CRYPT_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
										fieldID, CRYPT_ATTRIBUTE_NONE, NULL );

	return( ( int ) attributeInfoPtr->defaultValue );
	}

/* Determine whether an attribute field is valid for a given certificate
   object type */

BOOLEAN isValidField( const CRYPT_ATTRIBUTE_TYPE fieldID,
					  const CRYPT_CERTTYPE_TYPE certType )
	{
	const ATTRIBUTE_TYPE attributeType = \
					( certType == CRYPT_CERTTYPE_CMS_ATTRIBUTES ) ? \
					ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;
	ATTRIBUTE_INFO *attributeInfoPtr;
	const int certTypeFlag = \
		( certType == CRYPT_CERTTYPE_CERTIFICATE ) ? FL_VALID_CERT : \
		( certType == CRYPT_CERTTYPE_CRL ) ? FL_VALID_CRL : \
		( certType == CRYPT_CERTTYPE_CERTREQUEST || \
		  certType == CRYPT_CERTTYPE_CRMF_REQUEST ) ? FL_VALID_CERTREQ : 0;

	/* Find the attribute this field is a part of and check whether it's
	   allowed for this cert object */
	if( fieldIDToAttribute( attributeType, fieldID, CRYPT_ATTRIBUTE_NONE,
							&attributeID ) == NULL )
		return( FALSE );
	attributeInfoPtr = ( ATTRIBUTE_INFO * ) fieldIDToAttribute( attributeType,
									attributeID, CRYPT_ATTRIBUTE_NONE, NULL );
	return( ( attributeInfoPtr->flags & certTypeFlag ) ? TRUE : FALSE );
	}

/* Move the attribute cursor relative to the current cursor position.  This
   moves as far as possible in the direction given and then returns an
   appropriate return code, either CRYPT_OK or CRYPT_ERROR_NOTFOUND if no
   movement is possible.  Note that it's possible to both return
   CRYPT_ERROR_NOTFOUND and update the cursor, for example if we're halfway
   through the first attribute then a position code of CRYPT_CURSOR_FIRST
   will move to the start of the attribute, but the error will be returned to
   indicate that it wasn't possible to move back before the current
   attribute */

int moveAttributeCursor( ATTRIBUTE_LIST **currentCursor,
						 const BOOLEAN moveByField, const int position )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID = ( *currentCursor )->attributeID;
	ATTRIBUTE_LIST *newCursor = *currentCursor, *lastCursor = NULL;
	int count;

	/* Set the amount we want to move by based on the position code.  This
	   means we can handle the movement in a simple while loop instead of
	   having to special-case it for moves by one item */
	count = ( position == CRYPT_CURSOR_FIRST || \
			  position == CRYPT_CURSOR_LAST ) ? INT_MAX : 1;

	/* Moving by field is relatively simple, just move backwards or forwards
	   until we either run out of fields or the next field belongs to a
	   different attribute */
	if( moveByField )
		{
		if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_PREVIOUS )
			while( count-- && newCursor->prev != NULL && \
				   newCursor->prev->attributeID == attributeID )
				newCursor = newCursor->prev;
		else
			while( count-- && newCursor->next != NULL && \
				   newCursor->next->attributeID == attributeID )
				newCursor = newCursor->next;

		if( *currentCursor == newCursor )
			return( CRYPT_ERROR_NOTFOUND );
		*currentCursor = newCursor;
		return( CRYPT_OK );
		}

	/* Moving by attribute is a bit more complex.  First we find the start or
	   end of the current attribute, if there's another attribute before or
	   after it move back/forwards into that attribute and find the start of
	   that.  This has the effect of moving us from anywhere in the current
	   attribute to the start of the preceding or following attribute.
	   Finally, we repeat this as required */
	if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_PREVIOUS )
		while( count-- && newCursor != NULL )
			{
			lastCursor = newCursor;
			newCursor = findAttributeStart( findAttributeStart( newCursor )->prev );
			}
	else
		while( count-- && newCursor != NULL && \
			   newCursor->attributeID != CRYPT_ATTRIBUTE_NONE )
			{
			lastCursor = newCursor;
			newCursor = findAttributeEnd( newCursor )->next;
			}

	/* We've gone as far as we can.  If the new cursor is NULL, we've reached
	   the start or end of the attribute list, in case we haven't moved at all
	   we call findAttributeStart() to move to the first field.  If the new
	   cursor isn't NULL, it's located on the next or previous attribute */
	if( newCursor == NULL )
		*currentCursor = findAttributeStart( lastCursor );
	else
		*currentCursor = newCursor;
	if( *currentCursor == NULL )
		/* Positioning in null attribute lists is always unsuccessful */
		return( CRYPT_ERROR_NOTFOUND );
	if( position == CRYPT_CURSOR_FIRST || position == CRYPT_CURSOR_LAST )
		/* Absolute positioning is always successful */
		return( CRYPT_OK );
	return( ( ( *currentCursor )->attributeID == attributeID ) ? \
			CRYPT_ERROR_NOTFOUND : CRYPT_OK );
	}

/****************************************************************************
*																			*
*							Attribute Management Routines					*
*																			*
****************************************************************************/

/* Insert an element into an attribute list after the given insertion point */

static void insertListElements( ATTRIBUTE_LIST **listHeadPtr,
								ATTRIBUTE_LIST *insertPoint,
								ATTRIBUTE_LIST *newStartElement,
								ATTRIBUTE_LIST *newEndElement )
	{
	/* If it's an empty list, make this the new list */
	if( *listHeadPtr == NULL )
		{
		*listHeadPtr = newStartElement;
		return;
		}

	/* If we're inserting at the start of the list, make this the new first
	   element */
	if( insertPoint == NULL )
		{
		/* Insert the element at the start of the list */
		newEndElement->next = *listHeadPtr;
		( *listHeadPtr )->prev = newEndElement;
		*listHeadPtr = newStartElement;
		return;
		}

	/* Insert the element in the middle or end of the list.  Update the links
	   for the next element */
	newEndElement->next = insertPoint->next;
	if( insertPoint->next != NULL )
		insertPoint->next->prev = newEndElement;

	/* Update the links for the previous element */
	insertPoint->next = newStartElement;
	newStartElement->prev = insertPoint;
	}

/* Add a blob-type attribute to a list of attributes */

int addAttribute( const ATTRIBUTE_TYPE attributeType,
				  ATTRIBUTE_LIST **listHeadPtr, const BYTE *oid,
				  const BOOLEAN criticalFlag, const void *data,
				  const int dataLength )
	{
	ATTRIBUTE_LIST *newElement, *insertPoint;

	/* If this attribute type is already handled as a non-blob attribute,
	   don't allow it to be added as a blob as well.  This avoids problems
	   with the same attribute being added twice, once as a blob and once as
	   a non-blob.  In addition it forces the caller to use the (recommended)
	   normal attribute handling mechanism which allows for proper type
	   checking */
	if( oidToAttribute( attributeType, oid ) != NULL )
		return( CRYPT_ERROR_PERMISSION );

	/* Find the correct place in the list to insert the new element */
	if( *listHeadPtr != NULL )
		{
		ATTRIBUTE_LIST *prevElement = NULL;

		for( insertPoint = *listHeadPtr; insertPoint != NULL;
			 insertPoint = insertPoint->next )
			{
			/* Make sure this blob attribute isn't already present */
			if( insertPoint->attributeID != CRYPT_ATTRIBUTE_NONE && \
				sizeofOID( insertPoint->oid ) == sizeofOID( oid ) && \
				!memcmp( insertPoint->oid, oid, sizeofOID( oid ) ) )
				return( CRYPT_ERROR_INITED );

			prevElement = insertPoint;
			}
		insertPoint = prevElement;
		}

	/* Allocate memory for the new element and copy the information across */
	if( ( newElement  = ( ATTRIBUTE_LIST * ) malloc( sizeof( ATTRIBUTE_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( ATTRIBUTE_LIST ) );
	memcpy( newElement->oid, oid, sizeofOID( oid ) );
	newElement->isCritical = criticalFlag;
	if( dataLength <= CRYPT_MAX_TEXTSIZE )
		memcpy( newElement->smallData, data, dataLength );
	else
		{
		if( ( newElement->data = malloc( dataLength ) ) == NULL )
			{
			free( newElement );
			return( CRYPT_ERROR_MEMORY );
			}
		memcpy( newElement->data, data, dataLength );
		}
	newElement->dataLength = dataLength;
	insertListElements( listHeadPtr, insertPoint, newElement, newElement );

	return( CRYPT_OK );
	}

/* Add an attribute field at the appropriate location to a list of
   attributes after checking its validity */

static int checkAttributeField( const ATTRIBUTE_LIST *attributeList,
								const CRYPT_ATTRIBUTE_TYPE fieldID,
								const CRYPT_ATTRIBUTE_TYPE subFieldID,
								const void *data, const int dataLength,
								const BOOLEAN isBlob, 
								CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( fieldID >= CRYPT_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
												fieldID, subFieldID, NULL );
	ATTRIBUTE_LIST *attributeListSearchPtr;

	/* Make sure that a valid field has been specified, and that this field
	   isn't already present as a non-default entry */
	if( attributeInfoPtr == NULL )
		return( CRYPT_ARGERROR_VALUE );
	attributeListSearchPtr = findAttributeField( attributeList, fieldID,
												 subFieldID );
	if( attributeListSearchPtr != NULL )
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
		return( CRYPT_ERROR_INITED );
		}

	/* If it's a blob field, don't do any type checking.  This is a special
	   case which differs from FIELDTYPE_BLOB in that it corresponds to an
	   ASN.1 value which is mis-encoded by one or more implementations so we
	   have to accept absolutely anything at this point */
	if( isBlob )
		return( CRYPT_OK );

	/* If it's an identifier or special-case field, make sure all parameters
	   are CRYPT_UNUSED */
	if( attributeInfoPtr->fieldType == FIELDTYPE_IDENTIFIER || \
		attributeInfoPtr->fieldType == FIELDTYPE_DN || \
		attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
		{
		const int value = *( ( int * ) data );

		/* Make sure the data value is correct */
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
			{
			if( value < attributeInfoPtr->lowRange || \
				value > attributeInfoPtr->highRange )
				return( CRYPT_ARGERROR_NUM1 );
			}
		else
			if( value != CRYPT_UNUSED )
				return( CRYPT_ARGERROR_NUM1 );

		return( CRYPT_OK );
		}

	/* If it's an OID, convert it to a binary OID (which performs a syntax
	   check on the OID) */
	if( attributeInfoPtr->fieldType == BER_OBJECT_IDENTIFIER )
		{
		BYTE binaryOID[ CRYPT_MAX_TEXTSIZE ];

		if( !textToOID( data, dataLength, binaryOID ) )
			{
			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ARGERROR_STR1 );
			}

		return( CRYPT_OK );
		}

	/* If it's an integer type, type check it */
	if( attributeInfoPtr->fieldType == BER_INTEGER || \
		attributeInfoPtr->fieldType == BER_ENUMERATED || \
		attributeInfoPtr->fieldType == BER_BITSTRING || \
		attributeInfoPtr->fieldType == BER_BOOLEAN )
		{
		int value = *( ( int * ) data );

		/* Convert BOOLEAN data to the correct range */
		if( attributeInfoPtr->fieldType == BER_BOOLEAN )
			value = ( value ) ? TRUE : FALSE;

		/* Check that the data size and range is valid */
		if( value < attributeInfoPtr->lowRange || \
			value > attributeInfoPtr->highRange )
			{
			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ARGERROR_STR1 );
			}

		return( CRYPT_OK );
		}

	/* Type check the value */
	if( dataLength < attributeInfoPtr->lowRange || \
		dataLength > attributeInfoPtr->highRange )
		{
		if( errorType != NULL )
			*errorType = CRYPT_ERRTYPE_ATTR_SIZE;
		return( CRYPT_ARGERROR_NUM1 );
		}
	if( attributeInfoPtr->fieldType == FIELDTYPE_BLOB )
		{
		/* If it's a blob field, make sure it's a valid ASN.1 object */
		if( cryptStatusError( getObjectLength( data, dataLength ) ) )
			{
			if( errorType != NULL )
				*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
			return( CRYPT_ARGERROR_STR1 );
			}
		}
	if( attributeInfoPtr->fieldType == BER_STRING_NUMERIC )
		{
		const char *dataPtr = data;
		int i;

		for( i = 0; i < dataLength; i++ )
			if( !isdigit( dataPtr[ i ] ) )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
		}
	if( attributeInfoPtr->fieldType == BER_STRING_IA5 || \
		attributeInfoPtr->fieldType == BER_STRING_ISO646 || \
		attributeInfoPtr->fieldType == BER_STRING_PRINTABLE )
		{
		const char *dataPtr = data;
		BOOLEAN isOK = TRUE;
		int i;

		for( i = 0; i < dataLength; i++ )
			{
			const char ch = dataPtr[ i ];

			if( !isprint( ch ) )
				isOK = FALSE;
			if( attributeInfoPtr->fieldType == BER_STRING_PRINTABLE && \
				( ( ch >= '!' && ch <= '&' ) || ch == '*' || ch == ';' || \
				  ch == '<' || ch == '>' || ch == '@' || \
				  ( ch >= '[' && ch <= '`' ) || ch >= '{' ) )
				isOK = FALSE;
			if( !isOK )
				{
				if( errorType != NULL )
					*errorType = CRYPT_ERRTYPE_ATTR_VALUE;
				return( CRYPT_ARGERROR_STR1 );
				}
			}
		}

	return( CRYPT_OK );
	}

int addAttributeField( ATTRIBUTE_LIST **listHeadPtr,
					   const CRYPT_ATTRIBUTE_TYPE fieldID,
					   const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   const void *data, const int dataLength,
					   const BOOLEAN criticalFlag, const BOOLEAN isBlob,
					   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					   CRYPT_ERRTYPE_TYPE *errorType )
	{
	const ATTRIBUTE_TYPE attributeType = ( fieldID >= CRYPT_FIRST_CMS ) ? \
									ATTRIBUTE_CMS : ATTRIBUTE_CERTIFICATE;
	CRYPT_ATTRIBUTE_TYPE attributeID;
	const ATTRIBUTE_INFO *attributeInfoPtr = fieldIDToAttribute( attributeType,
										fieldID, subFieldID, &attributeID );
	ATTRIBUTE_LIST *newElement, *insertPoint, *prevElement = NULL;
	int status;

	assert( attributeInfoPtr != NULL );

	/* Check the fields validity if necessary */
	status = checkAttributeField( *listHeadPtr, fieldID, subFieldID, data,
								  dataLength, isBlob, errorType );
	if( cryptStatusError( status ) )
		{
		if( errorType != NULL && cryptStatusError( *errorType ) )
			/* If we encountered an error which sets the error type, record
			   the locus */
			*errorLocus = fieldID;
		return( status );
		}

	/* Find the location at which to insert this attribute field.  For now
	   we assume that the fieldID's are defined in sorted order, we may need
	   to change this and add internal mapping if new fieldID's are added out
	   of order.

	   This loop has a somewhat complex double test, the simpler one is done
	   for basic fields which are identified by the field ID (exit as soon as
	   we find a higher field ID), the more complex one is done for composite
	   fields which can have multiple fields with the same field ID. In this
	   case we exit if the overall field ID is greater (the component belongs
	   to a different field entirely) or if the field ID is the same, when the
	   subfield ID is greater (if the component belongs to the same field) */
	insertPoint = *listHeadPtr;
	while( insertPoint != NULL && \
		   insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE )
		{
		if( subFieldID == CRYPT_ATTRIBUTE_NONE )
			{
			if( insertPoint->fieldID >= fieldID )
				break;
			}
		else
			if( insertPoint->fieldID > fieldID || \
				( insertPoint->fieldID == fieldID && \
				  insertPoint->subFieldID >= subFieldID ) )
				break;

		prevElement = insertPoint;
		insertPoint = insertPoint->next;
		}
	insertPoint = prevElement;

	/* Allocate memory for the new element and copy the information across.
	   If it's a simple type we can assign it to the simple value in the
	   element itself, otherwise we either copy into the storage in the
	   element or allocate seperate storage and copy it into that */
	if( ( newElement  = ( ATTRIBUTE_LIST * ) malloc( sizeof( ATTRIBUTE_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memset( newElement, 0, sizeof( ATTRIBUTE_LIST ) );
	newElement->attributeID = attributeID;
	newElement->fieldID = fieldID;
	newElement->subFieldID = subFieldID;
	newElement->isCritical = criticalFlag;
	newElement->fieldType = attributeInfoPtr->fieldType;
	if( attributeInfoPtr->fieldType == BER_INTEGER || \
		attributeInfoPtr->fieldType == BER_ENUMERATED || \
		attributeInfoPtr->fieldType == BER_BITSTRING || \
		attributeInfoPtr->fieldType == BER_BOOLEAN || \
		attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
		{
		newElement->value = *( ( int * ) data );
		if( attributeInfoPtr->fieldType == BER_BOOLEAN )
			/* Force it to the correct type if it's a boolean */
			newElement->value = ( newElement->value ) ? TRUE : FALSE;
		if( attributeInfoPtr->fieldType == FIELDTYPE_CHOICE )
			/* For encoding purposes the subfield ID is set to the ID of the
			   CHOICE selection */
			newElement->subFieldID = newElement->value;
		}
	else
		if( attributeInfoPtr->fieldType == BER_OBJECT_IDENTIFIER )
			newElement->dataLength = textToOID( data, dataLength,
												newElement->smallData );
		else
			if( attributeInfoPtr->fieldType != FIELDTYPE_IDENTIFIER && \
				attributeInfoPtr->fieldType != FIELDTYPE_DN )
				{
				if( dataLength <= CRYPT_MAX_TEXTSIZE )
					memcpy( newElement->smallData, data, dataLength );
				else
					{
					if( ( newElement->data = malloc( dataLength ) ) == NULL )
						{
						free( newElement );
						return( CRYPT_ERROR_MEMORY );
						}
					memcpy( newElement->data, data, dataLength );
					}
				newElement->dataLength = dataLength;
				}
	insertListElements( listHeadPtr, insertPoint, newElement, newElement );

	return( CRYPT_OK );
	}

/* Copy an attribute from one attribute list to another.  This is an all-or-
   nothing copy in that it either copies a complete attribute or nothing at
   all */

static int copyAttributeField( ATTRIBUTE_LIST **destAttributeField,
							   const ATTRIBUTE_LIST *srcAttributeField )
	{
	ATTRIBUTE_LIST *newElement;
	int status = CRYPT_OK;

	/* Allocate memory for the new element and copy the information across.
	   If it's a simple type we can assign it to the simple value in the
	   element itself, otherwise we either copy into the storage in the
	   element or allocate seperate storage and copy it into that */
	*destAttributeField = NULL;
	if( ( newElement = ( ATTRIBUTE_LIST * ) malloc( sizeof( ATTRIBUTE_LIST ) ) ) == NULL )
		return( CRYPT_ERROR_MEMORY );
	memcpy( newElement, srcAttributeField, sizeof( ATTRIBUTE_LIST ) );
	if( srcAttributeField->dataLength > CRYPT_MAX_TEXTSIZE )
		{
		/* If the payload doesn't fit into the attribute structure, copy the
		   separate data payload across */
		if( ( newElement->data = malloc( srcAttributeField->dataLength ) ) == NULL )
			status = CRYPT_ERROR_MEMORY;
		else
			memcpy( newElement->data, srcAttributeField->data,
					srcAttributeField->dataLength );
		}
	if( srcAttributeField->fieldType == FIELDTYPE_DN )
		/* If the field contains a DN, copy the DN across */
		status = copyDN( ( DN_COMPONENT ** ) &newElement->data,
						 srcAttributeField->data );
	if( cryptStatusError( status ) )
		{
		free( newElement );
		return( status );
		}
	newElement->next = newElement->prev = NULL;
	*destAttributeField = newElement;

	return( CRYPT_OK );
	}

static int copyAttribute( ATTRIBUTE_LIST **listHeadPtr,
						  const ATTRIBUTE_LIST *attributeListPtr,
						  const BOOLEAN subjectToIssuer )
	{
	const CRYPT_ATTRIBUTE_TYPE attributeID = attributeListPtr->attributeID;
	CRYPT_ATTRIBUTE_TYPE newAttributeID = attributeID, newFieldID = attributeID;
	ATTRIBUTE_LIST *newAttributeListHead = NULL, *newAttributeListTail;
	ATTRIBUTE_LIST *insertPoint, *prevElement = NULL;

	/* If we're copying from an issuer to a subject attribute list and the
	   field is an altName or keyIdentifier, change the field type from
	   issuer.subjectAltName to subject.issuerAltName or
	   issuer.subjectKeyIdentifier to subject.authorityKeyIdentifier */
	if( subjectToIssuer )
		{
		if( attributeID == CRYPT_CERTINFO_SUBJECTALTNAME )
			newAttributeID = newFieldID = CRYPT_CERTINFO_ISSUERALTNAME;
		if( attributeID == CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER )
			{
			newAttributeID = CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER;
			newFieldID = CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER;
			}
		}

	/* Find the location at which to insert this attribute.  For now we
	   assume that the fieldID's are defined in sorted order, we may need to
	   change this and add internal mapping if new fieldID's are added out of
	   order */
	for( insertPoint = *listHeadPtr;
		 insertPoint != NULL && insertPoint->attributeID < newAttributeID && \
			insertPoint->fieldID != CRYPT_ATTRIBUTE_NONE;
		 insertPoint = insertPoint->next )
		prevElement = insertPoint;
	insertPoint = prevElement;

	/* Build a new attribute list containing the attribute fields */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attributeID == attributeID )
		{
		ATTRIBUTE_LIST *newAttributeField;
		int status;

		/* Copy the field across, append it to the new attribute list, and
		   adjust the type for issuer->subject copying if necessary */
		status = copyAttributeField( &newAttributeField, attributeListPtr );
		if( cryptStatusError( status ) )
			{
			deleteAttributes( &newAttributeListHead );
			return( CRYPT_ERROR_MEMORY );
			}
		if( newAttributeListHead == NULL )
			newAttributeListHead = newAttributeListTail = newAttributeField;
		else
			{
			newAttributeListTail->next = newAttributeField;
			newAttributeField->prev = newAttributeListTail;
			newAttributeListTail = newAttributeField;
			}
		if( newAttributeID != attributeID )
			{
			newAttributeField->attributeID = newAttributeID;
			newAttributeField->fieldID = newFieldID;
			}

		/* Move on to the next field */
		attributeListPtr = attributeListPtr->next;
		}

	/* Link the new list into the existing list at the appropriate position */
	insertListElements( listHeadPtr, insertPoint, newAttributeListHead,
						newAttributeListTail );

	return( CRYPT_OK );
	}

/* Copy a complete attribute list up to the blob-type attributes */

int copyAttributes( ATTRIBUTE_LIST **destListHeadPtr,
					ATTRIBUTE_LIST *srcListPtr,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType )
	{
	ATTRIBUTE_LIST *attributeListCursor = srcListPtr;

	/* Make a first pass down the list checking that the attribute to copy
	   isn't already present, first for recognised attributes and then for
	   unrecognised ones.  We have to do this separately since once we begin
	   the copy process it's rather hard to undo it */
	while( attributeListCursor != NULL && \
		   !isBlobAttribute( attributeListCursor ) )
		{
		if( findAttributeField( *destListHeadPtr,
				attributeListCursor->fieldID, CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = attributeListCursor->fieldID;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		attributeListCursor = attributeListCursor->next;
		}
	while( attributeListCursor != NULL )
		{
		if( findAttributeByOID( *destListHeadPtr, attributeListCursor->oid ) != NULL )
			{
			/* We can't set the locus for blob-type attributes since it's not
			   a known attribute */
			*errorLocus = CRYPT_ATTRIBUTE_NONE;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		attributeListCursor = attributeListCursor->next;
		}

	/* Make a second pass copying everything across */
	while( srcListPtr != NULL && !isBlobAttribute( srcListPtr ) )
		{
		CRYPT_ATTRIBUTE_TYPE attributeID = srcListPtr->attributeID;
		int status;

		/* Copy the complete attribute across */
		status = copyAttribute( destListHeadPtr, srcListPtr, FALSE );
		if( cryptStatusError( status ) )
			return( status );

		/* Move on to the next attribute */
		while( srcListPtr != NULL && srcListPtr->attributeID == attributeID )
			srcListPtr = srcListPtr->next;
		}

	/* If there are blob-type attributes left at the end of the list, copy
	   them across last */
	if( srcListPtr != NULL )
		{
		ATTRIBUTE_LIST *insertPoint;

		/* Find the end of the destination list */
		for( insertPoint = *destListHeadPtr;
			 insertPoint != NULL && insertPoint->next != NULL;
			 insertPoint = insertPoint->next );

		/* Copy all remaining attributes across */
		while( srcListPtr != NULL )
			{
			ATTRIBUTE_LIST *newAttribute;
			int status;

			status = copyAttributeField( &newAttribute, srcListPtr );
			if( cryptStatusError( status ) )
				return( status );
			insertListElements( destListHeadPtr, insertPoint, newAttribute,
								newAttribute );
			srcListPtr = srcListPtr->next;
			}
		}

	return( CRYPT_OK );
	}

/* Copy attributes which are propagated down cert chains from an issuer to a
   subject cert, changing the field types from subject to issuer at the same
   time if required */

int copyIssuerAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType,
						  const CRYPT_CERTTYPE_TYPE type )
	{
	ATTRIBUTE_LIST *attributeListPtr;
	int status = CRYPT_OK;

	/* If the destination is a CA cert and the source has name constraints,
	   copy them over to the destination */
	attributeListPtr = findAttribute( *destListHeadPtr, CRYPT_CERTINFO_CA );
	if( attributeListPtr != NULL && attributeListPtr->value )
		{
		ATTRIBUTE_LIST *srcPermittedSubtrees, *srcExcludedSubtrees;

		srcPermittedSubtrees = findAttributeField( srcListPtr,
					CRYPT_CERTINFO_PERMITTEDSUBTREES, CRYPT_ATTRIBUTE_NONE );
		srcExcludedSubtrees = findAttributeField( srcListPtr,
        			CRYPT_CERTINFO_EXCLUDEDSUBTREES, CRYPT_ATTRIBUTE_NONE );

		/* If we're copying permitted or excluded subtrees, they can't
		   already be present */
		if( srcPermittedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr, \
            		CRYPT_CERTINFO_PERMITTEDSUBTREES, CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_PERMITTEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}
		if( srcExcludedSubtrees != NULL && \
			findAttributeField( *destListHeadPtr,
            		CRYPT_CERTINFO_EXCLUDEDSUBTREES, CRYPT_ATTRIBUTE_NONE ) != NULL )
			{
			*errorLocus = CRYPT_CERTINFO_EXCLUDEDSUBTREES;
			*errorType = CRYPT_ERRTYPE_ATTR_PRESENT;
			return( CRYPT_ERROR_DUPLICATE );
			}

		/* Copy the fields across */
		if( srcPermittedSubtrees != NULL )
			status = copyAttribute( destListHeadPtr, srcPermittedSubtrees, FALSE );
		if( cryptStatusOK( status ) && srcExcludedSubtrees != NULL )
			status = copyAttribute( destListHeadPtr, srcExcludedSubtrees, FALSE );
		if( cryptStatusError( status ) )
			return( status );
		}

	/* If it's an attribute certificate, that's all we can copy */
	if( type == CRYPT_CERTTYPE_ATTRIBUTE_CERT )
		return( CRYPT_OK );

	/* Copy the altName and keyIdentifier if these are present.  We don't
	   have to check for their presence in the destination cert since they're
	   read-only fields and can't be added by the user */
	attributeListPtr = findAttributeField( srcListPtr,
					CRYPT_CERTINFO_SUBJECTALTNAME, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}
	attributeListPtr = findAttributeField( srcListPtr,
					CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, CRYPT_ATTRIBUTE_NONE );
	if( attributeListPtr != NULL )
		{
		status = copyAttribute( destListHeadPtr, attributeListPtr, TRUE );
		if( cryptStatusError( status ) )
			return( status );
		}

	return( CRYPT_OK );
	}

/* Delete an attribute/attribute field from a list of attributes, updating
   the list cursor at the same time (this is a somewhat ugly kludge, it's
   not really possible to do this cleanly) */

void deleteAttributeField( ATTRIBUTE_LIST **listHeadPtr,
						   ATTRIBUTE_LIST **listCursorPtr,
						   ATTRIBUTE_LIST *listItem )
	{
	ATTRIBUTE_LIST *listPrevPtr = listItem->prev;
	ATTRIBUTE_LIST *listNextPtr = listItem->next;

	/* If we're about to delete the field which is pointed to by the
	   attribute cursor, advance the cursor to the next field.  If there's no
	   next field, move it to the previous field.  This behaviour is the most
	   logically consistent, it means we can do things like deleting an
	   entire attribute list by repeatedly deleting a field */
	if( listCursorPtr != NULL && *listCursorPtr == listItem )
		*listCursorPtr = ( listNextPtr != NULL ) ? listNextPtr : listPrevPtr;

	/* Remove the item from the list */
	if( listItem == *listHeadPtr )
		{
		/* Special case for first item */
		*listHeadPtr = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = NULL;
		}
	else
		{
		/* Delete from the middle or the end of the chain */
		listPrevPtr->next = listNextPtr;
		if( listNextPtr != NULL )
			listNextPtr->prev = listPrevPtr;
		}

	/* Clear all data in the item and free the memory */
	if( listItem->fieldType == FIELDTYPE_DN )
		deleteDN( ( DN_COMPONENT ** ) &listItem->data );
	else
		if( listItem->dataLength > CRYPT_MAX_TEXTSIZE )
			{
			zeroise( listItem->data, listItem->dataLength );
			free( listItem->data );
			}
	zeroise( listItem, sizeof( ATTRIBUTE_LIST ) );
	free( listItem );
	}

void deleteAttribute( ATTRIBUTE_LIST **listHeadPtr,
					  ATTRIBUTE_LIST **listCursorPtr,
					  ATTRIBUTE_LIST *listItem )
	{
	CRYPT_ATTRIBUTE_TYPE attributeID;
	ATTRIBUTE_LIST *attributeListPtr;

	/* If it's a blob-type attribute, everything is contained in this one
	   list item so we only need to destroy that */
	if( isBlobAttribute( listItem ) )
		{
		deleteAttributeField( listHeadPtr, listCursorPtr, listItem );
		return;
		}

	/* If it's a field which denotes an entire (constructed) attribute, it
	   won't have an entry in the list, so we find the first field of the
	   constructed attribute which is present in the list and start deleting
	   from that point */
	if( isCompleteAttribute( listItem ) )
		{
		for( attributeListPtr = *listHeadPtr; attributeListPtr != NULL && \
			 attributeListPtr->attributeID != listItem->value;
			 attributeListPtr = attributeListPtr->next );
		assert( attributeListPtr != NULL );
		}
	else
		/* The list item is a field in the attribute, find the start of the
		   fields in this attribute */
		attributeListPtr = findAttributeStart( listItem );
	attributeID = attributeListPtr->attributeID;

	/* It's an item with multiple fields, destroy each field separately */
	while( attributeListPtr != NULL && \
		   attributeListPtr->attributeID == attributeID )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListPtr;

		attributeListPtr = attributeListPtr->next;
		deleteAttributeField( listHeadPtr, listCursorPtr, itemToFree );
		}
	}

/* Delete a certificate attribute component list */

void deleteAttributes( ATTRIBUTE_LIST **listHeadPtr )
	{
	ATTRIBUTE_LIST *attributeListPtr = *listHeadPtr;

	/* If the list was empty, return now */
	if( attributeListPtr == NULL )
		return;

	/* Destroy any remaining list items */
	while( attributeListPtr != NULL )
		{
		ATTRIBUTE_LIST *itemToFree = attributeListPtr;

		attributeListPtr = attributeListPtr->next;
		deleteAttributeField( listHeadPtr, NULL, itemToFree );
		}
	}
