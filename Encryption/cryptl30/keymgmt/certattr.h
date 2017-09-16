/****************************************************************************
*																			*
*			Certificate Attribute Handling Structures and Prototypes 		*
*						Copyright Peter Gutmann 1997-1998					*
*																			*
****************************************************************************/

#ifndef _CERTATTR_DEFINED

#define _CERTATTR_DEFINED

/* The attribute type information.  This is used to both check the validity
   of attribute data and to describe the structure of an attribute.  For
   example to describe the structure of the basicConstraints certificate
   extension the entries would be:

	fieldID = CRYPT_CERTINFO_BASICCONSTRAINTS, fieldType = BER_SEQUENCE,
			OID = xxx, flags = FL_CRITICAL, FL_VALID_CERT, FL_MORE
	fieldID = CRYPT_CERTINFO_CA, fieldType = BER_BOOLEAN,
			flags = FL_OPTIONAL, FL_DEFAULT, FL_MORE, default = FALSE
	fieldID = CRYPT_CERTINFO_PATHLENCONSTRAINT, fieldType = BER_INTEGER,
			flags = FL_OPTIONAL

   If the attribute has a single member rather than being built up as a
   SEQUENCE then the OID is set but the field-specific values are also set,
   so keyUsage would be:

	fieldID = CRYPT_CERTINFO_KEYUSAGE, fieldType = BER_BITSTRING,
			OID = xxx, flags = FL_CRITICAL, FL_VALID_CERTREQ, FL_VALID_CERT

   There are many special cases to handle things like no vs implicit vs
   explicit tagging (the X.509v3 default is to use implicit tags for
   attributes, so any explicit tags have to be explicitly specified):

	fieldID = CRYPT_NOTAG, fieldType = BER_INTEGER
	fieldID = CRYPT_IMPLICIT_TAG, fieldType = BER_INTEGER,
		fieldEncodedType = CTAG( 0 )
	fieldID = CRYPT_EXPLICIT_TAG, fieldType = BER_INTEGER,
		fieldEncodedType = CTAG( 0 ), flags = FL_EXPLICIT

   Constructed objects are handled by starting them with a BER_SEQUENCE and
   ending them with a BER_SEQEND flag at the last member:

	fieldID = CRYPT_SEQUENCE, fieldType = BER_SEQUENCE,
		flags = FL_MORE
	fieldID = CRYPT_SEQUENCE_INTEGER, fieldType = BER_INTEGER,
		flags = FL_MORE
	fieldID = CRYPT_SEQUENCE_BOOLEAN, fieldType = BER_BOOLEAN,
		flags = FL_SEQEND

   The following flags are applied for each entry */

#define FL_CRITICAL			0x0001	/* Critical certificate extension */
#define FL_OPTIONAL			0x0002	/* Optional field */
#define FL_DEFAULT			0x0004	/* Field has default value */
#define FL_EXPLICIT			0x0008	/* Explicitly tagged field */
#define FL_IDENTIFIER		0x0010	/* Field is OID for following field */
#define FL_SETOF			0x0020	/* Field contains SET OF */
#define FL_NONENCODING		0x0040	/* Field is a non-encoding value */
#define FL_RO				0x0080	/* Field is read-only */
#define FL_SEQEND			0x0100	/* End of constructed object */
#define FL_SEQEND_1			0x0100	/*  End of cons.obj, one nesting lvl.*/
#define FL_SEQEND_2			0x0200	/*  End of cons.obj, two nesting lvl.*/
#define FL_SEQEND_3			0x0300	/*  End of cons.obj, three nesting lvls.*/
#define FL_VALID_CERT		0x0400	/* Attribute valid in a cert */
#define FL_VALID_ATTRCERT	0x0800	/* Attribute valid in an attrib.cert */
#define FL_VALID_CRL		0x1000	/* Attribute valid in a CRL */
#define FL_VALID_CERTREQ	0x2000	/* Attribute valid in a cert.request */
#define FL_MORE				0x4000	/* Further entries follow */

/* The FL_CRITICAL and FL_VALID_xxx flags are only set for an attribute as a
   whole.

   CRL's actually contain two sets of extensions, one for the entire CRL
   (crlExtensions) and the other for each entry in the CRL
   (crlEntryExtension).  Since the cryptlib API doesn't currently support the
   kind of access required to access this second type (a certificate entry
   which contains another certificate object which itself contains further
   entries) these aren't supported (the validity flag is set to 0 in the
   encoding table).

   If a constructed field is nested (for example a SEQUENCE OF SEQUENCE), the
   FL_SEQEND may need to denote multiple levels of unnesting.  This is done
   by using FL_SEQEND_n, the following macro can be used to extract the
   actual level of nesting */

#define decodeNestingLevel( flags )	( ( ( int ) ( flags ) >> 8 ) & 3 )

/* Some fields are of the type:

	SEQUENCE {
		identifier	OBJECT IDENTIFIER
		data		ANY DEFINED BY identifier
		}

   For these types the field named with CRYPT_CERTINFO_xxx is the data field,
   and the encapsulating sequence is flagged with FL_IDENTIFIER to indicate
   that it should only be encoded if the data field is present.  If the data
   field isn't present, the entire SEQUENCE is skipped, so the FL_IDENTIFIER
   is a kind of linked FL_OPTIONAL in that the field is omitted if the data
   field is omitted.

   Fields of the type SET OF x or SEQUENCE OF x are flagged with FL_SETOF to
   indicate that the following constructed object may contain one or more
   instances of an item, usually a { type, value } sequence.  This covers
   both sets and sequences, since recent ASN.1 usage favours SEQUENCE OF
   where a SET OF should be used in order to avoid the encoding problems of
   SET OF.  Even though the field may be declared as a SEQUENCE OF, it
   behaves like a SET OF without the encoding hassles.

   Some fields aren't used for encoding user-supplied data but must be read
   and written when processing an attribute (for example version numbers).
   These are flagged with FL_NONENCODING which means they're read and written
   but not associated with any user data.

   Some fields have an intrinsic value but no explicitly set value (that is,
   their presence communicates the information they are intended to convey,
   but the fields themselves contain no actual data).  This applies for
   fields which contain OIDs which denote certain things (for example cert.
   policies or key usage).  To denote these identifier fields, the field type
   is set to FIELDTYPE_IDENTIFIER (note that we start at -2 rather than -1,
   which is the CRYPT_ERROR value).  When a field of this type is
   encountered, no data value is recorded, but the OID for the field is
   written to the cert when the field is encoded */

#define FIELDTYPE_IDENTIFIER	-2

/* Some fields have no set value (these arise from ANY DEFINED BY
   definitions) or an opaque value (typically fixed parameters for type-and-
   value pairs).  To denote these fields, the field type is set to
   FIELDTYPE_BLOB */

#define FIELDTYPE_BLOB			-3

/* When a field contains a CHOICE, it can contain any one of the CHOICE
   fields, as opposed to a FL_SETOF which can contain any of the fields which
   follow it.  Currently the only CHOICE fields contain OIDs as choices, the
   CHOICE fieldtype indicates that the value is stored in the field itself
   but the encoding is handled via a separate encoding table pointed to by
   extraData which maps the value to an OID */

#define FIELDTYPE_CHOICE		-4

/* Some fields are composite fields which contain complete certificate data
   structures.  To denote these fields, the field type is a special code
   which specifies the type, and the value member contains the handle or the
   data member contains a pointer to the composite object */

#define FIELDTYPE_DN			-5

/* As an extension of the above, some fields are complex enough to require
   complete alternative encoding tables.  The most obvious one is
   GeneralName, but this is also used for some CHOICE types where the value
   selects a particular OID or entry from an alternative encoding table.  In
   this case the extraData member is a pointer to the alternative encoding
   table */

#define FIELDTYPE_SUBTYPED		-6

/* Usually the field ID for the first field in an entry (the one containing
   the OID) is the overall attribute ID, however there are one or two
   exceptions in which the attribute ID and field ID are the same but are
   given in separate fields (examples of this are the altNames, which have
   a single field ID SUBJECT/ISSUERALTNAME which applies to the attribute as
   a whole, but also to the one and only field in it.

   If this happens, the field ID for the attribute as a whole is given the
   value FIELDID_FOLLOWS to indicate that the actual ID is present at a later
   point (the first field which isn't a FIELDID_FOLLOWS code is treated as
   the attribute ID */

#define FIELDID_FOLLOWS			-7

typedef struct {
	/* Information on the overall attribute.  These fields are only set
	   for overall attribute definitions */
	const BYTE FAR_BSS *oid;		/* OID for this attribute */

	/* Information on this particular field in the attribute.  The fieldType
	   is the field as defined (eg SEQUENCE, INTEGER), the fieldEncodingType
	   is the field as encoded: 0 if it's the same as the field type, or the
	   tag if it's a tagged field.  The default tagging is to use implicit
	   tags (eg [ 0 ] IMPLICIT SEQUENCE) with a field of type fieldType and
	   encoding of type fieldEncodedType.  If FL_EXPLICIT is set, it's an
	   explicitly tagged field and both fields are used for the encoding */
	const CRYPT_ATTRIBUTE_TYPE fieldID;	/* Magic ID for this field */
	const int fieldType;			/* ASN.1 tag value for this field */
	const int fieldEncodedType;		/* ASN.1 tag for field as encoded */

	/* General status information */
	const int flags;				/* Status and information flags */

	/* Information to allow validity checking for this field */
	const int lowRange;				/* Min/max allowed if numeric/boolean */
	const int highRange;			/* Min/max length if string */
	const long defaultValue;		/* Default value if IS_DEFAULT set */

	/* Extra data needed to process this field, either a pointer to an
	   alternative encoding table or a pointer to the validation function to
	   allow extended validity checking */
	void *extraData;
	} ATTRIBUTE_INFO;

/* The validation function used to perform additional validation on fields */

typedef int ( *VALIDATION_FUNCTION )( const ATTRIBUTE_LIST *extensionListPtr );

/* The table of attribute definitions */

extern const ATTRIBUTE_INFO FAR_BSS extensionInfo[];
extern const ATTRIBUTE_INFO FAR_BSS cmsAttributeInfo[];

/* Look up an ATTRIBUTE_INFO entry based on an OID */

ATTRIBUTE_INFO *oidToAttribute( const ATTRIBUTE_TYPE attributeType,
								const BYTE *oid );

/* Write an attribute field */

int writeAttributeField( STREAM *stream, ATTRIBUTE_LIST *extensionListPtr );

#endif /* _CERTATTR_DEFINED */
