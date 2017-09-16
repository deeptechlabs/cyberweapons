/****************************************************************************
*																			*
*					  Object Attribute Permission Information				*
*						Copyright Peter Gutmann 1998-1999					*
*																			*
****************************************************************************/

#ifndef _CRYPTACL_DEFINED

#define _CRYPTACL_DEFINED

/* Various includes and defines needed for range checking */

#include <limits.h>		/* For INT_MAX */

/* Each attribute has a mandatory ACL associated with it which controls how
   that attribute may be modified and used.  The ACL is enforced by the 
   kernel before dispatching attribute-manipulation messages to object.  For 
   example, a read of a CRYPT_CTXINFO_KEY wouldn't even make it to the 
   object, it'd be rejected immediately by the kernel.

   The first entry in the ACL is the attribute's type, which determines 
   what type the attribute should have.  The basic values are boolean, 
   numeric, or byte string, there are also some special types such as object
   handles which place extra constraints on the attribute */

typedef enum {
	VALUE_NONE,						/* Non-value */
	VALUE_BOOLEAN,					/* Boolean flag */
	VALUE_NUMERIC,					/* Numeric value */
	VALUE_STRING,					/* Byte string */
	VALUE_OBJECT,					/* Object handle */
	VALUE_TIME						/* Timestamp */
	} VALUE_TYPE;

/* The next entry is a bitfield which defines for which object subtypes the
   attribute is valid.  The interpretation of the bitfield is object-specific,
   the check is performed with a simple AND (if 
   ACL->bitfield & object->subType -> access is valid).  Since the full field
   names are rather long, we define a shortened form (only visible within this
   header file) which reduces the space required to define them.  In addition
   we define a subtype value which allows access for any subtype */

#define ST_CTX_CONV			SUBTYPE_CTX_CONV
#define ST_CTX_PKC			SUBTYPE_CTX_PKC
#define ST_CTX_HASH			SUBTYPE_CTX_HASH
#define ST_CTX_MAC			SUBTYPE_CTX_MAC
#define ST_CTX_ANY			( ST_CTX_CONV | ST_CTX_PKC | ST_CTX_HASH | ST_CTX_MAC )

#define ST_CERT_CERT		SUBTYPE_CERT_CERT
#define ST_CERT_CERTREQ		SUBTYPE_CERT_CERTREQ
#define ST_CERT_CERTCHAIN	SUBTYPE_CERT_CERTCHAIN
#define ST_CERT_ATTRCERT	SUBTYPE_CERT_ATTRCERT
#define ST_CERT_CRL			SUBTYPE_CERT_CRL
#define ST_CERT_CMSATTR		SUBTYPE_CERT_CMSATTR
#define ST_CERT_ANY_CERT	( ST_CERT_CERT | ST_CERT_CERTREQ | \
							  ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT )
#define ST_CERT_ANY			( ST_CERT_ANY_CERT | ST_CERT_CRL | ST_CERT_CMSATTR )

#define ST_KEYSET_FILE		SUBTYPE_KEYSET_FILE
#define ST_KEYSET_DBMS		SUBTYPE_KEYSET_DBMS
#define ST_KEYSET_HTTP		SUBTYPE_KEYSET_HTTP
#define ST_KEYSET_LDAP		SUBTYPE_KEYSET_LDAP
#define ST_KEYSET_SCARD		SUBTYPE_KEYSET_SCARD
#define ST_KEYSET_ANY		( ST_KEYSET_FILE | ST_KEYSET_DBMS | \
							  ST_KEYSET_HTTP | ST_KEYSET_LDAP |\
							  ST_KEYSET_SCARD )

#define ST_ENV_ENV			SUBTYPE_ENV_ENV
#define ST_ENV_DEENV		SUBTYPE_ENV_DEENV
#define ST_ENV_ANY			( SUBTYPE_ENV_ENV | SUBTYPE_ENV_DEENV )

#define ST_DEV_FORT			SUBTYPE_DEV_FORTEZZA
#define ST_DEV_P11			SUBTYPE_DEV_PKCS11
#define ST_DEV_ANY			( SUBTYPE_DEV_FORTEZZA | SUBTYPE_DEV_PKCS11 )

#define ST_SESSION_SSH		SUBTYPE_SESSION_SSH
#define ST_SESSION_SSL		SUBTYPE_SESSION_SSL
#define ST_SESSION_TLS		SUBTYPE_SESSION_TLS
#define ST_SESSION_CMP		SUBTYPE_SESSION_CMP
#define ST_SESSION_ANY		( ST_SESSION_SSH | ST_SESSION_SSL | \
							  ST_SESSION_TLS | ST_SESSION_CMP )

#define ST_ANY				SUBTYPE_ANY

/* The next entry is the read/write/delete permissions, which define what the
   user is allowed to do to the attribute.  Each object can have two modes, 
   "low" and "high", whose exact definition depends on the object type.  At 
   some point an operation on an object (loading a key for a context, signing
   a cert) will move it from the low to the high state, at which point a much
   more restricted set of permissions apply.  The permissions are given as
   RWD_RWD with the first set being for the object in the high state and the
   second for the object in the low state.
   
   In addition the the usual external-access permssions, some attributes are 
   only visible internally.  Normal attributes have matching internal-access
   and external-access permssions but the internal-access-only ones have the
   external-access permissions turned off */

#define ACCESS_xxx_xxx		0x0000	/* No access */
#define ACCESS_xxx_xWx		0x0202	/* Low: Write-only */
#define ACCESS_xxx_Rxx		0x0404	/* Low: Read-only */
#define ACCESS_xxx_RWx		0x0606	/* Low: Read/write */
#define ACCESS_xxx_RWD		0x0707	/* Low: All access */
#define ACCESS_xWx_xWx		0x2222	/* High: Write-only, Low: Write-only */
#define ACCESS_Rxx_xxx		0x4040	/* High: Read-only, Low: None */
#define ACCESS_Rxx_xWx		0x4242	/* High: Read-only, Low: Write-only */
#define ACCESS_Rxx_Rxx		0x44F4	/* High: Read-only, Low: Read-only */
#define ACCESS_Rxx_RxD		0x4545	/* High: Read-only, Low: Read/delete */
#define ACCESS_Rxx_RWx		0x4646	/* High: Read-only, Low: Read/write */
#define ACCESS_Rxx_RWD		0x4747	/* High: Read-only, Low: All access */
#define ACCESS_RxD_RxD		0x5555	/* High: Read/delete, Low: Read/delete */
#define ACCESS_RWx_Rxx		0x6464	/* High: Read/write, Low: Read-only */
#define ACCESS_RWx_RWx		0x6666	/* High: Read/write, Low: Read/write */
#define ACCESS_RWx_RWD		0x6767	/* High: Read/write, Low: All access */
#define ACCESS_RWD_xxx		0x7070	/* High: All access, Low: None */
#define ACCESS_RWD_RWD		0x7777	/* High: All access, Low: All access */

#define ACCESS_INT_xxx_xWx	0x0200	/* Internal: None, write-only */
#define ACCESS_INT_xxx_Rxx	0x0400	/* Internal: None, read-only */
#define ACCESS_INT_xWx_xWx	0x2200	/* Internal: Write-only, write-only */
#define ACCESS_INT_Rxx_xxx	0x4000	/* Internal: Read-only, none */
#define ACCESS_INT_Rxx_xWx	0x4200	/* Internal: Read-only, write-only */
#define ACCESS_INT_Rxx_Rxx	0x4400	/* Internal: Read-only, read-only */
#define ACCESS_INT_Rxx_RWx	0x4600	/* Internal: Read-only, read/write */
#define ACCESS_INT_RWx_RWx	0x6600	/* Internal: Read/write, read/write */

#define ACCESS_FLAG_R		0x0004	/* Read access permitted */
#define ACCESS_FLAG_W		0x0002	/* Write access permitted */
#define ACCESS_FLAG_D		0x0001	/* Delete access permitted */
#define ACCESS_FLAG_H_R		0x0040	/* Read access permitted in high mode */
#define ACCESS_FLAG_H_W		0x0020	/* Write access permitted in high mode */
#define ACCESS_FLAG_H_D		0x0010	/* Delete access permitted in high mode */

#define ACCESS_MASK_EXTERNAL 0x0077	/* External-access flags mask */
#define ACCESS_MASK_INTERNAL 0x7700	/* Internal-access flags mask */

#define MK_ACCESS_INTERNAL( value )	( ( value ) << 8 )

/* The next entry contains general flags for the attribute.  The flags are:

	FLAG_OBJECTPROPERTY
		This is an object property attribute which is handled by the kernel 
		rather than being forwarded to the object.

	FLAG_TRIGGER
		Successfully setting this attribute triggers a change from the low to
		the high state */

#define ATTRIBUTE_FLAG_PROPERTY	0x01
#define ATTRIBUTE_FLAG_TRIGGER	0x02

/* The next entry contains the routing type, which specifies the routing used
   for the attribute.  This routing applies not only for attribute 
   manipulation messages but for all messages in general, some of the routing 
   types defined below only apply for non-attribute messages.  The routing 
   types are:

	ROUTE_NONE
		Not routed (the message or attribute is valid for any object type).

	ROUTE( target )
	ROUTE_ALT( target, altTarget )
		Fixed-target messages always routed to a particular object type (eg
		a certificate attribute is always routed to a certificate object; a
		generate key message is always routed to a context).

	ROUTE_FIXED( target )
	ROUTE_FIXED_ALT( target, altTarget )
		Not routed, but checked to make sure they're addressed to the 
		required target type.  These message types aren't routed because 
		they're specific to a particular object and are explicitly unroutable 
		(for example a get key message sent to a cert or context tied to a 
		device shouldn't be forwarded on to the device, since it would result 
		in the cert acting as a keyset.  This is theoretically justifiable - 
		"Get me another cert from the same place this one came from" - but 
		it's stretching the orthogonality of objects a bit far).

	ROUTE_IMPLICIT
		For object attribute manipulation messages, implicitly routed by
		attribute type.

	ROUTE_SPECIAL( routingFunction )
		Special-case, message-dependent routing */

#define ROUTE_NONE \
		OBJECT_TYPE_NONE, NULL
#define ROUTE( target ) \
		( target ), findTargetType
#define ROUTE_ALT( target, altTarget ) \
		( target ) | ( ( altTarget ) << 8 ), findTargetType
#define ROUTE_FIXED( target ) \
		( target ), checkTargetType
#define ROUTE_FIXED_ALT( target, altTarget ) \
		( target ) | ( ( altTarget ) << 8 ), checkTargetType
#define ROUTE_IMPLICIT \
		OBJECT_TYPE_LAST, findTargetType
#define ROUTE_SPECIAL( function ) \
		OBJECT_TYPE_NONE, ( function )

/* Macros to determine which type of routing to apply */

#define isImplicitRouting( target ) \
		( ( target ) == OBJECT_TYPE_LAST )
#define isExplicitRouting( target ) \
		( ( target ) == OBJECT_TYPE_NONE )

/* Prototypes for routing functions used with the above definitions */

static int findTargetType( const int objectHandle, const int arg );

/* The next entry determines the value range (for numeric or boolean values),
   length range (for variable-length data), or special range types (eg the
   value must be a valid handle).  Some values aren't amenable to a simple 
   range check so we also allow various extended types of checking.  To 
   denote that an extended check needs to be performed, we set the low range 
   value to RANGE_SPECIAL and the high range value to an indicator of the 
   type of check to be performed.  The range types are:

	RANGE_NONE
		Must be zero.
	RANGE_UNUSED
		Must be CRYPT_UNUSED
	RANGE_BOOLEAN
		TRUE or FALSE.
	RANGE_HANDLE
		Valid object handle
	RANGE_HANDLE_OPT
		As RANGE_HANDLE but may also be CRYPT_UNUSED
	RANGE_ANY
		Allow any value
	RANGE_ALLOWEDVALUES
		extendedInfo contains int [] of allowed values, terminated by 
		CRYPT_ERROR
	RANGE_SUBRANGES
		extendedInfo contains subrange [] of allowed subranges, terminated
		by { CRYPT_ERROR, CRYPT_ERROR }
	RANGE_ASYMMETRIC
		extendedInfo contains acl [2], the first for read, the second for
		write */

enum { 
	RANGEVAL_UNUSED,				/* Must be CRYPT_UNUSED */
	RANGEVAL_HANDLE,				/* Valid object handle */
	RANGEVAL_HANDLE_OPT,			/* Valid object handle or CRYPT_UNUSED */
	RANGEVAL_ANY,					/* Any value allowed */
	RANGEVAL_ALLOWEDVALUES,			/* List of permissible values */
	RANGEVAL_SUBRANGES,				/* List of permissible subranges */
	RANGEVAL_ASYMMETRIC				/* One range for read, one for write */
	};

#define RANGE_EXT_MARKER	-1000	/* Marker to denote extended range value */

#define RANGE_NONE			-1, 1
#define RANGE_UNUSED		RANGE_EXT_MARKER, RANGEVAL_UNUSED
#define RANGE_BOOLEAN		FALSE - 1, TRUE + 1
#define RANGE_HANDLE		RANGE_EXT_MARKER, RANGEVAL_HANDLE
#define RANGE_HANDLE_OPT	RANGE_EXT_MARKER, RANGEVAL_HANDLE_OPT
#define RANGE_ANY			RANGE_EXT_MARKER, RANGEVAL_ANY
#define RANGE_ALLOWEDVALUES	RANGE_EXT_MARKER, RANGEVAL_ALLOWEDVALUES
#define RANGE_SUBRANGES		RANGE_EXT_MARKER, RANGEVAL_SUBRANGES
#define RANGE_ASYMMETRIC	RANGE_EXT_MARKER, RANGEVAL_ASYMMETRIC
#define RANGE( low, high )	( low ) - 1, ( high ) + 1

/* RANGE_ALLOWEDVALUES values for various attributes */

static const int allowedLDAPObjectTypes[] = {
	CRYPT_CERTTYPE_NONE, CRYPT_CERTTYPE_CERTIFICATE, CRYPT_CERTTYPE_CRL, 
	CRYPT_ERROR };
static const int allowedConfigChanged[] = { FALSE, CRYPT_ERROR };
static const int allowedPKCKeysizes[] = {
	sizeof( CRYPT_PKCINFO_DLP ), sizeof( CRYPT_PKCINFO_RSA ), 
	CRYPT_ERROR };
static const int allowedCursorValues[] = {
	CRYPT_CURSOR_FIRST, CRYPT_CURSOR_PREVIOUS, CRYPT_CURSOR_NEXT,
	CRYPT_CURSOR_LAST, CRYPT_ERROR };
static const int allowedObjectStatusValues[] = {
	CRYPT_OK, CRYPT_ERROR_NOTINITED, CRYPT_ERROR_BUSY, CRYPT_ERROR_SIGNALLED, 
	CRYPT_ERROR };

/* RANGE_SUBRANGES values for various attributes */

typedef int RANGE_SUBRANGE_TYPE[ 2 ];

static const RANGE_SUBRANGE_TYPE allowedXXX[] = {
	{ CRYPT_ERROR, CRYPT_ERROR } };

/* RANGE_ASYMMETRIC values for various attributes */

/*static const ATTRIBUTE_ACL allowedXYZ[ 2 ] = { 0 }; */

/* The ACL entry.  If the code is compiled in debug mode, we also add the 
   attribute type, which is used for an internal consistency check */

typedef struct {
#ifndef NDEBUG
	/* The attribute type, used for consistency checking */
	const CRYPT_ATTRIBUTE_TYPE attribute;	/* Attribute */
#endif /* NDEBUG */

	/* Attribute type checking information: The attribute value type and
	   object subtypes for which the attribute is valid */
	const VALUE_TYPE valueType;		/* Attribute value type */
	const int objectSubType;		/* Object subtype for which attr.valid */

	/* Access information: The type of access and object states which are
	   permitted, and general flags for this attribute */
	const int access;				/* Permitted access type */
	const int flags;				/* General flags */

	/* Routing information: The object type the attribute applies to, and the
	   routing function applied to the attribute message */
	const OBJECT_TYPE routingTarget;	/* Target type if routable */
	int ( *routingFunction )( const int objectHandle, const int arg );

	/* Attribute value checking information */
	const int lowRange;				/* Min/max allowed if numeric/boolean */
	const int highRange;			/* Length if string */
	const void *extendedInfo;		/* Extended access information */
	} ATTRIBUTE_ACL;

/* Macros to make it easy to set up ACL's.  We have one each for boolean, 
   numeric, and string attributes, and two general-purpose ones which
   provide more control over the values */

#ifndef NDEBUG
  /* Standard ACL entries */
  #define MKACL_B( attribute, subType, access, routing ) \
			{ attribute, VALUE_BOOLEAN, subType, access, 0, routing, FALSE, TRUE, NULL }
  #define MKACL_N( attribute, subType, access, routing, range ) \
			{ attribute, VALUE_NUMERIC, subType, access, 0, routing, range, NULL }
  #define MKACL_S( attribute, subType, access, routing, range ) \
			{ attribute, VALUE_STRING, subType, access, 0, routing, range, NULL }
  #define MKACL_O( attribute, subType, access, routing ) \
			{ attribute, VALUE_OBJECT, subType, access, 0, routing, 0, 0, NULL }
  #define MKACL_T( attribute, subType, access, routing ) \
			{ attribute, VALUE_TIME, subType, access, 0, routing, 0, 0, NULL }

  /* Extended types */
  #define MKACL_B_EX( attribute, subType, access, flags, routing ) \
			{ attribute, VALUE_BOOLEAN, subType, access, flags, routing, FALSE, TRUE, NULL }
  #define MKACL_N_EX( attribute, subType, access, flags, routing, range ) \
			{ attribute, VALUE_NUMERIC, subType, access, flags, routing, range, NULL }
  #define MKACL_S_EX( attribute, subType, access, flags, routing, range ) \
			{ attribute, VALUE_STRING, subType, access, flags, routing, range, NULL }

  /* General-purpose ACL macros */
  #define MKACL( attribute, valueType, subType, access, flags, routing, range ) \
			{ attribute, valueType, subType, access, flags, routing, range, NULL }
  #define MKACL_EX( attribute, valueType, subType, access, flags, routing, range, allowed ) \
			{ attribute, valueType, subType, access, flags, routing, range, allowed }

  /* End-of-ACL marker.  Note that the comma is necessary in order to allow 
     the non-debug version to evaluate to nothing */
  #define MKACL_END() \
			, { CRYPT_ERROR, VALUE_NONE, 0, ACCESS_xxx_xxx, 0, 0, NULL, 0, 0, NULL }
#else
  /* Standard ACL entries */
  #define MKACL_B( attribute, subType, access, routing ) \
			{ VALUE_BOOLEAN, subType, access, 0, routing, FALSE, TRUE, NULL }
  #define MKACL_N( attribute, subType, access, routing, range ) \
			{ VALUE_NUMERIC, subType, access, 0, routing, range, NULL }
  #define MKACL_S( attribute, subType, access, routing, range ) \
			{ VALUE_STRING, subType, access, 0, routing, range, NULL }
  #define MKACL_O( attribute, subType, access, routing ) \
			{ VALUE_OBJECT, subType, access, 0, routing, 0, 0, NULL }
  #define MKACL_T( attribute, subType, access, routing ) \
			{ VALUE_TIME, subType, access, 0, routing, 0, 0, NULL }

  /* Extended types */
  #define MKACL_B_EX( attribute, subType, access, flags, routing ) \
			{ VALUE_BOOLEAN, subType, access, flags, routing, FALSE, TRUE, NULL }
  #define MKACL_N_EX( attribute, subType, access, flags, routing, range ) \
			{ VALUE_NUMERIC, subType, access, flags, routing, range, NULL }
  #define MKACL_S_EX( attribute, subType, access, flags, routing, range ) \
			{ VALUE_STRING, subType, access, flags, routing, range, NULL }

  /* General-purpose ACL macros */
  #define MKACL( attribute, valueType, subType, access, flags, routing, range ) \
			{ valueType, subType, access, flags, routing, range, NULL }
  #define MKACL_EX( attribute, valueType, subType, access, flags, routing, range, allowed ) \
			{ valueType, subType, access, flags, routing, range, allowed }

  /* End-of-ACL marker */
  #define MKACL_END()
#endif /* NDEBUG */

/* The ACL tables for each attribute class */

static const ATTRIBUTE_ACL propertyACL[] = {	/* Object properties */
	MKACL(		/* Owned+non-forwardable+locked */
		CRYPT_PROPERTY_HIGHSECURITY, VALUE_BOOLEAN, ST_ANY, ACCESS_xWx_xWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_N_EX(	/* Object owner */
		CRYPT_PROPERTY_OWNER, ST_ANY, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE_ANY ),
	MKACL_N_EX(	/* No.of times object can be forwarded */
		CRYPT_PROPERTY_FORWARDABLE, ST_ANY, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(	/* Whether properties can be chged/read */
		CRYPT_PROPERTY_LOCKED, VALUE_BOOLEAN, ST_ANY, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL_N_EX(	/* Usage count before object expires */
		CRYPT_PROPERTY_USAGECOUNT, ST_ANY, ACCESS_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 1, 1000 ) ),
	MKACL(		/* Whether context can be used only */
		CRYPT_PROPERTY_ENCRYPTONLY, VALUE_BOOLEAN, ST_ANY, ACCESS_xxx_xxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL(		/*   for encryption or decryption */
		CRYPT_PROPERTY_DECRYPTONLY, VALUE_BOOLEAN, ST_ANY, ACCESS_xxx_xxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) ),
	MKACL(		/* Whether key is nonexp.from context */
		CRYPT_PROPERTY_NONEXPORTABLE, VALUE_BOOLEAN, ST_ANY, ACCESS_xxx_xxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( TRUE, TRUE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL genericACL[] = {		/* Generic attributes */
	MKACL_N(	/* Type of last error */
		CRYPT_ATTRIBUTE_ERRORTYPE, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( CRYPT_ERRTYPE_NONE, CRYPT_ERRTYPE_LAST ) ),
	MKACL_N(	/* Locus of last error */
		CRYPT_ATTRIBUTE_ERRORLOCUS, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( CRYPT_ATTRIBUTE_NONE, CRYPT_ATTRIBUTE_LAST ) ),
	MKACL_N(	/* Low-level, software-specific */
		CRYPT_ATTRIBUTE_INT_ERRORCODE, ST_ANY, ACCESS_RWx_RWx, 
		ROUTE_ALT( OBJECT_TYPE_DEVICE, OBJECT_TYPE_KEYSET ), RANGE_ANY ),
	MKACL_S(	/*   error code and message */
		CRYPT_ATTRIBUTE_INT_ERRORMESSAGE, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_ALT( OBJECT_TYPE_DEVICE, OBJECT_TYPE_KEYSET ), RANGE( 0, 512 ) ),
	MKACL_N(	/* Internal data buffer size */
		CRYPT_ATTRIBUTE_BUFFERSIZE, ST_ANY, ACCESS_Rxx_RWx, 
		ROUTE_ALT( OBJECT_TYPE_ENVELOPE, OBJECT_TYPE_SESSION ), RANGE( MIN_BUFFER_SIZE, INT_MAX - 1 ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL optionACL[] = {		/* Config attributes */
	MKACL_S(	/* Text description */
		CRYPT_OPTION_INFO_DESCRIPTION, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Copyright notice */
		CRYPT_OPTION_INFO_COPYRIGHT, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( 16, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Major release version */
		CRYPT_OPTION_INFO_MAJORVERSION, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( 3, 3 ) ),
	MKACL_N(	/* Minor release version */
		CRYPT_OPTION_INFO_MINORVERSION, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( 0, 0 ) ),
	MKACL_N(	/* Stepping version */
		CRYPT_OPTION_INFO_STEPPING, ST_ANY, ACCESS_Rxx_Rxx, 
		ROUTE_NONE, RANGE( 1, 50 ) ),

	MKACL_N(	/* Encryption algorithm */
		CRYPT_OPTION_ENCR_ALGO, ST_ANY, ACCESS_RWx_RWx, 
		ROUTE_NONE, RANGE( CRYPT_ALGO_FIRST_CONVENTIONAL, CRYPT_ALGO_LAST_CONVENTIONAL ) ),
	MKACL_N(	/* Hash algorithm */
		CRYPT_OPTION_ENCR_HASH, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( CRYPT_ALGO_FIRST_HASH, CRYPT_ALGO_LAST_HASH ) ),
	MKACL_N(	/* Public-key encryption algorithm */
		CRYPT_OPTION_PKC_ALGO, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),
	MKACL_N(	/* Public-key encryption key size */
		CRYPT_OPTION_PKC_KEYSIZE, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Signature algorithm */
		CRYPT_OPTION_SIG_ALGO, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( CRYPT_ALGO_FIRST_PKC, CRYPT_ALGO_LAST_PKC ) ),	
	MKACL_N(	/* Signature keysize */
		CRYPT_OPTION_SIG_KEYSIZE, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( bitsToBytes( 512 ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Key processing algorithm */
		CRYPT_OPTION_KEYING_ALGO, ST_ANY, ACCESS_RWx_RWx, 
		ROUTE_NONE, RANGE( CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_SHA ) ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_OPTION_KEYING_ITERATIONS, ST_ANY, ACCESS_RWx_RWx, 
		ROUTE_NONE, RANGE( 1, 20000 ) ),

	MKACL_B(	/* Whether to create X.509v3 certs */
		CRYPT_OPTION_CERT_CREATEV3CERT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Use alternative PKCS #10 encoding */
		CRYPT_OPTION_CERT_PKCS10ALT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Check for valid ASN.1 encoding */
		CRYPT_OPTION_CERT_CHECKENCODING, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to fix encoding of strings */
		CRYPT_OPTION_CERT_FIXSTRINGS, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to fix encoding of email addr.*/
		CRYPT_OPTION_CERT_FIXEMAILADDRESS, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to treat iName as a blob */
		CRYPT_OPTION_CERT_ISSUERNAMEBLOB, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to treat keyID as a blob */
		CRYPT_OPTION_CERT_KEYIDBLOB, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to sign unrecog.attrs */
		CRYPT_OPTION_CERT_SIGNUNRECOGNISEDATTRIBUTES, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to trust cert chain root */
		CRYPT_OPTION_CERT_TRUSTCHAINROOT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_N(	/* Certificate validity period */
		CRYPT_OPTION_CERT_VALIDITY, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 1, 20 * 365 ) ),
	MKACL_N(	/* CRL update interval */
		CRYPT_OPTION_CERT_UPDATEINTERVAL, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 1, 365 ) ),
	MKACL_B(	/* Enforce validity nesting on write */
		CRYPT_OPTION_CERT_ENCODE_VALIDITYNESTING, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Enforce validity nesting on read */
		CRYPT_OPTION_CERT_DECODE_VALIDITYNESTING, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Enforce critical flag in extensions on write */
		CRYPT_OPTION_CERT_ENCODE_CRITICAL, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Enforce critical flag in extensions on read */
		CRYPT_OPTION_CERT_DECODE_CRITICAL, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),

	MKACL_B(	/* Add default CMS attributes */
		CRYPT_OPTION_CMS_DEFAULTATTRIBUTES, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),

	MKACL_S(	/* URL of web proxy */
		CRYPT_OPTION_KEYS_HTTP_PROXY, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* Timeout for read */
		CRYPT_OPTION_KEYS_HTTP_TIMEOUT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 5, 300 ) ),

	MKACL_S(	/* Object class */
		CRYPT_OPTION_KEYS_LDAP_OBJECTCLASS, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_EX(	/* Object type to fetch */
		CRYPT_OPTION_KEYS_LDAP_OBJECTTYPE, VALUE_NUMERIC, ST_ANY, ACCESS_RWx_RWx, 0,
		ROUTE_NONE, RANGE_ALLOWEDVALUES, allowedLDAPObjectTypes ),
	MKACL_S(	/* CA certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CACERTNAME, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Certificate attribute name */
		CRYPT_OPTION_KEYS_LDAP_CERTNAME, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* CRL attribute name */
		CRYPT_OPTION_KEYS_LDAP_CRLNAME, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Email attribute name */
		CRYPT_OPTION_KEYS_LDAP_EMAILNAME, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* Name of first PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR01, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of second PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR02, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of third PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR03, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fourth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR04, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_S(	/* Name of fifth PKCS #11 driver */
		CRYPT_OPTION_DEVICE_PKCS11_DVR05, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, MAX_PATH_LENGTH ) ),
	MKACL_B(	/* Use only hardware mechanisms */
		CRYPT_OPTION_DEVICE_PKCS11_HARDWAREONLY, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),

	MKACL_S(	/* Serial-port-based RNG name */
		CRYPT_OPTION_DEVICE_SERIALRNG, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Serial RNG parameters */
		CRYPT_OPTION_DEVICE_SERIALRNG_PARAMS, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_N(	/* Timeout for network accesses */
		CRYPT_OPTION_SESSION_TIMEOUT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE, RANGE( 5, 300 ) ),

	MKACL_B(	/* Whether to force memory locking */
		CRYPT_OPTION_MISC_FORCELOCK, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),
	MKACL_B(	/* Whether to init cryptlib async'ly */
		CRYPT_OPTION_MISC_ASYNCINIT, ST_ANY, ACCESS_RWx_RWx,
		ROUTE_NONE ),

	MKACL_EX(	/* Whether in-mem.opts match on-disk ones */
		CRYPT_OPTION_CONFIGCHANGED, VALUE_BOOLEAN, ST_ANY, ACCESS_RWx_RWx, 0,
		ROUTE_NONE, RANGE_ALLOWEDVALUES, allowedConfigChanged )

	MKACL_END()
	};

static const ATTRIBUTE_ACL contextACL[] = {		/* Context attributes */
	MKACL_N(	/* Algorithm */
		CRYPT_CTXINFO_ALGO, 
		ST_CTX_ANY, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( CRYPT_ALGO_NONE + 1, CRYPT_ALGO_LAST - 1 ) ),
	MKACL_N(	/* Mode */
		CRYPT_CTXINFO_MODE, 
		ST_CTX_CONV, ACCESS_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( CRYPT_MODE_NONE + 1, CRYPT_MODE_LAST - 1 ) ),
	MKACL_S(	/* Algorithm name */
		CRYPT_CTXINFO_NAME_ALGO, 
		ST_CTX_ANY, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Mode name */
		CRYPT_CTXINFO_NAME_MODE, 
		ST_CTX_CONV, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 3, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_N(	/* Key size in bytes */
		CRYPT_CTXINFO_KEYSIZE, 
		ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Block size in bytes */
		CRYPT_CTXINFO_BLOCKSIZE, 
		ST_CTX_ANY, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 1, CRYPT_MAX_HASHSIZE ) ),
	MKACL_N(	/* IV size in bytes */
		CRYPT_CTXINFO_IVSIZE, 
		ST_CTX_CONV, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 1, CRYPT_MAX_HASHSIZE ) ),
	MKACL_N(	/* Key processing algorithm */
		CRYPT_CTXINFO_KEYING_ALGO, 
		ST_CTX_CONV | ST_CTX_MAC, ACCESS_Rxx_RWD, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( CRYPT_ALGO_HMAC_SHA, CRYPT_ALGO_HMAC_SHA ) ),
	MKACL_N(	/* Key processing iterations */
		CRYPT_CTXINFO_KEYING_ITERATIONS, 
		ST_CTX_CONV | ST_CTX_MAC, ACCESS_Rxx_RWD, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 1, 20000 ) ),
	MKACL_S(	/* Key processing salt */
		CRYPT_CTXINFO_KEYING_SALT, 
		ST_CTX_CONV | ST_CTX_MAC, ACCESS_Rxx_RWD, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 8, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S_EX(	/* Value used to derive key */
		CRYPT_CTXINFO_KEYING_VALUE, 
		ST_CTX_CONV | ST_CTX_MAC, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 1, 1024 ) ),
	MKACL_S_EX(	/* Key */
		CRYPT_CTXINFO_KEY, 
		ST_CTX_CONV | ST_CTX_MAC, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_KEYSIZE ) ),
	MKACL_EX(	/* Public-key components */
		CRYPT_CTXINFO_KEY_COMPONENTS, VALUE_STRING,
		ST_CTX_PKC, ACCESS_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE_ALLOWEDVALUES, allowedPKCKeysizes ),
	MKACL_S(	/* IV */
		CRYPT_CTXINFO_IV, 
		ST_CTX_CONV, ACCESS_RWx_RWx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 8, CRYPT_MAX_IVSIZE ) ),
	MKACL_S(	/* Hash value */
		CRYPT_CTXINFO_HASHVALUE, 
		ST_CTX_HASH | ST_CTX_MAC, ACCESS_RxD_RxD, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 16, CRYPT_MAX_HASHSIZE ) ),
	MKACL_S(	/* Label for private key */
		CRYPT_CTXINFO_LABEL, 
		ST_CTX_PKC, ACCESS_Rxx_RWD, 
		ROUTE( OBJECT_TYPE_CONTEXT ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL certificateACL[] = {	/* Certificate: General info */
	MKACL_B(	/* Cert is self-signed */
		CRYPT_CERTINFO_SELFSIGNED, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* Cert is signed and immutable */
		CRYPT_CERTINFO_IMMUTABLE, 
		ST_CERT_ANY, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Certificate object type */
		CRYPT_CERTINFO_CERTTYPE, 
		ST_CERT_ANY, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( CRYPT_CERTTYPE_NONE + 1, CRYPT_CERTTYPE_LAST - 1 ) ),
	MKACL_S(	/* Certificate fingerprint: MD5 */
		CRYPT_CERTINFO_FINGERPRINT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 16, 16 ) ),
	MKACL_S(	/* Certificate fingerprint: SHA-1 */
		CRYPT_CERTINFO_FINGERPRINT_SHA, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 20, 20 ) ),
	MKACL_EX(	/* Cursor management: Relative pos in chain/CRL */
		CRYPT_CERTINFO_CURRENT_CERTIFICATE, VALUE_NUMERIC, 
			/* The subtype flag is somewhat unusual since it includes as
			   an allowed subtype a cert, which doesn't have further cert
			   components.  The reason for this is that when the chain is
			   created it's just a collection of certs, it isn't until all
			   of them are available that one can be marked the leaf cert
			   and its type changed to cert chain.  Since an objects
			   subtype can't be changed after it's created, we have to allow
			   cursor movement commands to certs in case one of them is 
			   really the leaf in a cert chain - it's because of the way the
			   leaf can act as both a cert and a cert chain.  A pure cert
			   looks just like a one-cert chain, so there's no harm in 
			   sending a movement command to a cert which isn't a chain 
			   leaf */
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ACCESS_xWx_xWx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE_ALLOWEDVALUES, allowedCursorValues ),
	MKACL_EX(	/* Cursor management: Relative pos or abs.extension */
		CRYPT_CERTINFO_CURRENT_EXTENSION, VALUE_NUMERIC, 
		ST_CERT_ANY, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE_ALLOWEDVALUES, allowedCursorValues ),
	MKACL_EX(	/* Cursor management: Relative pos or abs.field in extension */
		CRYPT_CERTINFO_CURRENT_FIELD, VALUE_NUMERIC, 
		ST_CERT_ANY, ACCESS_RWx_RWx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE_ALLOWEDVALUES, allowedCursorValues ),
	MKACL_EX(	/* Cursor management: Relative pos in multi-comp.field */
		CRYPT_CERTINFO_CURRENT_COMPONENT, VALUE_NUMERIC, 
		ST_CERT_ANY, ACCESS_xxx_xxx, 0,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE_ALLOWEDVALUES, allowedCursorValues ),
	MKACL_N(	/* Usage which cert is trusted for */
		CRYPT_CERTINFO_TRUSTED_USAGE, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_RWD_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, CRYPT_KEYUSAGE_LAST ) ),
	MKACL_B(	/* Whether cert is implicitly trusted */
		CRYPT_CERTINFO_TRUSTED_IMPLICIT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_RWD_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	MKACL_S(	/* Serial number (read-only) */
		CRYPT_CERTINFO_SERIALNUMBER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 32 ) ),
	MKACL_O(	/* Public key */
		CRYPT_CERTINFO_SUBJECTPUBLICKEYINFO, 
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_O(	/* User certificate */
		CRYPT_CERTINFO_USERCERTIFICATE, 
		ST_CERT_CERTCHAIN | ST_CERT_CRL, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Issuer DN */
		CRYPT_CERTINFO_ISSUERNAME, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_T(	/* Cert valid from time */
		CRYPT_CERTINFO_VALIDFROM, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* Cert valid to time */
		CRYPT_CERTINFO_VALIDTO, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* Subject DN */
		CRYPT_CERTINFO_SUBJECTNAME, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_S(	/* Issuer unique ID (read-only) */
		CRYPT_CERTINFO_ISSUERUNIQUEID, 
		ST_CERT_CERT, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Subject unique ID (read-only) */
		CRYPT_CERTINFO_SUBJECTUNIQUEID, 
		ST_CERT_CERT, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 2, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Cert.request (DN + public key) */
		CRYPT_CERTINFO_CERTREQUEST, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL current update time */
		CRYPT_CERTINFO_THISUPDATE, 
		ST_CERT_CRL, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL next update time */
		CRYPT_CERTINFO_NEXTUPDATE, 
		ST_CERT_CRL, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* CRL cert revocation time */
		CRYPT_CERTINFO_REVOCATIONDATE, 
		ST_CERT_CRL, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL certNameACL[] = {	/* Certificate: Name components */
	MKACL_S(	/* countryName */
		CRYPT_CERTINFO_COUNTRYNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* stateOrProvinceName */
		CRYPT_CERTINFO_STATEORPROVINCENAME,	
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* localityName */
		CRYPT_CERTINFO_LOCALITYNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* organizationName */
		CRYPT_CERTINFO_ORGANIZATIONNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* organizationalUnitName */
		CRYPT_CERTINFO_ORGANIZATIONALUNITNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* commonName */
		CRYPT_CERTINFO_COMMONNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),

	MKACL_S(	/* otherName.typeID */
		CRYPT_CERTINFO_OTHERNAME_TYPEID, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* otherName.value */
		CRYPT_CERTINFO_OTHERNAME_VALUE, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* rfc822Name */
		CRYPT_CERTINFO_RFC822NAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( MIN_RFC822_SIZE, MAX_RFC822_SIZE ) ),
	MKACL_S(	/* dNSName */
		CRYPT_CERTINFO_DNSNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( MIN_DNS_SIZE, MAX_DNS_SIZE ) ),
	MKACL_N(	/* directoryName */
		CRYPT_CERTINFO_DIRECTORYNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_S(	/* ediPartyName.nameAssigner */
		CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* ediPartyName.partyName */
		CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* uniformResourceIdentifier */
		CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* iPAddress */
		CRYPT_CERTINFO_IPADDRESS, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 4, 4 ) ),
	MKACL_S(	/* registeredID */
		CRYPT_CERTINFO_REGISTEREDID, 
		ST_CERT_ANY_CERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL certExtensionACL[] = {	/* Certificate: Extensions */
	/* 1 3 6 1 5 5 7 1 1 authorityInfoAccess */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYINFOACCESS, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_OCSP, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 1 3 36 8 3 1 dateOfCertGen */
	MKACL_T(	/* dateOfCertGen */
		CRYPT_CERTINFO_SIGG_DATEOFCERTGEN, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 3 36 8 3 2 procuration */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_PROCURATION, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* country */
		CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 2, 2 ) ),
	MKACL_S(	/* typeOfSubstitution */
		CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),
	MKACL_N(	/* signingFor.thirdPerson */
		CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 1 3 36 8 3 4 monetaryLimit */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SIGG_MONETARYLIMIT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* currency */
		CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 3 ) ),
	MKACL_N(	/* amount */
		CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 255 ) ),
	MKACL_N(	/* exponent */
		CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 255 ) ),

	/* 1 3 36 8 3 8 restriction */
	MKACL_S(	/* restriction */
		CRYPT_CERTINFO_SIGG_RESTRICTION, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 128 ) ),

	/* 1 3 101 1 4 1 strongExtranet */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_STRONGEXTRANET, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* sxNetIDList.sxNetID.zone */
		CRYPT_CERTINFO_STRONGEXTRANET_ZONE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, INT_MAX - 1 ) ),
	MKACL_S(	/* sxNetIDList.sxNetID.id */
		CRYPT_CERTINFO_STRONGEXTRANET_ID, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 64 ) ),

	/* 2 5 29 9 subjectDirectoryAttributes */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* attribute.type */
		CRYPT_CERTINFO_SUBJECTDIR_TYPE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 3, 32 ) ),
	MKACL_S(	/* attribute.values */
		CRYPT_CERTINFO_SUBJECTDIR_VALUES, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 1024 ) ),

	/* 2 5 29 14 subjectKeyIdentifier */
	MKACL_S(	/* attribute.type */
		CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER, 
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 64 ) ),

	/* 2 5 29 15 keyUsage */
	MKACL_N(	/* accessDescription.accessLocation */
		CRYPT_CERTINFO_KEYUSAGE, 
		ST_CERT_CERT | ST_CERT_CERTREQ | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, CRYPT_KEYUSAGE_LAST ) ),

	/* 2 5 29 16 privateKeyUsagePeriod */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_T(	/* notBefore */
		CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 17 subjectAltName */
	MKACL_N(	/* subjectAltName */
		CRYPT_CERTINFO_SUBJECTALTNAME, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 2 5 29 18 issuerAltName */
	MKACL_N(	/* issuerAltName */
		CRYPT_CERTINFO_ISSUERALTNAME, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 2 5 29 19 basicConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_BASICCONSTRAINTS, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* cA */
		CRYPT_CERTINFO_CA, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* pathLenConstraint */
		CRYPT_CERTINFO_PATHLENCONSTRAINT, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, 64 ) ),

	/* 2 5 29 20 cRLNumber */
	MKACL_N(	/* cRLNumber */
		CRYPT_CERTINFO_CRLNUMBER, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, INT_MAX - 1 ) ),

	/* 2 5 29 21 cRLReason */
	MKACL_N(	/* cRLReason */
		CRYPT_CERTINFO_CRLREASON, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, CRYPT_CRLREASON_LAST ) ),

	/* 2 5 29 23 holdInstructionCode */
	MKACL_N(	/* holdInstructionCode */
		CRYPT_CERTINFO_HOLDINSTRUCTIONCODE, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( CRYPT_HOLDINSTRUCTION_NONE, CRYPT_HOLDINSTRUCTION_LAST ) ),

	/* 2 5 29 24 invalidityDate */
	MKACL_T(	/* invalidityDate */
		CRYPT_CERTINFO_INVALIDITYDATE, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 27 deltaCRLIndicator */
	MKACL_N(	/* deltaCRLIndicator */
		CRYPT_CERTINFO_DELTACRLINDICATOR, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, INT_MAX - 1 ) ),

	/* 2 5 29 28 issuingDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT, 
		ST_CERT_CRL, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_ISSUINGDIST_FULLNAME, 
		ST_CERT_CRL, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_B(	/* onlyContainsUserCerts */
		CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* onlyContainsCACerts */
		CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* onlySomeReasons */
		CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, CRYPT_CRLREASONFLAG_LAST ) ),
	MKACL_B(	/* indirectCRL */
		CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL, 
		ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 5 29 29 certificateIssuer */
	MKACL_N(	/* certificateIssuer */
		CRYPT_CERTINFO_CERTIFICATEISSUER, 
		ST_CERT_CRL, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 2 5 29 30 nameConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_NAMECONSTRAINTS, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* permittedSubtrees */
		CRYPT_CERTINFO_PERMITTEDSUBTREES, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_N(	/* excludedSubtrees */
		CRYPT_CERTINFO_EXCLUDEDSUBTREES, 
		ST_CERT_ANY_CERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 2 5 29 31 cRLDistributionPoint */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* distributionPointName.fullName */
		CRYPT_CERTINFO_CRLDIST_FULLNAME, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_N(	/* reasons */
		CRYPT_CERTINFO_CRLDIST_REASONS, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 0, CRYPT_CRLREASONFLAG_LAST ) ),
	MKACL_N(	/* cRLIssuer */
		CRYPT_CERTINFO_CRLDIST_CRLISSUER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 2 5 29 32 certificatePolicies */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CERTIFICATEPOLICIES, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CERTPOLICYID, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 3, 32 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.cPSuri */
		CRYPT_CERTINFO_CERTPOLICY_CPSURI, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.organization */
		CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 200 ) ),
	MKACL_N(	/* policyInformation.policyQualifiers.qualifier.userNotice.noticeRef.noticeNumbers */
		CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 1024 ) ),
	MKACL_S(	/* policyInformation.policyQualifiers.qualifier.userNotice.explicitText */
		CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 200 ) ),

	/* 2 5 29 33 policyMappings */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYMAPPINGS, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* policyMappings.issuerDomainPolicy */
		CRYPT_CERTINFO_ISSUERDOMAINPOLICY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 3, 32 ) ),
	MKACL_S(	/* policyMappings.subjectDomainPolicy */
		CRYPT_CERTINFO_SUBJECTDOMAINPOLICY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 3, 32 ) ),

	/* 2 5 29 35 authorityKeyIdentifier */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* keyIdentifier */
		CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* authorityCertIssuer */
		CRYPT_CERTINFO_AUTHORITY_CERTISSUER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_S(	/* authorityCertSerialNumber */
		CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT | ST_CERT_CRL, ACCESS_Rxx_RWD, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), 
		RANGE( 1, 32 ) ),

	/* 2 5 29 36 policyConstraints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_POLICYCONSTRAINTS, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* policyConstraints.requireExplicitPolicy */
		CRYPT_CERTINFO_REQUIREEXPLICITPOLICY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),
	MKACL_N(	/* policyConstraints.inhibitPolicyMapping */
		CRYPT_CERTINFO_INHIBITPOLICYMAPPING, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_ATTRCERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 64 ) ),

	/* 2 5 29 37 extKeyUsage */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_EXTKEYUSAGE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* individualCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* commercialCodeSigning */
		CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* certTrustListSigning */
		CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* timeStampSigning */
		CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* encrypedFileSystem */
		CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverAuth */
		CRYPT_CERTINFO_EXTKEY_SERVERAUTH, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* clientAuth */
		CRYPT_CERTINFO_EXTKEY_CLIENTAUTH, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* codeSigning */
		CRYPT_CERTINFO_EXTKEY_CODESIGNING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* emailProtection */
		CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecEndSystem */
		CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecTunnel */
		CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* ipsecUser */
		CRYPT_CERTINFO_EXTKEY_IPSECUSER, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* timeStamping */
		CRYPT_CERTINFO_EXTKEY_TIMESTAMPING, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* directoryService */
		CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto */
		CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* serverGatedCrypto CA */
		CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 16 840 1 113730 1 x Netscape extensions */
	MKACL_N(	/* netscape-cert-type */
		CRYPT_CERTINFO_NS_CERTTYPE, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, CRYPT_NS_CERTTYPE_LAST ) ),
	MKACL_S(	/* netscape-base-url */
		CRYPT_CERTINFO_NS_BASEURL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-revocation-url */
		CRYPT_CERTINFO_NS_REVOCATIONURL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-revocation-url */
		CRYPT_CERTINFO_NS_CAREVOCATIONURL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-cert-renewal-url */
		CRYPT_CERTINFO_NS_CERTRENEWALURL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ca-policy-url */
		CRYPT_CERTINFO_NS_CAPOLICYURL, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-ssl-server-name */
		CRYPT_CERTINFO_NS_SSLSERVERNAME, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_S(	/* netscape-comment */
		CRYPT_CERTINFO_NS_COMMENT, 
		ST_CERT_ANY_CERT, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 1024 ) ),

	/* 2 23 42 7 0 SET hashedRootKey */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_HASHEDROOTKEY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* rootKeyThumbPrint */
		CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),

	/* 2 23 42 7 1 SET certificateType */
	MKACL_N(	/* certificateType */
		CRYPT_CERTINFO_SET_CERTIFICATETYPE, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, CRYPT_SET_CERTTYPE_LAST ) ),

	/* 2 23 42 7 2 SET merchantData */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_MERCHANTDATA, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* merID */
		CRYPT_CERTINFO_SET_MERID, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 30 ) ),
	MKACL_S(	/* merAcquirerBIN */
		CRYPT_CERTINFO_SET_MERACQUIRERBIN, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 6, 6 ) ),
	MKACL_S(	/* merNames.language */
		CRYPT_CERTINFO_SET_MERCHANTLANGUAGE, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 35 ) ),
	MKACL_S(	/* merNames.name */
		CRYPT_CERTINFO_SET_MERCHANTNAME, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.city */
		CRYPT_CERTINFO_SET_MERCHANTCITY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.stateProvince */
		CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.postalCode */
		CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_S(	/* merNames.countryName */
		CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 50 ) ),
	MKACL_N(	/* merCountry */
		CRYPT_CERTINFO_SET_MERCOUNTRY, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 999 ) ),
	MKACL_B(	/* merAuthFlag */
		CRYPT_CERTINFO_SET_MERAUTHFLAG, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 3 SET certCardRequired */
	MKACL_B(	/* certCardRequired */
		CRYPT_CERTINFO_SET_CERTCARDREQUIRED, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 2 23 42 7 4 SET tunneling */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_SET_TUNNELING, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_B(	/* tunneling */
		CRYPT_CERTINFO_SET_TUNNELINGFLAG, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* tunnelingAlgID */
		CRYPT_CERTINFO_SET_TUNNELINGALGID, 
		ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CERTREQ, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL certSmimeACL[] = {	/* Certificate: S/MIME attributes */
	/* 1 2 840 113549 1 9 3 contentType */
	MKACL_N(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTTYPE,	
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CONTENT_NONE, CRYPT_CONTENT_LAST ) ),

	/* 1 2 840 113549 1 9 4 messageDigest */
	MKACL_S(	/* messageDigest */
		CRYPT_CERTINFO_CMS_MESSAGEDIGEST, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 64 ) ),

	/* 1 2 840 113549 1 9 5 signingTime */
	MKACL_T(	/* signingTime */
		CRYPT_CERTINFO_CMS_SIGNINGTIME, 
		ST_CERT_CMSATTR, ACCESS_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),

	/* 1 2 840 113549 1 9 6 counterSignature */
	MKACL_S(	/* counterSignature */
		CRYPT_CERTINFO_CMS_COUNTERSIGNATURE, 
		ST_CERT_CMSATTR, ACCESS_xxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 0 ) ),

	/* 1 2 840 113549 1 9 15 sMIMECapabilities */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SMIMECAPABILITIES, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* 3DES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_3DES, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* CAST-128 encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_CAST128, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* IDEA encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_IDEA, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* RC2 encryption (w.128 key) */
		CRYPT_CERTINFO_CMS_SMIMECAP_RC2, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* RC5 encryption (w.128 key) */
		CRYPT_CERTINFO_CMS_SMIMECAP_RC5, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* Skipjack encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* DES encryption */
		CRYPT_CERTINFO_CMS_SMIMECAP_DES, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* preferSignedData */
		CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* canNotDecryptAny */
		CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),

	/* 1 2 840 113549 1 9 16 2 1 receiptRequest */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_RECEIPTREQUEST, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentIdentifier */
		CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 16, 64 ) ),
	MKACL_N(	/* receiptsFrom */
		CRYPT_CERTINFO_CMS_RECEIPT_FROM, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 0, 1 ) ),
	MKACL_N(	/* receiptsTo */
		CRYPT_CERTINFO_CMS_RECEIPT_TO, 
		ST_CERT_CMSATTR, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 1 2 840 113549 1 9 16 2 2 essSecurityLabel */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SECURITYLABEL, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_SECLABEL_POLICY, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 3 mlExpansionHistory */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* mlData.mailListIdentifier.issuerAndSerialNumber */
		CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),
	MKACL_T(	/* mlData.expansionTime */
		CRYPT_CERTINFO_CMS_MLEXP_TIME, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* mlData.mlReceiptPolicy.none */
		CRYPT_CERTINFO_CMS_MLEXP_NONE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* mlData.mlReceiptPolicy.insteadOf.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF, 
		ST_CERT_CMSATTR, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),
	MKACL_N(	/* mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName */
		CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO, 
		ST_CERT_CMSATTR, ACCESS_RWx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
			/* Write = select this attribute, value = CRYPT_UNUSED,
			   read = report whether attribute present */
		RANGE_UNUSED ),

	/* 1 2 840 113549 1 9 16 2 4 contentHints */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_CONTENTHINTS, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* contentDescription */
		CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_N(	/* contentType */
		CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST ) ),

	/* 1 2 840 113549 1 9 16 2 9 equivalentLabels */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_EQUIVALENTLABEL, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* securityPolicyIdentifier */
		CRYPT_CERTINFO_CMS_EQVLABEL_POLICY, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_N(	/* securityClassification */
		CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST ) ),
	MKACL_S(	/* privacyMark */
		CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 64 ) ),
	MKACL_S(	/* securityCategories.securityCategory.type */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),
	MKACL_S(	/* securityCategories.securityCategory.value */
		CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 1, 512 ) ),

	/* 1 2 840 113549 1 9 16 2 12 signingCertificate */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* certs.essCertID.certHash */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_CERTS, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 20, 20 ) ),
	MKACL_S(	/* policies.policyInformation.policyIdentifier */
		CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( 3, 32 ) ),

	/* 1 3 6 1 4 1 311 2 1 10 spcAgencyInfo */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCAGENCYINFO, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_S(	/* spcAgencyInfo.url */
		CRYPT_CERTINFO_CMS_SPCAGENCYURL, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),

	/* 1 3 6 1 4 1 311 2 1 11 spcStatementType */
	MKACL_B(	/* Extension present flag */
		CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RxD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ) ),
	MKACL_N(	/* individualCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),
	MKACL_N(	/* commercialCodeSigning */
		CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED ),

	/* 1 3 6 1 4 1 311 2 1 12 spcOpusInfo */
	MKACL_N(	/* spcOpusInfo */
		CRYPT_CERTINFO_CMS_SPCOPUSINFO, 
		ST_CERT_CMSATTR, ACCESS_Rxx_RWD,
		ROUTE( OBJECT_TYPE_CERTIFICATE ),
		RANGE_UNUSED )

	MKACL_END()
	};

static const ATTRIBUTE_ACL keysetACL[] = {		/* Keyset attributes */
	MKACL_S(	/* Keyset query */
		CRYPT_KEYSETINFO_QUERY, 
		ST_KEYSET_DBMS, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_KEYSET ), 
		RANGE( 6, CRYPT_MAX_TEXTSIZE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL deviceACL[] = {		/* Device attributes */
	MKACL_S(	/* Initialise device for use */
		CRYPT_DEVINFO_INITIALISE, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Authenticate user to device */
		CRYPT_DEVINFO_AUTHENT_USER, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Authenticate supervisor to dev.*/
		CRYPT_DEVINFO_AUTHENT_SUPERVISOR, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set user authent.value */
		CRYPT_DEVINFO_SET_AUTHENT_USER, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Set supervisor auth.val.*/
		CRYPT_DEVINFO_SET_AUTHENT_SUPERVISOR, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Zeroise device */
		CRYPT_DEVINFO_ZEROISE, 
		ST_DEV_ANY, ACCESS_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL envelopeACL[] = {	/* Envelope attributes */
	MKACL_N(	/* Data size information */
		CRYPT_ENVINFO_DATASIZE, 
		ST_ENV_ENV, ACCESS_xxx_xWx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( 0, INT_MAX - 1 ) ),
	MKACL_N(	/* Compression information */
		CRYPT_ENVINFO_COMPRESSION, 
		ST_ENV_ENV, ACCESS_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE_UNUSED ),
	MKACL_N(	/* Inner CMS content type */
/* Writeable only for env */
		CRYPT_ENVINFO_CONTENTTYPE, 
		ST_ENV_ANY, ACCESS_Rxx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( CRYPT_CONTENT_NONE, CRYPT_CONTENT_LAST ) ),
	MKACL_B(	/* Generate CMS detached signature */
		CRYPT_ENVINFO_DETACHEDSIGNATURE, 
		ST_ENV_ENV, ACCESS_Rxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_N(	/* Signature check result */
		CRYPT_ENVINFO_SIGNATURE_RESULT, 
		ST_ENV_DEENV, ACCESS_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( CRYPT_OK, CRYPT_ENVELOPE_RESOURCE ) ),
	MKACL_N(	/* Env.information cursor management */
/* In = cursor components, out = component type */
		CRYPT_ENVINFO_CURRENT_COMPONENT, 
		ST_ENV_ANY, ACCESS_RWx_RWx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE_ANY ),
/*		CRYPT_ENVINFO_PASSWORD, CRYPT_ENVINFO_MAC ), */
	MKACL_S(	/* User password */
		CRYPT_ENVINFO_PASSWORD, 
		ST_ENV_ANY, ACCESS_xxx_xWx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Conventional encryption key */
		CRYPT_ENVINFO_KEY, 
		ST_ENV_ANY, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* Signature/signature check key */
/* Write-only for env, read-only for deenv */
		CRYPT_ENVINFO_SIGNATURE, 
		ST_ENV_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* Extra information added to CMS sigs */
/* Write-only for env, read-only for deenv */
		CRYPT_ENVINFO_SIGNATURE_EXTRADATA, 
		ST_ENV_ANY, ACCESS_RWx_RWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_S(	/* Recipient email address */
		CRYPT_ENVINFO_RECIPIENT, 
		ST_ENV_ENV, ACCESS_xxx_xWx, 
		ROUTE( OBJECT_TYPE_ENVELOPE ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* PKC encryption key */
		CRYPT_ENVINFO_PUBLICKEY, 
		ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY, 
		ST_ENV_DEENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_S(	/* Label of PKC decryption key */
		CRYPT_ENVINFO_PRIVATEKEY_LABEL,
		ST_ENV_DEENV, ACCESS_xxx_Rxx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_O(	/* Originator info/key */
		CRYPT_ENVINFO_ORIGINATOR, 
		ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* Session key */
		CRYPT_ENVINFO_SESSIONKEY, 
		ST_ENV_ANY, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* Hash algorithm */
		CRYPT_ENVINFO_HASH, 
		ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* MAC key */
		CRYPT_ENVINFO_MAC, 
		ST_ENV_ANY, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_S(	/* Timestamp authority */
		CRYPT_ENVINFO_TIMESTAMP_AUTHORITY,
		ST_ENV_ENV, ACCESS_xxx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ),
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_O(	/* Signature check keyset */
		CRYPT_ENVINFO_KEYSET_SIGCHECK, 
		ST_ENV_DEENV, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* PKC encryption keyset */
		CRYPT_ENVINFO_KEYSET_ENCRYPT, 
		ST_ENV_ENV, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) ),
	MKACL_O(	/* PKC decryption keyset */
		CRYPT_ENVINFO_KEYSET_DECRYPT, 
		ST_ENV_DEENV, ACCESS_xWx_xWx,
		ROUTE( OBJECT_TYPE_ENVELOPE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL sessionACL[] = {		/* Session attributes */
	MKACL_B_EX(	/* Whether session is active */
		CRYPT_SESSINFO_ACTIVE, 
		ST_SESSION_ANY, ACCESS_Rxx_RWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE( OBJECT_TYPE_SESSION ) ),
	MKACL_S(	/* User name */
		CRYPT_SESSINFO_USERNAME, 
		ST_SESSION_SSH, ACCESS_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Password */
		CRYPT_SESSINFO_PASSWORD, 
		ST_SESSION_SSH, ACCESS_xxx_RWx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) ),
	MKACL_S(	/* Server name */
		CRYPT_SESSINFO_SERVER, 
		ST_SESSION_ANY, ACCESS_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( MIN_URL_SIZE, MAX_URL_SIZE ) ),
	MKACL_N(	/* Server port number */
		CRYPT_SESSINFO_SERVER_PORT, 
		ST_SESSION_ANY, ACCESS_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 22, 65534 ) ),

	MKACL_N(	/* CMP status value */
		CRYPT_SESSINFO_CMP_STATUS, 
		ST_SESSION_CMP, ACCESS_xxx_xxx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 0, CRYPT_CMPSTATUS_LAST ) ),
	MKACL_N(	/* CMP password identifier */
		CRYPT_SESSINFO_CMP_STATUSINFO, 
		ST_SESSION_CMP, ACCESS_xxx_xxx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 0, CRYPT_CMPSTATUS_EXT_LAST ) ),
	MKACL_S(	/* CMP password identifier */
		CRYPT_SESSINFO_CMP_PASSWORD_ID, 
		ST_SESSION_CMP, ACCESS_xxx_xxx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 16, 16 ) ),
	MKACL_S(	/* CMP cert issuer name */
		CRYPT_SESSINFO_CMP_CA_NAME, 
		ST_SESSION_CMP, ACCESS_xxx_xxx, 
		ROUTE( OBJECT_TYPE_SESSION ), 
		RANGE( 1, CRYPT_MAX_TEXTSIZE ) )

	MKACL_END()
	};

static const ATTRIBUTE_ACL internalACL[] = {	/* Internal attributes */
	MKACL_N_EX(	/* Object type */
		CRYPT_IATTRIBUTE_TYPE, ST_ANY, ACCESS_INT_Rxx_Rxx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( OBJECT_TYPE_NONE, OBJECT_TYPE_LAST ) ),
	MKACL_EX(	/* Object status */
		CRYPT_IATTRIBUTE_STATUS, VALUE_NUMERIC, ST_ANY, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE_ALLOWEDVALUES, 
			/* Write = status value, read = OBJECT_FLAG_xxx (since an object
			   may be, for example, busy and signalled at the same time) */
		allowedObjectStatusValues ),
	MKACL_B_EX(	/* Object internal flag */
		CRYPT_IATTRIBUTE_INTERNAL, ST_ANY, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE ),
	MKACL_N_EX(	/* Object action permissions */
		CRYPT_IATTRIBUTE_ACTIONPERMS, ST_ANY, ACCESS_INT_RWx_RWx, ATTRIBUTE_FLAG_PROPERTY,
		ROUTE_NONE, RANGE( 0, ACTION_PERM_LAST ) ),
	MKACL_N_EX(	/* Object = inited (eg key loaded, cert signed) */
		CRYPT_IATTRIBUTE_INITIALISED, ST_ANY, ACCESS_INT_xxx_xWx, ATTRIBUTE_FLAG_TRIGGER,
		ROUTE_NONE, RANGE_UNUSED ),
	MKACL_N(	/* Ctx: Key size (for non-native ctxts) */
		CRYPT_IATTRIBUTE_KEYSIZE, ST_CTX_CONV | ST_CTX_PKC | ST_CTX_MAC, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_S(	/* Ctx: Key ID */
		CRYPT_IATTRIBUTE_KEYID, ST_CTX_PKC, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 20, 20 ) ),
	MKACL_S(	/* Ctx: Key agreement domain parameters */
		CRYPT_IATTRIBUTE_DOMAINPARAMS, ST_CTX_PKC, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 10, 10 ) ),
	MKACL_S(	/* Ctx: Key agreement public value */
		CRYPT_IATTRIBUTE_PUBLICVALUE, ST_CTX_PKC, ACCESS_INT_Rxx_Rxx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 64, CRYPT_MAX_PKCSIZE ) ),
	MKACL_S(	/* Ctx: Encoded SubjectPublicKeyInfo */
		CRYPT_IATTRIBUTE_PUBLICKEY, ST_CTX_PKC, ACCESS_INT_Rxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 64, CRYPT_MAX_PKCSIZE * 3 ) ),
	MKACL_S(	/* Ctx: SSH-format public key */
		CRYPT_IATTRIBUTE_SSH_PUBLICKEY, ST_CTX_PKC, ACCESS_INT_xxx_xWx,
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE( 64, CRYPT_MAX_PKCSIZE + 10 ) ),
	MKACL_N(	/* Ctx: Device object handle */
		CRYPT_IATTRIBUTE_DEVICEOBJECT,	ST_CTX_ANY, ACCESS_INT_Rxx_RWx, 
		ROUTE( OBJECT_TYPE_CONTEXT ), RANGE_ANY ),
	MKACL_S(	/* Cert: SubjectName */
		CRYPT_IATTRIBUTE_SUBJECT, ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_INT_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: IssuerName */
		CRYPT_IATTRIBUTE_ISSUER, ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ACCESS_INT_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: IssuerAndSerial */
		CRYPT_IATTRIBUTE_ISSUERANDSERIALNUMBER, ST_CERT_CERT | ST_CERT_CERTCHAIN | ST_CERT_CRL, ACCESS_INT_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: SET OF cert in chain */
		CRYPT_IATTRIBUTE_CERTSET, ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_INT_Rxx_xxx, 
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 16, 8192 ) ),
	MKACL_S(	/* Cert: Encoded SubjectPublicKeyInfo */
		CRYPT_IATTRIBUTE_SPKI, ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, CRYPT_MAX_PKCSIZE * 3 ) ),
	MKACL_S(	/* Cert: Encoded certificate */
		CRYPT_IATTRIBUTE_ENC_CERT, ST_CERT_ANY_CERT | SUBTYPE_CERT_CRL, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Cert: Encoded cert.chain */
		CRYPT_IATTRIBUTE_ENC_CERTCHAIN, ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Cert: Encoded CMS signed attrs.*/
		CRYPT_IATTRIBUTE_ENC_CMSATTR, ST_CERT_CMSATTR, ACCESS_INT_xxx_Rxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Cert: Base64-encoded certificate */
		CRYPT_IATTRIBUTE_TEXT_CERT, ST_CERT_ANY_CERT, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Cert: Base64-encoded cert.chain */
		CRYPT_IATTRIBUTE_TEXT_CERTCHAIN, ST_CERT_CERT | ST_CERT_CERTCHAIN, ACCESS_INT_Rxx_xxx,
		ROUTE( OBJECT_TYPE_CERTIFICATE ), RANGE( 64, 8192 ) ),
	MKACL_S(	/* Dev: Random data */
		CRYPT_IATTRIBUTE_RANDOM, ST_ANY, ACCESS_INT_RWx_RWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_S(	/* Dev: Nonzero random data */
		CRYPT_IATTRIBUTE_RANDOM_NZ, ST_ANY, ACCESS_INT_Rxx_Rxx, 
		ROUTE( OBJECT_TYPE_DEVICE ), RANGE( bitsToBytes( MIN_KEYSIZE_BITS ), CRYPT_MAX_PKCSIZE ) ),
	MKACL_N(	/* Dev: Quality of random data */
		CRYPT_IATTRIBUTE_RANDOM_QUALITY, ST_ANY, ACCESS_INT_xWx_xWx, 
		ROUTE( OBJECT_TYPE_DEVICE ), RANGE( 1, 100 ) ),
	MKACL_S(	/* Keyset: Encoded config information */
		CRYPT_IATTRIBUTE_CONFIGDATA, ST_KEYSET_FILE, ACCESS_INT_RWx_RWx, 
		ROUTE( OBJECT_TYPE_KEYSET ), RANGE( 64, 16384 ) )

	MKACL_END()
	};
#endif /* _CRYPTACL_DEFINED */
