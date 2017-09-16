/****************************************************************************
*																			*
*						Certificate Attribute Definitions					*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#include <ctype.h>
#include <string.h>
#if defined( INC_ALL ) ||  defined( INC_CHILD )
  #include "asn1.h"
  #include "asn1oid.h"
  #include "cert.h"
  #include "certattr.h"
#else
  #include "keymgmt/asn1.h"
  #include "keymgmt/asn1oid.h"
  #include "keymgmt/cert.h"
  #include "keymgmt/certattr.h"
#endif /* Compiler-specific includes */

/* The following certificate extensions are currently supported.  If
   'Enforced' is set to 'Yes', this means that they are constraint extensions
   which are enforced by the cert checking code; if set to '-', they are
   informational extensions for which enforcement doesn't apply; if set to
   'No', they need to be handled by the user (this only applies for
   certificate policies, where the user has to decide whether a given cert
   policy is acceptable or not).  If 'Read-only' is set to 'Yes', this means
   that they can be read by the user but not set (this applies for most
   informational extensions which are set by cryptlib, and to deprecated
   extensions).  The Yes/No in policyConstraints means that everything except
   the policy mapping constraint is enforced (because policyMappings itself
   isn't enforced).				Enforced	Read-only
								--------	---------
	authorityInfoAccess			   -			-
	authorityKeyIdentifier		   -		   Yes
	basicConstraints			  Yes			-
	certCardRequired (SET)		   -			-
	certificateIssuer			   -			-
	certificatePolicies			  Yes			-
	certificateType (SET)		   -			-
	cRLDistributionPoints		   -			-
	cRLNumber					   -			-
	cRLReason					   -			-
	deltaCRLIndicator			   -			-
	extKeyUsage					  Yes			-
	hashedRootKey (SET)			   -			-
	holdInstructionCode			   -			-
	invalidityDate				   -			-
	issuerAltName				   -		   Yes
	issuingDistributionPoint	   -			-
	keyUsage					  Yes			-
	nameConstraints				  Yes			-
	netscape-cert-type			  Yes			-
	netscape-base-url			   -			-
	netscape-revocation-url 	   -			-
	netscape-ca-revocation-url	   -			-
	netscape-cert-renewal-url	   -			-
	netscape-ca-policy-url		   -			-
	netscape-ssl-server-name	   -			-
	netscape-comment			   -			-
	merchantData (SET)			   -			-
	policyConstraints			 Yes/No			-
	policyMappings				  No			-
	privateKeyUsagePeriod		  Yes			-
	subjectAltName				   -			-
	subjectDirectoryAttributes	   -		   Yes
	subjectKeyIdentifier		   -		   Yes
	tunneling (SET)				   -			- */

/* Extended checking functions */

static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr );
static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr );
static int checkURL( const ATTRIBUTE_LIST *attributeListPtr );
static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr );
static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr );

/****************************************************************************
*																			*
*						Certificate Extension Definitions					*
*																			*
****************************************************************************/

/* The extension type and validity checking table.  This table is used to
   both check the validity of extension data and to describe the structure
   of an extension.  For example to describe the structure of the
   basicConstraints extension the entries would be:

	fieldID = CRYPT_CERTINFO_BASICCONSTRAINTS, fieldType = BER_SEQUENCE,
			OID = xxx, flags = FL_CRITICAL, FL_VALID_CERT, FL_MORE
	fieldID = CRYPT_CERTINFO_CA, fieldType = BER_BOOLEAN,
			flags = FL_OPTIONAL, FL_DEFAULT, FL_MORE, default = FALSE
	fieldID = CRYPT_CERTINFO_PATHLENCONSTRAINT, fieldType = BER_INTEGER,
			flags = FL_OPTIONAL

   If the extension has a single member rather than being built up as a
   SEQUENCE then the OID is set but the field-specific values are also set,
   so keyUsage would be:

	fieldID = CRYPT_CERTINFO_KEYUSAGE, fieldType = BER_BITSTRING,
			OID = xxx, flags = FL_CRITICAL, FL_VALID_CERTREQ, FL_VALID_CERT

   There are many special cases to handle things like no vs implicit vs
   explicit tagging (the X.509v3 default is to use implicit tags for
   extensions, so any explicit tags have to be explicitly specified):

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

   If the constructed object is nested, it's possible to specify the level of
   unnesting with BER_SEQEND_1... BER_SEQEND_3.

   Since some extensions fields are tagged, the fields as encoded differ from
   the fields as defined by the tagging, the following macro is used to turn
   a small integer into a context-specific tag.  By default the tag is
   implicit as per X.509v3, to make it an explicit tag we need to set the
   FL_EXPLICIT flag for the field */

#define CTAG( x )		( x | BER_CONTEXT_SPECIFIC )

/* Some extensions are specified as a SEQUENCE OF thing, to make it possible
   to process these automatically we rewrite them as a SEQUENCE OF
   thingInstance1 OPTIONAL, thingInstance2 OPTIONAL, ... thingInstanceN
   OPTIONAL.  Examples of this are extKeyUsage and the altNames */

extern const ATTRIBUTE_INFO FAR_BSS generalNameInfo[];	/* Alt.encoding table */
extern const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[];	/* Alt.encoding table */

const ATTRIBUTE_INFO FAR_BSS extensionInfo[] = {
	/* authorityInfoAccess:
		OID = 1 3 6 1 5 5 7 1 1
		critical = FALSE
		SEQUENCE SIZE (1...MAX) OF {							-- SIZE (1)
			SEQUENCE {
				accessMethod	OBJECT IDENTIFIER,
				accessLocation	GeneralName
				}
			} */
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x01\x01" ), CRYPT_CERTINFO_AUTHORITYINFOACCESS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* accessDescription */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x01" ), 0,
	  FIELDTYPE_IDENTIFIER, 0,	/* ocsp (1 3 6 1 5 5 7 48 1) */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_OCSP,
	  FIELDTYPE_SUBTYPED, 0,	/* accessDescription.accessLocation */
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* accessDescription */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x30\x02" ), 0,
	  FIELDTYPE_IDENTIFIER, 0,	/* caIssuers (1 3 6 1 5 5 7 48 2) */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS,
	  FIELDTYPE_SUBTYPED, 0,	/* accessDescription.accessLocation */
	  FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },

	/* dateOfCertGen
		OID = 1 3 36 8 3 1 
		critical = FALSE
		dateOfCertGen	GeneralizedTime */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x01" ), CRYPT_CERTINFO_SIGG_DATEOFCERTGEN,
	  BER_TIME_GENERALIZED, 0,
	  FL_VALID_CERT, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* procuration
		OID = 1 3 36 8 3 2 
		critical = FALSE
		SEQUENCE OF {											-- SIZE (1)
			country					PrintableString SIZE(2) OPTIONAL,
			typeOfSubstitution  [0]	PrintableString OPTIONAL,
			signingFor				GeneralName
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x02" ), CRYPT_CERTINFO_SIGG_PROCURATION,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_COUNTRY,
	  BER_STRING_PRINTABLE, 0,			/* country */
	  FL_MORE | FL_OPTIONAL, 2, 2, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_TYPEOFSUBSTITUTION,
	  BER_STRING_PRINTABLE, CTAG( 0 ),	/* typeOfSubstitution */
	  FL_MORE | FL_OPTIONAL, 1, 128, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR,
	  FIELDTYPE_SUBTYPED, 0,			/* signingFor.thirdPerson */
	  0, 0, 0, 0, ( void * ) generalNameInfo },

	/* monetaryLimit
		OID = 1 3 36 8 3 4 
		critical = FALSE
		SEQUENCE {
			currency	PrintableString SIZE(3),
			amount		INTEGER,
			exponent	INTEGER
			} */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x04" ), CRYPT_CERTINFO_SIGG_MONETARYLIMIT,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_CURRENCY,
	  BER_STRING_PRINTABLE, 0,	/* currency */
	  FL_MORE, 3, 3, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_AMOUNT,
	  BER_INTEGER, 0,	/* amount */
	  FL_MORE, 1, 255, 0, NULL },	/* That's what the spec says */
	{ NULL, CRYPT_CERTINFO_SIGG_MONETARY_EXPONENT,
	  BER_INTEGER, 0,	/* exponent */
	  0, 0, 255, 0, NULL },

	/* restriction
		OID = 1 3 36 8 3 8
		critical = FALSE
		restriction		PrintableString */
	{ MKOID( "\x06\x05\x2B\x24\x08\x03\x08" ), CRYPT_CERTINFO_SIGG_RESTRICTION,
	  BER_STRING_PRINTABLE, 0,
	  FL_VALID_CERT, 1, 128, 0, NULL },

	/* strongExtranet:
		OID = 1 3 101 1 4 1
		critical = FALSE
		SEQUENCE {
			version		INTEGER (0),
			SEQUENCE OF {										-- SIZE (1)
				SEQUENCE {
					zone	INTEGER,
					id		OCTET STRING (SIZE(1..64))
					}
				}
			} */
	{ MKOID( "\x06\x05\x2B\x65\x01\x04\x01" ), CRYPT_CERTINFO_STRONGEXTRANET,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  FIELDTYPE_BLOB, 0,				/* version = 0 */
	  FL_MORE | FL_NONENCODING, 0, 0, 3, "\x02\x01\x00" },
	{ NULL, 0,
	  BER_SEQUENCE, 0,					/* sxNetIDList */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,					/* sxNetIDList.sxNetID */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ZONE,
	  BER_INTEGER, 0,					/* sxNetIDList.sxNetID.zone */
	  FL_MORE, 0, INT_MAX, 0, NULL },
	{ NULL, CRYPT_CERTINFO_STRONGEXTRANET_ID,
	  BER_OCTETSTRING, 0,				/* sxNetIDList.sxnetID.id */
	  0, 1, 64, 0, NULL },

	/* subjectDirectoryAttributes:
		OID = 2 5 29 9
		critical = FALSE
		SEQUENCE SIZE (1..MAX) OF {								-- SIZE (1)
			SEQUENCE {
				type	OBJECT IDENTIFIER,
				values	SET OF ANY								-- SIZE (1)
				} */
	{ MKOID( "\x06\x03\x55\x1D\x09" ), CRYPT_CERTINFO_SUBJECTDIRECTORYATTRIBUTES,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_RO | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,					/* attribute */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_TYPE,
	  BER_OBJECT_IDENTIFIER, 0,			/* attribute.type */
	  FL_MORE | FL_RO, 3, 32, 0, NULL },
	{ NULL, 0,
	  BER_SET, 0,						/* attribute.values */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDIR_VALUES,
	  FIELDTYPE_BLOB, 0,				/* attribute.values.value */
	  FL_RO, 1, 1024, 0, NULL },

	/* subjectKeyIdentifier:
		OID = 2 5 29 14
		critical = FALSE
		OCTET STRING */
	{ MKOID( "\x06\x03\x55\x1D\x0E" ), CRYPT_CERTINFO_SUBJECTKEYIDENTIFIER,
	  BER_OCTETSTRING, 0,
	  FL_RO | FL_VALID_CERT, 1, 64, 0, NULL },

	/* keyUsage:
		OID = 2 5 29 15
		critical = TRUE
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x0F" ), CRYPT_CERTINFO_KEYUSAGE,
	  BER_BITSTRING, 0,
	  FL_CRITICAL | FL_VALID_CERTREQ | FL_VALID_CERT, 0, CRYPT_KEYUSAGE_LAST, 0, NULL },

	/* privateKeyUsagePeriod:
		OID = 2 5 29 16
		critical = FALSE
		SEQUENCE {
			notBefore	  [ 0 ]	GeneralizedTime OPTIONAL,
			notAfter	  [ 1 ]	GeneralizedTime OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x10" ), CRYPT_CERTINFO_PRIVATEKEYUSAGEPERIOD,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTBEFORE,
	  BER_TIME_GENERALIZED, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, sizeof( time_t ), sizeof( time_t ), 0, NULL },
	{ NULL, CRYPT_CERTINFO_PRIVATEKEY_NOTAFTER,
	  BER_TIME_GENERALIZED, CTAG( 1 ),
	  FL_OPTIONAL, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* subjectAltName:
		OID = 2 5 29 17
		SEQUENCE OF GeneralName									-- SIZE (1) */
	{ MKOID( "\x06\x03\x55\x1D\x11" ), FIELDID_FOLLOWS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTALTNAME,
	  FIELDTYPE_SUBTYPED, 0,
	  0, 0, 0, 0, ( void * ) generalNameInfo },

	/* issuerAltName:
		OID = 2 5 29 18
		SEQUENCE OF GeneralName									-- SIZE (1) */
	{ MKOID( "\x06\x03\x55\x1D\x12" ), FIELDID_FOLLOWS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT | FL_VALID_CRL | FL_RO, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUERALTNAME,
	  FIELDTYPE_SUBTYPED, 0,
	  0, 0, 0, 0, ( void * ) generalNameInfo },

	/* basicConstraints:
		OID = 2 5 29 19
		critical = TRUE
		SEQUENCE {
			cA					BOOLEAN DEFAULT FALSE,
			pathLenConstraint	INTEGER (0..64) OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x13" ), CRYPT_CERTINFO_BASICCONSTRAINTS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_VALID_CERTREQ | FL_VALID_CERT | FL_VALID_ATTRCERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CA,
	  BER_BOOLEAN, 0,
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_PATHLENCONSTRAINT,
	  BER_INTEGER, 0,
	  FL_OPTIONAL, 0, 64, 0, NULL },

	/* cRLNumber:
		OID = 2 5 29 20
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x14" ), CRYPT_CERTINFO_CRLNUMBER,
	  BER_INTEGER, 0,
	  FL_VALID_CRL, 0, INT_MAX, 0, NULL },

	/* cRLReason:
		OID = 2 5 29 21
		ENUMERATED */
	{ MKOID( "\x06\x03\x55\x1D\x15" ), CRYPT_CERTINFO_CRLREASON,
	  BER_ENUMERATED, 0,
	  FL_VALID_CRL /*Per-entry*/, 0, CRYPT_CRLREASON_LAST, 0, NULL },

	/* holdInstructionCode:
		OID = 2 5 29 23
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x03\x55\x1D\x17" ), CRYPT_CERTINFO_HOLDINSTRUCTIONCODE,
	  FIELDTYPE_CHOICE, 0,
	  FL_VALID_CRL /*Per-entry*/, CRYPT_HOLDINSTRUCTION_NONE, CRYPT_HOLDINSTRUCTION_LAST, 0, ( void * ) holdInstructionInfo },

	/* invalidityDate:
		OID = 2 5 29 24
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x18" ), CRYPT_CERTINFO_INVALIDITYDATE,
	  BER_TIME_GENERALIZED, 0,
	  FL_VALID_CRL /*Per-entry*/, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* deltaCRLIndicator:
		OID = 2 5 29 27
		critical = TRUE
		BITSTRING */
	{ MKOID( "\x06\x03\x55\x1D\x1B" ), CRYPT_CERTINFO_DELTACRLINDICATOR,
	  BER_INTEGER, 0,
	  FL_CRITICAL | FL_VALID_CRL, 0, INT_MAX, 0, NULL },

	/* issuingDistributionPoint:
		OID = 2 5 29 28
		critical = TRUE
		SEQUENCE {
			distributionPoint [ 0 ]	{
				fullName	  [ 0 ]	{			-- CHOICE { ... }
					SEQUENCE OF GeneralName		-- GeneralNames
					}
				} OPTIONAL,
			onlyContainsUserCerts
							  [ 1 ]	BOOLEAN DEFAULT FALSE,
			onlyContainsCACerts
							  [ 2 ]	BOOLEAN DEFAULT FALSE,
			onlySomeReasons	  [ 3 ]	BITSTRING OPTIONAL,
			indirectCRL		  [ 4 ]	BOOLEAN DEFAULT FALSE
		} */
	{ MKOID( "\x06\x03\x55\x1D\x1C" ), CRYPT_CERTINFO_ISSUINGDISTRIBUTIONPOINT,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),	/* distributionPoint */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),	/* distributionPoint.fullName */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* distributionPoint.fullName.generalNames */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_FULLNAME,
	  FIELDTYPE_SUBTYPED, 0,	/* distributionPoint.fullName.generalNames.generalName */
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_3, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_USERCERTSONLY,
	  BER_BOOLEAN, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_CACERTSONLY,
	  BER_BOOLEAN, CTAG( 2 ),
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_SOMEREASONSONLY,
	  BER_BITSTRING, CTAG( 3 ),
	  FL_MORE | FL_OPTIONAL, 0, CRYPT_CRLREASONFLAG_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUINGDIST_INDIRECTCRL,
	  BER_BOOLEAN, CTAG( 4 ),
	  FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },

	/* certificateIssuer:
		OID = 2 5 29 29
		critical = TRUE
		certificateIssuer SEQUENCE OF GeneralName	-- GeneralNames */
	{ MKOID( "\x06\x03\x55\x1D\x1D" ), 0,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTIFICATEISSUER,
	  FIELDTYPE_SUBTYPED, 0,
	  FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },

	/* nameConstraints
		OID = 2 5 29 30
		critical = TRUE
		SEQUENCE {
			permittedSubtrees [ 0 ]	SEQUENCE OF {				-- SIZE (1)
				SEQUENCE { GeneralName }
				} OPTIONAL,
			excludedSubtrees  [ 1 ]	SEQUENCE OF {				-- SIZE (1)
				SEQUENCE { GeneralName }
				} OPTIONAL,
			} */
	{ MKOID( "\x06\x03\x55\x1D\x1E" ), CRYPT_CERTINFO_NAMECONSTRAINTS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT | FL_VALID_ATTRCERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_PERMITTEDSUBTREES,
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EXCLUDEDSUBTREES,
	  FIELDTYPE_SUBTYPED, 0,
	  FL_OPTIONAL | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* cRLDistributionPoints:
		OID = 2 5 29 31
		SEQUENCE OF {											-- SIZE (1)
			SEQUENCE {
				distributionPoint
							  [ 0 ]	{			-- CHOICE { ... }
					fullName  [ 0 ]	{			-- SEQUENCE OF	-- SIZE (1)
						GeneralName
						}
					} OPTIONAL,
				reasons		  [ 1 ]	BIT STRING OPTIONAL,
				cRLIssuer	  [ 2 ]	SEQUENCE OF GeneralName OPTIONAL
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x1F" ), CRYPT_CERTINFO_CRLDISTRIBUTIONPOINT,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT | FL_VALID_ATTRCERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* distributionPoint */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),	/* distributionPoint.distributionPoint */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),	/* distributionPoint.distributionPoint.fullName */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CRLDIST_FULLNAME,
	  FIELDTYPE_SUBTYPED, 0,	/* distributionPoint.distributionPoint.fullName.generalName */
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_CRLDIST_REASONS,
	  BER_BOOLEAN, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, 0, CRYPT_CRLREASONFLAG_LAST, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 2 ),	/* distributionPoint.cRLIssuer */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CRLDIST_CRLISSUER,
	  FIELDTYPE_SUBTYPED, 0,
	  FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },

	/* certificatePolicies:
		OID = 2 5 29 32
		SEQUENCE SIZE (1..64) OF {								-- SIZE (1)
			SEQUENCE {
				policyIdentifier	OBJECT IDENTIFIER,
				policyQualifiers	SEQUENCE SIZE (1..64) OF	-- SIZE (1)
										PolicyQualifierInfo OPTIONAL
				}
			}

		PolicyQualifierInfo ::= SEQUENCE {
			policyQualifierId		OBJECT IDENTIFIER,
			qualifier				ANY DEFINED BY policyQualifierID
			}

		CPSuri ::= IA5String							-- OID = cps

		UserNotice ::= SEQUENCE {						-- OID = unotice
			noticeRef		SEQUENCE {
				organization	VisibleString,
				noticeNumbers	SEQUENCE OF INTEGER
				} OPTIONAL,
			explicitText	VisibleString OPTIONAL
			}
	   All draft versions of the PKIX profile had the organization as an 
	   IA5String, but the final RFC changed it to a VisibleString, in order 
	   to kludge around this for the certs which use an IA5String (which in
	   practice means only Verisign, since noone else uses policy
	   qualifiers), we allow both types but put the VisibleString option
	   first which means it'll get used preferentially when encoding */
	{ MKOID( "\x06\x03\x55\x1D\x20" ), CRYPT_CERTINFO_CERTIFICATEPOLICIES,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICYID,
	  BER_OBJECT_IDENTIFIER, 0,	/* policyInformation.policyIdentifier */
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifiers */
	  FL_MORE | FL_SETOF | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifier */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x01" ), 0,
	  FIELDTYPE_IDENTIFIER, 0,	/* cps (1 3 6 1 5 5 7 2 1) */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_CPSURI,
	  BER_STRING_IA5, 0,		/* policyInformation.policyQualifiers.qualifier.cPSuri */
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, MIN_URL_SIZE, MAX_URL_SIZE, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifier */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x02\x02" ), 0,
	  FIELDTYPE_IDENTIFIER, 0,	/* unotice (1 3 6 1 5 5 7 2 2) */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifier.userNotice */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifiers.userNotice.noticeRef */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,
	  BER_STRING_ISO646, 0,		/* policyInformation.policyQualifiers.userNotice.noticeRef.organization */
	  FL_MORE | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_ORGANIZATION,	/* Backwards-compat.kludge */
	  BER_STRING_IA5, 0,		/* policyInformation.policyQualifiers.userNotice.noticeRef.organization */
	  FL_MORE | FL_OPTIONAL, 1, 200, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policyInformation.policyQualifiers.userNotice.noticeRef.noticeNumbers */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_NOTICENUMBERS,
	  BER_INTEGER, 0,			/* policyInformation.policyQualifiers.userNotice.noticeRef.noticeNumbers */
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_2, 1, 1024, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CERTPOLICY_EXPLICITTEXT,
	  BER_STRING_ISO646, 0,		/* policyInformation.policyQualifiers.userNotice.explicitText */
	  FL_OPTIONAL, 1, 200, 0, NULL },

	/* policyMappings:
		OID = 2 5 29 33
		SEQUENCE SIZE (1..MAX) OF {						-- SIZE (1)
			SEQUENCE {
				issuerDomainPolicy	OBJECT IDENTIFIER,
				subjectDomainPolicy	OBJECT IDENTIFIER
				}
			} */
	{ MKOID( "\x06\x03\x55\x1D\x21" ), CRYPT_CERTINFO_POLICYMAPPINGS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_ISSUERDOMAINPOLICY,
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SUBJECTDOMAINPOLICY,
	  BER_OBJECT_IDENTIFIER, 0,
	  0, 3, 32, 0, NULL },

	/* authorityKeyIdentifier:
		OID = 2 5 29 35
		SEQUENCE {
			keyIdentifier [ 0 ]	OCTET STRING OPTIONAL,
			authorityCertIssuer
						  [ 1 ] {					-- SEQUENCE OF
				GeneralName
				} OPTIONAL,							-- Neither or both
			authorityCertSerialNumber				-- of these must
						  [ 2 ] INTEGER OPTIONAL	-- be present
			} */
	{ MKOID( "\x06\x03\x55\x1D\x23" ), CRYPT_CERTINFO_AUTHORITYKEYIDENTIFIER,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT | FL_VALID_CRL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_KEYIDENTIFIER,
	  BER_OCTETSTRING, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL | FL_RO, 1, 64, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTISSUER,
	  FIELDTYPE_SUBTYPED, 0,
	  FL_MORE | FL_OPTIONAL | FL_RO | FL_SEQEND, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, CRYPT_CERTINFO_AUTHORITY_CERTSERIALNUMBER,
	  BER_INTEGER, CTAG( 2 ),
	  FL_OPTIONAL | FL_RO, 0, INT_MAX, 0, NULL },

	/* policyConstraints:
		OID = 2 5 29 36
		SEQUENCE {
			requireExplicitPolicy [ 0 ]	INTEGER OPTIONAL,
			inhibitPolicyMapping  [ 1 ]	INTEGER OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x24" ), CRYPT_CERTINFO_POLICYCONSTRAINTS,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_REQUIREEXPLICITPOLICY,
	  BER_INTEGER, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_INHIBITPOLICYMAPPING,
	  BER_INTEGER, CTAG( 1 ),
	  FL_OPTIONAL, 0, 64, 0, NULL },

	/* extKeyUsage:
		OID = 2 5 29 37
		SEQUENCE {
			oidInstance1 OPTIONAL,
			oidInstance2 OPTIONAL,
				...
			oidInstanceN OPTIONAL
			} */
	{ MKOID( "\x06\x03\x55\x1D\x25" ), CRYPT_CERTINFO_EXTKEYUSAGE,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERTREQ | FL_VALID_CERT, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_EXTKEY_MS_INDIVIDUALCODESIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* individualCodeSigning (1 3 6 1 4 1 311 2 1 21) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_EXTKEY_MS_COMMERCIALCODESIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* commercialCodeSigning (1 3 6 1 4 1 311 2 1 22) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x01" ), CRYPT_CERTINFO_EXTKEY_MS_CERTTRUSTLISTSIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* certTrustListSigning (1 3 6 1 4 1 311 10 3 1) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x02" ), CRYPT_CERTINFO_EXTKEY_MS_TIMESTAMPSIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* timeStampSigning (1 3 6 1 4 1 311 10 3 2) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x03" ), CRYPT_CERTINFO_EXTKEY_MS_SERVERGATEDCRYPTO,
	  FIELDTYPE_IDENTIFIER, 0,	/* serverGatedCrypto (1 3 6 1 4 1 311 10 3 3) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x0A\x03\x04" ), CRYPT_CERTINFO_EXTKEY_MS_ENCRYPTEDFILESYSTEM,
	  FIELDTYPE_IDENTIFIER, 0,	/* encrypedFileSystem (1 3 6 1 4 1 311 10 3 4) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x01" ), CRYPT_CERTINFO_EXTKEY_SERVERAUTH,
	  FIELDTYPE_IDENTIFIER, 0,	/* serverAuth (1 3 6 1 5 5 7 3 1) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x02" ), CRYPT_CERTINFO_EXTKEY_CLIENTAUTH,
	  FIELDTYPE_IDENTIFIER, 0,	/* clientAuth (1 3 6 1 5 5 7 3 2) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x03" ), CRYPT_CERTINFO_EXTKEY_CODESIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* codeSigning (1 3 6 1 5 5 7 3 3) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x04" ), CRYPT_CERTINFO_EXTKEY_EMAILPROTECTION,
	  FIELDTYPE_IDENTIFIER, 0,	/* emailProtection (1 3 6 1 5 5 7 3 4) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x05" ), CRYPT_CERTINFO_EXTKEY_IPSECENDSYSTEM,
	  FIELDTYPE_IDENTIFIER, 0,	/* ipsecEndSystem (1 3 6 1 5 5 7 3 5) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x06" ), CRYPT_CERTINFO_EXTKEY_IPSECTUNNEL,
	  FIELDTYPE_IDENTIFIER, 0,	/* ipsecTunnel (1 3 6 1 5 5 7 3 6) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x07" ), CRYPT_CERTINFO_EXTKEY_IPSECUSER,
	  FIELDTYPE_IDENTIFIER, 0,	/* ipsecUser (1 3 6 1 5 5 7 3 7) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2B\x06\x01\x05\x05\x07\x03\x08" ), CRYPT_CERTINFO_EXTKEY_TIMESTAMPING,
	  FIELDTYPE_IDENTIFIER, 0,	/* timeStamping (1 3 6 1 5 5 7 3 8) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x05\x2B\x24\x08\x02\x01" ), CRYPT_CERTINFO_EXTKEY_DIRECTORYSERVICE,
	  FIELDTYPE_IDENTIFIER, 0,	/* directoryService (1 3 36 8 2 1) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x04\x01" ), CRYPT_CERTINFO_EXTKEY_NS_SERVERGATEDCRYPTO,
	  FIELDTYPE_IDENTIFIER, 0,	/* serverGatedCrypto (2 16 840 1 113730 4 1) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x60\x86\x48\x01\x86\xF8\x45\x01\x08\x01" ), CRYPT_CERTINFO_EXTKEY_VS_SERVERGATEDCRYPTO_CA,
	  FIELDTYPE_IDENTIFIER, 0,	/* serverGatedCryptoCA (2 16 840 1 113733 1 8 1) */
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* netscape-cert-type:
		OID = 2 16 840 1 113730 1 1
		BITSTRING */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x01" ), CRYPT_CERTINFO_NS_CERTTYPE,
	  BER_BITSTRING, 0,
	  FL_VALID_CERTREQ | FL_VALID_CERT, 0, CRYPT_NS_CERTTYPE_LAST, 0, NULL },

	/* netscape-base-url:
		OID = 2 16 840 1 113730 1 2
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x02" ), CRYPT_CERTINFO_NS_BASEURL,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERTREQ | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x03" ), CRYPT_CERTINFO_NS_REVOCATIONURL,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERTREQ | FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ca-revocation-url:
		OID = 2 16 840 1 113730 1 3
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x04" ), CRYPT_CERTINFO_NS_CAREVOCATIONURL,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-cert-renewal-url:
		OID = 2 16 840 1 113730 11 7
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x07" ), CRYPT_CERTINFO_NS_CERTRENEWALURL,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ca-policy-url:
		OID = 2 16 840 1 113730 1 8
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x08" ), CRYPT_CERTINFO_NS_CAPOLICYURL,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERT, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* netscape-ssl-server-name:
		OID = 2 16 840 1 113730 1 12
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0C" ), CRYPT_CERTINFO_NS_SSLSERVERNAME,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERTREQ | FL_VALID_CERT, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkDNS },

	/* netscape-comment:
		OID = 2 16 840 1 113730 1 13
		IA5String */
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x01\x0D" ), CRYPT_CERTINFO_NS_COMMENT,
	  BER_STRING_IA5, 0,
	  FL_VALID_CERTREQ | FL_VALID_CERT, 1, 1024, 0, NULL },

	/* hashedRootKey:
		OID = 2 23 42 7 0
		critical = TRUE
		SEQUENCE {
			rootKeyThumbprint	DigestedData	-- PKCS #7-type wrapper
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x00" ), CRYPT_CERTINFO_SET_HASHEDROOTKEY,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_CRITICAL | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, 0,
	  FIELDTYPE_BLOB, 0,				/* PKCS #7-type wrapper */
	  FL_MORE | FL_NONENCODING, 0, 0, 25, 
	  "\x30\x2D\x02\x01\x00\x30\x09\x06\x05\x2B\x0E\x03\x02\x1A\x05\x00\x30\x07\x06\x05\x67\x2A\x03\x00\x00" },
	{ NULL, CRYPT_CERTINFO_SET_ROOTKEYTHUMBPRINT,
	  BER_OCTETSTRING, 0,
	  0, 20, 20, 0, NULL },

	/* certificateType:
		OID = 2 23 42 7 1
		critical = TRUE
		BIT STRING */
	{ MKOID( "\x06\x04\x67\x2A\x07\x01" ), CRYPT_CERTINFO_SET_CERTIFICATETYPE,
	  BER_BITSTRING, 0,
	  FL_CRITICAL | FL_VALID_CERT | FL_VALID_CERTREQ, 0, CRYPT_SET_CERTTYPE_LAST, 0, NULL },

	/* merchantData:
		OID = 2 23 42 7 2
		SEQUENCE {
			merID				SETString SIZE(1..30),
			merAcquirerBIN		NumericString SIZE(6),
			merNameSeq			SEQUENCE OF MerNames,		-- Size 1
			merCountry			INTEGER (1..999),
			merAuthFlag			BOOLEAN DEFAULT TRUE
			}

		MerNames ::= SEQUENCE {
			language	  [ 0 ] VisibleString SIZE(1..35),
			name		  [ 1 ]	EXPLICIT SETString SIZE(1..50),
			city		  [ 2 ]	EXPLICIT SETString SIZE(1..50),
			stateProvince [ 3 ] EXPLICIT SETString SIZE(1..50) OPTIONAL,
			postalCode	  [ 4 ] EXPLICIT SETString SIZE(1..14) OPTIONAL,
			countryName	  [ 5 ]	EXPLICIT SETString SIZE(1..50)
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x02" ), CRYPT_CERTINFO_SET_MERCHANTDATA,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERID,
	  BER_STRING_ISO646, 0,			/* merID */
	  FL_MORE, 1, 30, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERACQUIRERBIN,
	  BER_STRING_NUMERIC, 0,		/* merAcquirerBIN */
	  FL_MORE,  6, 6, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,				/* merNameSeq */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTLANGUAGE,
	  BER_STRING_ISO646, CTAG( 0 ),	/* merNameSeq.language */
	  FL_MORE, 1, 35, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTNAME,
	  BER_STRING_ISO646, CTAG( 1 ),	/* merNameSeq.name */
	  FL_MORE | FL_EXPLICIT, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCITY,
	  BER_STRING_ISO646, CTAG( 2 ),	/* merNameSeq.city */
	  FL_MORE | FL_EXPLICIT, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTSTATEPROVINCE,
	  BER_STRING_ISO646, CTAG( 3 ),	/* merNameSeq.stateProvince */
	  FL_MORE | FL_EXPLICIT | FL_OPTIONAL, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTPOSTALCODE,
	  BER_STRING_ISO646, CTAG( 4 ),	/* merNameSeq.postalCode */
	  FL_MORE | FL_EXPLICIT | FL_OPTIONAL, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCHANTCOUNTRYNAME,
	  BER_STRING_ISO646, CTAG( 5 ),	/* merNameSeq.countryName */
	  FL_MORE | FL_EXPLICIT | FL_SEQEND, 1, 50, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERCOUNTRY,
	  BER_INTEGER, 0,				/* merCountry */
	  FL_MORE, 1, 999, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_MERAUTHFLAG,
	  BER_BOOLEAN, 0,				/* merAuthFlag */
	  FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, FALSE, NULL },

	/* certCardRequired
		OID = 2 23 42 7 3
		BOOLEAN */
	{ MKOID( "\x06\x04\x67\x2A\x07\x03" ), CRYPT_CERTINFO_SET_CERTCARDREQUIRED,
	  BER_BOOLEAN, 0,
	  FL_VALID_CERT, FALSE, TRUE, 0, NULL },

	/* tunneling:
		OID = 2 23 42 7 4
		SEQUENCE {
			tunneling 		DEFAULT TRUE,
			tunnelAlgIDs	SEQUENCE OF OBJECT IDENTIFIER	-- Size 1
			} */
	{ MKOID( "\x06\x04\x67\x2A\x07\x04" ), CRYPT_CERTINFO_SET_TUNNELING,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_VALID_CERT | FL_VALID_CERTREQ, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGFLAG,
	  BER_BOOLEAN, 0,			/* tunneling */
	  FL_MORE | FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, TRUE, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* tunnelingAlgIDs */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_SET_TUNNELINGALGID,
	  BER_OBJECT_IDENTIFIER, 0,	/* tunnelingAlgIDs.tunnelingAlgID */
	  0, 3, 32, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the holdInstructionCode */

const ATTRIBUTE_INFO FAR_BSS holdInstructionInfo[] = {
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x01" ), CRYPT_HOLDINSTRUCTION_NONE,
	  FIELDTYPE_IDENTIFIER, 0,	/* holdinstruction-none (1 2 840 10040 2 1) */
	  FL_MORE | FL_OPTIONAL | FL_RO, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x02" ), CRYPT_HOLDINSTRUCTION_CALLISSUER,
	  FIELDTYPE_IDENTIFIER, 0,	/* holdinstruction-callissuer (1 2 840 10040 2 2) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x03" ), CRYPT_HOLDINSTRUCTION_REJECT,
	  FIELDTYPE_IDENTIFIER, 0,	/* holdinstruction-reject (1 2 840 10040 2 3) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x07\x2A\x86\x48\xCE\x38\x02\x04" ), CRYPT_HOLDINSTRUCTION_PICKUPTOKEN,
	  FIELDTYPE_IDENTIFIER, 0,	/* holdinstruction-pickupToken (1 2 840 10040 2 4) */
	  FL_OPTIONAL, 0, 0, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*								GeneralName Definition						*
*																			*
****************************************************************************/

/* Encoding and decoding of GeneralNames is performed with the following
   subtable:

	otherName		  [ 0 ]	SEQUENCE OPTIONAL {
		type-id				OBJECT IDENTIFIER,
		value		  [ 0 ]	EXPLICIT ANY DEFINED BY type-id
		},
	rfc822Name		  [ 1 ]	IA5String OPTIONAL,
	dNSName			  [ 2 ]	IA5String OPTIONAL,
	x400Address		  [ 3 ] ITU-BrainDamage OPTIONAL
	directoryName	  [ 4 ]	EXPLICIT Name OPTIONAL,
	ediPartyName 	  [ 5 ]	SEQUENCE OPTIONAL {
		nameAssigner  [ 0 ]	PrintableString OPTIONAL,
		partyName	  [ 1 ]	PrintableString
		},
	uniformResourceIdentifier
					  [ 6 ]	IA5String OPTIONAL,
	iPAddress		  [ 7 ]	OCTET STRING SIZE(4) OPTIONAL,
	registeredID	  [ 8 ]	OBJECT IDENTIFIER OPTIONAL

	ITU-Braindamge ::= SEQUENCE {
		built-in-standard-attributes		SEQUENCE {
			country-name  [ APPLICATION 1 ]	CHOICE {
				x121-dcc-code				NumericString,
				iso-3166-alpha2-code		PrintableString
				},
			administration-domain-name
						  [ APPLICATION 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				},
			network-address			  [ 0 ]	NumericString OPTIONAL,
			terminal-identifier		  [ 1 ]	PrintableString OPTIONAL,
			private-domain-name		  [ 2 ]	CHOICE {
				numeric						NumericString,
				printable					PrintableString
				} OPTIONAL,
			organization-name		  [ 3 ]	PrintableString OPTIONAL,
			numeric-use-identifier	  [ 4 ]	NumericString OPTIONAL,
			personal-name			  [ 5 ]	SET {
				surname				  [ 0 ]	PrintableString,
				given-name			  [ 1 ]	PrintableString,
				initials			  [ 2 ]	PrintableString,
				generation-qualifier  [ 3 ]	PrintableString
				} OPTIONAL,
			organizational-unit-name  [ 6 ]	PrintableString OPTIONAL,
			}
		built-in-domain-defined-attributes	SEQUENCE OF {		-- SIZE (1)
			type							PrintableString SIZE(1..64),
			value							PrintableString SIZE(1..64)
			} OPTIONAL
		extensionAttributes					SET OF SEQUENCE {	-- SIZE (1)
			extension-attribute-type  [ 0 ]	INTEGER,
			extension-attribute-value [ 1 ]	ANY DEFINED BY extension-attribute-type
			} OPTIONAL
		}

   Needless to say, X.400 addresses aren't supported (for readers who've
   never seen one before, now you know why they've been so enormously
   successful).

   Note the special-case encoding of the DirectoryName.  This is required
   because a Name is actually a CHOICE { RDNSequence }, and if the tagging
   were implicit then there'd be no way to tell which of the CHOICE options
   was being used:

	directoryName	  [ 4 ]	Name OPTIONAL

   becomes:

	directoryName	  [ 4 ]	CHOICE { RDNSequence } OPTIONAL

   which, if implicit tagging is used, would replace the RDNSequence tag with
   the [4] tag, making it impossible to determine which of the Name choices
   was used (actually there's only one possibility and it's unlikely that
   there'll ever be more, but that's what the encoding rules require - X.208,
   section 26.7c) */

const ATTRIBUTE_INFO FAR_BSS generalNameInfo[] = {
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_TYPEID,
	  BER_OBJECT_IDENTIFIER, 0,
	  FL_MORE | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_OTHERNAME_VALUE,
	  FIELDTYPE_BLOB, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL | FL_EXPLICIT | FL_SEQEND, 3, 512, 0, NULL },
	{ NULL, CRYPT_CERTINFO_RFC822NAME,
	  BER_STRING_IA5, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL, MIN_RFC822_SIZE, MAX_RFC822_SIZE, 0, ( void * ) checkRFC822 },
	{ NULL, CRYPT_CERTINFO_DNSNAME,
	  BER_STRING_IA5, CTAG( 2 ),
	  FL_MORE | FL_OPTIONAL, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkDNS },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 4 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_DIRECTORYNAME,
	  FIELDTYPE_DN, BER_SEQUENCE,
	  FL_MORE | FL_OPTIONAL | FL_SEQEND_1, 0, 0, 0, ( void * ) checkDirectoryName },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 5 ),
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_NAMEASSIGNER,
	  BER_STRING_PRINTABLE, CTAG( 0 ),
	  FL_MORE | FL_OPTIONAL, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_EDIPARTYNAME_PARTYNAME,
	  BER_STRING_PRINTABLE, CTAG( 1 ),
	  FL_MORE | FL_OPTIONAL | FL_SEQEND, 1, CRYPT_MAX_TEXTSIZE, 0, NULL },
	{ NULL, CRYPT_CERTINFO_UNIFORMRESOURCEIDENTIFIER,
	  BER_STRING_IA5, CTAG( 6 ),
	  FL_MORE | FL_OPTIONAL, MIN_DNS_SIZE, MAX_DNS_SIZE, 0, ( void * ) checkURL },
	{ NULL, CRYPT_CERTINFO_IPADDRESS,
	  BER_OCTETSTRING, CTAG( 7 ),
	  FL_MORE | FL_OPTIONAL, 4, 4, 0, NULL },
	{ NULL, CRYPT_CERTINFO_REGISTEREDID,
	  BER_OBJECT_IDENTIFIER, CTAG( 8 ),
	  FL_OPTIONAL, 3, 32, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*							CMS Attribute Definitions						*
*																			*
****************************************************************************/

/* CMS attributes are encoded using the following table.  These work just
   like certificate attributes but are used in CMS signatures */

extern const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[];	/* Alt.encoding table */

const ATTRIBUTE_INFO FAR_BSS cmsAttributeInfo[] = {
	/* contentType:
		OID = 1 2 840 113549 1 9 3
		OBJECT IDENTIFIER */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x03" ), CRYPT_CERTINFO_CMS_CONTENTTYPE,
	  FIELDTYPE_CHOICE, 0,
	  0, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* messageDigest:
		OID = 1 2 840 113549 1 9 4
		OCTET STRING */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x04" ), CRYPT_CERTINFO_CMS_MESSAGEDIGEST,
	  BER_OCTETSTRING, 0,
	  0, 16, 32, 0, NULL },

	/* signingTime:
		OID = 1 2 840 113549 1 9 5
		CHOICE {
			utcTime			UTCTime,			-- Up to 2049
			generalizedTime	GeneralizedTime
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x05" ), CRYPT_CERTINFO_CMS_SIGNINGTIME,
	  BER_TIME_UTC, 0,
	  0, sizeof( time_t ), sizeof( time_t ), 0, NULL },

	/* counterSignature:
		OID = 1 2 840 113549 1 9 6
		CHOICE {
			utcTime			UTCTime,			-- Up to 2049
			generalizedTime	GeneralizedTime
			}
	   This field isn't an authenticated attribute so it isn't used */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x06" ), CRYPT_CERTINFO_CMS_COUNTERSIGNATURE,
	  -1, 0,
	  0, 0, 0, 0, NULL },

	/* sMIMECapabilities:
		OID = 1 2 840 113549 1 9 15
		SEQUENCE OF {
			SEQUENCE {
				capabilityID	OBJECT IDENTIFIER,
				parameters		ANY DEFINED BY capabilityID
				}
			} */
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F" ), CRYPT_CERTINFO_CMS_SMIMECAPABILITIES,
	  BER_SEQUENCE, 0,
	  FL_MORE | FL_SETOF, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: 3DES */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_3DES,
	  FIELDTYPE_IDENTIFIER, 0,	/* des-EDE3-CBC */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: CAST-128 */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF6\x7D\x07\x42\x0A" ), CRYPT_CERTINFO_CMS_SMIMECAP_CAST128,
	  FIELDTYPE_IDENTIFIER, 0,	/* cast5CBC */
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  FIELDTYPE_BLOB, 0,		/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: IDEA */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0B\x2B\x06\x01\x04\x01\x81\x3C\x07\x01\x01\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_IDEA,
	  FIELDTYPE_IDENTIFIER, 0,	/* Ascom Tech's ideaCBC */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: RC2 */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC2,
	  FIELDTYPE_IDENTIFIER, 0,	/* rc2CBC */
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  FIELDTYPE_BLOB, 0,		/* 128-bit key */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 4, "\x02\x02\x00\x80" },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: RC5 */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x08\x2A\x86\x48\x86\xF7\x0D\x03\x09" ), CRYPT_CERTINFO_CMS_SMIMECAP_RC5,
	  FIELDTYPE_IDENTIFIER, 0,	/* rC5-CBCPad */
	  FL_MORE | FL_NONENCODING, 0, 0, 0, NULL },
	{ NULL, 0,
	  FIELDTYPE_BLOB, 0,		/* 16-byte key, 12 rounds, 64-bit blocks */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 11, "\x30\x09\x02\x01\x10\x02\x01\x0C\x02\x01\x40" },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: Skipjack (because we can) */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x04" ), CRYPT_CERTINFO_CMS_SMIMECAP_SKIPJACK,
	  FIELDTYPE_IDENTIFIER, 0,	/* fortezzaConfidentialityAlgorithm */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: DES */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x05\x2B\x0E\x03\x02\x07" ), CRYPT_CERTINFO_CMS_SMIMECAP_DES,
	  FIELDTYPE_IDENTIFIER, 0,	/* desCBC */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: Prefer signed data */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x01" ), CRYPT_CERTINFO_CMS_SMIMECAP_PREFERSIGNEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* preferSignedData */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: Cannot decrypt data */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x09\x0F\x02" ), CRYPT_CERTINFO_CMS_SMIMECAP_CANNOTDECRYPTANY,
	  FIELDTYPE_IDENTIFIER, 0,	/* canNotDecryptAny */
	  FL_MORE | FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* capability: Catch-all NOP */
	  FL_MORE | FL_IDENTIFIER, 0, 0, 0, NULL },
	{ NULL, 10000,
	  FIELDTYPE_BLOB, 0,		/* Match anything and ignore it */
	  FL_NONENCODING | FL_SEQEND, 0, 0, 0, NULL },

	/* receiptRequest:
		OID = 1 2 840 113549 1 9 16 2 1
		SEQUENCE {
			contentIdentifier	OCTET STRING,
			receiptsFrom  [ 0 ]	INTEGER (0..1),
			receiptsTo			SEQUENCE {
				SEQUENCE OF GeneralName			-- GeneralNames
				}
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x01" ), CRYPT_CERTINFO_CMS_RECEIPTREQUEST,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_CONTENTIDENTIFIER,
	  BER_OCTETSTRING, 0,		/* contentIdentifier */
	  FL_MORE, 16, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_FROM,
	  BER_INTEGER, CTAG( 0 ),	/* receiptsFrom */
	  FL_MORE, 0, 1, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* receiptsTo */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* receiptsTo.generalNames */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_RECEIPT_TO,
	  FIELDTYPE_SUBTYPED, 0,	/* receiptsTo.generalNames.generalName */
	  FL_SEQEND_2, 0, 0, 0, ( void * ) generalNameInfo },

	/* essSecurityLabel:
		OID = 1 2 840 113549 1 9 16 2 2
		SET {
			policyIdentifier	OBJECT IDENTIFIER,
			classification		INTEGER (0..5+6..255) OPTIONAL,
			privacyMark			PrintableString OPTIONAL,
			categories			SET OF {
				SEQUENCE {
					type  [ 0 ]	OBJECT IDENTIFIER,
					value [ 1 ]	ANY DEFINED BY type
					}
				} OPTIONAL
			}
		Because this is a SET, we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x02" ), CRYPT_CERTINFO_CMS_SECURITYLABEL,
	  BER_SET, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CLASSIFICATION,
	  BER_INTEGER, 0,			/* securityClassification */
	  FL_MORE | FL_OPTIONAL, CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_POLICY,
	  BER_OBJECT_IDENTIFIER, 0,	/* securityPolicyIdentifier */
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_PRIVACYMARK,
	  BER_STRING_PRINTABLE, 0,	/* privacyMark */
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, 0,
	  BER_SET, 0,				/* securityCategories */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* securityCategories.securityCategory */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATTYPE,
	  BER_OBJECT_IDENTIFIER, CTAG( 0 ),	/* securityCategories.securityCategory.type */
	  FL_MORE | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SECLABEL_CATVALUE,
	  FIELDTYPE_BLOB, CTAG( 1 ),/* securityCategories.securityCategory.type */
	  FL_SEQEND_2 | FL_OPTIONAL, 1, 512, 0, NULL },

	/* mlExpansionHistory:
		OID = 1 2 840 113549 1 9 16 2 3
		SEQUENCE OF {
			SEQUENCE {
				entityIdentifier IssuerAndSerialNumber (blob),
				expansionTime	GeneralizedTime,
				mlReceiptPolicy	CHOICE {
					none		  [ 0 ]	NULL,
					insteadOf	  [ 1 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName			-- GeneralNames
						}
					inAdditionTo  [ 2 ]	SEQUENCE OF {
						SEQUENCE OF GeneralName			-- GeneralNames
						}
					}
				} OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x03" ), CRYPT_CERTINFO_CMS_MLEXPANSIONHISTORY,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* mlData */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_ENTITYIDENTIFIER,
	  FIELDTYPE_BLOB, 0,		/* mlData.mailListIdentifier.issuerAndSerialNumber */
	  FL_MORE, 1, 512, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_TIME,
	  BER_TIME_GENERALIZED, 0,		/* mlData.expansionTime */
	  FL_MORE, sizeof( time_t ), sizeof( time_t ), 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_NONE,
	  BER_NULL, CTAG( 0 ),		/* mlData.mlReceiptPolicy.none */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 1 ),	/* mlData.mlReceiptPolicy.insteadOf */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* mlData.mlReceiptPolicy.insteadOf.generalNames */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INSTEADOF,
	  FIELDTYPE_SUBTYPED, 0,	/* mlData.mlReceiptPolicy.insteadOf.generalNames.generalName */
	  FL_SEQEND_2 | FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 2 ),	/* mlData.mlReceiptPolicy.inAdditionTo */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* mlData.mlReceiptPolicy.inAdditionTo.generalNames */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_MLEXP_INADDITIONTO,
	  FIELDTYPE_SUBTYPED, 0,	/* mlData.mlReceiptPolicy.inAdditionTo.generalNames.generalName */
	  FL_SEQEND_2 | FL_OPTIONAL, 0, 0, 0, ( void * ) generalNameInfo },

	/* contentHints:
		OID = 1 2 840 113549 1 9 16 2 4
		SEQUENCE {
			contentDescription	UTF8String,
			contentType			OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x04" ), CRYPT_CERTINFO_CMS_CONTENTHINTS,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_DESCRIPTION,
	  BER_STRING_UTF8, 0,		/* contentDescription */
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_CONTENTHINT_TYPE,
	  FIELDTYPE_CHOICE, 0,		/* contentType */
	  0, CRYPT_CONTENT_DATA, CRYPT_CONTENT_LAST, 0, ( void * ) contentTypeInfo },

	/* equivalentLabels:
		OID = 1 2 840 113549 1 9 16 2 9
		SEQUENCE OF {
			SET {
				policyIdentifier OBJECT IDENTIFIER,
				classification	INTEGER (0..5) OPTIONAL,
				privacyMark		PrintableString OPTIONAL,
				categories		SET OF {
					SEQUENCE {
						type  [ 0 ]	OBJECT IDENTIFIER,
						value [ 1 ]	ANY DEFINED BY type
						}
					} OPTIONAL
				}
			}
		Because this is a SET, we don't order the fields in the sequence
		given in the above ASN.1 but in the order of encoded size to follow
		the DER SET encoding rules */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x09" ), CRYPT_CERTINFO_CMS_EQUIVALENTLABEL,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SET, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CLASSIFICATION,
	  BER_INTEGER, 0,			/* securityClassification */
	  FL_MORE | FL_OPTIONAL, CRYPT_CLASSIFICATION_UNMARKED, CRYPT_CLASSIFICATION_LAST, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_POLICY,
	  BER_OBJECT_IDENTIFIER, 0,	/* securityPolicyIdentifier */
	  FL_MORE, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_PRIVACYMARK,
	  BER_STRING_PRINTABLE, 0,	/* privacyMark */
	  FL_MORE | FL_OPTIONAL, 1, 64, 0, NULL },
	{ NULL, 0,
	  BER_SET, 0,				/* securityCategories */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* securityCategories.securityCategory */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATTYPE,
	  BER_OBJECT_IDENTIFIER, CTAG( 0 ),	/* securityCategories.securityCategory.type */
	  FL_MORE | FL_OPTIONAL, 3, 32, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_EQVLABEL_CATVALUE,
	  FIELDTYPE_BLOB, CTAG( 1 ),/* securityCategories.securityCategory.type */
	  FL_SEQEND_2 | FL_OPTIONAL, 1, 512, 0, NULL },

	/* signingCertificate:
		OID = 1 2 840 113549 1 9 16 2 12
		SEQUENCE {
			SEQUENCE OF {
				SEQUENCE {
					certHash			OCTET STRING
					}
				}
			SEQUENCE OF {
				SEQUENCE {
					policyIdentifier	OBJECT IDENTIFIER
					}
				} OPTIONAL
			} */
	{ MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x02\x0C" ), CRYPT_CERTINFO_CMS_SIGNINGCERTIFICATE,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* certs */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* certs.essCertID */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_CERTS,
	  BER_OCTETSTRING, 0,		/* certs.essCertID.certHash */
	  FL_MORE | FL_SEQEND_2, 20, 20, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policies */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, 0,			/* policies.policyInformation */
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SIGNINGCERT_POLICIES,
	  BER_OBJECT_IDENTIFIER, 0,	/* policies.policyInformation.policyIdentifier */
	  FL_OPTIONAL, 3, 32, 0, NULL },

	/* spcAgencyInfo:
		OID = 1 3 6 1 4 1 311 2 1 10
		SEQUENCE {
			???		  [ 0 ]	EXPLICIT {
				url	  [ 0 ]	IA5String
				}
			}
	   The exact format for this attribute is unknown but when it seems to be
	   an unnecessarily nested URL which is probably an IA5String */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0A" ), CRYPT_CERTINFO_CMS_SPCAGENCYINFO,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, 0,
	  BER_SEQUENCE, CTAG( 0 ),
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SPCAGENCYURL,
	  BER_STRING_IA5, CTAG( 0 ),
	  0, MIN_URL_SIZE, MAX_URL_SIZE, 0, ( void * ) checkHTTP },

	/* spcStatementType:
		OID = 1 3 6 1 4 1 311 2 1 11
		SEQUENCE OF {
			OBJECT IDENTIFIER
			} */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0B" ), CRYPT_CERTINFO_CMS_SPCSTATEMENTTYPE,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x15" ), CRYPT_CERTINFO_CMS_SPCSTMT_INDIVIDUALCODESIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* individualCodeSigning (1 3 6 1 4 1 311 2 1 21) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x16" ), CRYPT_CERTINFO_CMS_SPCSTMT_COMMERCIALCODESIGNING,
	  FIELDTYPE_IDENTIFIER, 0,	/* commercialCodeSigning (1 3 6 1 4 1 311 2 1 22) */
	  FL_OPTIONAL, 0, 0, 0, NULL },

	/* spcOpusInfo:
		OID = 1 3 6 1 4 1 311 2 1 12
		SEQUENCE {
			???
			}
	   The format for this attribute is unknown but it always seems to be
	   present as an empty sequence.  We obtain this effect by representing
	   it as a BOOLEAN with a default value of TRUE, which means it can be
	   added with ( CRYPT_CERTINFO_CMS_SPCOPUSINFO, TRUE ) but always gets
	   encoded as an empty sequence */
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x0C" ), FIELDID_FOLLOWS,
	  BER_SEQUENCE, 0,
	  FL_MORE, 0, 0, 0, NULL },
	{ NULL, CRYPT_CERTINFO_CMS_SPCOPUSINFO,
	  BER_BOOLEAN, 0,
	  FL_OPTIONAL | FL_DEFAULT, FALSE, TRUE, TRUE, NULL },

	{ NULL, CRYPT_ERROR }
	};

/* Subtable for encoding the contentType */

const ATTRIBUTE_INFO FAR_BSS contentTypeInfo[] = {
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" ), CRYPT_CONTENT_DATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* data (1 2 840 113549 1 7 1) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" ), CRYPT_CONTENT_SIGNEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* signedData (1 2 840 113549 1 7 2) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" ), CRYPT_CONTENT_ENVELOPEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* envelopedData (1 2 840 113549 1 7 3) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x04" ), CRYPT_CONTENT_SIGNEDANDENVELOPEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* envelopedData (1 2 840 113549 1 7 4) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" ), CRYPT_CONTENT_DIGESTEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* digestedData (1 2 840 113549 1 7 5) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" ), CRYPT_CONTENT_ENCRYPTEDDATA,
	  FIELDTYPE_IDENTIFIER, 0,	/* digestedData (1 2 840 113549 1 7 6) */
	  FL_MORE | FL_OPTIONAL, 0, 0, 0, NULL },
	{ MKOID( "\x06\x0A\x2B\x06\x01\x04\x01\x82\x37\x02\x01\x04" ), CRYPT_CONTENT_SPCINDIRECTDATACONTEXT,
	  FIELDTYPE_IDENTIFIER, 0,	/* spcIndirectDataContext (1 3 6 1 4 1 311 2 1 4) */
	  FL_OPTIONAL, 0, 0, 0, NULL },

	{ NULL, CRYPT_ERROR }
	};

/****************************************************************************
*																			*
*						Extended Validity Checking Functions				*
*																			*
****************************************************************************/

/* Determine whether a variety of URLs are valid */

typedef enum { URL_RFC822, URL_DNS, URL_HTTP, URL_ANY } URL_TYPE;

static int checkURLString( const char *url, const URL_TYPE urlType )
	{
	char *urlPtr = ( char * ) url;
	int i;

	/* Make sure the start of the URL looks valid */
	switch( urlType )
		{
		case URL_DNS:
			if( isdigit( url[ 0 ] && isdigit( url[ 1 ] ) ) )
				/* Catch erroneous use of IP address */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			/* Drop through */

		case URL_RFC822:
			for( i = 0; urlPtr[ i ]; i++ )
				if( urlPtr[ i ] == '/' || urlPtr[ i ] == ':' )
					/* Catch erroneous use of URL */
					return( CRYPT_ERRTYPE_ATTR_VALUE );
			break;

		case URL_HTTP:
			if( strnicmp( url, "http://", 7 ) && \
				strnicmp( url, "https://", 8 ) )
				return( CRYPT_ERRTYPE_ATTR_VALUE );
			break;

		case URL_ANY:
			if( strnicmp( url, "http://", 7 ) && \
				strnicmp( url, "https://", 8 ) && \
				strnicmp( url, "ftp://", 6 ) && \
				strnicmp( url, "ldap://", 7 ) && \
				strnicmp( url, "ldaps://", 8 ) && \
				strnicmp( url, "mailto:", 7 ) && \
				strnicmp( url, "icbmto://", 9 ) )
				/* Default = 47.63957'N, 122.12551'W */
				return( CRYPT_ERRTYPE_ATTR_VALUE );
		}

	/* Make sure the string follows the RFC 1738 rules for valid characters */
	while( *urlPtr )
		{
		int ch = *urlPtr++;

		if( !isgraph( ch ) || ch == '<' || ch == '>' || ch == '"' || \
			ch == '{' || ch == '}' || ch == '|' || ch == '\\' || \
			ch == '^' || ch == '[' || ch == ']' || ch == '`' || ch == '*' )
			return( CRYPT_ERRTYPE_ATTR_VALUE );
		}

	return( CRYPT_OK );
	}

static int checkRFC822( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							( char * ) attributeListPtr->smallData : \
							( char * ) attributeListPtr->data, URL_RFC822 ) );
	}

static int checkDNS( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							( char * ) attributeListPtr->smallData : \
							( char * ) attributeListPtr->data, URL_DNS ) );
	}

static int checkURL( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							( char * ) attributeListPtr->smallData : \
							( char * ) attributeListPtr->data, URL_ANY ) );
	}

static int checkHTTP( const ATTRIBUTE_LIST *attributeListPtr )
	{
	return( checkURLString( ( attributeListPtr->dataLength <= CRYPT_MAX_TEXTSIZE ) ? \
							( char * ) attributeListPtr->smallData : \
							( char * ) attributeListPtr->data, URL_HTTP ) );
	}

/* Determine whether a DN (either a complete DN or a DN subtree) are valid.
   Most attribute fields require a full DN, but some fields (which act as
   filters) are allowed a partial DN */

static int checkDirectoryName( const ATTRIBUTE_LIST *attributeListPtr )
	{
	CRYPT_ATTRIBUTE_TYPE dummy;
	const BOOLEAN checkFullDN = \
			( attributeListPtr->fieldID == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
			  attributeListPtr->fieldID == CRYPT_CERTINFO_PERMITTEDSUBTREES ) ? \
			FALSE : TRUE;
	CRYPT_ERRTYPE_TYPE errorType;

	if( cryptStatusError( checkDN( attributeListPtr->data, checkFullDN, TRUE,
								   &dummy, &errorType ) ) )
		return( errorType );
	return( CRYPT_OK );
	}
