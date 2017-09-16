/****************************************************************************
*																			*
*				Certificate Management Structures and Prototypes 			*
*						Copyright Peter Gutmann 1996-1999					*
*																			*
****************************************************************************/

#ifndef _CERT_DEFINED

#define _CERT_DEFINED

#include <time.h>
#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) || defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The character set (or at least ASN.1 string type) for a string.  Sometimes
   we can be fed Unicode strings which are just bloated versions of another
   string type, so we need to account for these as well.  In addition we may
   have an 8859-1 string which can't be encoded in the given type, so we mark
   it as needing conversion to Unicode.  Note that the value for the Unicode
   variant of the basic type must follow the value for the base type since
   the conversion code uses this relationship when reporting the string type.

   Although IA5String and VisibleString/ISO646String are technically
   different, the only real difference is that IA5String allows the full
   range of control characters, which isn't notably useful.  For this reason
   we treat both as ISO646String.

   UTF-8 strings are a pain because they're not supported as any native
   format and aren't needed because almost anything they can do is covered by
   a more sensible character set.  For this reason we currently convert them
   to a more sensible set (ASCII, 8859-1, or Unicode as appropriate) to make
   them usable.  UTF-8 strings are never written */

typedef enum {
	STRINGTYPE_NONE,				/* No string type */
	STRINGTYPE_PRINTABLE,			/* PrintableString */
	STRINGTYPE_UNICODE_PRINTABLE,	/* PrintableString as Unicode */
	STRINGTYPE_IA5,					/* IA5String */
		STRINGTYPE_VISIBLE = STRINGTYPE_IA5,	/* VisibleString */
	STRINGTYPE_UNICODE_IA5,			/* IA5String as Unicode */
		STRINGTYPE_UNICODE_VISIBLE = STRINGTYPE_UNICODE_IA5,
									/* VisibleString as Unicode */
	STRINGTYPE_T61,					/* T61 (8859-1) string */
	STRINGTYPE_UNICODE_T61,			/* T61String as Unicode */
	STRINGTYPE_UNICODE,				/* Unicode string */
	STRINGTYPE_T61_UNICODE,			/* Unicode as T61 string */
	STRINGTYPE_UTF8					/* UTF-8 string (never written) */
	} ASN1_STRINGTYPE;

/* The minimum size of an attribute, SEQUENCE (2), OID (5),
   OCTET STRING (2+3 for payload).  This is the amount of slop to allow when
   reading attributes.  Some software gets the length encoding wrong by a few
   bytes, if what's left at the end of an encoded object is >= this value
   then we look for attributes */

#define MIN_ATTRIBUTE_SIZE		12

/* The maximum size of a PKCS #7 certificate chain */

#define MAX_CHAINLENGTH			16

/****************************************************************************
*																			*
*							Certificate Data Structures						*
*																			*
****************************************************************************/

/* The structure to hold a DN component */

typedef struct DC {
	/* The next and previous list element in the linked list of DN
	   components */
	struct DC *next, *prev;

	/* DN component type and type information */
	CRYPT_ATTRIBUTE_TYPE type;		/* cryptlib component type */
	ASN1_STRINGTYPE stringType;		/* Component string data type */
	const void *typeInfo;			/* Type info for this component */

	/* Some implementations may place more than one AVA into a RDN.  In this
	   case we set a flag to indicate that the RDN continues in the next DN
	   component structure */
	BOOLEAN isContinued;

	/* DN component data.  We use fixed buffers rather than allocating new
	   memory blocks for the value data because it's very short and not worth
	   the overhead of calling malloc for each tiny block */
	BYTE value[ CRYPT_MAX_TEXTSIZE * 2 ];
	int valueLength;				/* The value of this component */

	/* Encoding information: The overall size of the RDN data (without the
	   tag and length) if this is the first or only component of an RDN, and
	   the size of the AVA data */
	int encodedRDNdataSize, encodedAVAdataSize;
	} DN_COMPONENT;

/* The structure to hold a field of a certificate attribute */

typedef struct AL {
	/* Identification and encoding information for this attribute field or
	   attribute.  This consists of the field ID for the attribute as a
	   whole, for the attribute field (that is, a field of an attribute, not
	   an attribute field) and for the subfield of the attribute field in the
	   case of composite fields like GeneralName's, a pointer to the sync
	   point used when encoding the attribute, and the encoded size of this
	   field.  If it's a special-case attribute field, the attributeID and
	   fieldID are set to special values decoded by the isXXX() macros
	   further down.  The subFieldID is only set if the fieldID is for a
	   GeneralName field

	   Although the field type information is contained in the
	   attributeInfoPtr, it's sometimes needed before this has been set up
	   to handle special formatting requirements (for example to enable
	   special-case handling for a DN attribute field or to specify that an
	   OID needs to be decoded into its string representation before being
	   returned to the caller).  Because of this we store the field type here
	   to allow for this special processing */
	CRYPT_ATTRIBUTE_TYPE attributeID;/* Attribute ID */
	CRYPT_ATTRIBUTE_TYPE fieldID;	/* Attribute field ID */
	CRYPT_ATTRIBUTE_TYPE subFieldID;	/* Attribute subfield ID */
	void *attributeInfoPtr;			/* Pointer to encoding sync point */
	int encodedSize;				/* Encoded size of this field */
	int fieldType;					/* Attribute field type */

	/* Sometimes a field is part of a constructed object, or even a nested
	   series of constructed objects (these are always SEQUENCEs).  Since
	   this purely an encoding issue, there are no attribute list entries for
	   the SEQUENCE fields, so when we perform the first pass over the
	   attribute list prior to encoding we remember the lengths of the
	   SEQUENCES for later use.  Since we can have nested SEQUENCEs
	   containing a given field, we store the lengths and pointers to the
	   table entries used to encode them in a fifo, with the innermost one
	   first and successive outer ones following it */
	int sizeFifo[ 10 ];				/* Encoded size of SEQUENCE containing
									   this field, if present */
	void *encodingFifo[ 10 ];		/* Encoding table entry used to encode
									   this SEQUENCE */
	int fifoEnd;					/* End of list of SEQUENCE sizes */
	int fifoPos;					/* Current position in list */

	/* Whether the attribute is marked critical if it's a cert extension.
	   All fields in a critical extension are regarded as being critical */
	BOOLEAN isCritical;

	/* If a field has a value which is identical to a default value for the
	   field, it doesn't get encoded.  The following flag records whether
	   this field has a default value, and is set by the preprocessing pass */
	BOOLEAN isDefaultValue;

	/* The data payload for this attribute field or attribute.  If it's an
	   attribute field and the data is a simple boolean, bitstring, or small
	   integer, we store it in the value member.  If it's an OID or some form
	   of string which will fit into a small buffer we store it in the
	   smallData buffer (most attributes fall into this category).  If it's a
	   longer string or a blob-type attribute, we store it in a dynamically-
	   allocated buffer */
	long value;						/* Value for simple types */
	BYTE smallData[ CRYPT_MAX_TEXTSIZE ];
	void *data;						/* Attribute data payload */
	int dataLength;					/* Value for short objects */

	/* The OID for blob-type attributes */
	BYTE oid[ CRYPT_MAX_TEXTSIZE ];

	/* The next and previous list element in the linked list of elements */
	struct AL *next, *prev;
	} ATTRIBUTE_LIST;

/* The structure to hold the current volatile state of a certificate object:
   which certificate in a chain is selected, and which GeneralName/DN is
   selected */

typedef struct {
	int savedCertChainPos;			/* Current cert.chain position */
	CRYPT_ATTRIBUTE_TYPE savedCurrentGeneralName;	/* Current GN */
	CRYPT_ATTRIBUTE_TYPE savedCurrentDN;	/* Current DN */
	DN_COMPONENT **savedCurrentDNptr;		/* Pointer to DN start */
	} SELECTION_STATE;

/* The structure to hold a CRL entry */

typedef struct CE {
	/* Certificate ID information */
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */
	BYTE issuerID[ CRYPT_MAX_HASHSIZE ];	/* Cert issuerID */

	/* Revocation information */
	time_t revocationTime;			/* Cert revocation time */

	/* Per-entry attributes.  These are a rather ugly special case for the
	   user because, unlike the attributes for all other cert objects where
	   cryptlib can provide the illusion of a flat type<->value mapping,
	   there can be multiple sets of identical per-entry attributes present
	   if there are multiple CRL entries present */
	ATTRIBUTE_LIST *attributes;		/* CRL entry attributes */
	int attributeSize;				/* Encoded size of attributes */

	/* The next element in the linked list of elements */
	struct CE *next;
	} CRL_ENTRY;

/* The structure which stores information on a certificate object */

typedef struct RI {
	/* The type of this certificate object */
	CRYPT_CERTTYPE_TYPE type;

	/* The encoded certificate object.  We save this when we import it
	   because there are many different interpretations of how a cert should
	   be encoded and if we parse and re-encode the cert object, the
	   signature check may fail */
	void *certificate;
	int certificateSize;

	/* The encryption context containing the key stored in this certificate */
	CRYPT_CONTEXT iCryptContext;

	/* Certificate status information.  We cache the check of the cert
	   encoding since it's only necessary to perform this once when the cert
	   is imported or checked for the first time */
	BOOLEAN selfSigned;				/* Whether certificate is self-signed */
	BOOLEAN encodingChecked;		/* Whether cert.encoding is checked */

	/* Some certificates are data-only certificates.  These constitute a
	   container object which contains certificate-related data but no key
	   information or copy of the encoded certificate, and are used for cert
	   chain validation and to store cert information in a private-key
	   context.  The publicKeyInfo field contains a pointer to the start of 
	   the encoded public key info in the stored encoded certificate.  This 
	   is used where it's not known yet during the import stage whether the 
	   cert will be a data-only or standard cert (this happens when importing 
	   cert chains, when it's not known until the entire chain has been 
	   processed which cert is the leaf cert) */
	BOOLEAN dataOnly;				/* Whether cert is data-only */
	void *publicKeyInfo;			/* Public key information */

	/* Some certificates are complex container objects which contain further
	   certificates leading up to a CA root cert.  These composite certs are
	   imported from or written to PKCS #7 cert chains.  In theory we should
	   use a linked list to store chains, but since the longest chain ever
	   seen in the wild has a length of 3, using a fixed maximum length
	   shouldn't be a problem.

	   The certs in the chain are ordered from the parent of the leaf cert up
	   to the root cert, with the leaf cert corresponding to the [-1]th entry
	   in the list.  We also maintain a current position in the cert chain
	   which denotes the cert in the chain which will be accessed by the
	   component-manipulation functions.  This is set to CRYPT_ERROR if the
	   current cert is the leaf cert */
	CRYPT_CERTIFICATE certChain[ MAX_CHAINLENGTH ];
	int certChainEnd;				/* Length of cert chain */
	int certChainPos;				/* Currently selected cert in chain */

	/* General certificate/CRL/cert request information */
	void *serialNumber;
	int serialNumberLength;			/* Certificate serial number */
	time_t startTime;				/* Validity start or update time */
	time_t endTime;					/* Validity end or next update time */
	void *issuerUniqueID, *subjectUniqueID;
	int issuerUniqueIDlength, subjectUniqueIDlength;
									/* Certificate serial number */
	/* Name fields */
	DN_COMPONENT *issuerName;		/* Issuer name */
	DN_COMPONENT *subjectName;		/* Subject name */

	/* In theory we can just copy the subject DN of a CA cert into the issuer
	   DN of a subject cert, however due to broken implementations this will
	   break chaining if we correct any problems in the DN.  Because of this
	   we need to preserve a copy of the certs subject DN so we can write it
	   as a blob to the issuer DN field of any certs it signs.  We also need
	   to remember the encoded issuer DN so we can chain upwards.

	   The following fields identify the size and location of the encoded DNs
	   inside the encoded certificate object */
	void *subjectDNptr, *issuerDNptr;	/* Pointer to encoded DN blobs */
	int subjectDNsize, issuerDNsize;	/* Size of encoded DN blobs */

	/* For chaining we may also need to use key identifiers, unfortunately
	   this rarely works as intended because most certs don't contain key
	   identifiers or contain them in some peculiar form which isn't useful
	   or in an incorrect form.  This isn't helped by the fact that the
	   subject and authority key identifiers have different forms and can't
	   be compared by matching the encoded blobs.  For this reason we only
	   try to chain on key identifiers if chaining on names fails */
	void *subjectKeyIDptr, *issuerKeyIDptr;	/* Pointer to encoded key ID blobs */
	int subjectKeyIDsize, issuerKeyIDsize;	/* Size of encoded key ID blobs */

	/* The list of revocations for a CRL and a pointer to the revocation
	   which is currently being accessed */
	CRL_ENTRY *revocations;
	CRL_ENTRY *currentRevocation;

	/* The default revocation time for a CRL which is used for revocations if
	   no explicit time is set for them */
	time_t revocationTime;			/* Cert revocation time */

	/* Certificate object attributes are stored in two ways, as the native
	   field types for the attributes we recognise (or at least for the ones
	   we care about), and as a list of encoded blobs for the rest.

	   When we generate a certificate, we generate a v1 cert if no attributes
	   are present and a v3 cert if either an attribute field is set or an
	   attribute list is present.  The same goes for CRL's, where we use a v1
	   or v2 CRL as required */
	ATTRIBUTE_LIST *attributes;		/* Certificate object attributes */

	/* The cursor into the attribute list.  This can be moved by the user on
	   a per-attribute, per-field, and per-component basis.  We also remember
	   whether there's been an attempt to set the attribute cursor so that
	   we can differentiate between the case where the cursor is NULL because
	   no attempt was made to set it, or because there are no attributes
	   present */
	ATTRIBUTE_LIST *attributeCursor;

	/* The currently selected GeneralName and DN and DN pointer.  A cert can
	   contain multiple GeneralName's and DN's which can be selected by their
	   field types, after which adding DN components will affected the
	   selected DN.  This value contains the currently selected GeneralName
	   and DN, and a pointer to the DN data if it exists (when creating a new
	   DN, the pointer will be null after it's selected since it won't be
	   instantiated until data is added to it in later calls) */
	CRYPT_ATTRIBUTE_TYPE currentGeneralName;
	CRYPT_ATTRIBUTE_TYPE currentDN;
	DN_COMPONENT **currentDNptr;

	/* The allowed usage for a certificate can be further controlled by the 
	   user.  The trustedUsage value is a mask which is applied to the key 
	   usage extension to further constrain usage, alongside this there is an
	   additional implicit trustImplicit value which acts a boolean flag 
	   which indicates whether the user implicitly trusts this certificate 
	   (without requiring further checking upstream).  This value isn't 
	   stored with the cert since it's a property of any instantiation of the 
	   cert rather than just the current one, so when the user queries it 
	   it's obtained dynamically from the trust manager */
	int trustedUsage;

	/* Save area for the currently selected GeneralName and DN, and position
	   in the cert chain.  The current values are saved to this area when the
	   object receives a lock object message, and restored when the object
	   receives the corresponding unlock message.  This guarantees that any
	   changes made during processing while the cert is locked don't get 
	   reflected back to external users */
	SELECTION_STATE selectionState;

	/* Error information */
	CRYPT_ATTRIBUTE_TYPE errorLocus;/* Error locus */
	CRYPT_ERRTYPE_TYPE errorType;	/* Error type */

	/* When we clone an object, there are certain per-instance fields which
	   don't get cloned.  These fields are located after the following
	   member, and must be initialised by the cloning function */
	int _sharedEnd;					/* Dummy used for end of shared fields */

	/* The object's handle, used when sending messages to the object when 
	   only the xxx_INFO is available */
	CRYPT_HANDLE objectHandle;

	/* In multithreaded environments we need to protect the information from
	   access by other threads while we use it.  The following macro declares
	   the actual variables required to handle the object locking (the actual 
	   values are defined in cryptos.h) */
	DECLARE_OBJECT_LOCKING_VARS
	} CERT_INFO;

/* Determine whether an attribute list item is a dummy entry which denotes
   either that this field isn't present in the list but has a default value
   or that this field isn't present in the list but represents an entire
   (constructed) attribute, or whether it contains a single blob-type
   attribute */

#define isDefaultFieldValue( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == CRYPT_ERROR && \
		  ( attributeListPtr )->attributeID == 0 )
#define isCompleteAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == CRYPT_ERROR )
#define isBlobAttribute( attributeListPtr ) \
		( ( attributeListPtr )->fieldID == 0 && \
		  ( attributeListPtr )->attributeID == 0 )

/* Determine whether a component which is being added to a cert is a special-
   case DN selection component which selects the current DN without changing
   the cert itself, a GeneralName selection component, an attribute cursor
   movement component, or a general control information component */

#define isDNSelectionComponent( certInfoType ) \
	( certInfoType == CRYPT_CERTINFO_ISSUERNAME || \
	  certInfoType == CRYPT_CERTINFO_SUBJECTNAME || \
	  certInfoType == CRYPT_CERTINFO_DIRECTORYNAME )

#define isGeneralNameSelectionComponent( certInfoType ) \
	( certInfoType == CRYPT_CERTINFO_AUTHORITYINFO_OCSP || \
	  certInfoType == CRYPT_CERTINFO_AUTHORITYINFO_CAISSUERS || \
	  certInfoType == CRYPT_CERTINFO_SIGG_PROCURE_SIGNINGFOR || \
	  certInfoType == CRYPT_CERTINFO_SUBJECTALTNAME || \
	  certInfoType == CRYPT_CERTINFO_ISSUERALTNAME || \
	  certInfoType == CRYPT_CERTINFO_ISSUINGDIST_FULLNAME || \
	  certInfoType == CRYPT_CERTINFO_CERTIFICATEISSUER || \
	  certInfoType == CRYPT_CERTINFO_PERMITTEDSUBTREES || \
	  certInfoType == CRYPT_CERTINFO_EXCLUDEDSUBTREES || \
	  certInfoType == CRYPT_CERTINFO_CRLDIST_FULLNAME || \
	  certInfoType == CRYPT_CERTINFO_CRLDIST_CRLISSUER || \
	  certInfoType == CRYPT_CERTINFO_AUTHORITY_CERTISSUER )

#define isCursorComponent( certInfoType ) \
	( certInfoType == CRYPT_CERTINFO_CURRENT_CERTIFICATE || \
	  certInfoType == CRYPT_CERTINFO_CURRENT_EXTENSION || \
	  certInfoType == CRYPT_CERTINFO_CURRENT_FIELD || \
	  certInfoType == CRYPT_CERTINFO_CURRENT_COMPONENT )

#define isControlComponent( certInfoType ) \
	( certInfoType == CRYPT_CERTINFO_TRUSTED_USAGE || \
	  certInfoType == CRYPT_CERTINFO_TRUSTED_IMPLICIT )

/* Determine whether a component which is being added is a DN or GeneralName
   component */

#define isDNComponent( certInfoType ) \
	( certInfoType >= CRYPT_FIRST_DN && certInfoType <= CRYPT_LAST_DN )

#define isGeneralNameComponent( certInfoType ) \
	( certInfoType >= CRYPT_FIRST_GENERALNAME && \
	  certInfoType <= CRYPT_LAST_GENERALNAME )

/* Determine whether a component which is being added to a CRL is a standard
   CRL attribute or a per-entry attribute */

#define isCRLEntryComponent( certInfoType ) \
	( certInfoType == CRYPT_CERTINFO_CRLREASON || \
	  certInfoType == CRYPT_CERTINFO_HOLDINSTRUCTIONCODE || \
	  certInfoType == CRYPT_CERTINFO_INVALIDITYDATE )

/* Sometimes we need to manipulate an internal component which is addressed
   indirectly as a side-effect of some other processing operation.  We can't
   change the selection information since this will affect any future
   operations the user performs, so we provide the following macros to save
   and restore the selection state around these operations */

#define saveSelectionState( savedState, certInfoPtr ) \
	{ \
	( savedState ).savedCertChainPos = ( certInfoPtr )->certChainPos; \
	( savedState ).savedCurrentGeneralName = ( certInfoPtr )->currentGeneralName; \
	( savedState ).savedCurrentDN = ( certInfoPtr )->currentDN; \
	( savedState ).savedCurrentDNptr = ( certInfoPtr )->currentDNptr; \
	}

#define restoreSelectionState( savedState, certInfoPtr ) \
	{ \
	( certInfoPtr )->certChainPos = ( savedState ).savedCertChainPos; \
	( certInfoPtr )->currentGeneralName = ( savedState ).savedCurrentGeneralName; \
	( certInfoPtr )->currentDN = ( savedState ).savedCurrentDN; \
	( certInfoPtr )->currentDNptr = ( savedState ).savedCurrentDNptr; \
	}

/* The are several types of attributes which can be used depending on the
   object they're associated with.  The following values are used to select
   the type of attribute we want to work with */

typedef enum { ATTRIBUTE_CERTIFICATE, ATTRIBUTE_CMS } ATTRIBUTE_TYPE;

/****************************************************************************
*																			*
*							DN Manipulation Functions						*
*																			*
****************************************************************************/

/* Convert a string into a form suitable for ASN.1 encoding, and compare two
   ASN.1 strings using the rules for matching RDN string types */

ASN1_STRINGTYPE copyConvertString( const void *source, const int sourceLen,
								   void *dest, int *destLen, const int maxLen,
								   const BOOLEAN isSETString,
								   const BOOLEAN isASN1string );
BOOLEAN compareASN1string( const void *string1, const int string1len,
						   const void *string2, const int string2len );

/* DN manipulation routines */

DN_COMPONENT *findDNComponent( const DN_COMPONENT *listHead,
							   const CRYPT_ATTRIBUTE_TYPE type,
							   const void *value, const int valueLength );
int insertDNComponent( DN_COMPONENT **listHead,
					   const CRYPT_ATTRIBUTE_TYPE componentType,
					   const void *value, const int valueLength,
					   const ASN1_STRINGTYPE stringType,
					   const BOOLEAN isContinued, 
					   CRYPT_ERRTYPE_TYPE *errorType );
int deleteDNComponent( DN_COMPONENT **listHead,
					   const CRYPT_ATTRIBUTE_TYPE type, const void *value,
					   const int valueLength );
void deleteDN( DN_COMPONENT **dnComponentListHead );

/* Copy and compare a DN */

int copyDN( DN_COMPONENT **dest, const DN_COMPONENT *src );
BOOLEAN compareDN( const DN_COMPONENT *dnComponentListHead1,
				   const DN_COMPONENT *dnComponentListHead2,
				   const BOOLEAN dn1substring );

/* Read/write a DN */

int checkDN( const DN_COMPONENT *dnComponentListHead,
			 const BOOLEAN checkCN, const BOOLEAN checkC,
			 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
			 CRYPT_ERRTYPE_TYPE *errorType );
int sizeofDN( const DN_COMPONENT *dnComponentListHead );
int readDNTag( STREAM *stream, DN_COMPONENT **dnComponentListHead,
			   const int tag );
int writeDN( STREAM *stream, const DN_COMPONENT *dnComponentListHead,
			 const int tag );

#define readDNData( stream, dnComponentListHead )	\
		readDNTag( stream, dnComponentListHead, NO_TAG )
#define readDN( stream, dnComponentListHead )	\
		readDNTag( stream, dnComponentListHead, DEFAULT_TAG )

/****************************************************************************
*																			*
*						Attribute Manipulation Functions					*
*																			*
****************************************************************************/

/* Find information on an attribute */

ATTRIBUTE_LIST *findAttributeByOID( const ATTRIBUTE_LIST *listHead,
									const BYTE *oid );
ATTRIBUTE_LIST *findAttribute( const ATTRIBUTE_LIST *listHead,
							   const CRYPT_ATTRIBUTE_TYPE attributeID );
ATTRIBUTE_LIST *findAttributeField( const ATTRIBUTE_LIST *listHead,
									const CRYPT_ATTRIBUTE_TYPE fieldID,
									const CRYPT_ATTRIBUTE_TYPE subFieldID );
ATTRIBUTE_LIST *findAttributeFieldEx( const ATTRIBUTE_LIST *listHead,
									  const CRYPT_ATTRIBUTE_TYPE fieldID );
int getDefaultFieldValue( const CRYPT_ATTRIBUTE_TYPE fieldID );

/* Move the current attribute cursor */

int moveAttributeCursor( ATTRIBUTE_LIST **currentCursor,
						 const BOOLEAN moveByField, const int position );

/* Add/delete attributes/attribute fields */

int addAttribute( const ATTRIBUTE_TYPE attributeType,
				  ATTRIBUTE_LIST **listHeadPtr, const BYTE *oid,
				  const BOOLEAN critical, const void *data,
				  const int dataLength );
int addAttributeField( ATTRIBUTE_LIST **listHeadPtr,
					   const CRYPT_ATTRIBUTE_TYPE fieldID,
					   const CRYPT_ATTRIBUTE_TYPE subFieldID,
					   const void *data, const int dataLength,
					   const BOOLEAN criticalFlag, const BOOLEAN isBlob,
					   CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					   CRYPT_ERRTYPE_TYPE *errorType );
void deleteAttribute( ATTRIBUTE_LIST **listHeadPtr,
					  ATTRIBUTE_LIST **listCursorPtr,
					  ATTRIBUTE_LIST *listItem );
void deleteAttributeField( ATTRIBUTE_LIST **listHeadPtr,
						   ATTRIBUTE_LIST **listCursorPtr,
						   ATTRIBUTE_LIST *listItem );
void deleteAttributes( ATTRIBUTE_LIST **listHeadPtr );
int copyAttributes( ATTRIBUTE_LIST **destListHeadPtr,
					ATTRIBUTE_LIST *srcListPtr,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType );
int copyIssuerAttributes( ATTRIBUTE_LIST **destListHeadPtr,
						  const ATTRIBUTE_LIST *srcListPtr,
						  CRYPT_ATTRIBUTE_TYPE *errorLocus, 
						  CRYPT_ERRTYPE_TYPE *errorType,
						  const CRYPT_CERTTYPE_TYPE type );

/* Read/write a collection of attributes */

int checkAttributes( const ATTRIBUTE_TYPE attributeType,
					 const ATTRIBUTE_LIST *listHeadPtr,
					 CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					 CRYPT_ERRTYPE_TYPE *errorType );
int sizeofAttributes( const ATTRIBUTE_LIST *attributeListPtr );
int writeAttributes( STREAM *stream, ATTRIBUTE_LIST *attributeListPtr,
					 const CRYPT_CERTTYPE_TYPE type,
					 const int attributeSize );
int readAttributes( STREAM *stream, ATTRIBUTE_LIST **attributeListPtrPtr,
					const CRYPT_CERTTYPE_TYPE type, const int attributeSize,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType );

/****************************************************************************
*																			*
*							CRL Manipulation Functions						*
*																			*
****************************************************************************/

/* Add/delete a CRL entry */

int addCRLEntry( CRL_ENTRY **listHeadPtr, CRL_ENTRY **newEntryPosition,
				 const DN_COMPONENT *issuerDN, const void *serialNumber,
				 const int serialNumberLength );
void deleteCRLEntries( CRL_ENTRY **listHeadPtr );

/* Determine whether a cert has been revoked by this CRL */

int checkRevocation( const CERT_INFO *certInfoPtr, CERT_INFO *crlInfoPtr );

/****************************************************************************
*																			*
*								Certificate Functions						*
*																			*
****************************************************************************/

/* Create a locked certificate information object ready for further 
   initialisation */

int createCertificateInfo( CERT_INFO **certInfoPtrPtr, 
						   const CRYPT_CERTTYPE_TYPE certType );

/* Read a certificate object */

int readCertInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readAttributeCertInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readCertRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readCRMFRequestInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readCRLInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readCertChain( STREAM *stream, CRYPT_CERTIFICATE *iCryptCert,
				   const CRYPT_CERTTYPE_TYPE type, 
				   const CERTIMPORT_TYPE importType );
int readSPKACInfo( STREAM *stream, CERT_INFO *certInfoPtr );
int readCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr );

/* Write a certificate object */

int writeCertInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
				   const CERT_INFO *issuerCertInfoPtr,
				   const CRYPT_CONTEXT iIssuerCryptContext );
int writeAttributeCertInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
							const CERT_INFO *issuerCertInfoPtr,
							const CRYPT_CONTEXT iIssuerCryptContext );
int writeCertRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext );
int writeCRMFRequestInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
						  const CERT_INFO *issuerCertInfoPtr,
						  const CRYPT_CONTEXT iIssuerCryptContext );
int writeCRLInfo( STREAM *stream, CERT_INFO *subjectCertInfoPtr,
				  const CERT_INFO *issuerCertInfoPtr,
				  const CRYPT_CONTEXT iIssuerCryptContext );
int writeCertChain( STREAM *stream, const CERT_INFO *certInfoPtr );
int writeCMSAttributes( STREAM *stream, CERT_INFO *attributeInfoPtr );

/* Check a certificate object */

int checkEncoding( const void *certObjectPtr, const int length );
int checkCert( CERT_INFO *subjectCertInfoPtr,
			   const CERT_INFO *issuerCertInfoPtr );
int checkCertChain( CERT_INFO *certInfoPtr );

/* Check that a key cert is valid for a particular purpose */

int checkCertUsage( const CERT_INFO *certInfoPtr, const int keyUsage,
					CRYPT_ATTRIBUTE_TYPE *errorLocus, 
					CRYPT_ERRTYPE_TYPE *errorType );

/* Trust management */

int addTrustInfo( const CERT_INFO *certInfoPtr );
int deleteTrustInfo( const CERT_INFO *certInfoPtr );
BOOLEAN checkCertTrusted( const CERT_INFO *certInfoPtr );
CRYPT_CERTIFICATE findTrustedCert( const void *dn, const int dnSize );

/* Add/get/delete a certificate component */

int addCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  const void *certInfo, const int certInfoLength );
int getCertComponent( CERT_INFO *certInfoPtr,
					  const CRYPT_ATTRIBUTE_TYPE certInfoType,
					  void *certInfo, int *certInfoLength );
int deleteCertComponent( CERT_INFO *certInfoPtr,
						 const CRYPT_ATTRIBUTE_TYPE certInfoType );

/* Import/export a certificate */

int importCert( const void *certObject, const int certObjectLength,
				CRYPT_CERTIFICATE *certificate,
				const CERTIMPORT_TYPE importType, 
				const CERTFORMAT_TYPE formatType );
int exportCert( void *certObject, int *certObjectLength,
				const CRYPT_CERTFORMAT_TYPE certFormatType,
				const CERT_INFO *certInfoPtr );

/* Sign/sig check a certificate */

int signCert( CERT_INFO *certInfoPtr, const CRYPT_CONTEXT signContext );
int checkCertValidity( CERT_INFO *certInfoPtr, const CRYPT_HANDLE sigCheckKey );

/* Read/write an issuerAndSerialNumber */

int sizeofIssuerAndSerialNumber( const DN_COMPONENT *dn,
								 const void *serialNumber,
								 const int serialNumberLength );
int writeIssuerAndSerialNumber( STREAM *stream, const DN_COMPONENT *dn,
								const void *serialNumber,
								const int serialNumberLength );

/* Read/write a SET OF Certificate */

int sizeofCertSet( const CERT_INFO *certInfoPtr );
int writeCertSet( STREAM *stream, const CERT_INFO *certInfoPtr );

/* Oddball routines: generate a nameID or issuerID which uniquely identifies
   a certificate for X.509 or S/MIME purposes, copy a cert chain, assemble a
   cert chain from certs read from an object */

int generateCertID( const DN_COMPONENT *dn, const void *serialNumber,
					const int serialNumberLength, BYTE *certID );
int copyCertChain( CERT_INFO *certInfoPtr, const CRYPT_HANDLE certChain );
int assembleCertChain( CRYPT_CERTIFICATE *iCertificate,
					   const CRYPT_HANDLE iCertSource, 
					   const CRYPT_KEYID_TYPE keyIDtype,
					   const void *keyID, const int keyIDlength,
					   const CERTIMPORT_TYPE importType );

#endif /* _CERT_DEFINED */
