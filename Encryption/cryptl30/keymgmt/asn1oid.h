/****************************************************************************
*																			*
*				ASN.1 Object Identifier Structures and Prototypes 			*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _ASN1OID_DEFINED

#define _ASN1OID_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* The cryptlib (strictly speaking DDS) OID arc is as follows:

	1 3 6 1 4 1 3029 = dds
					 1 = algorithm
					   1 = symmetric encryption
						 1 = blowfishECB
						 2 = blowfishCBC
						 3 = blowfishCFB
						 4 = blowfishOFB
					   2 = public-key encryption
						 1 = elgamal
						   1 = elgamalWithSHA-1
						   2 = elgamalWithRIPEMD-160
					   3 = hash
					 2 = mechanism
					 3 = attribute
					 4 = content-type
					   1 = cryptlibConfigData */

/* The maximum (encoded) object identifier size */

#define MAX_OID_SIZE		20

/* A macro to make make declaring OID's simpler */

#define MKOID( value )	( ( BYTE * ) value )

/* Data-type OIDs which are used in various places */

#define OID_CMS_DATA			MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x01" )
#define OID_CMS_SIGNEDDATA		MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x02" )
#define OID_CMS_ENVELOPEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x03" )
#define OID_CMS_DIGESTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x05" )
#define OID_CMS_ENCRYPTEDDATA	MKOID( "\x06\x09\x2A\x86\x48\x86\xF7\x0D\x01\x07\x06" )
#define OID_CMS_AUTHDATA		MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x02" )
#define OID_CMS_COMPRESSEDDATA	MKOID( "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x01\x07" )
#define OID_CRYPTLIB_CONFIGDATA	MKOID( "\x06\x09\x2B\x06\x01\x04\x01\x97\x55\x04\x01" )
#define OID_NS_CERTSEQ			MKOID( "\x06\x09\x60\x86\x48\x01\x86\xF8\x42\x02\x05" )
#define OID_PKCS15_CONTENTTYPE	MKOID( "\x06\x0A\x2A\x86\x48\x86\xF7\x0D\x01\x0F\x03\x01" )

/* AlgorithmIdentifiers which are used in various places.  The Fortezza key 
   wrap one is keyExchangeAlgorithm { fortezzaWrap80Algorithm } */

#define ALGOID_CMS_ZLIB			MKOID( "\x30\x0F" \
									   "\x06\x0B\x2A\x86\x48\x86\xF7\x0D\x01\x09\x10\x03\x08" \
									   "\x05\x00" )
#define ALGOID_FORTEZZA_KEYWRAP	MKOID( "\x30\x18" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x16" \
									   "\x30\x0B" \
									   "\x06\x09\x60\x86\x48\x01\x65\x02\x01\x01\x17" )

/* The structure which is used to look up OIDs when reading a CMS header.  We
   step through an array of these checking each OID in turn, when we find a
   match we return the selection value */

typedef struct {
	const BYTE *oid;		/* OID */
	const int minVersion;	/* Minimum version number for content type */
	const int maxVersion;	/* Maximum version number for content type */
	const int selection;	/* Value to return for this OID */
	} OID_SELECTION;

/* AlgorithmIdentifier routines */

BOOLEAN checkAlgoID( const CRYPT_ALGO algorithm, const CRYPT_MODE mode );
int sizeofAlgoID( const CRYPT_ALGO algorithm );
int sizeofAlgoIDex( const CRYPT_ALGO algorithm, const CRYPT_ALGO subAlgorithm,
					const int extraLength );
int writeAlgoID( STREAM *stream, const CRYPT_ALGO algorithm );
int writeAlgoIDex( STREAM *stream, const CRYPT_ALGO algorithm,
				   const CRYPT_ALGO subAlgorithm, const int extraLength );
int readAlgoID( STREAM *stream, CRYPT_ALGO *cryptAlgo );
int readAlgoIDex( STREAM *stream, CRYPT_ALGO *cryptAlgo, 
				  CRYPT_ALGO *cryptSubAlgo, int *extraLength );

/* Alternative versions which read/write basic algorithm ID's (algo and mode
   only) from encryption contexts */

int sizeofContextAlgoID( const CRYPT_CONTEXT iCryptContext,
						 const CRYPT_ALGO subAlgorithm );
int writeContextAlgoID( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
						const CRYPT_ALGO subAlgorithm );
int readContextAlgoID( STREAM *stream, CRYPT_CONTEXT *iCryptContext );

/* Another variant which handles full AlgorithmIdentifiers with all 
   parameters */

int writeContextCryptAlgoID( STREAM *stream, 
							 const CRYPT_CONTEXT iCryptContext );
int readCryptAlgoID( STREAM *stream, CRYPT_ALGO *algorithm, CRYPT_MODE *mode, 
					 BYTE *iv, int *ivSize );

/* Read/write general-purpose OIDs */

int readOID( STREAM *stream, const BYTE *oid );

/* Read/write CMS headers */

int readCMSheader( STREAM *stream, const OID_SELECTION *oidSelection,
				   long *dataSize );
void writeCMSheader( STREAM *stream, const BYTE *oid, const long dataSize );
int sizeofCMSencrHeader( const BYTE *contentOID, const long dataSize,
						 const CRYPT_CONTEXT iCryptContext );
int readCMSencrHeader( STREAM *stream, const OID_SELECTION *oidSelection,
					   long *dataSize, CRYPT_ALGO *algorithm,
					   CRYPT_MODE *mode, BYTE *iv, int *ivSize );
int writeCMSencrHeader( STREAM *stream, const BYTE *contentOID,
						const long dataSize,
						const CRYPT_CONTEXT iCryptContext );

#endif /* _ASN1OID_DEFINED */
