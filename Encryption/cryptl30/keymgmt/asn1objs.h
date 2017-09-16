/****************************************************************************
*																			*
*					  ASN.1 Data Object Management Routines					*
*						Copyright Peter Gutmann 1992-1999					*
*																			*
****************************************************************************/

#ifndef _ASN1OBJS_DEFINED

#define _ASN1OBJS_DEFINED

#ifndef _STREAM_DEFINED
  #if defined( INC_ALL ) ||  defined( INC_CHILD )
	#include "stream.h"
  #else
	#include "keymgmt/stream.h"
  #endif /* Compiler-specific includes */
#endif /* _STREAM_DEFINED */

/* Read/write a message digest */

int sizeofMessageDigest( const CRYPT_ALGO hashAlgo, const int hashSize );
int writeMessageDigest( STREAM *stream, const CRYPT_ALGO hashAlgo, 
						const void *hash, const int hashSize );
int readMessageDigest( STREAM *stream, CRYPT_ALGO *hashAlgo, void *hash, 
					   int *hashSize );

/* Read/write various CMS RecipientInfo's */

int writeKeyTransInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
					   const BYTE *buffer, const int length,
					   const void *auxInfo, const int auxInfoLength,
					   const RECIPIENT_TYPE recipientType );
int readKeyTransInfo( STREAM *stream, QUERY_INFO *queryInfo );
int writeKEKInfo( STREAM *stream, const CRYPT_CONTEXT iExportContext,
				  const BYTE *encryptedKey, const int encryptedKeyLength );
int readKEKInfo( STREAM *stream, QUERY_INFO *queryInfo, void *iv,
				 int *ivSize );
int writeKeyAgreeInfo( STREAM *stream, const CRYPT_CONTEXT iCryptContext,
					   const void *wrappedKey, const int wrappedKeyLength,
					   const void *ukm, const int ukmLength,
					   const void *auxInfo, const int auxInfoLength );
int readKeyAgreeInfo( STREAM *stream, QUERY_INFO *queryInfo,
					  CRYPT_CONTEXT *iKeyAgreeContext );

/* Read/write signatures */

int writeSignature( STREAM *stream, const CRYPT_CONTEXT iSignContext,
					const CRYPT_ALGO hashAlgo, const BYTE *signature,
					const int signatureLength, 
					const SIGNATURE_TYPE signatureType );
int readSignature( STREAM *stream, QUERY_INFO *queryInfo,
				   const SIGNATURE_TYPE signatureType );

/* Most of the time when we're reading a public key we just convert the data
   in an X.509 SubjectPublicKeyInfo into a context, however sometimes we need
   to defer the load until we've read separate private-key components, or the
   public key is stored in something other than an SPKI.  The following 
   values passed to readPublicKey() will change its behaviour to handle 
   various special cases */

typedef enum { 
	READKEY_OPTION_NONE,		/* Create public-key context from SPKI */
	READKEY_OPTION_DEFERREDLOAD,/* Defer the key load until later */
	READKEY_OPTION_LAST			/* Last possible option type */
	} READKEY_OPTION_TYPE;

/* Read public keys in the X.509 SubjectPublicKeyInfo format */

int readPublicKey( STREAM *stream, CRYPT_CONTEXT *iCryptContext,
				   const READKEY_OPTION_TYPE option );

/* Get information on exported key or signature data */

int queryObject( STREAM *stream, QUERY_INFO *queryInfo );

#endif /* _ASN1OBJS_DEFINED */
