/****************************************************************************
*																			*
*							  PGP Support Routines							*
*						Copyright Peter Gutmann 1992-1997					*
*																			*
****************************************************************************/

#include <stdlib.h>
#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "stream.h"
  #include "pgp.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "../keymgmt/stream.h"
  #include "pgp.h"
#else
  #include "crypt.h"
  #include "keymgmt/stream.h"
  #include "envelope/pgp.h"
#endif /* Compiler-specific includes */

/****************************************************************************
*																			*
*							PGP Data Packet Read Routines					*
*																			*
****************************************************************************/

/* Routines to read BYTE, WORD, LONG */

#define fgetByte( stream )	( ( BYTE ) sgetc( stream ) )

static WORD fgetWord( STREAM *stream )
	{
	WORD value;

	value = ( ( WORD ) sgetc( stream ) ) << 8;
	value |= ( WORD ) sgetc( stream );
	return( value );
	}

static LONG fgetLong( STREAM *stream )
	{
	LONG value;

	value = ( ( LONG ) sgetc( stream ) ) << 24;
	value |= ( ( LONG ) sgetc( stream ) ) << 16;
	value |= ( ( LONG ) sgetc( stream ) ) << 8;
	value |= ( LONG ) sgetc( stream );
	return( value );
	}

/* Get the length of a packet based on the CTB length field */

long pgpGetLength( STREAM *stream, const int ctb )
	{
#ifdef __TANDEM__
	long temp;
#endif /* __TANDEM__ */

	switch( ctb & 3 )
		{
		case 0:
			return( ( long ) fgetByte( stream ) );

		case 1:
#ifdef __TANDEM__
			temp = ( LONG ) fgetWord( stream );
			return( temp );
#else
			return( ( long ) fgetWord( stream ) );
#endif /* __TANDEM__ */

		case 2:
			return( fgetLong( stream ) );
		}

	/* The innermost packet has a length value of 3 to indicate that the
	   data length is determined externally (eg from the length field of the
	   containing packet) */
	return( 0 );
	}

/* Read a multiprecision integer value, returns the number of bits read */

int pgpReadMPI( STREAM *stream, BYTE *mpReg )
	{
	int bitLength, length;

	bitLength = fgetWord( stream );
	if( ( length = bitsToBytes( bitLength ) ) > PGP_MAX_MPISIZE )
		return( CRYPT_ERROR );
	if( sread( stream, mpReg, length ) != CRYPT_OK )
		return( CRYPT_ERROR );

	return( bitLength );
	}

/****************************************************************************
*																			*
*							Misc. PGP-related Routines						*
*																			*
****************************************************************************/

/* Checksum an MPI */

WORD pgpChecksumMPI( BYTE *data, int length )
	{
	WORD checkSum = ( ( BYTE ) ( length >> 8 ) ) + ( ( BYTE ) length );

	length = bitsToBytes( length );
	while( length-- )
		checkSum += *data++;
	return( checkSum );
	}

/* Create an encryption key from a password */

int pgpPasswordToKey( CRYPT_CONTEXT iCryptContext, const char *password,
					  const int passwordLength )
	{
	HASHFUNCTION hashFunction;
	RESOURCE_DATA msgData;
	BYTE hashedKey[ PGP_IDEA_KEYSIZE ];
	int hashSize, status;

	/* Get the hash algorithm information and hash the password */
	getHashParameters( CRYPT_ALGO_MD5, &hashFunction, &hashSize );
	hashFunction( NULL, hashedKey, ( BYTE * ) password, passwordLength, 
				  HASH_ALL );

	/* Load the key into the context */
	setResourceData( &msgData, hashedKey, PGP_IDEA_KEYSIZE );
	status = krnlSendMessage( iCryptContext, RESOURCE_IMESSAGE_SETATTRIBUTE_S, 
							  &msgData, CRYPT_CTXINFO_KEY );
	zeroise( hashedKey, PGP_IDEA_KEYSIZE );

	return( status );
	}

/* Query a PGP public-key related object and leave the stream pointing to
   the start of the PKC-related field */

int pgpQueryObject( STREAM *stream, BYTE *keyID, const int ctb )
	{
	int extraLength, data = fgetByte( stream );

	/* Check that we know what to do with this packet */
	if( data != PGP_VERSION_2 && data != PGP_VERSION_3 )
		return( CRYPT_ERROR_BADDATA );

	/* If it's a PKC-encrypted session key, read the key ID and return */
	if( ctb == PGP_CTB_PKE )
		{
		sread( stream, keyID, PGP_KEYID_SIZE );
		if( fgetByte( stream ) != PGP_ALGO_RSA )
			return( CRYPT_ERROR_BADDATA );
		return( CRYPT_OK );
		}

	/* Signature packets are a bit more complex.  First, we need to find out
	   how many bytes of extra data are present (5 mitout der validity
	   period, 7 mit der validity period) */
	extraLength = fgetByte( stream );
	if( extraLength != 5 && extraLength != 7 )
		return( CRYPT_ERROR_BADDATA );

	/* Read the signature type, timestamp, and optional validity period */
	data = fgetByte( stream );
	if( data != PGP_SIG_BINDATA && data != PGP_SIG_TEXT )
		return( CRYPT_ERROR_BADDATA );
	fgetLong( stream );			/* Skip signing time */
	if( extraLength == 7 )
		fgetWord( stream );		/* Skip validity period */

	/* Read the keyID and check the algorithm ID's */
	sread( stream, keyID, PGP_KEYID_SIZE );
	if( fgetByte( stream ) != PGP_ALGO_RSA || \
		fgetByte( stream ) != PGP_ALGO_MD5 )
		return( CRYPT_ERROR_BADDATA );

	/* Skip the message digest check bytes.  Since there's 18 bytes of ASN.1
	   and large amounts of PKCS #1 formatting and padding inside the
	   message, it's unlikely that an extra 2 bytes of check value are going
	   to help much */
	fgetWord( stream );

	return( CRYPT_OK );
	}

/* Check a PGP signature */

int pgpCheckSignature( STREAM *stream, const CRYPT_CONTEXT iPkcContext,
					   const CRYPT_CONTEXT iHashContext )
	{
	UNUSED( stream );
	if( iPkcContext );
	if( iHashContext );

	return( CRYPT_OK );
	}
