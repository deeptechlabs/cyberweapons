/****************************************************************************
*																			*
*							RC5 Encryption Algorithm 						*
*						  Copyright Peter Gutmann 1996						*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "rc5.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "rc5.h"
#else
  #include "crypt.h"
  #include "crypt/rc5.h"
#endif /* Compiler-specific includes */

/* The P32 and Q32 Mysterious Constants */

#define P32_MAGIC	0xB7E15163UL
#define Q32_MAGIC	0x9E3779B9UL

/* Left and right rotation operations.  Most decent compilers should be
   able to recognise these as rotate instructions */

#define ROTL(x,s)	( ( ( x ) << ( s ) ) | ( ( x ) >> ( 32 - ( s ) ) ) )
#define ROTR(x,s)	( ( ( x ) >> ( s ) ) | ( ( x ) << ( 32 - ( s ) ) ) )

/* The individual RC5 en/decryption rounds.  Note that the "& 0x1F" isn't
   necessary on a number of processors which mask off everything but the low
   5 bits of the rotate amount */

#define encryptRound(A,B,key) \
	A = MASK32( ROTL( A ^ B, B & 0x1F ) + *key++ ); \
	B = MASK32( ROTL( B ^ A, A & 0x1F ) + *key++ )

#define decryptRound(A,B,key) \
	B -= *--key; \
	B = ROTR( MASK32( B ), A & 0x1F ) ^ A; \
	A -= *--key; \
	A = ROTR( MASK32( A ), B & 0x1F ) ^ B

/* RC5 en/decryption routines */

void rc5encrypt( RC5_KEY *key, BYTE *data )
	{
	BYTE *dataPtr = data;
	LONG *keyPtr = key->S;
	LONG A, B;

	/* Copy the data buffer to the local variables */
	A = mgetLLong( dataPtr );
	B = mgetLLong( dataPtr );

	A = MASK32( A + *keyPtr++ );
	B = MASK32( B + *keyPtr++ );

	/* Perform the 12 rounds of encryption */
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );
	encryptRound( A, B, keyPtr );

	/* Copy the local variables back to the data buffer */
	dataPtr = data;
	mputLLong( dataPtr, A );
	mputLLong( dataPtr, B );
	}

void rc5decrypt( RC5_KEY *key, BYTE *data )
	{
	BYTE *dataPtr = data;
	LONG *keyPtr = key->S;
	LONG A, B;

	/* Copy the data buffer to the local variables */
	A = mgetLLong( dataPtr );
	B = mgetLLong( dataPtr );

	/* Point to the end of the keying material (no.rounds + the initial
	   addition, two longwords each time) */
	keyPtr += 2 * ( key->noRounds + 1 );

	/* Perform the 12 rounds of decryption */
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );
	decryptRound( A, B, keyPtr );

	B -= *--keyPtr;
	A -= *--keyPtr;

	/* Copy the local variables back to the data buffer */
	dataPtr = data;
	mputLLong( dataPtr, A );
	mputLLong( dataPtr, B );
	}

/* RC5 key setup routines.  The variable names, while cryptic, follow the
   original algorithm specification */

void rc5keyInit( RC5_KEY *key, const BYTE *userKey, const int userKeyLength )
	{
	LONG L[ RC5_EXPANDED_KEYSIZE_LONG ], A = 0, B = 0;
	BYTE temp[ RC5_EXPANDED_KEYSIZE ], *tempPtr = temp;
	int i, j, c = ( userKeyLength + 3 ) / 4, t = 2 * ( key->noRounds + 1 );
	int iterations = ( c > t ) ? 3 * c : 3 * t;

	/* Copy the user key into the L array */
	memset( temp, 0, RC5_EXPANDED_KEYSIZE );
	memcpy( temp, userKey, userKeyLength );
	for( i = 0; i < RC5_EXPANDED_KEYSIZE_LONG; i++ )
		{
		L[ i ] = mgetLLong( tempPtr );
		}

	/* Initialise the key array with the LCRNG */
	key->S[ 0 ] = P32_MAGIC;
	for( i = 1; i < RC5_EXPANDED_KEYSIZE_LONG; i++ )
		key->S[ i ] = key->S[ i - 1 ] + Q32_MAGIC;

	/* Mix the user key into the key array */
	i = j = 0;
	while( iterations-- )
		{
		A = key->S[ i ] = ROTL( MASK32( key->S[ i ] + A + B ), 3 );
		B = L[ j ] = ROTL( MASK32( L[ j ] + A + B ), ( A + B ) & 0x1F );
		i = ( i + 1 ) % t;
		j = ( j + 1 ) % c;
		}

	/* Clean up */
	zeroise( L, RC5_EXPANDED_KEYSIZE_LONG * sizeof( LONG ) );
	zeroise( temp, RC5_EXPANDED_KEYSIZE );
	}
