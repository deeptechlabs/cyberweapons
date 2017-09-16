/****************************************************************************
*																			*
*							RC2 Encryption Algorithm 						*
*						  Copyright Peter Gutmann 1996						*
*																			*
****************************************************************************/

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "rc2.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "rc2.h"
#else
  #include "crypt.h"
  #include "crypt/rc2.h"
#endif /* Compiler-specific includes */

/* "It feels morally wrong to use a 32-bit processor and have only half the
	gates flapping" - Chris Wedgwood */

/* The following code uses unsigned int rather than WORD since many 32-bit
   compilers generate awful code when working with 16-bit data.  We know
   when a result will overflow 16 bits so we use ints and manually mask off
   the extra bits rather than have the compiler do it after every operation
   on a WORD */

/* ROTATE_LEFT/RIGHT rotates x by n bits */

#define ROTATE_LEFT(x,n)	( ( ( x ) << n ) | ( ( x ) >> ( 16 - n ) ) )
#define ROTATE_RIGHT(x,n)	( ( ( x ) >> n ) | ( ( x ) << ( 16 - n ) ) )

/* The basic en/decryption operations */

#define enc(A,B,C,D,S,round,rotAmount) \
	MASK16( ROTATE_LEFT( MASK16( A + ( B & ~C ) + ( D & C ) + S[ round ] ), rotAmount ) )

#define dec(A,B,C,D,S,round,rotAmount) \
	MASK16( MASK16( ROTATE_RIGHT( A, rotAmount ) ) - ( B & ~D ) - ( C & D ) - S[ round ] )

/* One round of en/decryption */

#define encRound(A,B,C,D,S,round) \
	A = enc( A, B, D, C, S, ( round * 4 ) + 0, 1 ); \
	B = enc( B, C, A, D, S, ( round * 4 ) + 1, 2 ); \
	C = enc( C, D, B, A, S, ( round * 4 ) + 2, 3 ); \
	D = enc( D, A, C, B, S, ( round * 4 ) + 3, 5 )

#define decRound(A,B,C,D,S,round) \
	D = dec( D, A, B, C, S, ( round * 4 ) + 3, 5 ); \
	C = dec( C, D, A, B, S, ( round * 4 ) + 2, 3 ); \
	B = dec( B, C, D, A, S, ( round * 4 ) + 1, 2 ); \
	A = dec( A, B, C, D, S, ( round * 4 ) + 0, 1 )

/* The addition/subtraction of the S-boxes which occurs on the 4th and 10th
   rounds.  The addition will overflow the 16-bit limit, but this isn't a
   problem since the next round of en/decryption gets things back down to 16
   bits (unfortunately this doesn't work for subtraction) */

#define addSboxes(A,B,C,D,S) \
	A += S[ D & RC2_KEY_SIZE_WORDS - 1 ]; \
	B += S[ A & RC2_KEY_SIZE_WORDS - 1 ]; \
	C += S[ B & RC2_KEY_SIZE_WORDS - 1 ]; \
	D += S[ C & RC2_KEY_SIZE_WORDS - 1 ]

#define subSboxes(A,B,C,D,S) \
	D -= S[ C & RC2_KEY_SIZE_WORDS - 1 ]; \
	D = MASK16( D ); \
	C -= S[ B & RC2_KEY_SIZE_WORDS - 1 ]; \
	C = MASK16( C ); \
	B -= S[ A & RC2_KEY_SIZE_WORDS - 1 ]; \
	B = MASK16( B ); \
	A -= S[ D & RC2_KEY_SIZE_WORDS - 1 ]; \
	A = MASK16( A )

/* The permutation table used for the RC2 key setup */

static BYTE sBox[] = {
	0xD9, 0x78, 0xF9, 0xC4, 0x19, 0xDD, 0xB5, 0xED,
	0x28, 0xE9, 0xFD, 0x79, 0x4A, 0xA0, 0xD8, 0x9D,
	0xC6, 0x7E, 0x37, 0x83, 0x2B, 0x76, 0x53, 0x8E,
	0x62, 0x4C, 0x64, 0x88, 0x44, 0x8B, 0xFB, 0xA2,
	0x17, 0x9A, 0x59, 0xF5, 0x87, 0xB3, 0x4F, 0x13,
	0x61, 0x45, 0x6D, 0x8D, 0x09, 0x81, 0x7D, 0x32,
	0xBD, 0x8F, 0x40, 0xEB, 0x86, 0xB7, 0x7B, 0x0B,
	0xF0, 0x95, 0x21, 0x22, 0x5C, 0x6B, 0x4E, 0x82,
	0x54, 0xD6, 0x65, 0x93, 0xCE, 0x60, 0xB2, 0x1C,
	0x73, 0x56, 0xC0, 0x14, 0xA7, 0x8C, 0xF1, 0xDC,
	0x12, 0x75, 0xCA, 0x1F, 0x3B, 0xBE, 0xE4, 0xD1,
	0x42, 0x3D, 0xD4, 0x30, 0xA3, 0x3C, 0xB6, 0x26,
	0x6F, 0xBF, 0x0E, 0xDA, 0x46, 0x69, 0x07, 0x57,
	0x27, 0xF2, 0x1D, 0x9B, 0xBC, 0x94, 0x43, 0x03,
	0xF8, 0x11, 0xC7, 0xF6, 0x90, 0xEF, 0x3E, 0xE7,
	0x06, 0xC3, 0xD5, 0x2F, 0xC8, 0x66, 0x1E, 0xD7,
	0x08, 0xE8, 0xEA, 0xDE, 0x80, 0x52, 0xEE, 0xF7,
	0x84, 0xAA, 0x72, 0xAC, 0x35, 0x4D, 0x6A, 0x2A,
	0x96, 0x1A, 0xD2, 0x71, 0x5A, 0x15, 0x49, 0x74,
	0x4B, 0x9F, 0xD0, 0x5E, 0x04, 0x18, 0xA4, 0xEC,
	0xC2, 0xE0, 0x41, 0x6E, 0x0F, 0x51, 0xCB, 0xCC,
	0x24, 0x91, 0xAF, 0x50, 0xA1, 0xF4, 0x70, 0x39,
	0x99, 0x7C, 0x3A, 0x85, 0x23, 0xB8, 0xB4, 0x7A,
	0xFC, 0x02, 0x36, 0x5B, 0x25, 0x55, 0x97, 0x31,
	0x2D, 0x5D, 0xFA, 0x98, 0xE3, 0x8A, 0x92, 0xAE,
	0x05, 0xDF, 0x29, 0x10, 0x67, 0x6C, 0xBA, 0xC9,
	0xD3, 0x00, 0xE6, 0xCF, 0xE1, 0x9E, 0xA8, 0x2C,
	0x63, 0x16, 0x01, 0x3F, 0x58, 0xE2, 0x89, 0xA9,
	0x0D, 0x38, 0x34, 0x1B, 0xAB, 0x33, 0xFF, 0xB0,
	0xBB, 0x48, 0x0C, 0x5F, 0xB9, 0xB1, 0xCD, 0x2E,
	0xC5, 0xF3, 0xDB, 0x47, 0xE5, 0xA5, 0x9C, 0x77,
	0x0A, 0xA6, 0x20, 0x68, 0xFE, 0x7F, 0xC1, 0xAD
	};

/* Perform an RC2 key schedule.  This isn't 100% compatible with the full
   RC2 spec because this includes an extra parameter which specifies how
   many effective bits of key to truncate the actual key to.  This is only
   really useful for creating 40-bit espionage-enabled keys, although BSAFE
   always sets the bitcount to the actual key size (so for example for a 128-
   bit key it first expands it up to 1024 bits and then folds it back down
   again to 128 bits).  Because this scheme was copied by early S/MIME
   implementations (which were just BSAFE wrappers), it's become a part of
   CMS/SMIME so we use it here with an assumption that the key will be 128
   bits */

static int rc2_pow( int base, int exponent )
	{
	int i, result = 1;

	for( i = 0; i < exponent; i++ )
		result = result * base;

	return( result );
	}

void rc2keyInit( RC2_KEY *rc2key, const BYTE *userKey, const int length )
	{
	BYTE keyTemp[ RC2_KEY_SIZE ], *keyTempPtr = keyTemp;
#ifndef UNRESTRICTED_KEYS
	/* Determine the key parameters as per RFC 2268: Effective key bits in
	   T1, effective key bytes in T8, keysize mask in TM */
	const int T1 = 128, T8 = ( T1 + 7 ) / 8;
	const int TM = 255 % rc2_pow( 2, ( 8 + T1 - 8 * T8 ) );
#endif /* !UNRESTRICTED_KEYS */
	int i;

	/* Expand the key to 128 bytes by taking the sum of the first and last
	   bytes of the current key and appending the S-box entry this
	   corresponds to to the current key */
	memcpy( keyTemp, userKey, length );
	for( i = length; i < RC2_KEY_SIZE; i++ )
		keyTemp[ i ] = sBox[ ( keyTemp[ i - length ] + \
							   keyTemp[ i - 1 ] ) & 0xFF ];

#ifdef UNRESTRICTED_KEYS
	/* Finally, replace the first byte of the key with the entry it selects
	   from the S-box (this is equivalent to setting T1 = 1024) */
	keyTemp[ 0 ] = sBox[ keyTemp[ 0 ] ];
#else
	/* Shrink the effective key down again so only T1 effective bits are
	   used */
	keyTemp[ 128 - T8 ] = sBox[ keyTemp[ 128 - T8 ] & TM ];
	for( i = 127 - T8; i >= 0; i-- )
		keyTemp[ i ] = sBox[ keyTemp[ i + 1 ] ^ keyTemp[ i + T8 ] ];
#endif /* UNRESTRICTED_KEYS */

	/* Copy the scheduled key to the RC2 key structure and erase it */
	for( i = 0; i < RC2_KEY_SIZE_WORDS; i++ )
		{
		rc2key->key[ i ] = mgetLWord( keyTempPtr );
		}
	zeroise( keyTemp, RC2_KEY_SIZE );
	}

/* Encrypt a block of data with RC2 */

void rc2encrypt( RC2_KEY *rc2key, BYTE *buffer )
	{
	unsigned int word0, word1, word2, word3;
	unsigned int *key = rc2key->key;
	BYTE *bufPtr = buffer;

	/* Extract the data from the buffer */
	word0 = mgetLWord( bufPtr );
	word1 = mgetLWord( bufPtr );
	word2 = mgetLWord( bufPtr );
	word3 = mgetLWord( bufPtr );

	/* Perform 16 rounds of encryption */
	encRound( word0, word1, word2, word3, key, 0 );
	encRound( word0, word1, word2, word3, key, 1 );
	encRound( word0, word1, word2, word3, key, 2 );
	encRound( word0, word1, word2, word3, key, 3 );
	encRound( word0, word1, word2, word3, key, 4 );
	addSboxes( word0, word1, word2, word3, key );
	encRound( word0, word1, word2, word3, key, 5 );
	encRound( word0, word1, word2, word3, key, 6 );
	encRound( word0, word1, word2, word3, key, 7 );
	encRound( word0, word1, word2, word3, key, 8 );
	encRound( word0, word1, word2, word3, key, 9 );
	encRound( word0, word1, word2, word3, key, 10 );
	addSboxes( word0, word1, word2, word3, key );
	encRound( word0, word1, word2, word3, key, 11 );
	encRound( word0, word1, word2, word3, key, 12 );
	encRound( word0, word1, word2, word3, key, 13 );
	encRound( word0, word1, word2, word3, key, 14 );
	encRound( word0, word1, word2, word3, key, 15 );

	/* Deposit the data back in the buffer */
	mputLWord( buffer, word0 );
	mputLWord( buffer, word1 );
	mputLWord( buffer, word2 );
	mputLWord( buffer, word3 );
	}

/* Decrypt a block of data with RC2 */

void rc2decrypt( RC2_KEY *rc2key, BYTE *buffer )
	{
	unsigned int word0, word1, word2, word3;
	unsigned int *key = rc2key->key;
	BYTE *bufPtr = buffer;

	/* Extract the data from the buffer */
	word0 = mgetLWord( bufPtr );
	word1 = mgetLWord( bufPtr );
	word2 = mgetLWord( bufPtr );
	word3 = mgetLWord( bufPtr );

	/* Perform 16 rounds of decryption */
	decRound( word0, word1, word2, word3, key, 15 );
	decRound( word0, word1, word2, word3, key, 14 );
	decRound( word0, word1, word2, word3, key, 13 );
	decRound( word0, word1, word2, word3, key, 12 );
	decRound( word0, word1, word2, word3, key, 11 );
	subSboxes( word0, word1, word2, word3, key );
	decRound( word0, word1, word2, word3, key, 10 );
	decRound( word0, word1, word2, word3, key, 9 );
	decRound( word0, word1, word2, word3, key, 8 );
	decRound( word0, word1, word2, word3, key, 7 );
	decRound( word0, word1, word2, word3, key, 6 );
	decRound( word0, word1, word2, word3, key, 5 );
	subSboxes( word0, word1, word2, word3, key );
	decRound( word0, word1, word2, word3, key, 4 );
	decRound( word0, word1, word2, word3, key, 3 );
	decRound( word0, word1, word2, word3, key, 2 );
	decRound( word0, word1, word2, word3, key, 1 );
	decRound( word0, word1, word2, word3, key, 0 );

	/* Deposit the data back in the buffer */
	mputLWord( buffer, word0 );
	mputLWord( buffer, word1 );
	mputLWord( buffer, word2 );
	mputLWord( buffer, word3 );
	}

#ifdef TEST

/* Test routines */

#include <stdio.h>

void main( void )
	{
	BYTE key1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE plain1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE cipher1[] = { 0x1C, 0x19, 0x8A, 0x83, 0x8D, 0xF0, 0x28, 0xB7 };
	BYTE key2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	BYTE plain2[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE cipher2[] = { 0x21, 0x82, 0x9C, 0x78, 0xA9, 0xF9, 0xC0, 0x74 };
	BYTE key3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE plain3[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
	BYTE cipher3[] = { 0x13, 0xDB, 0x35, 0x17, 0xD3, 0x21, 0x86, 0x9E };
	BYTE key4[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
					0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };
	BYTE plain4[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE cipher4[] = { 0x50, 0xDC, 0x01, 0x62, 0xBD, 0x75, 0x7F, 0x31 };
	BYTE buffer[ 8 ];
	RC2_KEY rc2key;

	memcpy( buffer, plain1, 8 );
	rc2keyInit( &rc2key, key1, 16 );
	rc2encrypt( &rc2key, buffer );
	if( memcmp( buffer, cipher1, 8 ) )
		puts( "Bang" );
	rc2decrypt( &rc2key, buffer );
	memcpy( buffer, plain2, 8 );
	rc2keyInit( &rc2key, key2, 16 );
	rc2encrypt( &rc2key, buffer );
	if( memcmp( buffer, cipher2, 8 ) )
		puts( "Bang" );
	rc2decrypt( &rc2key, buffer );
	memcpy( buffer, plain3, 8 );
	rc2keyInit( &rc2key, key3, 16 );
	rc2encrypt( &rc2key, buffer );
	if( memcmp( buffer, cipher3, 8 ) )
		puts( "Bang" );
	rc2decrypt( &rc2key, buffer );
	memcpy( buffer, plain4, 8 );
	rc2keyInit( &rc2key, key4, 16 );
	rc2encrypt( &rc2key, buffer );
	if( memcmp( buffer, cipher4, 8 ) )
		puts( "Bang" );
	rc2decrypt( &rc2key, buffer );
	}
#endif /* TEST */
