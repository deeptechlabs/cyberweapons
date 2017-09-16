/****************************************************************************
*																			*
*							Safer Encryption Algorithm 						*
*						Copyright Peter Gutmann 1994-1996					*
*																			*
****************************************************************************/

/* Code to implement the improved SAFER-SK form of the SAFER cipher,
   originally published as "SAFER K-64: A Byte-Oriented Block-Ciphering
   Algorithm", James L. Massey, "Fast Software Encryption", Lecture Notes in
   Computer Science No. 809, Springer-Verlag 1994, p.1.  This code implements
   the 128-bit key extension designed by the Special Projects Team of the
   Ministry of Home Affairs, Singapore and published as "SAFER K-64: One
   Year Later", James L.Massey, presented at the K. U. Leuven Workshop on
   Algorithms, Leuven, Belgium, 14-16 December, 1994, to appear in "Fast
   Software Encryption II", Lecture Notes in Computer Science,
   Springer-Verlag 1995, along with Lars Knudsen's strengthened key schedule,
   presented in "A Key-Schedule Weakness in SAFER K-64," Lars Knudsen,
   presented at Crypto '95 in Santa Barbara, California.

   All parts of the SAFER-SK algorithm are non-proprietary and freely
   available for anyone to use as they see fit */

#include <string.h>
#if defined( INC_ALL )
  #include "crypt.h"
  #include "safer.h"
#elif defined( INC_CHILD )
  #include "../crypt.h"
  #include "safer.h"
#else
  #include "crypt.h"
  #include "crypt/safer.h"
#endif /* Compiler-specific includes */

/* Some C routines can be replaced with faster assembly-language equivalents
   for some systems.  These should really be defined in a makefile, but
   smegging Visual C will silently truncate all command-line defines when
   the line goes over 127 characters, so we define them here instead and
   save the makefile command line for other things */

#if defined( __MSDOS16__ ) || defined( __WIN16__ )
  #define ASM_SAFER
#endif /* __MSDOS16__ || __WIN16__ */

/* The size of each half key used in the key schedule */

#define SAFER_KEYHALF_SIZE		( SAFER_KEYSIZE / 2 )

/* The size of each half key plus the parity byte used in the key schedule */

#define SAFER_KEYHALF_P_SIZE	( SAFER_KEYHALF_SIZE + 1 )

/* Define for byte rotates (C isn't quite a high-level assembly language) */

#define ROL(x,n)	( ( ( x << n ) | ( x >> ( 8 - n ) ) ) & 0xFF )

/* Exponents and logs, evaluated via the pre-calculated lookup tables */

#define EXP(x)	expTable[ x ]
#define LOG(x)	logTable[ x ]

/* The two-point Pseudo-Hadamard Transform

	b1 = 2a1 + a2
	b2 =  a1 + a2

   and inverse two-point Pseudo-Hadamard Transform

	a1 =  b1 -  b2
	a2 = -b1 + 2b2

   which are used to create a three-dimensional PHT (ie independant
   two-point PHT's in each of three dimensions, which is why there are
   2^3 = 8 bytes in the input and output of the PHT) through a decimation-
   by-two/fanning-out-by-two network.  The PHT provides guaranteed complete
   diffusion within one linear layer */

#define PHT(x,y)	{ y += x; x += y; }
#define IPHT(x,y)	{ x -= y; y -= x; }

/* The lookup table for logs and exponents.  These contain the powers of the
   primitive element 45 of GF( 257 ) (ie values of 45^n mod 257) in
   "expTable" with the corresponding logs base 45 stored in "logTable".
   They may be calculated as follows:

	exponent = 1;
	for( i = 0; i < 256; i++ )
		{
		int exp = exponent & 0xFF;

		expTable[ i ] = exp;
		logTable[ exp ] = i;
		exponent = ( exponent * 45 ) % 257;
		} */

static BYTE expTable[] = {
	0x01, 0x2D, 0xE2, 0x93, 0xBE, 0x45, 0x15, 0xAE,
	0x78, 0x03, 0x87, 0xA4, 0xB8, 0x38, 0xCF, 0x3F,
	0x08, 0x67, 0x09, 0x94, 0xEB, 0x26, 0xA8, 0x6B,
	0xBD, 0x18, 0x34, 0x1B, 0xBB, 0xBF, 0x72, 0xF7,
	0x40, 0x35, 0x48, 0x9C, 0x51, 0x2F, 0x3B, 0x55,
	0xE3, 0xC0, 0x9F, 0xD8, 0xD3, 0xF3, 0x8D, 0xB1,
	0xFF, 0xA7, 0x3E, 0xDC, 0x86, 0x77, 0xD7, 0xA6,
	0x11, 0xFB, 0xF4, 0xBA, 0x92, 0x91, 0x64, 0x83,
	0xF1, 0x33, 0xEF, 0xDA, 0x2C, 0xB5, 0xB2, 0x2B,
	0x88, 0xD1, 0x99, 0xCB, 0x8C, 0x84, 0x1D, 0x14,
	0x81, 0x97, 0x71, 0xCA, 0x5F, 0xA3, 0x8B, 0x57,
	0x3C, 0x82, 0xC4, 0x52, 0x5C, 0x1C, 0xE8, 0xA0,
	0x04, 0xB4, 0x85, 0x4A, 0xF6, 0x13, 0x54, 0xB6,
	0xDF, 0x0C, 0x1A, 0x8E, 0xDE, 0xE0, 0x39, 0xFC,
	0x20, 0x9B, 0x24, 0x4E, 0xA9, 0x98, 0x9E, 0xAB,
	0xF2, 0x60, 0xD0, 0x6C, 0xEA, 0xFA, 0xC7, 0xD9,
	0x00, 0xD4, 0x1F, 0x6E, 0x43, 0xBC, 0xEC, 0x53,
	0x89, 0xFE, 0x7A, 0x5D, 0x49, 0xC9, 0x32, 0xC2,
	0xF9, 0x9A, 0xF8, 0x6D, 0x16, 0xDB, 0x59, 0x96,
	0x44, 0xE9, 0xCD, 0xE6, 0x46, 0x42, 0x8F, 0x0A,
	0xC1, 0xCC, 0xB9, 0x65, 0xB0, 0xD2, 0xC6, 0xAC,
	0x1E, 0x41, 0x62, 0x29, 0x2E, 0x0E, 0x74, 0x50,
	0x02, 0x5A, 0xC3, 0x25, 0x7B, 0x8A, 0x2A, 0x5B,
	0xF0, 0x06, 0x0D, 0x47, 0x6F, 0x70, 0x9D, 0x7E,
	0x10, 0xCE, 0x12, 0x27, 0xD5, 0x4C, 0x4F, 0xD6,
	0x79, 0x30, 0x68, 0x36, 0x75, 0x7D, 0xE4, 0xED,
	0x80, 0x6A, 0x90, 0x37, 0xA2, 0x5E, 0x76, 0xAA,
	0xC5, 0x7F, 0x3D, 0xAF, 0xA5, 0xE5, 0x19, 0x61,
	0xFD, 0x4D, 0x7C, 0xB7, 0x0B, 0xEE, 0xAD, 0x4B,
	0x22, 0xF5, 0xE7, 0x73, 0x23, 0x21, 0xC8, 0x05,
	0xE1, 0x66, 0xDD, 0xB3, 0x58, 0x69, 0x63, 0x56,
	0x0F, 0xA1, 0x31, 0x95, 0x17, 0x07, 0x3A, 0x28
	};

#ifndef ASM_SAFER

static BYTE logTable[] = {
	0x80, 0x00, 0xB0, 0x09, 0x60, 0xEF, 0xB9, 0xFD,
	0x10, 0x12, 0x9F, 0xE4, 0x69, 0xBA, 0xAD, 0xF8,
	0xC0, 0x38, 0xC2, 0x65, 0x4F, 0x06, 0x94, 0xFC,
	0x19, 0xDE, 0x6A, 0x1B, 0x5D, 0x4E, 0xA8, 0x82,
	0x70, 0xED, 0xE8, 0xEC, 0x72, 0xB3, 0x15, 0xC3,
	0xFF, 0xAB, 0xB6, 0x47, 0x44, 0x01, 0xAC, 0x25,
	0xC9, 0xFA, 0x8E, 0x41, 0x1A, 0x21, 0xCB, 0xD3,
	0x0D, 0x6E, 0xFE, 0x26, 0x58, 0xDA, 0x32, 0x0F,
	0x20, 0xA9, 0x9D, 0x84, 0x98, 0x05, 0x9C, 0xBB,
	0x22, 0x8C, 0x63, 0xE7, 0xC5, 0xE1, 0x73, 0xC6,
	0xAF, 0x24, 0x5B, 0x87, 0x66, 0x27, 0xF7, 0x57,
	0xF4, 0x96, 0xB1, 0xB7, 0x5C, 0x8B, 0xD5, 0x54,
	0x79, 0xDF, 0xAA, 0xF6, 0x3E, 0xA3, 0xF1, 0x11,
	0xCA, 0xF5, 0xD1, 0x17, 0x7B, 0x93, 0x83, 0xBC,
	0xBD, 0x52, 0x1E, 0xEB, 0xAE, 0xCC, 0xD6, 0x35,
	0x08, 0xC8, 0x8A, 0xB4, 0xE2, 0xCD, 0xBF, 0xD9,
	0xD0, 0x50, 0x59, 0x3F, 0x4D, 0x62, 0x34, 0x0A,
	0x48, 0x88, 0xB5, 0x56, 0x4C, 0x2E, 0x6B, 0x9E,
	0xD2, 0x3D, 0x3C, 0x03, 0x13, 0xFB, 0x97, 0x51,
	0x75, 0x4A, 0x91, 0x71, 0x23, 0xBE, 0x76, 0x2A,
	0x5F, 0xF9, 0xD4, 0x55, 0x0B, 0xDC, 0x37, 0x31,
	0x16, 0x74, 0xD7, 0x77, 0xA7, 0xE6, 0x07, 0xDB,
	0xA4, 0x2F, 0x46, 0xF3, 0x61, 0x45, 0x67, 0xE3,
	0x0C, 0xA2, 0x3B, 0x1C, 0x85, 0x18, 0x04, 0x1D,
	0x29, 0xA0, 0x8F, 0xB2, 0x5A, 0xD8, 0xA6, 0x7E,
	0xEE, 0x8D, 0x53, 0x4B, 0xA1, 0x9A, 0xC1, 0x0E,
	0x7A, 0x49, 0xA5, 0x2C, 0x81, 0xC4, 0xC7, 0x36,
	0x2B, 0x7F, 0x43, 0x95, 0x33, 0xF2, 0x6C, 0x68,
	0x6D, 0xF0, 0x02, 0x28, 0xCE, 0xDD, 0x9B, 0xEA,
	0x5E, 0x99, 0x7C, 0x14, 0x86, 0xCF, 0xE5, 0x42,
	0xB8, 0x40, 0x78, 0x2D, 0x3A, 0xE9, 0x64, 0x1F,
	0x92, 0x90, 0x7D, 0x39, 0x6F, 0xE0, 0x89, 0x30
	};

#endif /* ASM_SAFER */

/* Perform a SAFER key schedule */

void saferExpandKey( BYTE *key, const BYTE *userKey, int noRounds,
					 const BOOLEAN useSaferSK )
	{
	int round, i;
	BYTE *keyLow = ( BYTE * ) userKey;
	BYTE *keyHigh = ( BYTE * ) userKey + SAFER_KEYHALF_SIZE;
	BYTE ka[ SAFER_KEYHALF_P_SIZE ], kb[ SAFER_KEYHALF_P_SIZE ];

	/* Save the number of rounds as part of the key */
	if( noRounds > SAFER_MAX_ROUNDS )
		noRounds = SAFER_MAX_ROUNDS;
	*key++ = ( BYTE ) noRounds;

	/* Copy the user key halves to Ka and Kb */
	for( i = 0; i < SAFER_KEYHALF_SIZE; i++ )
		{
		ka[ i ] = keyLow[ i ];
		kb[ i ] = keyHigh[ i ];
		}

	/* Append a parity byte to keys Ka and Kb */
	ka[ SAFER_KEYHALF_SIZE ] = kb[ SAFER_KEYHALF_SIZE ] = 0;
	for( i = 0; i < SAFER_KEYHALF_SIZE; i++ )
		{
		ka[ SAFER_KEYHALF_SIZE ] ^= ka[ i ];
		kb[ SAFER_KEYHALF_SIZE ] ^= kb[ i ];
		}

	/* K1 = Kb */
	for( i = 0; i < SAFER_KEYHALF_SIZE; i++ )
		*key++ = kb[ i ];

	/* Rotate each byte of Ka right by 3 */
	for( i = 0; i < SAFER_KEYHALF_SIZE + 1; i++ )
		ka[ i ] = ROL( ka[ i ], 5 );

	/* Perform the key schedule needed to derive the remaining keys K2, ...
	   K2r+1 from the 128 bit input key Ka+Kb */
	for( round = 1; round <= noRounds; round++)
		{
		/* Left rotate each byte of Ka and Kb by 6 */
		for( i = 0; i < SAFER_KEYHALF_P_SIZE; i++ )
			{
			ka[ i ] = ROL( ka[ i ], 6 );
			kb[ i ] = ROL( kb[ i ], 6 );
			}

		/* Add the key biases to give K2i-1 and K2i.  The original algorithm
		   specification is:

			k[ 2 * i, j ] = ka[ ( ( j + 2 * i - 2 ) % 9 ) + 1 ] + \
							expTable[ expTable[ 18 * i + j ] ];
			k[ 2 * i + 1, j ] = kb[ ( ( j + 2 * i - 1 ) % 9 ) + 1 ] + \
								expTable[ expTable[ 18 * i + 9 + j ] ];

		   however we rearrange this to calculate K2i-1 and K2i seperately
		   to eliminate the need to repeatedly evaluate 2i on the LHS */
		for( i = 0; i < SAFER_KEYHALF_SIZE; i++ )
			if( useSaferSK )
				*key++ = ( ka[ ( i + 2 * round - 1 ) % SAFER_KEYHALF_P_SIZE ] + \
						   expTable[ expTable[ ( SAFER_KEYHALF_P_SIZE * 2 ) * \
							round + i + 1 ] ] ) & 0xFF;
            else
				*key++ = ( ka[ i ] + \
						   expTable[ expTable[ ( SAFER_KEYHALF_P_SIZE * 2 ) * \
							round + i + 1 ] ] ) & 0xFF;

		for( i = 0; i < SAFER_KEYHALF_SIZE; i++ )
			if( useSaferSK )
				*key++ = ( kb[ ( i + 2 * round ) % SAFER_KEYHALF_P_SIZE ] + \
						   expTable[ expTable[ ( SAFER_KEYHALF_P_SIZE * 2 ) * \
							round + i + ( SAFER_KEYHALF_P_SIZE + 1 ) ] ] ) & 0xFF;
            else
				*key++ = ( kb[ i ] + \
						   expTable[ expTable[ ( SAFER_KEYHALF_P_SIZE * 2 ) * \
							round + i + ( SAFER_KEYHALF_P_SIZE + 1 ) ] ] ) & 0xFF;
		}

	/* Clean up */
	zeroise( ka, SAFER_BLOCKSIZE );
	zeroise( kb, SAFER_BLOCKSIZE );
	}

#ifndef ASM_SAFER

/* Encrypt a block of data with SAFER */

void saferEncryptBlock( BYTE *data, BYTE *key )
	{
	BYTE a, b, c, d, e, f, g, h, t;
	int rounds = *key++;

	/* Copy the input block to local variables */
	a = data[ 0 ];
	b = data[ 1 ];
	c = data[ 2 ];
	d = data[ 3 ];
	e = data[ 4 ];
	f = data[ 5 ];
	g = data[ 6 ];
	h = data[ 7 ];

	while( rounds-- )
		{
		/* Perform the mixed xor/byte addition of the round input with the
		   subkey K2i-1, combined with the first level of the nonlinear
		   layer, either 45^n mod 257 or log45n, and the mixed xor/byte
		   addition with the subkey K2i */
		a = EXP( ( a ^ key[ 0 ] ) & 0xFF ) + key[  8 ];
		b = LOG( ( b + key[ 1 ] ) & 0xFF ) ^ key[  9 ];
		c = LOG( ( c + key[ 2 ] ) & 0xFF ) ^ key[ 10 ];
		d = EXP( ( d ^ key[ 3 ] ) & 0xFF ) + key[ 11 ];
		e = EXP( ( e ^ key[ 4 ] ) & 0xFF ) + key[ 12 ];
		f = LOG( ( f + key[ 5 ] ) & 0xFF ) ^ key[ 13 ];
		g = LOG( ( g + key[ 6 ] ) & 0xFF ) ^ key[ 14 ];
		h = EXP( ( h ^ key[ 7 ] ) & 0xFF ) + key[ 15 ];

		/* Perform the Pseudo-Hadamard Trasform of the round output.  If
		   we were implementing this in assembly language we should
		   interleave the order of the two operations in the PHT with those
		   of the following PHT to reduce pipeline stalls, but for the C
		   version we rely on the compiler to pick this optimization up */
		PHT( a, b );
		PHT( c, d );
		PHT( e, f );
		PHT( g, h );
		PHT( a, c );
		PHT( e, g );
		PHT( b, d );
		PHT( f, h );
		PHT( a, e );
		PHT( b, f );
		PHT( c, g );
		PHT( d, h );

		/* Swap the data octets around.  If we unrol the loop we can
		   eliminate this step through register renaming */
		t = b; b = e; e = c; c = t; t = d; d = f; f = g; g = t;
		key += 16;
		}

	/* Perform the final mixed xor/byte addition output transformation
	   using K2r + 1*/
	data[ 0 ] = a ^ key[ 0 ];
	data[ 1 ] = b + key[ 1 ];
	data[ 2 ] = c + key[ 2 ];
	data[ 3 ] = d ^ key[ 3 ];
	data[ 4 ] = e ^ key[ 4 ];
	data[ 5 ] = f + key[ 5 ];
	data[ 6 ] = g + key[ 6 ];
	data[ 7 ] = h ^ key[ 7 ];
	}

/* Decrypt a block of data with SAFER */

void saferDecryptBlock( BYTE *data, BYTE *key )
	{
	BYTE a, b, c, d, e, f, g, h, t;
	int rounds = *key;

	/* Since we're now running throught the algorithm backwards, we move to
	   the end of the key and start from there */
	key += SAFER_BLOCKSIZE * ( 1 + 2 * rounds );

	/* Perform the initial mixed xor/byte addition input transformation
	   using K2r+1 */
	a = data[ 0 ] ^ key[ -7 ];
	b = data[ 1 ] - key[ -6 ];
	c = data[ 2 ] - key[ -5 ];
	d = data[ 3 ] ^ key[ -4 ];
	e = data[ 4 ] ^ key[ -3 ];
	f = data[ 5 ] - key[ -2 ];
	g = data[ 6 ] - key[ -1 ];
	h = data[ 7 ] ^ key[ 0 ];
	key -= 8;

	while( rounds-- )
		{
		/* Swap the data octets around.  If we unrol the loop we can
		   eliminate this step through register renaming */
		t = e; e = b; b = c; c = t; t = f; f = d; d = g; g = t;

		/* Perform the inverse Pseudo-Hadamard Trasform of the round input.
		   If we were implementing this in assembly language we should
		   interleave the order of the two operations in the PHT with those
		   of the following PHT to reduce pipeline stalls, but for the C
		   version we rely on the compiler to pick this optimization up */
		IPHT( a, e );
		IPHT( b, f );
		IPHT( c, g );
		IPHT( d, h );
		IPHT( a, c );
		IPHT( e, g );
		IPHT( b, d );
		IPHT( f, h );
		IPHT( a, b );
		IPHT( c, d );
		IPHT( e, f );
		IPHT( g, h );

		/* Perform the mixed xor/byte addition of the inverse PHT output with
		   the subkey K2r+2-2i, combined with the second level of the
		   nonlinear layer, either 45^n mod 257 or log45n, and finally the
		   mixed xor/byte addition of the round output with K2r+1-2i */
		h = LOG( ( h - key[  0 ] ) & 0xFF ) ^ key[  -8 ];
		g = EXP( ( g ^ key[ -1 ] ) & 0xFF ) - key[  -9 ];
		f = EXP( ( f ^ key[ -2 ] ) & 0xFF ) - key[ -10 ];
		e = LOG( ( e - key[ -3 ] ) & 0xFF ) ^ key[ -11 ];
		d = LOG( ( d - key[ -4 ] ) & 0xFF ) ^ key[ -12 ];
		c = EXP( ( c ^ key[ -5 ] ) & 0xFF ) - key[ -13 ];
		b = EXP( ( b ^ key[ -6 ] ) & 0xFF ) - key[ -14 ];
		a = LOG( ( a - key[ -7 ] ) & 0xFF ) ^ key[ -15 ];
		key -= 16;
		}

	data[ 0 ] = a;
	data[ 1 ] = b;
	data[ 2 ] = c;
	data[ 3 ] = d;
	data[ 4 ] = e;
	data[ 5 ] = f;
	data[ 6 ] = g;
	data[ 7 ] = h;
	}
#endif /* ASM_SAFER */

#ifdef TEST_SAFER

/* CFB-mode en/decryption routines */

void saferEncryptCFB( BYTE *buffer, int noBytes, BYTE *iv, int ivLen, BYTE *key )
	{
	BYTE currentIV[ SAFER_BLOCKSIZE ];

	/* Set up the initial IV */
	memset( currentIV, 0, SAFER_BLOCKSIZE );
	memcpy( currentIV, iv, ivLen );

	while( noBytes )
		{
		int ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;
		int i;

		/* Encrypt the IV */
		saferEncryptBlock( currentIV, key );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( currentIV, buffer, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}
	}

void saferDecryptCFB( BYTE *buffer, int noBytes, BYTE *iv, int ivLen, BYTE *key )
	{
	BYTE currentIV[ SAFER_BLOCKSIZE ], temp[ SAFER_BLOCKSIZE ];

	/* Set up the initial IV */
	memset( currentIV, 0, SAFER_BLOCKSIZE );
	memcpy( currentIV, iv, ivLen );

	while( noBytes )
		{
		int ivCount = ( noBytes > SAFER_BLOCKSIZE ) ? SAFER_BLOCKSIZE : noBytes;
		int i;

		/* Encrypt the IV */
		saferEncryptBlock( currentIV, key );

		/* Save the ciphertext */
		memcpy( temp, buffer, ivCount );

		/* XOR the buffer contents with the encrypted IV */
		for( i = 0; i < ivCount; i++ )
			buffer[ i ] ^= currentIV[ i ];

		/* Shift the ciphertext into the IV */
		memcpy( currentIV, temp, ivCount );

		/* Move on to next block of data */
		noBytes -= ivCount;
		buffer += ivCount;
		}
	}

/* Test code */

#include <stdio.h>
#include <time.h>

void _saferEncryptBlock( BYTE *data, BYTE *key );
void _saferDecryptBlock( BYTE *data, BYTE *key );

void test8051( void )
	{
	BYTE key[] = { 0x03,
				   0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
				   0x10, 0x26, 0x8B, 0x5B, 0x46, 0xBE, 0xA8,
				   0xFD, 0xC6, 0x09, 0x81, 0x67, 0xD9, 0xB4,
				   0x7B, 0x8E, 0x88, 0xB9, 0xC4, 0xAF, 0xC5,
				   0x20, 0x1A, 0xC7, 0x3B, 0x99, 0x3A, 0x18,
				   0xAD, 0xE5, 0x35, 0x8C, 0x5B, 0xC9, 0xEA,
				   0x99, 0x5C, 0x8D, 0xF9, 0x1B, 0xF8, 0xA2,
				   0x1C, 0x65, 0x61, 0xFB, 0xB6, 0xF3, 0x0C };
	BYTE plainText[] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
	BYTE cipherText[] = { 0xE9, 0xB8, 0xC0, 0xEA, 0xBC, 0x10, 0x99, 0xA1 };
	BYTE plainString[] = "This is a test string which is longer than the blocksize...";
	BYTE cipherString[] = { 0xC1, 0x5B, 0x63, 0xE9, 0xA8, 0x15, 0x74, 0x19,
							0x88, 0x1B, 0xB6, 0xE4, 0xF3, 0x32, 0x93, 0xC2,
							0x6F, 0x81, 0x94, 0xA7, 0x69, 0xA6, 0x92, 0x05,
							0x54, 0xA1, 0x8E, 0x3B, 0xF2, 0x56, 0x28, 0xFF,
							0x12, 0x02, 0xAB, 0x66, 0xC6, 0xC5, 0xF0, 0xEC,
							0x65, 0x82, 0xD0, 0x29, 0x92, 0x2B, 0x26, 0x52,
							0x96, 0x83, 0xB1, 0x21, 0x53, 0x09, 0x02, 0x67,
							0xD9, 0x6B, 0x2E };
	BYTE cfbIV[] = "1234";
	BYTE data[ SAFER_BLOCKSIZE ];
	BYTE cfbData[ 100 ];
	int length = sizeof( plainString ) - 1;

	memcpy( data, plainText, SAFER_BLOCKSIZE );
	saferEncryptBlock( data, key );
	if( memcmp( data, cipherText, SAFER_BLOCKSIZE ) )
		puts( "Bang" );
	saferDecryptBlock( data, key );

	memcpy( cfbData, plainString, length );
	saferEncryptCFB( cfbData, sizeof( cfbData ) - 1,
					 cfbIV, sizeof( cfbIV ) - 1, key );
	if( memcmp( cfbData, cipherString, length ) )
		puts( "Bang" );
	saferDecryptCFB( cfbData, sizeof( cfbData ) - 1,
					 cfbIV, sizeof( cfbIV ) - 1, key );
	}

void main( void )
	{
	BYTE key1[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	BYTE plainText1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	BYTE cipherText1[] = { 0x41, 0x4C, 0x54, 0x5A, 0xB6, 0x99, 0x4A, 0xF7 };
	BYTE key2[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	BYTE plainText2[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	BYTE cipherText2[] = { 0xFF, 0x78, 0x11, 0xE4, 0xB3, 0xA7, 0x2E, 0x71 };
	BYTE key3[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	BYTE plainText3[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
	BYTE cipherText3[] = { 0x49, 0xC9, 0x9D, 0x98, 0xA5, 0xBC, 0x59, 0x08 };
	BYTE data[ SAFER_BLOCKSIZE ], key[ SAFER_KEYLEN ];
	BYTE cfbData[] = "This is a test string which is longer than the blocksize";
	BYTE cfbIV[] = "1234";
	time_t secondCount;
	long i;

	saferExpandKey( key, key1, SAFER_SK128_ROUNDS, TRUE );
	memcpy( data, plainText1, SAFER_BLOCKSIZE );
	saferEncryptBlock( data, key );
	memcpy( data, plainText1, SAFER_BLOCKSIZE );
	saferEncryptBlock( data, key );
	if( memcmp( data, cipherText1, SAFER_BLOCKSIZE ) )
		puts( "Bang" );
	saferDecryptBlock( data, key );
	saferExpandKey( key, key2, SAFER_SK128_ROUNDS, TRUE );
	memcpy( data, plainText2, SAFER_BLOCKSIZE );
	saferEncryptBlock( data, key );
	if( memcmp( data, cipherText2, SAFER_BLOCKSIZE ) )
		puts( "Bang" );
	saferDecryptBlock( data, key );
	saferExpandKey( key, key3, SAFER_SK128_ROUNDS, TRUE );
	memcpy( data, plainText3, SAFER_BLOCKSIZE );
	saferEncryptBlock( data, key );
	if( memcmp( data, cipherText3, SAFER_BLOCKSIZE ) )
		puts( "Bang" );
	saferDecryptBlock( data, key );

	/* CFB mode test */
	saferExpandKey( key, key1, SAFER_SK128_ROUNDS, TRUE );
	saferEncryptCFB( cfbData, sizeof( cfbData ) - 1,
					 cfbIV, sizeof( cfbIV ) - 1, key );
	saferDecryptCFB( cfbData, sizeof( cfbData ) - 1,
					 cfbIV, sizeof( cfbIV ) - 1, key );

	test8051();

	/* Speed test */
	puts( "Encrypting 5MB of data" );
	secondCount = time( NULL );
	for( i = 0; i < 625000L; i++ )
		saferEncryptBlock( data, key );
	secondCount = time( NULL ) - secondCount;
	printf( "Time = %ld seconds, %ld kbytes/second\n", \
			secondCount, 8 * 625L / secondCount );
	}
#endif /* TEST_SAFER */
