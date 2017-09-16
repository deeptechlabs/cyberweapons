// cast.cpp - modified by Wei Dai from Peter Gutmann's code
// Copyright 1996 by Peter Gutmann.  Distributed with permission.

/* Implementation of the CAST-128 cipher as described in "Constructing
   Symmetric Ciphers Using the CAST Design Procedure" by Carlisle Adams.
   Nortel, under whose aegis the CAST-128 algorithm was developed, have
   allowed free use of the algorithm for any purpose.  This implementation of
   CAST-128 is copyright 1996 Peter Gutmann, and may be used freely for any
   purpose provided you don't claim you wrote it.

   This code was written for use with cryptlib, my free encryption library
   which provides conventional and public-key encryption, key management, and
   encrypted data management functions.  You can find out more about cryptlib
   from http://www.cs.auckland.ac.nz/~pgut001/cryptlib.html */

// Wei's note: To avoid confusion, Peter's cryptlib is a different crypto
// library unrelated to Crypto++.  I have simply adapted his code for my
// own library.

#include "pch.h"
#include "cast.h"

NAMESPACE_BEGIN(CryptoPP)

/* The CAST f-functions */

#define f1( data )	\
	( ( ( S[0][GETBYTE(data, 3)] ^ S[1][GETBYTE(data, 2)] ) - \
		  S[2][GETBYTE(data, 1)] ) + S[3][GETBYTE(data, 0)] )

#define f2( data )	\
	( ( ( S[0][GETBYTE(data, 3)] - S[1][GETBYTE(data, 2)] ) + \
		  S[2][GETBYTE(data, 1)] ) ^ S[3][GETBYTE(data, 0)] )

#define f3( data )	\
	( ( ( S[0][GETBYTE(data, 3)] + S[1][GETBYTE(data, 2)] ) ^ \
		  S[2][GETBYTE(data, 1)] ) - S[3][GETBYTE(data, 0)] )

/* The individual encrypt/decrypt rounds */

#define round1( count, output, input )	\
	tmp = K[ count - 1 ] + input ; \
	tmp = rotlVariable( tmp, (unsigned int)K[ count + 15 ] ); \
	output ^= f1( tmp );

#define round2( count, output, input )	\
	tmp = K[ count - 1 ] ^ input ; \
	tmp = rotlVariable( tmp, (unsigned int)K[ count + 15 ] ); \
	output ^= f2( tmp );

#define round3( count, output, input )	\
	tmp = K[ count - 1 ] - input ; \
	tmp = rotlVariable( tmp, (unsigned int)K[ count + 15 ] ); \
	output ^= f3( tmp );

/* The CAST encrypt/decrypt functions */

void CAST128Encryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	word32 L, R, tmp;

	GetBlockBigEndian(inBlock,L,R);

	/* Perform 16 rounds of encryption */
	round1(  1, L, R );
	round2(  2, R, L );
	round3(  3, L, R );
	round1(  4, R, L );
	round2(  5, L, R );
	round3(  6, R, L );
	round1(  7, L, R );
	round2(  8, R, L );
	round3(  9, L, R );
	round1( 10, R, L );
	round2( 11, L, R );
	round3( 12, R, L );

	if (!reduced)
	{
		round1( 13, L, R );
		round2( 14, R, L );
		round3( 15, L, R );
		round1( 16, R, L );
	}

	PutBlockBigEndian(outBlock,R,L);
}

void CAST128Decryption::ProcessBlock(const byte *inBlock, byte * outBlock) const
{
	word32 L, R, tmp;

	GetBlockBigEndian(inBlock,L,R);

	/* Perform 16 rounds of decryption */
	if (!reduced)
	{
		round1( 16, L, R );
		round3( 15, R, L );
		round2( 14, L, R );
		round1( 13, R, L );
	}

	round3( 12, L, R );
	round2( 11, R, L );
	round1( 10, L, R );
	round3(  9, R, L );
	round2(  8, L, R );
	round1(  7, R, L );
	round3(  6, L, R );
	round2(  5, R, L );
	round1(  4, L, R );
	round3(  3, R, L );
	round2(  2, L, R );
	round1(  1, R, L );

	PutBlockBigEndian(outBlock,R,L);
}

/* Set up a CAST-128 key */

CAST128::CAST128(const byte *userKey, unsigned int keylength)
	: reduced(keylength <= 10), K(32)
{
	assert(keylength == KeyLength(keylength));

	word32 X[4], Z[4];
	GetUserKeyBigEndian(X, 4, userKey, keylength);

#define x(i) GETBYTE(X[i/4], 3-i%4)
#define z(i) GETBYTE(Z[i/4], 3-i%4)

	Z[0] = X[0] ^ S[4][ x(13) ] ^ S[5][ x(15) ] ^ S[6][ x(12) ] ^ S[7][ x(14) ] ^ S[6][ x( 8) ];
	Z[1] = X[2] ^ S[4][ z( 0) ] ^ S[5][ z( 2) ] ^ S[6][ z( 1) ] ^ S[7][ z( 3) ] ^ S[7][ x(10) ];
	Z[2] = X[3] ^ S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[4][ x( 9) ];
	Z[3] = X[1] ^ S[4][ z(10) ] ^ S[5][ z( 9) ] ^ S[6][ z(11) ] ^ S[7][ z( 8) ] ^ S[5][ x(11) ];

	K[  0 ] = S[4][ z( 8) ] ^ S[5][ z( 9) ] ^ S[6][ z( 7) ] ^ S[7][ z( 6) ] ^ S[4][ z( 2) ];
	K[  1 ] = S[4][ z(10) ] ^ S[5][ z(11) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[5][ z( 6) ];
	K[  2 ] = S[4][ z(12) ] ^ S[5][ z(13) ] ^ S[6][ z( 3) ] ^ S[7][ z( 2) ] ^ S[6][ z( 9) ];
	K[  3 ] = S[4][ z(14) ] ^ S[5][ z(15) ] ^ S[6][ z( 1) ] ^ S[7][ z( 0) ] ^ S[7][ z(12) ];

	X[0] = Z[2] ^ S[4][ z( 5) ] ^ S[5][ z( 7) ] ^ S[6][ z( 4) ] ^ S[7][ z( 6) ] ^ S[6][ z( 0) ];
	X[1] = Z[0] ^ S[4][ x( 0) ] ^ S[5][ x( 2) ] ^ S[6][ x( 1) ] ^ S[7][ x( 3) ] ^ S[7][ z( 2) ];
	X[2] = Z[1] ^ S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[4][ z( 1) ];
	X[3] = Z[3] ^ S[4][ x(10) ] ^ S[5][ x( 9) ] ^ S[6][ x(11) ] ^ S[7][ x( 8) ] ^ S[5][ z( 3) ];

	K[  4 ] = S[4][ x( 3) ] ^ S[5][ x( 2) ] ^ S[6][ x(12) ] ^ S[7][ x(13) ] ^ S[4][ x( 8) ];
	K[  5 ] = S[4][ x( 1) ] ^ S[5][ x( 0) ] ^ S[6][ x(14) ] ^ S[7][ x(15) ] ^ S[5][ x(13) ];
	K[  6 ] = S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 8) ] ^ S[7][ x( 9) ] ^ S[6][ x( 3) ];
	K[  7 ] = S[4][ x( 5) ] ^ S[5][ x( 4) ] ^ S[6][ x(10) ] ^ S[7][ x(11) ] ^ S[7][ x( 7) ];

	Z[0] = X[0] ^ S[4][ x(13) ] ^ S[5][ x(15) ] ^ S[6][ x(12) ] ^ S[7][ x(14) ] ^ S[6][ x( 8) ];
	Z[1] = X[2] ^ S[4][ z( 0) ] ^ S[5][ z( 2) ] ^ S[6][ z( 1) ] ^ S[7][ z( 3) ] ^ S[7][ x(10) ];
	Z[2] = X[3] ^ S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[4][ x( 9) ];
	Z[3] = X[1] ^ S[4][ z(10) ] ^ S[5][ z( 9) ] ^ S[6][ z(11) ] ^ S[7][ z( 8) ] ^ S[5][ x(11) ];

	K[  8 ] = S[4][ z( 3) ] ^ S[5][ z( 2) ] ^ S[6][ z(12) ] ^ S[7][ z(13) ] ^ S[4][ z( 9) ];
	K[  9 ] = S[4][ z( 1) ] ^ S[5][ z( 0) ] ^ S[6][ z(14) ] ^ S[7][ z(15) ] ^ S[5][ z(12) ];
	K[ 10 ] = S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 8) ] ^ S[7][ z( 9) ] ^ S[6][ z( 2) ];
	K[ 11 ] = S[4][ z( 5) ] ^ S[5][ z( 4) ] ^ S[6][ z(10) ] ^ S[7][ z(11) ] ^ S[7][ z( 6) ];

	X[0] = Z[2] ^ S[4][ z( 5) ] ^ S[5][ z( 7) ] ^ S[6][ z( 4) ] ^ S[7][ z( 6) ] ^ S[6][ z( 0) ];
	X[1] = Z[0] ^ S[4][ x( 0) ] ^ S[5][ x( 2) ] ^ S[6][ x( 1) ] ^ S[7][ x( 3) ] ^ S[7][ z( 2) ];
	X[2] = Z[1] ^ S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[4][ z( 1) ];
	X[3] = Z[3] ^ S[4][ x(10) ] ^ S[5][ x( 9) ] ^ S[6][ x(11) ] ^ S[7][ x( 8) ] ^ S[5][ z( 3) ];

	K[ 12 ] = S[4][ x( 8) ] ^ S[5][ x( 9) ] ^ S[6][ x( 7) ] ^ S[7][ x( 6) ] ^ S[4][ x( 3) ];
	K[ 13 ] = S[4][ x(10) ] ^ S[5][ x(11) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[5][ x( 7) ];
	K[ 14 ] = S[4][ x(12) ] ^ S[5][ x(13) ] ^ S[6][ x( 3) ] ^ S[7][ x( 2) ] ^ S[6][ x( 8) ];
	K[ 15 ] = S[4][ x(14) ] ^ S[5][ x(15) ] ^ S[6][ x( 1) ] ^ S[7][ x( 0) ] ^ S[7][ x(13) ];

	Z[0] = X[0] ^ S[4][ x(13) ] ^ S[5][ x(15) ] ^ S[6][ x(12) ] ^ S[7][ x(14) ] ^ S[6][ x( 8) ];
	Z[1] = X[2] ^ S[4][ z( 0) ] ^ S[5][ z( 2) ] ^ S[6][ z( 1) ] ^ S[7][ z( 3) ] ^ S[7][ x(10) ];
	Z[2] = X[3] ^ S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[4][ x( 9) ];
	Z[3] = X[1] ^ S[4][ z(10) ] ^ S[5][ z( 9) ] ^ S[6][ z(11) ] ^ S[7][ z( 8) ] ^ S[5][ x(11) ];

	K[ 16 ] = ( S[4][ z( 8) ] ^ S[5][ z( 9) ] ^ S[6][ z( 7) ] ^ S[7][ z( 6) ] ^ S[4][ z( 2) ] ) & 0x1F;
	K[ 17 ] = ( S[4][ z(10) ] ^ S[5][ z(11) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[5][ z( 6) ] ) & 0x1F;
	K[ 18 ] = ( S[4][ z(12) ] ^ S[5][ z(13) ] ^ S[6][ z( 3) ] ^ S[7][ z( 2) ] ^ S[6][ z( 9) ] ) & 0x1F;
	K[ 19 ] = ( S[4][ z(14) ] ^ S[5][ z(15) ] ^ S[6][ z( 1) ] ^ S[7][ z( 0) ] ^ S[7][ z(12) ] ) & 0x1F;

	X[0] = Z[2] ^ S[4][ z( 5) ] ^ S[5][ z( 7) ] ^ S[6][ z( 4) ] ^ S[7][ z( 6) ] ^ S[6][ z( 0) ];
	X[1] = Z[0] ^ S[4][ x( 0) ] ^ S[5][ x( 2) ] ^ S[6][ x( 1) ] ^ S[7][ x( 3) ] ^ S[7][ z( 2) ];
	X[2] = Z[1] ^ S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[4][ z( 1) ];
	X[3] = Z[3] ^ S[4][ x(10) ] ^ S[5][ x( 9) ] ^ S[6][ x(11) ] ^ S[7][ x( 8) ] ^ S[5][ z( 3) ];

	K[ 20 ] = ( S[4][ x( 3) ] ^ S[5][ x( 2) ] ^ S[6][ x(12) ] ^ S[7][ x(13) ] ^ S[4][ x( 8) ] ) & 0x1F;
	K[ 21 ] = ( S[4][ x( 1) ] ^ S[5][ x( 0) ] ^ S[6][ x(14) ] ^ S[7][ x(15) ] ^ S[5][ x(13) ] ) & 0x1F;
	K[ 22 ] = ( S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 8) ] ^ S[7][ x( 9) ] ^ S[6][ x( 3) ] ) & 0x1F;
	K[ 23 ] = ( S[4][ x( 5) ] ^ S[5][ x( 4) ] ^ S[6][ x(10) ] ^ S[7][ x(11) ] ^ S[7][ x( 7) ] ) & 0x1F;

	Z[0] = X[0] ^ S[4][ x(13) ] ^ S[5][ x(15) ] ^ S[6][ x(12) ] ^ S[7][ x(14) ] ^ S[6][ x( 8) ];
	Z[1] = X[2] ^ S[4][ z( 0) ] ^ S[5][ z( 2) ] ^ S[6][ z( 1) ] ^ S[7][ z( 3) ] ^ S[7][ x(10) ];
	Z[2] = X[3] ^ S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 5) ] ^ S[7][ z( 4) ] ^ S[4][ x( 9) ];
	Z[3] = X[1] ^ S[4][ z(10) ] ^ S[5][ z( 9) ] ^ S[6][ z(11) ] ^ S[7][ z( 8) ] ^ S[5][ x(11) ];

	K[ 24 ] = ( S[4][ z( 3) ] ^ S[5][ z( 2) ] ^ S[6][ z(12) ] ^ S[7][ z(13) ] ^ S[4][ z( 9) ] ) & 0x1F;
	K[ 25 ] = ( S[4][ z( 1) ] ^ S[5][ z( 0) ] ^ S[6][ z(14) ] ^ S[7][ z(15) ] ^ S[5][ z(12) ] ) & 0x1F;
	K[ 26 ] = ( S[4][ z( 7) ] ^ S[5][ z( 6) ] ^ S[6][ z( 8) ] ^ S[7][ z( 9) ] ^ S[6][ z( 2) ] ) & 0x1F;
	K[ 27 ] = ( S[4][ z( 5) ] ^ S[5][ z( 4) ] ^ S[6][ z(10) ] ^ S[7][ z(11) ] ^ S[7][ z( 6) ] ) & 0x1F;

	X[0] = Z[2] ^ S[4][ z( 5) ] ^ S[5][ z( 7) ] ^ S[6][ z( 4) ] ^ S[7][ z( 6) ] ^ S[6][ z( 0) ];
	X[1] = Z[0] ^ S[4][ x( 0) ] ^ S[5][ x( 2) ] ^ S[6][ x( 1) ] ^ S[7][ x( 3) ] ^ S[7][ z( 2) ];
	X[2] = Z[1] ^ S[4][ x( 7) ] ^ S[5][ x( 6) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[4][ z( 1) ];
	X[3] = Z[3] ^ S[4][ x(10) ] ^ S[5][ x( 9) ] ^ S[6][ x(11) ] ^ S[7][ x( 8) ] ^ S[5][ z( 3) ];

	K[ 28 ] = ( S[4][ x( 8) ] ^ S[5][ x( 9) ] ^ S[6][ x( 7) ] ^ S[7][ x( 6) ] ^ S[4][ x( 3) ] ) & 0x1F;
	K[ 29 ] = ( S[4][ x(10) ] ^ S[5][ x(11) ] ^ S[6][ x( 5) ] ^ S[7][ x( 4) ] ^ S[5][ x( 7) ] ) & 0x1F;
	K[ 30 ] = ( S[4][ x(12) ] ^ S[5][ x(13) ] ^ S[6][ x( 3) ] ^ S[7][ x( 2) ] ^ S[6][ x( 8) ] ) & 0x1F;
	K[ 31 ] = ( S[4][ x(14) ] ^ S[5][ x(15) ] ^ S[6][ x( 1) ] ^ S[7][ x( 0) ] ^ S[7][ x(13) ] ) & 0x1F;
}

NAMESPACE_END
