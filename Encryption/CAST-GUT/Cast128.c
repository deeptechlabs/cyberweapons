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

/***************************************************************************/

/* The following definitions are normally handled by cryptlib, which takes
   care of issues like endianness and machine word size.  Since it's not
   possible to include all of cryptlib here, the following are equivalent
   definitions.  If you're using this outside cryptlib, you may have to
   modify them to suit your system type */

typedef unsigned char BYTE;
typedef unsigned long LONG;

#define MASK32( x )     x

#define mgetBLong(memPtr)               \
                ( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ]
<< 16 ) | \
                  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( LONG ) memPtr[ 3 ] ); \
                memPtr += 4

#define mputBLong(memPtr,data)  \
                memPtr[ 0 ] = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ); \
                memPtr[ 1 ] = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ); \
                memPtr[ 2 ] = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ); \
                memPtr[ 3 ] = ( BYTE ) ( ( data ) & 0xFF ); \
                memPtr += 4

/***************************************************************************/

#include "cast128.h"
#include "cast128s.h"

/* Left and right rotation operations.  Most decent compilers should be
   able to recognise these as rotate instructions */

#define ROTL(x,s)       ( ( ( x ) << ( s ) ) | ( ( x ) >> ( 32 - ( s ) ) ) )

/* Macros to extract 8-bit values a, b, c, d from a 32-bit value.  The cast
   is necessary because some compilers prefer ints as array indices */

#define exta(x)         ( ( int ) ( ( x >> 24 ) & 0xFF ) )
#define extb(x)         ( ( int ) ( ( x >> 16 ) & 0xFF ) )
#define extc(x)         ( ( int ) ( ( x >> 8 ) & 0xFF ) )
#define extd(x)         ( ( int ) ( ( x ) & 0xFF ) )

/* The CAST f-functions */

#define f1( data )      \
        ( ( ( S1[ exta( data ) ] ^ S2[ extb( data ) ] ) - \
                  S3[ extc( data ) ] ) + S4[ extd( data ) ] )

#define f2( data )      \
        ( ( ( S1[ exta( data ) ] - S2[ extb( data ) ] ) + \
                  S3[ extc( data ) ] ) ^ S4[ extd( data ) ] )

#define f3( data )      \
        ( ( ( S1[ exta( data ) ] + S2[ extb( data ) ] ) ^ \
                  S3[ extc( data ) ] ) - S4[ extd( data ) ] )

/* The individual encrypt/decrypt rounds */

#define round1( count, output, input )  \
        tmp = MASK32( K[ count - 1 ] + input ); \
        tmp = ROTL( tmp, K[ count + 15 ] ); \
        output ^= f1( tmp );

#define round2( count, output, input )  \
        tmp = MASK32( K[ count - 1 ] ^ input ); \
        tmp = ROTL( tmp, K[ count + 15 ] ); \
        output ^= f2( tmp );

#define round3( count, output, input )  \
        tmp = MASK32( K[ count - 1 ] - input ); \
        tmp = ROTL( tmp, K[ count + 15 ] ); \
        output ^= f3( tmp );

/* The CAST encrypt/decrypt functions */

void castEncrypt( LONG *K, BYTE *data )
        {
        BYTE *dataPtr = data;
        LONG L, R, tmp;

        L = mgetBLong( dataPtr );
        R = mgetBLong( dataPtr );

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
        round1( 13, L, R );
        round2( 14, R, L );
        round3( 15, L, R );
        round1( 16, R, L );

        dataPtr = data;
        mputBLong( dataPtr, R );
        mputBLong( dataPtr, L );
        }

void castDecrypt( LONG *K, BYTE *data )
        {
        BYTE *dataPtr = data;
        LONG L, R, tmp;

        L = mgetBLong( dataPtr );
        R = mgetBLong( dataPtr );

        /* Perform 16 rounds of decryption */
        round1( 16, L, R );
        round3( 15, R, L );
        round2( 14, L, R );
        round1( 13, R, L );
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

        dataPtr = data;
        mputBLong( dataPtr, R );
        mputBLong( dataPtr, L );
        }

/* Unpack a 32-bit value into four 8-bit values */

#define unpackBytes( value, byte1, byte2, byte3, byte4 ) \
        byte1 = exta( value ); \
        byte2 = extb( value ); \
        byte3 = extc( value ); \
        byte4 = extd( value );

/* Set up a CAST-128 key */

void castKeyInit( LONG *K, BYTE *userKey )
        {
        LONG x0x1x2x3, x4x5x6x7, x8x9xAxB, xCxDxExF;
        LONG z0z1z2z3, z4z5z6z7, z8z9zAzB, zCzDzEzF;
        int z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, zA, zB, zC, zD, zE, zF;
        int x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, xA, xB, xC, xD, xE, xF;

        /* Load the 128-bit user key into the x-values */
        x0x1x2x3 = mgetBLong( userKey );
        unpackBytes( x0x1x2x3, x0, x1, x2, x3 );
        x4x5x6x7 = mgetBLong( userKey );
        unpackBytes( x4x5x6x7, x4, x5, x6, x7 );
        x8x9xAxB = mgetBLong( userKey );
        unpackBytes( x8x9xAxB, x8, x9, xA, xB );
        xCxDxExF = mgetBLong( userKey );
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        z0z1z2z3 = x0x1x2x3 ^ S5[ xD ] ^ S6[ xF ] ^ S7[ xC ] ^ S8[ xE ] ^
S7[ x8 ];
        unpackBytes( z0z1z2z3, z0, z1, z2, z3 );
        z4z5z6z7 = x8x9xAxB ^ S5[ z0 ] ^ S6[ z2 ] ^ S7[ z1 ] ^ S8[ z3 ] ^
S8[ xA ];
        unpackBytes( z4z5z6z7, z4, z5, z6, z7 );
        z8z9zAzB = xCxDxExF ^ S5[ z7 ] ^ S6[ z6 ] ^ S7[ z5 ] ^ S8[ z4 ] ^
S5[ x9 ];
        unpackBytes( z8z9zAzB, z8, z9, zA, zB );
        zCzDzEzF = x4x5x6x7 ^ S5[ zA ] ^ S6[ z9 ] ^ S7[ zB ] ^ S8[ z8 ] ^
S6[ xB ];
        unpackBytes( zCzDzEzF, zC, zD, zE, zF );

        K[  0 ] = S5[ z8 ] ^ S6[ z9 ] ^ S7[ z7 ] ^ S8[ z6 ] ^ S5[ z2 ];
        K[  1 ] = S5[ zA ] ^ S6[ zB ] ^ S7[ z5 ] ^ S8[ z4 ] ^ S6[ z6 ];
        K[  2 ] = S5[ zC ] ^ S6[ zD ] ^ S7[ z3 ] ^ S8[ z2 ] ^ S7[ z9 ];
        K[  3 ] = S5[ zE ] ^ S6[ zF ] ^ S7[ z1 ] ^ S8[ z0 ] ^ S8[ zC ];

        x0x1x2x3 = z8z9zAzB ^ S5[ z5 ] ^ S6[ z7 ] ^ S7[ z4 ] ^ S8[ z6 ] ^
S7[ z0 ];
        unpackBytes( x0x1x2x3, x0, x1, x2, x3 );
        x4x5x6x7 = z0z1z2z3 ^ S5[ x0 ] ^ S6[ x2 ] ^ S7[ x1 ] ^ S8[ x3 ] ^
S8[ z2 ];
        unpackBytes( x4x5x6x7, x4, x5, x6, x7 );
        x8x9xAxB = z4z5z6z7 ^ S5[ x7 ] ^ S6[ x6 ] ^ S7[ x5 ] ^ S8[ x4 ] ^
S5[ z1 ];
        unpackBytes( x8x9xAxB, x8, x9, xA, xB );
        xCxDxExF = zCzDzEzF ^ S5[ xA ] ^ S6[ x9 ] ^ S7[ xB ] ^ S8[ x8 ] ^
S6[ z3 ];
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        K[  4 ] = S5[ x3 ] ^ S6[ x2 ] ^ S7[ xC ] ^ S8[ xD ] ^ S5[ x8 ];
        K[  5 ] = S5[ x1 ] ^ S6[ x0 ] ^ S7[ xE ] ^ S8[ xF ] ^ S6[ xD ];
        K[  6 ] = S5[ x7 ] ^ S6[ x6 ] ^ S7[ x8 ] ^ S8[ x9 ] ^ S7[ x3 ];
        K[  7 ] = S5[ x5 ] ^ S6[ x4 ] ^ S7[ xA ] ^ S8[ xB ] ^ S8[ x7 ];

        z0z1z2z3 = x0x1x2x3 ^ S5[ xD ] ^ S6[ xF ] ^ S7[ xC ] ^ S8[ xE ] ^
S7[ x8 ];
        unpackBytes( z0z1z2z3, z0, z1, z2, z3 );
        z4z5z6z7 = x8x9xAxB ^ S5[ z0 ] ^ S6[ z2 ] ^ S7[ z1 ] ^ S8[ z3 ] ^
S8[ xA ];
        unpackBytes( z4z5z6z7, z4, z5, z6, z7 );
        z8z9zAzB = xCxDxExF ^ S5[ z7 ] ^ S6[ z6 ] ^ S7[ z5 ] ^ S8[ z4 ] ^
S5[ x9 ];
        unpackBytes( z8z9zAzB, z8, z9, zA, zB );
        zCzDzEzF = x4x5x6x7 ^ S5[ zA ] ^ S6[ z9 ] ^ S7[ zB ] ^ S8[ z8 ] ^
S6[ xB ];
        unpackBytes( zCzDzEzF, zC, zD, zE, zF );

        K[  8 ] = S5[ z3 ] ^ S6[ z2 ] ^ S7[ zC ] ^ S8[ zD ] ^ S5[ z9 ];
        K[  9 ] = S5[ z1 ] ^ S6[ z0 ] ^ S7[ zE ] ^ S8[ zF ] ^ S6[ zC ];
        K[ 10 ] = S5[ z7 ] ^ S6[ z6 ] ^ S7[ z8 ] ^ S8[ z9 ] ^ S7[ z2 ];
        K[ 11 ] = S5[ z5 ] ^ S6[ z4 ] ^ S7[ zA ] ^ S8[ zB ] ^ S8[ z6 ];

        x0x1x2x3 = z8z9zAzB ^ S5[ z5 ] ^ S6[ z7 ] ^ S7[ z4 ] ^ S8[ z6 ] ^
S7[ z0 ];
        unpackBytes( x0x1x2x3, x0, x1, x2, x3 );
        x4x5x6x7 = z0z1z2z3 ^ S5[ x0 ] ^ S6[ x2 ] ^ S7[ x1 ] ^ S8[ x3 ] ^
S8[ z2 ];
        unpackBytes( x4x5x6x7, x4, x5, x6, x7 );
        x8x9xAxB = z4z5z6z7 ^ S5[ x7 ] ^ S6[ x6 ] ^ S7[ x5 ] ^ S8[ x4 ] ^
S5[ z1 ];
        unpackBytes( x8x9xAxB, x8, x9, xA, xB );
        xCxDxExF = zCzDzEzF ^ S5[ xA ] ^ S6[ x9 ] ^ S7[ xB ] ^ S8[ x8 ] ^
S6[ z3 ];
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        K[ 12 ] = S5[ x8 ] ^ S6[ x9 ] ^ S7[ x7 ] ^ S8[ x6 ] ^ S5[ x3 ];
        K[ 13 ] = S5[ xA ] ^ S6[ xB ] ^ S7[ x5 ] ^ S8[ x4 ] ^ S6[ x7 ];
        K[ 14 ] = S5[ xC ] ^ S6[ xD ] ^ S7[ x3 ] ^ S8[ x2 ] ^ S7[ x8 ];
        K[ 15 ] = S5[ xE ] ^ S6[ xF ] ^ S7[ x1 ] ^ S8[ x0 ] ^ S8[ xD ];

        z0z1z2z3 = x0x1x2x3 ^ S5[ xD ] ^ S6[ xF ] ^ S7[ xC ] ^ S8[ xE ] ^
S7[ x8 ];
        unpackBytes( z0z1z2z3, z0, z1, z2, z3 );
        z4z5z6z7 = x8x9xAxB ^ S5[ z0 ] ^ S6[ z2 ] ^ S7[ z1 ] ^ S8[ z3 ] ^
S8[ xA ];
        unpackBytes( z4z5z6z7, z4, z5, z6, z7 );
        z8z9zAzB = xCxDxExF ^ S5[ z7 ] ^ S6[ z6 ] ^ S7[ z5 ] ^ S8[ z4 ] ^
S5[ x9 ];
        unpackBytes( z8z9zAzB, z8, z9, zA, zB );
        zCzDzEzF = x4x5x6x7 ^ S5[ zA ] ^ S6[ z9 ] ^ S7[ zB ] ^ S8[ z8 ] ^
S6[ xB ];
        unpackBytes( zCzDzEzF, zC, zD, zE, zF );
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        K[ 16 ] = ( S5[ z8 ] ^ S6[ z9 ] ^ S7[ z7 ] ^ S8[ z6 ] ^ S5[ z2 ] )
& 0x1F;
        K[ 17 ] = ( S5[ zA ] ^ S6[ zB ] ^ S7[ z5 ] ^ S8[ z4 ] ^ S6[ z6 ] )
& 0x1F;
        K[ 18 ] = ( S5[ zC ] ^ S6[ zD ] ^ S7[ z3 ] ^ S8[ z2 ] ^ S7[ z9 ] )
& 0x1F;
        K[ 19 ] = ( S5[ zE ] ^ S6[ zF ] ^ S7[ z1 ] ^ S8[ z0 ] ^ S8[ zC ] )
& 0x1F;

        x0x1x2x3 = z8z9zAzB ^ S5[ z5 ] ^ S6[ z7 ] ^ S7[ z4 ] ^ S8[ z6 ] ^
S7[ z0 ];
        unpackBytes( x0x1x2x3, x0, x1, x2, x3 );
        x4x5x6x7 = z0z1z2z3 ^ S5[ x0 ] ^ S6[ x2 ] ^ S7[ x1 ] ^ S8[ x3 ] ^
S8[ z2 ];
        unpackBytes( x4x5x6x7, x4, x5, x6, x7 );
        x8x9xAxB = z4z5z6z7 ^ S5[ x7 ] ^ S6[ x6 ] ^ S7[ x5 ] ^ S8[ x4 ] ^
S5[ z1 ];
        unpackBytes( x8x9xAxB, x8, x9, xA, xB );
        xCxDxExF = zCzDzEzF ^ S5[ xA ] ^ S6[ x9 ] ^ S7[ xB ] ^ S8[ x8 ] ^
S6[ z3 ];
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        K[ 20 ] = ( S5[ x3 ] ^ S6[ x2 ] ^ S7[ xC ] ^ S8[ xD ] ^ S5[ x8 ] )
& 0x1F;
        K[ 21 ] = ( S5[ x1 ] ^ S6[ x0 ] ^ S7[ xE ] ^ S8[ xF ] ^ S6[ xD ] )
& 0x1F;
        K[ 22 ] = ( S5[ x7 ] ^ S6[ x6 ] ^ S7[ x8 ] ^ S8[ x9 ] ^ S7[ x3 ] )
& 0x1F;
        K[ 23 ] = ( S5[ x5 ] ^ S6[ x4 ] ^ S7[ xA ] ^ S8[ xB ] ^ S8[ x7 ] )
& 0x1F;

        z0z1z2z3 = x0x1x2x3 ^ S5[ xD ] ^ S6[ xF ] ^ S7[ xC ] ^ S8[ xE ] ^
S7[ x8 ];
        unpackBytes( z0z1z2z3, z0, z1, z2, z3 );
        z4z5z6z7 = x8x9xAxB ^ S5[ z0 ] ^ S6[ z2 ] ^ S7[ z1 ] ^ S8[ z3 ] ^
S8[ xA ];
        unpackBytes( z4z5z6z7, z4, z5, z6, z7 );
        z8z9zAzB = xCxDxExF ^ S5[ z7 ] ^ S6[ z6 ] ^ S7[ z5 ] ^ S8[ z4 ] ^
S5[ x9 ];
        unpackBytes( z8z9zAzB, z8, z9, zA, zB );
        zCzDzEzF = x4x5x6x7 ^ S5[ zA ] ^ S6[ z9 ] ^ S7[ zB ] ^ S8[ z8 ] ^
S6[ xB ];
        unpackBytes( zCzDzEzF, zC, zD, zE, zF );

        K[ 24 ] = ( S5[ z3 ] ^ S6[ z2 ] ^ S7[ zC ] ^ S8[ zD ] ^ S5[ z9 ] )
& 0x1F;
        K[ 25 ] = ( S5[ z1 ] ^ S6[ z0 ] ^ S7[ zE ] ^ S8[ zF ] ^ S6[ zC ] )
& 0x1F;
        K[ 26 ] = ( S5[ z7 ] ^ S6[ z6 ] ^ S7[ z8 ] ^ S8[ z9 ] ^ S7[ z2 ] )
& 0x1F;
        K[ 27 ] = ( S5[ z5 ] ^ S6[ z4 ] ^ S7[ zA ] ^ S8[ zB ] ^ S8[ z6 ] )
& 0x1F;

        x0x1x2x3 = z8z9zAzB ^ S5[ z5 ] ^ S6[ z7 ] ^ S7[ z4 ] ^ S8[ z6 ] ^
S7[ z0 ];
        unpackBytes( x0x1x2x3, x0, x1, x2, x3 );
        x4x5x6x7 = z0z1z2z3 ^ S5[ x0 ] ^ S6[ x2 ] ^ S7[ x1 ] ^ S8[ x3 ] ^
S8[ z2 ];
        unpackBytes( x4x5x6x7, x4, x5, x6, x7 );
        x8x9xAxB = z4z5z6z7 ^ S5[ x7 ] ^ S6[ x6 ] ^ S7[ x5 ] ^ S8[ x4 ] ^
S5[ z1 ];
        unpackBytes( x8x9xAxB, x8, x9, xA, xB );
        xCxDxExF = zCzDzEzF ^ S5[ xA ] ^ S6[ x9 ] ^ S7[ xB ] ^ S8[ x8 ] ^
S6[ z3 ];
        unpackBytes( xCxDxExF, xC, xD, xE, xF );

        K[ 28 ] = ( S5[ x8 ] ^ S6[ x9 ] ^ S7[ x7 ] ^ S8[ x6 ] ^ S5[ x3 ] )
& 0x1F;
        K[ 29 ] = ( S5[ xA ] ^ S6[ xB ] ^ S7[ x5 ] ^ S8[ x4 ] ^ S6[ x7 ] )
& 0x1F;
        K[ 30 ] = ( S5[ xC ] ^ S6[ xD ] ^ S7[ x3 ] ^ S8[ x2 ] ^ S7[ x8 ] )
& 0x1F;
        K[ 31 ] = ( S5[ xE ] ^ S6[ xF ] ^ S7[ x1 ] ^ S8[ x0 ] ^ S8[ xD ] )
& 0x1F;
        }