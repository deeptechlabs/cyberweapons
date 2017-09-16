/* This code is copyright 1997 by John T. Barton <barton@best.com>.  
   It may be used for any purpose, either personal or commercial, 
   with the restrictions that this header must be retained, that
   the author will not be held liable for any damages that may result
   from use of this code, and that any documentation for a product using
   this code must give credit to the author.
   This implementation of CAST-128 was based on "Constructing Symmetric 
   Ciphers Using the CAST Design Procedure", by Carlisle M. Adams.  
*/

/* 2011-04-27: Code updated to be 64-bit arch safe by changing
   type declarations to use stdint.h. The code has also been updated
   to fix errors and warnings as found by the clang compiler.

   Updates done by Joachim Strömbergson - Secworks Sweden AB
*/

/* #define DEBUG */

/* un-comment this to get the slower, non-unrolled version 
     the unrolled version runs faster, but the non-unrolled version 
     may be preferable if doing research on variations of the algorithm */
/* #define ROLL */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

typedef uint8_t  BYTE;
typedef uint32_t LONG;

/* This can be varied at will - 16 is the recommended and official value
for CAST-128 */
#define ROUNDS			16

#define CAST_BLOCKSIZE		8       /* 8 bytes per block */
#define CAST_KEYSIZE		16      /* 16 byte = 128 bit key */
#define CAST_SBOX_SIZE		256	/* Number of S-box LONG entries, = 2 **
CAST_BLOCKSIZE  */
#define CAST_LONGS_PER_KEY      ( CAST_KEYSIZE / sizeof( LONG ) )
#define TEST_PLAINTEXT	  "\x01\x23\x45\x67\x89\xab\xcd\xef"
#define TEST_CIPHERTEXT	  "\x23\x8b\x4f\xe5\x84\x7e\x44\xb2"
#define REFA "\xEE\xA9\xD0\xA2\x49\xFD\x3B\xA6\xB3\x43\x6F\xB8\x9D\x6D\xCA\x92"
#define REFB "\xB2\xC9\x5E\xB0\x0C\x31\xAD\x71\x80\xAC\x05\xB8\xE8\x3D\x69\x6E"

/* These macros assume CAST_BLOCKSIZE = 8 */
#define mgetLong(memPtr)		\
	( ( ( LONG ) memPtr[ 0 ] << 24 ) | ( ( LONG ) memPtr[ 1 ] << 16 ) | \
	  ( ( LONG ) memPtr[ 2 ] << 8 ) | ( LONG ) memPtr[ 3 ] ); \
	memPtr += 4
#define mputLong(memPtr,data)	\
	*memPtr++ = ( BYTE ) ( ( ( data ) >> 24 ) & 0xFF ), \
	*memPtr++ = ( BYTE ) ( ( ( data ) >> 16 ) & 0xFF ), \
	*memPtr++ = ( BYTE ) ( ( ( data ) >> 8 ) & 0xFF ), \
	*memPtr++ = ( BYTE ) ( ( data ) & 0xFF )
#define exta(x)		( ( int ) ( ( x >> 24 ) & 0xFF ) )
#define extb(x)		( ( int ) ( ( x >> 16 ) & 0xFF ) )
#define extc(x)		( ( int ) ( ( x >> 8 ) & 0xFF ) )
#define extd(x)		( ( int ) ( ( x ) & 0xFF ) )

/* Macro for LONG left rotates, 32 = 8*sizeof( LONG ) */
#define ROL(x,n)	( ( x << n ) | ( x >> (32 - n ) ) )

/* The values for LONG S1[ CAST_SBOX_SIZE ] ... to ...  S8[ CAST_SBOX_SIZE] */
#include "cast_tab.h"


/* The CAST-128 key scheduling of Km, Kr */

void CASTinit( BYTE *key, LONG *Km, LONG *Kr ) {
   int32_t i ;
   BYTE *data ;
   LONG zlong[ CAST_LONGS_PER_KEY ], keylong[ CAST_LONGS_PER_KEY ], 
   	K[ ROUNDS * 2 + 1 ] ;
   BYTE z[ CAST_KEYSIZE ] ;

   
   data = (BYTE *)malloc( sizeof( LONG ) ) ; 

   /* put the key into LONGs */
   for ( i= 0; i < 4; i++ ) { keylong[ i ] = mgetLong( key ) ; }
   key -= CAST_KEYSIZE ;

   zlong[ 0 ] = keylong[ 0 ] ^ S5[ key[ 13 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[
12 ] ] ^ S8[ key[ 14 ] ] ^ S7[ key[ 8 ] ] ;
   mputLong( data, zlong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[ i
] = data[ i ] ; 
   zlong[ 1 ] = keylong[ 2 ] ^ S5[ z[ 0 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 1 ] ] ^
S8[ z[ 3 ] ] ^ S8[ key[ 10 ] ] ;

   mputLong( data, zlong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+4 ] = data[ i ] ;   
   zlong[ 2 ] = keylong[ 3 ] ^ S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 5 ] ] ^
S8[ z[ 4 ] ] ^ S5[ key[ 9 ] ] ;
   mputLong( data, zlong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+8 ] = data[ i ] ;   
   zlong[ 3 ] = keylong[ 1 ] ^ S5[ z[ 10 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 11 ] ]
^ S8[ z[ 8 ] ] ^ S6[ key[ 11 ] ] ;
   mputLong( data, zlong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+12 ] = data[ i ] ;   

   K[ 1 ] = S5[ z[ 8 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 7 ] ] ^ S8[ z[ 6 ] ] ^ S5[
z[ 2 ] ] ;
   
   K[ 2 ] = S5[ z[ 10 ] ] ^ S6[ z[ 11 ] ] ^ S7[ z[ 5 ] ] ^ S8[ z[ 4 ] ] ^
S6[ z[ 6 ] ] ;
   
   K[ 3 ] = S5[ z[ 12 ] ] ^ S6[ z[ 13 ] ] ^ S7[ z[ 3 ] ] ^ S8[ z[ 2 ] ] ^
S7[ z[ 9 ] ] ;
   
   K[ 4 ] = S5[ z[ 14 ] ] ^ S6[ z[ 15 ] ] ^ S7[ z[ 1 ] ] ^ S8[ z[ 0 ] ] ^
S8[ z[ 12 ] ] ;
   
   keylong[ 0 ] = zlong[ 2 ] ^ S5[ z[ 5 ] ] ^ S6[ z[ 7 ] ] ^ S7[ z[ 4 ] ] ^
S8[ z[ 6 ] ] ^ S7[ z[ 0 ] ] ;
   mputLong( data, keylong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i ] = data[ i ] ;      
   keylong[ 1 ] = zlong[ 0 ] ^ S5[ key[ 0 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 1
] ] ^ S8[ key[ 3 ] ] ^ S8[ z[ 2 ] ] ;
   mputLong( data, keylong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+4 ] = data[ i ] ;   
   keylong[ 2 ] = zlong[ 1 ] ^ S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 5
] ] ^ S8[ key[ 4 ] ] ^ S5[ z[ 1 ] ] ;
   mputLong( data, keylong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+8 ] = data[ i ] ;   
   keylong[ 3 ] = zlong[ 3 ] ^ S5[ key[ 10 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[
11 ] ] ^ S8[ key[ 8 ] ] ^ S6[ z[ 3 ] ] ;
   mputLong( data, keylong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+12 ] = data[ i ] ;   

   K[ 5 ] = S5[ key[ 3 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 12 ] ] ^ S8[ key[ 13
] ] ^ S5[ key[ 8 ] ] ;
   
   K[ 6 ] = S5[ key[ 1 ] ] ^ S6[ key[ 0 ] ] ^ S7[ key[ 14 ] ] ^ S8[ key[ 15
] ] ^ S6[ key[ 13 ] ] ;
   
   K[ 7 ] = S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 8 ] ] ^ S8[ key[ 9 ]
] ^ S7[ key[ 3 ] ] ;
   
   K[ 8 ] = S5[ key[ 5 ] ] ^ S6[ key[ 4 ] ] ^ S7[ key[ 10 ] ] ^ S8[ key[ 11
] ] ^ S8[ key[ 7 ] ] ;
   
   zlong[ 0 ] = keylong[ 0 ] ^ S5[ key[ 13 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[
12 ] ] ^ S8[ key[ 14 ] ] ^ S7[ key[ 8 ] ] ;
   mputLong( data, zlong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[ i
] = data[ i ] ;   
   zlong[ 1 ] = keylong[ 2 ] ^ S5[ z[ 0 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 1 ] ] ^
S8[ z[ 3 ] ] ^ S8[ key[ 10 ] ] ;
   mputLong( data, zlong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+4 ] = data[ i ] ;   
   zlong[ 2 ] = keylong[ 3 ] ^ S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 5 ] ] ^
S8[ z[ 4 ] ] ^ S5[ key[ 9 ] ] ;
   mputLong( data, zlong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+8 ] = data[ i ] ;   
   zlong[ 3 ] = keylong[ 1 ] ^ S5[ z[ 10 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 11 ] ]
^ S8[ z[ 8 ] ] ^ S6[ key[ 11 ] ] ;
   mputLong( data, zlong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+12 ] = data[ i ] ;   

   K[ 9 ] = S5[ z[ 3 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 12 ] ] ^ S8[ z[ 13 ] ] ^
S5[ z[ 9 ] ] ;
   

   K[ 10 ] = S5[ z[ 1 ] ] ^ S6[ z[ 0 ] ] ^ S7[ z[ 14 ] ] ^ S8[ z[ 15 ] ] ^
S6[ z[ 12 ] ] ;
   
   K[ 11 ] = S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 8 ] ] ^ S8[ z[ 9 ] ] ^
S7[ z[ 2 ] ] ;
   
   K[ 12 ] = S5[ z[ 5 ] ] ^ S6[ z[ 4 ] ] ^ S7[ z[ 10 ] ] ^ S8[ z[ 11 ] ] ^
S8[ z[ 6 ] ] ;
   
   keylong[ 0 ] = zlong[ 2 ] ^ S5[ z[ 5 ] ] ^ S6[ z[ 7 ] ] ^ S7[ z[ 4 ] ] ^
S8[ z[ 6 ] ] ^ S7[ z[ 0 ] ] ;
      mputLong( data, keylong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i ] = data[ i ] ;   
   keylong[ 1 ] = zlong[ 0 ] ^ S5[ key[ 0 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 1
] ] ^ S8[ key[ 3 ] ] ^ S8[ z[ 2 ] ] ;
      mputLong( data, keylong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+4 ] = data[ i ] ;   
   keylong[ 2 ] = zlong[ 1 ] ^ S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 5
] ] ^ S8[ key[ 4 ] ] ^ S5[ z[ 1 ] ] ;
      mputLong( data, keylong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+8 ] = data[ i ] ;   
   keylong[ 3 ] = zlong[ 3 ] ^ S5[ key[ 10 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[
11 ] ] ^ S8[ key[ 8 ] ] ^ S6[ z[ 3 ] ] ;
      mputLong( data, keylong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+12 ] = data[ i ] ;   

   K[ 13 ] = S5[ key[ 8 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[ 7 ] ] ^ S8[ key[ 6
] ] ^ S5[ key[ 3 ] ] ;
   
   K[ 14 ] = S5[ key[ 10 ] ] ^ S6[ key[ 11 ] ] ^ S7[ key[ 5 ] ] ^ S8[ key[
4 ] ] ^ S6[ key[ 7 ] ] ;
   
   K[ 15 ] = S5[ key[ 12 ] ] ^ S6[ key[ 13 ] ] ^ S7[ key[ 3 ] ] ^ S8[ key[
2 ] ] ^ S7[ key[ 8 ] ] ;
   
   K[ 16 ] = S5[ key[ 14 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[ 1 ] ] ^ S8[ key[
0 ] ] ^ S8[ key[ 13 ] ] ;
   
/*
   [The remaining half is identical to what is given above, carrying on
   from the last created x0..xF to generate keys K[ 17 ] - K[ 32 ].] 
*/
   
   zlong[ 0 ] = keylong[ 0 ] ^ S5[ key[ 13 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[
12 ] ] ^ S8[ key[ 14 ] ] ^ S7[ key[ 8 ] ] ;
      mputLong( data, zlong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
z[ i ] = data[ i ] ;   
   zlong[ 1 ] = keylong[ 2 ] ^ S5[ z[ 0 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 1 ] ] ^
S8[ z[ 3 ] ] ^ S8[ key[ 10 ] ] ;
      mputLong( data, zlong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
z[ i+4 ] = data[ i ] ;   
   zlong[ 2 ] = keylong[ 3 ] ^ S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 5 ] ] ^
S8[ z[ 4 ] ] ^ S5[ key[ 9 ] ] ;
      mputLong( data, zlong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
z[ i+8 ] = data[ i ] ;   
   zlong[ 3 ] = keylong[ 1 ] ^ S5[ z[ 10 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 11 ] ]
^ S8[ z[ 8 ] ] ^ S6[ key[ 11 ] ] ;
      mputLong( data, zlong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
z[ i+12 ] = data[ i ] ;   

   K[ 17 ] = S5[ z[ 8 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 7 ] ] ^ S8[ z[ 6 ] ] ^
S5[ z[ 2 ] ] ;
   
   K[ 18 ] = S5[ z[ 10 ] ] ^ S6[ z[ 11 ] ] ^ S7[ z[ 5 ] ] ^ S8[ z[ 4 ] ] ^
S6[ z[ 6 ] ] ;
   
   K[ 19 ] = S5[ z[ 12 ] ] ^ S6[ z[ 13 ] ] ^ S7[ z[ 3 ] ] ^ S8[ z[ 2 ] ] ^
S7[ z[ 9 ] ] ;
   
   K[ 20 ] = S5[ z[ 14 ] ] ^ S6[ z[ 15 ] ] ^ S7[ z[ 1 ] ] ^ S8[ z[ 0 ] ] ^
S8[ z[ 12 ] ] ;
   
   keylong[ 0 ] = zlong[ 2 ] ^ S5[ z[ 5 ] ] ^ S6[ z[ 7 ] ] ^ S7[ z[ 4 ] ] ^
S8[ z[ 6 ] ] ^ S7[ z[ 0 ] ] ;
   mputLong( data, keylong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i ] = data[ i ] ;      
   keylong[ 1 ] = zlong[ 0 ] ^ S5[ key[ 0 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 1
] ] ^ S8[ key[ 3 ] ] ^ S8[ z[ 2 ] ] ;

   mputLong( data, keylong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+4 ] = data[ i ] ;   
   keylong[ 2 ] = zlong[ 1 ] ^ S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 5
] ] ^ S8[ key[ 4 ] ] ^ S5[ z[ 1 ] ] ;
   mputLong( data, keylong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+8 ] = data[ i ] ;   
   keylong[ 3 ] = zlong[ 3 ] ^ S5[ key[ 10 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[
11 ] ] ^ S8[ key[ 8 ] ] ^ S6[ z[ 3 ] ] ;
   mputLong( data, keylong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+12 ] = data[ i ] ;   

   K[ 21 ] = S5[ key[ 3 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 12 ] ] ^ S8[ key[
13 ] ] ^ S5[ key[ 8 ] ] ;
   
   K[ 22 ] = S5[ key[ 1 ] ] ^ S6[ key[ 0 ] ] ^ S7[ key[ 14 ] ] ^ S8[ key[
15 ] ] ^ S6[ key[ 13 ] ] ;
   
   K[ 23 ] = S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 8 ] ] ^ S8[ key[ 9
] ] ^ S7[ key[ 3 ] ] ;
   
   K[ 24 ] = S5[ key[ 5 ] ] ^ S6[ key[ 4 ] ] ^ S7[ key[ 10 ] ] ^ S8[ key[
11 ] ] ^ S8[ key[ 7 ] ] ;
   
   zlong[ 0 ] = keylong[ 0 ] ^ S5[ key[ 13 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[
12 ] ] ^ S8[ key[ 14 ] ] ^ S7[ key[ 8 ] ] ;
   mputLong( data, zlong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[ i
] = data[ i ] ;      
   zlong[ 1 ] = keylong[ 2 ] ^ S5[ z[ 0 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 1 ] ] ^
S8[ z[ 3 ] ] ^ S8[ key[ 10 ] ] ;
   mputLong( data, zlong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+4 ] = data[ i ] ;   
   zlong[ 2 ] = keylong[ 3 ] ^ S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 5 ] ] ^
S8[ z[ 4 ] ] ^ S5[ key[ 9 ] ] ;
   mputLong( data, zlong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+8 ] = data[ i ] ;   
   zlong[ 3 ] = keylong[ 1 ] ^ S5[ z[ 10 ] ] ^ S6[ z[ 9 ] ] ^ S7[ z[ 11 ] ]
^ S8[ z[ 8 ] ] ^ S6[ key[ 11 ] ] ;
   mputLong( data, zlong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)  z[
i+12 ] = data[ i ] ;   

   K[ 25 ] = S5[ z[ 3 ] ] ^ S6[ z[ 2 ] ] ^ S7[ z[ 12 ] ] ^ S8[ z[ 13 ] ] ^
S5[ z[ 9 ] ] ;
   
   K[ 26 ] = S5[ z[ 1 ] ] ^ S6[ z[ 0 ] ] ^ S7[ z[ 14 ] ] ^ S8[ z[ 15 ] ] ^
S6[ z[ 12 ] ] ;
   
   K[ 27 ] = S5[ z[ 7 ] ] ^ S6[ z[ 6 ] ] ^ S7[ z[ 8 ] ] ^ S8[ z[ 9 ] ] ^
S7[ z[ 2 ] ] ;
   
   K[ 28 ] = S5[ z[ 5 ] ] ^ S6[ z[ 4 ] ] ^ S7[ z[ 10 ] ] ^ S8[ z[ 11 ] ] ^
S8[ z[ 6 ] ] ;
   
   keylong[ 0 ] = zlong[ 2 ] ^ S5[ z[ 5 ] ] ^ S6[ z[ 7 ] ] ^ S7[ z[ 4 ] ] ^
S8[ z[ 6 ] ] ^ S7[ z[ 0 ] ] ;
   mputLong( data, keylong [ 0 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i ] = data[ i ] ;   
   keylong[ 1 ] = zlong[ 0 ] ^ S5[ key[ 0 ] ] ^ S6[ key[ 2 ] ] ^ S7[ key[ 1
] ] ^ S8[ key[ 3 ] ] ^ S8[ z[ 2 ] ] ;
   mputLong( data, keylong [ 1 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+4 ] = data[ i ] ;   
   keylong[ 2 ] = zlong[ 1 ] ^ S5[ key[ 7 ] ] ^ S6[ key[ 6 ] ] ^ S7[ key[ 5
] ] ^ S8[ key[ 4 ] ] ^ S5[ z[ 1 ] ] ;
   mputLong( data, keylong [ 2 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+8 ] = data[ i ] ;   
   keylong[ 3 ] = zlong[ 3 ] ^ S5[ key[ 10 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[
11 ] ] ^ S8[ key[ 8 ] ] ^ S6[ z[ 3 ] ] ;
   mputLong( data, keylong [ 3 ]  ) ; data -= 4 ; for( i=0; i < 4; i++)
key[ i+12 ] = data[ i ] ;   

   K[ 29 ] = S5[ key[ 8 ] ] ^ S6[ key[ 9 ] ] ^ S7[ key[ 7 ] ] ^ S8[ key[ 6
] ] ^ S5[ key[ 3 ] ] ;
   

   K[ 30 ] = S5[ key[ 10 ] ] ^ S6[ key[ 11 ] ] ^ S7[ key[ 5 ] ] ^ S8[ key[
4 ] ] ^ S6[ key[ 7 ] ] ;
   
   K[ 31 ] = S5[ key[ 12 ] ] ^ S6[ key[ 13 ] ] ^ S7[ key[ 3 ] ] ^ S8[ key[
2 ] ] ^ S7[ key[ 8 ] ] ;
   
   K[ 32 ] = S5[ key[ 14 ] ] ^ S6[ key[ 15 ] ] ^ S7[ key[ 1 ] ] ^ S8[ key[
0 ] ] ^ S8[ key[ 13 ] ] ;
   
   for (i = 1; i <= ROUNDS; i++) { Km[ i ] = K[ i ]; Kr[ i ]  = ( K[ 16+i ]
& 0x1f ) ; } 

#ifdef DEBUG
   for (i = 1; i <= ROUNDS; i++) 
      printf( "Km[ %d ] = %08X, Kr[ %d ] = %08X \n", i, Km[i], i, Kr[i] ) ;
#endif

   /* clear all sensitive data, including the 128 bit key */
   memset( K, 0, (ROUNDS*2 + 1) * sizeof( LONG ) ) ;
   memset( zlong, 0, CAST_LONGS_PER_KEY * sizeof( LONG ) ) ;
   memset( keylong, 0, CAST_LONGS_PER_KEY * sizeof( LONG ) ) ;
   memset( z, 0, CAST_KEYSIZE * sizeof( BYTE ) ) ;
   memset( data, 0, sizeof( LONG ) ) ;
   memset( key, 0, CAST_KEYSIZE * sizeof( BYTE ) ) ;

   free( data ) ; 

}

void feist( int r, LONG data, LONG *out, LONG *Km, LONG *Kr ) {
   LONG A, B ;

   switch ( r % 3 ) {
   case 1  :
     A =  Km[ r ] + data ;
     A = ROL( A , (int32_t)Kr[ r ] ) ;
     B =  ( ( S1[ exta( A ) ] ^ S2[ extb( A )  ] ) - S3[ extc( A ) ] ) +
S4[ extd( A ) ] ;
     break ;

   case 2 :
     A =  ( Km[ r ] ^ data ) ;
     A = ROL( A , (int32_t)Kr[ r ] ) ;
     B =  ( ( S1[ exta( A ) ] - S2[ extb( A )  ] ) + S3[ extc( A ) ] ) ^
S4[ extd( A ) ] ;
     break ;

   case 0 :
     A = Km[ r ] - data ;
     A = ROL( A , (int32_t)Kr[ r ] ) ;
     B =  ( ( S1[ exta( A ) ] + S2[ extb( A )  ] ) ^ S3[ extc( A ) ] ) -
S4[ extd( A ) ] ;
     break ;

   default :
     printf( "should not get here!!! \n" ) ;
     exit( -1 ) ;
  }
   *out = B ;
}

void CASTencrypt( BYTE *data, LONG *Km, LONG *Kr ) {
	LONG A, B, T, BPTR[1] ;
	int32_t i ;

	B = mgetLong( data ); A = mgetLong( data ); data -= CAST_BLOCKSIZE ;
#ifndef ROLL
	T = Km[ 1 ] + A ;
	T = ROL( T , (int32_t)Kr[ 1 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T = Km[ 2 ] ^ B ;
	T = ROL( T , (int32_t)Kr[ 2 ] ) ;
	A ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T = Km[ 3 ] - A ;
	T = ROL( T , (int32_t)Kr[ 3 ] ) ;
	B ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T =  Km[ 4 ] + B ;
	T = ROL( T , (int32_t)Kr[ 4 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T =  Km[ 5 ] ^ A ;
	T = ROL( T , (int32_t)Kr[ 5 ] ) ;
	B ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 6 ] - B ;
	T = ROL( T , (int32_t)Kr[ 6 ] ) ;
	A ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T = Km[ 7 ] + A ;
	T = ROL( T , (int32_t)Kr[ 7 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T = Km[ 8 ] ^ B ;
	T = ROL( T , (int32_t)Kr[ 8 ] ) ;
	A ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T = Km[ 9 ] - A ;
	T = ROL( T , (int32_t)Kr[ 9 ] ) ;
	B ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;


	T =  Km[ 10 ] + B ;
	T = ROL( T , (int32_t)Kr[ 10 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T = Km[ 11 ] ^ A ;
	T = ROL( T , (int32_t)Kr[ 11 ] ) ;
	B ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 12 ] - B ;
	T = ROL( T , (int32_t)Kr[ 12 ] ) ;
	A ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T =  Km[ 13 ] + A ;
	T = ROL( T , (int32_t)Kr[ 13 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T =  Km[ 14 ] ^ B ;
	T = ROL( T , (int32_t)Kr[ 14 ] ) ;
	A ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 15 ] - A ;
	T = ROL( T, (int32_t)Kr[ 15 ] ) ;
	B ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T =  Km[ 16 ] + B ;
	T = ROL( T , (int32_t)Kr[ 16 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
#else
	for ( i = 1; i <= ROUNDS ; i++ ) {
	   feist( i, A, BPTR, Km, Kr ) ;
	   B ^= BPTR[0] ;
	   T = A ; A = B ; B = T ;
	}
#endif
	mputLong( data, A ); mputLong( data, B );
	data -= CAST_BLOCKSIZE ;
     }

void CASTdecrypt( BYTE *data, LONG *Km, LONG *Kr ) {
	LONG A, B, T, BPTR[1] ;
	int32_t i ;

	B = mgetLong( data ); A = mgetLong( data ); data -= CAST_BLOCKSIZE ;
#ifndef ROLL

	T =  Km[ 16 ] + A ;
	T = ROL( T , (int32_t)Kr[ 16 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T =  Km[ 15 ] - B ;
	T = ROL( T, (int32_t)Kr[ 15 ] ) ;
	A ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T =  Km[ 14 ] ^ A ;
	T = ROL( T , (int32_t)Kr[ 14 ] ) ;
	B ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 13 ] + B ;
	T = ROL( T , (int32_t)Kr[ 13 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T =  Km[ 12 ] - A ;
	T = ROL( T , (int32_t)Kr[ 12 ] ) ;
	B ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T = Km[ 11 ] ^ B ;
	T = ROL( T , (int32_t)Kr[ 11 ] ) ;
	A ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 10 ] + A ;
	T = ROL( T , (int32_t)Kr[ 10 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;

	T = Km[ 9 ] - B ;
	T = ROL( T , (int32_t)Kr[ 9 ] ) ;
	A ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T = Km[ 8 ] ^ A ;
	T = ROL( T , (int32_t)Kr[ 8 ] ) ;
	B ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T = Km[ 7 ] + B ;
	T = ROL( T , (int32_t)Kr[ 7 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;
	T =  Km[ 6 ] - A ;
	T = ROL( T , (int32_t)Kr[ 6 ] ) ;
	B ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T =  Km[ 5 ] ^ B ;
	T = ROL( T , (int32_t)Kr[ 5 ] ) ;
	A ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T =  Km[ 4 ] + A ;
	T = ROL( T , (int32_t)Kr[ 4 ] ) ;
	B ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;

	T = Km[ 3 ] - B ;
	T = ROL( T , (int32_t)Kr[ 3 ] ) ;
	A ^= ( ( S1[ exta( T ) ] + S2[ extb( T )  ] ) ^ S3[ extc( T ) ] ) - S4[
extd( T ) ] ;
	T = Km[ 2 ] ^ A ;
	T = ROL( T , (int32_t)Kr[ 2 ] ) ;
	B ^= ( ( S1[ exta( T ) ] - S2[ extb( T )  ] ) + S3[ extc( T ) ] ) ^ S4[
extd( T ) ] ;
	T = Km[ 1 ] + B ;
	T = ROL( T , (int32_t)Kr[ 1 ] ) ;
	A ^= ( ( S1[ exta( T ) ] ^ S2[ extb( T )  ] ) - S3[ extc( T ) ] ) + S4[
extd( T ) ] ;

#else
	for ( i = ROUNDS; i >= 1; i-- ) {
	   feist( i, A, BPTR, Km, Kr ) ;
	   B ^= BPTR[0] ;
	   T = A ; A = B ; B = T ;
	}
#endif
	mputLong( data, A ); mputLong( data, B );
	data -= CAST_BLOCKSIZE ;
     }

int main( int argc, char **argv ) {
   int32_t i, iter, maintflag = 0 ;
   int32_t j, maint_iter ;
   BYTE *data ;
   /* 128-bit tst case key = 01 23 45 67 12 34 56 78 23 45 67 89 34 56 78
9A (hex) */
   BYTE test_key[ CAST_KEYSIZE ] = { 0x01, 0x23, 0x45, 0x67, 0x12, 0x34,
0x56, 0x78, \
		   0x23, 0x45, 0x67, 0x89, 0x34, 0x56, 0x78, 0x9A } ;
   BYTE key[CAST_KEYSIZE], aL[ CAST_BLOCKSIZE ], aR[ CAST_BLOCKSIZE ], bL[
CAST_BLOCKSIZE ], bR[ CAST_BLOCKSIZE ], ref[ CAST_KEYSIZE ] ;
   LONG Km[ ROUNDS+1 ], Kr[ ROUNDS+1 ] ;

   if ( argc == 1 ) {
      printf( "usage: cast [ n | -x | -y ] \n" ) ;
      printf( "n (integer) will encrypt n times (useful for timing tests) \n" ) ;
      printf( "   -x will test the code by encrypting once (and print out the reference vector) \n" ) ;
      printf( "       and then run the 1000000 iteration Full Maintenance Test (with reference output)\n" ) ;
      printf( "   -y will test the code by encrypting once (and print out the reference vector) \n" ) ;
      printf( "       and then run a shortened 1000 iteration Partial Maintenance Test (with reference output)\n" ) ;
      printf( "       ( which is more convenient for debugging than the Full test \n" ) ;
      printf( "This code is an implementation of CAST-128 \n" ) ;
      exit( 0 ) ;
   }
   if ( strcmp( argv[1], "-x" ) == 0 ) maintflag = 1 ;
   if ( strcmp( argv[1], "-y" ) == 0 ) maintflag = 2 ;

   data = (BYTE *)malloc( CAST_BLOCKSIZE ) ;
   memcpy( key, test_key, CAST_KEYSIZE ) ; 

   printf( "key is: " ) ;
   for ( i = 0; i < CAST_KEYSIZE; i++ ) printf( " %02x", key[ i ] ) ;
printf( "\n" ) ; printf( "\n" ) ;

   CASTinit( key, Km, Kr ) ;

   memcpy( ref, TEST_PLAINTEXT, CAST_BLOCKSIZE ) ;
   memcpy( data, TEST_PLAINTEXT, CAST_BLOCKSIZE ) ;
   printf( "Single Key-Plaintext-Ciphertext Test:\n" ) ;
   printf( "plaintext is:  " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", ref[ i ] ) ;
printf( "\n" ) ;

   if ( maintflag == 0 ) iter = atoi( argv[1] ) ; 
   else iter = 1 ;
   printf( "iter = %d \n", iter ) ;
   for ( i = 0; i < iter; i++ ) CASTencrypt( data, Km, Kr ) ;

   printf( "ciphertext is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", data[ i ] ) ;
printf( "\n" ) ;

   memcpy( ref, TEST_CIPHERTEXT, CAST_BLOCKSIZE ) ;
   printf( "ref   text is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", ref[ i ] ) ;
printf( "\n" ) ; 
/*
   if ( memcmp( TEST_PLAINTEXT, TEST_CIPHERTEXT, CAST_BLOCKSIZE ) ) printf(
"Test succeeded \n" ) ;
   else { printf( "Test failed! \n" ) ; exit( -1 ) ; } 

*/
   for ( i = 0; i < iter; i++ ) CASTdecrypt( data, Km, Kr ) ;

   printf( "after decryption: \n" ) ;
   printf( "ciphertext is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", data[ i ] ) ;
printf( "\n" ) ;

   if ( maintflag == 0 ) exit( 0 ) ;

   if ( maintflag == 1 ) printf( "\nFull Maintenance Test: \n" ) ;
   else printf( "\nPartial Maintenance Test (only 1000 iterations): \n" ) ;
   printf( "key is: " ) ;
   memcpy( key, test_key, CAST_KEYSIZE ) ; 
   for ( i = 0; i < CAST_KEYSIZE; i++ ) printf( " %02x", key[ i ] ) ;
printf( "\n" ) ; printf( "\n" ) ;
   memcpy( aL, key, CAST_BLOCKSIZE ) ;
   memcpy( aR, key+CAST_BLOCKSIZE, CAST_BLOCKSIZE ) ;
   memcpy( bL, key, CAST_BLOCKSIZE ) ;
   memcpy( bR, key+CAST_BLOCKSIZE, CAST_BLOCKSIZE ) ;

   printf( "    a is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", aL[ i ] ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", aR[ i ] ) ;
   printf( "\n" ) ;
   printf( "    b is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", bL[ i ] ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", bR[ i ] ) ;
   printf( "\n" ) ;

   if ( maintflag == 1 ) maint_iter = 1000000L ;
   else if ( maintflag == 2 ) maint_iter = 1000 ;
   for ( j = 0; j < maint_iter; j++ ) {
      for ( i= 0; i < CAST_BLOCKSIZE; i++ ) { key[ i ] = bL[ i ] ; key[
i+CAST_BLOCKSIZE ] = bR[ i ] ; }
      CASTinit( key, Km, Kr ) ;
      CASTencrypt( aL, Km, Kr ) ; CASTencrypt( aR, Km, Kr ) ;
      for ( i= 0; i < CAST_BLOCKSIZE; i++ ) { key[ i ] = aL[ i ] ; key[
i+CAST_BLOCKSIZE ] = aR[ i ] ; }
      CASTinit( key, Km, Kr ) ;
      CASTencrypt( bL, Km, Kr ) ; CASTencrypt( bR, Km, Kr ) ;
   }
   printf( "    a is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", aL[ i ] ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", aR[ i ] ) ;
   printf( "\n" ) ;
   memcpy( ref, REFA, CAST_KEYSIZE ) ;
   printf( "ref a is: " ) ;
   if ( maintflag == 1 ) {
      for ( i = 0; i < CAST_KEYSIZE; i++ ) printf( " %02x", ref[ i ] ) ;
      printf( "\n" ) ;
   }
   else if ( maintflag == 2 ) 
     printf( " 23 f7 3b 14 b0 2a 2a d7 df b9 f2 c3 56 44 79 8d \n" ) ;
   printf( "\n" ) ;

   printf( "    b is: " ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", bL[ i ] ) ;
   for ( i = 0; i < CAST_BLOCKSIZE; i++ ) printf( " %02x", bR[ i ] ) ;
   printf( "\n" ) ;
   memcpy( ref, REFB, CAST_KEYSIZE ) ;
   printf( "ref b is: " ) ;
   if ( maintflag == 1 ) {
      for ( i = 0; i < CAST_KEYSIZE; i++ ) printf( " %02x", ref[ i ] ) ;
      printf( "\n" ) ;
   }
   else if ( maintflag == 2 ) 
     printf(" e5 bf 37 ef f1 4c 45 6a 40 b2 1c e3 69 37 0a 9f \n" ) ;

   return 0;
}

