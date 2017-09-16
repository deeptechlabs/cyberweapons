/* Test code */

#include <stdio.h>
#include <string.h>

void main( void )
        {
        LONG K[ CAST_KEYSIZE ];
        BYTE key[ CAST_USERKEY_SIZE ] =
                                        { 0x01, 0x23, 0x45, 0x67, 0x12,
0x34, 0x56, 0x78,
                                          0x23, 0x45, 0x67, 0x89, 0x34,
0x56, 0x78, 0x9A };
        BYTE plain[ CAST_BLOCKSIZE ] = { 0x01, 0x23, 0x45, 0x67, 0x89,
0xAB, 0xCD, 0xEF };
        BYTE cipher[ CAST_BLOCKSIZE ] = { 0x23, 0x8B, 0x4F, 0xE5, 0x84,
0x7E, 0x44, 0xB2 };
        BYTE data[ CAST_BLOCKSIZE ];
        BYTE a[ CAST_USERKEY_SIZE ] =
                                        { 0x01, 0x23, 0x45, 0x67, 0x12,
0x34, 0x56, 0x78,
                                          0x23, 0x45, 0x67, 0x89, 0x34,
0x56, 0x78, 0x9A };
        BYTE b[ CAST_USERKEY_SIZE ] =
                                        { 0x01, 0x23, 0x45, 0x67, 0x12,
0x34, 0x56, 0x78,
                                          0x23, 0x45, 0x67, 0x89, 0x34,
0x56, 0x78, 0x9A };
        BYTE cipherA[ CAST_USERKEY_SIZE ] =
                                        { 0xEE, 0xA9, 0xD0, 0xA2, 0x49,
0xFD, 0x3B, 0xA6,
                                          0xB3, 0x43, 0x6F, 0xB8, 0x9D,
0x6D, 0xCA, 0x92 };
        BYTE cipherB[ CAST_USERKEY_SIZE ] =
                                        { 0xB2, 0xC9, 0x5E, 0xB0, 0x0C,
0x31, 0xAD, 0x71,
                                          0x80, 0xAC, 0x05, 0xB8, 0xE8,
0x3D, 0x69, 0x6E };
        long count;

        /* Quick encrypt/decrypt test */
        memcpy( data, plain, 8 );
        castKeyInit( K, key );
        castEncrypt( K, data );
        if( memcmp( data, cipher, 8 ) )
                puts( "Bang" );         /* Emit comprehensive diagnostic
message */
        castDecrypt( K, data );
        if( memcmp( data, plain, 8 ) )
                puts( "Bang" );

        /* Coffee-break test */
        for( count = 0; count < 1000000L; count++ )
                {
                if( !( count % 10000 ) )
                        printf( "Completed %d%%\r", count / 10000 );
                castKeyInit( K, b );
                castEncrypt( K, a );
                castEncrypt( K, a + 8 );
                castKeyInit( K, a );
                castEncrypt( K, b );
                castEncrypt( K, b + 8 );
                }
        puts( "Completed 100%" );
        if( memcmp( a, cipherA, 16 ) || memcmp( b, cipherB, 16 ) )
                puts( "Bang" );
        }