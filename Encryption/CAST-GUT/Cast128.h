#ifndef _CAST_DEFINED

#define _CAST_DEFINED

/* CAST-128 global constants */

#define CAST_BLOCKSIZE                  8

/* CAST-128 constants */

#define CAST_KEYSIZE            ( 16 + 16 )             /* Masking and
rotate subkeys */
#define CAST_KEYSIZE_BYTES      ( CAST_KEYSIZE * 4 )
#define CAST_USERKEY_SIZE       16

/* Prototypes for functions in CAST128.C */

void castEncrypt( LONG *key, BYTE *data );
void castDecrypt( LONG *key, BYTE *data );
void castKeyInit( LONG *key, BYTE *userKey );

#endif /* _CAST_DEFINED */