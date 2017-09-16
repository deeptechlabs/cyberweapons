#ifndef _SAFER_DEFINED

#define _SAFER_DEFINED

/* The number of rounds for the different SAFER variants.  The maximum of 13
   rounds is set by the requirements of the key schedule operation */

#define SAFER_K64_ROUNDS	6
#define SAFER_K128_ROUNDS	10
#define SAFER_SK64_ROUNDS	8
#define SAFER_SK128_ROUNDS	10
#define SAFER_MAX_ROUNDS	13

/* The SAFER cipher block and key size */

#define SAFER_BLOCKSIZE		8		/* 64 bits */
#define SAFER_KEYSIZE		16		/* 128 bits */

/* The SAFER internal key length */

#define SAFER_KEYLEN		( 1 + SAFER_BLOCKSIZE * ( 1 + 2 * SAFER_MAX_ROUNDS ) )

/* Prototypes for routines in SAFER.C */

void saferExpandKey( BYTE *key, const BYTE *userKey, int noRounds,
					 const BOOLEAN useSaferSK );
void saferEncryptBlock( BYTE *data, BYTE *key );
void saferDecryptBlock( BYTE *data, BYTE *key );

#endif /* _SAFER_DEFINED */
