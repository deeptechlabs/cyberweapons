#ifndef _RC2_DEFINED

#define _RC2_DEFINED

/* The size of the key in bytes and 16-bit words */

#define RC2_KEY_SIZE		128
#define RC2_KEY_SIZE_WORDS	( RC2_KEY_SIZE / 2 )

/* The RC2 block size */

#define RC2_BLOCKSIZE		8

/* The RC2 key */

typedef struct {
	unsigned int key[ RC2_KEY_SIZE_WORDS ];
	} RC2_KEY;

void rc2keyInit( RC2_KEY *rc2key, const BYTE *userKey, const int length );
void rc2encrypt( RC2_KEY *rc2key, BYTE *buffer );
void rc2decrypt( RC2_KEY *rc2key, BYTE *buffer );

#endif /* _RC2_DEFINED */
